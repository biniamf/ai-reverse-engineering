# Biniam Demissie
# 09/29/2025
import base64
import json
import logging
import os
import re
import requests
import shutil
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, Response, send_from_directory
from ghidra_assistant import GhidraAssistant
from recovery_engine import (
    build_recovery_index,
    generate_recovered_files,
    generate_model_renamed_sources,
    generate_model_recovered_types,
    inspect_recovered_function,
    list_recovered_files,
    list_recovered_symbols,
    read_recovered_file,
)
from translator_config import get_translator_config
from runtime_settings import public_runtime_settings, save_runtime_settings

app = Flask(__name__)
assistant = GhidraAssistant()
GHIDRA_API_BASE = os.getenv("GHIDRA_API_BASE", "http://localhost:9090").rstrip("/")
GHIDRA_FAST_TIMEOUT_SECONDS = float(os.getenv("GHIDRA_FAST_TIMEOUT_SECONDS", "0.5"))
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
WEBUI_DIR = os.path.abspath(os.path.dirname(__file__))
DELETED_JOBS_FILE = os.path.join(WEBUI_DIR, "deleted_jobs.json")
LOG_DIR = os.getenv("AIREVERSE_LOG_DIR", os.path.join(ROOT_DIR, "logs"))


def _configure_file_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    for logger_name, filename in (("app", "flask.log"), ("werkzeug", "werkzeug.log")):
        logger = logging.getLogger(logger_name)
        if any(getattr(handler, "_aireverse_file_handler", False) for handler in logger.handlers):
            continue
        handler = RotatingFileHandler(
            os.path.join(LOG_DIR, filename),
            maxBytes=int(os.getenv("AIREVERSE_LOG_MAX_BYTES", "1048576")),
            backupCount=int(os.getenv("AIREVERSE_LOG_BACKUPS", "3")),
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        handler._aireverse_file_handler = True
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


_configure_file_logging()


def _safe_job_id(job_id):
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{8,128}", job_id or ""))


def _validate_job_id_or_error(job_id):
    if not _safe_job_id(job_id):
        return jsonify({"error": "Invalid job_id"}), 400
    return None


def _safe_remove_path(path, base_dir):
    abs_path = os.path.abspath(path)
    abs_base = os.path.abspath(base_dir)
    if abs_path != abs_base and os.path.commonpath([abs_base, abs_path]) == abs_base and os.path.exists(abs_path):
        if os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        return True
    return False


def _load_deleted_jobs():
    try:
        with open(DELETED_JOBS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(str(job_id) for job_id in data)
    except (OSError, ValueError):
        pass
    return set()


def _save_deleted_jobs(job_ids):
    os.makedirs(os.path.dirname(DELETED_JOBS_FILE), exist_ok=True)
    with open(DELETED_JOBS_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(job_ids), f, indent=2)


def _load_local_job_status(job_id):
    if not _safe_job_id(job_id):
        return None
    status_path = os.path.join(DATA_DIR, job_id, "status.json")
    try:
        with open(status_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("job_id", job_id)
            data.setdefault("source", "local")
            return data
    except (OSError, ValueError):
        pass
    return None


def _list_local_jobs():
    jobs = []
    if not os.path.isdir(DATA_DIR):
        return jobs
    for entry in os.scandir(DATA_DIR):
        if not entry.is_dir() or not _safe_job_id(entry.name):
            continue
        status = _load_local_job_status(entry.name)
        if status:
            jobs.append(status)
    return jobs


def _merge_jobs(upstream_jobs, local_jobs):
    merged = {}
    for job in local_jobs + upstream_jobs:
        if not isinstance(job, dict):
            continue
        job_id = str(job.get("job_id", ""))
        if not _safe_job_id(job_id):
            continue
        current = merged.get(job_id, {})
        current.update(job)
        current["job_id"] = job_id
        merged[job_id] = current
    return list(merged.values())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    response = send_from_directory(
        os.path.join(ROOT_DIR, "media"),
        "icon.ico",
        mimetype="image/vnd.microsoft.icon",
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.route('/media/<path:filename>')
def media_file(filename):
    return send_from_directory(os.path.join(ROOT_DIR, "media"), filename)

@app.route('/config', methods=['GET'])
def config():
    runtime = assistant.get_runtime_config()
    translator = get_translator_config()
    runtime["translator"] = {
        "provider": translator.provider,
        "api_base": translator.api_base,
        "endpoint": translator.endpoint,
        "enabled": translator.enabled,
    }
    return jsonify(runtime)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    global assistant
    if request.method == 'GET':
        runtime = assistant.get_runtime_config()
        translator = get_translator_config()
        return jsonify({
            "effective": {
                "llm": {
                    "provider": runtime.get("provider"),
                    "api_base": runtime.get("api_base"),
                    "model": runtime.get("model"),
                },
                "translator": {
                    "provider": translator.provider,
                    "api_base": translator.api_base,
                    "endpoint": translator.endpoint,
                    "enabled": translator.enabled,
                    "text_field": translator.text_field,
                    "source_field": translator.source_field,
                    "target_field": translator.target_field,
                    "result_field": translator.result_field,
                    "auth_header": translator.auth_header,
                },
            },
            "saved": public_runtime_settings(),
        })

    data = request.get_json(silent=True) or {}
    saved = save_runtime_settings(data)
    assistant = GhidraAssistant()
    return jsonify({"saved": public_runtime_settings(), "effective": saved})

def _extract_translation_result(payload, field_path):
    current = payload
    for part in (field_path or "translatedText").split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)] if int(part) < len(current) else None
        else:
            current = None
        if current is None:
            return ""
    if isinstance(current, list):
        return "\n".join(str(item) for item in current)
    return str(current or "")

def _build_translation_request(translator, text, source, target):
    headers = {"Content-Type": "application/json"}
    if translator.auth_header and translator.auth_token:
        headers[translator.auth_header] = translator.auth_token

    if translator.provider == "custom":
        payload = {
            translator.text_field: text,
            translator.source_field: source or "auto",
            translator.target_field: target,
        }
        if translator.api_key:
            payload["api_key"] = translator.api_key
        return f"{translator.api_base}{translator.endpoint}", payload, headers

    payload = {
        "q": text,
        "source": source or "auto",
        "target": target,
        "format": "text",
        "alternatives": 0,
        "api_key": translator.api_key,
    }
    return f"{translator.api_base}/translate", payload, headers

@app.route('/translate', methods=['POST'])
def translate_text():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or data.get("q") or "").strip()
    target = (data.get("target") or "").strip().lower()
    source = (data.get("source") or "auto").strip().lower()
    if not text:
        return jsonify({"error": "Text is required"}), 400
    if target not in ("ru", "en"):
        return jsonify({"error": "Only ru and en targets are enabled for now."}), 400

    translator = get_translator_config()
    if not translator.enabled:
        return jsonify({"error": "Translator is disabled. Set TRANSLATOR_PROVIDER=libretranslate or custom."}), 503

    try:
        url, payload, headers = _build_translation_request(translator, text, source, target)
        response = requests.post(url, json=payload, headers=headers, timeout=45)
        response.raise_for_status()
        result = response.json()
        translated = _extract_translation_result(result, translator.result_field)
        if not translated and isinstance(result, dict):
            translated = result.get("translation") or result.get("text") or ""
        return jsonify({
            "provider": translator.provider,
            "source": source,
            "target": target,
            "translatedText": translated,
            "raw": result,
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Translation service unavailable: {e}"}), 502

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        contents = file.read()
        encoded_contents = base64.b64encode(contents).decode('utf-8')

        payload = {
            "file_b64": encoded_contents,
            "filename": file.filename,
            "persist": True
        }

        response = requests.post(f"{GHIDRA_API_BASE}/analyze_b64", json=payload, timeout=120)
        response.raise_for_status()

        result = response.json()
        job_id = result.get("job_id")
        if job_id:
            deleted_jobs = _load_deleted_jobs()
            if job_id in deleted_jobs:
                deleted_jobs.remove(job_id)
                _save_deleted_jobs(deleted_jobs)

        return jsonify(result)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to connect to Ghidra service: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')
    job_id = data.get('job_id')

    if not user_message or not job_id:
        return jsonify({"error": "Message and job_id are required"}), 400
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job

    def generate():
        try:
            for chunk in assistant.chat_completion_stream(user_message, job_id):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            error_event = json.dumps({"type": "error", "content": str(e)})
            yield f"data: {error_event}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/jobs', methods=['GET'])
def list_jobs():
    deleted_jobs = _load_deleted_jobs()
    local_jobs = _list_local_jobs()
    upstream_warning = None
    upstream_jobs = []
    local_only = request.args.get("local") == "1"

    try:
        if local_only:
            raise requests.exceptions.RequestException("local-only job listing requested")
        response = requests.get(f"{GHIDRA_API_BASE}/jobs", timeout=GHIDRA_FAST_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            upstream_jobs = data
    except requests.exceptions.RequestException as e:
        upstream_warning = f"Ghidra service did not return jobs, using local artifacts only: {e}"

    jobs = _merge_jobs(upstream_jobs, local_jobs)
    if deleted_jobs:
        jobs = [job for job in jobs if str(job.get("job_id", "")) not in deleted_jobs]
    jobs.sort(key=lambda item: str(item.get("job_id", "")), reverse=True)

    if upstream_warning and not jobs:
        return jsonify({"error": upstream_warning}), 500
    return jsonify(jobs)

@app.route('/jobs/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    if not _safe_job_id(job_id):
        return jsonify({"error": "Invalid job_id"}), 400

    removed = []
    upstream_error = None

    try:
        response = requests.delete(f"{GHIDRA_API_BASE}/jobs/{job_id}", timeout=GHIDRA_FAST_TIMEOUT_SECONDS)
        if response.status_code not in (200, 202, 204, 404, 405):
            upstream_error = f"Ghidra service returned HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        upstream_error = str(e)

    cleanup_targets = [
        (os.path.join(DATA_DIR, job_id), DATA_DIR, "data"),
        (os.path.join(WEBUI_DIR, "recovered", job_id), os.path.join(WEBUI_DIR, "recovered"), "recovered"),
        (os.path.join(WEBUI_DIR, "recovery", f"{job_id}.json"), os.path.join(WEBUI_DIR, "recovery"), "recovery_index"),
        (os.path.join(WEBUI_DIR, "chats", f"{job_id}.json"), os.path.join(WEBUI_DIR, "chats"), "chat"),
    ]
    for path, base_dir, label in cleanup_targets:
        if _safe_remove_path(path, base_dir):
            removed.append(label)

    deleted_jobs = _load_deleted_jobs()
    deleted_jobs.add(job_id)
    _save_deleted_jobs(deleted_jobs)

    payload = {"job_id": job_id, "deleted": True, "removed": removed}
    if upstream_error:
        payload["warning"] = "Deleted locally. Ghidra service is offline or did not confirm upstream deletion."
        payload["upstream_delete_confirmed"] = False
    else:
        payload["upstream_delete_confirmed"] = True
    return jsonify(payload)

@app.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}", timeout=GHIDRA_FAST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        local_status = _load_local_job_status(job_id)
        if local_status:
            local_status["warning"] = f"Ghidra status unavailable, using local status.json: {e}"
            return jsonify(local_status)
        return jsonify({"error": f"Failed to get status: {e}"}), 500

@app.route('/chat/history/<job_id>', methods=['GET'])
def get_chat_history(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        history = assistant.load_history(job_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/index/<job_id>', methods=['GET', 'POST'])
def recovery_index(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        force = request.args.get("force") == "1" or request.method == "POST"
        return jsonify(build_recovery_index(job_id, force=force))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/files/<job_id>', methods=['GET', 'POST'])
def recovery_files(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        if request.method == "POST" or request.args.get("generate") == "1":
            force = request.args.get("force") == "1"
            result = generate_recovered_files(job_id, force=force)
            result.pop("index", None)
            return jsonify(result)
        return jsonify(list_recovered_files(job_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/symbols/<job_id>', methods=['GET'])
def recovery_symbols(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        return jsonify(list_recovered_symbols(job_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/function/<job_id>/<path:symbol>', methods=['GET'])
def recovery_function(job_id, symbol):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        result = inspect_recovered_function(job_id, symbol)
        status = 404 if result.get("error") else 200
        return jsonify(result), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/files/<job_id>/<path:filename>', methods=['GET'])
def recovery_file(job_id, filename):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        result = read_recovered_file(job_id, filename)
        status = 400 if result.get("error") else 200
        return jsonify(result), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/model/types/<job_id>', methods=['POST'])
def recovery_model_types(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        force = request.args.get("force") == "1"
        return jsonify(generate_model_recovered_types(job_id, force=force))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recovery/model/renames/<job_id>', methods=['POST'])
def recovery_model_renames(job_id):
    invalid_job = _validate_job_id_or_error(job_id)
    if invalid_job:
        return invalid_job
    try:
        force = request.args.get("force") == "1"
        return jsonify(generate_model_renamed_sources(job_id, force=force))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        use_reloader=False,
    )
