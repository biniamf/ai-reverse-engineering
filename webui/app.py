# Biniam Demissie
import json
import logging
import secrets
import time

from flask import (
    Flask,
    current_app,
    g,
    jsonify,
    make_response,
    render_template,
    request,
    Response,
)
from werkzeug.exceptions import RequestEntityTooLarge

from cache import BoundedTTLCache
from config import Config
from file_preflight import classify_file
from ghidra_assistant import GhidraAssistant
from ghidra_client import GhidraClient, GhidraClientError
from logging_setup import configure_logging
from version import ASSET_VERSION
from validation import (
    ValidationError,
    normalize_address,
    sanitize_filename,
    sanitize_thread_title,
    validate_job_id,
    validate_pagination,
    validate_query,
    validate_security_query,
    validate_thread_id,
)
from workflows import MODES, ModeError, list_workflows, validate_mode, validate_workflow

logger = logging.getLogger(__name__)

# Generic client-facing message for unexpected (non-GhidraClientError, non-
# ValidationError) failures.
_GENERIC_UPLOAD_ERROR = "An unexpected error occurred while processing the upload"
_GENERIC_HISTORY_ERROR = "An unexpected error occurred while loading chat history"
_GENERIC_ANALYSIS_ERROR = "An unexpected error occurred while fetching analysis data"
_GENERIC_CHAT_STREAM_ERROR = "An unexpected error occurred while generating the response"
_GENERIC_THREADS_ERROR = "An unexpected error occurred while managing chat threads"
_GENERIC_RETURN_ERROR = "An unexpected error occurred while returning the conclusion"


# Reserved literal for the default ("main") thread. The browser sends "main"
# (or nothing) for the default conversation; a set value must be a valid
# 32-hex sub-thread id before it can touch a path.
_MAIN_THREAD = "main"


def _resolve_thread_id(raw):
    """Map a request-supplied thread id to a store key, or raise on garbage."""
    if raw is None or raw == "" or raw == _MAIN_THREAD:
        return None
    return validate_thread_id(raw)


def _deps():
    return current_app.extensions["ghidra_webui"]


def _reject_cross_origin():
    """Same-origin guard for every state-changing browser route."""
    origin = request.headers.get("Origin")
    if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
        return jsonify({"error": "cross-origin request is not allowed"}), 403
    return None


def _ghidra_error_response(exc, verb):
    """Map a GhidraClientError to a safe JSON envelope + HTTP status."""
    code = exc.code
    if code in ("timeout", "connection"):
        status = 504
    elif code in ("invalid_query", "invalid_range"):
        status = 422
    elif code == "not_found":
        status = 404
    elif code == "conflict":
        status = 409
    elif code == "index_unavailable":
        # The security index is missing/stale/corrupt/building. Surface the stable 409
        # envelope (available:false + status + rescore_available) so the UI can offer a
        # rescore without treating the base workspace as broken. The envelope is data,
        # not an internal detail.
        status = 409
        body = {"error": f"Failed to {verb}: {exc.message}", "code": code}
        if isinstance(getattr(exc, "envelope", None), dict):
            body.update(exc.envelope)
        return jsonify(body), status
    elif code == "capability_required":
        status = 501
    else:
        status = 502
    return jsonify({"error": f"Failed to {verb}: {exc.message}", "code": code}), status


def create_app(config=None, assistant=None, ghidra_client=None):
    """Application factory."""
    if config is None:
        config = Config.from_env()

    if ghidra_client is None:
        ghidra_client = GhidraClient(
            config.ghidra_api_base,
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
            max_response_bytes=config.max_response_bytes,
        )

    if assistant is None:
        assistant = GhidraAssistant(config=config, ghidra_client=ghidra_client)

    # Structured logging with optional rotating file + redaction (Phase 6).
    # Idempotent: a repeated call re-uses handlers rather than duplicating them.
    configure_logging(config)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_upload_bytes

    # Cache-busting asset URLs. ``static_versioned("css/x.css")`` renders
    # ``/static/css/x.css?v=<ASSET_VERSION>`` where ASSET_VERSION changes exactly when
    # the shipped frontend changes (see webui/version.py).
    def static_versioned(path: str) -> str:
        clean = str(path).lstrip("/")
        base = f"/static/{clean}"
        return f"{base}?v={ASSET_VERSION}" if ASSET_VERSION else base

    app.jinja_env.globals["static_versioned"] = static_versioned
    app.extensions["ghidra_webui"] = {
        "config": config,
        "assistant": assistant,
        "ghidra_client": ghidra_client,
        # Bounded, TTL'd cache for *immutable* per-job evidence only
        # (completed-job summaries). Mutable data (annotations, in-flight
        # status) is never cached.
        "summary_cache": BoundedTTLCache(
            ttl=config.summary_cache_ttl,
            max_entries=config.summary_cache_max_entries,
        ),
    }

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_exc):
        return jsonify({"error": "Uploaded file is too large"}), 413

    @app.before_request
    def _assign_request_context():
        # A fresh per-response CSP nonce lets the single module script run under a
        # strict script-src without 'unsafe-inline'. A per-request id correlates the
        # Flask access log with any job/upstream call made while serving it.
        g.csp_nonce = secrets.token_urlsafe(16)
        incoming = request.headers.get("X-Request-ID", "")
        if incoming and len(incoming) <= 64 and incoming.isascii() and incoming.isprintable():
            g.request_id = incoming
        else:
            g.request_id = secrets.token_hex(8)
        g.request_started = time.monotonic()

    @app.after_request
    def _finalize_request(response):
        # Correlation header + one concise, redaction-safe access log line.
        request_id = getattr(g, "request_id", "")
        if request_id:
            response.headers.setdefault("X-Request-ID", request_id)
        started = getattr(g, "request_started", None)
        duration_ms = int((time.monotonic() - started) * 1000) if started else -1
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response

    @app.after_request
    def _security_headers(response):
        # The dedicated Mermaid sandbox frame sets its OWN narrowly-scoped CSP and
        # framing headers (see mermaid_frame()); it must not be overwritten here with
        # the main document's DENY policy, or the parent could never embed it.
        if getattr(g, "is_mermaid_frame", False):
            return response

        nonce = getattr(g, "csp_nonce", "")
        # Strict, self-hosted CSP for the MAIN document. No external origins: every
        # script, style, font, and image is served from this app, so untrusted
        # model/artifact content cannot pull in a remote script.
        csp = (
            "default-src 'none'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), usb=()",
        )
        return response

    @app.after_request
    def _cache_control(response):
        # Cache policy paired with the ?v= asset versioning above. Two rules, applied
        # only to the response types they concern; everything else (JSON APIs, the SSE
        # /chat stream, the binary /export proxy) is left exactly as its route produced
        # it.
        path = request.path or ""
        if path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
            return response
        if "Cache-Control" in response.headers:
            return response
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def index():
        return render_template("index.html", csp_nonce=g.csp_nonce)

    @app.route("/mermaid-frame", methods=["GET"])
    def mermaid_frame():
        # The sandboxed diagram renderer document. The parent embeds it with
        # sandbox="allow-scripts" ONLY, so it runs at an OPAQUE ("null") origin.
        origin = request.host_url.rstrip("/")
        frame_csp = (
            "default-src 'none'; "
            f"script-src {origin}; "
            f"style-src {origin} 'unsafe-inline'; "
            f"img-src {origin} data:; "
            f"font-src {origin}; "
            "connect-src 'none'; "
            "form-action 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'self'; "
            "object-src 'none'"
        )
        g.is_mermaid_frame = True
        response = make_response(render_template("mermaid-frame.html"))
        response.headers["Content-Security-Policy"] = frame_csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Per-resource override: only the frame may be embedded (same origin);
        # the main document keeps its global DENY set in _security_headers.
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), usb=()"
        )
        return response

    @app.route("/api/workflows", methods=["GET"])
    def api_workflows():
        # Safe, static metadata describing the operating modes and the bounded
        # autonomous workflows the UI may offer. No untrusted input involved.
        return jsonify({"modes": list(MODES), "workflows": list_workflows()})

    @app.route("/healthz", methods=["GET"])
    def healthz():
        # Liveness only: the web process itself is up and can serve. No network
        # calls, so this never blocks on a slow/absent Ghidra or LLM.
        return jsonify({"status": "ok"})

    @app.route("/readyz", methods=["GET"])
    def readyz():
        # Readiness: is the app configured and are its dependencies reachable? Probes
        # Ghidra capabilities safely (no raise, bounded timeout) and checks that an LLM
        # endpoint/model is configured WITHOUT making a paid call and WITHOUT leaking
        # the API key.
        deps = _deps()
        cfg = deps["config"]
        try:
            cap = deps["ghidra_client"].capability_report()
        except Exception:  # pragma: no cover - capability_report is no-raise
            logger.exception("readyz: capability probe failed")
            cap = {"tier": "unknown", "reachable": False, "features": {}}

        llm_configured = bool(cfg.api_base and cfg.model_name)
        ghidra_ok = bool(cap.get("reachable"))
        ready = ghidra_ok and llm_configured
        body = {
            "ready": ready,
            "ghidra": {
                "reachable": ghidra_ok,
                "tier": cap.get("tier", "unknown"),
            },
            # Booleans only -- never the key itself.
            "llm": {"configured": llm_configured, "model_set": bool(cfg.model_name)},
        }
        return jsonify(body), (200 if ready else 503)

    @app.route("/api/capabilities", methods=["GET"])
    def api_capabilities():
        # Safe capability report so the UI can gate v1-only features (types, globals,
        # annotations, native summary/callgraph, multipart upload) and clearly show
        # which are unavailable. Never raises; the Ghidra base URL is never exposed.
        try:
            report = _deps()["ghidra_client"].capability_report()
        except Exception:  # pragma: no cover - capability_report is no-raise
            logger.exception("Unexpected error building capability report")
            report = {"tier": "unknown", "reachable": False, "features": {}}
        return jsonify(report)

    @app.route("/api/capabilities/refresh", methods=["POST"])
    def api_capabilities_refresh():
        # Bounded, same-origin force-refresh of the capability cache, used after a
        # service restart or capability change so a stale report is not diagnosed as a
        # service downgrade.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        try:
            report = _deps()["ghidra_client"].capability_report(force=True)
        except Exception:  # pragma: no cover - capability_report is no-raise
            logger.exception("Unexpected error refreshing capability report")
            report = {"tier": "unknown", "reachable": False, "features": {}}
        return jsonify(report)

    @app.route("/upload", methods=["POST"])
    def upload_file():
        # Same-origin guard (see _reject_cross_origin): a multipart form post forged
        # from a hostile page always carries a cross-site Origin header in every modern
        # browser, so this is a real CSRF defense for the upload despite the request
        # being multipart rather than.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        try:
            filename = sanitize_filename(file.filename)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            contents = file.read()
            classification = classify_file(contents)
            analyze_as_raw = str(request.form.get("analyze_as_raw", "")).lower() in {
                "1",
                "true",
                "yes",
            }
            if classification.kind == "likely_text" and not analyze_as_raw:
                return (
                    jsonify(
                        {
                            "error": (
                                "This file appears to be plain text, not an "
                                "executable or binary container."
                            ),
                            "code": "confirmation_required",
                            "classification": classification.kind,
                            "format": classification.format,
                        }
                    ),
                    409,
                )
            # Prefer streamed v1 multipart when advertised; the client falls back to
            # legacy base64 only on an absent (404/405) v1 route, never on auth/5xx.
            # Both queued and immediate cache-hit "done" upload responses are accepted
            # and normalized (job_id + status).
            result = _deps()["ghidra_client"].upload_binary(
                contents, filename, persist=True
            )
            return jsonify(result)
        except GhidraClientError as exc:
            return _ghidra_error_response(exc, "start analysis")
        except Exception:  # pragma: no cover - defensive fallback
            logger.exception("Unexpected error handling /upload")
            return jsonify({"error": _GENERIC_UPLOAD_ERROR}), 500

    @app.route("/chat", methods=["POST"])
    def chat():
        # Same-origin guard (see _reject_cross_origin): a cross-site fetch/ form post
        # always carries Origin in every modern browser, so a forged chat request is
        # refused before the (potentially long-running) SSE stream starts.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        data = request.get_json(silent=True) or {}
        user_message = data.get("message")
        job_id = data.get("job_id")

        if not user_message or not job_id:
            return jsonify({"error": "Message and job_id are required"}), 400

        try:
            job_id = validate_job_id(job_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            mode = validate_mode(data.get("mode"))
            workflow_spec = validate_workflow(mode, data.get("workflow"))
        except ModeError as exc:
            return jsonify({"error": str(exc)}), 400

        assistant = _deps()["assistant"]
        max_step_budget = getattr(assistant, "max_step_budget", 50)

        step_budget = data.get("step_budget")
        if step_budget is not None:
            if isinstance(step_budget, bool) or not isinstance(step_budget, int):
                return jsonify({"error": "step_budget must be an integer"}), 400
            if step_budget < 1:
                return jsonify({"error": "step_budget must be >= 1"}), 400
            if step_budget > max_step_budget:
                return (
                    jsonify(
                        {"error": f"step_budget must be <= {max_step_budget}"}
                    ),
                    400,
                )

        unbounded = data.get("unbounded", False)
        if not isinstance(unbounded, bool):
            return jsonify({"error": "unbounded must be a boolean"}), 400

        # Optional target address: required by workflows that operate on a
        # selected function (selected_function, call_chain). Validated/normalized
        # here so an invalid address is a 400 before any stream begins.
        target = data.get("target") or data.get("addr")
        if target is not None and target != "":
            try:
                target = normalize_address(target)
            except ValidationError as exc:
                return jsonify({"error": str(exc)}), 400
        else:
            target = None
        if workflow_spec is not None and workflow_spec.requires_address and not target:
            return (
                jsonify(
                    {
                        "error": (
                            f"workflow {workflow_spec.name!r} requires a target "
                            "function address"
                        )
                    }
                ),
                400,
            )

        # Optional structured evidence references (evidence-to-chat boundary). The
        # browser sends only entity ids/addresses, never a concatenated prompt. The
        # server retrieves and delimits the evidence as untrusted data. Reject anything
        # malformed before streaming.
        try:
            evidence_refs = _validate_evidence_refs(data.get("evidence"))
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            thread_id = _resolve_thread_id(data.get("thread_id"))
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        workflow_name = workflow_spec.name if workflow_spec else None

        def generate():
            try:
                for chunk in assistant.chat_completion_stream(
                    user_message,
                    job_id,
                    mode=mode,
                    workflow=workflow_name,
                    step_budget=step_budget,
                    unbounded=unbounded,
                    target=target,
                    evidence_refs=evidence_refs,
                    thread_id=thread_id,
                ):
                    yield f"data: {chunk}\n\n"
            except Exception:
                # The raw exception can carry an upstream URL, request body, or other
                # internal detail -- log it server-side only and emit a fixed, generic
                # message into the SSE stream so nothing sensitive ever reaches the
                # browser.
                logger.exception(
                    "Unexpected error streaming /chat response for job_id=%s",
                    job_id,
                )
                error_event = json.dumps(
                    {"type": "error", "content": _GENERIC_CHAT_STREAM_ERROR}
                )
                yield f"data: {error_event}\n\n"

        response = Response(
            generate(), content_type="text/event-stream; charset=utf-8"
        )
        # Streaming-correctness headers. ``no-transform`` stops proxies from
        # buffering/altering the byte stream; ``X-Accel-Buffering: no`` disables nginx
        # response buffering so tokens reach the browser as they are produced rather
        # than in one flush at the end.
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["X-Accel-Buffering"] = "no"
        return response

    @app.route("/jobs", methods=["GET"])
    def list_jobs():
        # Normalized, redacted job list ({"items": [...]}): prefers v1 /v1/jobs,
        # falls back to legacy /jobs. Every record is stripped of stderr/logs/
        # traces/paths/internal URLs before it reaches the browser.
        try:
            return jsonify(_deps()["ghidra_client"].list_jobs_normalized())
        except GhidraClientError as exc:
            return _ghidra_error_response(exc, "list jobs")

    @app.route("/status/<job_id>", methods=["GET"])
    def get_status(job_id):
        try:
            job_id = validate_job_id(job_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            # Prefers v1 /v1/jobs/<id>, falls back to legacy /status/<id>;
            # redacted before return.
            return jsonify(_deps()["ghidra_client"].get_job(job_id))
        except GhidraClientError as exc:
            return _ghidra_error_response(exc, "get status")

    @app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
    def api_cancel_job(job_id):
        # Same-origin guard (see _reject_cross_origin): cancelling a job is
        # state-changing and must not be forgeable from a cross-site page.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked

        def _fn():
            jid = _validated_job(job_id)
            return _deps()["ghidra_client"].cancel_job(jid)

        return _analysis_route("cancel job", _fn)

    @app.route("/api/jobs/<job_id>", methods=["DELETE"])
    def api_delete_job(job_id):
        # Same-origin guard (see _reject_cross_origin): deleting a job is
        # state-changing and must not be forgeable from a cross-site page.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked

        def _fn():
            jid = _validated_job(job_id)
            result = _deps()["ghidra_client"].delete_job(jid)
            # Drop any cached summary for a deleted job so a later reupload of
            # the same id never shows a stale summary.
            cache = _deps().get("summary_cache")
            if cache is not None:
                cache.delete(jid)
            return result

        return _analysis_route("delete job", _fn)

    @app.route("/chat/history/<job_id>", methods=["GET"])
    def get_chat_history(job_id):
        try:
            job_id = validate_job_id(job_id)
            thread_id = _resolve_thread_id(request.args.get("thread_id"))
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            assistant = _deps()["assistant"]
            if thread_id is None:
                history = assistant.load_history(job_id)
            else:
                history = assistant.load_history(job_id, thread_id)
            return jsonify(history)
        except Exception:
            logger.exception("Unexpected error handling /chat/history/%s", job_id)
            return jsonify({"error": _GENERIC_HISTORY_ERROR}), 500

    # ------------------------------------------------------------------ # Chat threads
    # (sub-conversations). A job holds a main thread plus child sub-threads; every
    # state-changing route is same-origin guarded and every id is validated before it
    # can touch a path.
    @app.route("/chat/threads/<job_id>", methods=["GET"])
    def list_chat_threads(job_id):
        try:
            job_id = validate_job_id(job_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            threads = _deps()["assistant"].list_threads(job_id)
            return jsonify({"threads": threads})
        except Exception:
            logger.exception("Unexpected error listing threads for %s", job_id)
            return jsonify({"error": _GENERIC_THREADS_ERROR}), 500

    @app.route("/chat/threads/<job_id>", methods=["POST"])
    def create_chat_thread(job_id):
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        try:
            job_id = validate_job_id(job_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        data = request.get_json(silent=True) or {}
        try:
            title = sanitize_thread_title(data.get("title"))
            parent_thread_id = _resolve_thread_id(data.get("parent_thread_id"))
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            assistant = _deps()["assistant"]
            if parent_thread_id is not None and assistant.get_thread(
                job_id, parent_thread_id
            ) is None:
                return jsonify({"error": "parent thread not found"}), 404
            thread = assistant.create_thread(
                job_id, title=title, parent_thread_id=parent_thread_id
            )
            return jsonify(thread), 201
        except ValueError:
            return jsonify({"error": "thread limit reached for this job"}), 409
        except Exception:
            logger.exception("Unexpected error creating thread for %s", job_id)
            return jsonify({"error": _GENERIC_THREADS_ERROR}), 500

    @app.route("/chat/threads/<job_id>/<thread_id>/rename", methods=["POST"])
    def rename_chat_thread(job_id, thread_id):
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        try:
            job_id = validate_job_id(job_id)
            thread_id = validate_thread_id(thread_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        data = request.get_json(silent=True) or {}
        try:
            title = sanitize_thread_title(data.get("title"))
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            thread = _deps()["assistant"].rename_thread(job_id, thread_id, title=title)
            if thread is None:
                return jsonify({"error": "thread not found"}), 404
            return jsonify(thread)
        except Exception:
            logger.exception("Unexpected error renaming thread for %s", job_id)
            return jsonify({"error": _GENERIC_THREADS_ERROR}), 500

    @app.route("/chat/threads/<job_id>/<thread_id>/return", methods=["POST"])
    def return_chat_thread(job_id, thread_id):
        # Summarize the sub-thread in one bounded model call, then plug the provenance
        # card back into its parent. State-changing (it writes the parent transcript)
        # and model-invoking, so it is same-origin guarded and any raw exception is
        # redacted to a generic message.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked
        try:
            job_id = validate_job_id(job_id)
            thread_id = validate_thread_id(thread_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        assistant = _deps()["assistant"]
        record = assistant.get_thread(job_id, thread_id)
        if record is None:
            return jsonify({"error": "thread not found"}), 404
        history = assistant.load_history(job_id, thread_id)
        has_investigation = any(
            isinstance(message, dict)
            and message.get("role") in {"user", "assistant", "tool"}
            and bool(message.get("content") or message.get("tool_calls"))
            for message in history
        )
        if not has_investigation:
            return jsonify({"error": "sub-thread has no investigation to summarize"}), 409
        parent_thread_id = record.get("parent_thread_id")
        try:
            subresult = assistant.summarize_thread(job_id, thread_id)
            card = assistant.append_subresult(job_id, parent_thread_id, subresult)
        except Exception:
            logger.exception("Unexpected error returning thread %s", thread_id)
            return jsonify({"error": _GENERIC_RETURN_ERROR}), 500
        return jsonify(
            {
                "subresult": subresult,
                "parent_thread_id": parent_thread_id if parent_thread_id else _MAIN_THREAD,
                "card": card,
            }
        )

    # ------------------------------------------------------------------ # Analysis
    # proxy routes (Phase 3).
    def _analysis_route(verb, fn):
        """Run a client fetch, mapping validation/client errors to envelopes."""
        try:
            return jsonify(fn())
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        except GhidraClientError as exc:
            return _ghidra_error_response(exc, verb)
        except Exception:
            logger.exception("Unexpected error in analysis route (%s)", verb)
            return jsonify({"error": _GENERIC_ANALYSIS_ERROR}), 500

    def _validated_job(job_id):
        # Raises ValidationError, caught by _analysis_route -> 400.
        return validate_job_id(job_id)

    @app.route("/api/jobs/<job_id>/functions", methods=["GET"])
    def api_functions(job_id):
        def _fn():
            jid = _validated_job(job_id)
            offset, limit = validate_pagination(
                request.args.get("offset", 0), request.args.get("limit", None)
            )
            # Optional global function search (name/display-name/address). Bounded and
            # validated before any network call; an empty/absent query keeps the plain
            # paginated listing.
            raw_q = request.args.get("q")
            query = None
            if raw_q is not None and raw_q.strip() != "":
                query = validate_query(raw_q)
            return _deps()["ghidra_client"].fetch_functions(jid, offset, limit, query)

        return _analysis_route("list functions", _fn)

    @app.route("/api/jobs/<job_id>/decompile", methods=["GET"])
    def api_decompile(job_id):
        def _fn():
            jid = _validated_job(job_id)
            addr = normalize_address(request.args.get("addr"))
            return _deps()["ghidra_client"].fetch_decompile(jid, addr)

        return _analysis_route("decompile function", _fn)

    @app.route("/api/jobs/<job_id>/xrefs", methods=["GET"])
    def api_xrefs(job_id):
        def _fn():
            jid = _validated_job(job_id)
            addr = normalize_address(request.args.get("addr"))
            return _deps()["ghidra_client"].fetch_xrefs(jid, addr)

        return _analysis_route("get xrefs", _fn)

    @app.route("/api/jobs/<job_id>/imports", methods=["GET"])
    def api_imports(job_id):
        def _fn():
            jid = _validated_job(job_id)
            offset, limit = validate_pagination(
                request.args.get("offset", 0), request.args.get("limit", None)
            )
            return _deps()["ghidra_client"].fetch_imports(jid, offset, limit)

        return _analysis_route("list imports", _fn)

    @app.route("/api/jobs/<job_id>/strings", methods=["GET"])
    def api_strings(job_id):
        def _fn():
            jid = _validated_job(job_id)
            offset, limit = validate_pagination(
                request.args.get("offset", 0), request.args.get("limit", None)
            )
            min_length = request.args.get("min_length")
            if min_length is not None and min_length != "":
                # Reuse pagination's bounded int coercion via a small range.
                try:
                    ml = int(min_length)
                except (TypeError, ValueError):
                    raise ValidationError("min_length must be an integer")
                if ml < 1 or ml > 4096:
                    raise ValidationError("min_length must be between 1 and 4096")
            else:
                ml = None
            return _deps()["ghidra_client"].fetch_strings(jid, ml, offset, limit)

        return _analysis_route("list strings", _fn)

    @app.route("/api/jobs/<job_id>/query", methods=["GET"])
    def api_query(job_id):
        def _fn():
            jid = _validated_job(job_id)
            query = validate_query(request.args.get("query"))
            regex = request.args.get("regex", "").lower() in ("1", "true", "yes")
            return _deps()["ghidra_client"].fetch_query(jid, query, regex)

        return _analysis_route("query artifacts", _fn)

    @app.route("/api/jobs/<job_id>/summary", methods=["GET"])
    def api_summary(job_id):
        # Program summary: native v1 document when available, otherwise
        # synthesized from status + one page of functions (bounded, no N+1).
        # A per-job bounded cache is consulted first (Phase 6).
        def _fn():
            jid = _validated_job(job_id)
            cache = _deps().get("summary_cache")
            if cache is not None:
                cached = cache.get(jid)
                if cached is not None:
                    return cached
            summary = _deps()["ghidra_client"].fetch_summary(jid)
            # Only cache a completed, immutable summary. A still-running job's
            # summary can still change, so it is not cached.
            if cache is not None and _summary_is_final(summary):
                cache.set(jid, summary)
            return summary

        return _analysis_route("summarize program", _fn)

    @app.route("/api/jobs/<job_id>/callgraph", methods=["GET"])
    def api_callgraph(job_id):
        # Bounded call-graph neighborhood derived from legacy xrefs. Depth and
        # node/edge caps are clamped in the client; requested values are only
        # advisory and further bounded here.
        def _fn():
            jid = _validated_job(job_id)
            addr = normalize_address(request.args.get("addr"))
            depth = _bounded_int(request.args.get("depth"), default=2, lo=0, hi=4)
            return _deps()["ghidra_client"].fetch_callgraph(jid, addr, depth=depth)

        return _analysis_route("build call graph", _fn)

    @app.route("/api/jobs/<job_id>/types", methods=["GET"])
    def api_types(job_id):
        def _fn():
            jid = _validated_job(job_id)
            offset, limit = validate_pagination(
                request.args.get("offset", 0), request.args.get("limit", None)
            )
            return _deps()["ghidra_client"].fetch_types(jid, offset, limit)

        return _analysis_route("list types", _fn)

    @app.route("/api/jobs/<job_id>/globals", methods=["GET"])
    def api_globals(job_id):
        def _fn():
            jid = _validated_job(job_id)
            offset, limit = validate_pagination(
                request.args.get("offset", 0), request.args.get("limit", None)
            )
            return _deps()["ghidra_client"].fetch_globals(jid, offset, limit)

        return _analysis_route("list globals", _fn)

    @app.route("/api/jobs/<job_id>/annotations", methods=["GET"])
    def api_get_annotations(job_id):
        # Returns ``{"annotations": ..., "etag": "<rev>"}``; the browser keeps
        # the ETag so a later write can send If-Match and detect a lost update.
        def _fn():
            jid = _validated_job(job_id)
            addr_arg = request.args.get("addr")
            addr = normalize_address(addr_arg) if addr_arg else None
            return _deps()["ghidra_client"].fetch_annotations(jid, addr)

        return _analysis_route("get annotations", _fn)

    @app.route("/api/jobs/<job_id>/annotations/<addr>", methods=["PUT"])
    def api_put_annotation(job_id, addr):
        # Annotations are sidecar overlays -- never edits to the exported Ghidra
        # analysis.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked

        def _fn():
            jid = _validated_job(job_id)
            naddr = normalize_address(addr)
            body = request.get_json(silent=True) or {}
            if not isinstance(body, dict):
                raise ValidationError("annotation body must be a JSON object")
            payload = _sanitize_annotation(body)
            # Prefer an explicit If-Match header; fall back to a revision/etag
            # field in the body so either transport works.
            if_match = request.headers.get("If-Match") or payload.pop("etag", None)
            if if_match is None and payload.get("revision"):
                if_match = f'"{payload["revision"]}"'
            return _deps()["ghidra_client"].put_annotation(
                jid, naddr, payload, if_match=if_match
            )

        return _analysis_route("save annotation", _fn)

    @app.route("/api/jobs/<job_id>/hexdump", methods=["GET"])
    def api_hexdump(job_id):
        # Bounded hex slice of exported program memory (feature-gated, v1 only).
        # Not an arbitrary filesystem read: the start is a validated address and
        # the length is bounded client- and server-side.
        def _fn():
            jid = _validated_job(job_id)
            start = normalize_address(request.args.get("start") or request.args.get("addr"))
            length = _bounded_int(request.args.get("length"), default=16, lo=1, hi=4096)
            return _deps()["ghidra_client"].fetch_hexdump(jid, start, length)

        return _analysis_route("read hexdump", _fn)

    @app.route("/api/jobs/<job_id>/export", methods=["GET"])
    def api_export(job_id):
        # Bounded binary ZIP proxy (v1 only). The body is streamed through untouched as
        # an attachment; the browser never extracts or renders archive paths, and the
        # Ghidra URL is never exposed.
        try:
            jid = validate_job_id(job_id)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            content, content_type, filename = _deps()["ghidra_client"].export_archive(jid)
        except GhidraClientError as exc:
            return _ghidra_error_response(exc, "export archive")
        except Exception:
            logger.exception("Unexpected error in export route")
            return jsonify({"error": _GENERIC_ANALYSIS_ERROR}), 500
        response = make_response(content)
        response.headers["Content-Type"] = content_type
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        # Never let a downloaded archive be sniffed/rendered inline.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Length"] = str(len(content))
        return response

    # ------------------------------------------------------------------ # Attack
    # surface / security index proxy routes (Phase 1B). Read-only, v1-only proxies over
    # the deterministic security index.
    @app.route("/api/jobs/<job_id>/security/summary", methods=["GET"])
    def api_security_summary(job_id):
        # The summary route intentionally answers 200 with an ``available:false``
        # envelope when the index is missing/stale/corrupt/ building, so the UI can
        # offer a rescore without treating the whole workspace as broken.
        def _fn():
            jid = _validated_job(job_id)
            return _deps()["ghidra_client"].fetch_security_summary(jid)

        return _analysis_route("load security summary", _fn)

    @app.route("/api/jobs/<job_id>/security/functions", methods=["GET"])
    def api_security_functions(job_id):
        # Server-paginated ranked functions with strict param validation. The Rev·Deck
        # table defaults to 25 and caps at 100 rows/request; band, category, sort, and
        # order are all restricted to the allowed sets before any network call, so an
        # out-of-range value is a 400.
        def _fn():
            jid = _validated_job(job_id)
            query = validate_security_query(
                offset=request.args.get("offset", 0),
                limit=request.args.get("limit", None),
                band=request.args.get("band"),
                category=request.args.get("category"),
                min_score=request.args.get("min_score"),
                q=request.args.get("q"),
                rank=request.args.get("rank"),
                sort=request.args.get("sort", "score"),
                order=request.args.get("order", "desc"),
            )
            return _deps()["ghidra_client"].fetch_security_functions(jid, **query)

        return _analysis_route("list security functions", _fn)

    @app.route("/api/jobs/<job_id>/security/functions/<addr>", methods=["GET"])
    def api_security_function(job_id, addr):
        def _fn():
            jid = _validated_job(job_id)
            naddr = normalize_address(addr)
            return _deps()["ghidra_client"].fetch_security_function(jid, naddr)

        return _analysis_route("load security function", _fn)

    @app.route("/api/jobs/<job_id>/security/rescore", methods=["POST"])
    def api_security_rescore(job_id):
        # State-changing: enqueues a deterministic re-derivation of the security
        # index (it never invokes Ghidra). Same-origin guarded so a rescore
        # cannot be forged from a cross-site page, consistent with cancel/delete.
        blocked = _reject_cross_origin()
        if blocked is not None:
            return blocked

        def _fn():
            jid = _validated_job(job_id)
            return _deps()["ghidra_client"].rescore_security(jid)

        return _analysis_route("rescore security index", _fn)

    return app


# Fields an analyst annotation overlay may set. Everything else is dropped so a
# request cannot smuggle server-side control fields into the Ghidra service.
_ANNOTATION_FIELDS = ("display_name", "comment", "tags", "confidence", "revision", "etag")


def _sanitize_annotation(body):
    from validation import ValidationError as _VErr

    out = {}
    for key in _ANNOTATION_FIELDS:
        if key not in body:
            continue
        value = body[key]
        if key in ("display_name", "comment", "revision", "etag"):
            if value is not None and not isinstance(value, str):
                raise _VErr(f"annotation {key} must be a string")
            if isinstance(value, str) and len(value) > 4096:
                raise _VErr(f"annotation {key} is too long")
        elif key == "tags":
            if not isinstance(value, list) or not all(
                isinstance(t, str) for t in value
            ):
                raise _VErr("annotation tags must be a list of strings")
            if len(value) > 64:
                raise _VErr("too many annotation tags")
        elif key == "confidence":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise _VErr("annotation confidence must be a number")
            if not (0 <= value <= 1):
                raise _VErr("annotation confidence must be between 0 and 1")
        out[key] = value
    return out


_EVIDENCE_KINDS = ("function", "string", "import")
_MAX_EVIDENCE_REFS = 16


def _validate_evidence_refs(raw):
    """Validate structured evidence references from the browser."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValidationError("evidence must be a list")
    if len(raw) > _MAX_EVIDENCE_REFS:
        raise ValidationError(f"at most {_MAX_EVIDENCE_REFS} evidence refs")
    out = []
    for ref in raw:
        if not isinstance(ref, dict):
            raise ValidationError("each evidence ref must be an object")
        kind = ref.get("kind")
        if kind not in _EVIDENCE_KINDS:
            raise ValidationError(f"evidence kind must be one of {_EVIDENCE_KINDS}")
        item = {"kind": kind}
        addr = ref.get("addr")
        if addr is not None and addr != "":
            item["addr"] = normalize_address(addr)
        name = ref.get("name")
        if name is not None:
            if not isinstance(name, str) or len(name) > 256:
                raise ValidationError("evidence name must be a short string")
            # Names are untrusted symbol text; keep as data, bound length only.
            item["name"] = name
        if kind == "function" and "addr" not in item:
            raise ValidationError("function evidence requires an address")
        if kind == "import" and "name" not in item:
            raise ValidationError("import evidence requires a name")
        out.append(item)
    return out


def _bounded_int(raw, *, default, lo, hi):
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationError(f"expected an integer between {lo} and {hi}")
    return max(lo, min(value, hi))


def _summary_is_final(summary):
    """True when a summary describes a completed job (safe to cache)."""
    if not isinstance(summary, dict):
        return False
    status = str(summary.get("status", "")).lower()
    return status in ("done", "completed", "complete", "finished", "success")


app = create_app()
# Expose the default assistant at module scope for backwards-compatible access.
assistant = app.extensions["ghidra_webui"]["assistant"]


if __name__ == "__main__":
    cfg = app.extensions["ghidra_webui"]["config"]
    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)
