import json
import os
from typing import Any, Dict


SETTINGS_DIR = os.getenv("AIREVERSE_SETTINGS_DIR", os.path.join(os.path.dirname(__file__), "settings"))
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "runtime_settings.json")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def load_runtime_settings() -> Dict[str, Any]:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_runtime_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    current = load_runtime_settings()
    current_llm = current.get("llm") if isinstance(current.get("llm"), dict) else {}
    current_translator = current.get("translator") if isinstance(current.get("translator"), dict) else {}
    llm = settings.get("llm") if isinstance(settings.get("llm"), dict) else {}
    translator = settings.get("translator") if isinstance(settings.get("translator"), dict) else {}

    normalized = {
        "llm": {
            "provider": _clean(llm.get("provider")).lower(),
            "api_base": _clean(llm.get("api_base")).rstrip("/"),
            "api_key": _clean(llm.get("api_key")) or _clean(current_llm.get("api_key")),
            "model": _clean(llm.get("model")),
        },
        "translator": {
            "provider": _clean(translator.get("provider")).lower(),
            "api_base": _clean(translator.get("api_base")).rstrip("/"),
            "api_key": _clean(translator.get("api_key")) or _clean(current_translator.get("api_key")),
            "endpoint": _clean(translator.get("endpoint")) or "/translate",
            "text_field": _clean(translator.get("text_field")) or "q",
            "source_field": _clean(translator.get("source_field")) or "source",
            "target_field": _clean(translator.get("target_field")) or "target",
            "result_field": _clean(translator.get("result_field")) or "translatedText",
            "auth_header": _clean(translator.get("auth_header")),
            "auth_token": _clean(translator.get("auth_token")) or _clean(current_translator.get("auth_token")),
        },
    }

    if normalized["llm"]["provider"] not in ("ollama", "openai", "custom"):
        normalized["llm"]["provider"] = "ollama"
    if normalized["translator"]["provider"] not in ("off", "libretranslate", "custom"):
        normalized["translator"]["provider"] = "off"
    endpoint = normalized["translator"]["endpoint"]
    normalized["translator"]["endpoint"] = endpoint if endpoint.startswith("/") else f"/{endpoint}"

    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(normalized, f, ensure_ascii=False, indent=2)
    return normalized


def public_runtime_settings() -> Dict[str, Any]:
    data = load_runtime_settings()
    result = {
        "llm": dict(data.get("llm") or {}),
        "translator": dict(data.get("translator") or {}),
    }
    for section in ("llm", "translator"):
        if result[section].get("api_key"):
            result[section]["api_key_set"] = True
            result[section]["api_key"] = ""
    if result["translator"].get("auth_token"):
        result["translator"]["auth_token_set"] = True
        result["translator"]["auth_token"] = ""
    return result
