import os
from dataclasses import dataclass
from runtime_settings import load_runtime_settings


LIBRETRANSLATE_DEFAULT_BASE = "http://localhost:5000"


@dataclass(frozen=True)
class TranslatorConfig:
    provider: str
    api_base: str
    api_key: str
    enabled: bool
    endpoint: str
    text_field: str
    source_field: str
    target_field: str
    result_field: str
    auth_header: str
    auth_token: str


def _clean_base_url(value: str) -> str:
    return (value or "").strip().rstrip("/")


def get_translator_config() -> TranslatorConfig:
    """Resolve optional machine translation settings for chat messages.

    LibreTranslate is supported because it is self-hostable and matches the
    local-first workflow. It is disabled until TRANSLATOR_PROVIDER is set,
    because Flask commonly uses the same localhost:5000 port as LibreTranslate.
    """
    saved = (load_runtime_settings().get("translator") or {})
    provider = (saved.get("provider") or os.getenv("TRANSLATOR_PROVIDER", "off")).strip().lower()
    enabled = provider not in ("", "off", "none", "disabled")
    api_base = saved.get("api_base") or os.getenv("LIBRETRANSLATE_API_BASE", os.getenv("TRANSLATOR_API_BASE", LIBRETRANSLATE_DEFAULT_BASE))
    api_key = saved.get("api_key") or os.getenv("LIBRETRANSLATE_API_KEY", os.getenv("TRANSLATOR_API_KEY", ""))
    endpoint = (saved.get("endpoint") or os.getenv("TRANSLATOR_ENDPOINT", "/translate")).strip() or "/translate"

    if provider == "custom":
        api_base = saved.get("api_base") or os.getenv("TRANSLATOR_API_BASE", api_base)
        api_key = saved.get("api_key") or os.getenv("TRANSLATOR_API_KEY", api_key)
        text_field = saved.get("text_field") or os.getenv("TRANSLATOR_TEXT_FIELD", "q")
        source_field = saved.get("source_field") or os.getenv("TRANSLATOR_SOURCE_FIELD", "source")
        target_field = saved.get("target_field") or os.getenv("TRANSLATOR_TARGET_FIELD", "target")
        result_field = saved.get("result_field") or os.getenv("TRANSLATOR_RESULT_FIELD", "translatedText")
    else:
        text_field = "q"
        source_field = "source"
        target_field = "target"
        result_field = "translatedText"

    return TranslatorConfig(
        provider=provider or "off",
        api_base=_clean_base_url(api_base),
        api_key=api_key,
        enabled=enabled,
        endpoint=endpoint if endpoint.startswith("/") else f"/{endpoint}",
        text_field=text_field,
        source_field=source_field,
        target_field=target_field,
        result_field=result_field,
        auth_header=(saved.get("auth_header") or os.getenv("TRANSLATOR_AUTH_HEADER", "")).strip(),
        auth_token=(saved.get("auth_token") or os.getenv("TRANSLATOR_AUTH_TOKEN", "")).strip(),
    )
