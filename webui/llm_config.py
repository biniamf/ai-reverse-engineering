import os
from dataclasses import dataclass
from runtime_settings import load_runtime_settings


OLLAMA_DEFAULT_BASE = "http://localhost:11434/v1"
OLLAMA_DEFAULT_MODEL = "qwen2.5-coder:14b"
OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
OPENAI_DEFAULT_MODEL = "gpt-4.1-mini"


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    api_base: str
    api_key: str
    model: str


def _clean_base_url(value: str) -> str:
    return (value or "").strip().rstrip("/")


def get_llm_config() -> LLMConfig:
    """Resolve local, OpenAI, or custom OpenAI-compatible runtime settings.

    The project is local-first, so Ollama remains the default. The old global
    OpenAI-compatible mode is preserved through LLM_PROVIDER=openai, and custom
    gateways can still use the legacy API_BASE/API_KEY/MODEL_NAME variables.
    """
    saved = (load_runtime_settings().get("llm") or {})
    provider = (saved.get("provider") or os.getenv("LLM_PROVIDER", "")).strip().lower()
    if not provider:
        provider = "custom" if (saved.get("api_base") or os.getenv("API_BASE")) else "ollama"

    if provider == "openai":
        return LLMConfig(
            provider="openai",
            api_base=_clean_base_url(saved.get("api_base") or os.getenv("OPENAI_API_BASE", OPENAI_DEFAULT_BASE)),
            api_key=saved.get("api_key") or os.getenv("OPENAI_API_KEY", os.getenv("API_KEY", "")),
            model=saved.get("model") or os.getenv("OPENAI_MODEL", os.getenv("MODEL_NAME", OPENAI_DEFAULT_MODEL)),
        )

    if provider == "custom":
        return LLMConfig(
            provider="custom",
            api_base=_clean_base_url(saved.get("api_base") or os.getenv("API_BASE", OLLAMA_DEFAULT_BASE)),
            api_key=saved.get("api_key") or os.getenv("API_KEY", "not-used"),
            model=saved.get("model") or os.getenv("MODEL_NAME", OLLAMA_DEFAULT_MODEL),
        )

    return LLMConfig(
        provider="ollama",
        api_base=_clean_base_url(saved.get("api_base") or os.getenv("OLLAMA_API_BASE", os.getenv("API_BASE", OLLAMA_DEFAULT_BASE))),
        api_key=saved.get("api_key") or os.getenv("OLLAMA_API_KEY", os.getenv("API_KEY", "ollama")),
        model=saved.get("model") or os.getenv("OLLAMA_MODEL", os.getenv("MODEL_NAME", OLLAMA_DEFAULT_MODEL)),
    )
