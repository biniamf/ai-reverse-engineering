# Biniam Demissie
"""Validated web-application configuration."""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """Raised when environment configuration is malformed or unsafe."""


# URL schemes we are willing to talk to. Anything else (file://, gopher://,
# javascript:, ftp://, ...) is rejected so a misconfigured environment cannot
# redirect outbound requests to an unexpected transport.
_ALLOWED_URL_SCHEMES = ("http", "https")

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})

# Tri-state streaming preference for the LLM transport. auto -> attempt streaming; fall
# back to a blocking call once if the provider rejects streaming+tools before any output
# is committed.
STREAM_AUTO = "auto"
STREAM_TRUE = "true"
STREAM_FALSE = "false"

# Accepted spellings for each tri-state value. Robust parsing folds common
# boolean-ish synonyms onto true/false and anything empty/unset onto auto, so a
# provider-neutral default (attempt-then-fall-back) holds without config.
_STREAM_AUTO_VALUES = frozenset({"auto", "default"})
_STREAM_TRUE_VALUES = frozenset({"true", "1", "yes", "on", "always", "stream"})
_STREAM_FALSE_VALUES = frozenset(
    {"false", "0", "no", "off", "never", "block", "blocking"}
)


def _get_stream_mode(env: Mapping[str, str], name: str, default: str) -> str:
    """Parse the tri-state LLM streaming preference (auto|true|false)."""
    raw = env.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered == "":
        return default
    if lowered in _STREAM_AUTO_VALUES:
        return STREAM_AUTO
    if lowered in _STREAM_TRUE_VALUES:
        return STREAM_TRUE
    if lowered in _STREAM_FALSE_VALUES:
        return STREAM_FALSE
    raise ConfigError(
        f"{name} must be one of auto|true|false (or a recognized synonym), "
        f"got {raw!r}"
    )


def _validate_url(value: str, name: str) -> str:
    """Validate and normalize an outbound base URL."""
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a non-empty URL")
    normalized = value.strip().rstrip("/")
    parts = urlsplit(normalized)
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise ConfigError(
            f"{name} has unsupported URL scheme {parts.scheme!r}; "
            f"allowed schemes are {_ALLOWED_URL_SCHEMES}"
        )
    if not parts.netloc:
        raise ConfigError(f"{name} must include a host, got {value!r}")
    return normalized


def _get_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number, got {raw!r}")
    if not math.isfinite(value):
        raise ConfigError(f"{name} must be a finite number, got {raw!r}")
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value!r}")
    return value


def _get_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    min_value: int = 1,
    max_value: Optional[int] = None,
) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be an integer, got {raw!r}")
    if value < min_value:
        raise ConfigError(f"{name} must be >= {min_value}, got {value!r}")
    if max_value is not None and value > max_value:
        raise ConfigError(f"{name} must be <= {max_value}, got {value!r}")
    return value


def _get_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean-like value, got {raw!r}")


def _default_chats_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "chats")


@dataclass(frozen=True)
class Config:
    """Immutable, validated application configuration."""

    # LLM provider (startup only; never exposed via a writable route).
    api_base: Optional[str]
    api_key: str
    model_name: Optional[str]

    # Streaming transport preference: "auto" | "true" | "false" (see _get_stream_mode).
    # Provider-neutral; controls only whether the assistant requests a streamed vs.
    # blocking chat completion, never any provider- specific parameter.
    llm_stream: str

    # Ghidra service.
    ghidra_api_base: str

    connect_timeout: float
    read_timeout: float
    llm_timeout: float

    max_upload_bytes: int
    max_response_bytes: int
    max_tool_result_chars: int
    max_context_chars: int
    # Default per-turn budgets when the analyst requests nothing: copilot uses
    # ``max_agent_turns``, autonomous uses the workflow's default or
    # ``max_autonomous_steps``. A larger runtime request (or "unbounded") is
    # honored up to ``max_step_budget`` -- the absolute safety cap below.
    max_agent_turns: int
    max_autonomous_steps: int
    # Hard ceiling on any single run's step budget, including "unbounded". No
    # request can exceed it, so a looping/confused model cannot drain the key.
    max_step_budget: int

    chats_dir: str

    # Bounded per-job summary/evidence cache (Phase 6). Immutable data only.
    summary_cache_ttl: float
    summary_cache_max_entries: int

    log_level: str
    log_file: Optional[str]
    log_max_bytes: int
    log_backup_count: int

    host: str
    port: int
    debug: bool

    @property
    def request_timeout(self) -> tuple:
        """(connect, read) timeout tuple for the requests library."""
        return (self.connect_timeout, self.read_timeout)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        if env is None:
            env = os.environ

        api_base = env.get("API_BASE") or None
        if api_base is not None:
            api_base = _validate_url(api_base, "API_BASE")

        ghidra_api_base = _validate_url(
            env.get("GHIDRA_API_BASE") or "http://127.0.0.1:9090",
            "GHIDRA_API_BASE",
        )

        chats_dir = env.get("CHATS_DIR") or _default_chats_dir()

        host = env.get("HOST") or "127.0.0.1"
        if not host.strip():
            raise ConfigError("HOST must be non-empty")

        log_level = (env.get("LOG_LEVEL") or "INFO").strip().upper()
        _VALID_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        if log_level not in _VALID_LEVELS:
            raise ConfigError(
                f"LOG_LEVEL must be one of {sorted(_VALID_LEVELS)}, got {log_level!r}"
            )
        log_file = env.get("LOG_FILE") or None

        return cls(
            api_base=api_base,
            api_key=env.get("API_KEY") or "not-used",
            model_name=env.get("MODEL_NAME") or None,
            llm_stream=_get_stream_mode(env, "LLM_STREAM", STREAM_AUTO),
            ghidra_api_base=ghidra_api_base,
            connect_timeout=_get_float(env, "CONNECT_TIMEOUT", 5.0),
            read_timeout=_get_float(env, "READ_TIMEOUT", 30.0),
            llm_timeout=_get_float(env, "LLM_TIMEOUT", 60.0),
            max_upload_bytes=_get_int(env, "MAX_UPLOAD_BYTES", 100 * 1024 * 1024),
            max_response_bytes=_get_int(env, "MAX_RESPONSE_BYTES", 25 * 1024 * 1024),
            max_tool_result_chars=_get_int(env, "MAX_TOOL_RESULT_CHARS", 20000),
            max_context_chars=_get_int(env, "MAX_CONTEXT_CHARS", 100000),
            max_agent_turns=_get_int(env, "MAX_AGENT_TURNS", 5),
            max_autonomous_steps=_get_int(env, "MAX_AUTONOMOUS_STEPS", 12),
            max_step_budget=_get_int(env, "MAX_STEP_BUDGET", 50),
            chats_dir=chats_dir,
            summary_cache_ttl=_get_float(env, "SUMMARY_CACHE_TTL", 300.0),
            summary_cache_max_entries=_get_int(
                env, "SUMMARY_CACHE_MAX_ENTRIES", 128
            ),
            log_level=log_level,
            log_file=log_file,
            log_max_bytes=_get_int(env, "LOG_MAX_BYTES", 5 * 1024 * 1024),
            log_backup_count=_get_int(env, "LOG_BACKUP_COUNT", 3, min_value=0),
            host=host.strip(),
            port=_get_int(env, "PORT", 5000, min_value=1, max_value=65535),
            debug=_get_bool(env, "DEBUG", False),
        )
