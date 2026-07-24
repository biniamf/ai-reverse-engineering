# Biniam Demissie
"""Reusable, strict validation helpers."""
from __future__ import annotations

import re
from typing import Optional


class ValidationError(ValueError):
    """Raised when untrusted input fails validation."""


_JOB_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# A thread ID has the same shape as a job id: 32 hex chars (a uuid4().hex minted server-
# side).
_THREAD_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# A chat thread title is short free text (an analyst-typed label). We reject
# rather than coerce, matching sanitize_filename.
_MAX_THREAD_TITLE_LEN = 200

_ADDRESS_RE = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{1,16})$")

_PATH_SEPARATORS = ("/", "\\")

_MAX_FILENAME_LEN = 255
_MAX_QUERY_LEN = 1000
_MAX_LIMIT = 1000
_DEFAULT_LIMIT = 100
_MAX_OFFSET = 10_000_000


def validate_job_id(job_id: object) -> str:
    """Return the normalized lowercase job ID or raise ValidationError."""
    if not isinstance(job_id, str):
        raise ValidationError("job_id must be a string")
    candidate = job_id.strip()
    if not _JOB_ID_RE.match(candidate):
        raise ValidationError("job_id must be exactly 32 hexadecimal characters")
    return candidate.lower()


def validate_thread_id(thread_id: object) -> str:
    """Return the normalized lowercase thread ID or raise ValidationError."""
    if not isinstance(thread_id, str):
        raise ValidationError("thread_id must be a string")
    candidate = thread_id.strip()
    if not _THREAD_ID_RE.match(candidate):
        raise ValidationError("thread_id must be exactly 32 hexadecimal characters")
    return candidate.lower()


def sanitize_thread_title(title: object) -> str:
    """Validate a chat thread title and return it (trimmed) unchanged."""
    if not isinstance(title, str):
        raise ValidationError("thread title must be a string")
    candidate = title.strip()
    if not candidate:
        raise ValidationError("thread title must not be empty")
    if len(candidate) > _MAX_THREAD_TITLE_LEN:
        raise ValidationError(
            f"thread title must be at most {_MAX_THREAD_TITLE_LEN} characters"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValidationError("thread title must not contain control characters")
    return candidate


def normalize_address(address: object) -> str:
    """Return a normalized lowercase ``0x``-prefixed address."""
    if not isinstance(address, str):
        raise ValidationError("address must be a string")
    candidate = address.strip()
    match = _ADDRESS_RE.match(candidate)
    if not match:
        raise ValidationError(
            "address must be 1-16 hexadecimal digits, optionally 0x-prefixed"
        )
    return "0x" + match.group(1).lower()


def sanitize_filename(filename: object) -> str:
    """Validate an uploaded filename and return it unchanged (basename only)."""
    if not isinstance(filename, str):
        raise ValidationError("filename must be a string")
    candidate = filename.strip()
    if not candidate:
        raise ValidationError("filename must not be empty")
    if len(candidate) > _MAX_FILENAME_LEN:
        raise ValidationError(
            f"filename must be at most {_MAX_FILENAME_LEN} characters"
        )
    for sep in _PATH_SEPARATORS:
        if sep in candidate:
            raise ValidationError("filename must not contain path separators")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValidationError("filename must not contain control characters")
    if candidate in (".", ".."):
        raise ValidationError("filename must not be a dot name")
    return candidate


def validate_query(query: object, *, max_length: int = _MAX_QUERY_LEN) -> str:
    """Validate a search query string with a bounded length."""
    if not isinstance(query, str):
        raise ValidationError("query must be a string")
    candidate = query.strip()
    if not candidate:
        raise ValidationError("query must not be empty")
    if len(candidate) > max_length:
        raise ValidationError(f"query must be at most {max_length} characters")
    return candidate


def validate_pagination(
    offset: object = 0,
    limit: object = _DEFAULT_LIMIT,
    *,
    max_limit: int = _MAX_LIMIT,
    default_limit: int = _DEFAULT_LIMIT,
) -> tuple:
    """Return a validated ``(offset, limit)`` tuple with bounded ranges."""
    offset_value = _coerce_nonneg_int(offset, "offset", 0)
    if offset_value > _MAX_OFFSET:
        raise ValidationError(f"offset must be at most {_MAX_OFFSET}")

    if limit is None or limit == "":
        limit_value = default_limit
    else:
        limit_value = _coerce_nonneg_int(limit, "limit", default_limit)
        if limit_value < 1:
            raise ValidationError("limit must be >= 1")
        if limit_value > max_limit:
            raise ValidationError(f"limit must be at most {max_limit}")
    return offset_value, limit_value


# --------------------------------------------------------------------------- # Security
# index / attack-surface query validation (Phase 1B). These constants mirror the backend
# contract (SECURITY_INDEX_HANDOFF.md and security_models.CATEGORIES / BANDS).
SECURITY_BANDS = ("critical", "high", "medium", "low")
SECURITY_CATEGORIES = frozenset(
    {
        # v1 contract categories
        "attack_surface",
        "memory_safety",
        "format_string",
        "command_execution",
        "filesystem_loading",
        "integer_allocation",
        "auth_privilege",
        "crypto_verification",
        "indirect_call",
        "coverage_uncertainty",
        # scorer v2 additive categories (must stay in sync with the training
        # service's security_models.CATEGORIES)
        "native_interop",
        "android_input",
        "device_integrity",
        "anti_analysis",
        "mitigation",
    }
)
SECURITY_SORTS = ("score", "rank", "name")
SECURITY_ORDERS = ("asc", "desc")

_SECURITY_DEFAULT_LIMIT = 25
_SECURITY_MAX_LIMIT = 100


_SECURITY_MAX_QUERY_LEN = 256
_SECURITY_MAX_RANK = 10_000_000


def validate_security_query(
    offset: object = 0,
    limit: object = None,
    band: object = None,
    category: object = None,
    min_score: object = None,
    sort: object = "score",
    order: object = "desc",
    q: object = None,
    rank: object = None,
    *,
    default_limit: int = _SECURITY_DEFAULT_LIMIT,
    max_limit: int = _SECURITY_MAX_LIMIT,
) -> dict:
    """Return a validated ranked-functions query, or raise ``ValidationError``."""
    offset_value, limit_value = validate_pagination(
        offset,
        limit,
        max_limit=max_limit,
        default_limit=default_limit,
    )
    out: dict = {"offset": offset_value, "limit": limit_value}

    if q is not None and q != "":
        if not isinstance(q, str):
            raise ValidationError("q must be a string")
        candidate = q.strip()
        if candidate:
            if len(candidate) > _SECURITY_MAX_QUERY_LEN:
                raise ValidationError(
                    f"q must be at most {_SECURITY_MAX_QUERY_LEN} characters"
                )
            out["q"] = candidate

    if rank is not None and rank != "":
        rank_value = _coerce_nonneg_int(rank, "rank", 0)
        if rank_value < 1:
            raise ValidationError("rank must be a positive integer")
        if rank_value > _SECURITY_MAX_RANK:
            raise ValidationError(f"rank must be at most {_SECURITY_MAX_RANK}")
        out["rank"] = rank_value

    if band is not None and band != "":
        if not isinstance(band, str) or band not in SECURITY_BANDS:
            raise ValidationError(
                f"band must be one of {SECURITY_BANDS}"
            )
        out["band"] = band

    if category is not None and category != "":
        if not isinstance(category, str) or category not in SECURITY_CATEGORIES:
            raise ValidationError("category is not a recognized security category")
        out["category"] = category

    if min_score is not None and min_score != "":
        try:
            score = float(min_score)
        except (TypeError, ValueError):
            raise ValidationError("min_score must be a number")
        if score != score or score in (float("inf"), float("-inf")):
            raise ValidationError("min_score must be a finite number")
        if score < 0 or score > 100:
            raise ValidationError("min_score must be between 0 and 100")
        out["min_score"] = score

    sort_value = "score" if sort in (None, "") else sort
    if not isinstance(sort_value, str) or sort_value not in SECURITY_SORTS:
        raise ValidationError(f"sort must be one of {SECURITY_SORTS}")
    out["sort"] = sort_value

    order_value = "desc" if order in (None, "") else order
    if not isinstance(order_value, str) or order_value not in SECURITY_ORDERS:
        raise ValidationError(f"order must be one of {SECURITY_ORDERS}")
    out["order"] = order_value

    return out


def _coerce_nonneg_int(value: object, name: str, default: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValidationError(f"{name} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not re.fullmatch(r"[0-9]+", stripped or ""):
            raise ValidationError(f"{name} must be a non-negative integer")
        result = int(stripped)
    else:
        raise ValidationError(f"{name} must be an integer")
    if result < 0:
        raise ValidationError(f"{name} must be non-negative")
    return result
