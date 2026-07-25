# Biniam Demissie
"""Bounded context construction for the agent loop."""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, List

# Marker text is asserted by tests, so keep it stable.
TOOL_RESULT_OMITTED_MARKER = "... [tool result truncated]"
REPEATED_RESULT_MARKER = "[identical tool result omitted]"
DROPPED_MESSAGES_MARKER = "[earlier conversation omitted to fit context budget]"

# Fields safe to persist and replay. Anything else on a message dict (notably provider
# reasoning/thinking) is dropped at this choke point. ``subresult`` is app-authored
# provenance metadata for a returned sub-investigation.
_PERSISTED_MESSAGE_KEYS = frozenset(
    {"role", "content", "name", "tool_call_id", "tool_calls", "subresult"}
)
_MODEL_MESSAGE_KEYS = frozenset(
    {"role", "content", "name", "tool_call_id", "tool_calls"}
)
# Backwards-compatible private alias for tests/importers that reference the old
# name; persistence remains the default sanitization behavior.
_ALLOWED_MESSAGE_KEYS = _PERSISTED_MESSAGE_KEYS


def _message_length(message: Dict[str, Any]) -> int:
    return len(json.dumps(message, sort_keys=True, default=str))


def sanitize_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Copy a message keeping only persistence-safe keys."""
    return {
        k: copy.deepcopy(v)
        for k, v in message.items()
        if k in _PERSISTED_MESSAGE_KEYS
    }


def sanitize_model_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Copy a message into the OpenAI-compatible request schema."""
    return {
        k: copy.deepcopy(v) for k, v in message.items() if k in _MODEL_MESSAGE_KEYS
    }


def cap_tool_result(content: str, max_chars: int) -> str:
    """Cap a single tool-result string, appending an explicit marker."""
    if max_chars <= 0 or len(content) <= max_chars:
        return content
    keep = max(0, max_chars - len(TOOL_RESULT_OMITTED_MARKER))
    return content[:keep] + TOOL_RESULT_OMITTED_MARKER


def build_context(
    messages: List[Dict[str, Any]],
    *,
    max_tool_result_chars: int,
    max_context_chars: int,
) -> List[Dict[str, Any]]:
    """Return a bounded, deterministic copy of ``messages``."""
    # Provider-bound messages use the stricter schema (no app-only provenance
    # keys such as ``subresult``); persistence uses sanitize_message above.
    sanitized: List[Dict[str, Any]] = [sanitize_model_message(m) for m in messages]

    # Pass 1: cap each tool result, then collapse EARLIER identical repeats while
    # always keeping the most recent occurrence intact. Collapsing the latest
    # copy would blank the evidence the current turn just re-fetched, leaving the
    # model with a bare marker and no data to cite -- which is worse than a repeat.
    tool_msgs = [m for m in sanitized if m.get("role") == "tool"
                 and isinstance(m.get("content"), str)]
    for msg in tool_msgs:
        msg["content"] = cap_tool_result(msg["content"], max_tool_result_chars)
    last_index_by_content: Dict[str, int] = {}
    for i, msg in enumerate(tool_msgs):
        last_index_by_content[msg["content"]] = i
    for i, msg in enumerate(tool_msgs):
        if last_index_by_content.get(msg["content"]) != i:
            msg["content"] = REPEATED_RESULT_MARKER

    if _total_length(sanitized) <= max_context_chars:
        return sanitized

    head: List[Dict[str, Any]] = []
    body = sanitized
    if sanitized and sanitized[0].get("role") == "system":
        head = [sanitized[0]]
        body = sanitized[1:]

    kept_tail: List[Dict[str, Any]] = []
    running = _total_length(head)
    marker_msg = {"role": "system", "content": DROPPED_MESSAGES_MARKER}
    marker_len = _message_length(marker_msg)

    for msg in reversed(body):
        msg_len = _message_length(msg)
        if running + msg_len + marker_len <= max_context_chars:
            kept_tail.append(msg)
            running += msg_len
        else:
            break

    kept_tail.reverse()

    # A tool message must follow the assistant tool_calls message that spawned it, or an
    # OpenAI-compatible API rejects the request. If truncation would leave a leading
    # orphan tool response (its parent assistant message was dropped), drop those
    # orphans too.
    while kept_tail and kept_tail[0].get("role") == "tool":
        kept_tail.pop(0)

    dropped = len(body) - len(kept_tail)
    result = list(head)
    if dropped > 0:
        result.append(marker_msg)
    result.extend(kept_tail)
    return result


def _total_length(messages: List[Dict[str, Any]]) -> int:
    return sum(_message_length(m) for m in messages)
