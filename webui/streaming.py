# Biniam Demissie
# Streaming: provider-neutral OpenAI-compatible delta accumulator.
"""Pure accumulator for OpenAI-compatible Chat Completions streaming."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _get(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


class _ToolCallFragment:

    __slots__ = ("index", "id", "type", "name", "arguments")

    def __init__(self, index: int) -> None:
        self.index: int = index
        self.id: Optional[str] = None
        self.type: Optional[str] = None
        self.name: Optional[str] = None
        # Arguments arrive as a stream of string slices that must be
        # concatenated verbatim; start empty and never treat ``None`` as text.
        self.arguments: str = ""

    def update(self, fragment: Any) -> None:
        frag_id = _get(fragment, "id")
        if frag_id:
            self.id = frag_id
        frag_type = _get(fragment, "type")
        if frag_type:
            self.type = frag_type

        function = _get(fragment, "function")
        if function is not None:
            name = _get(function, "name")
            if name:
                if self.name is None:
                    self.name = name
                elif name != self.name and not self.name.endswith(name):
                    self.name += name
            args = _get(function, "arguments")
            if isinstance(args, str) and args:
                self.arguments += args

    def build(self) -> Dict[str, Any]:
        return {
            "id": self.id or "",
            "type": self.type or "function",
            "function": {
                "name": self.name or "",
                "arguments": self.arguments,
            },
        }


class StreamAccumulator:
    """Accumulates OpenAI-compatible streaming deltas into one message dict."""

    def __init__(self) -> None:
        self._content_parts: List[str] = []
        # Keyed by delta index; ``_tool_order`` preserves first-appearance order
        # so interleaved indices keep a stable output order regardless of how
        # the provider interleaves fragments.
        self._tool_calls: "Dict[int, _ToolCallFragment]" = {}
        self._tool_order: List[int] = []
        self._saw_tool_fragment = False
        self._saw_content = False

    def add_chunk(self, chunk: Any) -> str:
        """Fold one streamed chunk in; return the content text it added."""
        choices = _get(chunk, "choices")
        if not choices:
            return ""
        # A compliant stream has a single choice; be defensive and read the
        # first regardless.
        delta = _get(choices[0], "delta")
        if delta is None:
            return ""

        added = ""
        content = _get(delta, "content")
        if isinstance(content, str) and content:
            self._content_parts.append(content)
            self._saw_content = True
            added = content

        tool_calls = _get(delta, "tool_calls")
        if tool_calls:
            for frag in tool_calls:
                self._add_tool_fragment(frag)

        return added

    def _add_tool_fragment(self, frag: Any) -> None:
        index = _get(frag, "index")
        if index is None:
            # Without an index we cannot correlate fragments; fall back to the
            # last-seen call so a single-call stream that omits index still
            # assembles, else start a new one at 0.
            index = self._tool_order[-1] if self._tool_order else 0
        try:
            index = int(index)
        except (TypeError, ValueError):
            index = self._tool_order[-1] if self._tool_order else 0

        entry = self._tool_calls.get(index)
        if entry is None:
            entry = _ToolCallFragment(index)
            self._tool_calls[index] = entry
            self._tool_order.append(index)
        entry.update(frag)
        self._saw_tool_fragment = True

    @property
    def content(self) -> str:
        """The text accumulated so far (safe to persist as a partial answer)."""
        return "".join(self._content_parts)

    @property
    def has_tool_calls(self) -> bool:
        return self._saw_tool_fragment

    @property
    def has_any_fragment(self) -> bool:
        """True once any content or tool-call fragment has been observed."""
        return self._saw_content or self._saw_tool_fragment

    # ------------------------------------------------------------------ #
    # Assembly.
    # ------------------------------------------------------------------ #
    def build_message(self) -> Dict[str, Any]:
        """Assemble the final assistant message dict."""
        text = self.content
        message: Dict[str, Any] = {
            "role": "assistant",
            "content": text if text else None,
        }
        if self._saw_tool_fragment:
            message["tool_calls"] = [
                self._tool_calls[i].build() for i in self._tool_order
            ]
        return message
