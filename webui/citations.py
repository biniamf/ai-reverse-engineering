# Biniam Demissie
"""Extract and validate machine-checkable citations from model output."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

_CITATION_RE = re.compile(
    r"\[(function|string|import):\s*([^\]]+?)\s*\]",
    re.IGNORECASE,
)

_ADDR_RE = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{1,16})$")


def canonicalize_address(value: str) -> str:
    """Canonicalize a citation/evidence address by its *integer* value."""
    match = _ADDR_RE.match(value.strip())
    if not match:
        return value.strip().lower()
    return "0x" + format(int(match.group(1), 16), "x")


# Backwards-compatible internal alias; kept so any external/legacy caller
# importing the old private name keeps working.
_normalize_addr = canonicalize_address


@dataclass
class EvidenceIndex:
    """Addresses/symbols the agent actually retrieved during a turn."""

    functions: Set[str] = field(default_factory=set)
    strings: Set[str] = field(default_factory=set)
    imports: Set[str] = field(default_factory=set)

    def add_function(self, addr: str) -> None:
        if addr:
            self.functions.add(canonicalize_address(addr))

    def add_string(self, addr: str) -> None:
        if addr:
            self.strings.add(canonicalize_address(addr))

    def add_import(self, name: str) -> None:
        if name:
            self.imports.add(name.strip().lower())

    def observe_tool_result(self, tool: str, result: Any) -> None:
        """Fold one tool result into the index, defensively."""
        result = _coerce(result)
        # Legacy list tools (notably imports) may return a bare top-level list;
        # the collection helpers below already support dicts AND lists. Do not
        # discard valid retrieved evidence merely because the wrapper is absent.
        if not isinstance(result, (dict, list)):
            return
        # Any address-like field anywhere becomes a citable function address for
        # list_functions/decompile/xrefs/query and the security tools (whose
        # items/detail carry ``addr``); strings/imports handled by name.
        if tool in (
            "list_functions",
            "decompile_function",
            "get_xrefs",
            "get_callgraph",
            "query_artifacts",
            "list_security_functions",
            "get_security_function",
            "get_security_summary",
        ):
            for addr in _collect_addresses(result):
                self.add_function(addr)
        if tool == "list_strings":
            for addr in _collect_string_addresses(result):
                self.add_string(addr)
        if tool == "list_imports":
            for name in _collect_import_names(result):
                self.add_import(name)
        if tool in (
            "list_security_functions",
            "get_security_function",
            "get_security_summary",
        ):
            # Scoring signals carry typed evidence refs nested under
            # items/signals/evidence (e.g. {kind:"import",ref:"memcpy"}). Fold those
            # exact deterministic refs into the citation index; the old one-level
            # generic collector cannot see this nested shape.
            for kind, ref in _collect_security_evidence_refs(result):
                if kind == "function":
                    self.add_function(ref)
                elif kind == "string":
                    self.add_string(ref)
                elif kind == "import":
                    self.add_import(ref)
        if tool == "query_artifacts":
            for addr in _collect_string_addresses(result):
                self.add_string(addr)
            for name in _collect_import_names(result):
                self.add_import(name)


def _coerce(result: Any) -> Any:
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (ValueError, TypeError):
            return {}
    return result


def _iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        yield item
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item


def _collect_addresses(result: Any) -> List[str]:
    out: List[str] = []
    for d in _iter_dicts(result):
        for key in ("address", "addr", "entry", "ea", "to", "from"):
            v = d.get(key)
            if isinstance(v, str) and _ADDR_RE.match(v.strip()):
                out.append(v)
    return out


def _collect_string_addresses(result: Any) -> List[str]:
    out: List[str] = []
    for d in _iter_dicts(result):
        v = d.get("address") or d.get("addr")
        if isinstance(v, str) and _ADDR_RE.match(v.strip()):
            out.append(v)
    return out


def _collect_import_names(result: Any) -> List[str]:
    out: List[str] = []
    for d in _iter_dicts(result):
        for key in ("name", "symbol", "function"):
            v = d.get(key)
            if isinstance(v, str) and v.strip():
                out.append(v)
    return out


def _collect_security_evidence_refs(result: Any) -> List[tuple[str, str]]:
    """Collect bounded typed refs nested in security signal documents."""
    out: List[tuple[str, str]] = []
    stack = [(result, 0)]
    visited = 0
    while stack and visited < 2000:
        value, depth = stack.pop()
        visited += 1
        if depth > 5:
            continue
        if isinstance(value, dict):
            kind = value.get("kind")
            ref = value.get("ref")
            if (
                kind in {"function", "string", "import"}
                and isinstance(ref, str)
                and ref.strip()
            ):
                out.append((kind, ref))
            for child in value.values():
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
        elif isinstance(value, list):
            for child in value[:500]:
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
    return out


def extract_citations(text: str) -> List[Dict[str, str]]:
    """Return the citations found in ``text`` in order of appearance."""
    if not isinstance(text, str) or not text:
        return []
    out: List[Dict[str, str]] = []
    for match in _CITATION_RE.finditer(text):
        kind = match.group(1).lower()
        raw_value = match.group(2).strip()
        if kind in ("function", "string"):
            value = canonicalize_address(raw_value)
        else:
            value = raw_value
        out.append({"kind": kind, "raw": match.group(0), "value": value})
    return out


def validate_citations(text: str, index: EvidenceIndex) -> Dict[str, Any]:
    """Validate the citations in ``text`` against retrieved evidence."""
    citations = extract_citations(text)
    valid: List[Dict[str, Any]] = []
    invalid: List[Dict[str, Any]] = []
    seen = set()
    for c in citations:
        key = (c["kind"], c["value"])
        if key in seen:
            continue
        seen.add(key)
        if c["kind"] == "function":
            ok = c["value"] in index.functions
        elif c["kind"] == "string":
            ok = c["value"] in index.strings
        else:  # import
            ok = c["value"].strip().lower() in index.imports
        entry = {**c, "valid": ok}
        (valid if ok else invalid).append(entry)

    warnings = [
        f"Citation {c['raw']} does not match any evidence retrieved this turn "
        "and may be unreliable."
        for c in invalid
    ]
    if (
        isinstance(text, str)
        and text.strip()
        and not citations
        and (index.functions or index.strings or index.imports)
    ):
        warnings.append(
            "The answer contains binary-specific claims but no machine-checkable "
            "citations, even though evidence was retrieved; treat it as unverified."
        )
    return {
        "citations": valid + invalid,
        "valid": valid,
        "invalid": invalid,
        "warnings": warnings,
    }
