import re
from typing import Any, Dict, Iterable, List


BASE_NAME_RE = r"(?:param_\d+|this|local_[0-9a-fA-F]+|puVar\d+|piVar\d+|pcVar\d+|pbVar\d+|p\w+)"
OFFSET_RE = r"(?:0x[0-9a-fA-F]+|\d+)"


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _normalize_base_name(base: str) -> str:
    if base == "this":
        return "this"
    return base


def _field_type_from_context(type_hint: str, expression: str) -> str:
    hint = (type_hint or "").strip()
    expr = expression or ""
    if "char *" in hint or "char *" in expr:
        return "char *"
    if "byte" in hint.lower() or "undefined1" in hint:
        return "BYTE"
    if "ushort" in hint.lower() or "undefined2" in hint:
        return "WORD"
    if "uint" in hint.lower() or "ulong" in hint.lower() or "undefined4" in hint:
        return "DWORD"
    if "*" in hint:
        return "void *"
    return "DWORD"


def _field_name(offset: int, field_type: str) -> str:
    prefix = {
        "BYTE": "b",
        "WORD": "w",
        "DWORD": "dw",
        "char *": "psz",
        "void *": "p",
    }.get(field_type, "field")
    return f"{prefix}_{offset:02X}"


def _record_field(fields: Dict[int, Dict[str, Any]], offset: int, field_type: str, expression: str, function_addr: str, source: str):
    entry = fields.setdefault(offset, {
        "offset": offset,
        "offset_hex": f"0x{offset:X}",
        "type": field_type,
        "name": _field_name(offset, field_type),
        "confidence": "low",
        "evidence": [],
    })
    if entry["type"] == "DWORD" and field_type != "DWORD":
        entry["type"] = field_type
        entry["name"] = _field_name(offset, field_type)
    evidence = {"function": function_addr, "expression": expression.strip(), "source": source}
    if evidence not in entry["evidence"]:
        entry["evidence"].append(evidence)
    strong_functions = {
        item.get("function")
        for item in entry["evidence"]
        if item.get("source") in {"byte_cast_offset", "cast_offset"}
    }
    if len(strong_functions) >= 2:
        entry["confidence"] = "medium"


def extract_structure_candidates_from_text(function_addr: str, text: str) -> Dict[str, Any]:
    candidates: Dict[str, Any] = {}
    if not text:
        return candidates

    patterns = [
        re.compile(
            rf"\*\s*\(\s*([A-Za-z_][A-Za-z0-9_\s\*]+?)\s*\*\s*\)\s*\(\s*\(\s*int\s*\)\s*({BASE_NAME_RE})\s*\+\s*({OFFSET_RE})\s*\)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\*\s*\(\s*([A-Za-z_][A-Za-z0-9_\s\*]+?)\s*\*\s*\)\s*\(\s*({BASE_NAME_RE})\s*\+\s*({OFFSET_RE})\s*\)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\(\s*int\s*\)\s*({BASE_NAME_RE})\s*\+\s*({OFFSET_RE})",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\(\s*({BASE_NAME_RE})\s*\+\s*({OFFSET_RE})\s*\)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"({BASE_NAME_RE})\[(0x[0-9a-fA-F]+|\d+)\]",
            re.IGNORECASE,
        ),
    ]

    for pattern_index, pattern in enumerate(patterns):
        for match in pattern.finditer(text):
            if pattern_index in {0, 1}:
                type_hint, base, offset_text = match.groups()
                source = "byte_cast_offset" if pattern_index == 0 else "cast_offset"
            else:
                type_hint = ""
                base, offset_text = match.groups()
                source = "array_index" if pattern_index == 4 else "byte_paren_offset" if pattern_index == 2 else "paren_offset"

            try:
                offset = _parse_int(offset_text)
            except ValueError:
                continue
            if base == "this" and source in {"array_index", "cast_offset", "paren_offset"}:
                offset = offset * 4
            if offset < 0 or offset > 0x4000:
                continue

            base = _normalize_base_name(base)
            struct_name = "RecoveredThis" if base == "this" else f"Recovered_{base}"
            candidate = candidates.setdefault(base, {
                "base": base,
                "suggested_name": struct_name,
                "fields": {},
            })
            field_type = _field_type_from_context(type_hint, match.group(0))
            _record_field(candidate["fields"], offset, field_type, match.group(0), function_addr, source)

    for candidate in candidates.values():
        candidate["fields"] = [
            field for _, field in sorted(candidate["fields"].items(), key=lambda item: item[0])
        ]

    return candidates


def merge_structure_candidates(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for item in items:
        for base, candidate in item.items():
            target = merged.setdefault(base, {
                "base": base,
                "suggested_name": candidate.get("suggested_name", f"Recovered_{base}"),
                "fields": {},
            })
            for field in candidate.get("fields", []):
                offset = field["offset"]
                target_field = target["fields"].setdefault(offset, {
                    "offset": offset,
                    "offset_hex": field["offset_hex"],
                    "type": field["type"],
                    "name": field["name"],
                    "confidence": field.get("confidence", "low"),
                    "evidence": [],
                })
                for evidence in field.get("evidence", []):
                    if evidence not in target_field["evidence"]:
                        target_field["evidence"].append(evidence)
                strong_functions = {
                    item.get("function")
                    for item in target_field["evidence"]
                    if item.get("source") in {"byte_cast_offset", "cast_offset"}
                }
                if len(strong_functions) >= 2:
                    target_field["confidence"] = "medium"

    result = {}
    for base, candidate in merged.items():
        fields = [
            field for _, field in sorted(candidate["fields"].items(), key=lambda item: item[0])
        ]
        if not fields:
            continue
        candidate["fields"] = fields
        result[base] = candidate
    return result


def get_renderable_structure_candidates(structure_candidates: Dict[str, Any]) -> Dict[str, Any]:
    renderable: Dict[str, Any] = {}
    for key, candidate in structure_candidates.items():
        base = candidate.get("base", "")
        if not (base == "this" or base.startswith("param_")):
            continue
        fields = [
            field for field in candidate.get("fields", [])
            if field.get("confidence") in {"medium", "high"}
        ]
        if base == "this" and len(fields) > 24:
            continue
        if base.startswith("param_") and len(fields) > 12:
            continue
        if not fields:
            continue
        filtered = dict(candidate)
        filtered["fields"] = fields
        renderable[key] = filtered
    return renderable


def render_structure_declarations(structure_candidates: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    renderable = get_renderable_structure_candidates(structure_candidates)
    if not renderable:
        return lines

    lines.append("/* Structure/layout candidates from pointer offset usage */")
    for _, candidate in sorted(renderable.items()):
        lines.append(f"struct {candidate['suggested_name']}")
        lines.append("{")
        last_end = 0
        for field in candidate.get("fields", []):
            offset = field["offset"]
            if offset > last_end:
                lines.append(f"    BYTE gap_{last_end:02X}[0x{offset - last_end:X}];")
            lines.append(
                f"    {field['type']} {field['name']}; /* {field['offset_hex']}, confidence={field.get('confidence', 'low')} */"
            )
            size = 1 if field["type"] == "BYTE" else 2 if field["type"] == "WORD" else 4
            last_end = max(last_end, offset + size)
        lines.append("};")
        lines.append("")
    return lines
