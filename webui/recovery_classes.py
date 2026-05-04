import re
from typing import Any, Dict, Iterable, List


VTABLE_RE = re.compile(r"\*\s*this\s*=\s*&\s*(PTR_FUN_[0-9a-fA-F]+)", re.IGNORECASE)
DWORD_SLOT_RE = re.compile(r"\bthis\[(0x[0-9a-fA-F]+|\d+)\]\s*=", re.IGNORECASE)
BYTE_CAST_RE = re.compile(
    r"\*\s*\(\s*(undefined1|byte|char)\s*\*\s*\)\s*\(\s*((?:\(int\)\s*)?)this\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*=",
    re.IGNORECASE,
)


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _class_name_from_vtable(vtable: str) -> str:
    suffix = re.sub(r"[^0-9A-Fa-f]+", "", vtable)[-8:].upper()
    return f"RecoveredClass_{suffix}"


def extract_class_layout_candidates_from_text(function_addr: str, text: str) -> Dict[str, Any]:
    match = VTABLE_RE.search(text or "")
    if not match:
        return {}

    vtable = match.group(1)
    candidate = {
        "vtable": vtable,
        "suggested_name": _class_name_from_vtable(vtable),
        "constructors": [function_addr],
        "fields": {},
    }

    for slot in DWORD_SLOT_RE.findall(text or ""):
        offset = _parse_int(slot) * 4
        candidate["fields"].setdefault(offset, {
            "offset": offset,
            "offset_hex": f"0x{offset:X}",
            "type": "DWORD",
            "name": f"dw_{offset:03X}",
            "confidence": "medium",
            "evidence": [],
        })["evidence"].append({"function": function_addr, "expression": f"this[{slot}]"})

    for _, int_cast, offset_text in BYTE_CAST_RE.findall(text or ""):
        raw_offset = _parse_int(offset_text)
        offset = raw_offset if int_cast else raw_offset * 4
        candidate["fields"].setdefault(offset, {
            "offset": offset,
            "offset_hex": f"0x{offset:X}",
            "type": "BYTE",
            "name": f"b_{offset:03X}",
            "confidence": "medium",
            "evidence": [],
        })["evidence"].append({"function": function_addr, "expression": f"byte this+{offset_text}"})

    if not candidate["fields"]:
        return {}

    candidate["fields"] = [
        field for _, field in sorted(candidate["fields"].items(), key=lambda item: item[0])
    ]
    return {vtable: candidate}


def merge_class_layout_candidates(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for item in items:
        for vtable, candidate in item.items():
            target = merged.setdefault(vtable, {
                "vtable": vtable,
                "suggested_name": candidate.get("suggested_name", _class_name_from_vtable(vtable)),
                "constructors": [],
                "fields": {},
            })
            for ctor in candidate.get("constructors", []):
                if ctor not in target["constructors"]:
                    target["constructors"].append(ctor)
            for field in candidate.get("fields", []):
                existing = target["fields"].setdefault(field["offset"], dict(field, evidence=[]))
                for evidence in field.get("evidence", []):
                    if evidence not in existing["evidence"]:
                        existing["evidence"].append(evidence)

    result = {}
    for vtable, candidate in merged.items():
        candidate["fields"] = [
            field for _, field in sorted(candidate["fields"].items(), key=lambda item: item[0])
        ]
        result[vtable] = candidate
    return result


def render_class_layout_declarations(class_layouts: Dict[str, Any], limit: int = 40) -> List[str]:
    lines: List[str] = []
    if not class_layouts:
        return lines

    lines.append("/* Class layout candidates grouped by constructor vtable assignment */")
    for _, candidate in sorted(class_layouts.items())[:limit]:
        fields = candidate.get("fields", [])
        if not fields:
            continue
        lines.append(f"struct {candidate['suggested_name']}")
        lines.append("{")
        lines.append(f"    void **vftable; /* {candidate['vtable']} */")
        last_end = 4
        for field in fields:
            offset = field["offset"]
            if offset < 4:
                continue
            if offset > last_end:
                lines.append(f"    BYTE gap_{last_end:03X}[0x{offset - last_end:X}];")
            lines.append(f"    {field['type']} {field['name']}; /* {field['offset_hex']} */")
            size = 1 if field["type"] == "BYTE" else 4
            last_end = max(last_end, offset + size)
        ctor_comment = ", ".join(candidate.get("constructors", [])[:3])
        lines.append(f"}}; /* ctor(s): {ctor_comment} */")
        lines.append("")
    return lines
