import os
import re
from typing import Any, Dict, List, Tuple


def _normalize_cpp_type(text: str) -> str:
    replacements = [
        (r"\bundefined4\b", "DWORD"),
        (r"\bundefined2\b", "WORD"),
        (r"\bundefined1\b", "BYTE"),
        (r"\bundefined\b", "void"),
        (r"\bbyte\b", "BYTE"),
        (r"\buint\b", "UINT"),
        (r"\bulong\b", "DWORD"),
    ]
    result = text or ""
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    return result


def _apply_known_renames(text: str, index: Dict[str, Any]) -> str:
    stages = index.get("stages", {})
    rename_map: Dict[str, str] = {}
    rename_map.update(stages.get("helper_renames", {}))
    rename_map.update(stages.get("function_pointer_globals", {}))
    rename_map.update(stages.get("dynamic_modules", {}))

    for old_name, new_name in sorted(rename_map.items(), key=lambda item: len(item[0]), reverse=True):
        if not old_name or not new_name:
            continue
        text = re.sub(rf"\b{re.escape(old_name)}\b", new_name, text)
    return text


def _load_decompile_text(artifacts_dir: str, addr: str, fallback: str) -> str:
    normalized = (addr or "").lower()
    filename = f"decompile_{normalized}.c"
    path = os.path.join(artifacts_dir, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return fallback or ""


def _score_function(fn: Dict[str, Any]) -> Tuple[int, int]:
    name = fn.get("name", "")
    signature = fn.get("signature", "")
    score = 0
    if name and not name.startswith("FUN_"):
        score += 80
    if "__thiscall" in signature or "this" in signature:
        score += 40
    if "GetProcAddress" in (fn.get("decompiled_excerpt") or ""):
        score += 30
    if fn.get("size", 0) > 40:
        score += 10
    if fn.get("is_thunk") or fn.get("is_external") or fn.get("is_library"):
        score -= 100
    return score, int(fn.get("size", 0) or 0)


def select_function_drafts(functions: List[Dict[str, Any]], limit: int = 80) -> List[Dict[str, Any]]:
    candidates = [
        fn for fn in functions or []
        if not fn.get("is_external") and not fn.get("is_library") and not fn.get("is_thunk")
    ]
    candidates.sort(key=_score_function, reverse=True)
    return candidates[:limit]


def render_function_drafts(
    job_id: str,
    index: Dict[str, Any],
    functions: List[Dict[str, Any]],
    artifacts_dir: str,
    limit: int = 80,
) -> str:
    selected = select_function_drafts(functions, limit=limit)
    lines = [
        '#include "recovered_symbols.h"',
        "",
        "/*",
        "  Auto-generated function recovery draft.",
        "  This file is intentionally non-compiling draft material: each function body",
        "  is preserved from Ghidra pseudocode after conservative type/name cleanup.",
        "  Use AI per-function reconstruction to turn individual drafts into compilable VC++ 2003 code.",
        f"  Job: {job_id}",
        "*/",
        "",
    ]

    for fn in selected:
        name = fn.get("name", "unknown")
        addr = fn.get("addr", "")
        signature = _normalize_cpp_type(fn.get("signature", ""))
        raw = _load_decompile_text(artifacts_dir, addr, fn.get("decompiled_excerpt", ""))
        cleaned = _apply_known_renames(_normalize_cpp_type(raw), index).strip()
        lines.append(f"/*")
        lines.append(f"  Function: {name}")
        lines.append(f"  Address: {addr}")
        lines.append(f"  Signature: {signature}")
        lines.append(f"  Status: decompiler draft, not yet manually verified")
        lines.append(f"*/")
        lines.append("#if 0")
        lines.append(cleaned)
        lines.append("#endif")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_function_draft_file(
    job_id: str,
    index: Dict[str, Any],
    functions: List[Dict[str, Any]],
    artifacts_dir: str,
    output_dir: str,
    limit: int = 80,
) -> Dict[str, Any]:
    content = render_function_drafts(
        job_id=job_id,
        index=index,
        functions=functions,
        artifacts_dir=artifacts_dir,
        limit=limit,
    )
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "recovered_functions.cpp")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return {
        "name": "recovered_functions.cpp",
        "path": path,
        "size": os.path.getsize(path),
        "function_drafts": min(limit, len(functions or [])),
    }
