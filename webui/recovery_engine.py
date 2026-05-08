import os
import json
import re
from typing import Any, Dict, Optional
from recovery_classes import (
    extract_class_layout_candidates_from_text,
    merge_class_layout_candidates,
    render_class_layout_declarations,
)
from recovery_functions import select_function_drafts, write_function_draft_file
from recovery_model import generate_types_header_with_model
from recovery_renamer import generate_ai_renames
from recovery_structures import (
    extract_structure_candidates_from_text,
    get_renderable_structure_candidates,
    merge_structure_candidates,
    render_structure_declarations,
)

ARTIFACTS_ROOT = os.getenv("GHIDRA_PROJECTS_DIR", os.path.join(os.getcwd(), "data"))
RECOVERY_DIR = os.path.join(os.path.dirname(__file__), "recovery")
RECOVERED_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "recovered")
ENUM_CANDIDATE_DENYLIST = {
    "WARNING", "TODO", "NULL", "TRUE", "FALSE",
    "BYTE", "WORD", "DWORD", "LONG", "ULONG", "UINT", "INT", "BOOL",
    "CHAR", "WCHAR", "FILE", "HANDLE", "HMODULE", "FARPROC",
    "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR", "LPCVOID", "LPVOID",
    "LPBOOL", "LPWORD", "LPDWORD", "LPWCH", "SIZE_T", "PVOID", "LCID",
    "LPCH", "LPOVERLAPPED", "PEXCEPTION_RECORD", "PLONG", "LARGE_INTEGER",
    "STRFLT", "INTRNCVT_STATUS",
    "KERNEL32", "USER32", "MSVCRT",
    "INF", "QNAN", "SNAN", "IND",
    "CONCAT11", "CONCAT12", "CONCAT13", "CONCAT22", "CONCAT31", "CONCAT44",
    "CONCAT21", "SUB41", "CARRY4", "SBORROW4",
}

def _extract_internal_call_addrs(text: str, max_calls: int = 4) -> list:
    seen = set()
    addrs = []
    for match in re.finditer(r"\bFUN_([0-9a-fA-F]{8})\b", text or ""):
        addr = f"0x{match.group(1).lower()}"
        if addr not in seen:
            seen.add(addr)
            addrs.append(addr)
        if len(addrs) >= max_calls:
            break
    return addrs

def _make_identifier(value: str) -> str:
    value = re.sub(r"^\?+", "", value or "")
    value = value.split("@")[0] if "@" in value else value
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")
    if not value:
        return "unknown"
    if value[0].isdigit():
        value = f"symbol_{value}"
    return value

def _extract_global_proc_assignments(text: str) -> Dict[str, str]:
    assignments = {}
    used_names = {}
    pattern = re.compile(
        r"\b(DAT_[0-9a-fA-F]+)\s*=\s*GetProcAddress\s*\([^,]+,\s*\"([^\"]+)\"\s*\)",
        re.IGNORECASE
    )
    for global_name, proc_name in pattern.findall(text or ""):
        base_name = f"pfn_{_make_identifier(proc_name)}"
        used_names[base_name] = used_names.get(base_name, 0) + 1
        suffix = f"_{used_names[base_name]}" if used_names[base_name] > 1 else ""
        assignments[global_name] = f"{base_name}{suffix}"
    return assignments

def _extract_getprocaddress_details(text: str) -> Dict[str, Dict[str, str]]:
    details = {}
    used_names = {}
    pattern = re.compile(
        r"\b(DAT_[0-9a-fA-F]+)\s*=\s*GetProcAddress\s*\(\s*([^,]+?)\s*,\s*\"([^\"]+)\"\s*\)",
        re.IGNORECASE
    )
    for global_name, module_expr, proc_name in pattern.findall(text or ""):
        base_name = f"pfn_{_make_identifier(proc_name)}"
        used_names[base_name] = used_names.get(base_name, 0) + 1
        suffix = f"_{used_names[base_name]}" if used_names[base_name] > 1 else ""
        details[global_name] = {
            "role": "function_pointer",
            "source": "GetProcAddress",
            "module_expr": module_expr.strip(),
            "target_name": proc_name,
            "inferred_name": f"{base_name}{suffix}",
        }
    return details

def _extract_indirect_calls(text: str) -> Dict[str, list]:
    calls = {}
    for match in re.finditer(r"\(\s*\*\s*(DAT_[0-9a-fA-F]+)\s*\)\s*\(([^)]*)\)", text or ""):
        global_name, args = match.groups()
        calls.setdefault(global_name, []).append({
            "arguments": args.strip(),
            "expression": match.group(0),
        })
    return calls

def _signature_to_typedef(signature: str, typedef_name: str) -> str:
    signature = signature or ""
    callconv = "__stdcall" if "__stdcall" in signature else "__cdecl" if "__cdecl" in signature else "__cdecl"
    params_match = re.search(r"\((.*)\)\s*$", signature)
    params = params_match.group(1).strip() if params_match else "void"
    if not params:
        params = "void"

    return_type = "int"
    if signature.startswith("void ") or " void " in signature[:24]:
        return_type = "void"
    elif signature.startswith("bool ") or " bool " in signature[:24]:
        return_type = "BOOL"
    elif signature.startswith("ulong ") or signature.startswith("uint ") or " unsigned long " in signature:
        return_type = "DWORD"
    elif signature.startswith("undefined4 "):
        return_type = "int"

    params = re.sub(r"\bundefined4\b", "DWORD", params)
    params = re.sub(r"\bundefined1\b", "BYTE", params)
    params = re.sub(r"\bchar \*", "LPCSTR ", params)
    return f"typedef {return_type} ({callconv} *{typedef_name})({params});"

def _build_signature_lookup(functions: list) -> Dict[str, Dict[str, str]]:
    lookup = {}
    for fn in functions or []:
        name = fn.get("name")
        if not name:
            continue
        lookup[name] = {
            "addr": fn.get("addr"),
            "signature": fn.get("signature", ""),
        }
    return lookup

def _extract_loadlibrary_globals(text: str) -> Dict[str, str]:
    rename_map = {}
    for match in re.finditer(r"\b(DAT_[0-9a-fA-F]+)\s*=\s*LoadLibraryA\s*\(\s*\"([^\"]+)\"", text or "", re.IGNORECASE):
        global_name, dll_path = match.groups()
        base = os.path.splitext(os.path.basename(dll_path.replace("\\", "/")))[0]
        identifier = _make_identifier(base)
        rename_map[global_name] = f"h{identifier[:1].upper()}{identifier[1:]}" if base else "hLoadedModule"
    return rename_map

def _infer_helper_name(addr: str, text: str) -> Optional[str]:
    if "LoadLibraryA" in text and "GetProcAddress" in text:
        dll_match = re.search(r"LoadLibraryA\s*\(\s*\"([^\"]+)\"", text)
        if dll_match:
            base = os.path.splitext(os.path.basename(dll_match.group(1).replace("\\", "/")))[0]
            return f"ensure_{_make_identifier(base).lower()}_loaded"
        return "ensure_module_loaded"
    if "_vsprintf" in text or "va_list" in text:
        return "log_debug"
    if "_fprintf" in text and "_fclose" in text:
        return "append_log_line"
    if "GetProcAddress" in text:
        return "resolve_imported_functions"
    if "LoadLibraryA" in text:
        return "load_runtime_library"
    return None

def _is_enum_candidate(name: str) -> bool:
    if name in ENUM_CANDIDATE_DENYLIST:
        return False
    if re.match(r"YA[A-Z0-9_]+$", name):
        return False
    if re.match(r"^(CONCAT|SUB|CARRY|SBORROW)\d+$", name):
        return False
    if name.startswith("LP") and len(name) > 3:
        return False
    if name.endswith("_T"):
        return False
    return True

def _read_json_file(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _get_artifacts_dir(job_id: str) -> str:
    return os.path.join(ARTIFACTS_ROOT, job_id, "artifacts")

def _load_artifact_json(job_id: str, filename: str, default: Any) -> Any:
    return _read_json_file(os.path.join(_get_artifacts_dir(job_id), filename), default)

def _normalize_hex_address(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.upper().startswith("FUN_"):
        text = text[4:]
    text = text.lower()
    if text.startswith("0x"):
        digits = text[2:]
    else:
        digits = text
    if not re.fullmatch(r"[0-9a-f]+", digits or ""):
        return ""
    return f"0x{digits.zfill(8)}"

def _function_address_value(fn: Dict[str, Any]) -> int:
    normalized = _normalize_hex_address(fn.get("addr") or fn.get("address"))
    if not normalized:
        return -1
    try:
        return int(normalized, 16)
    except ValueError:
        return -1

def _find_containing_function(functions: list, address: str) -> Optional[Dict[str, Any]]:
    addr_value = _function_address_value({"addr": address})
    if addr_value < 0:
        return None
    best = None
    for fn in functions or []:
        if not isinstance(fn, dict):
            continue
        start = _function_address_value(fn)
        size = int(fn.get("size") or 0)
        if start < 0:
            continue
        end = start + max(size, 1)
        if start <= addr_value < end:
            if best is None or start > _function_address_value(best):
                best = fn
    return best

def _symbol_display_name(symbol: Dict[str, Any]) -> str:
    renamed = symbol.get("renamed")
    original = symbol.get("original")
    return renamed or original or symbol.get("name") or symbol.get("address") or "unknown"

def _iter_decompile_artifacts(job_id: str):
    artifacts_dir = _get_artifacts_dir(job_id)
    if not os.path.isdir(artifacts_dir):
        return

    for filename in os.listdir(artifacts_dir):
        if not filename.startswith("decompile_") or not filename.endswith(".c"):
            continue
        path = os.path.join(artifacts_dir, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception:
            continue
        addr = filename[len("decompile_"):-len(".c")]
        yield addr, text

def _extract_msvc_decorated_symbol(symbol: str) -> Optional[Dict[str, str]]:
    match = re.match(r"\?([^@]+)@([^@]+)@@", symbol or "")
    if not match:
        return None
    member_name, owner_name = match.groups()
    return {
        "decorated": symbol,
        "owner": _make_identifier(owner_name),
        "member": _make_identifier(member_name),
    }

def _extract_cpp_owner_from_text(text: str) -> list:
    owners = []
    for owner, member in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)::(~?[A-Za-z_][A-Za-z0-9_]*|operator=)\b", text or ""):
        owners.append({"owner": _make_identifier(owner), "member": _make_identifier(member)})
    return owners

def _interesting_strings(strings: list, limit: int = 80) -> list:
    result = []
    for item in strings:
        value = item.get("s") if isinstance(item, dict) else str(item)
        if not value or len(value) < 5:
            continue
        if not re.search(r"[A-Za-z_./\\]", value):
            continue
        if sum(ch.isprintable() for ch in value) < len(value):
            continue
        result.append(item)
        if len(result) >= limit:
            break
    return result

def build_recovery_index(job_id: str, force: bool = False) -> Dict[str, Any]:
    os.makedirs(RECOVERY_DIR, exist_ok=True)
    index_path = os.path.join(RECOVERY_DIR, f"{job_id}.json")
    if not force and os.path.exists(index_path):
        return _read_json_file(index_path, {})

    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    imports = _load_artifact_json(job_id, "imports.json", [])
    strings = _load_artifact_json(job_id, "strings.json", [])

    index = {
        "job_id": job_id,
        "metadata": {
            "program_name": functions_data.get("program_name") if isinstance(functions_data, dict) else None,
            "language": functions_data.get("language") if isinstance(functions_data, dict) else None,
            "compiler": functions_data.get("compiler") if isinstance(functions_data, dict) else None,
            "image_base": functions_data.get("image_base") if isinstance(functions_data, dict) else None,
            "function_count": len(functions or []),
        },
        "stages": {
            "imports": imports[:200] if isinstance(imports, list) else imports,
            "interesting_strings": _interesting_strings(strings if isinstance(strings, list) else []),
            "dynamic_modules": {},
            "function_pointer_globals": {},
            "function_pointer_details": {},
            "function_pointer_typedefs": {},
            "indirect_calls": {},
            "helper_renames": {},
            "cpp_owners": {},
            "class_layouts": {},
            "global_roles": {},
            "enum_candidates": {},
            "structure_candidates": {},
        }
    }
    signature_lookup = _build_signature_lookup(functions)

    decorated_symbols = set()
    for item in index["stages"]["interesting_strings"]:
        value = item.get("s") if isinstance(item, dict) else str(item)
        if value.startswith("?"):
            decorated_symbols.add(value)

    for fn in functions or []:
        for value in (fn.get("name"), fn.get("signature")):
            if value and "?" in value:
                decorated_symbols.add(value)
        cpp_text = "\n".join([fn.get("signature", ""), fn.get("decompiled_excerpt", "")])
        for parsed in _extract_cpp_owner_from_text(cpp_text):
            owner = parsed["owner"]
            index["stages"]["cpp_owners"].setdefault(owner, {"members": [], "decorated_symbols": []})
            index["stages"]["cpp_owners"][owner]["members"].append(parsed["member"])

    for symbol in decorated_symbols:
        parsed = _extract_msvc_decorated_symbol(symbol)
        if not parsed:
            continue
        owner = parsed["owner"]
        index["stages"]["cpp_owners"].setdefault(owner, {"members": [], "decorated_symbols": []})
        index["stages"]["cpp_owners"][owner]["members"].append(parsed["member"])
        index["stages"]["cpp_owners"][owner]["decorated_symbols"].append(parsed["decorated"])

    structure_candidate_items = []
    class_layout_items = []
    for addr, text in _iter_decompile_artifacts(job_id) or []:
        structure_candidate_items.append(extract_structure_candidates_from_text(addr, text))
        class_layout_items.append(extract_class_layout_candidates_from_text(addr, text))
        helper_name = _infer_helper_name(addr, text)
        if helper_name:
            index["stages"]["helper_renames"][f"FUN_{addr[2:].lower()}"] = helper_name

        for global_name, proc_name in _extract_global_proc_assignments(text).items():
            index["stages"]["function_pointer_globals"][global_name] = proc_name
            index["stages"]["global_roles"][global_name] = "function_pointer"

        for global_name, detail in _extract_getprocaddress_details(text).items():
            index["stages"]["function_pointer_details"][global_name] = detail
            target_info = signature_lookup.get(detail["target_name"])
            if target_info:
                typedef_name = "PFN_" + re.sub(r"^pfn_", "", detail["inferred_name"]).upper()
                index["stages"]["function_pointer_typedefs"][global_name] = {
                    "typedef_name": typedef_name,
                    "typedef": _signature_to_typedef(target_info.get("signature", ""), typedef_name),
                    "source_function": detail["target_name"],
                    "source_addr": target_info.get("addr"),
                    "confidence": "medium",
                    "evidence": "local function/export with same name as GetProcAddress target",
                }

        for global_name, call_list in _extract_indirect_calls(text).items():
            entries = index["stages"]["indirect_calls"].setdefault(global_name, [])
            for call in call_list:
                call["caller_artifact"] = addr
                entries.append(call)
            index["stages"]["global_roles"].setdefault(global_name, "indirect_call_target")

        for global_name, module_name in _extract_loadlibrary_globals(text).items():
            index["stages"]["dynamic_modules"][global_name] = module_name
            index["stages"]["global_roles"][global_name] = "module_handle"

        for global_name in re.findall(r"\b(DAT_[0-9a-fA-F]+)\s*=\s*'\\x01'", text):
            index["stages"]["global_roles"].setdefault(global_name, "boolean_or_state_flag")

        for enum_like in re.findall(r"\b([A-Z][A-Z0-9_]{2,})\b", text):
            if not _is_enum_candidate(enum_like):
                continue
            index["stages"]["enum_candidates"].setdefault(enum_like, 0)
            index["stages"]["enum_candidates"][enum_like] += 1

    for owner_data in index["stages"]["cpp_owners"].values():
        owner_data["members"] = sorted(set(owner_data["members"]))
        owner_data["decorated_symbols"] = sorted(set(owner_data["decorated_symbols"]))

    for owner_name in index["stages"]["cpp_owners"].keys():
        index["stages"]["enum_candidates"].pop(owner_name, None)

    index["stages"]["structure_candidates"] = merge_structure_candidates(structure_candidate_items)
    index["stages"]["class_layouts"] = merge_class_layout_candidates(class_layout_items)

    index["stages"]["enum_candidates"] = dict(
        sorted(
            ((name, count) for name, count in index["stages"]["enum_candidates"].items() if count >= 2),
            key=lambda item: item[1],
            reverse=True
        )[:80]
    )

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)

    return index

def _header_guard(job_id: str) -> str:
    return f"RECOVERED_{re.sub(r'[^A-Za-z0-9]', '_', job_id).upper()}_SYMBOLS_H"

def _load_rename_map(output_dir: str) -> Dict[str, Any]:
    return _read_json_file(os.path.join(output_dir, "recovered_renames.json"), {})

def _file_descriptor(filename: str, output_dir: str) -> Dict[str, Any]:
    rename_map = _load_rename_map(output_dir)
    descriptors = {
        "recovered_symbols.h": {
            "category": "Deterministic",
            "title": "Symbols and layout candidates",
            "validity": "draft",
            "description": "Conservative header generated from Ghidra artifacts: class layout candidates, function pointer globals, helper names, and struct candidates. Not final source.",
        },
        "recovered_stubs.cpp": {
            "category": "Deterministic",
            "title": "Recovered global storage",
            "validity": "draft",
            "description": "Storage definitions for recovered globals and role hints. May compile only when symbols/types are completed.",
        },
        "recovered_functions.cpp": {
            "category": "Decompiler",
            "title": "Function pseudocode drafts",
            "validity": "not_compilable",
            "description": "Ghidra decompiler output wrapped in #if 0. Useful for reading and per-function AI reconstruction, not intended to compile as-is.",
        },
        "recovered_types.h": {
            "category": "AI",
            "title": "AI type/class proposal",
            "validity": "experimental",
            "description": "Ollama-generated or fallback type header. Treat as a proposal until checked against constructors, vtables, and call sites.",
        },
        "recovered_types.model.txt": {
            "category": "AI raw",
            "title": "Raw AI type response",
            "validity": "diagnostic",
            "description": "Raw model output used to produce recovered_types.h. Useful when the model fails or hallucinates.",
        },
        "recovered_renames.json": {
            "category": "AI rename",
            "title": "Validated rename map",
            "validity": "empty" if not rename_map else "draft",
            "description": "Validated JSON map of old symbol names to proposed names. Empty means AI did not produce safe renames.",
        },
        "recovered_renames.model.json": {
            "category": "AI raw",
            "title": "Raw AI rename response",
            "validity": "diagnostic",
            "description": "Raw model response for rename pass. If it is {}, no safe rename was accepted.",
        },
        "recovery_manifest.json": {
            "category": "Guide",
            "title": "Recovery file guide",
            "validity": "reference",
            "description": "Machine-readable explanation of generated files, statuses, and recovery counters.",
        },
    }
    if ".renamed." in filename:
        return {
            "category": "AI rename",
            "title": "Renamed variant",
            "validity": "hidden_empty" if not rename_map else "draft",
            "description": "Source variant with AI rename map applied. Hidden from the main list when the rename map is empty.",
            "hidden": not bool(rename_map),
        }
    return descriptors.get(filename, {
        "category": "Other",
        "title": filename,
        "validity": "unknown",
        "description": "Generated recovery artifact.",
    })

def _make_recovery_manifest(job_id: str, output_dir: str, summary: Dict[str, Any], files: list) -> Dict[str, Any]:
    manifest = {
        "job_id": job_id,
        "summary": summary,
        "validity_legend": {
            "draft": "Generated from static evidence; useful, but must be verified.",
            "not_compilable": "Readable analysis material, intentionally not buildable.",
            "experimental": "Model-assisted proposal; expect mistakes.",
            "diagnostic": "Raw/debug artifact.",
            "empty": "No accepted result yet.",
        },
        "files": [
            {
                "name": item["name"],
                **_file_descriptor(item["name"], output_dir),
            }
            for item in files
        ],
    }
    path = os.path.join(output_dir, "recovery_manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return {"name": "recovery_manifest.json", "path": path, "size": os.path.getsize(path)}

def generate_recovered_files(job_id: str, force: bool = False) -> Dict[str, Any]:
    index = build_recovery_index(job_id, force=force)
    stages = index.get("stages", {})
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    os.makedirs(output_dir, exist_ok=True)

    guard = _header_guard(job_id)
    header_lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <windows.h>",
        "",
        "/*",
        "  Auto-generated recovery draft.",
        "  Target: Microsoft Visual C++ 2003 style.",
        "  Types and calling conventions are conservative until verified.",
        "*/",
        "",
    ]

    dynamic_modules = stages.get("dynamic_modules", {})
    function_pointers = stages.get("function_pointer_globals", {})
    function_pointer_typedefs = stages.get("function_pointer_typedefs", {})
    function_pointer_details = stages.get("function_pointer_details", {})
    helper_renames = stages.get("helper_renames", {})

    if dynamic_modules:
        header_lines.append("/* Dynamically loaded modules */")
        for original, inferred in sorted(dynamic_modules.items()):
            header_lines.append(f"extern HMODULE g_{inferred}; /* {original} */")
        header_lines.append("")

    if function_pointers:
        if function_pointer_typedefs:
            header_lines.append("/* Function pointer typedef candidates */")
            emitted_typedefs = set()
            for detail in function_pointer_typedefs.values():
                typedef_line = detail.get("typedef")
                if typedef_line and typedef_line not in emitted_typedefs:
                    header_lines.append(f"{typedef_line} /* {detail.get('evidence')} */")
                    emitted_typedefs.add(typedef_line)
            header_lines.append("")

        header_lines.append("/* Dynamically resolved functions */")
        for original, inferred in sorted(function_pointers.items()):
            typedef_info = function_pointer_typedefs.get(original, {})
            typedef_name = typedef_info.get("typedef_name", "FARPROC")
            detail = function_pointer_details.get(original, {})
            target = detail.get("target_name", "unknown")
            header_lines.append(f"extern {typedef_name} g_{inferred}; /* {original} -> {target} */")
        header_lines.append("")

    if helper_renames:
        header_lines.append("/* Helper functions inferred from decompiler patterns */")
        helper_groups = {}
        for original, inferred in sorted(helper_renames.items()):
            helper_groups.setdefault(inferred, []).append(original)
        for inferred, originals in sorted(helper_groups.items()):
            original_comment = ", ".join(originals)
            if inferred.startswith("ensure_") and inferred.endswith("_loaded"):
                header_lines.append(f"BOOL __stdcall {inferred}(void); /* {original_comment} */")
            elif inferred == "log_debug":
                header_lines.append(f"void __cdecl {inferred}(const char *pszFormat, ...); /* {original_comment} */")
            else:
                header_lines.append(f"void __cdecl {inferred}(void); /* {original_comment}, TODO: refine prototype */")
        header_lines.append("")

    cpp_owners = stages.get("cpp_owners", {})
    if cpp_owners:
        header_lines.append("/* C++ owner/class candidates from MSVC decorated symbols */")
        for owner, data in sorted(cpp_owners.items()):
            members = ", ".join(data.get("members", [])[:20])
            header_lines.append(f"/* class/namespace {owner}: {members} */")
        header_lines.append("")

    class_layout_lines = render_class_layout_declarations(stages.get("class_layouts", {}))
    if class_layout_lines:
        header_lines.extend(class_layout_lines)

    structure_lines = render_structure_declarations(stages.get("structure_candidates", {}))
    if structure_lines:
        header_lines.extend(structure_lines)

    header_lines.extend([f"#endif /* {guard} */", ""])

    cpp_lines = [
        '#include "recovered_symbols.h"',
        "",
        "/*",
        "  Storage for recovered globals.",
        "  These names are generated from Ghidra artifacts and still need manual verification.",
        "*/",
        "",
    ]

    for original, inferred in sorted(dynamic_modules.items()):
        cpp_lines.append(f"HMODULE g_{inferred} = NULL; /* {original} */")
    if dynamic_modules:
        cpp_lines.append("")

    for original, inferred in sorted(function_pointers.items()):
        typedef_info = function_pointer_typedefs.get(original, {})
        typedef_name = typedef_info.get("typedef_name", "FARPROC")
        cpp_lines.append(f"{typedef_name} g_{inferred} = NULL; /* {original} */")
    if function_pointers:
        cpp_lines.append("")

    if stages.get("global_roles"):
        cpp_lines.append("/* Global role hints */")
        for original, role in sorted(stages["global_roles"].items()):
            cpp_lines.append(f"/* {original}: {role} */")
        cpp_lines.append("")

    if stages.get("enum_candidates"):
        cpp_lines.append("/* Enum/constant name candidates observed in code */")
        for name, count in list(stages["enum_candidates"].items())[:40]:
            cpp_lines.append(f"/* {name}: observed {count} time(s) */")
        cpp_lines.append("")

    files = {
        "recovered_symbols.h": "\n".join(header_lines),
        "recovered_stubs.cpp": "\n".join(cpp_lines),
    }

    written = []
    for filename, content in files.items():
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        written.append({
            "name": filename,
            "path": path,
            "size": len(content.encode("utf-8")),
            **_file_descriptor(filename, output_dir),
        })

    function_draft_file = write_function_draft_file(
        job_id=job_id,
        index=index,
        functions=functions,
        artifacts_dir=_get_artifacts_dir(job_id),
        output_dir=output_dir,
    )
    function_draft_file.update(_file_descriptor(function_draft_file["name"], output_dir))
    written.append(function_draft_file)

    summary = {
        "dynamic_modules": len(dynamic_modules),
        "function_pointers": len(function_pointers),
        "typed_function_pointers": len(function_pointer_typedefs),
        "helper_renames": len(helper_renames),
        "cpp_owners": len(stages.get("cpp_owners", {})),
        "class_layouts": len(stages.get("class_layouts", {})),
        "structure_candidates": len(stages.get("structure_candidates", {})),
        "renderable_structures": len(get_renderable_structure_candidates(stages.get("structure_candidates", {}))),
        "function_drafts": function_draft_file.get("function_drafts", 0),
        "enum_candidates": len(stages.get("enum_candidates", {})),
    }
    manifest_file = _make_recovery_manifest(job_id, output_dir, summary, written)
    manifest_file.update(_file_descriptor(manifest_file["name"], output_dir))
    written.append(manifest_file)

    return {"job_id": job_id, "output_dir": output_dir, "files": written, "summary": summary, "index": index}

def list_recovered_files(job_id: str) -> Dict[str, Any]:
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    files = []
    if os.path.isdir(output_dir):
        for filename in sorted(os.listdir(output_dir)):
            if not filename.endswith((".h", ".hpp", ".c", ".cpp", ".json", ".txt")):
                continue
            path = os.path.join(output_dir, filename)
            descriptor = _file_descriptor(filename, output_dir)
            if descriptor.get("hidden"):
                continue
            files.append({"name": filename, "path": path, "size": os.path.getsize(path), **descriptor})

    index = build_recovery_index(job_id)
    stages = index.get("stages", {})
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    summary = {
        "dynamic_modules": len(stages.get("dynamic_modules", {})),
        "function_pointers": len(stages.get("function_pointer_globals", {})),
        "typed_function_pointers": len(stages.get("function_pointer_typedefs", {})),
        "helper_renames": len(stages.get("helper_renames", {})),
        "cpp_owners": len(stages.get("cpp_owners", {})),
        "class_layouts": len(stages.get("class_layouts", {})),
        "structure_candidates": len(stages.get("structure_candidates", {})),
        "renderable_structures": len(get_renderable_structure_candidates(stages.get("structure_candidates", {}))),
        "function_drafts": min(80, len(functions or [])),
        "enum_candidates": len(stages.get("enum_candidates", {})),
    }
    if os.path.isdir(output_dir):
        visible_without_manifest = [item for item in files if item["name"] != "recovery_manifest.json"]
        manifest_file = _make_recovery_manifest(job_id, output_dir, summary, visible_without_manifest)
        manifest_file.update(_file_descriptor(manifest_file["name"], output_dir))
        files = visible_without_manifest + [manifest_file]
    return {"job_id": job_id, "output_dir": output_dir, "files": files, "summary": summary}

def _rename_payload_value(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        return payload.get("new") or payload.get("name") or payload.get("renamed")
    if isinstance(payload, str):
        return payload
    return None

def _rename_payload_source(payload: Any) -> str:
    if isinstance(payload, dict):
        return payload.get("source") or payload.get("reason") or "ai"
    return "inferred"

def _load_recovered_function_addresses(output_dir: str) -> set:
    addresses = set()
    for filename in ("recovered_functions.cpp", "recovered_functions.renamed.cpp"):
        path = os.path.join(output_dir, filename)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for addr in re.findall(r"\bAddress:\s*(0x[0-9A-Fa-f]+)", text):
            addresses.add(addr.lower())
    return addresses

def list_recovered_symbols(job_id: str) -> Dict[str, Any]:
    """Return clickable function identity data for the recovered source view."""
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    index = build_recovery_index(job_id)
    stages = index.get("stages", {})
    rename_map = _load_rename_map(output_dir)
    helper_renames = stages.get("helper_renames", {})
    renamed_cpp = os.path.exists(os.path.join(output_dir, "recovered_functions.renamed.cpp"))
    draft_addresses = _load_recovered_function_addresses(output_dir)
    if not draft_addresses:
        draft_addresses = {
            str(fn.get("addr") or "").lower()
            for fn in select_function_drafts(functions or [], limit=80)
            if isinstance(fn, dict) and fn.get("addr")
        }

    symbols = []
    renamed_count = 0
    navigable_count = 0
    for fn in functions or []:
        if not isinstance(fn, dict) or fn.get("is_external"):
            continue
        original = fn.get("name") or ""
        if not original:
            continue
        rename_payload = rename_map.get(original)
        renamed = _rename_payload_value(rename_payload) or helper_renames.get(original) or original
        is_renamed = bool(renamed and renamed != original)
        if is_renamed:
            renamed_count += 1
        in_draft = str(fn.get("addr") or "").lower() in draft_addresses
        if in_draft:
            navigable_count += 1
        symbols.append({
            "kind": "function",
            "original": original,
            "renamed": renamed,
            "address": fn.get("addr"),
            "signature": fn.get("signature", ""),
            "size": fn.get("size", 0),
            "renamed_active": is_renamed,
            "in_draft": in_draft,
            "rename_source": _rename_payload_source(rename_payload) if rename_payload else ("helper" if original in helper_renames else "none"),
            "source_file": "recovered_functions.renamed.cpp" if is_renamed and renamed_cpp else "recovered_functions.cpp",
            "search_terms": [value for value in (
                renamed,
                original,
                fn.get("addr"),
                str(fn.get("addr") or "").replace("0x", ""),
                f"Function: {original}",
                f"Address: {fn.get('addr')}",
            ) if value],
        })

    symbols.sort(key=lambda item: (not item.get("in_draft"), str(item.get("address") or item.get("original") or "")))
    return {
        "job_id": job_id,
        "symbols": symbols,
        "summary": {
            "functions": len(symbols),
            "renamed": renamed_count,
            "navigable": navigable_count,
            "unrenamed": max(0, len(symbols) - renamed_count),
        },
    }

def read_recovered_file(job_id: str, filename: str) -> Dict[str, Any]:
    safe_name = os.path.basename(filename)
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    path = os.path.abspath(os.path.join(output_dir, safe_name))
    if not path.startswith(os.path.abspath(output_dir) + os.sep):
        return {"error": "Invalid file path"}
    if not os.path.exists(path):
        return {"error": "Recovered file not found"}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return {"job_id": job_id, "name": safe_name, "path": path, "content": f.read()}

def inspect_recovered_function(job_id: str, query: str) -> Dict[str, Any]:
    """Resolve a function symbol/address and return local navigation context for the Web UI."""
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    if not isinstance(functions, list):
        functions = []

    symbols_payload = list_recovered_symbols(job_id)
    symbols = symbols_payload.get("symbols", [])
    by_name: Dict[str, Dict[str, Any]] = {}
    by_addr: Dict[str, Dict[str, Any]] = {}
    for symbol in symbols:
        for value in (symbol.get("original"), symbol.get("renamed")):
            if value:
                by_name[str(value).lower()] = symbol
        normalized = _normalize_hex_address(symbol.get("address"))
        if normalized:
            by_addr[normalized] = symbol
            by_addr[normalized.replace("0x", "")] = symbol

    query_text = str(query or "").strip()
    normalized_query_addr = _normalize_hex_address(query_text)
    symbol = by_addr.get(normalized_query_addr) or by_addr.get(normalized_query_addr.replace("0x", "")) if normalized_query_addr else None
    if symbol is None:
        symbol = by_name.get(query_text.lower())

    fn = None
    if symbol:
        symbol_addr = _normalize_hex_address(symbol.get("address"))
        for candidate in functions:
            if _normalize_hex_address(candidate.get("addr")) == symbol_addr:
                fn = candidate
                break
    elif normalized_query_addr:
        fn = _find_containing_function(functions, normalized_query_addr)
        if fn:
            symbol = by_addr.get(_normalize_hex_address(fn.get("addr")))
    else:
        for candidate in functions:
            if str(candidate.get("name") or "").lower() == query_text.lower():
                fn = candidate
                break

    if not fn and not symbol:
        return {"job_id": job_id, "query": query, "found": False, "error": "Function was not found in local artifacts."}

    if not symbol and fn:
        symbol = {
            "kind": "function",
            "original": fn.get("name") or "",
            "renamed": fn.get("name") or "",
            "address": fn.get("addr"),
            "signature": fn.get("signature", ""),
            "size": fn.get("size", 0),
            "renamed_active": False,
            "in_draft": False,
            "source_file": "recovered_functions.cpp",
        }
    if not fn:
        for candidate in functions:
            if _normalize_hex_address(candidate.get("addr")) == _normalize_hex_address(symbol.get("address")):
                fn = candidate
                break

    address = _normalize_hex_address(symbol.get("address") or (fn or {}).get("addr"))
    xrefs = _load_artifact_json(job_id, "xrefs.json", {})
    xref_item = xrefs.get(address) or xrefs.get(address.replace("0x", "")) if isinstance(xrefs, dict) and address else {}

    callers = []
    for ref in (xref_item or {}).get("from", []) if isinstance(xref_item, dict) else []:
        callsite = _normalize_hex_address(ref.get("from"))
        owner = _find_containing_function(functions, callsite)
        owner_symbol = by_addr.get(_normalize_hex_address(owner.get("addr"))) if owner else None
        callers.append({
            "type": ref.get("type") or "xref",
            "callsite": callsite,
            "address": _normalize_hex_address(owner.get("addr")) if owner else callsite,
            "original": (owner_symbol or {}).get("original") or (owner or {}).get("name") or "",
            "renamed": (owner_symbol or {}).get("renamed") or (owner or {}).get("name") or "",
            "signature": (owner or {}).get("signature", ""),
        })

    excerpt = (fn or {}).get("decompiled_excerpt") or ""
    known_tokens: Dict[str, Dict[str, Any]] = {}
    for item in symbols:
        for token in (item.get("original"), item.get("renamed")):
            if token:
                known_tokens[str(token)] = item
    callees = []
    seen_callees = set()
    for token in re.findall(r"\b(FUN_[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]{2,})\s*\(", excerpt):
        target_symbol = known_tokens.get(token)
        if not target_symbol:
            continue
        target_addr = _normalize_hex_address(target_symbol.get("address"))
        if target_addr == address or target_addr in seen_callees:
            continue
        seen_callees.add(target_addr)
        callees.append({
            "address": target_addr,
            "original": target_symbol.get("original"),
            "renamed": target_symbol.get("renamed"),
            "signature": target_symbol.get("signature", ""),
        })
        if len(callees) >= 40:
            break

    strings_data = _load_artifact_json(job_id, "strings.json", [])
    related_strings = []
    for item in strings_data if isinstance(strings_data, list) else []:
        text = item.get("s") if isinstance(item, dict) else ""
        if not text or len(text) < 4:
            continue
        addr = _normalize_hex_address(item.get("addr") if isinstance(item, dict) else "")
        if text in excerpt or (addr and addr.lower() in excerpt.lower()):
            related_strings.append({"address": addr, "text": text[:240]})
        if len(related_strings) >= 24:
            break

    function_payload = {
        "original": symbol.get("original") or (fn or {}).get("name") or "",
        "renamed": symbol.get("renamed") or symbol.get("original") or (fn or {}).get("name") or "",
        "display_name": _symbol_display_name(symbol),
        "address": address,
        "signature": symbol.get("signature") or (fn or {}).get("signature", ""),
        "size": symbol.get("size") or (fn or {}).get("size", 0),
        "renamed_active": bool(symbol.get("renamed_active")),
        "in_draft": bool(symbol.get("in_draft")),
        "source_file": symbol.get("source_file") or "recovered_functions.cpp",
        "search_terms": symbol.get("search_terms") or [],
        "excerpt": excerpt[:2400],
    }

    return {
        "job_id": job_id,
        "query": query,
        "found": True,
        "function": function_payload,
        "xrefs": {
            "callers": callers[:40],
            "callees": callees[:40],
        },
        "related_strings": related_strings,
    }

def _collect_owner_function_context(job_id: str, owner_names: list, max_functions: int = 24) -> list:
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    result = []
    owner_tokens = [owner.lower() for owner in owner_names]

    for fn in functions or []:
        signature = fn.get("signature", "")
        name = fn.get("name", "")
        excerpt = fn.get("decompiled_excerpt", "")
        haystack = f"{signature}\n{name}\n{excerpt}".lower()
        if not any(token.lower() in haystack for token in owner_tokens):
            continue
        result.append({
            "name": name,
            "addr": fn.get("addr"),
            "signature": signature,
            "decompiled_excerpt": excerpt[:1800],
        })
        if len(result) >= max_functions:
            break

    return result

def generate_model_recovered_types(job_id: str, force: bool = False) -> Dict[str, Any]:
    generate_recovered_files(job_id, force=force)
    index = build_recovery_index(job_id, force=force)
    stages = index.get("stages", {})
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    os.makedirs(output_dir, exist_ok=True)

    owner_names = sorted(stages.get("cpp_owners", {}).keys())
    result = generate_types_header_with_model(
        job_id=job_id,
        index=index,
        owner_function_context=_collect_owner_function_context(job_id, owner_names),
        output_dir=output_dir,
    )

    return {
        "job_id": job_id,
        "output_dir": output_dir,
        **result,
        "summary": list_recovered_files(job_id).get("summary", {}),
    }

def generate_model_renamed_sources(job_id: str, force: bool = False) -> Dict[str, Any]:
    generated = generate_recovered_files(job_id, force=force)
    index = generated.get("index") or build_recovery_index(job_id, force=force)
    output_dir = os.path.join(RECOVERED_SOURCES_DIR, job_id)
    functions_data = _load_artifact_json(job_id, "functions.json", {})
    functions = functions_data.get("functions", []) if isinstance(functions_data, dict) else functions_data
    result = generate_ai_renames(index=index, output_dir=output_dir, functions=functions)
    return {
        "job_id": job_id,
        "output_dir": output_dir,
        **result,
        "summary": list_recovered_files(job_id).get("summary", {}),
    }

def infer_names_from_context(context: Dict[str, Any]) -> Dict[str, str]:
    rename_map = {}
    primary = context.get("primary") or {}
    primary_text = primary.get("result") or primary.get("pseudocode") or ""
    resolved_name = primary.get("resolved_name")

    if resolved_name:
        rename_map[resolved_name] = resolved_name

    related_by_addr = {}
    for related in context.get("related_internal_calls") or []:
        decompile = related.get("decompile") or {}
        text = decompile.get("result") or decompile.get("pseudocode") or ""
        addr = related.get("addr")
        if addr:
            related_by_addr[addr.lower()] = text
            helper_name = _infer_helper_name(addr, text)
            if helper_name:
                ghidra_name = f"FUN_{addr[2:].lower()}" if addr.startswith("0x") else addr
                rename_map[ghidra_name] = helper_name

    combined_text = "\n".join([primary_text] + list(related_by_addr.values()))
    rename_map.update(_extract_global_proc_assignments(combined_text))
    rename_map.update(_extract_loadlibrary_globals(combined_text))

    for fun_name in re.findall(r"\b(FUN_[0-9a-fA-F]{8})\b", primary_text):
        addr = f"0x{fun_name[4:].lower()}"
        if fun_name not in rename_map and addr in related_by_addr:
            helper_name = _infer_helper_name(addr, related_by_addr[addr])
            if helper_name:
                rename_map[fun_name] = helper_name

    return rename_map
