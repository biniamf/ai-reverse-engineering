import json
import os
import re
from typing import Any, Dict, List

from openai import OpenAI
from llm_config import get_llm_config

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RECOVERED_PREFIXES = ("FUN_", "DAT_", "LAB_", "PTR_", "UNK_", "param_", "local_")


def _strip_json_fence(content: str) -> str:
    content = (content or "").strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else content


def _extract_json_object(content: str) -> Dict[str, Any]:
    content = _strip_json_fence(content)
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    start = content.find("{")
    end = content.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(content[start:end + 1])
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def _safe_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value or "").strip("_")
    if not value:
        return ""
    if value[0].isdigit():
        value = "_" + value
    return value[:80]


def _name_from_phrase(prefix: str, phrase: str) -> str:
    words = re.findall(r"[A-Za-z][A-Za-z0-9]+", phrase or "")
    words = [word.lower() for word in words if word.lower() not in {"the", "and", "for", "with"}]
    if not words:
        return ""
    return _safe_identifier(prefix + "_" + "_".join(words[:4]))


def _is_recoverable_name(name: str) -> bool:
    if not name or not IDENTIFIER_RE.match(name):
        return False
    if name.startswith(RECOVERED_PREFIXES):
        return True
    return name.startswith(("g_pfn_", "g_h", "pfn_", "PFN_", "Recovered_"))


def _validate_rename_map(raw_map: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    used = set()

    for old_name, payload in (raw_map or {}).items():
        if not _is_recoverable_name(str(old_name)):
            continue

        if isinstance(payload, str):
            new_name = payload
            confidence = "low"
            reason = ""
        elif isinstance(payload, dict):
            new_name = payload.get("new") or payload.get("name") or payload.get("rename_to")
            confidence = payload.get("confidence", "low")
            reason = payload.get("reason", "")
        else:
            continue

        new_name = _safe_identifier(str(new_name or ""))
        if not new_name or not IDENTIFIER_RE.match(new_name):
            continue
        if new_name == old_name or new_name in used:
            continue
        if new_name.startswith(RECOVERED_PREFIXES):
            continue

        confidence = confidence if confidence in {"low", "medium", "high"} else "low"
        result[str(old_name)] = {
            "new": new_name,
            "confidence": confidence,
            "reason": str(reason)[:300],
        }
        used.add(new_name)

    return result


def _infer_fallback_name(symbol: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
    calls = set(candidate.get("calls") or [])
    strings = [item for item in candidate.get("strings") or [] if len(item) >= 3]
    signature = candidate.get("signature", "")
    current = candidate.get("current", "")

    if current and current != symbol and _is_recoverable_name(symbol):
        return {
            "new": current,
            "confidence": "medium",
            "reason": "deterministic helper/global inference",
        }

    joined_strings = " ".join(strings).lower()
    primary_phrase = next((text for text in strings if re.search(r"[A-Za-z]{3,}", text or "")), "")
    phrase_lower = primary_phrase.lower()
    if primary_phrase:
        if any(token in phrase_lower for token in ("height", "width", "count", "name", "size", "length", "id", "index")):
            name = _name_from_phrase("get", primary_phrase)
            if name:
                return {
                    "new": name,
                    "confidence": "medium",
                    "reason": f"references data label '{primary_phrase[:60]}'",
                }
        if any(token in phrase_lower for token in ("error", "warning", "failed", "invalid")):
            name = _name_from_phrase("handle", primary_phrase) or _name_from_phrase("log", primary_phrase)
            if name:
                return {
                    "new": name,
                    "confidence": "medium",
                    "reason": f"references diagnostic string '{primary_phrase[:60]}'",
                }
        name = _name_from_phrase("process", primary_phrase)
        if name and len(strings) >= 2:
            return {
                "new": name,
                "confidence": "low",
                "reason": f"references strings including '{primary_phrase[:60]}'",
            }
    if "DACOM_CRC::GetCRC32" in calls or "GetCRC32" in calls:
        phrase_name = _name_from_phrase("load_crc_for", strings[0] if strings else "resource")
        return {
            "new": phrase_name or "compute_resource_crc",
            "confidence": "medium",
            "reason": "calls DACOM_CRC::GetCRC32 and references resource strings",
        }
    if "_vsnprintf" in calls:
        return {
            "new": "format_debug_message",
            "confidence": "medium",
            "reason": "formats a message with _vsnprintf",
        }
    if "FDUMP_exref" in calls or "fdump" in joined_strings:
        return {
            "new": "log_warning_message",
            "confidence": "medium",
            "reason": "calls dump/logging path and references warning strings",
        }
    if "DACOM_Acquire" in calls and "channel" in joined_strings:
        return {
            "new": "load_channel_component",
            "confidence": "medium",
            "reason": "references Channel and acquires a DACOM component",
        }
    if "free" in calls and "operator_new" not in calls:
        return {
            "new": "release_owned_resources",
            "confidence": "low",
            "reason": "frees owned buffers and releases referenced objects",
        }
    if "operator_new" in calls or "operator_new" in signature:
        return {
            "new": "initialize_allocated_state",
            "confidence": "low",
            "reason": "allocates and initializes object/global state",
        }
    for text in strings:
        lowered = text.lower()
        if any(token in lowered for token in ("animation", "script", "filesystem", "object map", "event map", "joint map")):
            name = _name_from_phrase("process", text)
            if name:
                return {
                    "new": name,
                    "confidence": "low",
                    "reason": f"references string '{text[:60]}'",
                }
    if "__thiscall" in signature:
        if len(calls) >= 2 or strings:
            return {
                "new": "update_object_state",
                "confidence": "low",
                "reason": "thiscall method with object state access",
            }
    return {}


def _fallback_rename_map(candidates: Dict[str, Any], existing: Dict[str, Dict[str, Any]], limit: int = 48) -> Dict[str, Dict[str, Any]]:
    result = dict(existing)
    used = {payload.get("new") for payload in result.values()}
    sorted_candidates = sorted(
        candidates.items(),
        key=lambda item: (
            0 if item[1].get("strings") else 1,
            0 if item[1].get("calls") else 1,
            -int(item[1].get("size", 0) or 0),
        ),
    )
    for symbol, candidate in sorted_candidates:
        if symbol in result or not _is_recoverable_name(symbol):
            continue
        inferred = _infer_fallback_name(symbol, candidate)
        if not inferred:
            continue
        new_name = _safe_identifier(inferred.get("new", ""))
        if new_name in used:
            suffix = re.sub(r"[^0-9A-Fa-f]", "", symbol)[-6:].lower()
            new_name = _safe_identifier(f"{new_name}_{suffix}") if suffix else new_name
        if not new_name or new_name in used or new_name == symbol or new_name.startswith(RECOVERED_PREFIXES):
            continue
        result[symbol] = {
            "new": new_name,
            "confidence": inferred.get("confidence", "low"),
            "reason": "fallback: " + inferred.get("reason", "static evidence"),
        }
        used.add(new_name)
        if len(result) >= limit:
            break
    return result


def _candidate_symbols_from_index(index: Dict[str, Any], functions: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    stages = index.get("stages", {})
    candidates: Dict[str, Any] = {}

    function_candidates = [
        fn for fn in functions or []
        if (fn.get("name", "") or "").startswith("FUN_")
        and not fn.get("is_external")
        and not fn.get("is_library")
        and not fn.get("is_thunk")
    ]
    function_candidates.sort(key=lambda item: int(item.get("size", 0) or 0), reverse=True)
    for fn in function_candidates[:80]:
        name = fn.get("name", "")
        excerpt = fn.get("decompiled_excerpt", "") or ""
        hints = _extract_behavior_hints(excerpt)
        candidates[name] = {
            "current": name,
            "kind": "function",
            "addr": fn.get("addr"),
            "signature": fn.get("signature", ""),
            "size": fn.get("size", 0),
            "calls": hints["calls"],
            "strings": hints["strings"],
        }

    for old_name, inferred in stages.get("helper_renames", {}).items():
        candidates[old_name] = {"current": inferred, "kind": "function", "evidence": "helper pattern"}

    for old_name, inferred in stages.get("function_pointer_globals", {}).items():
        candidates[old_name] = {
            "current": inferred,
            "kind": "function_pointer_global",
            "details": stages.get("function_pointer_details", {}).get(old_name, {}),
            "indirect_calls": stages.get("indirect_calls", {}).get(old_name, [])[:5],
        }
        candidates[f"g_{inferred}"] = {
            "current": f"g_{inferred}",
            "kind": "generated_global",
            "details": stages.get("function_pointer_details", {}).get(old_name, {}),
        }

    for old_name, inferred in stages.get("dynamic_modules", {}).items():
        candidates[old_name] = {"current": inferred, "kind": "module_handle"}
        candidates[f"g_{inferred}"] = {"current": f"g_{inferred}", "kind": "generated_module_handle"}

    return candidates


def _extract_behavior_hints(text: str) -> Dict[str, List[str]]:
    calls = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_:]*|FUN_[0-9A-Fa-f]{8})\s*\(", text or "")))
    strings = sorted(set(re.findall(r"\"([^\"\r\n]{3,80})\"", text or "")))
    calls = [item for item in calls if item not in {"if", "while", "switch", "return", "sizeof"}]
    return {
        "calls": calls[:24],
        "strings": strings[:12],
    }


def _collect_file_excerpts(output_dir: str, max_chars: int = 9000) -> Dict[str, str]:
    excerpts: Dict[str, str] = {}
    for filename in ("recovered_symbols.h", "recovered_stubs.cpp", "recovered_functions.cpp", "recovered_types.h"):
        path = os.path.join(output_dir, filename)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            excerpts[filename] = f.read(max_chars)
    return excerpts


def _apply_rename_map_to_text(text: str, rename_map: Dict[str, Dict[str, Any]]) -> str:
    for old_name, payload in sorted(rename_map.items(), key=lambda item: len(item[0]), reverse=True):
        new_name = payload.get("new")
        if not new_name:
            continue
        text = re.sub(rf"\b{re.escape(old_name)}\b", new_name, text)
    return text


def _write_renamed_sources(output_dir: str, rename_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    written: List[Dict[str, Any]] = []
    if not rename_map:
        for filename in (
            "recovered_symbols.renamed.h",
            "recovered_stubs.renamed.cpp",
            "recovered_functions.renamed.cpp",
            "recovered_types.renamed.h",
        ):
            path = os.path.join(output_dir, filename)
            if os.path.exists(path):
                os.remove(path)
        return written
    for filename in ("recovered_symbols.h", "recovered_stubs.cpp", "recovered_functions.cpp", "recovered_types.h"):
        path = os.path.join(output_dir, filename)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        renamed = _apply_rename_map_to_text(content, rename_map)
        stem, ext = os.path.splitext(filename)
        renamed_name = f"{stem}.renamed{ext}"
        renamed_path = os.path.join(output_dir, renamed_name)
        with open(renamed_path, "w", encoding="utf-8") as f:
            f.write(renamed)
        written.append({"name": renamed_name, "path": renamed_path, "size": os.path.getsize(renamed_path)})
    return written


def generate_ai_renames(index: Dict[str, Any], output_dir: str, functions: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    candidates = _candidate_symbols_from_index(index, functions=functions)
    context = {
        "metadata": index.get("metadata", {}),
        "candidate_symbols": candidates,
    }

    system = (
        "You are a C/C++ source maintenance assistant for the user's own legacy code. "
        "Your only task is to propose better C/C++ identifier names for placeholder symbols in generated source drafts. "
        "Return one valid JSON object only. Do not explain. Do not summarize. Do not return Markdown. "
        "Only rename names that are clearly generated placeholders. "
        "Prefer VC++ 2003 style identifiers: no C++11, no namespaces invented without evidence. "
        "Be conservative: if evidence is weak, omit the rename."
    )
    user = (
        "Input is C/C++ symbol metadata for owned legacy maintenance. "
        "Do not describe the input. Do not mention recovered data. "
        "Return exactly this JSON shape:\n"
        "{\"FUN_12345678\":{\"new\":\"descriptive_function_name\",\"confidence\":\"medium\",\"reason\":\"short evidence\"}}\n"
        "Only include keys from candidate_symbols. If no safe rename exists, return {}. Context:\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )

    llm_config = get_llm_config()
    client = OpenAI(base_url=llm_config.api_base, api_key=llm_config.api_key)
    request = {
        "model": llm_config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
    }
    response = client.chat.completions.create(**request)
    model_content = response.choices[0].message.content or ""
    raw_data = _extract_json_object(model_content)
    raw_map = raw_data.get("renames", raw_data)
    rename_map = _validate_rename_map(raw_map if isinstance(raw_map, dict) else {})
    fallback_used = False
    before_fallback = len(rename_map)
    if len(rename_map) < 24:
        rename_map = _fallback_rename_map(candidates, rename_map, limit=48)
        fallback_used = len(rename_map) > before_fallback

    os.makedirs(output_dir, exist_ok=True)
    raw_path = os.path.join(output_dir, "recovered_renames.model.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(model_content.rstrip() + "\n")

    map_path = os.path.join(output_dir, "recovered_renames.json")
    with open(map_path, "w", encoding="utf-8") as f:
        json.dump(rename_map, f, ensure_ascii=False, indent=2)

    written = _write_renamed_sources(output_dir, rename_map)
    written.append({"name": "recovered_renames.json", "path": map_path, "size": os.path.getsize(map_path)})
    written.append({"name": "recovered_renames.model.json", "path": raw_path, "size": os.path.getsize(raw_path)})

    return {
        "rename_count": len(rename_map),
        "fallback_used": fallback_used,
        "renames": rename_map,
        "files": written,
    }
