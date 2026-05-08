import json
import os
import re
from typing import Any, Dict

from openai import OpenAI
from llm_config import get_llm_config

def strip_markdown_code_fence(content: str) -> str:
    content = (content or "").strip()
    match = re.fullmatch(r"```(?:cpp|c\+\+|c|h|hpp)?\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else content


def looks_like_header(content: str) -> bool:
    if not content:
        return False
    header_tokens = ["#include", "typedef", "class ", "struct ", "enum ", "#ifndef"]
    return any(token in content for token in header_tokens) and "feel free to ask" not in content.lower()


def fallback_recovered_types_header(job_id: str, index: Dict[str, Any]) -> str:
    stages = index.get("stages", {})
    guard = f"RECOVERED_{re.sub(r'[^A-Za-z0-9]', '_', job_id).upper()}_TYPES_H"
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <windows.h>",
        "",
        "/*",
        "  Conservative type/class recovery fallback.",
        "  Generated from deterministic Ghidra artifact analysis.",
        "  TODO: refine signatures after per-function recovery.",
        "*/",
        "",
    ]

    typedefs = stages.get("function_pointer_typedefs", {})
    function_pointers = stages.get("function_pointer_globals", {})
    if typedefs or function_pointers:
        lines.append("/* Function pointer typedef candidates */")
        emitted = set()
        for info in typedefs.values():
            typedef_line = info.get("typedef")
            if typedef_line and typedef_line not in emitted:
                lines.append(f"{typedef_line} /* {info.get('evidence', 'static evidence')} */")
                emitted.add(typedef_line)
        for _, inferred in sorted(function_pointers.items()):
            typedef_name = "PFN_" + re.sub(r"^pfn_", "", inferred).upper()
            if typedef_name in emitted:
                continue
            lines.append(f"typedef FARPROC {typedef_name}; /* TODO: replace FARPROC with exact signature */")
        lines.append("")

    cpp_owners = stages.get("cpp_owners", {})
    if cpp_owners:
        lines.append("/* C++ class/namespace candidates from MSVC decorated symbols */")
        for owner, data in sorted(cpp_owners.items()):
            lines.append(f"class {owner}")
            lines.append("{")
            lines.append("public:")
            for member in data.get("members", []):
                lines.append(f"    static void __cdecl {member}(void); /* TODO: refine return type and parameters */")
            lines.append("};")
            lines.append("")

    dynamic_modules = stages.get("dynamic_modules", {})
    if dynamic_modules:
        lines.append("/* Module handle typedef/context candidates */")
        for original, inferred in sorted(dynamic_modules.items()):
            lines.append(f"extern HMODULE g_{inferred}; /* {original} */")
        lines.append("")

    structure_candidates = stages.get("structure_candidates", {})
    if structure_candidates:
        lines.append("/* Structure/layout candidates from pointer offset usage */")
        for _, candidate in sorted(structure_candidates.items()):
            lines.append(f"struct {candidate['suggested_name']}; /* {candidate['base']}: {len(candidate.get('fields', []))} field candidate(s) */")
        lines.append("")

    lines.extend([f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def generate_types_header_with_model(
    job_id: str,
    index: Dict[str, Any],
    owner_function_context: list,
    output_dir: str,
) -> Dict[str, Any]:
    stages = index.get("stages", {})
    context = {
        "metadata": index.get("metadata", {}),
        "cpp_owners": stages.get("cpp_owners", {}),
        "function_pointer_globals": stages.get("function_pointer_globals", {}),
        "function_pointer_details": stages.get("function_pointer_details", {}),
        "function_pointer_typedefs": stages.get("function_pointer_typedefs", {}),
        "indirect_calls": stages.get("indirect_calls", {}),
        "dynamic_modules": stages.get("dynamic_modules", {}),
        "helper_renames": stages.get("helper_renames", {}),
        "global_roles": stages.get("global_roles", {}),
        "structure_candidates": stages.get("structure_candidates", {}),
        "owner_function_context": owner_function_context,
    }

    system = (
        "You are reconstructing C++ types from Ghidra artifacts for legacy x86 software. "
        "Generate Microsoft Visual C++ 2003 compatible header code only. "
        "Do not use C++11, stdint.h, nullptr, auto, range-for, or lambdas. "
        "Prefer conservative declarations with comments marking uncertainty. "
        "Recover likely classes/namespaces, structs, typedefs, function pointer typedefs, and enums only when evidence supports them. "
        "Return only the contents of a .h file, no Markdown and no explanation."
    )
    user = (
        "Build recovered_types.h from this recovery context. "
        "Use comments with evidence/confidence. "
        "If a type is probably a namespace with only static functions, represent it as a class with public static methods or a namespace-style comment, VC++ 2003 compatible.\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )

    llm_config = get_llm_config()
    client = OpenAI(base_url=llm_config.api_base, api_key=llm_config.api_key)
    response = client.chat.completions.create(
        model=llm_config.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    content = strip_markdown_code_fence(response.choices[0].message.content or "")
    model_content = content

    if not looks_like_header(content):
        content = fallback_recovered_types_header(job_id, index)
    elif "#include <windows.h>" not in content:
        content = "#include <windows.h>\n\n" + content

    os.makedirs(output_dir, exist_ok=True)
    header_path = os.path.join(output_dir, "recovered_types.h")
    with open(header_path, "w", encoding="utf-8") as f:
        f.write(content.rstrip() + "\n")

    model_path = os.path.join(output_dir, "recovered_types.model.txt")
    with open(model_path, "w", encoding="utf-8") as f:
        f.write((model_content or "").rstrip() + "\n")

    return {
        "file": {"name": "recovered_types.h", "path": header_path, "size": os.path.getsize(header_path)},
        "model_response_file": {
            "name": "recovered_types.model.txt",
            "path": model_path,
            "size": os.path.getsize(model_path),
        },
    }
