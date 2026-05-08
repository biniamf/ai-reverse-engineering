# Biniam Demissie
# 09/29/2025
import os
import json
import re
import requests
from difflib import get_close_matches
from typing import Dict, Any, Generator, Optional
from openai import OpenAI
from llm_config import get_llm_config
from recovery_engine import (
    _extract_internal_call_addrs,
    build_recovery_index,
    generate_recovered_files,
    infer_names_from_context,
)

GHIDRA_API_BASE = os.getenv("GHIDRA_API_BASE", "http://localhost:9090").rstrip("/")

SYSTEM_PROMPT = """You are a local reverse engineering assistant for legacy x86 software.
You have access to Ghidra analysis tools for a binary identified by job_id.

Work like an analyst:
- Inspect imports, strings, function names, xrefs, and decompiled pseudocode before making claims.
- Prefer small, evidence-backed conclusions over broad guesses.
- When reconstructing old C/C++ code, clearly separate confirmed behavior from inferred names, types, and control flow.
- For unknown functions, propose descriptive names and explain why.
- If the user asks for recovered code, produce readable C-like code and note uncertain types or missing context.
- Use Mermaid call graphs or flowcharts when they clarify relationships.
- Do not print tool-call JSON to the user. If you need data, use the available tools internally.
- Answer in the same language as the user's latest message.
- Separate direct behavior of the requested function from behavior performed by helper functions.
- For function reconstruction requests, lead with clean recovered C-like code using meaningful inferred names.
- After the code, provide a compact rename map for original Ghidra symbols to inferred names.
- Target recovered code for Microsoft Visual C++ 2003 compatibility unless the user says otherwise.
- Avoid C99/C++11+ constructs: no stdint.h, nullptr, auto, range-for, lambdas, or uniform initialization.
- Prefer Win32/VC2003 types such as DWORD, UINT, BOOL, HMODULE, FARPROC, LPCSTR, and explicit calling conventions.

Always format the final response in Markdown."""
MAX_AGENT_TURNS = 5
REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "120"))

TOOLS = [
  { "type": "function", "function": { "name": "analyze", "description": "Upload a base64-encoded binary and start headless Ghidra analysis. Returns job_id.", "parameters": { "type": "object", "properties": { "file_b64": {"type": "string"}, "filename": {"type": "string"}}, "required": ["file_b64", "filename"] }}},
  { "type": "function", "function": { "name": "status", "description": "Get status for an existing analysis job.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_functions", "description": "Retrieve a paginated list of discovered functions for a job. Use offset/limit to page through results.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "decompile_function", "description": "Get decompiled pseudocode for a function at a given address.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "get_xrefs", "description": "Get callers and callees for a function (cross-references).", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "list_imports", "description": "List imported libraries and symbols for the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_strings", "description": "Return printable strings extracted from the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "min_length": {"type": "integer"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "query_artifacts", "description": "Search artifacts (functions, strings) for a pattern. Supports regex.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "query": {"type": "string"}, "regex": {"type": "boolean"} }, "required": ["job_id", "query"] }}}
]

TOOL_INTENT_DESCRIPTIONS = {
    "list_functions": "Okay, I need to get the list of all functions first.",
    "decompile_function": "Now I will decompile that function to see the code.",
    "get_xrefs": "I'm checking for cross-references to see what calls this function.",
    "list_imports": "I'll start by listing the imported libraries and functions.",
    "list_strings": "Let me search for any interesting strings in the binary.",
    "query_artifacts": "I will perform a query to find relevant information.",
    "status": "Checking the status of the analysis job."
}

def call_ghidra_tool(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = requests.post(
            f"{GHIDRA_API_BASE}/tools/{endpoint}",
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"result": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def _normalize_symbol_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())

def resolve_function_addr(job_id: str, value: str) -> Dict[str, Any]:
    value = (value or "").strip()
    placeholder_match = re.fullmatch(r"<?(?:address|addr)?_?of_?(.+?)>?", value, re.IGNORECASE)
    if placeholder_match:
        value = placeholder_match.group(1)

    if re.fullmatch(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{6,}", value or ""):
        return {"addr": value}

    functions_result = call_ghidra_tool(
        "list_functions",
        {"job_id": job_id, "offset": 0, "limit": 5000}
    )
    functions = functions_result.get("functions") or []
    if not functions:
        return {"error": f"Could not resolve function name '{value}': no functions returned by Ghidra."}

    wanted = _normalize_symbol_name(value)
    by_normalized_name = {
        _normalize_symbol_name(fn.get("name", "")): fn
        for fn in functions
        if fn.get("name") and fn.get("addr")
    }

    if wanted in by_normalized_name:
        return {"addr": by_normalized_name[wanted]["addr"], "resolved_name": by_normalized_name[wanted]["name"]}

    matches = get_close_matches(wanted, by_normalized_name.keys(), n=5, cutoff=0.72)
    if matches:
        best = by_normalized_name[matches[0]]
        return {
            "addr": best["addr"],
            "resolved_name": best["name"],
            "candidates": [
                {"name": by_normalized_name[m]["name"], "addr": by_normalized_name[m]["addr"]}
                for m in matches
            ]
        }

    candidates = [
        {"name": fn.get("name"), "addr": fn.get("addr")}
        for fn in functions
        if value.lower() in fn.get("name", "").lower()
    ][:10]
    return {
        "error": f"Could not resolve function name '{value}' to an address.",
        "candidates": candidates
    }

def call_decompile_function(job_id: str, addr: str, **kwargs) -> Dict[str, Any]:
    resolved = resolve_function_addr(job_id, addr)
    if "error" in resolved:
        return resolved

    result = call_ghidra_tool("decompile_function", {"job_id": job_id, "addr": resolved["addr"]})
    if resolved.get("resolved_name"):
        result["resolved_name"] = resolved["resolved_name"]
    if resolved.get("candidates"):
        result["resolution_candidates"] = resolved["candidates"]
    return result

def call_get_xrefs(job_id: str, addr: str, **kwargs) -> Dict[str, Any]:
    resolved = resolve_function_addr(job_id, addr)
    if "error" in resolved:
        return resolved

    result = call_ghidra_tool("get_xrefs", {"job_id": job_id, "addr": resolved["addr"]})
    if resolved.get("resolved_name"):
        result["resolved_name"] = resolved["resolved_name"]
    return result

def build_function_context(job_id: str, requested_name: str) -> Dict[str, Any]:
    primary = call_decompile_function(job_id=job_id, addr=requested_name)
    recovery_index = build_recovery_index(job_id)
    context = {
        "requested_name": requested_name,
        "primary": primary,
        "recovery_index_summary": {
            "dynamic_modules": recovery_index.get("stages", {}).get("dynamic_modules", {}),
            "function_pointer_globals": recovery_index.get("stages", {}).get("function_pointer_globals", {}),
            "function_pointer_details": recovery_index.get("stages", {}).get("function_pointer_details", {}),
            "function_pointer_typedefs": recovery_index.get("stages", {}).get("function_pointer_typedefs", {}),
            "indirect_calls": recovery_index.get("stages", {}).get("indirect_calls", {}),
            "helper_renames": recovery_index.get("stages", {}).get("helper_renames", {}),
            "cpp_owners": recovery_index.get("stages", {}).get("cpp_owners", {}),
            "global_roles": recovery_index.get("stages", {}).get("global_roles", {}),
            "structure_candidates": recovery_index.get("stages", {}).get("structure_candidates", {}),
        }
    }

    primary_text = primary.get("result") or primary.get("pseudocode") or ""
    resolved_addr = None
    if primary.get("resolution_candidates"):
        resolved_addr = primary["resolution_candidates"][0].get("addr")
    elif primary.get("address"):
        resolved_addr = primary.get("address")

    if resolved_addr:
        context["xrefs"] = call_get_xrefs(job_id=job_id, addr=resolved_addr)

    related = []
    for addr in _extract_internal_call_addrs(primary_text):
        related_result = call_decompile_function(job_id=job_id, addr=addr)
        related.append({"addr": addr, "decompile": related_result})
    if related:
        context["related_internal_calls"] = related

    context["inferred_rename_map"] = infer_names_from_context(context)
    context["inferred_rename_map"].update(
        recovery_index.get("stages", {}).get("helper_renames", {})
    )
    context["inferred_rename_map"].update(
        recovery_index.get("stages", {}).get("function_pointer_globals", {})
    )
    context["inferred_rename_map"].update(
        recovery_index.get("stages", {}).get("dynamic_modules", {})
    )
    return context

class GhidraAssistant:
    def __init__(self):
        llm_config = get_llm_config()
        self.client = OpenAI(
           base_url=llm_config.api_base,
           api_key=llm_config.api_key
        )
        self.provider = llm_config.provider
        self.api_base = llm_config.api_base
        self.model = llm_config.model

        self.available_tools = {
            "status": lambda **kwargs: call_ghidra_tool("status", kwargs),
            "list_functions": lambda **kwargs: call_ghidra_tool("list_functions", kwargs),
            "decompile_function": call_decompile_function,
            "get_xrefs": call_get_xrefs,
            "list_imports": lambda **kwargs: call_ghidra_tool("list_imports", kwargs),
            "list_strings": lambda **kwargs: call_ghidra_tool("list_strings", kwargs),
            "query_artifacts": lambda **kwargs: call_ghidra_tool("query_artifacts", kwargs),
        }

        self.chats_dir = os.path.join(os.path.dirname(__file__), "chats")
        if not os.path.exists(self.chats_dir):
            os.makedirs(self.chats_dir)

    def _get_chat_file(self, job_id: str) -> str:
        return os.path.join(self.chats_dir, f"{job_id}.json")

    def _is_internal_context_message(self, message: Dict[str, Any]) -> bool:
        content = (message.get("content") or "").lstrip()
        return content.startswith("Ghidra function reconstruction context.")

    def _public_history(self, messages: list) -> list:
        result = []
        for message in messages:
            message = self._message_to_dict(message)
            if self._is_internal_context_message(message):
                continue
            result.append(message)
        return result

    def load_history(self, job_id: str) -> list:
        chat_file = self._get_chat_file(job_id)
        if os.path.exists(chat_file):
            try:
                with open(chat_file, 'r', encoding="utf-8") as f:
                    data = json.load(f)
                return self._public_history(data if isinstance(data, list) else [])
            except Exception:
                pass
        return []

    def save_history(self, job_id: str, messages: list):
        chat_file = self._get_chat_file(job_id)
        with open(chat_file, 'w', encoding="utf-8") as f:
            json.dump(self._public_history(messages), f, ensure_ascii=False, indent=2)

    def get_runtime_config(self) -> Dict[str, str]:
        return {
            "provider": self.provider,
            "api_base": self.api_base,
            "model": self.model,
            "ghidra_api_base": GHIDRA_API_BASE,
        }

    def _message_to_dict(self, message: Any) -> Dict[str, Any]:
        if isinstance(message, dict):
            return message

        result = {"role": message.role, "content": message.content}
        if getattr(message, "tool_calls", None):
            result["tool_calls"] = []
            for tc in message.tool_calls:
                result["tool_calls"].append({
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments
                    }
                })
        return result

    def _content_to_tool_calls(self, message: Dict[str, Any]) -> list:
        content = (message.get("content") or "").strip()
        if not content:
            return []

        fenced_match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
        if fenced_match:
            content = fenced_match.group(1).strip()

        parsed_objects = []
        try:
            parsed_objects.append(json.loads(content))
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            for match in re.finditer(r"\{", content):
                try:
                    parsed, _ = decoder.raw_decode(content[match.start():])
                except json.JSONDecodeError:
                    continue
                parsed_objects.append(parsed)

        tool_calls = []
        for parsed in parsed_objects:
            if not isinstance(parsed, dict):
                continue

            function_name = parsed.get("name") or parsed.get("function")
            arguments = parsed.get("arguments") or {}
            if function_name not in self.available_tools or not isinstance(arguments, dict):
                continue

            tool_calls.append({
                "id": f"local_call_{len(content)}_{len(tool_calls)}",
                "type": "function",
                "function": {
                    "name": function_name,
                    "arguments": json.dumps(arguments)
                }
            })

        return tool_calls

    def _extract_requested_function(self, user_message: str) -> Optional[str]:
        patterns = [
            r"(?:функци(?:ю|и|я)|function)\s+([A-Za-z_?@$][A-Za-z0-9_?@$:.<>~]*)",
            r"(?:decompile|reconstruct|restore|восстанови|декомпилируй|разбери)\s+([A-Za-z_?@$][A-Za-z0-9_?@$:.<>~]*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, user_message, re.IGNORECASE)
            if match:
                return match.group(1).strip("`'\".,;:()[]{}")
        return None

    def _answer_from_tool_context(self, messages: list) -> Generator[str, None, str]:
        complete_response_content = ""
        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True
        )
        for chunk in stream:
            content: Optional[str] = chunk.choices[0].delta.content
            if content:
                complete_response_content += content
                yield json.dumps({"type": "token", "content": content})
        return complete_response_content

    def _stream_final_response(self, messages: list) -> Generator[str, None, str]:
        complete_response_content = ""

        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True
        )

        for chunk in stream:
            content: Optional[str] = chunk.choices[0].delta.content
            if content:
                complete_response_content += content
                yield json.dumps({"type": "token", "content": content})

        return complete_response_content

    def chat_completion_stream(self, user_message: str, job_id: str) -> Generator[str, None, None]:
        history = self.load_history(job_id)

        if not history:
            history.append({"role": "system", "content": SYSTEM_PROMPT})

        if history[0]["role"] != "system":
            history.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

        history.append({"role": "user", "content": f"[Job ID: {job_id}] {user_message}"})
        messages = history

        requested_function = self._extract_requested_function(user_message)
        if requested_function:
            yield json.dumps({"type": "tool_call", "description": "Resolving and decompiling the requested function in Ghidra."})
            context = build_function_context(job_id=job_id, requested_name=requested_function)
            generate_recovered_files(job_id)
            yield json.dumps({"type": "tool_call", "description": "Recovered .h/.cpp drafts updated."})
            messages.append({
                "role": "user",
                "content": (
                    "Ghidra function reconstruction context. Use this evidence to answer the user's request. "
                    "Use related_internal_calls to infer helper semantics. "
                    "Answer in the same language as the user's request. "
                    "Clearly separate what the requested function does directly from what its helper calls do. "
                    "Produce the answer in this order:\n"
                    "1. `Recovered VC++ 2003-compatible code` - a clean code block with inferred meaningful names, not Ghidra names. "
                    "Use VC++ 2003-compatible Win32 C/C++ style; avoid C99/C++11+ syntax.\n"
                    "2. `Rename map` - compact mapping from original Ghidra symbols to inferred names.\n"
                    "3. `Notes` - only important uncertainties about types/calling convention.\n"
                    "Do not lead with prose analysis. Do not invent addresses or tool calls. "
                    "If the result is an error, explain it and list candidates.\n\n"
                    f"Requested function: {requested_function}\n"
                    f"Context JSON:\n{json.dumps(context, ensure_ascii=False, indent=2)}"
                )
            })
            try:
                final_response_content = yield from self._answer_from_tool_context(messages)
            except Exception as e:
                yield json.dumps({"type": "error", "content": f"LLM Error: {str(e)}"})
                return

            messages.append({"role": "assistant", "content": final_response_content})
            self.save_history(job_id, messages)
            return

        final_response_content = ""

        for _ in range(MAX_AGENT_TURNS):
            try:
                first_response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto"
                )
            except Exception as e:
                yield json.dumps({"type": "error", "content": f"LLM Error: {str(e)}"})
                return

            message = self._message_to_dict(first_response.choices[0].message)
            messages.append(message)

            tool_calls = message.get("tool_calls") or self._content_to_tool_calls(message)
            if tool_calls and "tool_calls" not in message:
                message["tool_calls"] = tool_calls
                message["content"] = None
            if not tool_calls:
                final_response_content = message.get("content") or ""
                if final_response_content:
                    yield json.dumps({"type": "token", "content": final_response_content})
                break

            for tool_call in tool_calls:
                function_name = tool_call["function"]["name"]
                if function_name in self.available_tools:
                    intent_description = TOOL_INTENT_DESCRIPTIONS.get(function_name, f"Executing tool: {function_name}...")
                    yield json.dumps({"type": "tool_call", "description": intent_description})

                    function_to_call = self.available_tools[function_name]
                    try:
                        args = json.loads(tool_call["function"].get("arguments") or "{}")
                    except Exception:
                        args = {}

                    args['job_id'] = job_id

                    result = function_to_call(**args)

                    messages.append({
                        "tool_call_id": tool_call["id"],
                        "role": "tool",
                        "name": function_name,
                        "content": json.dumps(result)
                    })
        else:
            try:
                final_response_content = yield from self._stream_final_response(messages)
                messages.append({"role": "assistant", "content": final_response_content})
            except Exception as e:
                yield json.dumps({"type": "error", "content": f"LLM Error: {str(e)}"})
                return

        self.save_history(job_id, messages)
