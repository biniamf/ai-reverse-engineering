# Biniam Demissie
# 09/29/2025
import os
import json
import requests
from typing import Dict, Any, Generator
from openai import OpenAI

GHIDRA_API_BASE = "http://localhost:9090"

SYSTEM_PROMPT = "You are a helpful reverse engineering assistant. You have access to a set of tools to analyze a binary identified by a job_id. When the user asks a question, use the available tools to find the answer. If something is not clear, ask for clarification before answering. Format your final response in Markdown. You can generate Call Graphs or Flowcharts using Mermaid.js syntax (wrap in ```mermaid code block) to visualize function relationships or logic flow."
MAX_AGENT_TURNS = 5

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
        response = requests.post(f"{GHIDRA_API_BASE}/tools/{endpoint}", json=payload)
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"result": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

class GhidraAssistant:
    def __init__(self):
        self.client = OpenAI(
           # e.g., https://api.openai.com/v1
           base_url=os.getenv("API_BASE"),
           api_key=os.getenv("API_KEY", "not-used")
        )
        self.model = os.getenv("MODEL_NAME")

        self.available_tools = {
            "status": lambda **kwargs: call_ghidra_tool("status", kwargs),
            "list_functions": lambda **kwargs: call_ghidra_tool("list_functions", kwargs),
            "decompile_function": lambda **kwargs: call_ghidra_tool("decompile_function", kwargs),
            "get_xrefs": lambda **kwargs: call_ghidra_tool("get_xrefs", kwargs),
            "list_imports": lambda **kwargs: call_ghidra_tool("list_imports", kwargs),
            "list_strings": lambda **kwargs: call_ghidra_tool("list_strings", kwargs),
            "query_artifacts": lambda **kwargs: call_ghidra_tool("query_artifacts", kwargs),
        }

        self.chats_dir = os.path.join(os.path.dirname(__file__), "chats")
        if not os.path.exists(self.chats_dir):
            os.makedirs(self.chats_dir)

    def _get_chat_file(self, job_id: str) -> str:
        return os.path.join(self.chats_dir, f"{job_id}.json")

    def load_history(self, job_id: str) -> list:
        chat_file = self._get_chat_file(job_id)
        if os.path.exists(chat_file):
            try:
                with open(chat_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def save_history(self, job_id: str, messages: list):
        chat_file = self._get_chat_file(job_id)
        with open(chat_file, 'w') as f:
            json.dump(messages, f, indent=2)

    def chat_completion_stream(self, user_message: str, job_id: str) -> Generator[str, None, None]:
        history = self.load_history(job_id)

        if not history or history[0].get("role") != "system":
            history.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

        history.append({"role": "user", "content": f"[Job ID: {job_id}] {user_message}"})
        messages = history

        finalized = False
        complete_response_content = ""

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

            message = first_response.choices[0].message
            messages.append(message)

            if not message.tool_calls:
                if message.content:
                    complete_response_content = message.content
                    yield json.dumps({"type": "token", "content": message.content})
                finalized = True
                break

            for tool_call in message.tool_calls:
                function_name = tool_call.function.name
                if function_name not in self.available_tools:
                    continue

                intent_description = TOOL_INTENT_DESCRIPTIONS.get(function_name, f"Executing tool: {function_name}...")
                yield json.dumps({"type": "tool_call", "description": intent_description})

                function_to_call = self.available_tools[function_name]
                try:
                    args = json.loads(tool_call.function.arguments)
                except Exception:
                    args = {}

                args['job_id'] = job_id

                result = function_to_call(**args)

                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": json.dumps(result)
                })

        # Only stream a final answer if the agent loop exhausted MAX_AGENT_TURNS
        # without producing one. Otherwise we'd call the LLM a second time and
        # emit the same response twice (doubling token cost and duplicating UI).
        if not finalized:
            try:
                stream = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    stream=True
                )
                for chunk in stream:
                    content = chunk.choices[0].delta.content
                    if content:
                        complete_response_content += content
                        yield json.dumps({"type": "token", "content": content})
            except Exception as e:
                yield json.dumps({"type": "error", "content": f"LLM Error: {str(e)}"})
                return

            messages.append({"role": "assistant", "content": complete_response_content})

        serializable_history = []
        for m in messages:
            if isinstance(m, dict):
                serializable_history.append(m)
            else:
                d = {"role": m.role, "content": m.content}
                if m.tool_calls:
                    d["tool_calls"] = []
                    for tc in m.tool_calls:
                        d["tool_calls"].append({
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        })
                serializable_history.append(d)

        self.save_history(job_id, serializable_history)
