# Biniam Demissie
"""Single source of truth for the agent's callable tools."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from validation import (
    SECURITY_BANDS,
    SECURITY_CATEGORIES,
    SECURITY_ORDERS,
    SECURITY_SORTS,
    ValidationError,
    normalize_address,
    validate_pagination,
    validate_query,
    validate_security_query,
)

# Agent tools are capped tighter than the UI: the model never pages more than this many
# ranked functions in a single list call, and the default is 25.
SECURITY_TOOL_DEFAULT_LIMIT = 25
SECURITY_TOOL_MAX_LIMIT = 50


class ToolError(Exception):
    """Raised when a tool name is unknown or its arguments are invalid."""

    def __init__(self, message: str, *, tool: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.tool = tool


@dataclass(frozen=True)
class ArgSpec:
    """One accepted argument of a tool."""

    name: str
    json_type: str
    description: str
    required: bool = False
    normalizer: Optional[Callable[[Any], Any]] = None


def _norm_addr(value: Any) -> str:
    return normalize_address(value)


def _norm_query(value: Any) -> str:
    return validate_query(value)


def _make_int_normalizer(minimum: int, maximum: int):
    def _norm(value: Any) -> int:
        if isinstance(value, bool):
            raise ValidationError("expected an integer, not a boolean")
        if isinstance(value, int):
            candidate = value
        elif isinstance(value, str):
            stripped = value.strip()
            if not stripped.lstrip("+").isdigit():
                raise ValidationError("expected an integer")
            candidate = int(stripped)
        else:
            raise ValidationError("expected an integer")
        if candidate < minimum or candidate > maximum:
            raise ValidationError(
                f"value must be between {minimum} and {maximum}"
            )
        return candidate

    return _norm


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    raise ValidationError("expected a boolean")


@dataclass(frozen=True)
class ToolSpec:
    """A single declaratively-defined tool."""

    name: str
    endpoint: str
    description: str
    rationale: str
    max_result_chars: int
    args: List[ArgSpec] = field(default_factory=list)
    # Pagination is validated together (offset/limit interplay), so tools that accept it
    # opt in with this flag rather than an ArgSpec per field. Agent list tools use
    # tighter limits than browser routes to keep model context bounded independently of
    # service/UI maxima.
    paginated: bool = False
    page_default_limit: int = 100
    page_max_limit: int = 100
    # ``kind`` selects how the assistant dispatches the tool: "tool" -> the legacy
    # ``/tools/<endpoint>`` route via ``call_tool``; a "security_*" kind -> a typed
    # GhidraClient security method.
    kind: str = "tool"
    # The ranked-security-functions tool accepts band/category/min_score/sort/
    # order plus a *tightly bounded* offset/limit (default 25, hard max 50).
    # Validated as a group via validate_security_query rather than per-field.
    security_query: bool = False

    def openai_schema(self) -> Dict[str, Any]:
        """Build the OpenAI-compatible function schema for this tool."""
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for arg in self.args:
            properties[arg.name] = {
                "type": arg.json_type,
                "description": arg.description,
            }
            if arg.required:
                required.append(arg.name)
        if self.paginated:
            properties["offset"] = {
                "type": "integer",
                "description": "Zero-based start index for pagination.",
            }
            properties["limit"] = {
                "type": "integer",
                "description": (
                    f"Maximum results (default {self.page_default_limit}, "
                    f"hard maximum {self.page_max_limit})."
                ),
            }
        if self.security_query:
            properties["offset"] = {
                "type": "integer",
                "description": "Zero-based start index for pagination.",
            }
            properties["limit"] = {
                "type": "integer",
                "description": (
                    f"Maximum ranked functions to return (default "
                    f"{SECURITY_TOOL_DEFAULT_LIMIT}, hard maximum "
                    f"{SECURITY_TOOL_MAX_LIMIT})."
                ),
            }
            properties["band"] = {
                "type": "string",
                "enum": list(SECURITY_BANDS),
                "description": "Filter to one triage band.",
            }
            properties["category"] = {
                "type": "string",
                "enum": sorted(SECURITY_CATEGORIES),
                "description": "Filter to one evidence category.",
            }
            properties["min_score"] = {
                "type": "number",
                "description": "Only include functions scoring at least this (0-100).",
            }
            properties["sort"] = {
                "type": "string",
                "enum": list(SECURITY_SORTS),
                "description": "Sort key (default score).",
            }
            properties["order"] = {
                "type": "string",
                "enum": list(SECURITY_ORDERS),
                "description": "Sort order (default desc).",
            }
        schema: Dict[str, Any] = {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
            },
        }
        return schema

    def validate_arguments(self, raw: Any, *, job_id: str) -> Dict[str, Any]:
        """Return a validated payload for dispatch, or raise :class:`ToolError`."""
        if not isinstance(raw, dict):
            raise ToolError(
                "tool arguments must be a JSON object", tool=self.name
            )

        allowed = {arg.name: arg for arg in self.args}
        payload: Dict[str, Any] = {}

        pagination_fields = {"offset", "limit"} if self.paginated else set()
        security_fields = (
            {"offset", "limit", "band", "category", "min_score", "sort", "order"}
            if self.security_query
            else set()
        )
        for key in raw:
            if key == "job_id":
                continue
            if key in allowed or key in pagination_fields or key in security_fields:
                continue
            raise ToolError(
                f"unknown argument {key!r} for tool {self.name!r}",
                tool=self.name,
            )

        # Validate/normalize each declared argument.
        for arg in self.args:
            if arg.name not in raw:
                if arg.required:
                    raise ToolError(
                        f"missing required argument {arg.name!r} for tool "
                        f"{self.name!r}",
                        tool=self.name,
                    )
                continue
            value = raw[arg.name]
            try:
                payload[arg.name] = (
                    arg.normalizer(value) if arg.normalizer else value
                )
            except (ValidationError, ValueError) as exc:
                raise ToolError(
                    f"invalid value for argument {arg.name!r}: {exc}",
                    tool=self.name,
                ) from exc

        # Pagination is validated as a pair when present.
        if self.paginated:
            try:
                offset, limit = validate_pagination(
                    raw.get("offset", 0),
                    raw.get("limit", None),
                    default_limit=self.page_default_limit,
                    max_limit=self.page_max_limit,
                )
            except (ValidationError, ValueError) as exc:
                raise ToolError(
                    f"invalid pagination for tool {self.name!r}: {exc}",
                    tool=self.name,
                ) from exc
            if "offset" in raw:
                payload["offset"] = offset
            if "limit" in raw and raw.get("limit") not in (None, ""):
                payload["limit"] = limit

        # Ranked-security-functions query: validate the whole group with the agent-
        # tightened bounds (default 25, hard max 50).
        if self.security_query:
            try:
                validated = validate_security_query(
                    offset=raw.get("offset", 0),
                    limit=raw.get("limit", None),
                    band=raw.get("band"),
                    category=raw.get("category"),
                    min_score=raw.get("min_score"),
                    sort=raw.get("sort", "score"),
                    order=raw.get("order", "desc"),
                    default_limit=SECURITY_TOOL_DEFAULT_LIMIT,
                    max_limit=SECURITY_TOOL_MAX_LIMIT,
                )
            except (ValidationError, ValueError) as exc:
                raise ToolError(
                    f"invalid security query for tool {self.name!r}: {exc}",
                    tool=self.name,
                ) from exc
            payload.update(validated)

        # Forced job scope: always the active validated job id, never the
        # model's. This is the last write so it cannot be overridden.
        payload["job_id"] = job_id
        return payload


# One registry entry per supported read-only tool. ``analyze`` is intentionally
# excluded -- the chat agent never starts or mutates analysis.
_MIN_LENGTH_NORM = _make_int_normalizer(1, 4096)
_GRAPH_DEPTH_NORM = _make_int_normalizer(1, 3)
_GRAPH_NODES_NORM = _make_int_normalizer(1, 100)
_HEXDUMP_LENGTH_NORM = _make_int_normalizer(1, 4096)

REGISTRY: Dict[str, ToolSpec] = {
    "status": ToolSpec(
        name="status",
        endpoint="status",
        description="Get the analysis status for the active job.",
        rationale="Checking the status of the analysis job.",
        max_result_chars=4000,
    ),
    "get_program_summary": ToolSpec(
        name="get_program_summary",
        endpoint="summary",
        kind="summary",
        description=(
            "Get deterministic program metadata and artifact counts for the "
            "active job (program/language/compiler/image base/functions/imports/"
            "strings and schema provenance). Use this before whole-program triage."
        ),
        rationale="Reading the deterministic program summary.",
        max_result_chars=8000,
    ),
    "list_functions": ToolSpec(
        name="list_functions",
        endpoint="list_functions",
        kind="functions",
        description=(
            "List or globally search discovered functions for the active job. "
            "When the analyst gives a name or address, pass it as query: the "
            "service matches the COMPLETE program before pagination and returns "
            "the canonical function entry address. Use this exact-address lookup "
            "before decompile_function/get_xrefs; do not use query_artifacts for "
            "address resolution because suffix matches can select another function."
        ),
        rationale="Listing or resolving functions in the binary.",
        max_result_chars=20000,
        paginated=True,
        args=[
            ArgSpec(
                name="query",
                json_type="string",
                description=(
                    "Optional global function name or address query, e.g. "
                    "0x2c7c0. Matches across all pages before pagination."
                ),
                normalizer=_norm_query,
            )
        ],
    ),
    "decompile_function": ToolSpec(
        name="decompile_function",
        endpoint="decompile_function",
        description=(
            "Get decompiled pseudocode for the function at an address. Pass a "
            "function entry address (resolve a user-supplied address with "
            "list_functions(query=<address>), not broad query_artifacts). "
            "Padded and unpadded forms of the same address (e.g. "
            "0x0002c7c0 and 0x2c7c0) resolve identically; a 404 means no "
            "decompilation is stored for that function, not that the function "
            "is dead."
        ),
        rationale="Decompiling the function to inspect its pseudocode.",
        max_result_chars=20000,
        args=[
            ArgSpec(
                name="addr",
                json_type="string",
                description=(
                    "Function entry address, e.g. 0x401000. May be given with "
                    "or without a 0x prefix and with or without zero-padding."
                ),
                required=True,
                normalizer=_norm_addr,
            )
        ],
    ),
    "get_xrefs": ToolSpec(
        name="get_xrefs",
        endpoint="get_xrefs",
        description=(
            "Get callers and callees (cross-references) for a function. Pass a "
            "function entry address (resolve it first with "
            "list_functions(query=<address>), not broad query_artifacts). "
            "Padded and unpadded address forms resolve "
            "identically. An empty result means the function has no recorded "
            "references (known-empty) -- NOT that it is dead or unreachable; a "
            "404 means the address is not a known function."
        ),
        rationale="Checking cross-references to see what calls this function.",
        max_result_chars=12000,
        args=[
            ArgSpec(
                name="addr",
                json_type="string",
                description=(
                    "Function entry address, e.g. 0x401000. May be given with "
                    "or without a 0x prefix and with or without zero-padding."
                ),
                required=True,
                normalizer=_norm_addr,
            )
        ],
    ),
    "get_callgraph": ToolSpec(
        name="get_callgraph",
        endpoint="callgraph",
        kind="callgraph",
        description=(
            "Get a bounded caller/callee graph around one canonical function "
            "address. Prefer this over manually paging xrefs for multi-hop call "
            "chains; depth and node count are hard bounded."
        ),
        rationale="Reading a bounded call-graph neighborhood.",
        max_result_chars=16000,
        args=[
            ArgSpec(
                name="addr",
                json_type="string",
                description="Canonical function entry address.",
                required=True,
                normalizer=_norm_addr,
            ),
            ArgSpec(
                name="depth",
                json_type="integer",
                description="Call-graph depth (1-3, default 2).",
                normalizer=_GRAPH_DEPTH_NORM,
            ),
            ArgSpec(
                name="max_nodes",
                json_type="integer",
                description="Maximum graph nodes (1-100, default 40).",
                normalizer=_GRAPH_NODES_NORM,
            ),
        ],
    ),
    "list_imports": ToolSpec(
        name="list_imports",
        endpoint="list_imports",
        description="List imported libraries and symbols for the binary.",
        rationale="Listing the imported libraries and functions.",
        max_result_chars=12000,
    ),
    "list_strings": ToolSpec(
        name="list_strings",
        endpoint="list_strings",
        description="Return printable strings extracted from the binary.",
        rationale="Searching for interesting strings in the binary.",
        max_result_chars=20000,
        args=[
            ArgSpec(
                name="min_length",
                json_type="integer",
                description="Minimum string length to include (1-4096).",
                normalizer=_MIN_LENGTH_NORM,
            )
        ],
    ),
    "list_types": ToolSpec(
        name="list_types",
        endpoint="types",
        kind="types",
        description=(
            "List bounded recovered structures, enums, typedefs, arrays, and "
            "function definitions from the active job. Native v1 evidence only."
        ),
        rationale="Reading recovered data types.",
        max_result_chars=12000,
        paginated=True,
        page_default_limit=25,
        page_max_limit=100,
    ),
    "list_globals": ToolSpec(
        name="list_globals",
        endpoint="globals",
        kind="globals",
        description=(
            "List bounded recovered global variables/data symbols for the active "
            "job. Native v1 evidence only."
        ),
        rationale="Reading recovered globals.",
        max_result_chars=12000,
        paginated=True,
        page_default_limit=25,
        page_max_limit=100,
    ),
    "get_hexdump": ToolSpec(
        name="get_hexdump",
        endpoint="hexdump",
        kind="hexdump",
        description=(
            "Read a bounded hex slice from exported program memory at an address. "
            "This is analyzed image evidence, never an arbitrary filesystem read."
        ),
        rationale="Reading bounded bytes at an analyzed program address.",
        max_result_chars=12000,
        args=[
            ArgSpec(
                name="start",
                json_type="string",
                description="Start address in exported program memory.",
                required=True,
                normalizer=_norm_addr,
            ),
            ArgSpec(
                name="length",
                json_type="integer",
                description="Number of bytes (1-4096, default 64).",
                normalizer=_HEXDUMP_LENGTH_NORM,
            ),
        ],
    ),
    "get_annotations": ToolSpec(
        name="get_annotations",
        endpoint="annotations",
        kind="annotations",
        description=(
            "Read analyst sidecar annotations for the active job, optionally at "
            "one function address. Read-only: this tool never writes annotations."
        ),
        rationale="Reading analyst annotations without modifying evidence.",
        max_result_chars=8000,
        args=[
            ArgSpec(
                name="addr",
                json_type="string",
                description="Optional function address to filter annotations.",
                normalizer=_norm_addr,
            )
        ],
    ),
    "query_artifacts": ToolSpec(
        name="query_artifacts",
        endpoint="query_artifacts",
        description=(
            "Search function names/decompilation and strings for a content "
            "pattern; set regex true for regular-expression matching. This is a "
            "broad artifact search, not an exact address resolver. Use "
            "list_functions(query=<address-or-name>) to resolve canonical "
            "function entries before decompiling or reading xrefs."
        ),
        rationale="Querying artifacts to find relevant information.",
        max_result_chars=16000,
        args=[
            ArgSpec(
                name="query",
                json_type="string",
                description="Search text or pattern.",
                required=True,
                normalizer=_norm_query,
            ),
            ArgSpec(
                name="regex",
                json_type="boolean",
                description="Treat the query as a regular expression.",
                normalizer=_norm_bool,
            ),
        ],
    ),
    # ------------------------------------------------------------------ # Attack
    # surface / security index tools (Phase 1B; v1-only, read-only). Scores are
    # deterministic, evidence-based triage PRIORITIES -- never vulnerability verdicts or
    # exploitability claims.
    "get_security_summary": ToolSpec(
        name="get_security_summary",
        endpoint="security_summary",
        kind="security_summary",
        description=(
            "Get the attack-surface security summary for the active job: "
            "triage band counts, evidence category counts, coverage, and "
            "scorer/weights versions. Scores are deterministic triage "
            "priorities, not vulnerability verdicts. If the index is "
            "unavailable it reports that a rescore is needed."
        ),
        rationale="Reading the attack-surface security summary.",
        max_result_chars=8000,
    ),
    "list_security_functions": ToolSpec(
        name="list_security_functions",
        endpoint="security_functions",
        kind="security_functions",
        description=(
            "List the top ranked functions by attack-surface triage score for "
            "the active job (highest priority first). Returns a small bounded "
            "page (default 25, at most 50). Filter by band/category/min_score "
            "and sort by score/rank/name. These are triage priorities to "
            "inspect, not confirmed findings."
        ),
        rationale="Listing the top attack-surface ranked functions.",
        max_result_chars=16000,
        security_query=True,
    ),
    "get_security_function": ToolSpec(
        name="get_security_function",
        endpoint="security_function",
        kind="security_function",
        description=(
            "Get the ranked attack-surface explanation for one function: its "
            "score, band, confidence, categories, and the bounded signals with "
            "their weights, confidence class, and evidence references. Never "
            "returns pseudocode and never asserts a vulnerability -- use "
            "decompile_function/get_xrefs to inspect the evidence."
        ),
        rationale="Reading the ranked signals for one function.",
        max_result_chars=12000,
        args=[
            ArgSpec(
                name="addr",
                json_type="string",
                description="Function address, e.g. 0x401000.",
                required=True,
                normalizer=_norm_addr,
            )
        ],
    ),
}


def openai_tool_schemas() -> List[Dict[str, Any]]:
    """All tool schemas, in a stable registry order, for ``tools=`` requests."""
    return [spec.openai_schema() for spec in REGISTRY.values()]


def get_spec(name: str) -> ToolSpec:
    """Return the :class:`ToolSpec` for ``name`` or raise :class:`ToolError`."""
    spec = REGISTRY.get(name)
    if spec is None:
        raise ToolError(f"unknown tool {name!r}", tool=name)
    return spec


def cap_result_text(text: str, max_chars: int) -> str:
    """Cap a serialized tool result to ``max_chars`` with an omission marker."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    marker = f"... [truncated {len(text) - max_chars} chars]"
    if len(marker) >= max_chars:
        return text[:max_chars]
    keep = max_chars - len(marker)
    return text[:keep] + marker
