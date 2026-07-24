# Biniam Demissie
"""Operating modes and named autonomous workflows."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

MODE_COPILOT = "copilot"
MODE_AUTONOMOUS = "autonomous"
MODES = (MODE_COPILOT, MODE_AUTONOMOUS)


class ModeError(ValueError):
    """Raised when an unknown mode or workflow is requested."""


@dataclass(frozen=True)
class Workflow:
    """Metadata for a bounded autonomous workflow."""

    name: str
    title: str
    description: str
    prompt: str
    scope: str
    default_budget: int
    # Forced read-only checkpoints; the model chooses arguments and writes the result.
    required_tools: Tuple[str, ...] = ()
    requires_address: bool = False


WORKFLOWS: Dict[str, Workflow] = {
    "program_triage": Workflow(
        name="program_triage",
        title="Program triage",
        description=(
            "Summarize the program: metadata/status, imports, high-signal "
            "strings, and notable functions."
        ),
        prompt=(
            "Perform a bounded program triage of the active job. Start with "
            "get_program_summary, then inspect one bounded page each of imports, "
            "high-signal strings, and notable functions. Summarize the likely "
            "purpose and analysis coverage, citing concrete function addresses "
            "and strings. Do not page through the whole program or speculate "
            "beyond retrieved evidence."
        ),
        scope="Active job (whole program), read-only.",
        default_budget=6,
        required_tools=(
            "get_program_summary",
            "list_imports",
            "list_strings",
            "list_functions",
        ),
    ),
    "suspicious_behavior": Workflow(
        name="suspicious_behavior",
        title="Suspicious behavior review",
        description=(
            "Surface deterministic indicators (imports, strings, calls) first, "
            "then bounded hypotheses."
        ),
        prompt=(
            "Review the active job for suspicious behavior. Start with the "
            "deterministic program summary, then collect bounded indicators from "
            "imports, strings (URLs, commands, paths), and relevant functions. "
            "Use get_callgraph only for a selected indicator that needs reachability "
            "context. Present evidence with citations before any hypothesis, and "
            "label every hypothesis unconfirmed."
        ),
        scope="Active job (whole program), read-only.",
        default_budget=8,
        required_tools=(
            "get_program_summary",
            "list_imports",
            "list_strings",
            "list_security_functions",
        ),
    ),
    "selected_function": Workflow(
        name="selected_function",
        title="Selected function explanation",
        description=(
            "Decompile a function and its callers/callees, referenced strings "
            "and imports, with citations."
        ),
        prompt=(
            "Explain the selected function in the active job. Resolve the target "
            "exactly with list_functions(query=<target address>) and use the "
            "returned canonical entry; never use broad query_artifacts for address "
            "resolution. Decompile it, read immediate xrefs and a bounded "
            "get_callgraph neighborhood, then consult a small hexdump or analyst "
            "annotation only if it clarifies the function. Cite retrieved evidence "
            "and stay within the selected function and immediate neighbors. A tool "
            "error or empty xrefs is an evidence limitation, never proof the "
            "function is dead or uncalled."
        ),
        scope="One function and its immediate callers/callees, read-only.",
        default_budget=6,
        required_tools=(
            "list_functions",
            "decompile_function",
            "get_xrefs",
            "get_callgraph",
        ),
        requires_address=True,
    ),
    "call_chain": Workflow(
        name="call_chain",
        title="Call-chain exploration",
        description=(
            "Explore a bounded call-graph neighborhood and explain the path."
        ),
        prompt=(
            "Explore a bounded call-chain in the active job. Resolve the target "
            "exactly with list_functions(query=<target address>), then call "
            "get_callgraph once with a small depth/node limit. Explain only paths "
            "present in that bounded graph and cite each retrieved function "
            "address. Do not manually page xrefs or expand beyond the graph. Empty "
            "or truncated results are evidence limitations, not proof a function "
            "is dead or unreachable."
        ),
        scope="Bounded call-graph neighborhood, read-only.",
        default_budget=8,
        required_tools=("list_functions", "get_callgraph"),
        requires_address=True,
    ),
    "attack_surface_triage": Workflow(
        name="attack_surface_triage",
        title="Attack surface triage",
        description=(
            "Read the deterministic security summary and top ranked functions, "
            "then inspect a few selected high-priority functions in depth."
        ),
        prompt=(
            "Perform a bounded attack-surface triage of the active job. First "
            "call get_security_summary to read the band/category counts and "
            "coverage. Then call list_security_functions ONCE to get the small "
            "ranked head (do NOT call list_functions or page the whole program). "
            "Select at most 3 highest-priority functions and call "
            "get_security_function for each and retrieve the bounded import "
            "inventory. Before writing any final answer, you MUST deeply inspect "
            "at least the top candidate with "
            "decompile_function and a bounded get_callgraph (inspect a second only "
            "if the budget permits). Then summarize the "
            "prioritized attack surface, citing each function address and the "
            "signal evidence references. These scores are deterministic triage "
            "PRIORITIES, not vulnerability verdicts or exploitability claims: "
            "never state that a function is vulnerable or exploitable; describe "
            "only what the evidence shows and label any concern as an unconfirmed "
            "hypothesis to investigate. If the security index is unavailable, say "
            "so and recommend a rescore rather than guessing."
        ),
        scope=(
            "Active job: security summary + bounded ranked head, at most 3 "
            "selected functions and 1-2 deep inspections, read-only."
        ),
        default_budget=12,
        required_tools=(
            "get_security_summary",
            "list_security_functions",
            "get_security_function",
            "list_imports",
            "decompile_function",
            "get_callgraph",
        ),
    ),
    "vulnerability_hypothesis": Workflow(
        name="vulnerability_hypothesis",
        title="Vulnerability hypothesis review",
        description=(
            "Candidate, evidence, counter-evidence, uncertainty; never confirm "
            "from model text alone."
        ),
        prompt=(
            "Review one bounded vulnerability hypothesis in the active job. Use "
            "the security summary and one bounded ranked page to select a candidate "
            "unless the analyst already supplied one. Retrieve its score detail, "
            "decompilation, xrefs or bounded callgraph, and relevant bytes/types "
            "only when needed. Present supporting evidence, counter-evidence, and "
            "open questions with citations. Never label a vulnerability confirmed "
            "or infer exploitability from model reasoning or score alone."
        ),
        scope="Active job, read-only.",
        default_budget=8,
        required_tools=(
            "get_security_summary",
            "list_security_functions",
            "get_security_function",
            "list_imports",
            "decompile_function",
            "get_callgraph",
        ),
    ),
}


def validate_mode(mode: Optional[str]) -> str:
    """Return a validated mode string, defaulting to copilot."""
    if mode is None or mode == "":
        return MODE_COPILOT
    if not isinstance(mode, str):
        raise ModeError("mode must be a string")
    candidate = mode.strip().lower()
    if candidate not in MODES:
        raise ModeError(f"unknown mode {mode!r}; allowed: {MODES}")
    return candidate


def validate_workflow(mode: str, workflow: Optional[str]) -> Optional[Workflow]:
    """Validate the workflow selection for a mode."""
    if workflow in (None, ""):
        if mode == MODE_AUTONOMOUS:
            raise ModeError("autonomous mode requires a workflow")
        return None
    if not isinstance(workflow, str):
        raise ModeError("workflow must be a string")
    spec = WORKFLOWS.get(workflow.strip())
    if spec is None:
        raise ModeError(f"unknown workflow {workflow!r}")
    return spec


def list_workflows() -> List[Dict[str, str]]:
    """Public, safe metadata for surfacing available workflows to the UI."""
    return [
        {
            "name": wf.name,
            "title": wf.title,
            "description": wf.description,
            "scope": wf.scope,
            "default_budget": wf.default_budget,
            "requires_address": wf.requires_address,
        }
        for wf in WORKFLOWS.values()
    ]


# Machine-checkable citation syntax required of the model in every mode. The
# extractor/validator in webui/citations.py parses exactly these forms and
# checks each against retrieved/cached evidence before the UI links it.
CITATION_INSTRUCTIONS = (
    "Every factual claim about the binary MUST carry a machine-checkable "
    "citation in square brackets using one of these exact forms:\n"
    "  [function:0x<address>]  e.g. [function:0x401000]\n"
    "  [string:0x<address>]    e.g. [string:0x402010]\n"
    "  [import:NAME]           e.g. [import:CreateProcessA]\n"
    "A bracketed name such as [FUN_123] is NOT a citation. Before finalizing, "
    "check every binary-specific paragraph and replace plain brackets or bare "
    "addresses with one of the exact forms above. Only cite evidence actually "
    "retrieved with a tool in this conversation; never invent an address. If a "
    "retrieved item has no citable address/name, state the limitation instead of "
    "fabricating one. When stating a possible vulnerability, label it an "
    "unconfirmed hypothesis and give supporting and counter evidence; never "
    "present it as a confirmed finding."
)
