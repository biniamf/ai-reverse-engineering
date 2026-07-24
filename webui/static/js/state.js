// Biniam Demissie
// The timeline reducer is a PURE function of (previousTimeline,
// sseEvent).

// Event/field names that carry hidden model reasoning. These are never
// rendered, transmitted, or logged by the client. If the backend ever leaks
// one (it should not -- see webui/context.sanitize_message), we drop it here.
const REASONING_EVENT_TYPES = new Set([
  "reasoning",
  "thinking",
  "reasoning_content",
  "thought",
  "scratchpad",
]);

// Event types the timeline understands. Anything else (including unknown
// future or reasoning types) is ignored.
const KNOWN_EVENT_TYPES = new Set([
  "activity_start",
  "tool_call",
  "tool_result",
  "token",
  "warning",
  "error",
  "citations",
  "done",
]);

export function emptyTimeline() {
  return {
    started: false,
    mode: "copilot",
    workflow: null,
    scope: null,
    budget: null,
    steps: [], // {step, tool, rationale, args, status, durationMs, evidence}
    warnings: [],
    terminal: null, // {status, steps, toolCalls} | {status:"cancelled"} | {status:"error", message}
    answer: "", // accumulated final assistant text (rendered separately)
    // Structured citations validated server-side against retrieved evidence. Only
    // `validCitations` (function kind) become navigable links; invalid ones are
    // surfaced as warnings, never linked, so a hallucinated address is never presented
    // as confirmed evidence.
    validCitations: [], // [{kind, value, raw}]
    invalidCitations: [], // [{kind, value, raw}]
  };
}

function isReasoning(event) {
  if (!event || typeof event !== "object") return true;
  if (REASONING_EVENT_TYPES.has(event.type)) return true;
  return false;
}

/* Fold one SSE event into a timeline, returning a NEW timeline object. Unknown and
 * reasoning events are ignored. Never reads a `reasoning`/ `thinking` field even on a
 * known event. / */
export function reduceTimeline(prev, event) {
  const t = cloneTimeline(prev);
  if (isReasoning(event)) return t;
  const type = event.type;
  if (!KNOWN_EVENT_TYPES.has(type)) return t; // drop unknown types

  switch (type) {
    case "activity_start":
      t.started = true;
      t.mode = safeStr(event.mode) || "copilot";
      t.workflow = event.workflow != null ? safeStr(event.workflow) : null;
      t.scope = event.scope != null ? safeStr(event.scope) : null;
      t.budget = Number.isFinite(event.budget) ? event.budget : null;
      break;

    case "tool_call": {
      const step = {
        step: Number.isFinite(event.step) ? event.step : t.steps.length + 1,
        tool: safeStr(event.tool) || safeStr(event.description) || "tool",
        rationale: safeStr(event.rationale || event.description),
        args: safeStr(event.arguments),
        status: safeStr(event.status) || "running",
        durationMs: null,
        evidence: null,
      };
      const idx = t.steps.findIndex((s) => s.step === step.step);
      if (idx >= 0) t.steps[idx] = { ...t.steps[idx], ...step };
      else t.steps.push(step);
      break;
    }

    case "tool_result": {
      const idx = t.steps.findIndex((s) => s.step === event.step);
      const patch = {
        status: safeStr(event.status) || "done",
        durationMs: Number.isFinite(event.duration_ms) ? event.duration_ms : null,
        evidence: safeStr(event.evidence),
      };
      if (idx >= 0) t.steps[idx] = { ...t.steps[idx], ...patch };
      else
        t.steps.push({
          step: Number.isFinite(event.step) ? event.step : t.steps.length + 1,
          tool: safeStr(event.tool) || "tool",
          rationale: "",
          args: "",
          ...patch,
        });
      break;
    }

    case "token":
      t.answer += safeStr(event.content);
      break;

    case "warning":
      t.warnings.push(safeStr(event.content));
      break;

    case "citations": {
      // Server already validated these against retrieved evidence. We only
      // keep the machine-checkable fields; never any free-form model text.
      const sani = (list) =>
        (Array.isArray(list) ? list : [])
          .map((c) => ({
            kind: safeStr(c && c.kind),
            value: safeStr(c && c.value),
            raw: safeStr(c && c.raw),
          }))
          .filter((c) => c.kind && c.value);
      t.validCitations = sani(event.valid);
      t.invalidCitations = sani(event.invalid);
      break;
    }

    case "error":
      t.terminal = { status: "error", message: safeStr(event.content) };
      break;

    case "done":
      t.terminal = {
        status: safeStr(event.status) || "complete",
        steps: Number.isFinite(event.steps) ? event.steps : t.steps.length,
        toolCalls: Number.isFinite(event.tool_calls) ? event.tool_calls : null,
      };
      break;

    default:
      break;
  }
  return t;
}

/** Mark a timeline as cancelled by the analyst (client-side terminal state). */
export function markCancelled(prev) {
  const t = cloneTimeline(prev);
  // Any still-running step becomes "cancelled".
  for (const s of t.steps) {
    if (s.status === "running") s.status = "cancelled";
  }
  t.terminal = { status: "cancelled" };
  return t;
}

function cloneTimeline(t) {
  return {
    started: t.started,
    mode: t.mode,
    workflow: t.workflow,
    scope: t.scope,
    budget: t.budget,
    steps: t.steps.map((s) => ({ ...s })),
    warnings: t.warnings.slice(),
    terminal: t.terminal ? { ...t.terminal } : null,
    answer: t.answer,
    validCitations: (t.validCitations || []).map((c) => ({ ...c })),
    invalidCitations: (t.invalidCitations || []).map((c) => ({ ...c })),
  };
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

// Observable app store (browser runtime; the reducer above is what tests use)
export function createStore(initial) {
  let state = { ...initial };
  const listeners = new Set();
  return {
    get: () => state,
    set(patch) {
      state = { ...state, ...patch };
      for (const fn of listeners) fn(state);
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}
