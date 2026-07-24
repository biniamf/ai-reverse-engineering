
export const BUDGET_MIN = 1;
export const BUDGET_MAX = 12;

export function clampBudget(value, min = BUDGET_MIN, max = BUDGET_MAX) {
  const n = typeof value === "number" ? value : parseInt(value, 10);
  if (!Number.isFinite(n)) return null;
  return Math.max(min, Math.min(Math.trunc(n), max));
}

export function controlState(selection) {
  const autonomous = selection.mode === "autonomous";
  const wf = autonomous ? selection.workflow || null : null;
  const requiresAddress = Boolean(wf && wf.requiresAddress);
  return {
    workflowEnabled: autonomous,
    budgetEnabled: autonomous,
    targetVisible: requiresAddress,
    targetRequired: requiresAddress,
    defaultBudget: wf && wf.defaultBudget ? clampBudget(wf.defaultBudget) : null,
  };
}

/* Is submission blocked because a required target is missing? Returns null when OK, or a
 * short reason string when blocked. `hasTarget` is true when a typed address or a
 * pending evidence ref is present. / */
export function submitBlockReason(selection, hasTarget) {
  const state = controlState(selection);
  if (state.targetRequired && !hasTarget) {
    return "requires a target function address";
  }
  return null;
}

/** Build the safe chat payload fields for a selection (evidence/target added
 * by the caller). Autonomous-only fields are dropped in copilot mode. */
export function composePayload(selection, { budgetValue } = {}) {
  const out = { mode: selection.mode };
  if (selection.mode === "autonomous") {
    if (selection.workflowName) out.workflow = selection.workflowName;
    const b = clampBudget(budgetValue);
    if (b !== null) out.stepBudget = b;
  }
  return out;
}
