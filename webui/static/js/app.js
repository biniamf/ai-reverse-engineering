// Biniam Demissie

import { api, ApiError } from "./api.js";
import { createStore } from "./state.js";
import { createJobsController } from "./jobs.js";
import { createChatController } from "./chat.js";
import { createAnalysisController } from "./analysis.js";
import { el } from "./render.js";
import { submitBlockReason } from "./composer.js";
import { isAnalysisReady, jobStateCopy } from "./jobLifecycle.js";

const store = createStore({
  selectedJob: null,
  selectedJobStatus: null,
  selectedThread: "main",
  tab: "chat",
  streaming: false,
});

// Readout (Ghidra reachability)
function setReadout(state, text) {
  const node = document.getElementById("readout");
  if (!node) return;
  node.dataset.state = state;
  node.querySelector(".readout__text").textContent = text;
}

// Tabs
function setupTabs(analysis) {
  const tabs = Array.from(document.querySelectorAll("[role=tab][data-tab]"));
  const panels = {
    chat: document.getElementById("panel-chat"),
    analysis: document.getElementById("panel-analysis"),
  };
  function activate(name) {
    store.set({ tab: name });
    for (const t of tabs) {
      const on = t.dataset.tab === name;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
    }
    for (const [key, panel] of Object.entries(panels)) {
      panel.dataset.active = key === name ? "true" : "false";
    }
    if (name === "analysis") analysis.activate();
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => activate(t.dataset.tab));
    t.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const dir = e.key === "ArrowRight" ? 1 : -1;
        const next = tabs[(i + dir + tabs.length) % tabs.length];
        next.focus();
        activate(next.dataset.tab);
      }
    });
  });
  return { activate };
}

// Upload dropzone
function setupUpload(jobs) {
  const zone = document.getElementById("dropzone");
  const input = document.getElementById("file-input");
  const statusEl = document.getElementById("upload-status");
  const fileLabel = document.getElementById("dropzone-file");

  function setStatus(kind, msg) {
    statusEl.dataset.kind = kind;
    statusEl.textContent = msg;
  }

  async function upload(file, { analyzeAsRaw = false } = {}) {
    if (!file) return;
    fileLabel.textContent = `${file.name} · ${formatBytes(file.size)}`;
    setStatus(
      "busy",
      analyzeAsRaw ? "Uploading as raw binary…" : "Uploading & queuing analysis…"
    );
    try {
      const data = await api.upload(file, undefined, { analyzeAsRaw });
      if (data && data.error) {
        setStatus("error", data.error);
        return;
      }
      setStatus("ok", "Analysis queued.");
      if (data && data.job_id) {
        jobs.addJob(
          { job_id: data.job_id, filename: file.name, status: data.status || "queued" },
          { prepend: true }
        );
        jobs.select(data.job_id);
      }
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.code === "confirmation_required" &&
        !analyzeAsRaw
      ) {
        const proceed =
          typeof window.confirm === "function" &&
          window.confirm(
            `${err.message}\n\nAnalyze it as a raw binary anyway? Ghidra may fail to import plain text.`
          );
        if (proceed) {
          await upload(file, { analyzeAsRaw: true });
        } else {
          setStatus("warning", "Upload cancelled: file appears to be plain text.");
        }
        return;
      }
      setStatus(
        "error",
        err instanceof ApiError ? err.message : "Upload failed."
      );
    }
  }

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      input.click();
    }
  });
  input.addEventListener("change", () => {
    if (input.files && input.files[0]) upload(input.files[0]);
  });
  ["dragenter", "dragover"].forEach((ev) =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.dataset.dragover = "true";
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.dataset.dragover = "false";
    })
  );
  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) upload(file);
  });
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return "";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

// Composer controls (mode / workflow / budget)
async function setupComposer(chat, tabs) {
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");
  const cancelBtn = document.getElementById("chat-cancel");
  const modeSel = document.getElementById("mode-select");
  const workflowSel = document.getElementById("workflow-select");
  const workflowField = document.getElementById("workflow-field");
  const budgetInput = document.getElementById("budget-input");
  const budgetField = document.getElementById("budget-field");
  const budgetHelp = document.getElementById("budget-help");
  const unboundedInput = document.getElementById("unbounded-input");
  const targetInput = document.getElementById("target-input");
  const targetField = document.getElementById("target-field");
  const targetHelp = document.getElementById("target-help");
  const scopeEl = document.getElementById("composer-scope");

  const BUDGET_MIN = parseInt(budgetInput.getAttribute("min"), 10) || 1;
  const BUDGET_MAX = parseInt(budgetInput.getAttribute("max"), 10) || 12;

  try {
    const data = await api.workflows();
    const workflows = (data && data.workflows) || [];
    for (const wf of workflows) {
      const opt = el("option", { text: wf.title || wf.name, attrs: { value: wf.name } });
      opt.dataset.scope = wf.scope || "";
      opt.dataset.description = wf.description || "";
      opt.dataset.budget = wf.default_budget || "";
      opt.dataset.requiresAddress = wf.requires_address ? "true" : "false";
      workflowSel.append(opt);
    }
  } catch {
    /* workflows are optional; copilot mode still works */
  }

  function currentWorkflowOpt() {
    return modeSel.value === "autonomous" ? workflowSel.selectedOptions[0] : null;
  }

  function selectDefaultWorkflow() {
    if (workflowSel.value || workflowSel.options.length < 2) return;
    workflowSel.selectedIndex = 1;
    const opt = workflowSel.selectedOptions[0];
    if (opt && opt.dataset.budget) budgetInput.value = opt.dataset.budget;
  }

  function syncBudgetEnabled() {
    // Budget applies to both modes now; the number input is disabled only when
    // "No step limit" is checked (the server caps unbounded at MAX_STEP_BUDGET).
    budgetInput.disabled = unboundedInput.checked;
  }

  function syncMode() {
    const autonomous = modeSel.value === "autonomous";
    workflowSel.disabled = !autonomous;
    workflowField.hidden = !autonomous;
    // Budget + unbounded stay visible in copilot too.
    if (autonomous) selectDefaultWorkflow();
    syncBudgetEnabled();
    updateScope();
  }

  function updateBudgetHelp() {
    budgetHelp.hidden = false;
    if (unboundedInput.checked) {
      budgetHelp.textContent =
        `No step limit (safety-capped at ${BUDGET_MAX}). The run continues ` +
        `until it finishes; cost grows with the number of tool/model calls.`;
    } else {
      budgetHelp.textContent =
        `Bounded steps (${BUDGET_MIN}–${BUDGET_MAX}). If the budget is reached, ` +
        `the run reports partial results and offers Continue — it never continues silently.`;
    }
  }

  function updateScope() {
    scopeEl.dataset.kind = modeSel.value;
    updateBudgetHelp();
    if (modeSel.value === "autonomous") {
      const opt = currentWorkflowOpt();
      const scope = opt ? opt.dataset.scope : "";
      const description = opt ? opt.dataset.description : "";
      const requiresAddress = Boolean(opt && opt.dataset.requiresAddress === "true");
      if (opt && opt.dataset.budget && !budgetInput.value) {
        budgetInput.value = opt.dataset.budget;
      }
      targetField.hidden = !requiresAddress;
      targetInput.hidden = !requiresAddress;
      targetInput.required = requiresAddress;
      targetInput.disabled = !requiresAddress;
      if (!requiresAddress) clearTargetError();
      scopeEl.innerHTML = "";
      scopeEl.append(
        el("b", { text: "Autonomous run. " }),
        document.createTextNode(
          `Bounded, read-only. ${description ? description + " " : ""}Scope: ${
            scope || "active job"
          }. The run stops at the step budget and reports partial results; it never widens its own scope.`
        )
      );
      if (requiresAddress) {
        scopeEl.append(
          document.createTextNode(
            " This workflow needs a target function: enter an address, or select a function in Analysis and choose Send to chat."
          )
        );
      }
    } else {
      targetField.hidden = true;
      targetInput.hidden = true;
      targetInput.required = false;
      targetInput.disabled = true;
      clearTargetError();
      scopeEl.innerHTML = "";
      scopeEl.append(
        el("b", { text: "Copilot. " }),
        document.createTextNode(
          "One bounded step per message over the selected job. Autonomous workflows, step budget, and target are available in Autonomous mode."
        )
      );
    }
  }

  function clearTargetError() {
    targetHelp.hidden = true;
    targetHelp.textContent = "";
    targetInput.removeAttribute("aria-invalid");
  }

  function showTargetError(msg) {
    targetHelp.hidden = false;
    targetHelp.textContent = msg;
    targetInput.setAttribute("aria-invalid", "true");
  }

  modeSel.addEventListener("change", syncMode);
  unboundedInput.addEventListener("change", () => {
    syncBudgetEnabled();
    updateBudgetHelp();
  });
  workflowSel.addEventListener("change", () => {
    const opt = workflowSel.selectedOptions[0];
    if (opt && opt.dataset.budget) budgetInput.value = opt.dataset.budget;
    updateScope();
  });
  targetInput.addEventListener("input", () => {
    if (targetInput.value.trim()) clearTargetError();
  });
  syncMode();

  chat.onStreamingChange((active) => {
    // Cancel stays available during a run; Send is swapped out. There is no
    // Pause control (the backend does not support pause/resume), so it is not
    // shown at all rather than faked.
    sendBtn.hidden = active;
    cancelBtn.hidden = !active;
    input.disabled = active;
  });

  // One pending evidence ref (from an Analysis "Send to chat" action). It is
  // attached to the next message, then cleared so it does not leak into later
  // turns. A workflow that requires an address uses the ref's address.
  let pendingEvidence = null;
  const readComposer = () => {
    const ref = pendingEvidence;
    pendingEvidence = null;
    const evidence = ref ? [ref] : null;
    const typedTarget = targetInput.value.trim();
    const target =
      (ref && ref.kind === "function" ? ref.addr : null) || typedTarget || null;
    const unbounded = unboundedInput.checked;
    return {
      mode: modeSel.value,
      workflow: modeSel.value === "autonomous" ? workflowSel.value || null : null,
      // Budget/unbounded now apply in both modes; the server caps at MAX_STEP_BUDGET.
      unbounded,
      stepBudget:
        !unbounded && budgetInput.value ? parseInt(budgetInput.value, 10) : null,
      evidence,
      target,
    };
  };

  function missingRequiredTarget() {
    const opt = currentWorkflowOpt();
    const selection = {
      mode: modeSel.value,
      workflow: opt
        ? { requiresAddress: opt.dataset.requiresAddress === "true" }
        : null,
    };
    const hasTarget = Boolean(
      targetInput.value.trim() || (pendingEvidence && pendingEvidence.addr)
    );
    return submitBlockReason(selection, hasTarget)
      ? (opt && opt.textContent) || "this workflow"
      : null;
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const msg = input.value.trim();
    if (!msg) return;
    // A required-but-missing target blocks submit inline (no stream started).
    const needs = missingRequiredTarget();
    if (needs) {
      showTargetError(`${needs} requires a target function address before it can run.`);
      targetInput.focus();
      return;
    }
    input.value = "";
    input.style.height = "auto";
    chat.send(msg);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit();
    }
  });
  input.addEventListener("input", () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 200) + "px";
  });
  cancelBtn.addEventListener("click", () => chat.cancel());

  return {
    input,
    readComposer,
    setPendingEvidence: (ref) => {
      pendingEvidence = ref || null;
      if (ref && ref.kind === "function" && ref.addr) {
        targetInput.value = ref.addr;
        clearTargetError();
      }
    },
    enable: (on) => {
      input.disabled = !on;
      sendBtn.disabled = !on;
    },
  };
}

// Boot
async function boot() {
  let composerApi = null;
  let getComposer = () => ({ mode: "copilot" });
  const chat = createChatController({
    store,
    getComposer: () => getComposer(),
    onEvidence: () => {},
    // A valid function citation navigates to the inspector for that address.
    onCitation: (c) => {
      if (c && c.kind === "function" && c.value) {
        tabsApi.activate("analysis");
        analysis.activate();
        analysis.inspectFunction(c.value);
      }
    },
    onSeedComposer: (text) => {
      tabsApi.activate("chat");
      const input = document.getElementById("chat-input");
      if (input) {
        input.value = text;
        input.focus();
      }
    },
  });

  const analysis = createAnalysisController({
    store,
    onSendEvidence: (ref) => {
      // Evidence handoff sends only structured entity refs (kind/addr/name),
      // never raw pseudocode. The server builds the trusted framing.
      const input = document.getElementById("chat-input");
      tabsApi.activate("chat");
      const addr = ref && ref.addr;
      input.value = addr
        ? `Explain the function at ${addr}. Cite evidence.`
        : "Explain the selected evidence. Cite evidence.";
      if (composerApi && composerApi.setPendingEvidence) {
        composerApi.setPendingEvidence(ref);
      }
      input.focus();
    },
  });

  function showJobState(job) {
    const copy = jobStateCopy(job);
    const title = document.getElementById("workspace-empty-title");
    const body = document.getElementById("workspace-empty-body");
    if (title) title.textContent = copy.title;
    if (body) body.textContent = copy.body;
    document.getElementById("workspace-empty").hidden = false;
    document.getElementById("workspace-body").hidden = true;
    if (composerApi) composerApi.enable(false);
    analysis.reset();
  }

  async function activateCompletedJob(jobId) {
    if (store.get().selectedJob !== jobId) return;
    document.getElementById("workspace-empty").hidden = true;
    document.getElementById("workspace-body").hidden = false;
    if (composerApi) composerApi.enable(true);
    analysis.reset();
    await chat.loadThreads(jobId);
    if (store.get().tab === "analysis") analysis.activate();
  }

  const jobs = createJobsController({
    store,
    onSelect: async (jobId, job) => {
      if (!isAnalysisReady(job && job.status)) {
        showJobState(job);
        return;
      }
      await activateCompletedJob(jobId);
    },
    onStatus: async (jobId, job) => {
      if (store.get().selectedJob !== jobId) return;
      store.set({ selectedJobStatus: String(job.status || "unknown").toLowerCase() });
      if (isAnalysisReady(job.status)) await activateCompletedJob(jobId);
      else showJobState(job);
    },
    onError: (err) => {
      if (err instanceof ApiError && err.code === "offline") {
        setReadout("offline", "Server offline");
      }
    },
    onRemove: (jobId) => {
      if (store.get().selectedJob === jobId) {
        store.set({ selectedJob: null, selectedJobStatus: null });
        document.getElementById("workspace-empty").hidden = false;
        document.getElementById("workspace-body").hidden = true;
        const title = document.getElementById("workspace-empty-title");
        const body = document.getElementById("workspace-empty-body");
        if (title) title.textContent = "No job selected";
        if (body) body.textContent =
          "Upload a binary or pick a job from the rail to open its chat and evidence workspace.";
        if (composerApi) composerApi.enable(false);
        analysis.reset();
      }
    },
  });

  const tabsApi = setupTabs(analysis);
  setupUpload(jobs);
  composerApi = await setupComposer(chat, tabsApi);
  if (composerApi) {
    getComposer = composerApi.readComposer;
    composerApi.enable(false);
  }

  setReadout("checking", "Connecting…");
  const ok = await jobs.load();
  setReadout(ok ? "online" : "offline", ok ? "Service online" : "Service offline");

  window.addEventListener("beforeunload", () => jobs.teardown());
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
