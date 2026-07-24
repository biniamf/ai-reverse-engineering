
import { api, ApiError } from "./api.js";
import { el } from "./render.js";
import {
  STATUS_FILTERS,
  normalizeJobSearch,
  matchesJobQuery,
  matchesStatusFilter,
} from "./jobsSearch.js";

// Every terminal state stops polling -- including `interrupted` (a job the
// service abandoned on restart) and `cancelled`, not only done/failed.
const TERMINAL = new Set([
  "done",
  "completed",
  "failed",
  "error",
  "cancelled",
  "interrupted",
]);
const POLL_BASE_MS = 1500;
const POLL_MAX_MS = 30000;
const POLL_FACTOR = 1.6;
// Give up polling a job that never reaches a terminal state to avoid an
// unbounded background timer.
const POLL_MAX_ATTEMPTS = 40;

export function isTerminalStatus(status) {
  return TERMINAL.has(String(status || "").toLowerCase());
}

/** Next backoff delay (ms), bounded by POLL_MAX_MS. Pure/testable. */
export function nextBackoff(prevMs) {
  const base = prevMs && prevMs > 0 ? prevMs : POLL_BASE_MS / POLL_FACTOR;
  return Math.min(Math.round(base * POLL_FACTOR), POLL_MAX_MS);
}

const SEARCH_DEBOUNCE_MS = 150;

export function createJobsController({ store, onSelect, onStatus, onError, onRemove }) {
  const listEl = document.getElementById("jobs-list");
  const emptyEl = document.getElementById("jobs-empty");
  const pollers = new Map(); // jobId -> {timer, delay, attempts}
  const rows = new Map(); // jobId -> {row, chip, meta, job}

  // ---- Search / status-filter toolbar ------------------------------------ Client-
  // side only: filters the rows that already exist in the DOM by toggling `hidden` (see
  // .job[hidden] handling via the global [hidden] rule in layout.css).
  const searchInput = document.getElementById("jobs-search-input");
  const searchClearBtn = document.getElementById("jobs-search-clear");
  const filtersEl = document.getElementById("jobs-status-filters");
  const countEl = document.getElementById("jobs-count");
  const filteredEmptyEl = document.getElementById("jobs-filtered-empty");
  const filteredEmptyClearBtn = document.getElementById("jobs-filtered-empty-clear");

  let searchQuery = "";
  let statusFilter = "all";
  let searchDebounceTimer = null;
  const filterKeys = STATUS_FILTERS.map((f) => f.key);
  const filterButtons = new Map(); // key -> button

  if (filtersEl) {
    for (const f of STATUS_FILTERS) {
      const btn = el("button", {
        class: "jobs-toolbar__filter",
        text: f.label,
        attrs: {
          type: "button",
          "data-filter": f.key,
          "aria-pressed": f.key === statusFilter ? "true" : "false",
        },
      });
      btn.addEventListener("click", () => setStatusFilter(f.key));
      btn.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        e.preventDefault();
        const idx = filterKeys.indexOf(f.key);
        const dir = e.key === "ArrowRight" ? 1 : -1;
        const nextKey = filterKeys[(idx + dir + filterKeys.length) % filterKeys.length];
        const nextBtn = filterButtons.get(nextKey);
        if (nextBtn) {
          nextBtn.focus();
          setStatusFilter(nextKey);
        }
      });
      filterButtons.set(f.key, btn);
      filtersEl.append(btn);
    }
  }

  function setStatusFilter(key) {
    statusFilter = key;
    for (const [k, btn] of filterButtons) {
      btn.setAttribute("aria-pressed", k === key ? "true" : "false");
    }
    applyFilter();
  }

  function setSearchQuery(value) {
    searchQuery = value;
    if (searchClearBtn) searchClearBtn.hidden = !searchQuery;
    applyFilter();
  }

  function clearSearch() {
    clearTimeout(searchDebounceTimer);
    if (searchInput) searchInput.value = "";
    setSearchQuery("");
    if (searchInput) searchInput.focus();
  }

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      const value = searchInput.value;
      // Un-hide the clear button immediately (no debounce) so it always
      // reflects what's actually typed; the filter application itself is
      // debounced to avoid re-filtering on every keystroke of a fast typist.
      if (searchClearBtn) searchClearBtn.hidden = !value;
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => setSearchQuery(value), SEARCH_DEBOUNCE_MS);
    });
    searchInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        clearSearch();
      }
    });
  }
  if (searchClearBtn) {
    searchClearBtn.addEventListener("click", () => clearSearch());
  }
  if (filteredEmptyClearBtn) {
    filteredEmptyClearBtn.addEventListener("click", () => {
      clearSearch();
      setStatusFilter("all");
    });
  }

  /** Re-apply the current search query + status filter to every existing
   * row. Pure side effect on already-rendered DOM: toggles `hidden`, never
   * adds/removes/reorders a row, never touches a poller or the selection. */
  function applyFilter() {
    let visible = 0;
    const total = rows.size;
    for (const entry of rows.values()) {
      const normalized = normalizeJobSearch(entry.job);
      const matches =
        matchesStatusFilter(normalized, statusFilter) &&
        matchesJobQuery(normalized, searchQuery);
      entry.row.hidden = !matches;
      if (matches) visible += 1;
    }
    if (countEl) countEl.textContent = total > 0 ? `${visible} of ${total}` : "";
    if (filteredEmptyEl) filteredEmptyEl.hidden = !(total > 0 && visible === 0);
  }

  // Non-terminal jobs can be cancelled; any job can be deleted (with confirm).
  function isCancellable(status) {
    const s = String(status || "").toLowerCase();
    return s === "queued" || s === "running" || s === "" || s === "unknown";
  }

  function statusChip(status) {
    const s = String(status || "unknown").toLowerCase();
    return el("span", {
      class: "chip",
      attrs: { "data-status": s, role: "status" },
      children: [el("span", { class: "chip__led" }), el("span", { text: s.toUpperCase() })],
    });
  }

  function renderRow(job) {
    const jobId = job.job_id;
    const name = job.filename || "Unknown binary";
    const created = job.created_at
      ? new Date(job.created_at * 1000).toLocaleString()
      : "";
    const chip = statusChip(job.status);
    const meta = el("span", {
      class: "job__meta",
      children: [
        el("span", { class: "job__id", text: `#${String(jobId).slice(0, 8)}` }),
        el("span", { text: created ? ` · ${created}` : "" }),
      ],
    });
    // The selectable main control is a button; action buttons live OUTSIDE it
    // (a button cannot legally nest interactive controls).
    const main = el("button", {
      class: "job__main",
      attrs: {
        type: "button",
        "data-job-id": jobId,
        "aria-current": "false",
      },
      children: [
        el("span", { class: "job__name", text: name, attrs: { title: name } }),
        el("span", { class: "job__status", children: [chip] }),
        meta,
      ],
    });
    main.addEventListener("click", () => select(jobId));

    const cancelBtn = el("button", {
      class: "job__action job__action--cancel",
      text: "Cancel",
      attrs: { type: "button", title: "Cancel this analysis" },
    });
    cancelBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      cancelJob(jobId);
    });
    const deleteBtn = el("button", {
      class: "job__action job__action--delete",
      text: "Delete",
      attrs: { type: "button", title: "Delete this job", "aria-label": `Delete job ${String(jobId).slice(0, 8)}` },
    });
    deleteBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteJob(jobId);
    });

    const actions = el("div", {
      class: "job__actions",
      children: [cancelBtn, deleteBtn],
    });
    const row = el("div", {
      class: "job",
      attrs: { role: "listitem" },
      children: [main, actions],
    });
    rows.set(jobId, { row, main, chip, meta, cancelBtn, job });
    applyActionState(jobId, job.status);
    return row;
  }

  function applyActionState(jobId, status) {
    const entry = rows.get(jobId);
    if (!entry || !entry.cancelBtn) return;
    // Cancel is only meaningful while the job is still running/queued.
    entry.cancelBtn.hidden = !isCancellable(status);
  }

  function updateRowStatus(jobId, status) {
    const entry = rows.get(jobId);
    if (!entry) return;
    const previous = String(entry.job.status || "").toLowerCase();
    const chip = statusChip(status);
    entry.chip.replaceWith(chip);
    entry.chip = chip;
    entry.job.status = status;
    applyActionState(jobId, status);
    const current = String(status || "").toLowerCase();
    if (current !== previous && onStatus) onStatus(jobId, entry.job);
    // A status transition (e.g. running -> done) can move a row in/out of
    // the active status filter's Active/Done/Failed/Cancelled/Interrupted
    // bucket, so visibility is re-evaluated for every transition.
    applyFilter();
  }

  async function cancelJob(jobId) {
    try {
      const out = await api.cancelJob(jobId);
      updateRowStatus(jobId, (out && out.status) || "cancelled");
      stopPoll(jobId);
    } catch (err) {
      if (onError) onError(err);
    }
  }

  async function deleteJob(jobId) {
    const label = rows.get(jobId)?.job?.filename || jobId;
    const ok =
      typeof window !== "undefined" && typeof window.confirm === "function"
        ? window.confirm(`Delete job "${label}"? This cannot be undone.`)
        : true;
    if (!ok) return;
    try {
      await api.deleteJob(jobId);
      stopPoll(jobId);
      const entry = rows.get(jobId);
      if (entry && entry.row && entry.row.parentNode) {
        entry.row.parentNode.removeChild(entry.row);
      }
      rows.delete(jobId);
      refreshEmptyState();
      applyFilter();
      if (onRemove) onRemove(jobId);
    } catch (err) {
      if (onError) onError(err);
    }
  }

  function refreshEmptyState() {
    if (emptyEl) emptyEl.hidden = rows.size > 0;
  }

  function select(jobId) {
    for (const [id, entry] of rows) {
      const control = entry.main || entry.row;
      control.setAttribute("aria-current", id === jobId ? "true" : "false");
    }
    const job = rows.get(jobId)?.job || null;
    store.set({
      selectedJob: jobId,
      selectedJobStatus: job ? String(job.status || "unknown").toLowerCase() : "unknown",
    });
    if (onSelect) onSelect(jobId, job);
  }

  function stopPoll(jobId) {
    const p = pollers.get(jobId);
    if (p) {
      clearTimeout(p.timer);
      pollers.delete(jobId);
    }
  }

  function startPoll(jobId) {
    if (pollers.has(jobId)) return; // one timer per job
    const p = { timer: null, delay: 0, attempts: 0 };
    pollers.set(jobId, p);

    const tick = async () => {
      p.attempts += 1;
      try {
        const data = await api.jobStatus(jobId);
        const status = (data && data.status) || "unknown";
        updateRowStatus(jobId, status);
        if (isTerminalStatus(status)) {
          stopPoll(jobId);
          return;
        }
      } catch (err) {
        if (err instanceof ApiError && err.code === "offline" && onError) {
          onError(err);
        }
      }
      if (p.attempts >= POLL_MAX_ATTEMPTS) {
        stopPoll(jobId);
        return;
      }
      p.delay = nextBackoff(p.delay);
      p.timer = setTimeout(tick, p.delay);
    };

    p.delay = POLL_BASE_MS;
    p.timer = setTimeout(tick, p.delay);
  }

  function addJob(job, { prepend = false } = {}) {
    if (rows.has(job.job_id)) {
      updateRowStatus(job.job_id, job.status);
    } else {
      const row = renderRow(job);
      if (prepend && listEl.firstChild) listEl.insertBefore(row, listEl.firstChild);
      else listEl.append(row);
      // A freshly-added row must be filtered against the current search
      // query/status filter immediately, not left visible until the next
      // unrelated status transition happens to re-run applyFilter().
      applyFilter();
    }
    refreshEmptyState();
    if (!isTerminalStatus(job.status)) startPoll(job.job_id);
  }

  async function load() {
    try {
      const data = await api.listJobs();
      // The normalized route returns {items:[...]}; older/legacy shapes used
      // {jobs:[...]} or a bare array. Accept all three.
      const jobs = Array.isArray(data)
        ? data
        : (data && (data.items || data.jobs)) || null;
      if (Array.isArray(jobs)) {
        for (const job of jobs) if (job && job.job_id) addJob(job);
      }
      refreshEmptyState();
      applyFilter();
      return true;
    } catch (err) {
      if (onError) onError(err);
      refreshEmptyState();
      return false;
    }
  }

  function teardown() {
    for (const id of Array.from(pollers.keys())) stopPoll(id);
    clearTimeout(searchDebounceTimer);
  }

  return {
    load,
    addJob,
    select,
    teardown,
    isTerminalStatus,
    setSearchQuery,
    setStatusFilter,
    getFilterState: () => ({ query: searchQuery, statusFilter }),
  };
}
