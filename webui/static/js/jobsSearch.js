// Biniam Demissie
// Jobs rail search/filter: pure, dependency-free helpers. Everything
// here operates ONLY on the already-redacted job record the server sends (see
// webui/ghidra_client.py:_JOB_SAFE_FIELDS / redact_job).

// Status filter chips shown in the toolbar, in display order. "all" always matches; the
// rest match a job's normalized (lowercased) status, with a couple of UI aliases folded
// onto the same chip (e.g. "done" also covers the legacy "completed" status string).
export const STATUS_FILTERS = Object.freeze([
  { key: "all", label: "All" },
  { key: "active", label: "Active" },
  { key: "done", label: "Done" },
  { key: "failed", label: "Failed" },
  { key: "cancelled", label: "Cancelled" },
  { key: "interrupted", label: "Interrupted" },
]);

const STATUS_FILTER_KEYS = new Set(STATUS_FILTERS.map((f) => f.key));

// Statuses considered "Done" for the Done chip (includes the legacy alias).
const DONE_STATUSES = new Set(["done", "completed", "ok"]);
// Statuses considered "Failed" for the Failed chip (includes the legacy alias).
const FAILED_STATUSES = new Set(["failed", "error"]);
// Every status that is NOT active, mirroring webui/static/js/jobs.js's isTerminalStatus
// set (done/completed/failed/error/cancelled/interrupted). A job is "Active" iff its
// status is not in this terminal set -- so any unrecognized/future in-progress status
// (e.g.
const TERMINAL_STATUSES = new Set([
  "done",
  "completed",
  "failed",
  "error",
  "cancelled",
  "interrupted",
]);

function lower(v) {
  return String(v == null ? "" : v).trim().toLowerCase();
}

/* Normalize a single redacted job record into a flat, lowercase, searchable string plus
 * a normalized status. Pure and total: never throws on missing or malformed fields. */
export function normalizeJobSearch(job) {
  const j = job && typeof job === "object" ? job : {};
  const jobId = j.job_id != null ? String(j.job_id) : "";
  const shortId = jobId.slice(0, 8);
  const status = lower(j.status);
  const parts = [
    jobId,
    shortId,
    j.filename,
    j.status,
    j.error_code,
    j.message,
    j.sha256,
    formatTimestamp(j.created_at),
    formatTimestamp(j.started_at),
    formatTimestamp(j.completed_at),
  ];
  const haystack = parts
    .map((p) => (p == null ? "" : String(p)))
    .filter(Boolean)
    .join(" ␟ ") // unit-separator join; never matches user input
    .toLowerCase();
  return { jobId, shortId, status, haystack };
}

function formatTimestamp(v) {
  if (v == null || v === "") return "";
  const n = Number(v);
  if (!Number.isFinite(n)) return String(v);
  try {
    return new Date(n * 1000).toISOString();
  } catch {
    return String(v);
  }
}

/* Does a job's normalized search text match a free-text query? Semantics: AND across
 * whitespace-separated terms (every term must appear somewhere in the haystack), case-
 * insensitive, substring match. An empty or whitespace-only query matches everything. / */
export function matchesJobQuery(normalized, query) {
  const q = lower(query);
  if (!q) return true;
  const hay = (normalized && normalized.haystack) || "";
  const terms = q.split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  return terms.every((term) => hay.includes(term));
}

/* Does a job's normalized status match a status filter key? `filter` is validated
 * against STATUS_FILTERS; an unknown key behaves like "all" (matches everything) rather
 * than throwing or hiding every row. / */
export function matchesStatusFilter(normalized, filter) {
  const key = STATUS_FILTER_KEYS.has(filter) ? filter : "all";
  const status = (normalized && normalized.status) || "";
  switch (key) {
    case "all":
      return true;
    case "active":
      return !TERMINAL_STATUSES.has(status);
    case "done":
      return DONE_STATUSES.has(status);
    case "failed":
      return FAILED_STATUSES.has(status);
    case "cancelled":
      return status === "cancelled";
    case "interrupted":
      return status === "interrupted";
    default:
      return true;
  }
}

export function jobMatches(job, query, statusFilter) {
  const normalized = normalizeJobSearch(job);
  return (
    matchesStatusFilter(normalized, statusFilter) &&
    matchesJobQuery(normalized, query)
  );
}
