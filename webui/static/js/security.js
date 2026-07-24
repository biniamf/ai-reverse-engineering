// Biniam Demissie
// Pure shaping helpers for the Attack Surface view.

export const TRIAGE_DISCLAIMER =
  "Scores are deterministic, evidence-based triage priorities — not " +
  "vulnerability verdicts, exploitability claims, or model-generated findings. " +
  "Use them to decide what to inspect first.";

export const ZERO_SIGNAL_CAVEAT =
  "No scoring signals detected. This does not imply the function is safe.";

// The Rev·Deck ranked table is bounded tighter than the raw service page: it
// never loads all rows into the DOM. Default 25, hard maximum 100 per request.
export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

export const CATEGORY_LABELS = {
  attack_surface: "Attack surface",
  memory_safety: "Memory safety",
  format_string: "Format string",
  command_execution: "Command execution",
  filesystem_loading: "Filesystem / loading",
  integer_allocation: "Integer / allocation",
  auth_privilege: "Auth / privilege",
  crypto_verification: "Crypto / verification",
  indirect_call: "Indirect call",
  coverage_uncertainty: "Coverage uncertainty",
  native_interop: "Native interop / JNI",
  android_input: "Android input / buffers",
  device_integrity: "Device integrity",
  anti_analysis: "Anti-analysis",
  mitigation: "Mitigating factor",
};

export function categoryLabel(slug) {
  return CATEGORY_LABELS[String(slug || "")] || String(slug || "");
}

export const BANDS = ["critical", "high", "medium", "low"];
const BAND_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function bandLabel(band) {
  return BAND_LABELS[String(band || "").toLowerCase()] || "—";
}

function str(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/* Is this summary document the "index unavailable" envelope (missing / stale / corrupt /
 * building)? The summary route answers HTTP 200 for these, so the caller must branch on
 * the body, not the status. / */
export function isUnavailable(summary) {
  return Boolean(summary && typeof summary === "object" && summary.available === false);
}

/**
 * Normalize the unavailable envelope into {status, rescoreAvailable, message}.
 * Tolerates a missing status. Never fabricates a verdict.
 */
export function unavailableInfo(summary) {
  const status = str((summary && summary.status) || "unavailable") || "unavailable";
  const rescoreAvailable =
    !summary || summary.rescore_available === undefined
      ? true
      : Boolean(summary.rescore_available);
  const known = {
    missing: "No security index has been built for this job yet.",
    stale: "The security index is out of date relative to the analysis artifacts.",
    corrupt: "The security index could not be read and needs to be rebuilt.",
    building: "A security index rescore is currently running.",
    unavailable: "The security index is not available for this job.",
  };
  return {
    status,
    rescoreAvailable,
    building: status === "building",
    message: known[status] || known.unavailable,
  };
}

/* Shape an available summary document into flat render data: { versions, counts,
 * bands:[{band,label,count}], categories:[{category,count}], coverage:[{label,value}],
 * meta:[{label,value}] }. Every field is defensive: absent pieces simply produce empty
 * lists. / */
export function summaryView(summary) {
  const doc = summary && typeof summary === "object" ? summary : {};
  const s = doc.summary && typeof doc.summary === "object" ? doc.summary : {};
  const coverage = doc.coverage && typeof doc.coverage === "object" ? doc.coverage : {};
  const meta = doc.metadata && typeof doc.metadata === "object" ? doc.metadata : {};

  const bandCounts = s.bands && typeof s.bands === "object" ? s.bands : {};
  const bands = BANDS.map((band) => ({
    band,
    label: bandLabel(band),
    count: num(bandCounts[band]) || 0,
  }));

  const catCounts = s.categories && typeof s.categories === "object" ? s.categories : {};
  const categories = Object.keys(catCounts)
    .sort()
    .map((category) => ({ category, count: num(catCounts[category]) || 0 }));

  const total = num(s.total_functions);

  const versions = {
    schema: str(doc.schema_version),
    scorer: str(doc.scorer_version),
    weights: str(doc.weights_version),
    artifact: str(meta.artifact_schema_version),
    downgraded: coverage.scorer_downgraded === true,
  };

  const coverageRows = [];
  const covScore = num(coverage.score);
  if (covScore != null) {
    coverageRows.push({ label: "Coverage score", value: covScore.toFixed(3) });
  }
  const flag = (label, key) => {
    if (coverage[key] === true) coverageRows.push({ label, value: "yes" });
  };
  flag("Functions truncated", "functions_truncated");
  flag("Edges truncated", "edges_truncated");
  flag("Strings truncated", "strings_truncated");
  flag("Legacy artifacts", "legacy_artifacts");
  flag("Downgraded rescore", "scorer_downgraded");
  const invalid = num(coverage.invalid_functions);
  if (invalid != null && invalid > 0) {
    coverageRows.push({ label: "Invalid functions", value: String(invalid) });
  }

  // Per-component coverage (scorer v2). Each is a 0..1 ratio; render as a
  // percentage so a low structural-typing / decompile / Android-metadata
  // coverage is visible next to the score.
  const componentLabels = {
    entry_export: "Entry / export",
    call_edges: "Call edges",
    param_types: "Parameter types",
    local_types: "Local types",
    import_resolution: "Import resolution",
    string_refs: "String references",
    decompile: "Decompilation",
    indirect_resolution: "Indirect targets",
    android_jni: "Android / JNI",
  };
  const components = coverage.components && typeof coverage.components === "object" ? coverage.components : {};
  const componentRows = Object.keys(componentLabels)
    .filter((key) => num(components[key]) != null)
    .map((key) => ({ label: componentLabels[key], value: `${Math.round(num(components[key]) * 100)}%` }));

  const unresolved = num(s.unresolved_indirect_calls);
  const rootCount = num(s.root_count);
  const androidFns = num(s.android_functions);
  const durationMs = num(meta.scoring_duration_ms);
  const metaRows = [];
  if (total != null) metaRows.push({ label: "Ranked functions", value: String(total) });
  if (rootCount != null) metaRows.push({ label: "Attack-surface roots", value: String(rootCount) });
  if (androidFns != null && androidFns > 0)
    metaRows.push({ label: "Android / JNI functions", value: String(androidFns) });
  if (unresolved != null)
    metaRows.push({ label: "Unresolved indirect calls", value: String(unresolved) });
  if (durationMs != null)
    metaRows.push({ label: "Scoring time (ms)", value: durationMs.toFixed(1) });

  return {
    versions,
    total,
    bands,
    categories,
    coverage: coverageRows,
    components: componentRows,
    meta: metaRows,
  };
}

/* Extract a bounded, defensive list of ranked-function rows from a list response
 * ({items, pagination}). Each row: {rank, addr, name, score, band, confidence,
 * categories:[...]}. Never returns more than the server page. / */
export function functionRows(data) {
  const items = data && Array.isArray(data.items) ? data.items : [];
  return items.map((it) => {
    const o = it && typeof it === "object" ? it : {};
    const score = num(o.score);
    const confidence = num(o.confidence);
    return {
      rank: num(o.rank),
      addr: str(o.addr || o.address),
      name: str(o.name),
      score: score != null ? score : null,
      band: str(o.band).toLowerCase(),
      confidence: confidence != null ? confidence : null,
      categories: Array.isArray(o.categories) ? o.categories.map(str).filter(Boolean) : [],
    };
  });
}

/** Read {total, offset, limit} from a list response's pagination, defensively. */
export function pagination(data) {
  const p = data && data.pagination && typeof data.pagination === "object" ? data.pagination : {};
  return {
    total: num(p.total) || 0,
    offset: num(p.offset) || 0,
    limit: num(p.limit) || DEFAULT_PAGE_SIZE,
  };
}

export function pageLabel(data) {
  const { total, offset, limit } = pagination(data);
  const shown = functionRows(data).length;
  if (total === 0 || shown === 0) return "No ranked functions";
  const start = offset + 1;
  const end = offset + shown;
  return `Showing ${start}–${end} of ${total}`;
}

export function hasNextPage(data) {
  const { total, offset, limit } = pagination(data);
  return offset + limit < total;
}

export function hasPrevPage(data) {
  return pagination(data).offset > 0;
}

export function formatScore(score) {
  const n = num(score);
  return n == null ? "—" : n.toFixed(1);
}

export function formatConfidence(confidence) {
  const n = num(confidence);
  return n == null ? "—" : `${Math.round(n * 100)}%`;
}

/* Shape a function-detail document into render data. Signals keep their exact
 * weight/confidence/category/id and evidence references (kind/ref/detail); no pseudocode
 * is ever present in this document, and none is synthesized here. / */
export function detailView(detail) {
  const d = detail && typeof detail === "object" ? detail : {};
  const rawSignals = Array.isArray(d.signals) ? d.signals : [];
  const signals = rawSignals.map((sig) => {
    const s = sig && typeof sig === "object" ? sig : {};
    const weight = num(s.weight);
    const evidence = Array.isArray(s.evidence) ? s.evidence : [];
    return {
      signalId: str(s.signal_id),
      category: str(s.category),
      weight: weight != null ? weight : null,
      weightLabel: weight == null ? "—" : (weight > 0 ? `+${weight}` : String(weight)),
      confidence: str(s.confidence),
      evidence: evidence.map((e) => {
        const ev = e && typeof e === "object" ? e : {};
        return {
          kind: str(ev.kind),
          ref: str(ev.ref),
          detail: ev.detail == null ? "" : str(ev.detail),
        };
      }),
    };
  });
  // Split signals into positive (aggravating) evidence and signed mitigating
  // factors so the view can present them SEPARATELY (plan §11). A mitigating
  // signal is one with a negative weight or the "mitigation" category.
  const positive = signals.filter((sig) => sig.category !== "mitigation" && (sig.weight == null || sig.weight >= 0));
  const mitigating = signals.filter((sig) => sig.category === "mitigation" || (sig.weight != null && sig.weight < 0));
  const score = num(d.score);
  const zeroSignal = positive.length === 0 && (score == null || score <= 0);

  return {
    rank: num(d.rank),
    addr: str(d.addr || d.address),
    name: str(d.name),
    score,
    band: str(d.band).toLowerCase(),
    confidence: num(d.confidence),
    categories: Array.isArray(d.categories) ? d.categories.map(str).filter(Boolean) : [],
    signals,
    positiveSignals: positive,
    mitigatingSignals: mitigating,
    zeroSignal,
    zeroSignalCaveat: zeroSignal ? ZERO_SIGNAL_CAVEAT : "",
  };
}
