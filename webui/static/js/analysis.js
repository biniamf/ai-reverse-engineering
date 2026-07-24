// Biniam Demissie
// Every accessor is defensive: response shapes vary between the legacy
// and v1 Ghidra services, so the UI degrades to a clear, capability-gated placeholder
// when a field or whole feature is absent -- it never fabricates data.

import { api, ApiError } from "./api.js";
import { el } from "./render.js";
import {
  TRIAGE_DISCLAIMER,
  ZERO_SIGNAL_CAVEAT,
  DEFAULT_PAGE_SIZE as SEC_PAGE_SIZE,
  MAX_PAGE_SIZE as SEC_MAX_PAGE_SIZE,
  BANDS as SEC_BANDS,
  CATEGORY_LABELS as SEC_CATEGORY_LABELS,
  categoryLabel,
  bandLabel,
  isUnavailable,
  unavailableInfo,
  summaryView,
  functionRows,
  pageLabel as secPageLabel,
  hasNextPage as secHasNext,
  hasPrevPage as secHasPrev,
  formatScore,
  formatConfidence,
  detailView,
} from "./security.js";

const PAGE_SIZE = 100;
const MAX_ROWS = 500; // bounded DOM per view

// Security category slugs -> readable labels for chips. The full label map
// (including the scorer v2 native-interop / android-input / device-integrity /
// anti-analysis / mitigation categories) is defined once in security.js.
function secCategoryLabel(slug) {
  return categoryLabel(slug);
}

// Views always available against the legacy service.
const CORE_VIEWS = [
  { id: "summary", label: "Summary" },
  { id: "functions", label: "Functions" },
  { id: "imports", label: "Imports" },
  { id: "strings", label: "Strings" },
  { id: "query", label: "Query" },
];
const V1_VIEWS = [
  { id: "attack_surface", label: "Attack Surface", feature: "attack_surface" },
  { id: "types", label: "Types", feature: "types" },
  { id: "globals", label: "Globals", feature: "globals" },
];

export function createAnalysisController({ store, onSendEvidence }) {
  const rootEl = document.getElementById("analysis");
  const listEl = document.getElementById("analysis-list");
  const detailEl = document.getElementById("analysis-detail");
  const subtabsEl = document.getElementById("analysis-subtabs");

  let view = "summary";
  let offset = 0;
  let loadToken = 0; // guards against out-of-order async responses
  let functionsToken = 0; // dedicated guard for the debounced functions search
  let selectedAddr = null;
  let functionFilter = "";
  // Whether the connected service can search functions globally (v1 q=). A
  // legacy service cannot; the view then degrades to a labelled current-page
  // filter instead of implying it searched the whole program.
  let functionsSearchSupported = true;
  let capabilities = null; // {features:{types:{available},...}} | null

  // Attack Surface view state. Server-side pagination + filters; the ranked
  // table never loads all rows into the DOM (bounded to one page).
  const sec = {
    offset: 0,
    limit: SEC_PAGE_SIZE,
    band: "",
    category: "",
    minScore: "",
    query: "", // name/address substring (server-backed q=)
    rank: "", // exact rank (server-backed rank=)
    sort: "score",
    order: "desc",
  };
  let secSearchToken = 0; // out-of-order guard for the debounced AS search
  function resetSecurity() {
    sec.offset = 0;
    sec.limit = SEC_PAGE_SIZE;
    sec.band = "";
    sec.category = "";
    sec.minScore = "";
    sec.query = "";
    sec.rank = "";
    sec.sort = "score";
    sec.order = "desc";
  }

  function jobId() {
    return store.get().selectedJob;
  }

  function openInspector() {
    if (rootEl) rootEl.dataset.detail = "open";
  }

  function closeInspector({ focusList = true } = {}) {
    // Invalidate any in-flight detail fetch so a late response cannot repaint
    // the pane we are closing.
    loadToken++;
    selectedAddr = null;
    if (detailEl) detailEl.replaceChildren();
    if (rootEl) rootEl.dataset.detail = "closed";
    refreshSelection();
    if (focusList && listEl && typeof listEl.focus === "function") {
      const active = listEl.querySelector('.addr[aria-current="true"]') || null;
      (active && typeof active.focus === "function" ? active : listEl).focus();
    }
  }

  // A visible, keyboard-focusable Close control for a detail header. Shared by
  // the function inspector and the security detail so both close identically.
  function closeInspectorButton() {
    const btn = el("button", {
      class: "detail__close",
      attrs: {
        type: "button",
        title: "Close inspector and return to the full-width list",
        "aria-label": "Close inspector",
      },
      children: [
        el("span", { class: "detail__close__x", attrs: { "aria-hidden": "true" }, text: "✕" }),
        el("span", { text: "Close" }),
      ],
    });
    btn.addEventListener("click", () => closeInspector());
    return btn;
  }

  function featureAvailable(name) {
    return Boolean(
      capabilities &&
        capabilities.features &&
        capabilities.features[name] &&
        capabilities.features[name].available
    );
  }

  async function ensureCapabilities() {
    if (capabilities !== null) return;
    try {
      capabilities = await api.capabilities();
    } catch {
      capabilities = { tier: "unknown", reachable: false, features: {} };
    }
  }

  function placeholder(title, body, glyph = "▤") {
    return el("div", {
      class: "placeholder",
      children: [
        el("div", { class: "placeholder__glyph", text: glyph }),
        el("p", { class: "placeholder__title", text: title }),
        el("p", { class: "placeholder__body", text: body }),
      ],
    });
  }

  function capabilityGate(feature) {
    return placeholder(
      `${feature} requires the v1 analysis service`,
      "The currently connected Ghidra service does not expose this data. " +
        "It will appear automatically once the service is upgraded to the v1 API. " +
        "No placeholder or fabricated data is shown.",
      "⛔"
    );
  }

  function errorState(err) {
    const capReq = err instanceof ApiError && err.code === "capability_required";
    if (capReq) {
      return placeholder(
        "Requires the v1 analysis service",
        (err && err.message) ||
          "This feature is not available on the connected Ghidra service.",
        "⛔"
      );
    }
    const offline =
      err instanceof ApiError && (err.code === "offline" || err.status === 504);
    return placeholder(
      offline ? "Analysis service offline" : "Could not load analysis data",
      offline
        ? "The Ghidra analysis service is unreachable. Data will load once it responds."
        : (err && err.message) || "An unexpected error occurred.",
      "⚠"
    );
  }

  function loadingState() {
    return el("div", {
      class: "placeholder",
      children: [
        el("span", { class: "spinner", attrs: { "aria-hidden": "true" } }),
        el("p", { class: "placeholder__body", text: "Loading…" }),
      ],
    });
  }

  function renderSubtabs() {
    subtabsEl.replaceChildren();
    const views = [...CORE_VIEWS, ...V1_VIEWS];
    let activeBtn = null;
    for (const v of views) {
      const gated = v.feature && !featureAvailable(v.feature);
      const btn = el("button", {
        class: "subtab" + (gated ? " subtab--gated" : ""),
        text: v.label + (gated ? " ·v1" : ""),
        attrs: {
          type: "button",
          role: "tab",
          "aria-selected": v.id === view ? "true" : "false",
          id: `subtab-${v.id}`,
          title: gated ? "Requires the v1 analysis service" : "",
        },
      });
      if (v.id === view) activeBtn = btn;
      btn.addEventListener("click", () => {
        view = v.id;
        offset = 0;
        // Changing evidence view must not carry a stale inspector across: the
        // selection and detail pane belong to the previous view. Close it so we
        // return to the full-width browse column for the new view.
        closeInspector({ focusList: false });
        if (v.id === "attack_surface") resetSecurity();
        renderSubtabs();
        refresh();
      });
      subtabsEl.append(btn);
    }
    if (activeBtn && typeof activeBtn.scrollIntoView === "function") {
      activeBtn.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
  }

  function pickList(data, ...keys) {
    if (Array.isArray(data)) return data;
    if (data && typeof data === "object") {
      for (const k of keys) if (Array.isArray(data[k])) return data[k];
    }
    return null;
  }

  // A table cell for an entity address/name. The second argument makes the navigation
  // intent EXPLICIT rather than assuming every address is a function: * onOpen (a
  // function) -> render a clickable, keyboard-operable control that invokes
  // onOpen(value) when.
  function entityCell(value, onOpen) {
    const cell = el("td");
    if (value === undefined || value === null || value === "") {
      cell.textContent = "—";
      return cell;
    }
    const text = str(value);
    if (typeof onOpen !== "function") {
      // Plain display: a pseudo-address (EXTERNAL:*), a string location, or any
      // token we deliberately do not treat as a navigable code address.
      cell.append(el("span", { class: "addr addr--plain", text }));
      return cell;
    }
    const a = el("span", {
      class: "addr addr--link",
      text,
      attrs: { role: "button", tabindex: "0", title: "Open inspector" },
    });
    const open = () => onOpen(text);
    a.addEventListener("click", open);
    a.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });
    cell.append(a);
    return cell;
  }

  // A clickable function-address cell (the common case). Only wires navigation when the
  // value is a genuine navigable code address per the backend's 1..16 hex-digit policy;
  // otherwise the value is shown as plain text so an import/string/namespace token can
  // never.
  function addrCell(addr) {
    if (isNavigableCodeAddress(addr)) {
      return entityCell(addr, (a) => inspectFunction(a));
    }
    return entityCell(addr, null);
  }

  function nameCell(name, addr) {
    const label = name || "—";
    if (isNavigableCodeAddress(addr)) {
      return entityCell(label, () => inspectFunction(str(addr)));
    }
    return el("td", { text: label });
  }

  function renderSummary(data) {
    if (!data || typeof data !== "object") {
      listEl.replaceChildren(placeholder("No summary", "No summary was returned for this job."));
      return;
    }
    const rows = [];
    const push = (label, value) => {
      if (value === undefined || value === null || value === "") return;
      rows.push(
        el("tr", {
          children: [
            el("th", { attrs: { scope: "row" }, text: label }),
            el("td", { text: typeof value === "object" ? JSON.stringify(value) : str(value) }),
          ],
        })
      );
    };
    push("Program", data.program || data.filename);
    push("Status", data.status);
    push("Language", data.language);
    push("Compiler", data.compiler);
    push("Image base", data.image_base);
    push("SHA-256", data.sha256 || data.hash);
    push("MD5", data.md5);
    push("Functions", data.function_count);
    push("Analyzer", data.analyzer_version);
    push("Schema", data.schema_version);
    push("Elapsed", data.analysis_time || data.elapsed);

    const provenance = el("div", {
      class: "provenance",
      children: [
        el("span", { class: "tag tag--fact", text: "deterministic" }),
        el("span", {
          class: "provenance__src",
          text:
            data.source === "v1"
              ? "source: v1 service document"
              : "source: synthesized from status + functions (legacy service)",
        }),
      ],
    });

    const table = el("table", {
      class: "data-table kv-table",
      attrs: { "aria-label": "Program summary" },
    });
    const tbody = el("tbody");
    if (!rows.length) {
      tbody.append(
        el("tr", {
          children: [el("td", { attrs: { colspan: "2" }, text: "No summary fields available yet." })],
        })
      );
    }
    for (const r of rows) tbody.append(r);
    table.append(tbody);

    const warnings = pickList(data.warnings, "warnings");
    const parts = [provenance, table];

    // Bounded archive export (feature-gated). A same-origin download link --
    // the browser never sees the Ghidra URL and never extracts archive paths.
    if (featureAvailable("export")) {
      const exportLink = el("a", {
        class: "btn btn--sm",
        text: "Export archive (.zip)",
        attrs: {
          href: api.exportUrl(jobId()),
          download: "",
          title: "Download a bounded ZIP of metadata, artifacts, annotations, and manifest",
        },
      });
      parts.push(el("div", { class: "analysis__toolbar", children: [exportLink] }));
    }
    if (Array.isArray(warnings) && warnings.length) {
      const ul = el("ul", { class: "warn-list" });
      for (const w of warnings.slice(0, 50)) ul.append(el("li", { text: str(w) }));
      parts.push(el("p", { class: "label", text: "Warnings" }), ul);
    }
    listEl.replaceChildren(el("div", { class: "summary", children: parts }));
  }

  // Function search is server-backed across the full program, not the current page.
  let functionsFilterInput = null;

  function renderFunctionsShell() {
    functionsFilterInput = el("input", {
      class: "field",
      attrs: {
        type: "search",
        placeholder: "Search functions by name or address…",
        "aria-label": "Search functions",
        value: functionFilter,
      },
    });
    const status = el("p", {
      class: "analysis__search-note",
      attrs: { role: "status", id: "functions-search-note" },
    });
    const tableHost = el("div", { class: "functions-table-host" });

    let debounce = null;
    functionsFilterInput.addEventListener("input", () => {
      functionFilter = functionsFilterInput.value;
      offset = 0; // a new query starts at the first page
      clearTimeout(debounce);
      debounce = setTimeout(() => loadFunctionsPage(tableHost, status), 150);
    });

    const toolbar = el("div", { class: "analysis__toolbar", children: [functionsFilterInput, status] });
    listEl.replaceChildren(toolbar, tableHost);
    loadFunctionsPage(tableHost, status);
  }

  async function loadFunctionsPage(tableHost, status) {
    const q = functionFilter.trim();
    const token = ++functionsToken;
    tableHost.replaceChildren(loadingState());
    let data;
    try {
      data = await api.functions(jobId(), { offset, limit: PAGE_SIZE, query: q || undefined });
    } catch (err) {
      if (token !== functionsToken) return; // superseded by a newer keystroke
      tableHost.replaceChildren(errorState(err));
      return;
    }
    if (token !== functionsToken) return; // out-of-order: a newer search won
    functionsSearchSupported = data && data.search_supported !== false;
    renderFunctionsTable(data, tableHost, status, q);
    if (functionsFilterInput && typeof functionsFilterInput.focus === "function") {
      const active = document.activeElement;
      if (active !== functionsFilterInput) {
        if (!active || active === document.body || active === listEl) {
          functionsFilterInput.focus();
        }
      }
    }
  }

  function renderFunctionsTable(data, tableHost, status, q) {
    let fns = pickList(data, "functions", "results", "items");
    if (!fns) {
      tableHost.replaceChildren(
        placeholder(
          "No function data",
          "The analysis service did not return a function list for this job. It may still be analyzing, or this build does not expose functions."
        )
      );
      if (status) status.textContent = "";
      return;
    }

    // Legacy fallback: no global search. Apply a local, current-page-only
    // filter and clearly say so, rather than implying the whole program was
    // searched.
    let localFiltered = false;
    if (q && !functionsSearchSupported) {
      const needle = q.toLowerCase();
      fns = fns.filter((fn) => {
        const name = str(fn.name || fn.symbol || fn.label || "").toLowerCase();
        const addr = str(fn.address || fn.addr || fn.entry || fn.ea || "").toLowerCase();
        return name.includes(needle) || addr.includes(needle);
      });
      localFiltered = true;
    }

    if (status) {
      if (!q) {
        status.textContent = "";
      } else if (localFiltered) {
        status.textContent =
          "This service cannot search all pages; filtering the current page only.";
      } else {
        const total =
          data && data.pagination && typeof data.pagination.total === "number"
            ? data.pagination.total
            : null;
        status.textContent =
          total != null ? `${total} match${total === 1 ? "" : "es"} across all pages.` : "";
      }
    }

    const table = el("table", { class: "data-table", attrs: { "aria-label": "Functions" } });
    table.append(
      el("thead", {
        html: "<tr><th>Address</th><th>Name</th><th>Size</th><th>Refs</th></tr>",
      })
    );
    const tbody = el("tbody");
    if (!fns.length) {
      tbody.append(
        el("tr", {
          children: [
            el("td", {
              attrs: { colspan: "4" },
              text: q ? `No functions match "${q}".` : "No functions.",
            }),
          ],
        })
      );
    }
    for (const fn of fns.slice(0, MAX_ROWS)) {
      const addr = str(fn.address || fn.addr || fn.entry || fn.ea);
      const name = str(fn.display_name || fn.name || fn.symbol || fn.label || "");
      const size = fn.size !== undefined ? str(fn.size) : "";
      const refs =
        fn.xref_count !== undefined
          ? str(fn.xref_count)
          : fn.references !== undefined
          ? str(fn.references)
          : "";
      tbody.append(
        el("tr", {
          attrs: { "aria-current": addr === selectedAddr ? "true" : "false" },
          children: [
            addrCell(addr),
            nameCell(name, addr),
            el("td", { text: size || "—" }),
            el("td", { text: refs || "—" }),
          ],
        })
      );
    }
    table.append(tbody);
    const total =
      data && data.pagination && typeof data.pagination.total === "number"
        ? data.pagination.total
        : null;
    tableHost.replaceChildren(
      table,
      functionsPager(fns.length, total, tableHost, status)
    );
  }

  function functionsPager(count, total, tableHost, status) {
    const prev = el("button", { class: "btn btn--sm btn--ghost", text: "‹ Prev", attrs: { type: "button" } });
    const next = el("button", { class: "btn btn--sm btn--ghost", text: "Next ›", attrs: { type: "button" } });
    prev.disabled = offset === 0;
    next.disabled = total != null ? offset + count >= total : count < PAGE_SIZE;
    prev.addEventListener("click", () => {
      offset = Math.max(0, offset - PAGE_SIZE);
      loadFunctionsPage(tableHost, status);
    });
    next.addEventListener("click", () => {
      offset += PAGE_SIZE;
      loadFunctionsPage(tableHost, status);
    });
    return el("div", {
      class: "pager",
      children: [prev, el("span", { text: `Rows ${count ? offset + 1 : offset}–${offset + count}` }), next],
    });
  }

  function renderImports(data) {
    const imports = pickList(data, "imports", "results", "items");
    if (!imports) {
      listEl.replaceChildren(placeholder("No import data", "No imports were returned for this job."));
      return;
    }
    const table = el("table", { class: "data-table", attrs: { "aria-label": "Imports" } });
    table.append(el("thead", { html: "<tr><th>Library</th><th>Symbol</th><th>Address</th></tr>" }));
    const tbody = el("tbody");
    for (const im of imports.slice(0, MAX_ROWS)) {
      const lib = str(im.library || im.lib || im.module || "");
      const name = str(im.name || im.symbol || im.function || (typeof im === "string" ? im : ""));
      const addr = str(im.address || im.addr || "");
      // Imports resolve through the PLT/GOT and carry pseudo-addresses like
      // ``EXTERNAL:00000001`` that are NOT navigable code addresses. They must never
      // become a function link (which would issue a decompile/xrefs/ annotation call
      // the backend rejects).
      tbody.append(
        el("tr", {
          children: [
            el("td", { text: lib || "—" }),
            el("td", { text: name || "—" }),
            entityCell(addr, null),
          ],
        })
      );
    }
    table.append(tbody);
    listEl.replaceChildren(table);
  }

  function renderStrings(data) {
    const strings = pickList(data, "strings", "results", "items");
    if (!strings) {
      listEl.replaceChildren(placeholder("No string data", "No strings were returned for this job."));
      return;
    }
    const table = el("table", { class: "data-table", attrs: { "aria-label": "Strings" } });
    table.append(el("thead", { html: "<tr><th>Address</th><th>Value</th></tr>" }));
    const tbody = el("tbody");
    for (const s of strings.slice(0, MAX_ROWS)) {
      const value = typeof s === "string" ? s : str(s.value || s.string || s.text || s.s || "");
      const addr = typeof s === "string" ? "" : str(s.address || s.addr || "");
      // A string's address is a DATA location, not a function entry. Selecting a
      // string must never decompile/xref/annotate a function. Until a dedicated
      // string inspector exists, the address is shown plainly (non-navigable).
      tbody.append(el("tr", { children: [entityCell(addr, null), el("td", { text: value })] }));
    }
    table.append(tbody);
    listEl.replaceChildren(table);
  }

  function renderTypes(data) {
    const types = pickList(data, "types", "structures", "results", "items");
    if (!types || !types.length) {
      listEl.replaceChildren(placeholder("No types", "The service returned no type information."));
      return;
    }
    const table = el("table", { class: "data-table", attrs: { "aria-label": "Types" } });
    table.append(el("thead", { html: "<tr><th>Name</th><th>Kind</th><th>Size</th></tr>" }));
    const tbody = el("tbody");
    for (const t of types.slice(0, MAX_ROWS)) {
      tbody.append(
        el("tr", {
          children: [
            el("td", { text: str(t.name || t.type || "") || "—" }),
            el("td", { text: str(t.kind || t.category || "") || "—" }),
            el("td", { text: t.size !== undefined ? str(t.size) : "—" }),
          ],
        })
      );
    }
    table.append(tbody);
    listEl.replaceChildren(table);
  }

  function renderGlobals(data) {
    const globs = pickList(data, "globals", "data", "results", "items");
    if (!globs || !globs.length) {
      listEl.replaceChildren(placeholder("No globals", "The service returned no global data symbols."));
      return;
    }
    const table = el("table", { class: "data-table", attrs: { "aria-label": "Globals" } });
    table.append(el("thead", { html: "<tr><th>Address</th><th>Name</th><th>Type</th></tr>" }));
    const tbody = el("tbody");
    for (const gvar of globs.slice(0, MAX_ROWS)) {
      tbody.append(
        el("tr", {
          children: [
            addrCell(str(gvar.address || gvar.addr || "")),
            el("td", { text: str(gvar.name || gvar.symbol || "") || "—" }),
            el("td", { text: str(gvar.type || gvar.datatype || "") || "—" }),
          ],
        })
      );
    }
    table.append(tbody);
    listEl.replaceChildren(table);
  }

  function renderQueryForm() {
    const input = el("input", {
      class: "field",
      attrs: { type: "search", placeholder: "Search functions & strings…", "aria-label": "Query" },
    });
    const regex = el("input", { attrs: { type: "checkbox", id: "q-regex" } });
    const regexLabel = el("label", {
      attrs: { for: "q-regex" },
      children: [regex, document.createTextNode(" regex")],
    });
    const btn = el("button", { class: "btn btn--sm", text: "Run", attrs: { type: "submit" } });
    const results = el("div");
    const form = el("form", { class: "analysis__toolbar", children: [input, regexLabel, btn] });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q) return;
      results.replaceChildren(loadingState());
      const token = ++loadToken;
      try {
        const data = await api.query(jobId(), q, regex.checked);
        if (token !== loadToken) return;
        const hits = pickList(data, "results", "matches", "functions", "strings") || [];
        if (!hits.length) {
          results.replaceChildren(placeholder("No matches", `Nothing matched "${q}".`));
          return;
        }
        const table = el("table", { class: "data-table" });
        table.append(el("thead", { html: "<tr><th>Address</th><th>Match</th></tr>" }));
        const tbody = el("tbody");
        for (const h of hits.slice(0, MAX_ROWS)) {
          const addr = typeof h === "string" ? "" : str(h.address || h.addr || "");
          const text = typeof h === "string" ? h : str(h.name || h.value || h.text || JSON.stringify(h));
          tbody.append(el("tr", { children: [addrCell(addr), el("td", { text })] }));
        }
        table.append(tbody);
        results.replaceChildren(table);
      } catch (err) {
        if (token !== loadToken) return;
        results.replaceChildren(errorState(err));
      }
    });
    listEl.replaceChildren(form, results);
  }

  async function inspectFunction(addr) {
    // Defense in depth: never issue function API calls for a non-navigable address.
    // Callers already gate via addrCell/isNavigableCodeAddress, but a programmatic call
    // with a pseudo/namespace token (EXTERNAL:*, a symbol, empty) must not reach.
    if (!isNavigableCodeAddress(addr)) {
      openInspector();
      detailEl.replaceChildren(
        placeholder(
          "Not a code address",
          "This entity is not a navigable function address, so it has no " +
            "decompilation, cross-references, or annotations.",
          "▤"
        )
      );
      return;
    }
    selectedAddr = addr;
    openInspector();
    detailEl.replaceChildren(loadingState());
    const token = ++loadToken;
    try {
      const [decompile, xrefs, callgraph] = await Promise.allSettled([
        api.decompile(jobId(), addr),
        api.xrefs(jobId(), addr),
        api.callgraph(jobId(), addr, 2),
      ]);
      if (token !== loadToken) return;

      const head = el("div", {
        class: "detail__head",
        children: [
          el("h3", { class: "detail__title", text: `Function ${addr}` }),
          el("span", { class: "tag tag--fact", text: "deterministic" }),
          sendEvidenceButton(addr),
          el("span", { class: "detail__spacer" }),
          closeInspectorButton(),
        ],
      });

      const parts = [head];

      parts.push(annotationsPanel(addr));

      // Decompilation
      if (decompile.status === "fulfilled") {
        const code = extractDecompile(decompile.value);
        if (code) {
          parts.push(el("p", { class: "label", text: "Pseudocode" }));
          parts.push(el("pre", { class: "code-well", text: code }));
        } else {
          parts.push(placeholder("Decompilation unavailable", "No pseudocode returned for this address."));
        }
      } else {
        parts.push(errorState(decompile.reason));
      }

      // Xrefs
      if (xrefs.status === "fulfilled") {
        const { callers, callees } = extractXrefs(xrefs.value);
        parts.push(el("p", { class: "label", text: "Cross-references" }));
        parts.push(xrefColumns(callers, callees));
      }

      // Bounded local call graph (accessible table fallback -- no canvas).
      if (callgraph.status === "fulfilled") {
        parts.push(callgraphTable(callgraph.value));
      }

      // Bounded hexdump (feature-gated; hex + ASCII, exported memory only).
      if (featureAvailable("hexdump")) {
        parts.push(hexdumpPanel(addr));
      }

      detailEl.replaceChildren(el("div", { class: "detail", children: parts }));
      refreshSelection();
    } catch (err) {
      if (token !== loadToken) return;
      detailEl.replaceChildren(errorState(err));
    }
  }

  function annotationsPanel(addr) {
    const wrap = el("div", { class: "annotations" });
    wrap.append(el("p", { class: "label", text: "Analyst annotation (overlay)" }));
    if (!featureAvailable("annotations")) {
      // Read-only disabled with an explanation; never a fake local store.
      wrap.append(
        el("p", {
          class: "placeholder__body",
          text:
            "Annotations require the v1 analysis service. Editing is disabled; " +
            "the original evidence is always preserved and no local annotation is stored.",
        })
      );
      return wrap;
    }
    const nameInput = el("input", {
      class: "field",
      attrs: { type: "text", placeholder: "Display name (overlay)", "aria-label": "Display name" },
    });
    const commentInput = el("textarea", {
      class: "field",
      attrs: { rows: "2", placeholder: "Comment", "aria-label": "Comment" },
    });
    const origName = el("p", { class: "annotations__orig", text: "" });
    const saveBtn = el("button", { class: "btn btn--sm", text: "Save annotation", attrs: { type: "button" } });
    const statusLine = el("p", { class: "annotations__status", attrs: { role: "status" } });
    // The ETag/revision is the concurrency token: captured on read, forwarded
    // as If-Match on write, and refreshed from the write response.
    let etag = null;

    // Load current annotation (shows original_name always). The server wraps the
    // overlay under `annotations` and surfaces the ETag alongside it.
    api
      .annotations(jobId(), addr)
      .then((data) => {
        etag = (data && data.etag) || null;
        const ann = extractAnnotation(data, addr);
        if (ann.original_name) origName.textContent = `original: ${ann.original_name}`;
        if (ann.display_name) nameInput.value = str(ann.display_name);
        if (ann.comment) commentInput.value = str(ann.comment);
        if (!etag && (ann.revision || ann.etag)) {
          etag = ann.etag || `"${ann.revision}"`;
        }
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 404) {
          return;
        }
        if (err instanceof ApiError && err.code === "capability_required") {
          return;
        }
        statusLine.textContent =
          err instanceof ApiError
            ? `Could not load the existing annotation: ${err.message}`
            : "Could not load the existing annotation.";
      });

    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      statusLine.textContent = "Saving…";
      try {
        const body = { display_name: nameInput.value, comment: commentInput.value };
        const out = await api.saveAnnotation(jobId(), addr, body, etag);
        etag = (out && out.etag) || etag;
        statusLine.textContent = "Saved (overlay only; original evidence unchanged).";
      } catch (err) {
        if (err instanceof ApiError && err.status === 409) {
          statusLine.textContent =
            "This annotation changed elsewhere. Your text is preserved — reopen the function to reload the latest, then reapply.";
        } else {
          statusLine.textContent =
            err instanceof ApiError ? `Save failed: ${err.message}` : "Save failed.";
        }
      } finally {
        saveBtn.disabled = false;
      }
    });

    wrap.append(origName, nameInput, commentInput, saveBtn, statusLine);
    return wrap;
  }

  function callgraphTable(data) {
    const nodes = Array.isArray(data && data.nodes) ? data.nodes : [];
    const edges = Array.isArray(data && data.edges) ? data.edges : [];
    const wrap = el("div", { class: "callgraph" });
    wrap.append(
      el("p", {
        class: "label",
        text: `Local call graph (${nodes.length} nodes, ${edges.length} edges${
          data && data.truncated ? ", truncated" : ""
        })`,
      })
    );
    if (!edges.length) {
      wrap.append(el("p", { class: "placeholder__body", text: "No call edges in the bounded neighborhood." }));
      return wrap;
    }
    const table = el("table", { class: "data-table", attrs: { "aria-label": "Call graph edges" } });
    table.append(el("thead", { html: "<tr><th>Caller</th><th>→</th><th>Callee</th></tr>" }));
    const tbody = el("tbody");
    for (const e of edges.slice(0, MAX_ROWS)) {
      tbody.append(
        el("tr", {
          children: [addrCell(str(e.from)), el("td", { text: "→" }), addrCell(str(e.to))],
        })
      );
    }
    table.append(tbody);
    wrap.append(table);
    return wrap;
  }

  // ---- Hexdump (v1, bounded) -------------------------------------------
  function hexdumpPanel(addr) {
    const wrap = el("div", { class: "hexdump" });
    wrap.append(el("p", { class: "label", text: "Hexdump (exported memory, bounded)" }));
    const lenInput = el("input", {
      class: "field field--budget",
      attrs: { type: "number", min: "1", max: "256", value: "64", "aria-label": "Hexdump length in bytes" },
    });
    const loadBtn = el("button", { class: "btn btn--sm", text: "Read", attrs: { type: "button" } });
    const out = el("pre", { class: "code-well hexdump__out" });
    const statusLine = el("p", { class: "annotations__status", attrs: { role: "status" } });

    const run = async () => {
      loadBtn.disabled = true;
      out.textContent = "";
      statusLine.textContent = "Reading…";
      let length = parseInt(lenInput.value, 10);
      if (!Number.isFinite(length) || length < 1) length = 16;
      length = Math.min(length, 256);
      try {
        const data = await api.hexdump(jobId(), addr, length);
        out.textContent = formatHexdump(data);
        statusLine.textContent = data && data.truncated ? "Truncated: fewer bytes available." : "";
      } catch (err) {
        out.textContent = "";
        if (err instanceof ApiError && err.status === 404) {
          statusLine.textContent = "This address was not exported for the program.";
        } else if (err instanceof ApiError && err.status === 422) {
          statusLine.textContent = "Requested range is invalid or too large.";
        } else {
          statusLine.textContent =
            err instanceof ApiError ? `Hexdump failed: ${err.message}` : "Hexdump failed.";
        }
      } finally {
        loadBtn.disabled = false;
      }
    };
    loadBtn.addEventListener("click", run);

    const toolbar = el("div", { class: "analysis__toolbar", children: [lenInput, loadBtn] });
    wrap.append(toolbar, statusLine, out);
    return wrap;
  }

  function refreshSelection() {
    const rows = listEl.querySelectorAll("tbody tr");
    rows.forEach((tr) => {
      const a = tr.querySelector(".addr");
      tr.setAttribute("aria-current", a && a.textContent === selectedAddr ? "true" : "false");
    });
  }

  function sendEvidenceButton(addr) {
    const btn = el("button", {
      class: "btn btn--sm",
      text: "Send to chat",
      attrs: { type: "button", title: "Reference this function in the chat by address" },
    });
    btn.addEventListener("click", () => {
      if (onSendEvidence) onSendEvidence({ kind: "function", addr });
    });
    return btn;
  }

  function xrefColumns(callers, callees) {
    const col = (title, list) => {
      const items = el("ul");
      if (!list.length) items.append(el("li", { text: "—" }));
      for (const x of list.slice(0, 100)) {
        const li = el("li");
        if (isNavigableCodeAddress(x)) {
          const a = el("span", {
            class: "addr addr--link",
            text: x,
            attrs: { role: "button", tabindex: "0", title: "Open inspector" },
          });
          a.addEventListener("click", () => inspectFunction(x));
          a.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              inspectFunction(x);
            }
          });
          li.append(a);
        } else {
          li.append(el("span", { class: "addr addr--plain", text: str(x) }));
        }
        items.append(li);
      }
      return el("div", { children: [el("p", { class: "label", text: title }), items] });
    };
    return el("div", {
      class: "kv",
      children: [col(`Callers (${callers.length})`, callers), col(`Callees (${callees.length})`, callees)],
    });
  }

  function extractDecompile(data) {
    if (!data) return "";
    if (typeof data === "string") return data;
    return str(data.decompilation || data.pseudocode || data.code || data.result || data.c || "");
  }

  function extractXrefs(data) {
    const callers = [];
    const callees = [];
    if (data && typeof data === "object") {
      const cIn = data.callers || data.xrefs_to || data.to || [];
      const cOut = data.callees || data.xrefs_from || data.from || [];
      for (const x of asArray(cIn)) callers.push(str(x.address || x.addr || x));
      for (const x of asArray(cOut)) callees.push(str(x.address || x.addr || x));
    }
    return { callers: callers.filter(Boolean), callees: callees.filter(Boolean) };
  }

  // ---- Attack Surface (security index) --------------------------------- A
  // capability-gated subtab. It loads the deterministic security summary and ONE
  // server-paginated page of ranked functions (never all rows).
  function disclaimerBanner() {
    return el("p", {
      class: "as-disclaimer",
      attrs: { role: "note" },
      text: TRIAGE_DISCLAIMER,
    });
  }

  async function renderAttackSurface() {
    const id = jobId();
    listEl.replaceChildren(loadingState());
    const token = ++loadToken;
    let summary;
    try {
      summary = await api.securitySummary(id);
    } catch (err) {
      if (token !== loadToken) return;
      listEl.replaceChildren(errorState(err));
      return;
    }
    if (token !== loadToken) return;

    if (isUnavailable(summary)) {
      listEl.replaceChildren(securityUnavailable(summary));
      return;
    }

    const container = el("div", { class: "attack-surface" });
    container.append(disclaimerBanner());
    container.append(securitySummaryPanel(summary));
    const tableHost = el("div", { class: "as-table-host" });
    container.append(securityFilters(tableHost), tableHost);
    listEl.replaceChildren(container);
    await loadSecurityPage(tableHost);
  }

  function securityUnavailable(summary) {
    const info = unavailableInfo(summary);
    const wrap = el("div", { class: "placeholder as-unavailable" });
    wrap.append(
      el("div", { class: "placeholder__glyph", text: info.building ? "⏳" : "▤" }),
      el("p", { class: "placeholder__title", text: "Attack surface index unavailable" }),
      el("p", { class: "placeholder__body", text: info.message }),
      disclaimerBanner()
    );
    if (info.rescoreAvailable && !info.building) {
      const btn = el("button", {
        class: "btn btn--sm",
        text: "Rescore now",
        attrs: { type: "button" },
      });
      const status = el("p", { class: "annotations__status", attrs: { role: "status" } });
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        status.textContent = "Requesting rescore…";
        try {
          await api.rescoreSecurity(jobId());
          status.textContent =
            "Rescore queued. It runs in the background — reopen this view shortly to see results.";
        } catch (err) {
          status.textContent =
            err instanceof ApiError ? `Rescore failed: ${err.message}` : "Rescore failed.";
          btn.disabled = false;
        }
      });
      wrap.append(btn, status);
    } else if (info.building) {
      wrap.append(
        el("p", {
          class: "annotations__status",
          text: "A rescore is already running; reopen this view shortly.",
        })
      );
    }
    return wrap;
  }

  function securitySummaryPanel(summary) {
    const v = summaryView(summary);
    const parts = [];
    parts.push(
      el("div", {
        class: "provenance",
        children: [
          el("span", { class: "tag tag--fact", text: "deterministic" }),
          el("span", {
            class: "provenance__src",
            text:
              `scorer ${v.versions.scorer || "?"} · weights ${v.versions.weights || "?"} · ` +
              `schema ${v.versions.schema || "?"} · artifact ${v.versions.artifact || "?"}` +
              (v.versions.downgraded ? " · downgraded rescore" : ""),
          }),
        ],
      })
    );

    const bandRow = el("div", { class: "as-bands" });
    for (const b of v.bands) {
      bandRow.append(
        el("span", {
          class: `as-band as-band--${b.band}`,
          attrs: { "data-band": b.band },
          children: [
            el("span", { class: "as-band__label", text: b.label }),
            el("span", { class: "as-band__count", text: String(b.count) }),
          ],
        })
      );
    }
    parts.push(el("p", { class: "label", text: "Triage bands" }), bandRow);

    if (v.categories.length) {
      const catRow = el("div", { class: "as-categories" });
      for (const c of v.categories) {
        catRow.append(
          el("span", {
            class: "as-cat",
            text: `${secCategoryLabel(c.category)} (${c.count})`,
          })
        );
      }
      parts.push(el("p", { class: "label", text: "Evidence categories" }), catRow);
    }

    // Coverage + meta as a small kv table.
    const kvRows = [...v.coverage, ...v.meta];
    if (kvRows.length) {
      const table = el("table", {
        class: "data-table kv-table",
        attrs: { "aria-label": "Coverage and metadata" },
      });
      const tbody = el("tbody");
      for (const r of kvRows) {
        tbody.append(
          el("tr", {
            children: [
              el("th", { attrs: { scope: "row" }, text: r.label }),
              el("td", { text: r.value }),
            ],
          })
        );
      }
      table.append(tbody);
      parts.push(el("p", { class: "label", text: "Coverage" }), table);
    }

    // Per-component coverage (scorer v2), as its own small kv table so a low
    // structural / decompile / Android-metadata ratio is visible.
    if (v.components && v.components.length) {
      const compTable = el("table", {
        class: "data-table kv-table",
        attrs: { "aria-label": "Component coverage" },
      });
      const compBody = el("tbody");
      for (const r of v.components) {
        compBody.append(
          el("tr", {
            children: [
              el("th", { attrs: { scope: "row" }, text: r.label }),
              el("td", { text: r.value }),
            ],
          })
        );
      }
      compTable.append(compBody);
      parts.push(el("p", { class: "label", text: "Component coverage" }), compTable);
    }

    return el("div", { class: "as-summary", children: parts });
  }

  function parseSecuritySearch(raw) {
    const text = str(raw).trim();
    if (!text) return { query: "", rank: "" };
    const hashRank = text.match(/^#\s*(\d{1,9})$/);
    if (hashRank) return { query: "", rank: hashRank[1] };
    if (/^\d{1,9}$/.test(text)) return { query: "", rank: text };
    return { query: text, rank: "" };
  }

  function securityFilters(tableHost) {
    const searchInput = el("input", {
      class: "field as-search",
      attrs: {
        type: "search",
        placeholder: "Function name, address, or #rank…",
        "aria-label": "Search ranked functions by name, address, or rank",
        value: sec.rank ? `#${sec.rank}` : sec.query,
      },
    });

    const bandSel = el("select", { class: "field", attrs: { "aria-label": "Filter by band" } });
    bandSel.append(el("option", { text: "All bands", attrs: { value: "" } }));
    for (const b of SEC_BANDS) {
      bandSel.append(el("option", { text: bandLabel(b), attrs: { value: b } }));
    }
    bandSel.value = sec.band;

    const catSel = el("select", { class: "field", attrs: { "aria-label": "Filter by category" } });
    catSel.append(el("option", { text: "All categories", attrs: { value: "" } }));
    for (const slug of Object.keys(SEC_CATEGORY_LABELS)) {
      catSel.append(el("option", { text: secCategoryLabel(slug), attrs: { value: slug } }));
    }
    catSel.value = sec.category;

    const minScore = el("input", {
      class: "field field--budget",
      attrs: {
        type: "number",
        min: "0",
        max: "100",
        step: "1",
        placeholder: "min score",
        "aria-label": "Minimum score",
        value: sec.minScore,
      },
    });

    const sortSel = el("select", { class: "field", attrs: { "aria-label": "Sort by" } });
    for (const [val, label] of [["score", "Score"], ["rank", "Rank"], ["name", "Name"]]) {
      sortSel.append(el("option", { text: label, attrs: { value: val } }));
    }
    sortSel.value = sec.sort;

    const orderSel = el("select", { class: "field", attrs: { "aria-label": "Sort order" } });
    for (const [val, label] of [["desc", "Desc"], ["asc", "Asc"]]) {
      orderSel.append(el("option", { text: label, attrs: { value: val } }));
    }
    orderSel.value = sec.order;

    const apply = () => {
      const parsed = parseSecuritySearch(searchInput.value);
      sec.query = parsed.query;
      sec.rank = parsed.rank;
      sec.band = bandSel.value;
      sec.category = catSel.value;
      sec.minScore = minScore.value.trim();
      sec.sort = sortSel.value;
      sec.order = orderSel.value;
      sec.offset = 0; // filter/search/sort change resets to the first page
      loadSecurityPage(tableHost);
    };
    for (const ctl of [bandSel, catSel, sortSel, orderSel]) {
      ctl.addEventListener("change", apply);
    }
    let deb = null;
    minScore.addEventListener("input", () => {
      clearTimeout(deb);
      deb = setTimeout(apply, 200);
    });
    let searchDeb = null;
    searchInput.addEventListener("input", () => {
      clearTimeout(searchDeb);
      searchDeb = setTimeout(apply, 200);
    });
    // Keep a handle so loadSecurityPage can restore focus after repaint.
    securitySearchInput = searchInput;

    return el("div", {
      class: "analysis__toolbar as-filters",
      children: [searchInput, bandSel, catSel, minScore, sortSel, orderSel],
    });
  }

  let securitySearchInput = null;

  async function loadSecurityPage(tableHost) {
    tableHost.replaceChildren(loadingState());
    // Use the dedicated search token so a slow earlier page cannot overwrite a
    // newer keystroke's result (in addition to the shared loadToken).
    const token = ++loadToken;
    const searchToken = ++secSearchToken;
    let data;
    try {
      data = await api.securityFunctions(jobId(), {
        offset: sec.offset,
        limit: sec.limit,
        band: sec.band || undefined,
        category: sec.category || undefined,
        minScore: sec.minScore || undefined,
        query: sec.query || undefined,
        rank: sec.rank || undefined,
        sort: sec.sort,
        order: sec.order,
      });
    } catch (err) {
      if (searchToken !== secSearchToken) return; // superseded by a newer search
      if (token !== loadToken) return;
      if (err instanceof ApiError && err.status === 409) {
        tableHost.replaceChildren(
          securityUnavailable({ available: false, status: "missing", rescore_available: true })
        );
        return;
      }
      tableHost.replaceChildren(errorState(err));
      return;
    }
    if (searchToken !== secSearchToken) return; // out-of-order: newer search won
    if (token !== loadToken) return;
    tableHost.replaceChildren(securityTable(data, tableHost));
    if (securitySearchInput && typeof securitySearchInput.focus === "function") {
      const active = document.activeElement;
      if (!active || active === document.body || active === listEl) {
        securitySearchInput.focus();
      }
    }
  }

  function securityTable(data, tableHost) {
    const rows = functionRows(data);
    const wrap = el("div", { class: "as-ranked" });
    wrap.append(el("p", { class: "label", text: secPageLabel(data) }));
    if (!rows.length) {
      wrap.append(
        el("p", { class: "placeholder__body", text: "No ranked functions match the current filters." })
      );
      return wrap;
    }
    const table = el("table", {
      class: "data-table",
      attrs: { "aria-label": "Ranked functions by triage priority" },
    });
    table.append(
      el("thead", {
        html:
          "<tr><th>#</th><th>Score</th><th>Band</th><th>Conf.</th>" +
          "<th>Categories</th><th>Name</th><th>Address</th></tr>",
      })
    );
    const tbody = el("tbody");
    for (const r of rows) {
      const catText = r.categories.map(secCategoryLabel).join(", ");
      // In the Attack Surface table BOTH the name and the address open the ranked-
      // signals score detail (not the function inspector); the detail pane offers a
      // separate "Inspect function evidence" action for decompile/xrefs.
      const openDetail = () => inspectSecurityFunction(r.addr);
      const scoreNameCell = el("td");
      const nameBtn = el("span", {
        class: "addr addr--link",
        text: r.name || "(unnamed)",
        attrs: { role: "button", tabindex: "0", title: "Open ranked signals" },
      });
      nameBtn.addEventListener("click", openDetail);
      nameBtn.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openDetail();
        }
      });
      scoreNameCell.append(nameBtn);
      tbody.append(
        el("tr", {
          attrs: { "aria-current": r.addr === selectedAddr ? "true" : "false" },
          children: [
            el("td", { text: r.rank != null ? String(r.rank) : "—" }),
            el("td", { text: formatScore(r.score) }),
            el("td", {
              children: [
                el("span", {
                  class: `as-band-pill as-band--${r.band}`,
                  text: bandLabel(r.band),
                }),
              ],
            }),
            el("td", { text: formatConfidence(r.confidence) }),
            el("td", { text: catText || "—" }),
            scoreNameCell,
            entityCell(r.addr, isNavigableCodeAddress(r.addr) ? openDetail : null),
          ],
        })
      );
    }
    table.append(tbody);
    wrap.append(table, securityPager(data, tableHost));
    return wrap;
  }

  function securityPager(data, tableHost) {
    const prev = el("button", {
      class: "btn btn--sm btn--ghost",
      text: "‹ Prev",
      attrs: { type: "button" },
    });
    const next = el("button", {
      class: "btn btn--sm btn--ghost",
      text: "Next ›",
      attrs: { type: "button" },
    });
    prev.disabled = !secHasPrev(data);
    next.disabled = !secHasNext(data);
    prev.addEventListener("click", () => {
      sec.offset = Math.max(0, sec.offset - sec.limit);
      loadSecurityPage(tableHost);
    });
    next.addEventListener("click", () => {
      sec.offset += sec.limit;
      loadSecurityPage(tableHost);
    });
    return el("div", { class: "pager", children: [prev, next] });
  }

  async function inspectSecurityFunction(addr) {
    selectedAddr = addr;
    openInspector();
    detailEl.replaceChildren(loadingState());
    const token = ++loadToken;
    let detail;
    try {
      detail = await api.securityFunction(jobId(), addr);
    } catch (err) {
      if (token !== loadToken) return;
      detailEl.replaceChildren(errorState(err));
      return;
    }
    if (token !== loadToken) return;
    detailEl.replaceChildren(securityDetail(detailView(detail)));
    refreshSelection();
  }

  function securityDetail(d) {
    const parts = [];
    parts.push(
      el("div", {
        class: "detail__head",
        children: [
          el("h3", { class: "detail__title", text: `${d.name || "(unnamed)"} ${d.addr}` }),
          el("span", { class: "tag tag--fact", text: "deterministic" }),
          el("span", { class: "detail__spacer" }),
          closeInspectorButton(),
        ],
      })
    );

    const kv = el("table", { class: "data-table kv-table", attrs: { "aria-label": "Ranking" } });
    const kvBody = el("tbody");
    const kvRow = (label, value) =>
      kvBody.append(
        el("tr", {
          children: [
            el("th", { attrs: { scope: "row" }, text: label }),
            el("td", { text: value }),
          ],
        })
      );
    kvRow("Triage score", formatScore(d.score));
    kvRow("Band", bandLabel(d.band));
    kvRow("Confidence", formatConfidence(d.confidence));
    if (d.rank != null) kvRow("Rank", String(d.rank));
    if (d.categories.length) kvRow("Categories", d.categories.map(secCategoryLabel).join(", "));
    kv.append(kvBody);
    parts.push(kv);

    parts.push(disclaimerBanner());

    const openBtn = el("button", {
      class: "btn btn--sm",
      text: "Inspect function evidence",
      attrs: { type: "button", title: "Open decompilation, xrefs, and call graph for this address" },
    });
    openBtn.addEventListener("click", () => inspectFunction(d.addr));
    const sendBtn = sendEvidenceButton(d.addr);
    parts.push(el("div", { class: "analysis__toolbar", children: [openBtn, sendBtn] }));

    if (d.zeroSignal) {
      parts.push(
        el("p", {
          class: "as-zero-signal",
          attrs: { role: "note" },
          text: d.zeroSignalCaveat || ZERO_SIGNAL_CAVEAT,
        })
      );
    }

    // Positive (aggravating) evidence and mitigating factors are presented
    // SEPARATELY so a protective signal is never mistaken for a risk signal.
    const positive = d.positiveSignals || d.signals.filter((s) => s.category !== "mitigation");
    const mitigating = d.mitigatingSignals || [];
    parts.push(el("p", { class: "label", text: `Positive evidence (${positive.length})` }));
    if (!positive.length) {
      parts.push(
        el("p", { class: "placeholder__body", text: "No positive scoring signals were recorded." })
      );
    } else {
      for (const sig of positive) {
        parts.push(securitySignal(sig));
      }
    }
    if (mitigating.length) {
      parts.push(el("p", { class: "label", text: `Mitigating factors (${mitigating.length})` }));
      for (const sig of mitigating) {
        parts.push(securitySignal(sig));
      }
    }

    return el("div", { class: "detail as-detail", children: parts });
  }

  function securitySignal(sig) {
    const head = el("div", {
      class: "as-signal__head",
      children: [
        el("span", { class: "as-signal__id", text: sig.signalId || "signal" }),
        el("span", { class: "as-cat", text: secCategoryLabel(sig.category) }),
        el("span", {
          class: "as-signal__weight",
          attrs: { title: "Signed weight contribution" },
          text: sig.weightLabel,
        }),
        el("span", { class: "as-signal__conf", text: `conf: ${sig.confidence || "—"}` }),
      ],
    });
    const wrap = el("div", { class: "as-signal", children: [head] });
    if (sig.evidence.length) {
      const ul = el("ul", { class: "as-evidence" });
      for (const ev of sig.evidence.slice(0, 50)) {
        const label = ev.detail ? `${ev.kind}: ${ev.ref} — ${ev.detail}` : `${ev.kind}: ${ev.ref}`;
        ul.append(el("li", { text: label }));
      }
      wrap.append(ul);
    }
    return wrap;
  }

  async function refresh() {
    const id = jobId();
    if (!id) {
      listEl.replaceChildren(
        placeholder("No job selected", "Select an analysis job to inspect its artifacts.", "▦")
      );
      closeInspector({ focusList: false });
      return;
    }
    const gated = V1_VIEWS.find((v) => v.id === view);
    if (gated && !featureAvailable(gated.feature)) {
      listEl.replaceChildren(capabilityGate(gated.label));
      return;
    }
    if (view === "query") {
      renderQueryForm();
      return;
    }
    if (view === "attack_surface") {
      await renderAttackSurface();
      return;
    }
    if (view === "functions") {
      renderFunctionsShell();
      return;
    }
    listEl.replaceChildren(loadingState());
    const token = ++loadToken;
    try {
      let data;
      if (view === "summary") data = await api.summary(id);
      else if (view === "imports") data = await api.imports(id);
      else if (view === "strings") data = await api.strings(id, {});
      else if (view === "types") data = await api.types(id);
      else if (view === "globals") data = await api.globals(id);
      if (token !== loadToken) return;
      if (view === "summary") renderSummary(data);
      else if (view === "imports") renderImports(data);
      else if (view === "strings") renderStrings(data);
      else if (view === "types") renderTypes(data);
      else if (view === "globals") renderGlobals(data);
    } catch (err) {
      if (token !== loadToken) return;
      listEl.replaceChildren(errorState(err));
    }
  }

  // Escape closes the inspector while the analyst is anywhere inside the Analysis panel
  // (the browse list, the detail pane, a subtab, a filter).
  const panelEl = document.getElementById("panel-analysis");
  if (panelEl) {
    panelEl.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!rootEl || rootEl.dataset.detail !== "open") return;
      e.preventDefault();
      closeInspector();
    });
  }

  async function activate() {
    await ensureCapabilities();
    renderSubtabs();
    refresh();
  }

  function reset() {
    view = "summary";
    offset = 0;
    functionFilter = "";
    resetSecurity();
    closeInspector({ focusList: false });
  }

  return { activate, refresh, reset, inspectFunction, closeInspector };
}

function str(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}
function asArray(v) {
  return Array.isArray(v) ? v : v ? [v] : [];
}

// Mirror the backend address policy (webui/validation.py:_ADDRESS_RE and the service's
// security.ADDRESS_RE): a navigable code address is 1..16 hex digits, optionally
// 0x-prefixed.
const _NAV_ADDRESS_RE = /^(?:0[xX])?[0-9a-fA-F]{1,16}$/;
export function isNavigableCodeAddress(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  return _NAV_ADDRESS_RE.test(trimmed);
}

// Extract the annotation record for `addr` from the wrapped server response, tolerating
// every observed shape: {etag, annotations:{annotation:{...}}}, {etag,
// annotations:{annotations:[{entity_id,...}]}}, a bare list, or a bare object.
export function extractAnnotation(data, addr) {
  const wrapper = (data && data.annotations) || data || {};
  const list = Array.isArray(wrapper)
    ? wrapper
    : Array.isArray(wrapper.annotations)
    ? wrapper.annotations
    : null;
  if (list) {
    const hit = list.find(
      (a) => a && (a.entity_id === addr || a.addr === addr || a.address === addr)
    );
    return hit || list[0] || {};
  }
  return (wrapper && (wrapper.annotation || wrapper)) || {};
}

export function formatHexdump(data) {
  const hex = data && typeof data.hex === "string" ? data.hex.replace(/[^0-9a-fA-F]/g, "") : "";
  if (!hex) return "(no bytes)";
  const bytes = [];
  for (let i = 0; i + 1 < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  let base = 0;
  if (data && typeof data.start === "string") {
    const m = data.start.match(/0x([0-9a-fA-F]+)/);
    if (m) base = parseInt(m[1], 16) || 0;
  }
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const row = bytes.slice(off, off + 16);
    const hexPart = row.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(16 * 3 - 1, " ");
    const asciiPart = row
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    const offStr = (base + off).toString(16).padStart(8, "0");
    lines.push(`${offStr}  ${hexPart}  |${asciiPart}|`);
  }
  return lines.join("\n");
}
