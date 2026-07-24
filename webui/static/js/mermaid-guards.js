// Biniam Demissie
// Pure guard predicates shared by the sandbox-frame Mermaid runtime.

(function (root, factory) {
  "use strict";
  const api = factory();
  // Browser (sandbox frame): expose on window for the classic runtime script.
  if (typeof window !== "undefined") {
    window.__revdeckMermaidGuards = api;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Bounds. Source cap is the hard 8000-char limit from the plan; the rest are
  // cheap structural ceilings computed from the raw text before Mermaid runs.
  const LIMITS = {
    MAX_SOURCE_CHARS: 8000,
    MAX_LINES: 400,
    MAX_NODES: 300,
    MAX_EDGES: 500,
    MAX_LINE_CHARS: 2000,
    MAX_TEXT_CHARS: 12000,
    MAX_DIM: 4000,
    MIN_DIM: 1,
  };

  // Fixed, safe error codes. Raw Mermaid exception text (which can echo the
  // untrusted source) is NEVER forwarded to the parent — only these codes.
  const ERR = {
    PROTOCOL: "protocol_error",
    EMPTY: "empty_source",
    TOO_LARGE: "source_too_large",
    PREFLIGHT: "preflight_rejected",
    PARSE: "parse_error",
    RENDER: "render_error",
    SANITIZE: "sanitize_error",
    INTERNAL: "internal_error",
  };

  const SVG_NS = "http://www.w3.org/2000/svg";
  const XLINK_NS = "http://www.w3.org/1999/xlink";
  const XML_NS = "http://www.w3.org/XML/1998/namespace";

  // Elements permitted in sanitized output. Anything else (script,
  // foreignObject, iframe, HTML/unknown/foreign-namespace elements) is removed.
  const ALLOWED_TAGS = new Set([
    "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline",
    "polygon", "text", "tspan", "textpath", "marker", "defs", "title", "desc",
    "use", "symbol", "clippath", "lineargradient", "radialgradient", "stop",
    "pattern", "mask", "filter", "fegaussianblur", "feoffset", "feblend",
    "femerge", "femergenode", "fecolormatrix", "fecomposite", "feflood",
    "style",
  ]);

  function isEventAttr(name) {
    return /^on/i.test(String(name || ""));
  }

  function isSafeRef(value) {
    const v = String(value == null ? "" : value).trim();
    return v.startsWith("#") && !/[\s<>"']/.test(v);
  }

  // A style attribute/body may not smuggle expression(), @import, a behavior: property,
  // or a javascript: scheme. url() is allowed ONLY when every occurrence references an
  // in-document fragment (url(#id)) — Mermaid uses these for gradients/filters/markers.
  function styleIsSafe(value) {
    const v = String(value == null ? "" : value);
    if (/expression\s*\(|javascript:|@import|behaviou?r\s*:/i.test(v)) return false;
    // Every url(...) must resolve to a bare in-document fragment.
    const urlRe = /url\s*\(\s*(['"]?)([^)'"]*)\1\s*\)/gi;
    let m;
    while ((m = urlRe.exec(v)) !== null) {
      const target = m[2].trim();
      if (!target.startsWith("#")) return false;
    }
    // Reject a malformed/unterminated url( that the regex above would miss.
    if (/url\s*\(/i.test(v)) {
      const opens = (v.match(/url\s*\(/gi) || []).length;
      urlRe.lastIndex = 0;
      let matched = 0;
      while (urlRe.exec(v) !== null) matched++;
      if (matched !== opens) return false;
    }
    return true;
  }

  // Cheap preflight on the RAW source before Mermaid sees it. Returns null when
  // acceptable, else a fixed ERR code.
  function preflight(code) {
    const src = String(code == null ? "" : code);
    if (src.length > LIMITS.MAX_SOURCE_CHARS) return ERR.TOO_LARGE;
    const lines = src.split("\n");
    if (lines.length > LIMITS.MAX_LINES) return ERR.PREFLIGHT;
    let textBudget = 0;
    let edgeCount = 0;
    const idents = new Set();
    for (const line of lines) {
      if (line.length > LIMITS.MAX_LINE_CHARS) return ERR.PREFLIGHT;
      textBudget += line.length;
      const edges = line.match(/--+>|--+|==+>|==+|-\.-|:::|-->|===/g);
      if (edges) edgeCount += edges.length;
      const ids = line.match(/[A-Za-z_][A-Za-z0-9_]*/g);
      if (ids) for (const id of ids) idents.add(id);
    }
    if (textBudget > LIMITS.MAX_TEXT_CHARS) return ERR.PREFLIGHT;
    if (edgeCount > LIMITS.MAX_EDGES) return ERR.PREFLIGHT;
    if (idents.size > LIMITS.MAX_NODES) return ERR.PREFLIGHT;
    return null;
  }

  function clamp(v, lo, hi) {
    v = Number(v);
    if (!Number.isFinite(v)) return lo;
    return Math.max(lo, Math.min(hi, Math.round(v)));
  }

  // Request ids are opaque tokens minted by the parent; keep only a bounded
  // [A-Za-z0-9_-] string so a malformed id can't be reflected as markup.
  function safeId(id) {
    if (typeof id !== "string") return "";
    if (id.length < 1 || id.length > 64) return "";
    return /^[A-Za-z0-9_-]+$/.test(id) ? id : "";
  }

  function isAllowedElement(namespaceURI, localName) {
    const tag = String(localName || "").toLowerCase();
    if (namespaceURI !== SVG_NS) return false;
    if (!ALLOWED_TAGS.has(tag)) return false;
    if (tag === "script" || tag === "foreignobject") return false;
    return true;
  }

  function isAllowedAttr(namespaceURI, name, localName, value) {
    const nm = String(name || "");
    const local = String(localName || nm).toLowerCase();
    if (isEventAttr(nm)) return false;
    if (
      namespaceURI &&
      namespaceURI !== SVG_NS &&
      namespaceURI !== XLINK_NS &&
      namespaceURI !== XML_NS
    ) {
      return false;
    }
    if (local === "href") return isSafeRef(value);
    if (local === "style") return styleIsSafe(value);
    if (/^(?:javascript|data|vbscript):/i.test(String(value).trim())) return false;
    return true;
  }

  return {
    LIMITS,
    ERR,
    SVG_NS,
    XLINK_NS,
    XML_NS,
    ALLOWED_TAGS,
    isEventAttr,
    isSafeRef,
    styleIsSafe,
    preflight,
    clamp,
    safeId,
    isAllowedElement,
    isAllowedAttr,
  };
});
