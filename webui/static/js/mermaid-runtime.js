// Biniam Demissie
// Sandbox-frame Mermaid runtime (runs INSIDE the isolated iframe).
// Trust model This file executes in a document the parent embeds with sandbox="allow-
// scripts" ONLY.

(function () {
  "use strict";

  const G = window.__revdeckMermaidGuards;
  const PROTOCOL = "revdeck-mermaid/1";
  const ERR = G ? G.ERR : {
    PROTOCOL: "protocol_error", EMPTY: "empty_source", TOO_LARGE: "source_too_large",
    PREFLIGHT: "preflight_rejected", PARSE: "parse_error", RENDER: "render_error",
    SANITIZE: "sanitize_error", INTERNAL: "internal_error",
  };
  const MAX_DIM = G ? G.LIMITS.MAX_DIM : 4000;
  const MIN_DIM = G ? G.LIMITS.MIN_DIM : 1;
  const MAX_TEXT_CHARS = G ? G.LIMITS.MAX_TEXT_CHARS : 12000;
  const MAX_EDGES = G ? G.LIMITS.MAX_EDGES : 500;

  // -- SVG sanitizer (allowlist walk over the parsed DOM) -----------------
  function sanitizeSvgDocument(svgText) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(svgText, "image/svg+xml");
    const rootEl = doc.documentElement;
    if (!rootEl || rootEl.nodeName.toLowerCase() !== "svg") {
      throw new Error("not-svg");
    }
    walkAndClean(rootEl);
    return rootEl;
  }

  function walkAndClean(node) {
    const toRemove = [];
    for (let i = 0; i < node.childNodes.length; i++) {
      const child = node.childNodes[i];
      if (child.nodeType === 1 /* element */) {
        if (!G.isAllowedElement(child.namespaceURI, child.localName)) {
          toRemove.push(child);
          continue;
        }
        cleanAttributes(child);
        const tag = child.localName.toLowerCase();
        if (tag === "style" && !G.styleIsSafe(child.textContent)) {
          child.textContent = "";
        }
        walkAndClean(child);
      } else if (child.nodeType === 8 /* comment */ || child.nodeType === 7 /* PI */) {
        toRemove.push(child);
      }
    }
    for (const dead of toRemove) node.removeChild(dead);
  }

  function cleanAttributes(el) {
    const attrs = Array.from(el.attributes);
    for (const attr of attrs) {
      if (!G.isAllowedAttr(attr.namespaceURI, attr.name, attr.localName, attr.value)) {
        el.removeAttributeNode(attr);
      }
    }
  }

  // -- Mermaid configuration (hardened) -----------------------------------
  // securityLevel:"strict" HTML-encodes labels and disables click handlers;
  // htmlLabels:false keeps labels as <text> (no foreignObject); startOnLoad: false so
  // nothing runs until we explicitly.
  function configureMermaid(mermaid) {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      htmlLabels: false,
      flowchart: { htmlLabels: false, useMaxWidth: true },
      sequence: { useMaxWidth: true },
      class: { htmlLabels: false },
      er: { useMaxWidth: true },
      maxTextSize: MAX_TEXT_CHARS,
      maxEdges: MAX_EDGES,
      deterministicIds: true,
      theme: "base",
      themeVariables: {
        darkMode: true,
        background: "#12171d",
        primaryColor: "#1c242c",
        primaryBorderColor: "#f0a63a",
        primaryTextColor: "#e9d9be",
        lineColor: "#7c8794",
        secondaryColor: "#232c34",
        tertiaryColor: "#1a2127",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: "14px",
      },
    });
  }

  let renderSeq = 0;

  async function renderDiagram(mermaid, code) {
    try {
      await mermaid.parse(code);
    } catch (_e) {
      return { ok: false, code: ERR.PARSE };
    }

    let svgText;
    const id = "revdeck-mmd-" + renderSeq++;
    try {
      const out = await mermaid.render(id, code);
      svgText = out && out.svg;
      if (!svgText) return { ok: false, code: ERR.RENDER };
    } catch (_e) {
      return { ok: false, code: ERR.RENDER };
    }

    // 3. Sanitize (allowlist walk) and adopt into this document.
    let cleanRoot;
    try {
      cleanRoot = sanitizeSvgDocument(svgText);
    } catch (_e) {
      return { ok: false, code: ERR.SANITIZE };
    }

    // 4. Insert via importNode (never innerHTML).
    const host = document.getElementById("diagram");
    host.replaceChildren();
    const imported = document.importNode(cleanRoot, true);
    host.appendChild(imported);

    // Prefer the SVG's intrinsic size, which is layout-independent and reliable
    // right after import. mermaid encodes it in viewBox ("0 0 W H") and usually
    // an explicit width/height. getBBox is a last resort: on a freshly-imported,
    // not-yet-laid-out SVG it can return ~0 height, which previously collapsed the
    // diagram to MIN_DIM (a thin strip).
    let width = 0;
    let height = 0;
    const viewBox = imported.getAttribute && imported.getAttribute("viewBox");
    if (viewBox) {
      const parts = viewBox.split(/[\s,]+/).map(Number);
      if (parts.length === 4 && parts[2] > 0 && parts[3] > 0) {
        width = Math.ceil(parts[2]);
        height = Math.ceil(parts[3]);
      }
    }
    if (!width || !height) {
      const aw = parseFloat(imported.getAttribute("width"));
      const ah = parseFloat(imported.getAttribute("height"));
      if (aw > 0) width = Math.ceil(aw);
      if (ah > 0) height = Math.ceil(ah);
    }
    if (!width || !height) {
      try {
        const box = imported.getBBox ? imported.getBBox() : null;
        if (box && box.width && box.height) {
          width = Math.ceil(box.width + box.x + 8);
          height = Math.ceil(box.height + box.y + 8);
        }
      } catch (_e) {
        /* getBBox can throw before layout; handled by the fallback below */
      }
    }
    // Absolute fallback so a diagram is never rendered as a thin strip.
    if (!width) width = 320;
    if (!height) height = 160;
    // A real diagram needs vertical room; clamp height up to a usable minimum.
    width = G.clamp(width, MIN_DIM, MAX_DIM);
    height = G.clamp(height, 80, MAX_DIM);
    // Render at the diagram's INTRINSIC size; only downscale on a narrow
    // container, never upscale. Setting width="100%" previously stretched a
    // small 2-node graph to the full chat column, magnifying fonts ~6x. The
    // viewBox preserves aspect ratio, so a fixed intrinsic width + auto height
    // keeps text at its natural size while max-width lets it shrink responsively.
    imported.setAttribute("width", String(width));
    imported.removeAttribute("height");
    imported.style.width = width + "px";
    imported.style.maxWidth = "100%";
    imported.style.height = "auto";
    return { ok: true, width, height };
  }

  // -- postMessage protocol ------------------------------------------------
  let busy = false;

  function post(msg) {
    // Reply to the opener. targetOrigin "*" is acceptable because the payload carries
    // NO sensitive data (no SVG, no source echo) — only a status code and integer
    // dimensions — and the parent independently validates event.source identity before
    // trusting anything.
    try {
      window.parent.postMessage(Object.assign({ protocol: PROTOCOL }, msg), "*");
    } catch (_e) {
      /* parent gone */
    }
  }

  function handleMessage(event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (!data || typeof data !== "object" || data.protocol !== PROTOCOL) return;
    const id = G.safeId(data.id);
    if (data.type !== "render") {
      post({ type: "error", id, code: ERR.PROTOCOL });
      return;
    }
    if (!id) {
      post({ type: "error", id: "", code: ERR.PROTOCOL });
      return;
    }
    if (busy) {
      post({ type: "error", id, code: ERR.PROTOCOL });
      return;
    }
    let code = typeof data.code === "string" ? data.code : "";
    code = code.replace(/\r\n?/g, "\n");
    if (!code.trim()) {
      post({ type: "error", id, code: ERR.EMPTY });
      return;
    }
    const pf = G.preflight(code);
    if (pf) {
      post({ type: "error", id, code: pf });
      return;
    }
    busy = true;
    renderDiagram(window.__revdeckMermaid, code)
      .then((res) => {
        if (res.ok) post({ type: "rendered", id, width: res.width, height: res.height });
        else post({ type: "error", id, code: res.code });
      })
      .catch(() => post({ type: "error", id, code: ERR.INTERNAL }))
      .finally(() => {
        busy = false;
      });
  }

  function boot() {
    const mermaid = window.mermaid;
    if (!mermaid || !G) {
      // Mermaid or the guards failed to load (e.g. blocked). Answer any render
      // request with an error so the parent falls back to escaped source.
      window.addEventListener("message", function (event) {
        if (event.source !== window.parent) return;
        const d = event.data;
        if (d && typeof d === "object" && d.protocol === PROTOCOL && d.type === "render") {
          post({ type: "error", id: G ? G.safeId(d.id) : "", code: ERR.INTERNAL });
        }
      });
      return;
    }
    window.__revdeckMermaid = mermaid;
    try {
      configureMermaid(mermaid);
    } catch (_e) {
      /* fall through; render surfaces errors */
    }
    window.addEventListener("message", handleMessage);
    post({ type: "ready" });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
