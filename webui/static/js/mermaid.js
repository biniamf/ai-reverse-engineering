// Biniam Demissie
// Parent-side controller for the sandboxed Mermaid renderer. This
// module runs in the MAIN (trusted) document. It never parses or renders Mermaid
// itself. For each ```mermaid code block produced by the safe Markdown renderer
// (render.js), it: 1.

const PROTOCOL = "revdeck-mermaid/1";
const FRAME_SRC = "/mermaid-frame";
const RENDER_TIMEOUT_MS = 8000;
const READY_TIMEOUT_MS = 8000;
const MAX_SOURCE_CHARS = 8000;
const MAX_DIM = 4000;
const MIN_DIM = 20;
// A rendered diagram must be at least this tall so a small reported height
// cannot collapse it into an unreadable strip.
const MIN_DIAGRAM_HEIGHT = 80;

// Safe, user-facing messages for the fixed frame error codes. We never show the
// raw Mermaid exception; only these strings.
const ERROR_TEXT = {
  protocol_error: "Diagram could not be rendered",
  empty_source: "Diagram is empty",
  source_too_large: "Diagram source is too large to render",
  preflight_rejected: "Diagram is too complex to render safely",
  parse_error: "Diagram could not be parsed",
  render_error: "Diagram could not be rendered",
  sanitize_error: "Diagram could not be rendered",
  internal_error: "Diagram could not be rendered",
  timeout: "Diagram rendering timed out",
};

function randomId() {
  const bytes = new Uint8Array(16);
  (window.crypto || {}).getRandomValues
    ? window.crypto.getRandomValues(bytes)
    : bytes.forEach((_, i) => (bytes[i] = Math.floor(Math.random() * 256)));
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return "r" + s;
}

function appOrigin() {
  return window.location.origin;
}

function clampDim(v, lo, hi) {
  v = Number(v);
  if (!Number.isFinite(v)) return lo;
  return Math.max(lo, Math.min(hi, Math.round(v)));
}

/**
 * A single live diagram render. Owns one iframe and one message listener, and
 * cleans both up on completion, error, timeout, or cancel.
 */
class DiagramRender {
  constructor(figure, source) {
    this.figure = figure;
    this.source = source;
    this.id = randomId();
    this.iframe = null;
    this.readyTimer = null;
    this.renderTimer = null;
    this.settled = false;
    this._onMessage = this._handleMessage.bind(this);
    this.pendingSend = true; // send once the frame reports ready
  }

  start() {
    if (this.source.length > MAX_SOURCE_CHARS) {
      this._fail("source_too_large");
      return;
    }
    const iframe = document.createElement("iframe");
    // The ONLY capability granted is script execution. No allow-same-origin (keeps the
    // frame opaque and unable to touch cookies/DOM/APIs), no allow-forms/allow-
    // popups/allow-top-navigation/allow-downloads/ allow-modals/allow-pointer-lock.
    iframe.setAttribute("sandbox", "allow-scripts");
    iframe.setAttribute("src", FRAME_SRC);
    iframe.setAttribute("title", "Rendered diagram (sandboxed)");
    iframe.className = "mermaid-frame";
    iframe.style.width = "100%";
    iframe.style.border = "0";
    // Collapse it visually until a successful render (so the escaped-source placeholder
    // is what the analyst sees meanwhile) WITHOUT using hidden/display:none or
    // loading="lazy": an off-screen or display:none iframe is not loaded by the
    // browser, so it would never.
    iframe.style.height = "0px";
    iframe.style.overflow = "hidden";
    this.iframe = iframe;

    window.addEventListener("message", this._onMessage);

    // If the frame never reports ready (e.g. blocked), fall back.
    this.readyTimer = setTimeout(() => this._fail("timeout"), READY_TIMEOUT_MS);

    this.figure.appendChild(iframe);
  }

  _handleMessage(event) {
    if (this.settled) return;
    // Identity gate: the message must come from OUR iframe's window.
    if (!this.iframe || event.source !== this.iframe.contentWindow) return;
    // Origin gate: a sandbox="allow-scripts" (no allow-same-origin) frame has an opaque
    // origin, so its messages arrive with origin "null". Some engines may instead
    // report the app origin for a same-origin document; accept either, and reject
    // anything else.
    if (event.origin !== "null" && event.origin !== appOrigin()) return;

    const data = event.data;
    if (!data || typeof data !== "object" || data.protocol !== PROTOCOL) return;

    if (data.type === "ready") {
      this._onReady();
      return;
    }
    // For render results, the id must match this render's id (drops stale or
    // cross-talk responses from an earlier/other diagram frame).
    if (data.id !== this.id) return;

    if (data.type === "rendered") {
      this._onRendered(data);
    } else if (data.type === "error") {
      this._fail(typeof data.code === "string" ? data.code : "render_error");
    }
  }

  _onReady() {
    if (this.settled || !this.pendingSend) return;
    this.pendingSend = false;
    clearTimeout(this.readyTimer);
    this.readyTimer = null;
    // Post the source to the frame. targetOrigin "*" is required because the frame's
    // origin is opaque ("null") and cannot be named; the payload is just our own
    // diagram source going *into* the sandbox, and the frame independently validates
    // that the sender is its.
    try {
      this.iframe.contentWindow.postMessage(
        { protocol: PROTOCOL, type: "render", id: this.id, code: this.source },
        "*"
      );
    } catch (_e) {
      this._fail("internal_error");
      return;
    }
    this.renderTimer = setTimeout(() => this._fail("timeout"), RENDER_TIMEOUT_MS);
  }

  _onRendered(data) {
    if (this.settled) return;
    this.settled = true;
    this._clearTimers();
    // A rendered diagram needs real vertical room. Clamp height up to a usable
    // minimum so a small or zero reported size can never collapse it into a thin
    // strip (the frame also floors this; the parent is the last guard).
    const h = clampDim(data.height, MIN_DIAGRAM_HEIGHT, MAX_DIM);
    // Size the iframe to the diagram's intrinsic width (capped to the column via
    // CSS max-width), not 100%, so a small graph is not stretched to full width
    // and magnified. Height gets a usable floor; width follows the content.
    const w = clampDim(data.width, MIN_DIM, MAX_DIM);
    this.iframe.style.width = w + "px";
    this.iframe.style.maxWidth = "100%";
    this.iframe.style.height = h + "px";
    this.iframe.style.overflow = "";
    this.iframe.hidden = false;
    this.figure.setAttribute("data-state", "rendered");
    const details = this.figure.querySelector(".mermaid-src-details");
    if (details) details.open = false;
    window.removeEventListener("message", this._onMessage);
  }

  _fail(code) {
    if (this.settled) return;
    this.settled = true;
    this._clearTimers();
    window.removeEventListener("message", this._onMessage);
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
    }
    this.iframe = null;
    this.figure.setAttribute("data-state", "error");
    const caption = this.figure.querySelector(".mermaid-caption");
    if (caption) {
      caption.textContent = ERROR_TEXT[code] || ERROR_TEXT.render_error;
      caption.classList.add("mermaid-caption--error");
    }
    const details = this.figure.querySelector(".mermaid-src-details");
    if (details) details.open = true;
  }

  _clearTimers() {
    if (this.readyTimer) clearTimeout(this.readyTimer);
    if (this.renderTimer) clearTimeout(this.renderTimer);
    this.readyTimer = null;
    this.renderTimer = null;
  }

  /** Cancel an in-flight render and tear everything down. */
  cancel() {
    if (this.settled) {
      this._clearTimers();
      window.removeEventListener("message", this._onMessage);
      return;
    }
    this.settled = true;
    this._clearTimers();
    window.removeEventListener("message", this._onMessage);
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
    }
    this.iframe = null;
  }
}

/* Enhance every not-yet-enhanced mermaid figure inside `root` by rendering it in a
 * sandboxed frame. Returns the list of live DiagramRender handles so the caller can
 * cancel them (e.g. on a new render or when the turn is replaced). */
export function enhanceMermaid(root) {
  if (!root || typeof root.querySelectorAll !== "function") return [];
  const figures = root.querySelectorAll(
    'figure.md-mermaid[data-state="placeholder"]'
  );
  const renders = [];
  for (const figure of figures) {
    const codeEl = figure.querySelector("code[data-mermaid-source]");
    if (!codeEl) continue;
    // textContent gives us the decoded original source (the entities that
    // render.js emitted are decoded by the DOM), never raw markup.
    const source = codeEl.textContent || "";
    if (!source.trim()) {
      figure.setAttribute("data-state", "error");
      continue;
    }
    figure.setAttribute("data-state", "loading");
    const r = new DiagramRender(figure, source);
    r.start();
    renders.push(r);
  }
  return renders;
}

/** Cancel and clean up a list of DiagramRender handles. */
export function cancelRenders(renders) {
  if (!Array.isArray(renders)) return;
  for (const r of renders) {
    try {
      r.cancel();
    } catch (_e) {
      /* best effort */
    }
  }
}

export const __internals = { randomId, clampDim, ERROR_TEXT, DiagramRender };
