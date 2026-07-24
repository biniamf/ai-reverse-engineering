// Biniam Demissie
// This module is the ONLY place untrusted content becomes markup. It
// replaces the previous unsafe `marked.parse()` + innerHTML path.

// Escaping
const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

// Only these URL schemes may appear in a rendered link. Everything else
// (javascript:, data:, vbscript:, ...) is dropped so a Markdown link cannot
// smuggle script execution.
const SAFE_URL_RE = /^(?:https?:\/\/|mailto:|#|\/)/i;

export function safeUrl(url) {
  const trimmed = String(url == null ? "" : url).trim();
  for (let k = 0; k < trimmed.length; k++) {
    if (trimmed.charCodeAt(k) <= 0x20) return "#";
  }
  return SAFE_URL_RE.test(trimmed) ? trimmed : "#";
}

const CODE_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
  "return", "goto", "void", "int", "char", "short", "long", "unsigned",
  "signed", "float", "double", "struct", "union", "enum", "typedef", "const",
  "static", "extern", "sizeof", "volatile", "register", "default",
  "def", "class", "import", "from", "function", "var", "let", "true", "false",
  "null", "nullptr", "NULL", "and", "or", "not", "new", "delete", "public",
  "private", "protected",
]);

/* Highlight a single line of already-UNESCAPED code, returning ESCAPED HTML with <span
 * class="tok-*"> wrappers. This is intentionally approximate: it never executes and only
 * ever emits our own span tags around escaped text. / */
function highlightCodeLine(line) {
  let out = "";
  let i = 0;
  const n = line.length;
  while (i < n) {
    const ch = line[i];
    if ((ch === "/" && line[i + 1] === "/") || ch === "#") {
      out += `<span class="tok-com">${escapeHtml(line.slice(i))}</span>`;
      break;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < n && line[j] !== ch) {
        if (line[j] === "\\") j++;
        j++;
      }
      out += `<span class="tok-str">${escapeHtml(line.slice(i, j + 1))}</span>`;
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < n && /[0-9a-fA-FxX._]/.test(line[j])) j++;
      out += `<span class="tok-num">${escapeHtml(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(line[j])) j++;
      const word = line.slice(i, j);
      const isCall = line[j] === "(";
      if (CODE_KEYWORDS.has(word)) {
        out += `<span class="tok-kw">${escapeHtml(word)}</span>`;
      } else if (isCall) {
        out += `<span class="tok-fn">${escapeHtml(word)}</span>`;
      } else {
        out += escapeHtml(word);
      }
      i = j;
      continue;
    }
    out += escapeHtml(ch);
    i++;
  }
  return out;
}

export function highlightCode(code, lang) {
  const useHighlight =
    !lang ||
    /^(c|cpp|c\+\+|h|py|python|js|javascript|ts|java|go|rust|asm|pseudo|pseudoc)$/i.test(
      lang
    );
  if (!useHighlight) return escapeHtml(code);
  return code
    .split("\n")
    .map((line) => highlightCodeLine(line))
    .join("\n");
}

// Inline Markdown (operates on already HTML-escaped text)
/* Apply inline formatting to text that has ALREADY been HTML-escaped. Because the input
 * is escaped, the regexes below can only ever match literal characters the user typed,
 * never injected tags. / */
function renderInline(escaped) {
  let out = escaped;
  out = out.replace(/`([^`]+)`/g, (_m, c) => `<code>${c}</code>`);
  // Links [text](url) -- url validated by safeUrl.
  out = out.replace(
    /\[([^\]]+)\]\(([^)\s]+)\)/g,
    (_m, text, url) =>
      `<a href="${escapeHtml(safeUrl(_decodeEntities(url)))}" rel="noopener noreferrer nofollow" target="_blank">${text}</a>`
  );
  out = out.replace(/\*\*([^*]+)\*\*/g, (_m, c) => `<strong>${c}</strong>`);
  out = out.replace(/(^|[^*])\*([^*]+)\*/g, (_m, pre, c) => `${pre}<em>${c}</em>`);
  out = out.replace(/__([^_]+)__/g, (_m, c) => `<strong>${c}</strong>`);
  return out;
}

function _decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

// Block Markdown -> safe HTML string
const MAX_MARKDOWN_CHARS = 200000;
const MAX_MERMAID_CHARS = 8000;

/* Render a Markdown string to a safe HTML string. Guarantees: - all HTML is escaped
 * before any structure is parsed; - only a fixed allowlist of tags is emitted; -
 * ```mermaid blocks are rendered as their (escaped) SOURCE inside a <figure> rather than
 * executed. */
export function renderMarkdown(src) {
  const input = String(src == null ? "" : src).slice(0, MAX_MARKDOWN_CHARS);
  const lines = input.replace(/\r\n?/g, "\n").split("\n");
  const html = [];
  let i = 0;

  const flushParagraph = (buf) => {
    if (!buf.length) return;
    const text = renderInline(escapeHtml(buf.join("\n"))).replace(/\n/g, "<br>");
    html.push(`<p>${text}</p>`);
    buf.length = 0;
  };

  let para = [];

  while (i < lines.length) {
    const line = lines[i];

    const fence = line.match(/^```\s*([A-Za-z0-9_+-]*)\s*$/);
    if (fence) {
      flushParagraph(para);
      const lang = (fence[1] || "").toLowerCase();
      const body = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      i++; // skip closing fence
      const code = body.join("\n");
      if (lang === "mermaid") {
        // Progressive placeholder. The diagram SOURCE is emitted here only as escaped
        // text inside a <code> element (never as a raw attribute); a parent enhancer
        // (static/js/mermaid.js) reads it back via textContent and renders it inside a
        // sandboxed, opaque-origin iframe.
        const shown = code.slice(0, MAX_MERMAID_CHARS);
        html.push(
          `<figure class="md-mermaid mermaid-src" data-state="placeholder">` +
            `<figcaption class="mermaid-caption">Loading diagram…</figcaption>` +
            `<details class="mermaid-src-details" open>` +
            `<summary class="mermaid-src-summary">Diagram source</summary>` +
            `<pre class="md"><code data-mermaid-source="1">${escapeHtml(
              shown
            )}</code></pre>` +
            `</details>` +
          `</figure>`
        );
      } else {
        html.push(
          `<pre><code${lang ? ` class="lang-${escapeHtml(lang)}"` : ""}>${highlightCode(
            code,
            lang
          )}</code></pre>`
        );
      }
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flushParagraph(para);
      const level = heading[1].length;
      html.push(`<h${level}>${renderInline(escapeHtml(heading[2].trim()))}</h${level}>`);
      i++;
      continue;
    }

    if (/^>\s?/.test(line)) {
      flushParagraph(para);
      const quote = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quote.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      html.push(`<blockquote>${renderInline(escapeHtml(quote.join("\n"))).replace(/\n/g, "<br>")}</blockquote>`);
      continue;
    }

    if (
      /\|/.test(line) &&
      i + 1 < lines.length &&
      /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1]) &&
      /-/.test(lines[i + 1])
    ) {
      flushParagraph(para);
      const header = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /\|/.test(lines[i]) && lines[i].trim() !== "") {
        rows.push(splitRow(lines[i]));
        i++;
      }
      const thead = `<thead><tr>${header
        .map((c) => `<th>${renderInline(escapeHtml(c))}</th>`)
        .join("")}</tr></thead>`;
      const tbody = `<tbody>${rows
        .map(
          (r) =>
            `<tr>${r
              .map((c) => `<td>${renderInline(escapeHtml(c))}</td>`)
              .join("")}</tr>`
        )
        .join("")}</tbody>`;
      html.push(`<table>${thead}${tbody}</table>`);
      continue;
    }

    const ul = line.match(/^\s*[-*+]\s+(.*)$/);
    const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (ul || ol) {
      flushParagraph(para);
      const ordered = Boolean(ol);
      const items = [];
      const itemRe = ordered ? /^\s*\d+[.)]\s+(.*)$/ : /^\s*[-*+]\s+(.*)$/;
      while (i < lines.length && itemRe.test(lines[i])) {
        items.push(lines[i].match(itemRe)[1]);
        i++;
      }
      const tag = ordered ? "ol" : "ul";
      html.push(
        `<${tag}>${items
          .map((it) => `<li>${renderInline(escapeHtml(it))}</li>`)
          .join("")}</${tag}>`
      );
      continue;
    }

    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      flushParagraph(para);
      html.push("<hr>");
      i++;
      continue;
    }

    if (line.trim() === "") {
      flushParagraph(para);
      i++;
      continue;
    }

    para.push(line);
    i++;
  }
  flushParagraph(para);
  return html.join("\n");
}

function splitRow(line) {
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => c.trim());
}

// Small DOM helpers (browser-only; not exercised by the pure tests)
export function el(tag, opts = {}) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = opts.text;
  if (opts.attrs) {
    for (const [k, v] of Object.entries(opts.attrs)) {
      if (v !== null && v !== undefined) node.setAttribute(k, String(v));
    }
  }
  if (opts.html !== undefined) node.innerHTML = opts.html; // caller must pass safe HTML
  if (opts.children) {
    for (const child of opts.children) {
      if (child) node.append(child);
    }
  }
  return node;
}

export function setMarkdown(node, src) {
  node.innerHTML = renderMarkdown(src);
}
