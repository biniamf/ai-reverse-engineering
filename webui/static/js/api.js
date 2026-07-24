// Biniam Demissie
// The browser only ever talks to this Flask app (same origin). It never
// sees or constructs the Ghidra base URL: analysis data comes from the validated
// /api/jobs/<id>/... proxy routes.

/** A network/HTTP error carrying a status and a safe message. */
export class ApiError extends Error {
  constructor(message, { status = 0, code = "error" } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function parseJson(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function request(url, { method = "GET", body, signal, headers } = {}) {
  let response;
  try {
    response = await fetch(url, {
      method,
      body,
      signal,
      headers: headers || (body ? { "Content-Type": "application/json" } : undefined),
    });
  } catch (err) {
    if (err && err.name === "AbortError") throw err;
    throw new ApiError("Cannot reach the server", { code: "offline" });
  }
  const data = await parseJson(response);
  if (!response.ok) {
    const msg =
      (data && (data.error || data.message)) ||
      `Request failed (HTTP ${response.status})`;
    throw new ApiError(msg, {
      status: response.status,
      code: (data && data.code) || "http_error",
    });
  }
  return data;
}

export const api = {
  listJobs: (signal) => request("/jobs", { signal }),
  jobStatus: (jobId, signal) => request(`/status/${encodeURIComponent(jobId)}`, { signal }),
  // History for one thread. `threadId` (absent/"main" -> default thread) is
  // mirror-encoded like every other path/param. A cache-bust param keeps a
  // reload fresh per (job, thread) after a return-conclusion write.
  chatHistory: (jobId, threadId, signal) => {
    // Backwards compatibility: the pre-thread API accepted (jobId, signal).
    // Treat a non-string second argument as that legacy AbortSignal position.
    if (threadId != null && typeof threadId !== "string") {
      signal = threadId;
      threadId = null;
    }
    const qs = new URLSearchParams();
    if (threadId != null && String(threadId) !== "" && String(threadId) !== "main") {
      qs.set("thread_id", String(threadId));
    }
    qs.set("_", String(Date.now()));
    return request(
      `/chat/history/${encodeURIComponent(jobId)}?${qs.toString()}`,
      { signal }
    );
  },
  // Chat threads (sub-conversations). List is a GET; create/return are
  // same-origin POSTs (no forged cross-site create/return).
  chatThreads: (jobId, signal) =>
    request(`/chat/threads/${encodeURIComponent(jobId)}`, { signal }),
  createThread: (jobId, { title, parentThreadId } = {}, signal) =>
    request(`/chat/threads/${encodeURIComponent(jobId)}`, {
      method: "POST",
      body: JSON.stringify({ title, parent_thread_id: parentThreadId || null }),
      signal,
    }),
  returnThread: (jobId, threadId, signal) =>
    request(
      `/chat/threads/${encodeURIComponent(jobId)}/${encodeURIComponent(threadId)}/return`,
      { method: "POST", signal, headers: {} }
    ),
  renameThread: (jobId, threadId, title, signal) =>
    request(
      `/chat/threads/${encodeURIComponent(jobId)}/${encodeURIComponent(threadId)}/rename`,
      {
        method: "POST",
        body: JSON.stringify({ title }),
        signal,
      }
    ),
  workflows: (signal) => request("/api/workflows", { signal }),
  capabilities: (signal) => request("/api/capabilities", { signal }),
  // Bounded, same-origin force-refresh after a service restart / capability
  // change so a stale report is not diagnosed as a downgrade.
  refreshCapabilities: (signal) =>
    request("/api/capabilities/refresh", { method: "POST", signal, headers: {} }),

  cancelJob: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, {
      method: "POST",
      signal,
      headers: {},
    }),
  deleteJob: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}`, {
      method: "DELETE",
      signal,
      headers: {},
    }),

  upload(file, signal, { analyzeAsRaw = false } = {}) {
    const form = new FormData();
    form.append("file", file);
    if (analyzeAsRaw) form.append("analyze_as_raw", "true");
    // Let the browser set the multipart boundary; do not force Content-Type.
    return request("/upload", { method: "POST", body: form, signal, headers: {} });
  },

  // Analysis proxy routes. `query` is an optional bounded substring the *service*
  // matches by name/display-name/address across the whole program before pagination, so
  // a hit outside the current page is still found. Omitted/empty -> plain listing.
  functions: (jobId, { offset = 0, limit = 100, query } = {}, signal) => {
    const qs = new URLSearchParams();
    qs.set("offset", String(offset));
    qs.set("limit", String(limit));
    if (query != null && String(query).trim() !== "") qs.set("q", String(query).trim());
    return request(
      `/api/jobs/${encodeURIComponent(jobId)}/functions?${qs.toString()}`,
      { signal }
    );
  },
  decompile: (jobId, addr, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/decompile?addr=${encodeURIComponent(addr)}`,
      { signal }
    ),
  xrefs: (jobId, addr, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/xrefs?addr=${encodeURIComponent(addr)}`,
      { signal }
    ),
  imports: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/imports`, { signal }),
  strings: (jobId, { minLength } = {}, signal) => {
    const q = minLength ? `?min_length=${encodeURIComponent(minLength)}` : "";
    return request(`/api/jobs/${encodeURIComponent(jobId)}/strings${q}`, { signal });
  },
  query: (jobId, query, regex, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/query?query=${encodeURIComponent(
        query
      )}&regex=${regex ? "1" : "0"}`,
      { signal }
    ),
  summary: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/summary`, { signal }),
  callgraph: (jobId, addr, depth, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/callgraph?addr=${encodeURIComponent(
        addr
      )}${depth ? `&depth=${encodeURIComponent(depth)}` : ""}`,
      { signal }
    ),
  types: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/types`, { signal }),
  globals: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/globals`, { signal }),
  annotations: (jobId, addr, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/annotations${
        addr ? `?addr=${encodeURIComponent(addr)}` : ""
      }`,
      { signal }
    ),
  // The known ETag/revision is forwarded as If-Match so the server can reject a
  // lost update (409). The body carries the sanitized overlay fields only.
  saveAnnotation: (jobId, addr, body, etag, signal) => {
    const headers = { "Content-Type": "application/json" };
    if (etag) headers["If-Match"] = etag;
    return request(
      `/api/jobs/${encodeURIComponent(jobId)}/annotations/${encodeURIComponent(addr)}`,
      { method: "PUT", body: JSON.stringify(body), headers, signal }
    );
  },
  hexdump: (jobId, start, length, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/hexdump?start=${encodeURIComponent(
        start
      )}&length=${encodeURIComponent(length || 16)}`,
      { signal }
    ),
  // The export is a bounded binary ZIP the browser downloads via a normal
  // same-origin navigation; the URL never contains the Ghidra base URL.
  exportUrl: (jobId) => `/api/jobs/${encodeURIComponent(jobId)}/export`,

  // ---- Attack surface / security index (v1-only) ---------------------- Deterministic
  // evidence-based triage priorities -- not vulnerability verdicts.
  securitySummary: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/security/summary`, { signal }),
  securityFunctions: (jobId, params = {}, signal) => {
    const qs = new URLSearchParams();
    const { offset, limit, band, category, minScore, query, rank, sort, order } = params;
    if (offset != null) qs.set("offset", String(offset));
    if (limit != null) qs.set("limit", String(limit));
    if (band) qs.set("band", band);
    if (category) qs.set("category", category);
    if (minScore != null && minScore !== "") qs.set("min_score", String(minScore));
    if (query != null && String(query).trim() !== "") qs.set("q", String(query).trim());
    if (rank != null && String(rank).trim() !== "") qs.set("rank", String(rank).trim());
    if (sort) qs.set("sort", sort);
    if (order) qs.set("order", order);
    const q = qs.toString();
    return request(
      `/api/jobs/${encodeURIComponent(jobId)}/security/functions${q ? `?${q}` : ""}`,
      { signal }
    );
  },
  securityFunction: (jobId, addr, signal) =>
    request(
      `/api/jobs/${encodeURIComponent(jobId)}/security/functions/${encodeURIComponent(addr)}`,
      { signal }
    ),
  // State-changing: same-origin only (no forged cross-site rescore).
  rescoreSecurity: (jobId, signal) =>
    request(`/api/jobs/${encodeURIComponent(jobId)}/security/rescore`, {
      method: "POST",
      signal,
      headers: {},
    }),
};

/* Open a chat SSE stream. Calls `onEvent(parsedObject)` for each `data:` frame and
 * resolves when the stream ends. Abort via the provided AbortSignal. */
export async function streamChat(payload, { signal, onEvent }) {
  const response = await fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal,
  });
  if (!response.ok || !response.body) {
    const data = await parseJson(response);
    throw new ApiError((data && data.error) || `Chat failed (HTTP ${response.status})`, {
      status: response.status,
    });
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE frames are separated by a blank line.
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      for (const line of frame.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        const raw = line.slice(6);
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch {
          continue; // ignore malformed frame
        }
        onEvent(parsed);
      }
    }
  }
}
