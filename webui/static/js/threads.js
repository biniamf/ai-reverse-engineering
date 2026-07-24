
export const MAIN_THREAD_ID = "main";

export function isMainThread(threadId) {
  return threadId == null || threadId === MAIN_THREAD_ID;
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

function safeNum(v) {
  return Number.isFinite(v) ? v : null;
}

export function normalizeThreads(list) {
  const arr = Array.isArray(list) ? list : [];
  const out = [];
  for (const t of arr) {
    if (!t || typeof t !== "object") continue;
    const threadId = safeStr(t.thread_id);
    if (!threadId) continue;
    out.push({
      threadId,
      title: safeStr(t.title) || (threadId === MAIN_THREAD_ID ? "Main" : "Sub-investigation"),
      parentThreadId: t.parent_thread_id == null ? null : safeStr(t.parent_thread_id),
      createdAt: safeNum(t.created_at),
      updatedAt: safeNum(t.updated_at),
      messageCount: safeNum(t.message_count) || 0,
    });
  }
  return out;
}

/* Order threads for the switcher: the main thread first, then sub-threads by creation
 * time (oldest first; entries without a timestamp keep their order). Returns a NEW
 * array; the input is never mutated. */
export function orderThreads(threads) {
  const norm = normalizeThreads(threads);
  const main = norm.find((t) => t.threadId === MAIN_THREAD_ID) || {
    threadId: MAIN_THREAD_ID,
    title: "Main",
    parentThreadId: null,
    createdAt: null,
    updatedAt: null,
    messageCount: 0,
  };
  const subs = norm
    .filter((t) => t.threadId !== MAIN_THREAD_ID)
    .map((t, i) => ({ t, i }))
    .sort((a, b) => {
      const ca = a.t.createdAt;
      const cb = b.t.createdAt;
      if (ca != null && cb != null && ca !== cb) return ca - cb;
      return a.i - b.i; // stable for equal/absent timestamps
    })
    .map((x) => x.t);
  return [main, ...subs];
}

/* Extract the provenance sub-result card data from a replayed history message, or null
 * when the message is not a sub-result card. */
export function subresultCard(msg) {
  if (!msg || typeof msg !== "object") return null;
  const sr = msg.subresult;
  if (!sr || typeof sr !== "object") return null;
  const cites = sr.citations && typeof sr.citations === "object" ? sr.citations : {};
  const norm = (rawList) =>
    (Array.isArray(rawList) ? rawList : [])
      .map((c) => ({
        kind: safeStr(c && c.kind),
        value: safeStr(c && c.value),
        raw: safeStr(c && c.raw),
      }))
      .filter((c) => c.kind && c.value);
  return {
    sourceThreadId: safeStr(sr.source_thread_id) || null,
    title: safeStr(sr.title) || "Sub-investigation",
    summary: safeStr(sr.summary),
    valid: norm(cites.valid),
    invalid: norm(cites.invalid),
  };
}
