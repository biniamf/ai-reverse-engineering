// Biniam Demissie
// Performance: - streamed tokens are appended to a buffer; the Markdown
// render is debounced (rAF-batched) so a long response renders a handful of times, not
// once per token; - the final code highlight/diagram handling happens in renderMarkdown
// at.

import { streamChat, api, ApiError } from "./api.js";
import { el, renderMarkdown } from "./render.js";
import { enhanceMermaid, cancelRenders } from "./mermaid.js";
import {
  emptyTimeline,
  reduceTimeline,
  markCancelled,
} from "./state.js";
import {
  MAIN_THREAD_ID,
  isMainThread,
  orderThreads,
  subresultCard,
} from "./threads.js";

const MAX_TURN_NODES = 60; // bounded chat DOM

export function createChatController({
  store,
  getComposer,
  onEvidence,
  onCitation,
  onSeedComposer,
}) {
  const logEl = document.getElementById("chat-log");
  let abortController = null;

  // ---- Threads (sub-conversations) -------------------------------------- The main
  // thread is the job's default conversation; sub-threads branch a focused line of
  // inquiry over the same job.
  const threadsWrap = document.getElementById("chat-threads");
  const threadTabsEl = document.getElementById("thread-tabs");
  const threadNewBtn = document.getElementById("thread-new");
  const threadRenameBtn = document.getElementById("thread-rename");
  const threadReturnBtn = document.getElementById("thread-return");
  const threadDialog = document.getElementById("thread-dialog");
  const threadDialogForm = document.getElementById("thread-dialog-form");
  const threadDialogTitle = document.getElementById("thread-dialog-title");
  const threadDialogHint = document.getElementById("thread-dialog-hint");
  const threadDialogSubmit = document.getElementById("thread-dialog-submit");
  const threadBriefing = document.getElementById("thread-briefing");
  const threadDialogCancel = document.getElementById("thread-dialog-cancel");
  let dialogMode = "create";
  let currentJob = null;
  let threads = []; // ordered client threads (main first)
  let selectedThread = MAIN_THREAD_ID; // "main" | <hex>
  // Budget the just-finished run used, so a Continue action can resume with the
  // same budget. Null means the run was unbounded (Continue also resumes unbounded).
  let lastRunBudget = null;
  // Set only for the duration of a Continue-triggered send(): override the
  // composer's current budget so resume uses the finished run's budget.
  let resumeBudget; // number | null | undefined
  let resumeUnbounded; // boolean | undefined

  function currentThreadKey() {
    return isMainThread(selectedThread) ? null : selectedThread;
  }
  // Live sandboxed-diagram renders for the CURRENT streaming turn only. They
  // are cancelled/torn down when a new turn starts, on cancel, and when a fresh
  // history replay wipes the log, so no orphan iframe/listener/timeout leaks.
  let activeRenders = [];

  function scrollToEnd() {
    logEl.scrollTop = logEl.scrollHeight;
  }

  function trimLog() {
    while (logEl.children.length > MAX_TURN_NODES) {
      logEl.removeChild(logEl.firstChild);
    }
  }

  function messageShell(role) {
    const roleLabel = role === "user" ? "Analyst" : "Assistant";
    const head = el("div", {
      class: "msg__head",
      children: [el("span", { class: "msg__role", text: roleLabel })],
    });
    const bubble = el("div", { class: "msg__bubble" });
    const wrap = el("div", {
      class: `msg msg--${role}`,
      children: [head, bubble],
    });
    return { wrap, bubble, head };
  }

  function addUserMessage(text) {
    const { wrap, bubble } = messageShell("user");
    bubble.textContent = text; // pre-wrap via CSS; never HTML
    logEl.append(wrap);
    trimLog();
    scrollToEnd();
  }

  function renderTimeline(timeline) {
    if (!timeline.started && timeline.steps.length === 0) return null;
    const stepsList = el("ol", { class: "timeline__steps" });
    for (const s of timeline.steps) {
      const title = el("div", {
        class: "step__title",
        children: [
          el("span", { class: "step__tool", text: s.tool }),
          s.args ? el("span", { class: "step__args", text: `(${s.args})` }) : null,
          statusChip(s.status),
        ],
      });
      const children = [
        el("div", { class: "step__rail", children: [el("span", { class: "step__dot" })] }),
        title,
      ];
      if (s.rationale) {
        children.push(el("div", { class: "step__rationale", text: s.rationale }));
      }
      if (s.evidence) {
        const ev = el("div", { class: "step__evidence" });
        ev.append(document.createTextNode("evidence: "));
        ev.append(el("b", { text: s.evidence }));
        children.push(ev);
      }
      if (s.durationMs !== null && s.durationMs !== undefined) {
        children.push(el("span", { class: "step__dur", text: `${s.durationMs} ms` }));
      }
      stepsList.append(
        el("li", { class: "step", attrs: { "data-status": s.status }, children })
      );
    }

    const headChildren = [
      el("span", { text: "Agent activity" }),
      el("span", {
        class: "timeline__meta",
        children: [
          el("span", {
            class: "chip",
            text: timeline.mode + (timeline.workflow ? ` · ${timeline.workflow}` : ""),
          }),
          timeline.budget
            ? el("span", { class: "chip", text: `budget ${timeline.budget}` })
            : null,
        ],
      }),
    ];

    const parts = [
      el("div", { class: "timeline__head", children: headChildren }),
      stepsList,
    ];

    for (const w of timeline.warnings) {
      parts.push(
        el("div", { class: "timeline__terminal", children: [statusChip("warning"), el("span", { text: w })] })
      );
    }

    // Cited evidence. Valid function citations become navigable links into the Analysis
    // workspace; string/import citations are shown as verified chips.
    const valid = timeline.validCitations || [];
    const invalid = timeline.invalidCitations || [];
    if (valid.length || invalid.length) {
      const citeChildren = [el("span", { class: "label", text: "Cited evidence" })];
      const chips = el("div", { class: "cite-list" });
      for (const c of valid) {
        if (c.kind === "function" && onCitation) {
          const link = el("button", {
            class: "cite cite--valid addr",
            text: `${c.kind}:${c.value}`,
            attrs: { type: "button", title: "Open in Analysis workspace" },
          });
          link.addEventListener("click", () => onCitation(c));
          chips.append(link);
        } else {
          chips.append(
            el("span", { class: "cite cite--valid", text: `${c.kind}:${c.value}` })
          );
        }
      }
      for (const c of invalid) {
        chips.append(
          el("span", {
            class: "cite cite--invalid",
            text: `${c.kind}:${c.value} (unverified)`,
            attrs: { title: "No matching evidence was retrieved for this citation." },
          })
        );
      }
      citeChildren.push(chips);
      parts.push(el("div", { class: "timeline__cites", children: citeChildren }));
    }

    if (timeline.terminal) {
      const term = timeline.terminal;
      const label =
        term.status === "cancelled"
          ? "Run cancelled by analyst"
          : term.status === "error"
          ? `Error: ${term.message || "run failed"}`
          : term.status === "max_turns"
          ? "Step budget reached — partial results"
          : "Run complete";
      parts.push(
        el("div", {
          class: "timeline__terminal",
          children: [statusChip(term.status), el("span", { text: label })],
        })
      );
    }

    return el("section", {
      class: "timeline",
      attrs: { "aria-label": "Agent activity timeline" },
      children: parts,
    });
  }

  function statusChip(status) {
    const s = String(status || "").toLowerCase();
    return el("span", {
      class: "chip",
      attrs: { "data-status": s },
      children: [el("span", { class: "chip__led" }), el("span", { text: s })],
    });
  }

  // A provenance "sub-result card": a visually distinct summary folded back into the
  // parent thread when a sub-investigation concludes.
  function renderSubresultCard(card) {
    const head = el("div", {
      class: "subresult__head",
      children: [
        el("span", { class: "subresult__badge", text: "Sub-investigation concluded" }),
        el("span", { class: "subresult__title", text: card.title }),
      ],
    });
    const summary = el("div", { class: "md subresult__summary" });
    summary.innerHTML = renderMarkdown(card.summary);
    const parts = [head, summary];

    if (card.valid.length || card.invalid.length) {
      const chips = el("div", { class: "cite-list" });
      for (const c of card.valid) {
        if (c.kind === "function" && onCitation) {
          const link = el("button", {
            class: "cite cite--valid addr",
            text: `${c.kind}:${c.value}`,
            attrs: { type: "button", title: "Open in Analysis workspace" },
          });
          link.addEventListener("click", () => onCitation(c));
          chips.append(link);
        } else {
          chips.append(
            el("span", { class: "cite cite--valid", text: `${c.kind}:${c.value}` })
          );
        }
      }
      for (const c of card.invalid) {
        chips.append(
          el("span", {
            class: "cite cite--invalid",
            text: `${c.kind}:${c.value} (unverified)`,
            attrs: { title: "No matching evidence was retrieved for this citation." },
          })
        );
      }
      parts.push(
        el("div", {
          class: "subresult__cites",
          children: [el("span", { class: "label", text: "Cited evidence" }), chips],
        })
      );
    }

    if (card.sourceThreadId) {
      const open = el("button", {
        class: "subresult__open",
        text: "Open sub-thread →",
        attrs: { type: "button" },
      });
      open.addEventListener("click", () => switchThread(card.sourceThreadId));
      parts.push(open);
    }

    return el("section", {
      class: "subresult",
      attrs: { "aria-label": "Sub-investigation conclusion" },
      children: parts,
    });
  }

  function replayHistory(history) {
    cancelRenders(activeRenders);
    activeRenders = [];
    logEl.replaceChildren();
    if (!Array.isArray(history)) return;
    const enhanceHosts = [];
    for (const msg of history) {
      if (!msg || typeof msg !== "object") continue;
      const role = msg.role;
      // Only user/assistant turns are shown. system/tool turns are internal;
      // rendering them (or calling the Markdown renderer on a null tool
      // content) is exactly the historical marked.parse(null) bug we avoid.
      if (role === "user") {
        const content = typeof msg.content === "string" ? stripJobTag(msg.content) : "";
        addUserMessage(content);
      } else if (role === "assistant") {
        const card = subresultCard(msg);
        if (card) {
          // Provenance card takes precedence over the mirrored content so the
          // conclusion is never double-rendered.
          const { wrap, bubble } = messageShell("assistant");
          const cardEl = renderSubresultCard(card);
          bubble.append(cardEl);
          logEl.append(wrap);
          const md = cardEl.querySelector(".subresult__summary");
          if (md) enhanceHosts.push(md);
        } else if (typeof msg.content === "string" && msg.content.trim() !== "") {
          const { wrap, bubble } = messageShell("assistant");
          const md = el("div", { class: "md" });
          md.innerHTML = renderMarkdown(msg.content);
          bubble.append(md);
          logEl.append(wrap);
          enhanceHosts.push(md);
        }
        // assistant tool-call-only turns (content null) render nothing here.
      }
    }
    trimLog();
    scrollToEnd();
    // Enhance mermaid diagrams once, after the whole replayed transcript is in
    // the DOM (not per token — this is static history).
    for (const host of enhanceHosts) {
      activeRenders = activeRenders.concat(enhanceMermaid(host));
    }
  }

  function stripJobTag(text) {
    return text.replace(/^\[Job ID:\s*[0-9a-fA-F]{32}\]\s*/, "");
  }

  // ---- Streaming --------------------------------------------------------
  async function send(message) {
    const jobId = store.get().selectedJob;
    if (!jobId || !message.trim()) return;
    if (abortController) return; // one active stream at a time

    cancelRenders(activeRenders);
    activeRenders = [];

    addUserMessage(message);

    const composer = getComposer ? getComposer() : {};
    const payload = { message, job_id: jobId };
    const threadKey = currentThreadKey();
    if (threadKey) payload.thread_id = threadKey;
    if (composer.mode && composer.mode !== "copilot") {
      payload.mode = composer.mode;
      if (composer.workflow) payload.workflow = composer.workflow;
    }
    // Budget/unbounded apply in both modes; the server caps unbounded at
    // MAX_STEP_BUDGET and ignores step_budget when unbounded is set. A Continue
    // action overrides the composer with the finished run's budget.
    const useUnbounded =
      resumeUnbounded !== undefined ? resumeUnbounded : composer.unbounded;
    const useBudget =
      resumeBudget !== undefined ? resumeBudget : composer.stepBudget;
    if (useUnbounded) payload.unbounded = true;
    else if (useBudget) payload.step_budget = useBudget;
    lastRunBudget = payload.unbounded ? null : payload.step_budget || null;
    // Structured evidence-to-chat handoff: only entity refs/addresses cross
    // the wire; the server builds the trusted, delimited framing.
    if (composer.target) payload.target = composer.target;
    if (Array.isArray(composer.evidence) && composer.evidence.length) {
      payload.evidence = composer.evidence;
    }

    const { wrap, bubble } = messageShell("assistant");
    const timelineHost = el("div");
    const answerHost = el("div", { class: "md" });
    const waitingHost = el("div", {
      class: "agent-waiting",
      attrs: { role: "status", "aria-live": "polite" },
      children: [
        el("span", { class: "agent-waiting__scan", attrs: { "aria-hidden": "true" } }),
        el("span", { class: "agent-waiting__label", text: "Model working" }),
        el("span", { class: "agent-waiting__dots", attrs: { "aria-hidden": "true" } }),
      ],
    });
    bubble.append(waitingHost, timelineHost, answerHost);
    logEl.append(wrap);
    trimLog();
    scrollToEnd();

    let timeline = emptyTimeline();
    let renderScheduled = false;
    let done = false;
    // Once we've done the final paint + diagram enhancement, a late rAF paint
    // must NOT run: re-writing answerHost.innerHTML would wipe the freshly
    // inserted sandbox iframes. This guard makes any queued paint a no-op.
    let finished = false;

    const paint = () => {
      renderScheduled = false;
      if (finished) return;
      const tl = renderTimeline(timeline);
      timelineHost.replaceChildren(...(tl ? [tl] : []));
      answerHost.innerHTML = renderMarkdown(timeline.answer);

      // The OpenAI-compatible completion call can be quiet for several seconds
      // before it returns a tool call or final answer. Keep an explicit visual
      // heartbeat during that gap. This is status—not hidden chain-of-thought.
      const activeStep = timeline.steps.find((s) => s.status === "running");
      const waiting = !timeline.terminal && !timeline.answer;
      waitingHost.hidden = !waiting;
      const waitingLabel = waitingHost.querySelector(".agent-waiting__label");
      if (waitingLabel) {
        waitingLabel.textContent = activeStep
          ? activeStep.rationale || `Running ${activeStep.tool}`
          : timeline.started
          ? timeline.mode === "autonomous"
            ? "Planning the bounded investigation"
            : "Reviewing the request"
          : "Connecting to the model";
      }
      scrollToEnd();
    };
    const schedulePaint = () => {
      if (renderScheduled) return;
      renderScheduled = true;
      (window.requestAnimationFrame || ((cb) => setTimeout(cb, 16)))(paint);
    };

    abortController = new AbortController();
    setStreaming(true);

    try {
      await streamChat(payload, {
        signal: abortController.signal,
        onEvent: (event) => {
          timeline = reduceTimeline(timeline, event);
          if (event && event.type === "done") done = true;
          schedulePaint();
          if (onEvidence && event && event.type === "tool_result" && event.evidence) {
            onEvidence(event);
          }
        },
      });
    } catch (err) {
      if (err && err.name === "AbortError") {
        timeline = markCancelled(timeline);
      } else {
        const msg =
          err instanceof ApiError ? err.message : "Connection to assistant failed.";
        timeline = reduceTimeline(timeline, { type: "error", content: msg });
      }
    } finally {
      abortController = null;
      setStreaming(false);
      if (!done && !timeline.terminal) {
        timeline = markCancelled(timeline);
      }
      paint();
      finished = true; // freeze the answer markup before enhancing
      // Diagram enhancement happens ONCE here, after the final paint has written the
      // completed answer markup — never per streamed token.
      activeRenders = activeRenders.concat(enhanceMermaid(answerHost));

      // Budget-exhausted run: offer a Continue that resumes on the SAME thread
      // with the same budget. The agent reloads the persisted tool results, so
      // it finishes without redoing completed tool calls.
      if (timeline.terminal && timeline.terminal.status === "max_turns") {
        renderContinue(bubble);
      }
    }
  }

  const CONTINUE_MESSAGE =
    "Continue the previous task. You already retrieved the evidence above; " +
    "do not restart — finish the task and give the final answer.";

  function renderContinue(bubble) {
    const budget = lastRunBudget;
    const label = budget ? `Continue (+${budget})` : "Continue";
    const btn = el("button", {
      class: "btn btn--continue",
      text: label,
      attrs: { type: "button" },
    });
    const wrap = el("div", { class: "chat__continue", children: [btn] });
    btn.addEventListener("click", () => {
      if (abortController) return; // one active stream at a time
      wrap.remove();
      // Resume with the same budget/unbounded the finished run used.
      resumeBudget = budget;
      resumeUnbounded = budget === null;
      send(CONTINUE_MESSAGE);
      resumeBudget = undefined;
      resumeUnbounded = undefined;
    });
    bubble.append(wrap);
  }

  function cancel() {
    if (abortController) abortController.abort();
    cancelRenders(activeRenders);
    activeRenders = [];
  }

  let streamingListeners = [];
  function setStreaming(active) {
    store.set({ streaming: active });
    for (const fn of streamingListeners) fn(active);
  }
  function onStreamingChange(fn) {
    streamingListeners.push(fn);
  }

  async function loadHistory(jobId, threadId) {
    logEl.replaceChildren();
    try {
      const history = await api.chatHistory(jobId, threadId == null ? null : threadId);
      replayHistory(history);
    } catch (err) {
      const banner = el("div", {
        class: "banner",
        text:
          err instanceof ApiError
            ? `Could not load chat history: ${err.message}`
            : "Could not load chat history.",
      });
      logEl.append(banner);
    }
  }

  function renderThreadTabs() {
    if (!threadTabsEl) return;
    threadTabsEl.replaceChildren();
    for (const t of threads) {
      const isSel =
        t.threadId === selectedThread ||
        (isMainThread(selectedThread) && t.threadId === MAIN_THREAD_ID);
      const tab = el("button", {
        class: "threadbar__tab" + (isSel ? " threadbar__tab--active" : ""),
        text: t.title,
        attrs: {
          type: "button",
          role: "tab",
          "aria-selected": isSel ? "true" : "false",
          title: t.messageCount ? `${t.title} · ${t.messageCount} msgs` : t.title,
        },
      });
      tab.addEventListener("click", () => switchThread(t.threadId));
      threadTabsEl.append(tab);
    }
    const onMain = isMainThread(selectedThread);
    if (threadRenameBtn) threadRenameBtn.hidden = onMain;
    if (threadReturnBtn) threadReturnBtn.hidden = onMain;
    if (threadsWrap) threadsWrap.hidden = false;
  }

  async function refreshThreads(jobId) {
    try {
      const data = await api.chatThreads(jobId);
      threads = orderThreads(data && data.threads);
    } catch {
      threads = orderThreads([]); // main-only fallback; the chat still works
    }
  }

  async function loadThreads(jobId) {
    currentJob = jobId;
    selectedThread = MAIN_THREAD_ID;
    store.set({ selectedThread: MAIN_THREAD_ID });
    await refreshThreads(jobId);
    renderThreadTabs();
    await loadHistory(jobId, null);
  }

  async function switchThread(threadId) {
    if (abortController) return; // one active stream: block switch mid-stream
    const target = isMainThread(threadId) ? MAIN_THREAD_ID : threadId;
    if (target === selectedThread) return;
    selectedThread = target;
    store.set({ selectedThread: target });
    renderThreadTabs();
    await loadHistory(currentJob, currentThreadKey());
  }

  async function createSubthread(briefing) {
    if (!currentJob || abortController) return;
    const title = briefing.trim().slice(0, 200);
    try {
      const thread = await api.createThread(currentJob, {
        title,
        parentThreadId: isMainThread(selectedThread) ? MAIN_THREAD_ID : selectedThread,
      });
      await refreshThreads(currentJob);
      selectedThread = thread.thread_id;
      store.set({ selectedThread: thread.thread_id });
      renderThreadTabs();
      await loadHistory(currentJob, thread.thread_id);
      if (onSeedComposer) onSeedComposer(briefing);
    } catch (err) {
      showThreadBanner(err, "Could not create the sub-investigation.");
    }
  }

  async function returnConclusion() {
    if (!currentJob || abortController) return;
    if (isMainThread(selectedThread)) return;
    const sub = selectedThread;
    const returnLabel = threadReturnBtn ? threadReturnBtn.textContent : "";
    if (threadReturnBtn) {
      threadReturnBtn.disabled = true;
      threadReturnBtn.textContent = "Summarizing…";
      threadReturnBtn.setAttribute("aria-busy", "true");
    }
    try {
      const res = await api.returnThread(currentJob, sub);
      const parent = (res && res.parent_thread_id) || MAIN_THREAD_ID;
      await refreshThreads(currentJob);
      selectedThread = isMainThread(parent) ? MAIN_THREAD_ID : parent;
      store.set({ selectedThread });
      renderThreadTabs();
      await loadHistory(currentJob, currentThreadKey());
    } catch (err) {
      showThreadBanner(err, "Could not return the conclusion.");
    } finally {
      if (threadReturnBtn) {
        threadReturnBtn.disabled = false;
        threadReturnBtn.textContent = returnLabel;
        threadReturnBtn.removeAttribute("aria-busy");
      }
    }
  }

  async function renameCurrentThread(title) {
    if (!currentJob || abortController || isMainThread(selectedThread)) return;
    try {
      await api.renameThread(currentJob, selectedThread, title);
      await refreshThreads(currentJob);
      renderThreadTabs();
    } catch (err) {
      showThreadBanner(err, "Could not rename the sub-investigation.");
    }
  }

  function showThreadBanner(err, fallback) {
    const banner = el("div", {
      class: "banner",
      text: err instanceof ApiError ? `${fallback} ${err.message}` : fallback,
    });
    logEl.append(banner);
  }

  function openThreadDialog(mode = "create") {
    if (abortController || !threadDialog) return;
    dialogMode = mode;
    const current = threads.find((t) => t.threadId === selectedThread);
    if (threadDialogTitle) {
      threadDialogTitle.textContent =
        mode === "rename" ? "Rename sub-investigation" : "New sub-investigation";
    }
    if (threadDialogHint) {
      threadDialogHint.textContent =
        mode === "rename"
          ? "Choose a short title for this focused investigation."
          : "Start a focused, blank sub-thread over the same job with the same read-only tools. Give it a one-line briefing.";
    }
    if (threadDialogSubmit) {
      threadDialogSubmit.textContent = mode === "rename" ? "Save title" : "Create & switch";
    }
    if (threadBriefing) {
      threadBriefing.value = mode === "rename" && current ? current.title : "";
    }
    if (typeof threadDialog.showModal === "function") threadDialog.showModal();
    else threadDialog.setAttribute("open", "");
    if (threadBriefing) {
      threadBriefing.focus();
      if (mode === "rename" && typeof threadBriefing.select === "function") {
        threadBriefing.select();
      }
    }
  }
  function closeThreadDialog() {
    if (!threadDialog) return;
    if (typeof threadDialog.close === "function") threadDialog.close();
    else threadDialog.removeAttribute("open");
  }

  if (threadNewBtn)
    threadNewBtn.addEventListener("click", () => openThreadDialog("create"));
  if (threadRenameBtn)
    threadRenameBtn.addEventListener("click", () => openThreadDialog("rename"));
  if (threadReturnBtn) threadReturnBtn.addEventListener("click", () => returnConclusion());
  if (threadDialogCancel)
    threadDialogCancel.addEventListener("click", () => closeThreadDialog());
  if (threadDialogForm)
    threadDialogForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const text = (threadBriefing && threadBriefing.value ? threadBriefing.value : "").trim();
      if (!text) return;
      closeThreadDialog();
      if (dialogMode === "rename") renameCurrentThread(text);
      else createSubthread(text);
    });

  return {
    send,
    cancel,
    loadHistory,
    loadThreads,
    switchThread,
    onStreamingChange,
    replayHistory,
    renderTimeline,
    renderSubresultCard,
  };
}
