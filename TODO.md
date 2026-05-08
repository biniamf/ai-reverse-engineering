# Roadmap And Product Notes

[English](TODO.md) | [Русский](TODO.ru.md)

This file separates the working local tool from future product ideas. The
current codebase is already useful as a local-first native binary analyzer with
AI-assisted Ghidra chat, recovery drafts, symbol navigation, and optional
translation. Larger product tracks should be merged separately.

## Near-Term Engineering

- Add `.env` loading with `python-dotenv` or a small config bootstrap.
- Add optional Ollama service/profile to Docker Compose for fully containerized
  local model runs.
- Add a health page for Ghidra, LLM provider, and translator connectivity.
- Add tests for `llm_config.py`, `translator_config.py`, runtime settings,
  job-id validation, and recovery helpers.
- Add a mocked Ghidra artifact fixture for repeatable UI and recovery tests.
- Add export buttons for Markdown recovery reports.
- Add "copy current function context" and "copy selected source" buttons.
- Turn the new per-function inspector into a full call graph/xref graph view.
- Add frontend module split by feature once `app.js` grows further:
  `jobs.js`, `chat.js`, `recovery.js`, `translation.js`, `upload.js`.
- Add keyboard shortcuts for Analysis: focus editor, toggle wrap, next symbol,
  previous symbol.

## Native Binary Pipeline

- Keep Ghidra as the core analysis backend.
- Make supported formats explicit: PE first, then verified ELF/Mach-O support.
- Extract and display binary metadata: architecture, compiler hints, imports,
  sections, image base, entry point, and suspicious strings.
- Improve function selection for recovery drafts beyond the current top selected
  functions.
- Add per-function report generation.
- Add confidence scoring for recovered names, structures, classes, and type
  candidates.
- Add manual rename override UI that writes a local user rename map.
- Add diff view between raw and renamed recovered files.
- Add persistent per-function notes linked to address, original name, and
  recovered name.

## APK Pipeline Idea

APK should not be treated as just another native binary. A real APK mode needs:

- APK unpacking.
- `AndroidManifest.xml` extraction.
- Permission, activity, service, receiver, and provider analysis.
- DEX analysis.
- jadx for Java/Kotlin decompilation.
- apktool for resources and smali.
- Ghidra only for native `.so` files inside the APK.
- URL, API key, tracker, crypto, root-check, anti-debug, and obfuscation scans.
- A report connecting Java/Kotlin calls with native JNI behavior.
- Separate job type: `native_binary` or `android_apk`.

## SaaS/Product Work

- User accounts and ownership boundaries.
- Per-user job isolation.
- Queue/worker architecture.
- PostgreSQL for users, jobs, quotas, reports, and billing state.
- Redis/RQ/Celery for analysis jobs.
- Object storage or volumes for uploads and artifacts.
- Billing integration only after real demand is validated.
- Trial quotas such as analysis count, AI messages, and file size.
- Admin tools, audit logs, cleanup jobs, and retention policy.

## Security Requirements

- Never execute uploaded binaries.
- Analyze untrusted files only inside sandboxed or containerized workers.
- Keep path traversal checks everywhere a job id or filename is accepted.
- Add CPU/RAM/time limits for analysis workers.
- Add upload size limits.
- Add optional YARA/AV pre-scan.
- Keep per-user directories isolated if multi-user mode is added.
- Add automatic artifact cleanup and audit logs.

## Notes For The Original Maintainer

- Keep the old OpenAI-compatible workflow as a supported mode, not as the only
  mode.
- Keep Ollama as the default for privacy-sensitive reverse engineering.
- Treat recovery output as draft evidence, not compile-ready generated code.
- Merge provider configuration first; it is low-risk and makes the project more
  flexible.
- Merge recovery features as an optional `Analysis` tab so the basic chat flow
  remains familiar.
- Avoid merging SaaS, billing, auth, and APK analysis in the same PR. Those are
  separate product tracks.
