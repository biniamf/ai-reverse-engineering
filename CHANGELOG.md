# Changelog

[English](CHANGELOG.md) | [Русский](CHANGELOG.ru.md)

## 2026-05-04 - Local Recovery Workbench

This release turns the archived `ai-reverse-engineering-main` demo into a
local-first reverse-engineering workbench. The original project was a compact
Flask chat UI that uploaded binaries to a headless Ghidra REST service and let
an OpenAI-compatible model call Ghidra tools. That flow is still preserved, but
the current project adds local model configuration, generated recovery files,
symbol navigation, translation, and a much more usable analysis interface.

### Preserved From `ai-reverse-engineering-main`

- Flask web server with upload, job, status, chat, and chat-history routes.
- Headless Ghidra REST service on `http://localhost:9090`.
- OpenAI-compatible chat completions workflow.
- Ghidra tool calls for function listing, decompilation, xrefs, imports,
  strings, and artifact search.
- Browser chat with Markdown, Mermaid diagrams, and syntax-highlighted code.
- Demo assets and the basic "upload binary, wait for analysis, ask questions"
  workflow.

### Core Additions

- Local-first LLM mode through Ollama.
- Preserved hosted/global mode through `LLM_PROVIDER=openai`.
- Custom OpenAI-compatible gateway mode through `LLM_PROVIDER=custom`.
- Shared model configuration in `webui/llm_config.py` for chat, type recovery,
  and rename recovery.
- Web `Settings` panel for switching AI provider, model, endpoint, translator,
  and custom translator field mapping at runtime.
- Runtime sidebar showing provider, model, LLM endpoint, Ghidra endpoint, and
  translator status.
- `/config` route for frontend runtime configuration.
- Safer job-id and filename validation across chat, status, recovery, and file
  routes.
- Local job deletion with cleanup of `data/`, chat history, recovery indexes,
  and generated recovered files.
- Deleted-job tracking so locally removed jobs do not immediately reappear from
  the Ghidra service.

### Recovery Pipeline

- Added `webui/recovery_engine.py` as the deterministic recovery orchestrator.
- Added dedicated recovery modules for functions, structures, classes, model
  output, and renaming.
- Generates `recovery_manifest.json` with file descriptions, validity labels,
  counters, and machine-readable metadata.
- Generates `recovered_symbols.h`, `recovered_stubs.cpp`,
  `recovered_functions.cpp`, and optional `.renamed.*` variants.
- Extracts dynamic module hints, `GetProcAddress`-style pointers, helper names,
  MSVC decorated symbol owners, pointer/offset structure candidates, and class
  layout candidates.
- Wraps selected Ghidra pseudocode in draft C/C++ files for inspection.
- Adds optional AI type/class recovery through `AI Types`.
- Adds optional AI rename-map generation through `AI Rename`.
- Rename output is conservative, validated, and non-destructive: renamed files
  are written as separate variants.
- Added fallback rename inference when the model returns too few safe names.

### Analysis UX

- Added a dedicated `Analysis` tab next to `Chat`.
- Added syntax-highlighted C/C++/JSON/Markdown editor for recovered files.
- Added recovery progress cards for Ghidra, artifacts, recovery, and AI passes.
- Added a Symbol Map with old name, recovered name, address, signature, filters,
  and click-to-jump navigation.
- Symbol Map now supports `All`, `Draft`, `Renamed`, `Raw`, and `Missing`
  filters.
- Symbol clicks open the best generated source file and search by address,
  original name, recovered name, and metadata comments.
- Known function names and large hex addresses inside the source editor are now
  clickable without breaking syntax highlighting.
- Added a per-function inspector backed by local Ghidra artifacts. It shows the
  resolved address, signature, source file, callers, inferred callees, related
  strings, and draft/rename status.
- Inspector actions can hand off a focused prompt to the AI chat for function
  explanation, rename review, or VC++ 2003 reconstruction.
- Focused function lines are highlighted in the editor gutter.
- Added collapsible analysis navigation so the code editor can use more width.
- Added editor `Wrap` mode for long decompiler lines.
- Added editor `Focus` mode with `Esc` exit for large files.
- Replaced raw character counts with compact line and file-size badges.
- Added custom scrollbars, loading skeletons, upload drop-zone polish, and a
  branded empty-state screen.
- Split the old monolithic frontend into `webui/static/css/app.css` and
  `webui/static/js/app.js`.

### Translation

- Added `webui/translator_config.py`.
- Added optional LibreTranslate support.
- Added optional custom JSON network translator support for proxying DeepL,
  Google, Argos, or another service.
- Added `/translate` route.
- Added per-message `Translate` buttons in chat.
- Russian text targets English; other text targets Russian.
- Translation preserves code blocks, inline code, symbol names, and hex
  addresses as much as possible before sending text to the translator.

### Branding And Documentation

- Added `media/icon.ico`.
- Added favicon route and visible sidebar brand icon.
- Rebuilt `README.md` and `README.ru.md` with Windows and Linux/macOS startup
  instructions.
- Added translator setup to both README files.
- Added `FEATURES.md`, `FEATURES.ru.md`, `TODO.md`, and `TODO.ru.md`.
- Added `webui/static/README.md` to document the frontend module layout.
- Added a fuller `.env.example`.
- Filled `.gitignore` for virtualenvs, logs, generated Ghidra data, chats, and
  recovered artifacts.
- Added `Dockerfile`, `.dockerignore`, and `docker-compose.yml` for a local stack
  with Flask, Ghidra REST, and `dvurechensky/libretranslate-offline-ru-en-zh`.
- Added configurable compose host ports: `WEBUI_PORT`, `GHIDRA_PORT`, and
  `LIBRETRANSLATE_PORT`.
- Added persistent `webui/settings/runtime_settings.json` for web-edited runtime
  settings.
- Added `logs/` with `.gitkeep`, ignored runtime log files, and rotating
  Flask/Werkzeug file logging.

### Fixes

- Fixed mojibake-prone Russian docs by rewriting UTF-8 `.ru.md` files.
- Fixed Werkzeug header encoding issue by keeping user-facing non-ASCII errors
  out of response headers.
- Improved local job loading when Ghidra is offline.
- Improved delete UX when local files are removed but upstream Ghidra delete is
  unavailable.
- Fixed chat overflow and large-message formatting.
- Fixed Symbol Map navigation for renamed functions and address-based jumps.
- Added static cache-busting for CSS and JS during development.
- Verified the compose stack: web UI, Ghidra `/jobs`, LibreTranslate
  `/languages`, and Flask `/translate` responded successfully.

### Known Limits

- Ghidra REST is still an external service and must be started separately.
- Recovery output is evidence and draft material, not guaranteed compile-ready
  source.
- The UI does not yet edit provider settings at runtime; configuration is via
  environment variables.
- APK analysis is a roadmap item, not a working pipeline.
- Production deployment, auth, queues, quotas, and multi-user isolation are not
  included in this local workbench release.
