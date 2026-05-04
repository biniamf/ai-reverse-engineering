<p align="center">
  <img src="media/icon.ico" width="96" height="96" alt="AIReverse icon">
</p>

<h1 align="center">Local AI-Assisted Reverse Engineering with Ghidra</h1>

<p align="center">
  Local-first Ghidra analysis, AI chat, recovery drafts, symbol maps, and optional translation.
</p>

[English](README.md) | [Русский](README.ru.md)

![alt text](demo/demo3.gif)

Local-first web assistant for reverse engineering native binaries with Ghidra
and an OpenAI-compatible language model. The default setup uses Ollama so the
binary, decompiler output, prompts, and chat history can stay on your machine.
The original remote/global LLM workflow is still supported: choose Ollama,
OpenAI, or any OpenAI-compatible endpoint through environment variables.

This repository intentionally keeps the old `ai-reverse-engineering-main`
workflow alive while extending it. The archived project was a small Flask chat
demo around Ghidra. The current version is a local recovery workbench with
generated C/C++ drafts, Symbol Map navigation, AI type and rename passes,
translation, and a modern analysis UI.

## What It Does

- Uploads a native binary and starts headless Ghidra analysis.
- Lets you chat with an AI assistant that can call Ghidra tools.
- Lists functions, imports, strings, xrefs, and decompiled pseudocode.
- Streams assistant responses and tool progress into the browser.
- Saves per-job chat history locally.
- Shows previous analysis jobs and lets you delete local job artifacts.
- Generates deterministic recovery drafts: symbols, globals, function pointer
  candidates, class/structure layout hints, and wrapped decompiler output.
- Runs optional AI passes for type/class proposals and conservative rename maps.
- Targets legacy x86 and Microsoft Visual C++ 2003 style output by default.
- Provides a Symbol Map with address/name navigation into generated source.
- Turns known function names and large hex addresses in the editor into
  clickable analysis links.
- Opens a per-function inspector with signature, callers, inferred calls,
  related strings, and quick AI prompt handoff.
- Provides a C/C++ editor with syntax highlighting, line jump, wrap mode,
  collapsible navigator, and focus mode for large recovered files.
- Optionally translates chat messages through LibreTranslate or a custom JSON
  network translator.

See the full feature list in [FEATURES.md](FEATURES.md) and the old-to-new
comparison in [CHANGELOG.md](CHANGELOG.md).

## Architecture

The current project is a Flask web UI around two services:

- `webui/app.py` exposes browser routes for uploads, chat, jobs, and recovery
  artifacts.
- `webui/ghidra_assistant.py` runs the chat/tool loop against Ghidra and the
  selected LLM provider.
- `webui/llm_config.py` resolves Ollama, OpenAI, or custom compatible model
  settings.
- `webui/recovery_*.py` modules build deterministic and model-assisted recovery
  drafts.
- A separate headless Ghidra REST service performs binary analysis.

Generated runtime artifacts are written under `data/`, `webui/chats/`,
`webui/recovery/`, and `webui/recovered/`.

## Old Project vs Current Project

| Area               | `ai-reverse-engineering-main` | Current directory                                                 |
| ------------------ | ----------------------------- | ----------------------------------------------------------------- |
| LLM mode           | One OpenAI-compatible setup   | Ollama, OpenAI, or custom endpoint                                |
| Privacy            | Usually remote/global model   | Local-first by default                                            |
| UI                 | Monolithic template           | HTML shell plus modular CSS/JS                                    |
| Chat               | Ghidra tool loop              | Preserved and extended                                            |
| Recovery files     | Not present                   | Manifest, headers, stubs, function drafts, renamed variants       |
| Symbol navigation  | Not present                   | Address/name Symbol Map with filters and jump-to-code             |
| Function inspector | Not present                   | Clickable code symbols, xrefs, related strings, AI prompt handoff |
| Translation        | Not present                   | LibreTranslate or custom network translator                       |
| Job cleanup        | Minimal                       | Local cleanup and hidden deleted jobs                             |
| Documentation      | Single README                 | English/Russian README, changelog, features, roadmap              |

## Requirements

- Python 3.10+.
- Docker for the headless Ghidra REST container.
- One OpenAI-compatible model provider:
  - Ollama for local models.
  - OpenAI for hosted models.
  - Any compatible gateway using `API_BASE`, `API_KEY`, and `MODEL_NAME`.

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Docker Compose Start

Use this when you want one command to start the web UI, the Ghidra REST service,
and your offline LibreTranslate image.

The compose stack contains:

- `aireverse`: this Flask project, published at `http://localhost:5000`.
- `ghidra`: `biniamfd/ghidra-headless-rest:latest`, published at
  `http://localhost:9090`.
- `libretranslate`: `dvurechensky/libretranslate-offline-ru-en-zh:latest`,
  published at `http://localhost:5001` for direct testing and used internally at
  `http://libretranslate:5000`.

The web container uses these internal URLs:

```text
GHIDRA_API_BASE=http://ghidra:9090
LIBRETRANSLATE_API_BASE=http://libretranslate:5000
```

By default, the app still expects Ollama to run on the host machine:

```text
OLLAMA_API_BASE=http://host.docker.internal:11434/v1
OLLAMA_MODEL=qwen2.5-coder:14b
```

Start the stack:

```bash
docker compose up --build
```

Open:

- Web UI: `http://localhost:5000`
- Ghidra REST: `http://localhost:9090`
- LibreTranslate direct UI/API: `http://localhost:5001`

If one of those ports is already busy, override only the host-side port. The
internal compose URLs stay the same:

```env
WEBUI_PORT=5050
GHIDRA_PORT=9091
LIBRETRANSLATE_PORT=5002
```

To override provider settings, create a local `.env` next to
`docker-compose.yml`:

```env
LLM_PROVIDER=ollama
OLLAMA_API_BASE=http://host.docker.internal:11434/v1
OLLAMA_MODEL=qwen2.5-coder:14b

# Or use OpenAI/custom:
# LLM_PROVIDER=openai
# OPENAI_API_KEY=sk-...
# OPENAI_MODEL=your-model-name
```

Stop the stack:

```bash
docker compose down
```

## Web Runtime Settings

The sidebar has a `Settings` button in the `Local runtime` card. It can change
runtime providers without editing shell variables or `docker-compose.yml`.

Settings are saved to `webui/settings/runtime_settings.json`. In Docker Compose
that directory is mounted as a volume, so settings survive container rebuilds.
Environment variables still provide defaults; saved web settings take priority.

AI provider options:

- `Ollama`: local OpenAI-compatible endpoint, usually
  `http://host.docker.internal:11434/v1` in Docker or
  `http://localhost:11434/v1` outside Docker.
- `OpenAI`: hosted OpenAI-compatible endpoint.
- `Custom OpenAI-compatible`: any gateway with `/v1/chat/completions` behavior.

Translator options:

- `Off`: hide translation controls.
- `LibreTranslate`: expects `q`, `source`, `target`, and `translatedText`.
- `Custom JSON API`: lets you map request fields and the response field path.
  This is the right place to connect a Google/DeepL/Argos proxy. For example,
  a gateway can accept `q/source/target` and return `translations.0.text`; set
  `Result field` to `translations.0.text`.

Blank API key fields keep the currently saved secret.

## Runtime Logs

Flask and Werkzeug runtime logs are written under `logs/`:

- `logs/flask.log` for application logs.
- `logs/werkzeug.log` for development server/access logs.

The directory is kept in the repository through `logs/.gitkeep`, but real
`*.log` files are ignored. Do not publish logs by default: they can contain file
names, local endpoints, prompts, stack traces, or other environment details.

In Docker Compose, `./logs` is mounted to `/app/logs`. Log rotation is controlled
by:

```env
AIREVERSE_LOG_DIR=logs
AIREVERSE_LOG_MAX_BYTES=1048576
AIREVERSE_LOG_BACKUPS=3
```

## Windows Start

### 1. Start Ghidra REST

Run Ghidra REST from PowerShell in the repository root. The command below uses
the current directory, so it works no matter where the project is cloned.

```powershell
$ProjectDir = (Get-Location).Path
docker run --rm -p 9090:9090 -v "${ProjectDir}\data:/data/ghidra_projects" biniamfd/ghidra-headless-rest:latest
```

### 2. Choose the LLM provider

In a second PowerShell window, choose one provider block.

Local Ollama:

```powershell
$env:LLM_PROVIDER = "ollama"
$env:OLLAMA_API_BASE = "http://localhost:11434/v1"
$env:OLLAMA_API_KEY = "ollama"
$env:OLLAMA_MODEL = "qwen2.5-coder:14b"
$env:GHIDRA_API_BASE = "http://localhost:9090"
```

Hosted OpenAI:

```powershell
$env:LLM_PROVIDER = "openai"
$env:OPENAI_API_KEY = "sk-..."
$env:OPENAI_MODEL = "your-model-name"
$env:GHIDRA_API_BASE = "http://localhost:9090"
```

Custom OpenAI-compatible endpoint:

```powershell
$env:LLM_PROVIDER = "custom"
$env:API_BASE = "https://your-compatible-endpoint/v1"
$env:API_KEY = "your-key"
$env:MODEL_NAME = "your-model-name"
$env:GHIDRA_API_BASE = "http://localhost:9090"
```

### 3. Optional: enable chat translation

Translation is disabled by default because Flask also uses `http://localhost:5000`.
If you run LibreTranslate on your LAN, add these variables in the same PowerShell
window before starting Flask:

```powershell
$env:TRANSLATOR_PROVIDER = "libretranslate"
$env:LIBRETRANSLATE_API_BASE = "http://192.168.0.179:5000"
$env:LIBRETRANSLATE_API_KEY = ""
```

For another network translator, run it behind a small JSON HTTP endpoint and use
the `custom` provider. The defaults expect a request like
`{"q":"text","source":"auto","target":"ru"}` and a response field named
`translatedText`. Nested response paths such as `translations.0.text` are also
supported through `TRANSLATOR_RESULT_FIELD`.

```powershell
$env:TRANSLATOR_PROVIDER = "custom"
$env:TRANSLATOR_API_BASE = "http://translator-gateway.local:8080"
$env:TRANSLATOR_ENDPOINT = "/translate"
$env:TRANSLATOR_TEXT_FIELD = "q"
$env:TRANSLATOR_SOURCE_FIELD = "source"
$env:TRANSLATOR_TARGET_FIELD = "target"
$env:TRANSLATOR_RESULT_FIELD = "translatedText"
# Optional auth:
# $env:TRANSLATOR_AUTH_HEADER = "Authorization"
# $env:TRANSLATOR_AUTH_TOKEN = "Bearer your-token"
```

Skip this step, or set `$env:TRANSLATOR_PROVIDER = "off"`, to hide translation controls.
When enabled, every chat message gets a `Translate` button. Russian text targets English; other text targets Russian.

### 4. Start Flask

```powershell
python webui/app.py
```

Open `http://localhost:5000`.

## Linux/macOS Start

### 1. Start Ghidra REST

Run Ghidra REST from the repository root:

```bash
docker run --rm -p 9090:9090 -v "$(pwd)/data:/data/ghidra_projects" biniamfd/ghidra-headless-rest:latest
```

### 2. Choose the LLM provider

In a second terminal, choose one provider block.

Local Ollama:

```bash
export LLM_PROVIDER=ollama
export OLLAMA_API_BASE=http://localhost:11434/v1
export OLLAMA_API_KEY=ollama
export OLLAMA_MODEL=qwen2.5-coder:14b
export GHIDRA_API_BASE=http://localhost:9090
```

Hosted OpenAI:

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=your-model-name
export GHIDRA_API_BASE=http://localhost:9090
```

Custom OpenAI-compatible endpoint:

```bash
export LLM_PROVIDER=custom
export API_BASE=https://your-compatible-endpoint/v1
export API_KEY=your-key
export MODEL_NAME=your-model-name
export GHIDRA_API_BASE=http://localhost:9090
```

### 3. Optional: enable chat translation

Translation is disabled by default because Flask also uses `http://localhost:5000`.
If you run LibreTranslate on your LAN, add these variables in the same terminal
before starting Flask:

```bash
export TRANSLATOR_PROVIDER=libretranslate
export LIBRETRANSLATE_API_BASE=http://192.168.0.179:5000
export LIBRETRANSLATE_API_KEY=
```

For another network translator, run it behind a small JSON HTTP endpoint and use
the `custom` provider. The defaults expect a request like
`{"q":"text","source":"auto","target":"ru"}` and a response field named
`translatedText`. Nested response paths such as `translations.0.text` are also
supported through `TRANSLATOR_RESULT_FIELD`.

```bash
export TRANSLATOR_PROVIDER=custom
export TRANSLATOR_API_BASE=http://translator-gateway.local:8080
export TRANSLATOR_ENDPOINT=/translate
export TRANSLATOR_TEXT_FIELD=q
export TRANSLATOR_SOURCE_FIELD=source
export TRANSLATOR_TARGET_FIELD=target
export TRANSLATOR_RESULT_FIELD=translatedText
# Optional auth:
# export TRANSLATOR_AUTH_HEADER=Authorization
# export TRANSLATOR_AUTH_TOKEN="Bearer your-token"
```

Skip this step, or set `export TRANSLATOR_PROVIDER=off`, to hide translation controls.
When enabled, every chat message gets a `Translate` button. Russian text targets English; other text targets Russian.

### 4. Start Flask

```bash
python webui/app.py
```

Open `http://localhost:5000`.

The sidebar shows the active provider, model, LLM endpoint, Ghidra endpoint, and translator status.

## Workflow

1. Start the Ghidra REST container.
2. Start Ollama, OpenAI, or a compatible endpoint.
3. Run `python webui/app.py`.
4. Upload a binary in the left panel.
5. Wait until the job status becomes `DONE`.
6. Ask targeted questions, for example:

```text
List imports and strings. What runtime/library does this binary look like?
Find the likely main entry and decompile it.
Build a call graph around the function at 0x00401234.
Rename this function based on behavior and reconstruct C-like code.
Search for file, registry, network, serial, or license-check related strings.
```

For legacy Windows reconstruction:

```text
Reconstruct function DACOM_Acquire as clean VC++ 2003-compatible code.
```

## Recovery Panel

After selecting a job, open the `Analysis` tab to inspect generated recovery
artifacts:

- `recovery_manifest.json` explains generated files and counters.
- `recovered_symbols.h` contains conservative symbols and layout candidates.
- `recovered_stubs.cpp` contains storage for recovered globals.
- `recovered_functions.cpp` wraps selected Ghidra pseudocode in `#if 0`.
- `recovered_types.h` is generated by the optional AI type pass.
- `recovered_renames.json` contains validated AI rename proposals.
- `.renamed.*` variants appear only when a safe rename map exists.

The generated code is draft material. Treat it as analysis evidence, not as
drop-in production source.

### Analysis UX Tips

- Use `Symbol Map` to move by function address or recovered name.
- Use `Renamed` to inspect functions that received AI or fallback names.
- Use `Draft` to show functions emitted into `recovered_functions*.cpp`.
- Press `Hide` in the navigator to give the editor more horizontal room.
- Use `Wrap` for long decompiler expressions.
- Use `Focus` for large files; press `Esc` to return.
- Click a function in Symbol Map, a highlighted function name, or a large hex
  address in the editor to open the function inspector.
- Use the inspector buttons to prepare targeted AI chat prompts for explanation,
  rename review, or VC++ 2003 reconstruction.

## Headless Ghidra Tool Endpoints

The assistant calls these Ghidra tool endpoints through
`GHIDRA_API_BASE=http://localhost:9090`.

| Endpoint                    | Method | Description                                   |
| --------------------------- | ------ | --------------------------------------------- |
| `/tools/status`             | POST   | Get status for an existing analysis job.      |
| `/tools/list_functions`     | POST   | Retrieve discovered functions for a job.      |
| `/tools/decompile_function` | POST   | Get pseudocode for a function address.        |
| `/tools/get_xrefs`          | POST   | Get callers and callees for a function.       |
| `/tools/list_imports`       | POST   | List imported libraries and symbols.          |
| `/tools/list_strings`       | POST   | Return printable strings.                     |
| `/tools/query_artifacts`    | POST   | Search functions and artifacts by text/regex. |

Upload and job management routes are handled by the Flask app and the Ghidra
REST service.

## Notes

- This project is meant for authorized research and maintenance of binaries you
  are allowed to inspect.
- Do not run untrusted binaries directly. Ghidra analysis should remain
  isolated in containers or controlled worker environments.
- Large decompiled functions can exceed model context. Ask for one function or
  subsystem at a time.
