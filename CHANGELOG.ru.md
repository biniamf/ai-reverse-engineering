# Журнал изменений

[English](CHANGELOG.md) | [Русский](CHANGELOG.ru.md)

## 2026-05-04 - Локальная recovery workbench-версия

Эта версия превращает архивный `ai-reverse-engineering-main` из небольшого
демо-чата в локальный рабочий инструмент для reverse engineering. Старый проект
был компактным Flask UI: загрузка бинарника, headless Ghidra REST, чат и
OpenAI-compatible tool calls. Этот поток сохранен, но текущий проект добавляет
локальные модели, generated recovery files, Symbol Map, переводчик и намного
более удобный Analysis UX.

### Сохранено из `ai-reverse-engineering-main`

- Flask-сервер с upload, jobs, status, chat и chat-history routes.
- Headless Ghidra REST service на `http://localhost:9090`.
- OpenAI-compatible chat completions workflow.
- Ghidra tool calls для списка функций, декомпиляции, xrefs, imports, strings и
  поиска по artifact-данным.
- Browser chat с Markdown, Mermaid и подсветкой кода.
- Demo assets и базовый сценарий: загрузить бинарник, дождаться анализа,
  задавать вопросы.

### Основные добавления

- Local-first режим LLM через Ollama.
- Сохраненный hosted/global режим через `LLM_PROVIDER=openai`.
- Режим любого OpenAI-compatible gateway через `LLM_PROVIDER=custom`.
- Общая модельная конфигурация в `webui/llm_config.py` для чата, type recovery и
  rename recovery.
- Web `Settings` panel для переключения AI provider, model, endpoint,
  translator и custom translator field mapping в runtime.
- Sidebar показывает provider, model, LLM endpoint, Ghidra endpoint и статус
  переводчика.
- Route `/config` для runtime-конфига фронтенда.
- Более строгая проверка job id и filename в chat, status, recovery и file
  routes.
- Локальное удаление job с очисткой `data/`, истории чата, recovery indexes и
  generated recovered files.
- Учет удаленных job, чтобы локально удаленные анализы не появлялись обратно из
  Ghidra service.

### Recovery pipeline

- Добавлен `webui/recovery_engine.py` как deterministic recovery orchestrator.
- Добавлены отдельные recovery modules для функций, структур, классов, model
  output и renaming.
- Генерируется `recovery_manifest.json` с описанием файлов, validity labels,
  счетчиками и machine-readable metadata.
- Генерируются `recovered_symbols.h`, `recovered_stubs.cpp`,
  `recovered_functions.cpp` и опциональные `.renamed.*` варианты.
- Извлекаются dynamic module hints, `GetProcAddress`-style pointers, helper
  names, MSVC decorated symbol owners, pointer/offset structure candidates и
  class layout candidates.
- Selected Ghidra pseudocode сохраняется в draft C/C++ files для просмотра.
- Добавлен optional AI type/class pass через `AI Types`.
- Добавлен optional AI rename-map pass через `AI Rename`.
- Rename output консервативный, валидируемый и non-destructive: renamed files
  пишутся отдельными вариантами.
- Добавлен fallback rename inference, если модель вернула слишком мало
  безопасных имен.

### Analysis UX

- Добавлена отдельная вкладка `Analysis` рядом с `Chat`.
- Добавлен editor с подсветкой C/C++/JSON/Markdown для recovered files.
- Добавлены progress cards для Ghidra, artifacts, recovery и AI passes.
- Добавлен Symbol Map: старое имя, recovered name, address, signature, filters и
  click-to-jump navigation.
- Symbol Map поддерживает фильтры `All`, `Draft`, `Renamed`, `Raw`, `Missing`.
- Клик по символу открывает лучший generated source file и ищет по адресу,
  старому имени, recovered name и metadata comments.
- Известные имена функций и крупные hex-адреса внутри source editor стали
  кликабельными без поломки syntax highlighting.
- Добавлен function inspector на локальных Ghidra artifacts: address,
  signature, source file, callers, inferred callees, related strings и статус
  draft/rename.
- Inspector умеет передавать сфокусированный prompt в AI chat для explanation,
  rename review или VC++ 2003 reconstruction.
- Строка найденной функции подсвечивается в gutter редактора.
- Analysis navigation можно свернуть, чтобы отдать больше ширины редактору.
- Добавлен `Wrap` mode для длинных decompiler lines.
- Добавлен `Focus` mode редактора с выходом через `Esc`.
- Сырые character counts заменены на компактные бейджи lines и file size.
- Добавлены custom scrollbars, loading skeletons, красивый upload drop-zone и
  branded empty state.
- Старый монолитный frontend разделен на `webui/static/css/app.css` и
  `webui/static/js/app.js`.

### Переводчик

- Добавлен `webui/translator_config.py`.
- Добавлена optional LibreTranslate integration.
- Добавлена optional custom JSON network translator integration для proxy DeepL,
  Google, Argos или другого сервиса.
- Добавлен route `/translate`.
- В chat у каждого сообщения появляется кнопка `Translate`.
- Русский текст переводится на English, остальной текст - на Russian.
- Перед переводом по возможности сохраняются code blocks, inline code, symbol
  names и hex addresses.

### Branding и документация

- Добавлен `media/icon.ico`.
- Добавлены favicon route и видимая brand icon в sidebar.
- Переписаны `README.md` и `README.ru.md` с инструкциями запуска для Windows и
  Linux/macOS.
- В оба README добавлена настройка переводчика.
- Добавлены `FEATURES.md`, `FEATURES.ru.md`, `TODO.md`, `TODO.ru.md`.
- Добавлен `webui/static/README.md` с правилами модульного frontend layout.
- Добавлен расширенный `.env.example`.
- Заполнен `.gitignore` для virtualenvs, logs, generated Ghidra data, chats и
  recovered artifacts.
- Добавлены `Dockerfile`, `.dockerignore` и `docker-compose.yml` для локального
  stack с Flask, Ghidra REST и `dvurechensky/libretranslate-offline-ru-en-zh`.
- Добавлены настраиваемые host-side ports для compose: `WEBUI_PORT`,
  `GHIDRA_PORT` и `LIBRETRANSLATE_PORT`.
- Добавлен persistent `webui/settings/runtime_settings.json` для runtime
  settings, измененных через Web UI.
- Добавлен `logs/` с `.gitkeep`, игнорируемыми runtime log files и rotating
  Flask/Werkzeug file logging.

### Исправления

- Переписаны UTF-8 `.ru.md` файлы, чтобы убрать mojibake.
- Исправлена проблема Werkzeug/header encoding: не-ASCII user-facing errors не
  попадают в response headers.
- Улучшена загрузка local jobs, когда Ghidra offline.
- Улучшен delete UX, когда local files удалены, а upstream Ghidra delete
  недоступен.
- Исправлены overflow и formatting больших сообщений в чате.
- Исправлена Symbol Map navigation для renamed функций и переходов по адресу.
- Добавлен static cache-busting для CSS и JS во время разработки.
- Проверен compose stack: web UI, Ghidra `/jobs`, LibreTranslate `/languages` и
  Flask `/translate` успешно ответили.

### Известные ограничения

- Ghidra REST остается внешним сервисом и запускается отдельно.
- Recovery output - это evidence и draft material, а не гарантированно
  compile-ready source.
- UI пока не редактирует provider settings в runtime; настройка идет через
  environment variables.
- APK analysis пока roadmap item, а не рабочий pipeline.
- Production deployment, auth, queues, quotas и multi-user isolation не входят в
  эту local workbench-версию.
