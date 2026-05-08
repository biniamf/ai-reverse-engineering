# Список возможностей

[English](FEATURES.md) | [Русский](FEATURES.ru.md)

## Уже есть

### Анализ и чат

- Flask web UI для uploads, выбора job, чата и recovered artifacts.
- Интеграция с headless Ghidra REST.
- Загрузка нативных бинарников и отслеживание analysis jobs.
- Streaming AI responses через server-sent events.
- Отображение tool-call activity во время работы ассистента.
- История чата отдельно для каждой job.
- Вопросы по imports, strings, functions, xrefs, pseudocode и artifact search.
- Разрешение запросов к функциям по имени или адресу.
- Сохранен исходный OpenAI-compatible workflow.

### Model providers

- Local Ollama mode для приватного/offline reverse engineering.
- Hosted OpenAI mode.
- Custom OpenAI-compatible endpoint mode.
- Общая LLM configuration для chat и recovery passes.
- Runtime sidebar показывает provider, model, LLM endpoint и Ghidra endpoint.
- Web `Settings` panel для изменения AI provider и translator configuration в
  runtime.

### Recovery artifacts

- Deterministic recovery index из Ghidra artifacts.
- `recovery_manifest.json` с описанием generated files и счетчиками.
- `recovered_symbols.h` для conservative symbols и layout candidates.
- `recovered_stubs.cpp` для recovered storage/global stubs.
- `recovered_functions.cpp` для selected Ghidra pseudocode drafts.
- Optional `recovered_types.h` через AI type/class recovery.
- Optional `recovered_renames.json` через AI rename recovery.
- Non-destructive `.renamed.*` variants, если есть безопасная rename map.
- Dynamic module и function pointer hints.
- Helper-name inference.
- Извлечение MSVC decorated owner/class candidates.
- Structure layout candidates из pointer/offset patterns.
- Class layout candidates из constructor/vtable patterns.
- VC++ 2003-oriented prompts для legacy Windows code.

### Analysis UX

- Отдельная вкладка `Analysis`.
- Syntax-highlighted editor для C/C++, headers, JSON, Markdown и text.
- Recovery progress cards для Ghidra, artifacts, recovery и AI passes.
- Symbol Map со старым именем, recovered name, address, signature и status.
- Фильтры Symbol Map: `All`, `Draft`, `Renamed`, `Raw`, `Missing`.
- Click-to-jump из Symbol Map в generated source editor.
- Кликабельные function names и крупные hex-addresses прямо в source editor.
- Function inspector с signature, source file, callers, inferred calls и related strings.
- Inspector-to-chat кнопки для explanation, rename review и VC++ 2003 reconstruction prompts.
- Подсветка целевой строки в gutter редактора.
- Сворачиваемый analysis navigator.
- Editor `Wrap` mode для длинных decompiler lines.
- Editor `Focus` mode для больших файлов, выход по `Esc`.
- Компактная статистика файла: language, lines и file size.
- Custom dark scrollbars и аккуратные loading states.
- Branded favicon и icon в sidebar.
- Drag-and-drop upload zone с preview выбранного файла.

### Переводчик

- Optional LibreTranslate support.
- Optional custom JSON network translator support.
- Кнопка перевода на каждом сообщении чата.
- Автовыбор направления: русский на английский, остальное на русский.
- Markdown/code-aware protection перед переводом для code blocks, inline code,
  symbols и hex addresses.

### Local storage и cleanup

- Локальные runtime directories для Ghidra data, chats, recovery indexes и
  recovered files.
- Локальное удаление job и cleanup.
- Deleted-job tracking, чтобы скрывать локально удаленные jobs.
- `.gitignore` исключает generated data, logs, virtual environments и caches.
- Dockerfile для Flask app.
- Docker Compose stack для Flask, Ghidra REST и offline LibreTranslate image.
- Runtime log directory с игнорируемыми rotating Flask/Werkzeug logs.

## Пока не реализовано

- Health dashboard для Ghidra, LLM и translator connectivity.
- Markdown/PDF export recovery reports.
- Compile-ready generated source.
- APK analysis pipeline с jadx/apktool.
- Multi-user auth, queues, quotas, billing и production deployment topology.
