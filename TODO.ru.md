# Roadmap и продуктовые заметки

[English](TODO.md) | [Русский](TODO.ru.md)

Этот файл отделяет рабочий локальный инструмент от будущих продуктовых идей.
Текущий codebase уже полезен как local-first analyzer нативных бинарников с
AI-assisted Ghidra chat, recovery drafts, Symbol Map и опциональным переводом.
Крупные продуктовые направления лучше мержить отдельно.

## Ближайшая инженерия

- Добавить загрузку `.env` через `python-dotenv` или маленький config bootstrap.
- Добавить optional Ollama service/profile в Docker Compose для полностью
  containerized local model runs.
- Добавить health page для Ghidra, LLM provider и translator connectivity.
- Добавить tests для `llm_config.py`, `translator_config.py`, runtime settings,
  job-id validation и recovery helpers.
- Добавить mocked Ghidra artifact fixture для повторяемых UI/recovery tests.
- Добавить export buttons для Markdown recovery reports.
- Добавить кнопки "copy current function context" и "copy selected source".
- Развить новый function inspector в полноценный call graph/xref graph view.
- Когда `app.js` станет еще больше, разделить frontend по feature modules:
  `jobs.js`, `chat.js`, `recovery.js`, `translation.js`, `upload.js`.
- Добавить keyboard shortcuts для Analysis: focus editor, toggle wrap, next
  symbol, previous symbol.

## Native binary pipeline

- Оставить Ghidra основным analysis backend.
- Явно описать supported formats: сначала PE, затем проверенные ELF/Mach-O.
- Извлекать и показывать binary metadata: architecture, compiler hints,
  imports, sections, image base, entry point и suspicious strings.
- Улучшить выбор функций для recovery drafts за пределами текущих selected
  functions.
- Добавить per-function report generation.
- Добавить confidence scoring для recovered names, structures, classes и type
  candidates.
- Добавить manual rename override UI, который пишет локальную user rename map.
- Добавить diff view между raw и renamed recovered files.
- Добавить persistent per-function notes, привязанные к address, original name и
  recovered name.

## Идея APK pipeline

APK не стоит обрабатывать как просто еще один нативный бинарник. Для настоящего
APK mode нужны:

- APK unpacking.
- Извлечение `AndroidManifest.xml`.
- Анализ permissions, activities, services, receivers и providers.
- DEX analysis.
- jadx для Java/Kotlin decompilation.
- apktool для resources и smali.
- Ghidra только для native `.so` внутри APK.
- Поиск URL, API keys, trackers, crypto, root-check, anti-debug и obfuscation.
- Отчет, связывающий Java/Kotlin calls с native JNI behavior.
- Отдельный job type: `native_binary` или `android_apk`.

## SaaS/Product work

- Users и ownership boundaries.
- Per-user job isolation.
- Queue/worker architecture.
- PostgreSQL для users, jobs, quotas, reports и billing state.
- Redis/RQ/Celery для analysis jobs.
- Object storage или volumes для uploads и artifacts.
- Billing integration только после проверки реального спроса.
- Trial quotas: analysis count, AI messages и file size.
- Admin tools, audit logs, cleanup jobs и retention policy.

## Security requirements

- Никогда не выполнять uploaded binaries.
- Анализировать недоверенные файлы только в sandboxed/containerized workers.
- Оставить path traversal checks везде, где принимается job id или filename.
- Добавить CPU/RAM/time limits для analysis workers.
- Добавить upload size limits.
- Добавить optional YARA/AV pre-scan.
- Если появится multi-user mode, держать per-user directories изолированными.
- Добавить automatic artifact cleanup и audit logs.

## Заметки для автора исходного проекта

- Старый OpenAI-compatible workflow лучше оставить supported mode, а не
  единственным вариантом.
- Ollama стоит держать дефолтом для privacy-sensitive reverse engineering.
- Recovery output нужно считать draft evidence, а не compile-ready generated
  code.
- Provider configuration можно мержить первым: это low-risk и сразу делает
  проект гибче.
- Recovery features лучше мержить как optional вкладку `Analysis`, чтобы
  базовый chat flow остался знакомым.
- SaaS, billing, auth и APK analysis не стоит смешивать с этим PR. Это отдельные
  продуктовые треки.
