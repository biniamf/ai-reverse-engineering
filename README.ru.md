<p align="center">
  <img src="media/icon.ico" width="96" height="96" alt="AIReverse icon">
</p>

<h1 align="center">Локальный AI reverse engineering с Ghidra</h1>

<p align="center">
  Локальный анализ Ghidra, AI-чат, recovery drafts, карты символов и опциональный переводчик.
</p>
<p align="center">
  <img src="https://img.shields.io/docker/pulls/dvurechensky/aireverse?style=flat-square)](https://hub.docker.com/r/dvurechensky/aireverse" alt="downloads">
  <img src="https://img.shields.io/docker/image-size/dvurechensky/aireverse/latest?style=flat-square" alt="size">
</p>

[English](README.md) | [Русский](README.ru.md)

![alt text](demo/demo3.gif)

Локальный web-ассистент для reverse engineering нативных бинарников через
Ghidra и OpenAI-compatible языковую модель. По умолчанию используется Ollama:
бинарник, декомпиляторный вывод, промпты и история чата остаются на вашей
машине. Старый удаленный/глобальный способ тоже сохранен: можно выбрать Ollama,
OpenAI или любой совместимый endpoint через переменные окружения.

Репозиторий специально сохраняет старый workflow из `ai-reverse-engineering-main`
и расширяет его. Архивный проект был небольшим Flask chat demo вокруг Ghidra.
Текущая версия - local recovery workbench с generated C/C++ drafts, Symbol Map,
AI type/rename passes, переводчиком и современным Analysis UI.

## Что умеет проект

- Загружает нативный бинарник и запускает headless-анализ Ghidra.
- Дает чат с AI-ассистентом, который может вызывать инструменты Ghidra.
- Показывает функции, импорты, строки, xrefs и декомпилированный псевдокод.
- Стримит ответы ассистента и ход tool-call операций в браузер.
- Хранит историю чата отдельно для каждого job.
- Показывает прошлые анализы и умеет удалять локальные артефакты job.
- Генерирует recovery-драфты: символы, globals, function pointer candidates,
  class/structure layout hints и wrapped decompiler output.
- Запускает опциональные AI-проходы для типов/классов и безопасной rename-map.
- По умолчанию ориентирован на legacy x86 и стиль Microsoft Visual C++ 2003.
- Дает Symbol Map с навигацией по address/name в generated source.
- Превращает известные имена функций и крупные hex-адреса в editor в
  кликабельные analysis-ссылки.
- Открывает inspector функции с сигнатурой, callers, inferred calls,
  связанными строками и быстрыми AI prompt-кнопками.
- Дает C/C++ editor с подсветкой, line jump, wrap mode, collapsible navigator и
  focus mode для больших recovered files.
- Опционально переводит сообщения чата через LibreTranslate или custom JSON
  network translator.

Полный список возможностей: [FEATURES.ru.md](FEATURES.ru.md). Сравнение со
старой версией: [CHANGELOG.ru.md](CHANGELOG.ru.md).

## Запуск в Docker

```bash
docker pull dvurechensky/aireverse
docker run -p 5000:5000 dvurechensky/aireverse
```

## Архитектура

Текущий проект - это Flask web UI вокруг двух сервисов:

- `webui/app.py` отвечает за upload, chat, jobs и recovery routes.
- `webui/ghidra_assistant.py` ведет chat/tool loop между Ghidra и выбранной LLM.
- `webui/llm_config.py` выбирает настройки Ollama, OpenAI или custom endpoint.
- `webui/recovery_*.py` строят deterministic и model-assisted recovery drafts.
- Отдельный headless Ghidra REST service анализирует бинарник.

Runtime-артефакты пишутся в `data/`, `webui/chats/`, `webui/recovery/` и
`webui/recovered/`.

## Старый проект vs текущий проект

| Область           | `ai-reverse-engineering-main` | Текущая директория                                          |
| ----------------- | ----------------------------- | ----------------------------------------------------------- |
| LLM mode          | Один OpenAI-compatible setup  | Ollama, OpenAI или custom endpoint                          |
| Privacy           | Обычно remote/global model    | Local-first по умолчанию                                    |
| UI                | Monolithic template           | HTML shell плюс modular CSS/JS                              |
| Chat              | Ghidra tool loop              | Сохранен и расширен                                         |
| Recovery files    | Не было                       | Manifest, headers, stubs, function drafts, renamed variants |
| Symbol navigation | Не было                       | Address/name Symbol Map с filters и jump-to-code            |
| Translation       | Не было                       | LibreTranslate или custom network translator                |
| Job cleanup       | Минимальный                   | Local cleanup и hidden deleted jobs                         |
| Documentation     | Один README                   | English/Russian README, changelog, features, roadmap        |

## Требования

- Python 3.10+.
- Docker для headless Ghidra REST container.
- Один OpenAI-compatible провайдер:
  - Ollama для локальных моделей.
  - OpenAI для hosted-моделей.
  - Любой compatible gateway через `API_BASE`, `API_KEY`, `MODEL_NAME`.

Установка зависимостей:

```bash
pip install -r requirements.txt
```

## Запуск через Docker Compose

Используйте этот вариант, если хотите одной командой поднять web UI, Ghidra REST
и ваш offline LibreTranslate image.

Compose stack содержит:

- `aireverse`: этот Flask-проект, доступен на `http://localhost:5000`.
- `ghidra`: `biniamfd/ghidra-headless-rest:latest`, доступен на
  `http://localhost:9090`.
- `libretranslate`: `dvurechensky/libretranslate-offline-ru-en-zh:latest`,
  доступен напрямую на `http://localhost:5001`, а внутри compose-сети
  используется как `http://libretranslate:5000`.

Web container использует внутренние URL:

```text
GHIDRA_API_BASE=http://ghidra:9090
LIBRETRANSLATE_API_BASE=http://libretranslate:5000
```

По умолчанию приложение ожидает, что Ollama запущена на host machine:

```text
OLLAMA_API_BASE=http://host.docker.internal:11434/v1
OLLAMA_MODEL=qwen2.5-coder:14b
```

Запуск stack:

```bash
docker compose up --build
```

Открыть:

- Web UI: `http://localhost:5000`
- Ghidra REST: `http://localhost:9090`
- LibreTranslate UI/API напрямую: `http://localhost:5001`

Если один из портов уже занят, переопределите только host-side port. Внутренние
compose URL останутся прежними:

```env
WEBUI_PORT=5050
GHIDRA_PORT=9091
LIBRETRANSLATE_PORT=5002
```

Чтобы переопределить provider settings, создайте локальный `.env` рядом с
`docker-compose.yml`:

```env
LLM_PROVIDER=ollama
OLLAMA_API_BASE=http://host.docker.internal:11434/v1
OLLAMA_MODEL=qwen2.5-coder:14b

# Или OpenAI/custom:
# LLM_PROVIDER=openai
# OPENAI_API_KEY=sk-...
# OPENAI_MODEL=your-model-name
```

Остановить stack:

```bash
docker compose down
```

## Runtime settings в Web UI

В sidebar есть кнопка `Settings` в карточке `Local runtime`. Через нее можно
менять runtime providers без редактирования shell variables или
`docker-compose.yml`.

Настройки сохраняются в `webui/settings/runtime_settings.json`. В Docker Compose
эта директория смонтирована как volume, поэтому настройки переживают rebuild
контейнера. Environment variables остаются дефолтами; web settings имеют
приоритет.

Варианты AI provider:

- `Ollama`: локальный OpenAI-compatible endpoint, обычно
  `http://host.docker.internal:11434/v1` в Docker или
  `http://localhost:11434/v1` без Docker.
- `OpenAI`: hosted OpenAI-compatible endpoint.
- `Custom OpenAI-compatible`: любой gateway с поведением `/v1/chat/completions`.

Варианты translator:

- `Off`: скрыть controls перевода.
- `LibreTranslate`: ожидает `q`, `source`, `target` и `translatedText`.
- `Custom JSON API`: позволяет настроить поля request и путь к полю response.
  Сюда можно подключить Google/DeepL/Argos proxy. Например, gateway принимает
  `q/source/target` и возвращает `translations.0.text`; тогда в `Result field`
  укажите `translations.0.text`.

Пустые поля API key сохраняют уже записанный secret.

## Runtime logs

Flask и Werkzeug runtime logs пишутся в `logs/`:

- `logs/flask.log` для application logs.
- `logs/werkzeug.log` для development server/access logs.

Папка остается в репозитории через `logs/.gitkeep`, но реальные `*.log` файлы
игнорируются. По умолчанию публиковать логи не стоит: там могут быть имена
файлов, локальные endpoints, prompts, stack traces и детали окружения.

В Docker Compose `./logs` монтируется в `/app/logs`. Ротация настраивается через:

```env
AIREVERSE_LOG_DIR=logs
AIREVERSE_LOG_MAX_BYTES=1048576
AIREVERSE_LOG_BACKUPS=3
```

## Запуск на Windows

### 1. Запустите Ghidra REST

Запустите Ghidra REST из PowerShell в корне репозитория. Команда ниже берет
текущую директорию, поэтому работает независимо от того, куда склонирован проект.

```powershell
$ProjectDir = (Get-Location).Path
docker run --rm -p 9090:9090 -v "${ProjectDir}\data:/data/ghidra_projects" biniamfd/ghidra-headless-rest:latest
```

### 2. Выберите LLM provider

Во втором окне PowerShell выберите один блок настроек.

Локальная Ollama:

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

Любой OpenAI-compatible endpoint:

```powershell
$env:LLM_PROVIDER = "custom"
$env:API_BASE = "https://your-compatible-endpoint/v1"
$env:API_KEY = "your-key"
$env:MODEL_NAME = "your-model-name"
$env:GHIDRA_API_BASE = "http://localhost:9090"
```

### 3. Опционально включите переводчик чата

Переводчик выключен по умолчанию, потому что Flask UI тоже работает на `http://localhost:5000`.
Если LibreTranslate запущен в вашей локальной сети, добавьте эти переменные в том же PowerShell-окне перед запуском Flask:

```powershell
$env:TRANSLATOR_PROVIDER = "libretranslate"
$env:LIBRETRANSLATE_API_BASE = "http://192.168.0.179:5000"
$env:LIBRETRANSLATE_API_KEY = ""
```

Для другого сетевого переводчика запустите его через простой JSON HTTP endpoint
и используйте provider `custom`. По умолчанию ожидается запрос вида
`{"q":"text","source":"auto","target":"ru"}` и поле ответа `translatedText`.
Вложенные пути ответа, например `translations.0.text`, тоже поддерживаются через
`TRANSLATOR_RESULT_FIELD`.

```powershell
$env:TRANSLATOR_PROVIDER = "custom"
$env:TRANSLATOR_API_BASE = "http://translator-gateway.local:8080"
$env:TRANSLATOR_ENDPOINT = "/translate"
$env:TRANSLATOR_TEXT_FIELD = "q"
$env:TRANSLATOR_SOURCE_FIELD = "source"
$env:TRANSLATOR_TARGET_FIELD = "target"
$env:TRANSLATOR_RESULT_FIELD = "translatedText"
# Опциональная авторизация:
# $env:TRANSLATOR_AUTH_HEADER = "Authorization"
# $env:TRANSLATOR_AUTH_TOKEN = "Bearer your-token"
```

Пропустите этот шаг или задайте `$env:TRANSLATOR_PROVIDER = "off"`, чтобы скрыть кнопки перевода.
Когда переводчик включен, на каждом сообщении чата появляется кнопка `Translate`: русский текст переводится на English, остальной текст - на Russian.

### 4. Запустите Flask

```powershell
python webui/app.py
```

Откройте `http://localhost:5000`.

## Запуск на Linux/macOS

### 1. Запустите Ghidra REST

Запустите Ghidra REST из корня репозитория:

```bash
docker run --rm -p 9090:9090 -v "$(pwd)/data:/data/ghidra_projects" biniamfd/ghidra-headless-rest:latest
```

### 2. Выберите LLM provider

Во втором терминале выберите один блок настроек.

Локальная Ollama:

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

Любой OpenAI-compatible endpoint:

```bash
export LLM_PROVIDER=custom
export API_BASE=https://your-compatible-endpoint/v1
export API_KEY=your-key
export MODEL_NAME=your-model-name
export GHIDRA_API_BASE=http://localhost:9090
```

### 3. Опционально включите переводчик чата

Переводчик выключен по умолчанию, потому что Flask UI тоже работает на `http://localhost:5000`.
Если LibreTranslate запущен в вашей локальной сети, добавьте эти переменные в том же терминале перед запуском Flask:

```bash
export TRANSLATOR_PROVIDER=libretranslate
export LIBRETRANSLATE_API_BASE=http://192.168.0.179:5000
export LIBRETRANSLATE_API_KEY=
```

Для другого сетевого переводчика запустите его через простой JSON HTTP endpoint
и используйте provider `custom`. По умолчанию ожидается запрос вида
`{"q":"text","source":"auto","target":"ru"}` и поле ответа `translatedText`.
Вложенные пути ответа, например `translations.0.text`, тоже поддерживаются через
`TRANSLATOR_RESULT_FIELD`.

```bash
export TRANSLATOR_PROVIDER=custom
export TRANSLATOR_API_BASE=http://translator-gateway.local:8080
export TRANSLATOR_ENDPOINT=/translate
export TRANSLATOR_TEXT_FIELD=q
export TRANSLATOR_SOURCE_FIELD=source
export TRANSLATOR_TARGET_FIELD=target
export TRANSLATOR_RESULT_FIELD=translatedText
# Опциональная авторизация:
# export TRANSLATOR_AUTH_HEADER=Authorization
# export TRANSLATOR_AUTH_TOKEN="Bearer your-token"
```

Пропустите этот шаг или задайте `export TRANSLATOR_PROVIDER=off`, чтобы скрыть кнопки перевода.
Когда переводчик включен, на каждом сообщении чата появляется кнопка `Translate`: русский текст переводится на English, остальной текст - на Russian.

### 4. Запустите Flask

```bash
python webui/app.py
```

Откройте `http://localhost:5000`.

В sidebar отображается активный provider, model, LLM endpoint, Ghidra endpoint и статус переводчика.

## Рабочий процесс

1. Запустите Ghidra REST container.
2. Запустите Ollama, OpenAI или compatible endpoint.
3. Выполните `python webui/app.py`.
4. Загрузите бинарник в левую панель.
5. Дождитесь статуса `DONE`.
6. Задавайте точечные вопросы:

```text
List imports and strings. What runtime/library does this binary look like?
Find the likely main entry and decompile it.
Build a call graph around the function at 0x00401234.
Rename this function based on behavior and reconstruct C-like code.
Search for file, registry, network, serial, or license-check related strings.
```

Для старого Windows-кода:

```text
Восстанови функцию DACOM_Acquire как чистый VC++ 2003-compatible код.
```

## Recovery Panel

После выбора job откройте вкладку `Analysis`, чтобы увидеть recovery artifacts:

- `recovery_manifest.json` объясняет generated files и счетчики.
- `recovered_symbols.h` содержит conservative symbols и layout candidates.
- `recovered_stubs.cpp` содержит storage для recovered globals.
- `recovered_functions.cpp` сохраняет selected Ghidra pseudocode внутри `#if 0`.
- `recovered_types.h` создается optional AI type pass.
- `recovered_renames.json` содержит validated AI rename proposals.
- `.renamed.*` файлы появляются только если есть безопасная rename-map.

Generated code - это draft material. Его нужно проверять как evidence, а не
использовать как готовый production source.

### Analysis UX tips

- Используйте `Symbol Map`, чтобы перемещаться по function address или recovered
  name.
- Используйте `Renamed`, чтобы смотреть функции с AI/fallback именами.
- Используйте `Draft`, чтобы показывать функции, попавшие в
  `recovered_functions*.cpp`.
- Нажмите `Hide` в navigator, чтобы дать editor больше ширины.
- Используйте `Wrap` для длинных decompiler expressions.
- Используйте `Focus` для больших файлов; `Esc` возвращает обычный режим.
- Клик по функции в Symbol Map, подсвеченному имени функции или крупному
  hex-адресу в editor открывает inspector функции.
- Кнопки inspector готовят точные запросы в AI chat: объяснение, rename review
  или VC++ 2003 reconstruction.

## Ghidra Tool Endpoints

Ассистент вызывает эти endpoints через `GHIDRA_API_BASE=http://localhost:9090`.

| Endpoint                    | Method | Описание                              |
| --------------------------- | ------ | ------------------------------------- |
| `/tools/status`             | POST   | Статус analysis job.                  |
| `/tools/list_functions`     | POST   | Список найденных функций.             |
| `/tools/decompile_function` | POST   | Псевдокод функции по адресу.          |
| `/tools/get_xrefs`          | POST   | Callers/callees для функции.          |
| `/tools/list_imports`       | POST   | Импортированные библиотеки и символы. |
| `/tools/list_strings`       | POST   | Printable strings.                    |
| `/tools/query_artifacts`    | POST   | Поиск по функциям и артефактам.       |

Upload и job management routes обрабатываются Flask-приложением и Ghidra REST
service.

## Важные заметки

- Используйте проект только для разрешенного исследования и поддержки файлов,
  которые вы имеете право анализировать.
- Не запускайте недоверенные бинарники напрямую. Анализ Ghidra должен оставаться
  в контейнере или контролируемой worker-среде.
- Большие функции могут не помещаться в контекст модели. Лучше спрашивать по
  одной функции или подсистеме.
