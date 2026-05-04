# Static-модули Web UI

[English](README.md) | [Русский](README.ru.md)

В исходном проекте HTML, стили и browser behavior жили вместе в одном большом
template. В текущей версии frontend специально вынесен из
`templates/index.html`, чтобы интерфейс мог расти и не превращался обратно в
один смешанный файл.

## Текущие файлы

- `css/app.css` теперь CSS manifest: импортирует theme variables и feature
  styles в стабильном порядке.
- `css/themes/dark.css` содержит default dark theme tokens.
- `css/themes/light.css` содержит первый scaffold для будущего
  `data-theme="light"`.
- `css/modules/*.css` содержит feature styles: base, controls/settings, upload,
  chat/welcome, Markdown, jobs/recovery, analysis layout и editor/inspector.
- `js/modules/core.js` содержит shared formatting, escaping и address helpers.
- `js/modules/theme.js` применяет `data-theme`, хранит выбранную тему в
  `localStorage` и подключает selector темы в Settings.
- `js/modules/translation.js` содержит markdown-aware chat translation behavior.
- `js/app.js` остается главным application coordinator для uploads, jobs, chat
  streaming, recovery files, Symbol Map navigation, function inspection и
  editor controls.
- `templates/index.html` должен оставаться HTML shell: external libraries, app
  stylesheet, semantic page markup и app script.

## Текущие UX-модули внутри `app.js`

- Upload drop-zone и selected-file state.
- Runtime config loading.
- Local/Ghidra job list loading.
- Chat history rendering и streaming responses.
- Translation button flow вынесен в `js/modules/translation.js`.
- Recovery file loading и generated source preview.
- Symbol Map filtering и click-to-jump behavior.
- Function inspector и inspector-to-chat prompt handoff.
- Clickable source tokens для известных функций и крупных адресов.
- Code editor controls: line focus, wrap mode, focus mode.

## Направление тем

Цвета держим в `css/themes/*.css` как CSS variables. Новые компоненты сначала
используют существующие variables; новые tokens добавляем только когда light
theme невозможно сделать читаемой через текущий набор.

Активная тема хранится как `aireverse.theme` в `localStorage` и применяется к
`document.documentElement` как `data-theme="dark"` или `data-theme="light"`.

## Будущий split

Когда frontend снова вырастет, лучше разделить его по feature modules, а не
возвращать логику в template:

- `css/sidebar.css`
- `css/chat.css`
- `css/recovery.css`
- `css/editor.css`
- `js/upload.js`
- `js/jobs.js`
- `js/chat.js`
- `js/translation.js`
- `js/recovery.js`
- `js/editor.js`

Лучше добавлять feature files, чем снова смешивать новые стили или scripts в
`templates/index.html`.
