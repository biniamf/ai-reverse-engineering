# Web UI Static Modules

[English](README.md) | [Русский](README.ru.md)

The original project kept HTML, styles, and browser behavior together in one
large template. The current frontend is intentionally split away from
`templates/index.html` so the interface can keep growing without becoming a
single mixed file again.

## Current Files

- `css/app.css` is a CSS manifest. It imports theme variables and feature
  styles in a stable order.
- `css/themes/dark.css` contains the default dark theme tokens.
- `css/themes/light.css` contains the first light-theme token override scaffold
  for future `data-theme="light"` support.
- `css/modules/*.css` contains feature styles: base, controls/settings, upload,
  chat/welcome, Markdown, jobs/recovery, analysis layout, and editor/inspector.
- `js/modules/core.js` contains shared formatting, escaping, and address helpers.
- `js/modules/theme.js` applies `data-theme`, stores the selected theme in
  `localStorage`, and binds the Settings theme selector.
- `js/modules/translation.js` contains markdown-aware chat translation behavior.
- `js/app.js` remains the main application coordinator for uploads, jobs, chat
  streaming, recovery files, Symbol Map navigation, function inspection, and
  editor controls.
- `templates/index.html` should stay the HTML shell: external libraries, app
  stylesheet, semantic page markup, and app script.

## Current UX Modules Inside `app.js`

- Upload drop-zone and selected-file state.
- Runtime config loading.
- Local/Ghidra job list loading.
- Chat history rendering and streaming responses.
- Translation button flow lives in `js/modules/translation.js`.
- Recovery file loading and generated source preview.
- Symbol Map filtering and click-to-jump behavior.
- Function inspector and inspector-to-chat prompt handoff.
- Clickable source tokens for known functions and large addresses.
- Code editor controls: line focus, wrap mode, focus mode.

## Theme Direction

Keep colors in `css/themes/*.css` as CSS variables. New components should use
existing variables first and add new variables only when a light theme cannot be
made readable through existing tokens.

The active theme is stored as `aireverse.theme` in `localStorage` and applied to
`document.documentElement` as `data-theme="dark"` or `data-theme="light"`.

## Future Split

When the frontend grows again, split by feature instead of moving logic back
into the template:

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

Prefer feature files over mixing new styles or scripts back into
`templates/index.html`.
