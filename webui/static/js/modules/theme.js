(function(window, $) {
    const namespace = window.AIReverse = window.AIReverse || {};
    const storageKey = 'aireverse.theme';
    const defaultTheme = 'dark';
    const supportedThemes = new Set(['dark', 'light']);

    function normalizeTheme(theme) {
        return supportedThemes.has(theme) ? theme : defaultTheme;
    }

    function getStoredTheme() {
        try {
            return normalizeTheme(window.localStorage.getItem(storageKey));
        } catch (e) {
            return defaultTheme;
        }
    }

    function setTheme(theme) {
        const resolved = normalizeTheme(theme);
        document.documentElement.setAttribute('data-theme', resolved);
        try {
            window.localStorage.setItem(storageKey, resolved);
        } catch (e) {
            // localStorage can be unavailable in hardened browser modes.
        }
        $('#settings-theme').val(resolved);
        return resolved;
    }

    function initTheme() {
        setTheme(getStoredTheme());
    }

    function bindThemeControls() {
        $('#settings-theme').val(getStoredTheme());
        $('#settings-theme').on('change', function() {
            setTheme($(this).val());
        });
    }

    namespace.theme = {
        initTheme,
        bindThemeControls,
        setTheme,
        getStoredTheme,
    };

    initTheme();
})(window, jQuery);
