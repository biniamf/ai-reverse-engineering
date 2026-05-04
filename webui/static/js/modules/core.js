(function(window, $) {
    const namespace = window.AIReverse = window.AIReverse || {};

    function formatBytes(bytes) {
        const value = Number(bytes || 0);
        if (value < 1024) return `${value} B`;
        const units = ['KB', 'MB', 'GB'];
        let size = value / 1024;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex += 1;
        }
        return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIndex]}`;
    }

    function formatCompactNumber(value) {
        const number = Number(value || 0);
        if (number >= 1000000) return `${(number / 1000000).toFixed(1)}M`;
        if (number >= 1000) return `${(number / 1000).toFixed(1)}k`;
        return String(number);
    }

    function escapeHtml(text) {
        return $('<div/>').text(text || '').html();
    }

    function normalizeAddress(value) {
        let text = String(value || '').trim();
        if (!text) return '';
        if (/^FUN_/i.test(text)) text = text.slice(4);
        text = text.toLowerCase();
        const digits = text.startsWith('0x') ? text.slice(2) : text;
        if (!/^[0-9a-f]+$/.test(digits)) return '';
        return `0x${digits.padStart(8, '0')}`;
    }

    namespace.core = {
        formatBytes,
        formatCompactNumber,
        escapeHtml,
        normalizeAddress,
    };
})(window, jQuery);
