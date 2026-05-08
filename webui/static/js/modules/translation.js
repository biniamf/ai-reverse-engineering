(function(window, $) {
    const namespace = window.AIReverse = window.AIReverse || {};

    function detectTranslationTarget(text) {
        return /[\u0400-\u04FF]/.test(text || '') ? 'en' : 'ru';
    }

    function normalizeTranslatedMarkdown(text) {
        return (text || '')
            .replace(/\r\n/g, '\n')
            .replace(/^(\s*\d+)\s*\*\*/gm, '$1. **')
            .replace(/\*\*\s*([^*\n][^*\n]*?)\s*\*\*/g, '**$1**')
            .replace(/(^|\n)(#{1,6})([^\s#])/g, '$1$2 $3')
            .replace(/(^|\n)(\s*[-*])([^\s*])/g, '$1$2 $3')
            .replace(/`+\s*([^`\n]+?)\s*`+/g, '`$1`');
    }

    function protectMarkdownForTranslation(text) {
        const segments = [];
        let protectedText = text || '';
        function storeSegment(match) {
            const token = `AIREVKEEP${segments.length}TOKEN`;
            segments.push({ token, value: match });
            return token;
        }
        protectedText = protectedText.replace(/```[\s\S]*?```/g, storeSegment);
        protectedText = protectedText.replace(/`[^`\n]+`/g, storeSegment);
        protectedText = protectedText.replace(/\b(FUN|DAT|LAB|PTR|UNK)_[0-9A-Za-z_]+\b/g, storeSegment);
        protectedText = protectedText.replace(/\b0x[0-9A-Fa-f]+\b/g, storeSegment);

        return {
            text: protectedText,
            restore(translatedText) {
                let restored = translatedText || '';
                segments.forEach(({ token, value }) => {
                    const spacedToken = token.split('').join('\\s*');
                    restored = restored.replace(new RegExp(spacedToken, 'gi'), value);
                    restored = restored.replace(new RegExp(token, 'g'), value);
                });
                return normalizeTranslatedMarkdown(restored);
            },
        };
    }

    function attachTranslation($container, text, target) {
        const rawText = normalizeTranslatedMarkdown(text || '');
        let rendered = '';
        try {
            rendered = marked.parse(rawText);
        } catch (e) {
            rendered = `<p>${namespace.core.escapeHtml(rawText)}</p>`;
        }
        $container.find('.translation-card').remove();
        $container.append(`
            <details class="translation-card" open>
                <summary>
                    <span class="translation-label">Translation to ${target.toUpperCase()}</span>
                    <span class="translation-hint">click to collapse</span>
                </summary>
                <div class="translation-content markdown-content">${rendered}</div>
            </details>
        `);
        const $translation = $container.find('.translation-card').last();
        $translation.find('pre code').each(function(i, block) {
            hljs.highlightElement(block);
        });
        $translation.find('code.language-mermaid').each(function(index) {
            const $code = $(this);
            const graphDef = $code.text();
            const $pre = $code.parent();
            const uniqueId = `mermaid-translation-${Date.now()}-${index}`;
            $pre.replaceWith(`<div class="mermaid" id="${uniqueId}">${graphDef}</div>`);
            try {
                mermaid.run({ nodes: document.querySelectorAll(`#${uniqueId}`) });
            } catch(e) { console.error("Mermaid translation error", e); }
        });
    }

    function translateChatMessage($button) {
        const $bubble = $button.closest('.chat-bubble');
        const text = $bubble.data('raw') || '';
        if (!text.trim()) return;
        const target = detectTranslationTarget(text);
        const protectedPayload = protectMarkdownForTranslation(text);
        const originalLabel = $button.text();
        $button.prop('disabled', true).text(`Translating to ${target.toUpperCase()}...`);
        fetch('/translate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: protectedPayload.text, source: 'auto', target }),
        })
            .then(response => response.json().then(data => ({ ok: response.ok, data })))
            .then(({ ok, data }) => {
                if (!ok || data.error) throw new Error(data.error || 'Translation failed.');
                attachTranslation($bubble, protectedPayload.restore(data.translatedText || ''), target);
            })
            .catch(error => attachTranslation($bubble, `Translation failed: ${error.message}`, target))
            .finally(() => $button.prop('disabled', false).text(originalLabel));
    }

    namespace.translation = {
        detectTranslationTarget,
        normalizeTranslatedMarkdown,
        protectMarkdownForTranslation,
        attachTranslation,
        translateChatMessage,
    };
})(window, jQuery);
