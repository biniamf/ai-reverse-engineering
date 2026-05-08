$(document).ready(function() {
    const {
        formatBytes,
        formatCompactNumber,
        escapeHtml,
        normalizeAddress,
    } = window.AIReverse.core;
    const {
        detectTranslationTarget,
        normalizeTranslatedMarkdown,
        protectMarkdownForTranslation,
        translateChatMessage,
    } = window.AIReverse.translation;
    const { bindThemeControls } = window.AIReverse.theme;
    let currentJobId = null;
    let currentWorkspaceView = 'chat';
    let currentJobStatus = {};
    let currentRecoveryFile = null;
    let currentEditorContent = '';
    let currentEditorFile = '';
    let focusedEditorLine = null;
    let recoveredSymbols = [];
    let symbolViewFilter = 'all';
    let pendingSymbolFocus = null;
    let lastRecoverySummary = null;
    let currentFunctionContext = null;
    let selectedUploadFile = null;
    let jobStatusPollers = {};
    let translatorEnabled = false;
    let codeWrapEnabled = false;

    mermaid.initialize({ startOnLoad: false, theme: 'dark' });
    bindThemeControls();

    function applyRuntimeConfig(data) {
        $('#runtime-provider').text(data.provider || 'unknown');
        $('#runtime-model').text(data.model || 'unknown');
        $('#runtime-llm').text(data.api_base || 'unknown');
        $('#runtime-ghidra').text(data.ghidra_api_base || 'unknown');
        translatorEnabled = !!(data.translator && data.translator.enabled);
        $('#runtime-translator').text(data.translator && data.translator.enabled ? `${data.translator.provider} @ ${data.translator.api_base}` : 'off');
        $('#chat-provider-label').text(`${data.provider || 'provider'} · ${data.model || 'model'}`);
    }

    function refreshRuntimeConfig() {
        return $.get('/config', applyRuntimeConfig).fail(function() {
            $('#runtime-provider, #runtime-model, #runtime-llm, #runtime-ghidra, #runtime-translator').text('unavailable');
        });
    }
    function setSelectedUploadFile(file) {
        selectedUploadFile = file || null;
        const hasFile = !!selectedUploadFile;
        $('#upload-dropzone').toggleClass('has-file', hasFile).removeClass('drag-over');
        $('#selected-file-card').toggleClass('hidden', !hasFile);
        $('#dropzone-title').text(hasFile ? 'Ready for analysis' : 'Drop binary here');
        $('#dropzone-subtitle').text(hasFile ? 'Review the selected file, then start Ghidra analysis.' : 'or choose a file from disk');
        if (hasFile) {
            const extension = selectedUploadFile.name.includes('.') ? selectedUploadFile.name.split('.').pop().toUpperCase() : 'BINARY';
            $('#selected-file-name').text(selectedUploadFile.name);
            $('#selected-file-meta').text(`${formatBytes(selectedUploadFile.size)} · ${extension}`);
        } else {
            $('#file-input').val('');
            $('#selected-file-name, #selected-file-meta').text('');
        }
    }

    function openFilePicker() {
        $('#file-input').trigger('click');
    }

    $('#choose-file').on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        openFilePicker();
    });
    $('#upload-dropzone').on('click', function(e) {
        if ($(e.target).is('#clear-file, #choose-file')) return;
        openFilePicker();
    });
    $('#upload-dropzone').on('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openFilePicker();
        }
    });
    $('#file-input').on('change', function() {
        setSelectedUploadFile(this.files && this.files[0] ? this.files[0] : null);
    });
    $('#clear-file').on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        setSelectedUploadFile(null);
        showUploadStatus('File selection cleared.', false);
    });
    $('#upload-dropzone').on('dragenter dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).addClass('drag-over');
        $('#dropzone-title').text('Release to attach binary');
        $('#dropzone-subtitle').text('The file will be staged locally before analysis.');
    });
    $('#upload-dropzone').on('dragleave dragend', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).removeClass('drag-over');
        $('#dropzone-title').text(selectedUploadFile ? 'Ready for analysis' : 'Drop binary here');
        $('#dropzone-subtitle').text(selectedUploadFile ? 'Review the selected file, then start Ghidra analysis.' : 'or choose a file from disk');
    });
    $('#upload-dropzone').on('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const files = e.originalEvent.dataTransfer && e.originalEvent.dataTransfer.files;
        if (!files || files.length === 0) {
            $(this).removeClass('drag-over');
            return;
        }
        setSelectedUploadFile(files[0]);
        showUploadStatus(`Selected ${files[0].name}.`, false);
    });

    refreshRuntimeConfig();

    setJobsLoading('Loading local jobs...', true);
    renderJobSkeletons();
    $.get('/jobs?local=1', function(data) {
        $('#jobs-list').empty();
        if (Array.isArray(data)) {
            data.forEach(job => {
                renderJobItem(job);
            });
        }
        if ($('#jobs-list .job-item').length) {
            setJobsLoading('local cache', false, 'text-blue-300');
        } else {
            setJobsLoading('checking Ghidra', true);
            renderJobSkeletons(2);
        }
        refreshJobsFromGhidra();
    }).fail(function() {
        $('#jobs-list').empty();
        setJobsLoading('local unavailable', false, 'text-red-300');
        renderEmptyJobs('Local job cache is not available.');
        refreshJobsFromGhidra();
    });

    function refreshJobsFromGhidra() {
        $.get('/jobs', function(data) {
            if (!Array.isArray(data)) {
                if (!$('#jobs-list .job-item').length) renderEmptyJobs('No analysis jobs found yet.');
                setJobsLoading('idle', false);
                return;
            }
            if (!$('#jobs-list .job-item').length) $('#jobs-list').empty();
            data.forEach(job => {
                const jobId = job.job_id;
                if (!jobId) return;
                if ($(`#job-${jobId}`).length) {
                    updateJobStatusUi(jobId, job.status || 'unknown');
                } else {
                    renderJobItem(job);
                }
            });
            if ($('#jobs-list .job-item').length) {
                setJobsLoading('synced', false, 'text-green-300');
            } else {
                renderEmptyJobs('No analysis jobs yet. Upload a binary to start.');
                setJobsLoading('empty', false);
            }
        }).fail(function() {
            if ($('#jobs-list .job-item').length) {
                setJobsLoading('offline cache', false, 'text-yellow-300');
            } else {
                $('#jobs-list').empty();
                renderEmptyJobs('Ghidra jobs are unavailable. Start the Ghidra service or upload a binary.');
                setJobsLoading('offline', false, 'text-red-300');
            }
        });
    }

    function setJobsLoading(label, isLoading, colorClass = 'text-gray-500') {
        $('#jobs-sync-status').html(`
            ${isLoading ? '<span class="jobs-sync-dot"></span>' : '<span class="h-2 w-2 rounded-full bg-slate-600"></span>'}
            <span class="${colorClass}">${escapeHtml(label)}</span>
        `);
    }

    function renderJobSkeletons(count = 3) {
        $('#jobs-list').html(Array.from({ length: count }, () => '<div class="job-skeleton"></div>').join(''));
    }

    function renderEmptyJobs(message) {
        $('#jobs-list').html(`
            <div class="empty-jobs rounded-md p-4 text-sm text-gray-500">
                <div class="text-gray-300 font-medium mb-1">No jobs visible</div>
                <div>${escapeHtml(message)}</div>
            </div>
        `);
    }

    function renderJobItem(job, prepend = false) {
        const { job_id, status, filename, created_at } = job;
        const name = filename || "Unknown Binary";
        const dateStr = created_at ? new Date(created_at * 1000).toLocaleString() : "";
        const safeName = escapeHtml(name);
        const safeStatus = String(status || 'unknown').toUpperCase();
        const newJobHtml = `
            <div id="job-${job_id}" class="job-item p-3 bg-gray-800 hover:bg-gray-700 rounded-md cursor-pointer transition" data-job-id="${job_id}">
                <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0">
                        <div class="font-medium truncate text-gray-200">${safeName}</div>
                        <div class="text-xs text-gray-400">ID: ${job_id.substring(0,8)}... <span class="ml-2">${dateStr}</span></div>
                    </div>
                    <button type="button" class="job-delete shrink-0 text-xs bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 px-2 py-1 rounded"
                        title="Delete analysis" data-job-id="${job_id}" data-job-name="${safeName}">Delete</button>
                </div>
                <div class="text-xs text-yellow-400 font-mono job-status mt-1">${safeStatus}</div>
                <div class="job-progress mt-2"><div class="job-progress-bar"></div></div>
            </div>`;
        if (prepend) $('#jobs-list').prepend(newJobHtml);
        else $('#jobs-list').append(newJobHtml);
        updateJobStatusUi(job_id, status || 'unknown');
        if (status !== 'done' && status !== 'failed') pollStatus(job_id);
    }

    function showUploadStatus(message, isError = false, tone = null) {
        const resolvedTone = tone || (isError ? 'error' : 'success');
        const title = resolvedTone === 'error' ? 'Action failed'
            : resolvedTone === 'warning' ? 'Completed with note'
            : 'Status';
        $('#upload-status')
            .removeClass('text-red-400 text-green-400 status-message status-success status-warning status-error')
            .addClass(`status-message status-${resolvedTone}`)
            .html(`
                <div class="font-medium">${title}</div>
                <div class="text-xs mt-1 break-words">${escapeHtml(message)}</div>
            `);
    }
    function buildSymbolLookup() {
        const lookup = new Map();
        recoveredSymbols.forEach(symbol => {
            [symbol.original, symbol.renamed].forEach(value => {
                if (value) lookup.set(String(value).toLowerCase(), symbol);
            });
            const addr = normalizeAddress(symbol.address);
            if (addr) {
                lookup.set(addr, symbol);
                lookup.set(addr.replace('0x', ''), symbol);
                lookup.set(`fun_${addr.replace('0x', '')}`, symbol);
            }
        });
        return lookup;
    }
    function symbolFromToken(token) {
        const lookup = buildSymbolLookup();
        const normalized = normalizeAddress(token);
        return lookup.get(String(token || '').toLowerCase())
            || (normalized ? lookup.get(normalized) || lookup.get(normalized.replace('0x', '')) || lookup.get(`fun_${normalized.replace('0x', '')}`) : null);
    }
    function showRecoveryStatus(message, isError = false) {
        $('#recovery-status').text(message).toggleClass('text-red-400', isError).toggleClass('text-green-400', !isError);
    }
    function setSettingsStatus(message, isError = false) {
        $('#settings-status').text(message || '').toggleClass('text-red-300', isError).toggleClass('text-green-300', !isError && !!message);
    }
    function openSettingsModal() {
        $('#settings-modal').removeClass('hidden');
        loadSettings();
    }
    function closeSettingsModal() {
        $('#settings-modal').addClass('hidden');
        setSettingsStatus('');
    }
    function valueOrEffective(savedValue, effectiveValue, fallback = '') {
        return savedValue || effectiveValue || fallback;
    }
    function loadSettings() {
        setSettingsStatus('Loading settings...');
        $.get('/settings', function(data) {
            const savedLlm = (data.saved && data.saved.llm) || {};
            const effectiveLlm = (data.effective && data.effective.llm) || {};
            const savedTranslator = (data.saved && data.saved.translator) || {};
            const effectiveTranslator = (data.effective && data.effective.translator) || {};
            $('#settings-llm-provider').val(valueOrEffective(savedLlm.provider, effectiveLlm.provider, 'ollama'));
            $('#settings-llm-model').val(valueOrEffective(savedLlm.model, effectiveLlm.model, 'qwen2.5-coder:14b'));
            $('#settings-llm-api-base').val(valueOrEffective(savedLlm.api_base, effectiveLlm.api_base, 'http://localhost:11434/v1'));
            $('#settings-llm-api-key').attr('placeholder', savedLlm.api_key_set ? 'Saved key is set; leave blank to keep it' : 'API key');
            $('#settings-llm-api-key').val('');

            $('#settings-translator-provider').val(valueOrEffective(savedTranslator.provider, effectiveTranslator.provider, 'off'));
            $('#settings-translator-api-base').val(valueOrEffective(savedTranslator.api_base, effectiveTranslator.api_base, ''));
            $('#settings-translator-endpoint').val(valueOrEffective(savedTranslator.endpoint, effectiveTranslator.endpoint, '/translate'));
            $('#settings-translator-text-field').val(valueOrEffective(savedTranslator.text_field, effectiveTranslator.text_field, 'q'));
            $('#settings-translator-source-field').val(valueOrEffective(savedTranslator.source_field, effectiveTranslator.source_field, 'source'));
            $('#settings-translator-target-field').val(valueOrEffective(savedTranslator.target_field, effectiveTranslator.target_field, 'target'));
            $('#settings-translator-result-field').val(valueOrEffective(savedTranslator.result_field, effectiveTranslator.result_field, 'translatedText'));
            $('#settings-translator-auth-header').val(valueOrEffective(savedTranslator.auth_header, effectiveTranslator.auth_header, ''));
            $('#settings-translator-api-key').attr('placeholder', savedTranslator.api_key_set ? 'Saved key is set; leave blank to keep it' : 'Optional API key');
            $('#settings-translator-auth-token').attr('placeholder', savedTranslator.auth_token_set ? 'Saved token is set; leave blank to keep it' : 'Bearer ...');
            $('#settings-translator-api-key, #settings-translator-auth-token').val('');
            setSettingsStatus('Settings loaded.');
        }).fail(function(xhr) {
            setSettingsStatus(xhr.responseJSON?.error || 'Failed to load settings.', true);
        });
    }
    function collectSettingsPayload() {
        return {
            llm: {
                provider: $('#settings-llm-provider').val(),
                model: $('#settings-llm-model').val(),
                api_base: $('#settings-llm-api-base').val(),
                api_key: $('#settings-llm-api-key').val(),
            },
            translator: {
                provider: $('#settings-translator-provider').val(),
                api_base: $('#settings-translator-api-base').val(),
                endpoint: $('#settings-translator-endpoint').val(),
                text_field: $('#settings-translator-text-field').val(),
                source_field: $('#settings-translator-source-field').val(),
                target_field: $('#settings-translator-target-field').val(),
                result_field: $('#settings-translator-result-field').val(),
                api_key: $('#settings-translator-api-key').val(),
                auth_header: $('#settings-translator-auth-header').val(),
                auth_token: $('#settings-translator-auth-token').val(),
            },
        };
    }
    function setRecoveryButtonsBusy(isBusy) {
        $('#recovery-build, #recovery-ai-types, #recovery-ai-renames')
            .prop('disabled', isBusy)
            .toggleClass('busy-button', isBusy);
    }
    function renderSkeletonFiles(count = 5) {
        const skeletons = Array.from({ length: count }, () => '<div class="skeleton-card"></div>').join('');
        $('#recovery-files').html(skeletons);
    }
    function setRecoveryBusy(isBusy, options = {}) {
        setRecoveryButtonsBusy(isBusy);
        $('#recovery-panel').toggleClass('recovery-busy', isBusy);
        if (!isBusy) {
            $('#recovery-busy-panel').addClass('hidden');
            return;
        }
        const logs = options.logs || [
            'reading Ghidra artifacts',
            'building recovery index',
            'ranking recovered files',
            'preparing editor preview',
        ];
        $('#busy-title').text(options.title || 'Working');
        $('#busy-subtitle').text(options.subtitle || 'Preparing analysis pipeline...');
        $('#busy-log').html(logs.map(item => `<div class="busy-log-line">${escapeHtml(item)}</div>`).join(''));
        $('#recovery-busy-panel').removeClass('hidden');
        if (options.skeleton) renderSkeletonFiles(options.skeleton);
    }
    function jobProgressPercent(status) {
        const normalized = String(status || '').toLowerCase();
        if (normalized === 'done' || normalized === 'completed') return 100;
        if (normalized === 'failed') return 100;
        if (normalized === 'running') return 62;
        if (normalized === 'queued') return 24;
        return 12;
    }
    function updateJobStatusUi(jobId, status) {
        const normalized = String(status || 'unknown').toLowerCase();
        currentJobStatus[jobId] = normalized;
        const $jobItem = $(`#job-${jobId}`);
        const $status = $jobItem.find('.job-status');
        const $bar = $jobItem.find('.job-progress-bar');
        $status.text(normalized.toUpperCase())
            .removeClass('text-yellow-400 text-green-400 text-red-400 text-blue-300')
            .addClass(normalized === 'done' || normalized === 'completed' ? 'text-green-400'
                : normalized === 'failed' ? 'text-red-400'
                : normalized === 'running' ? 'text-blue-300'
                : 'text-yellow-400');
        $bar.css('width', `${jobProgressPercent(normalized)}%`)
            .css('background-color', normalized === 'failed' ? '#ef4444'
                : normalized === 'done' || normalized === 'completed' ? '#22c55e'
                : normalized === 'running' ? '#60a5fa'
                : '#f59e0b');
    }
    function renderAnalysisProgress(summary = null, stage = 'idle') {
        const jobStatus = currentJobStatus[currentJobId] || 'unknown';
        const hasFiles = !!summary;
        const steps = [
            {
                label: 'Ghidra',
                detail: jobStatus.toUpperCase(),
                done: jobStatus === 'done' || jobStatus === 'completed',
                active: ['queued', 'running'].includes(jobStatus),
            },
            {
                label: 'Artifacts',
                detail: hasFiles ? `${summary.function_drafts || 0} functions` : 'waiting',
                done: hasFiles,
                active: stage === 'loading',
            },
            {
                label: 'Recovery',
                detail: hasFiles ? `${summary.renderable_structures || 0}/${summary.structure_candidates || 0} structs` : 'not built',
                done: hasFiles && ((summary.function_drafts || 0) > 0 || (summary.structure_candidates || 0) > 0),
                active: stage === 'building',
            },
            {
                label: 'AI passes',
                detail: hasFiles ? `${summary.typed_function_pointers || 0} typed ptrs` : 'optional',
                done: hasFiles && ((summary.typed_function_pointers || 0) > 0),
                active: stage === 'ai',
            },
        ];
        $('#analysis-progress').html(steps.map(step => `
            <div class="recovery-step ${step.done ? 'done' : ''} ${step.active ? 'active' : ''} border border-gray-700 rounded-md p-3 bg-gray-900 min-w-0">
                <div class="flex items-center justify-between gap-2">
                    <div class="text-xs uppercase tracking-wide text-gray-500">${step.label}</div>
                    <div class="h-2 w-2 rounded-full ${step.done ? 'bg-green-400' : step.active ? 'bg-indigo-400 animate-pulse' : 'bg-gray-600'}"></div>
                </div>
                <div class="mt-1 text-sm font-mono text-gray-200 truncate">${escapeHtml(step.detail)}</div>
            </div>
        `).join(''));
    }
    function showWorkspaceView(view) {
        currentWorkspaceView = view;
        $('.workspace-tab').removeClass('active');
        $(`.workspace-tab[data-view="${view}"]`).addClass('active');
        if (view === 'analysis') {
            $('#chat-container').addClass('hidden').removeClass('flex');
            $('#recovery-panel').removeClass('hidden').addClass('flex');
            refreshRecoveryPanel(false, false);
        } else {
            $('#recovery-panel').addClass('hidden').removeClass('flex');
            $('#chat-container').removeClass('hidden').addClass('flex');
            $('#chat-input').focus();
        }
    }
    function renderRecoveryFiles(files) {
        const $files = $('#recovery-files');
        $files.empty();
        if (!files || files.length === 0) {
            $files.html('<div class="text-xs text-gray-500">No recovered files yet.</div>');
            $('#recovery-preview').addClass('hidden').empty();
            $('#recovery-file-info').addClass('hidden').empty();
            $('#function-inspector').addClass('hidden').empty();
            return;
        }
        const groups = {};
        files.forEach(file => {
            const category = file.category || 'Other';
            if (!groups[category]) groups[category] = [];
            groups[category].push(file);
        });
        Object.keys(groups).sort().forEach(category => {
            $files.append(`<div class="text-[11px] uppercase tracking-wide text-gray-500 mt-2 mb-1">${escapeHtml(category)}</div>`);
            groups[category].forEach(file => {
                const validityClass = file.validity === 'not_compilable' ? 'text-yellow-300'
                    : file.validity === 'experimental' ? 'text-purple-300'
                    : file.validity === 'empty' ? 'text-gray-500'
                    : file.validity === 'diagnostic' ? 'text-blue-300'
                    : 'text-green-300';
                const activeClass = file.name === currentRecoveryFile ? 'active' : '';
                $files.append(`
                    <button type="button" class="recovery-file ${activeClass} block w-full text-left text-xs bg-gray-800 hover:bg-gray-700 border border-transparent rounded px-2 py-2"
                        data-name="${escapeHtml(file.name)}"
                        data-title="${escapeHtml(file.title || file.name)}"
                        data-validity="${escapeHtml(file.validity || 'unknown')}"
                        data-description="${escapeHtml(file.description || '')}">
                        <div class="flex justify-between gap-2">
                            <span class="font-mono text-green-400 truncate">${escapeHtml(file.name)}</span>
                            <span class="text-gray-500 shrink-0">${file.size} bytes</span>
                        </div>
                        <div class="text-gray-400 truncate">${escapeHtml(file.title || '')}</div>
                        <div class="${validityClass}">${escapeHtml(file.validity || 'unknown')}</div>
                    </button>
                `);
            });
        });
    }
    function renderRecoverySummary(summary) {
        if (!summary) {
            $('#recovery-summary').addClass('hidden').empty();
            renderAnalysisProgress(null);
            return;
        }
        lastRecoverySummary = summary;
        $('#recovery-summary').removeClass('hidden').html(`
            <div class="grid grid-cols-2 gap-x-3 gap-y-1">
                <div>Modules: <span class="font-mono text-gray-200">${summary.dynamic_modules || 0}</span></div>
                <div>Function ptrs: <span class="font-mono text-gray-200">${summary.function_pointers || 0}</span></div>
                <div>Typed ptrs: <span class="font-mono text-gray-200">${summary.typed_function_pointers || 0}</span></div>
                <div>Helpers: <span class="font-mono text-gray-200">${summary.helper_renames || 0}</span></div>
                <div>Function drafts: <span class="font-mono text-gray-200">${summary.function_drafts || 0}</span></div>
                <div>C++ owners: <span class="font-mono text-gray-200">${summary.cpp_owners || 0}</span></div>
                <div>Class layouts: <span class="font-mono text-gray-200">${summary.class_layouts || 0}</span></div>
                <div>Structures: <span class="font-mono text-gray-200">${summary.renderable_structures || 0}</span> <span class="text-gray-500">/ ${summary.structure_candidates || 0} raw</span></div>
                <div>Enum candidates: <span class="font-mono text-gray-200">${summary.enum_candidates || 0}</span></div>
            </div>
        `);
        renderAnalysisProgress(summary);
    }
    function renderSymbolNavigator(filter = '') {
        const query = (filter || '').trim().toLowerCase();
        const hasDraftMetadata = recoveredSymbols.some(symbol => Object.prototype.hasOwnProperty.call(symbol, 'in_draft'));
        const isSymbolNavigable = (symbol) => hasDraftMetadata ? !!symbol.in_draft : true;
        const visible = recoveredSymbols.filter(symbol => {
            const haystack = `${symbol.original || ''} ${symbol.renamed || ''} ${symbol.address || ''} ${symbol.signature || ''}`.toLowerCase();
            const inDraft = isSymbolNavigable(symbol);
            const matchesQuery = !query || haystack.includes(query);
            const matchesMode = symbolViewFilter === 'all'
                || (symbolViewFilter === 'draft' && inDraft)
                || (symbolViewFilter === 'renamed' && symbol.renamed_active)
                || (symbolViewFilter === 'raw' && !symbol.renamed_active)
                || (symbolViewFilter === 'missing' && !inDraft);
            return matchesQuery && matchesMode;
        }).slice(0, 80);
        const renamed = recoveredSymbols.filter(symbol => symbol.renamed_active).length;
        const navigable = recoveredSymbols.filter(symbol => isSymbolNavigable(symbol)).length;
        const missing = recoveredSymbols.length - navigable;
        $('#symbol-navigator').toggleClass('hidden', recoveredSymbols.length === 0);
        $('#symbol-map-count').text(`${navigable}/${recoveredSymbols.length}`);
        $('#symbol-map-status').text(recoveredSymbols.length ? `${navigable} in draft, ${renamed} renamed, ${missing} outside draft` : 'No symbols available.');
        if (!visible.length) {
            $('#symbol-list').html('<div class="text-xs text-gray-500 rounded border border-dashed border-gray-700 p-3">No matching symbols.</div>');
            return;
        }
        $('#symbol-list').html(visible.map(symbol => {
            const renamed = symbol.renamed || symbol.original;
            const isRenamed = symbol.renamed_active;
            const inDraft = isSymbolNavigable(symbol);
            const active = pendingSymbolFocus
                && (pendingSymbolFocus.address === symbol.address || pendingSymbolFocus.original === symbol.original)
                ? 'active'
                : '';
            const unavailable = inDraft ? '' : 'unavailable';
            const stateLabel = inDraft ? (isRenamed ? 'renamed' : 'raw') : 'not in draft';
            const stateClass = inDraft ? (isRenamed ? 'text-green-300' : 'text-gray-500') : 'text-yellow-300';
            return `
                <button type="button" class="symbol-row ${active} ${unavailable} block w-full rounded px-2 py-2 text-left text-xs"
                    data-original="${escapeHtml(symbol.original || '')}"
                    data-renamed="${escapeHtml(renamed || '')}"
                    data-address="${escapeHtml(symbol.address || '')}"
                    data-source-file="${escapeHtml(symbol.source_file || 'recovered_functions.cpp')}"
                    data-renamed-active="${isRenamed ? '1' : '0'}"
                    data-in-draft="${inDraft ? '1' : '0'}">
                    <div class="flex items-center justify-between gap-2">
                        <span class="symbol-address">${escapeHtml(symbol.address || 'no address')}</span>
                        <span class="${stateClass}">${stateLabel}</span>
                    </div>
                    <div class="mt-1 min-w-0">
                        <span class="font-mono text-gray-400 truncate">${escapeHtml(symbol.original || '')}</span>
                        <span class="symbol-rename-arrow mx-1">-></span>
                        <span class="font-mono ${isRenamed ? 'text-green-300' : 'text-gray-300'} truncate">${escapeHtml(renamed || '')}</span>
                    </div>
                    ${isRenamed && !inDraft ? '<div class="mt-1 text-[11px] text-yellow-300">renamed, but not emitted in current function draft</div>' : ''}
                    <div class="mt-1 truncate text-gray-500">${escapeHtml(symbol.signature || '')}</div>
                </button>
            `;
        }).join(''));
    }
    function loadSymbolNavigator() {
        if (!currentJobId) return;
        fetch(`/recovery/symbols/${currentJobId}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) throw new Error(data.error);
                recoveredSymbols = data.symbols || [];
                renderSymbolNavigator($('#symbol-search').val());
            })
            .catch(() => {
                recoveredSymbols = [];
                $('#symbol-navigator').addClass('hidden');
            });
    }
    function symbolFromRow($row) {
        return {
            original: $row.attr('data-original') || '',
            renamed: $row.attr('data-renamed') || '',
            address: $row.attr('data-address') || '',
            sourceFile: $row.attr('data-source-file') || '',
            renamedActive: $row.attr('data-renamed-active') === '1',
            inDraft: $row.attr('data-in-draft') === '1',
        };
    }
    function focusEditorSymbol(symbol) {
        if (!symbol || !currentEditorContent) return;
        const terms = [
            symbol.address,
            symbol.original,
            symbol.renamed,
            symbol.address ? String(symbol.address).replace(/^0x/i, '') : '',
            symbol.original ? `Function: ${symbol.original}` : '',
            symbol.address ? `Address: ${symbol.address}` : '',
        ].filter(Boolean);
        const haystack = currentEditorContent.toLowerCase();
        let index = -1;
        for (const term of terms) {
            index = haystack.indexOf(String(term).toLowerCase());
            if (index >= 0) break;
        }
        if (index < 0) {
            focusedEditorLine = null;
            $('.line-number-row').removeClass('focused');
            showRecoveryStatus(`Opened ${currentEditorFile}; ${symbol.original || symbol.address} is not present in this generated draft.`, false);
            return;
        }
        const line = currentEditorContent.slice(0, index).split('\n').length;
        focusedEditorLine = line;
        const $body = $('#recovery-preview .code-editor-body');
        const lineHeight = parseFloat($('.code-lines').css('line-height')) || 21;
        $body.scrollTop(Math.max(0, (line - 8) * lineHeight));
        $('.line-number-row').removeClass('focused');
        $(`.line-number-row[data-line="${line}"]`).addClass('focused');
        showRecoveryStatus(`${symbol.address || 'symbol'} -> ${symbol.renamed || symbol.original} near line ${line}`);
    }
    function linkEditorSymbols() {
        const $code = $('#recovery-preview code');
        if (!$code.length || !recoveredSymbols.length) return;
        const lookup = buildSymbolLookup();
        const tokenRegex = /\bFUN_[0-9A-Fa-f]+\b|\b0x[0-9A-Fa-f]{6,16}\b|\b[A-Za-z_][A-Za-z0-9_]{2,}\b/g;
        const walker = document.createTreeWalker($code[0], NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                if (!node.nodeValue || !tokenRegex.test(node.nodeValue)) return NodeFilter.FILTER_REJECT;
                tokenRegex.lastIndex = 0;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        const nodes = [];
        while (walker.nextNode()) nodes.push(walker.currentNode);
        nodes.forEach(node => {
            const text = node.nodeValue;
            const fragment = document.createDocumentFragment();
            let lastIndex = 0;
            text.replace(tokenRegex, (match, offset) => {
                const normalized = normalizeAddress(match);
                const symbol = lookup.get(match.toLowerCase())
                    || (normalized ? lookup.get(normalized) || lookup.get(normalized.replace('0x', '')) || lookup.get(`fun_${normalized.replace('0x', '')}`) : null);
                if (!symbol && !normalized) return match;
                if (offset > lastIndex) fragment.appendChild(document.createTextNode(text.slice(lastIndex, offset)));
                const button = document.createElement('button');
                button.type = 'button';
                button.className = symbol ? 'code-link' : 'code-link code-link-address';
                button.dataset.symbol = match;
                if (symbol && symbol.address) button.dataset.address = symbol.address;
                button.textContent = match;
                fragment.appendChild(button);
                lastIndex = offset + match.length;
                return match;
            });
            if (lastIndex === 0) return;
            if (lastIndex < text.length) fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
            node.parentNode.replaceChild(fragment, node);
        });
    }
    function renderFunctionInspector(data) {
        currentFunctionContext = data;
        const fn = data && data.function ? data.function : null;
        if (!fn) {
            $('#function-inspector').removeClass('hidden').html(`
                <div class="inspector-empty">Function context was not found in local artifacts.</div>
            `);
            return;
        }
        const callers = (data.xrefs && data.xrefs.callers) || [];
        const callees = (data.xrefs && data.xrefs.callees) || [];
        const strings = data.related_strings || [];
        const callChip = (item, role) => `
            <button type="button" class="inspector-chip" data-inspect-symbol="${escapeHtml(item.address || item.renamed || item.original || '')}">
                <span>${escapeHtml(item.renamed || item.original || item.address || 'unknown')}</span>
                <small>${escapeHtml(role === 'caller' ? (item.callsite || item.address || '') : (item.address || ''))}</small>
            </button>
        `;
        $('#function-inspector').removeClass('hidden').html(`
            <div class="inspector-header">
                <div class="min-w-0">
                    <div class="inspector-kicker">${escapeHtml(fn.address || 'no address')}</div>
                    <div class="inspector-title">${escapeHtml(fn.display_name || fn.renamed || fn.original || 'Function')}</div>
                    <div class="inspector-signature">${escapeHtml(fn.signature || 'signature unavailable')}</div>
                </div>
                <div class="inspector-actions">
                    <button type="button" class="toolbar-button inspector-open-source">Open</button>
                    <button type="button" class="toolbar-button inspector-chat" data-mode="explain">Explain</button>
                    <button type="button" class="toolbar-button inspector-chat" data-mode="rename">Rename</button>
                    <button type="button" class="toolbar-button inspector-chat" data-mode="reconstruct">Reconstruct</button>
                </div>
            </div>
            <div class="inspector-grid">
                <div class="inspector-metric"><span>Callers</span><strong>${callers.length}</strong></div>
                <div class="inspector-metric"><span>Callees</span><strong>${callees.length}</strong></div>
                <div class="inspector-metric"><span>Strings</span><strong>${strings.length}</strong></div>
                <div class="inspector-metric"><span>Draft</span><strong>${fn.in_draft ? 'yes' : 'no'}</strong></div>
            </div>
            <div class="inspector-relations">
                <section>
                    <div class="inspector-section-title">Callers</div>
                    <div class="inspector-chip-list">${callers.length ? callers.slice(0, 12).map(item => callChip(item, 'caller')).join('') : '<span class="inspector-muted">No caller xrefs in artifacts.</span>'}</div>
                </section>
                <section>
                    <div class="inspector-section-title">Calls</div>
                    <div class="inspector-chip-list">${callees.length ? callees.slice(0, 12).map(item => callChip(item, 'callee')).join('') : '<span class="inspector-muted">No direct calls inferred from draft.</span>'}</div>
                </section>
            </div>
            ${strings.length ? `
                <div class="inspector-strings">
                    <div class="inspector-section-title">Related strings</div>
                    ${strings.slice(0, 6).map(item => `<code>${escapeHtml(item.address || '')} ${escapeHtml(item.text || '')}</code>`).join('')}
                </div>
            ` : ''}
        `);
    }
    function inspectFunction(query) {
        if (!currentJobId || !query) return;
        showRecoveryStatus(`Inspecting ${query}...`);
        fetch(`/recovery/function/${currentJobId}/${encodeURIComponent(query)}`)
            .then(response => response.json().then(data => ({ ok: response.ok, data })))
            .then(({ ok, data }) => {
                if (!ok || data.error) throw new Error(data.error || 'Function context unavailable.');
                renderFunctionInspector(data);
                const fn = data.function || {};
                const rowSymbol = {
                    original: fn.original,
                    renamed: fn.renamed,
                    address: fn.address,
                    sourceFile: fn.source_file,
                    renamedActive: !!fn.renamed_active,
                    inDraft: !!fn.in_draft,
                };
                pendingSymbolFocus = rowSymbol;
                if (fn.source_file && currentEditorFile !== fn.source_file) {
                    openRecoveryFile(fn.source_file, { focusSymbol: rowSymbol });
                } else {
                    focusEditorSymbol(rowSymbol);
                }
            })
            .catch(error => showRecoveryStatus(error.message, true));
    }
    function promptForFunction(mode) {
        const fn = currentFunctionContext && currentFunctionContext.function;
        if (!fn) return '';
        const callers = ((currentFunctionContext.xrefs || {}).callers || []).slice(0, 8)
            .map(item => `${item.renamed || item.original || item.address} @ ${item.callsite || item.address}`)
            .join(', ') || 'нет данных';
        const callees = ((currentFunctionContext.xrefs || {}).callees || []).slice(0, 8)
            .map(item => `${item.renamed || item.original || item.address} @ ${item.address}`)
            .join(', ') || 'нет данных';
        const header = `Функция ${fn.renamed || fn.original} (${fn.original}) по адресу ${fn.address}. Сигнатура: ${fn.signature || 'unknown'}. Вызывают: ${callers}. Вызывает: ${callees}.`;
        if (mode === 'rename') {
            return `${header}\nПредложи безопасное смысловое имя для этой функции и объясни, почему оно лучше старого.`;
        }
        if (mode === 'reconstruct') {
            return `${header}\nВосстанови эту функцию как читаемый VC++ 2003-compatible C/C++ код. Отдели уверенные выводы от предположений.`;
        }
        return `${header}\nОбъясни, что делает эта функция, какие побочные эффекты видны, какие вызовы важны и на что обратить внимание при реверсе.`;
    }
    function languageForFile(filename) {
        const lower = (filename || '').toLowerCase();
        if (lower.endsWith('.h') || lower.endsWith('.hpp') || lower.endsWith('.c') || lower.endsWith('.cpp')) return 'cpp';
        if (lower.endsWith('.json')) return 'json';
        if (lower.endsWith('.md')) return 'markdown';
        if (lower.endsWith('.txt')) return 'plaintext';
        return 'plaintext';
    }
    function renderCodeEditor(filename, content, meta = {}) {
        const language = languageForFile(filename);
        const raw = content || '';
        currentEditorContent = raw;
        currentEditorFile = filename;
        const lines = raw.split('\n');
        const bytes = new Blob([raw]).size;
        const lineNumbers = lines.map((_, index) => {
            const line = index + 1;
            const focused = focusedEditorLine === line ? ' focused' : '';
            return `<span class="line-number-row${focused}" data-line="${line}">${line}</span>`;
        }).join('');
        let highlighted = escapeHtml(raw);
        try {
            if (language !== 'plaintext' && hljs.getLanguage(language)) {
                highlighted = hljs.highlight(raw, { language }).value;
            }
        } catch (e) {
            highlighted = escapeHtml(raw);
        }
        $('#recovery-preview').removeClass('hidden').toggleClass('code-wrap-enabled', codeWrapEnabled).html(`
            <div class="code-editor-toolbar">
                <div class="code-toolbar-main">
                    <div class="min-w-0">
                        <div class="code-file-name">${escapeHtml(filename)}</div>
                        <div class="code-file-title">${escapeHtml(meta.title || 'Recovered source')}</div>
                    </div>
                    <div class="code-toolbar-actions">
                        <span class="code-pill">${language.toUpperCase()}</span>
                        <span class="code-pill">${formatCompactNumber(lines.length)} lines</span>
                        <span class="code-pill">${formatBytes(bytes)}</span>
                        <button id="code-wrap-toggle" type="button" class="toolbar-button ${codeWrapEnabled ? 'active' : ''}" title="Toggle line wrapping">Wrap</button>
                        <button id="code-focus-toggle" type="button" class="toolbar-button ${$('#recovery-panel').hasClass('analysis-focus-mode') ? 'active' : ''}" title="Focus editor">${$('#recovery-panel').hasClass('analysis-focus-mode') ? 'Exit Focus' : 'Focus'}</button>
                    </div>
                </div>
                <div class="code-mini-map" aria-hidden="true">
                    <span style="width:${Math.min(100, Math.max(8, (lines.length / 10000) * 100)).toFixed(1)}%"></span>
                </div>
            </div>
            <div class="code-editor-body h-full">
                <div class="code-lines">
                    <div class="line-numbers">${lineNumbers}</div>
                    <pre><code class="language-${language}">${highlighted}</code></pre>
                </div>
            </div>
        `);
        linkEditorSymbols();
        if (pendingSymbolFocus) {
            setTimeout(() => focusEditorSymbol(pendingSymbolFocus), 0);
        }
    }
    function refreshRecoveryPanel(generate = false, force = false) {
        if (!currentJobId) return;
        showRecoveryStatus(generate ? 'Building recovery index...' : 'Loading recovered files...');
        renderAnalysisProgress(null, generate ? 'building' : 'loading');
        setRecoveryBusy(true, {
            title: generate ? 'Rebuilding recovery drafts' : 'Loading recovered artifacts',
            subtitle: generate ? 'Scanning functions, globals, layout candidates, and generated source files.' : 'Reading local recovery files and preparing the editor.',
            logs: generate
                ? ['loading functions.json', 'extracting imports and strings', 'detecting helper names', 'rendering .h/.cpp drafts']
                : ['reading recovery manifest', 'grouping files by stage', 'checking selected file', 'warming syntax highlighter'],
            skeleton: generate ? 6 : 4,
        });
        const method = generate ? 'POST' : 'GET';
        const suffix = generate && force ? '?force=1' : '';
        fetch(`/recovery/files/${currentJobId}${suffix}`, { method })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showRecoveryStatus(data.error, true);
                    setRecoveryBusy(false);
                    return;
                }
                renderRecoveryFiles(data.files || []);
                renderRecoverySummary(data.summary);
                loadSymbolNavigator();
                const currentPreview = $('#recovery-file-info .font-mono').text();
                if (!currentPreview || generate) {
                    const guide = (data.files || []).find(file => file.name === 'recovery_manifest.json')
                        || (data.files || []).find(file => file.name === 'recovered_symbols.h')
                        || (data.files || [])[0];
                    if (guide && guide.name) {
                        openRecoveryFile(guide.name);
                    }
                }
                showRecoveryStatus(generate ? 'Recovered files updated.' : 'Recovered files loaded.');
                setRecoveryBusy(false);
            })
            .catch(() => {
                setRecoveryBusy(false);
                showRecoveryStatus('Recovery panel failed.', true);
            });
    }
    function openRecoveryFile(filename, options = {}) {
        if (!currentJobId || !filename) return;
        if (options.focusSymbol) pendingSymbolFocus = options.focusSymbol;
        else focusedEditorLine = null;
        currentRecoveryFile = filename;
        showRecoveryStatus(`Opening ${filename}...`);
        setRecoveryBusy(false);
        $('.recovery-file').removeClass('active');
        const $button = $('.recovery-file').filter(function() { return $(this).data('name') === filename; }).first();
        if ($button.length) {
            $button.addClass('active');
            $('#recovery-file-info').removeClass('hidden').html(`
                <div class="flex items-start justify-between gap-3">
                    <div class="min-w-0">
                        <div class="font-mono text-green-300 truncate">${escapeHtml(filename)}</div>
                        <div class="text-gray-300">${escapeHtml($button.data('title') || '')}</div>
                        <div class="text-gray-500">${escapeHtml($button.data('description') || '')}</div>
                    </div>
                    <span class="shrink-0 rounded bg-gray-800 px-2 py-1 text-xs text-gray-400">${escapeHtml($button.data('validity') || 'unknown')}</span>
                </div>
            `);
        }
        fetch(`/recovery/files/${currentJobId}/${encodeURIComponent(filename)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    const fallbackFiles = options.fallbackFiles || [];
                    const nextFile = fallbackFiles.find(file => file && file !== filename);
                    if (nextFile) {
                        openRecoveryFile(nextFile, {
                            focusSymbol: options.focusSymbol,
                            fallbackFiles: fallbackFiles.filter(file => file !== nextFile),
                        });
                        return;
                    }
                    $('#recovery-file-info').removeClass('hidden').html(`
                        <div class="font-mono text-red-300">${escapeHtml(filename)}</div>
                        <div class="text-gray-400">File is not available in the current recovery state.</div>
                        <div class="text-gray-500">If this is a .renamed.* file, the AI rename map is probably empty, so stale renamed variants were removed.</div>
                    `);
                    $('#recovery-preview').addClass('hidden').empty();
                    showRecoveryStatus(data.error, true);
                    return;
                }
                renderCodeEditor(filename, data.content || '', {
                    title: $button.data('title') || '',
                    validity: $button.data('validity') || '',
                });
                showRecoveryStatus(filename);
            })
            .catch(() => showRecoveryStatus('Failed to open recovered file.', true));
    }
    function buildAiTypes() {
        if (!currentJobId) return;
        showRecoveryStatus('Asking local model to recover types/classes...');
        renderAnalysisProgress(lastRecoverySummary, 'ai');
        setRecoveryBusy(true, {
            title: 'Recovering C/C++ types',
            subtitle: 'The local model is reading constructors, vtables, function pointers, and structure hints.',
            logs: ['packing recovery context', 'calling selected LLM provider', 'validating header shape', 'writing recovered_types.h'],
        });
        fetch(`/recovery/model/types/${currentJobId}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showRecoveryStatus(data.error, true);
                    setRecoveryBusy(false);
                    return;
                }
                refreshRecoveryPanel(false);
                if (data.file && data.file.name) {
                    openRecoveryFile(data.file.name);
                }
                showRecoveryStatus('AI recovered types updated.');
                setRecoveryBusy(false);
            })
            .catch(() => {
                setRecoveryBusy(false);
                showRecoveryStatus('AI type recovery failed.', true);
            });
    }
    function buildAiRenames() {
        if (!currentJobId) return;
        showRecoveryStatus('Asking local model to rename recovered sources...');
        renderAnalysisProgress(lastRecoverySummary, 'ai');
        setRecoveryBusy(true, {
            title: 'Renaming generated symbols',
            subtitle: 'The local model is proposing conservative names and validating the rename map.',
            logs: ['collecting placeholder symbols', 'asking model for JSON map', 'validating identifiers', 'writing renamed variants'],
        });
        fetch(`/recovery/model/renames/${currentJobId}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showRecoveryStatus(data.error, true);
                    setRecoveryBusy(false);
                    return;
                }
                refreshRecoveryPanel(false);
                const renamed = (data.files || []).find(file => file.name === 'recovered_symbols.renamed.h')
                    || (data.files || []).find(file => file.name === 'recovered_renames.json');
                if (renamed && renamed.name) {
                    openRecoveryFile(renamed.name);
                }
                const count = data.rename_count || 0;
                if (count && data.fallback_used) {
                    showRecoveryStatus(`AI returned no safe renames; fallback renamed ${count} symbol(s).`, false, 'warning');
                } else {
                    showRecoveryStatus(count ? `AI rename pass updated ${count} symbol(s).` : 'AI rename found no safe renames.');
                }
                setRecoveryBusy(false);
            })
            .catch(() => {
                setRecoveryBusy(false);
                showRecoveryStatus('AI rename pass failed.', true);
            });
    }
    function addChatMessage(role, message) {
        const senderClass = role === 'user' ? 'chat-bubble-user text-white' : 'chat-bubble-assistant text-gray-200';
        const alignClass = role === 'user' ? 'justify-end' : 'justify-start';
        const avatar = role === 'user' ? 'YOU' : 'AI';
        const label = role === 'user' ? 'You' : 'Assistant';
        const sanitizedMessage = $('<div/>').text(message).html();
        const translateAction = translatorEnabled ? '<div class="chat-actions"><button type="button" class="translate-button">Translate</button></div>' : '';
        const $message = $(`
            <div class="flex ${alignClass} gap-3 mb-4">
                ${role === 'assistant' ? `<div class="chat-avatar shrink-0">${avatar}</div>` : ''}
                <div class="chat-bubble ${senderClass} rounded-lg p-3">
                    <div class="text-[11px] uppercase tracking-wide opacity-70 mb-1">${label}</div>
                    <div>${sanitizedMessage}</div>
                    ${translateAction}
                </div>
                ${role === 'user' ? `<div class="chat-avatar shrink-0">${avatar}</div>` : ''}
            </div>
        `);
        $message.find('.chat-bubble').data('raw', message || '');
        $('#chat-log').append($message);
        $('#chat-log').scrollTop($('#chat-log')[0].scrollHeight);
    }
    function addShimmerPlaceholder() {
        const placeholderId = `shimmer-${Date.now()}`;
        $('#chat-log').append(`
            <div id="${placeholderId}" class="mb-4">
                <div class="chat-bubble chat-bubble-assistant rounded-lg p-3 space-y-3">
                    <div class="h-4 w-5/6 rounded bg-gray-700 animate-pulse"></div>
                    <div class="h-4 w-full rounded bg-gray-700 animate-pulse"></div>
                    <div class="h-4 w-3/4 rounded bg-gray-700 animate-pulse"></div>
                </div>
            </div>
        `);
        $('#chat-log').scrollTop($('#chat-log')[0].scrollHeight);
        return placeholderId;
    }
    function pollStatus(jobId) {
        if (jobStatusPollers[jobId]) return;
        jobStatusPollers[jobId] = setInterval(async () => {
            try {
                const response = await fetch(`/status/${jobId}`);
                if (!response.ok) throw new Error('Network response was not ok');
                const data = await response.json();
                const status = data.status || 'unknown';
                updateJobStatusUi(jobId, status);
                if (jobId === currentJobId) renderAnalysisProgress(null);
                if (status === 'done') {
                    clearInterval(jobStatusPollers[jobId]);
                    delete jobStatusPollers[jobId];
                    if (jobId === currentJobId) refreshRecoveryPanel(true, false);
                } else if (status === 'failed') {
                    clearInterval(jobStatusPollers[jobId]);
                    delete jobStatusPollers[jobId];
                }
            } catch (error) {
                console.error("Polling error:", error);
                updateJobStatusUi(jobId, 'failed');
                clearInterval(jobStatusPollers[jobId]);
                delete jobStatusPollers[jobId];
            }
        }, 3000);
    }

    function renderMessage(role, content) {
        if (role === 'tool' || role === 'system') return;
        content = content || '';
        if (content.trim().startsWith('Ghidra function reconstruction context.')) return;
        let html = '';
        if (role === 'user') {
            const cleanContent = content.replace(/^\[Job ID:\s*[^\]]+\]\s*/, '');
            html = `
                <div class="flex justify-end gap-3 mb-4">
                    <div class="chat-bubble chat-bubble-user text-white p-3 rounded-lg">
                        <div class="text-[11px] uppercase tracking-wide opacity-70 mb-1">You</div>
                        ${escapeHtml(cleanContent)}
                        ${translatorEnabled ? '<div class="chat-actions"><button type="button" class="translate-button">Translate</button></div>' : ''}
                    </div>
                    <div class="chat-avatar shrink-0">YOU</div>
                </div>`;
        } else if (role === 'assistant') {
            html = `
                <div class="flex justify-start gap-3 mb-4">
                    <div class="chat-avatar shrink-0">AI</div>
                    <div class="chat-bubble chat-bubble-assistant text-gray-200 p-3 rounded-lg markdown-content">
                        <div class="text-[11px] uppercase tracking-wide text-gray-500 mb-1">Assistant</div>
                        ${marked.parse(content)}
                        ${translatorEnabled ? '<div class="chat-actions"><button type="button" class="translate-button">Translate</button></div>' : ''}
                    </div>
                </div>`;
        }
        const $msg = $(html);
        $msg.find('.chat-bubble').data('raw', role === 'user' ? content.replace(/^\[Job ID:\s*[^\]]+\]\s*/, '') : content);
        $('#chat-log').append($msg);
        $msg.find('code.language-mermaid').each(function(index) {
            const $code = $(this);
            const graphDef = $code.text();
            const $pre = $code.parent();
            const uniqueId = `mermaid-hist-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            $pre.replaceWith(`<div class="mermaid" id="${uniqueId}">${graphDef}</div>`);
            try {
                mermaid.run({ nodes: document.querySelectorAll(`#${uniqueId}`) });
            } catch(e) { console.error("Mermaid error", e); }
        });
        $msg.find('pre code').each(function(i, block) {
            hljs.highlightElement(block);
        });
        $('#chat-log').scrollTop($('#chat-log')[0].scrollHeight);
    }

    function loadJob(jobId) {
        currentJobId = jobId;
        currentRecoveryFile = null;
        currentEditorContent = '';
        currentEditorFile = '';
        recoveredSymbols = [];
        symbolViewFilter = 'all';
        pendingSymbolFocus = null;
        currentFunctionContext = null;
        $('#symbol-search').val('');
        $('.symbol-filter').removeClass('active');
        $('.symbol-filter[data-filter="all"]').addClass('active');
        $('#symbol-navigator').addClass('hidden');
        $('#function-inspector').addClass('hidden').empty();
        $('#chat-log').empty();
        $('#welcome-message').hide();
        $('#workspace-tabs').removeClass('hidden').addClass('flex');
        $('.job-item').removeClass('bg-gray-700');
        $(`#job-${jobId}`).addClass('bg-gray-700');
        $('#chat-input, #chat-form button').prop('disabled', false);
        $('#chat-job-label').text(jobId);
        renderPromptBar();
        showWorkspaceView('chat');
        refreshRecoveryPanel(true, false);
        $.get(`/chat/history/${jobId}`, function(history) {
            if (Array.isArray(history)) {
                history.forEach(msg => {
                    renderMessage(msg.role, msg.content);
                });
            }
            renderConnectedCard(currentJobId);
        });
    }

    function renderConnectedCard(jobId) {
        $('#chat-log').append(`
            <div class="tool-event rounded-lg p-3 mb-4 text-sm text-gray-400">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <div class="text-gray-200 font-medium">Connected to analysis job</div>
                        <div class="font-mono text-xs text-indigo-300 mt-1">${escapeHtml(jobId)}</div>
                    </div>
                    <div class="text-xs text-green-300">ready</div>
                </div>
            </div>
        `);
    }

    function renderPromptBar() {
        const prompts = [
            'List imports and suspicious strings',
            'Find likely main entry and summarize',
            'Reconstruct selected function as VC++ 2003 code',
        ];
        $('#prompt-bar').removeClass('hidden').html(prompts.map(prompt => `
            <button type="button" class="prompt-chip rounded-md px-3 py-2 text-left text-xs text-gray-300">${escapeHtml(prompt)}</button>
        `).join(''));
    }

    $('#upload-form').on('submit', function(e) {
        e.preventDefault();
        if (!selectedUploadFile) {
            showUploadStatus('No file selected.', true);
            return;
        }
        const formData = new FormData();
        formData.append('file', selectedUploadFile);
        $('#analyze-button').prop('disabled', true).text('Analyzing...');
        $('#upload-dropzone').addClass('drag-over');
        showUploadStatus('Uploading binary and starting Ghidra analysis...', false);
        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(data) {
                if (data.error) {
                    showUploadStatus(`ERROR: ${data.error}`, true);
                    return;
                }
                showUploadStatus('Analysis started!', false);
                const { job_id, status } = data;
                const filename = selectedUploadFile.name;
                renderJobItem({ job_id, status, filename }, true);
                pollStatus(job_id);
                setSelectedUploadFile(null);
            },
            error: function(xhr) {
                const error = xhr.responseJSON ? xhr.responseJSON.error : 'Unknown error.';
                showUploadStatus(`UPLOAD FAILED: ${error}`, true);
            },
            complete: function() {
                $('#analyze-button').prop('disabled', false).text('Analyze');
                $('#upload-dropzone').removeClass('drag-over');
            }
        });
    });
    $('#jobs-list').on('click', '.job-item', function() {
        const jobId = $(this).data('job-id');
        loadJob(jobId);
    });
    $('#jobs-list').on('click', '.job-delete', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const jobId = $(this).data('job-id');
        const jobName = $(this).data('job-name') || jobId;
        if (!confirm(`Delete analysis "${jobName}"?\n\nThis removes local artifacts, recovered files, and chat history for this job.`)) return;
        if (jobStatusPollers[jobId]) {
            clearInterval(jobStatusPollers[jobId]);
            delete jobStatusPollers[jobId];
        }
        fetch(`/jobs/${jobId}`, { method: 'DELETE' })
            .then(response => response.text().then(text => {
                let data = {};
                try {
                    data = text ? JSON.parse(text) : {};
                } catch (e) {
                    data = { error: text || response.statusText };
                }
                return { ok: response.ok, status: response.status, data };
            }))
            .then(({ ok, status, data }) => {
                if (!ok || data.error) {
                    showUploadStatus(data.error || `Delete failed: HTTP ${status}.`, true);
                    return;
                }
                $(`#job-${jobId}`).remove();
                showUploadStatus(data.warning || 'Analysis deleted.', false, data.warning ? 'warning' : 'success');
                if (!$('#jobs-list .job-item').length) {
                    renderEmptyJobs('No analysis jobs yet. Upload a binary to start.');
                    setJobsLoading('empty', false);
                }
                if (currentJobId === jobId) {
                    currentJobId = null;
                    $('#chat-log').empty();
                    $('#workspace-tabs').addClass('hidden').removeClass('flex');
                    $('#chat-container').addClass('hidden').removeClass('flex');
                    $('#recovery-panel').addClass('hidden').removeClass('flex');
                    recoveredSymbols = [];
                    symbolViewFilter = 'all';
                    pendingSymbolFocus = null;
                    currentFunctionContext = null;
                    currentEditorContent = '';
                    currentEditorFile = '';
                    $('#symbol-search').val('');
                    $('.symbol-filter').removeClass('active');
                    $('.symbol-filter[data-filter="all"]').addClass('active');
                    $('#symbol-navigator').addClass('hidden');
                    $('#recovery-files, #recovery-summary, #recovery-file-info, #function-inspector, #symbol-list').empty();
                    $('#analysis-progress, #recovery-preview').empty();
                    $('#welcome-message').show();
                    $('#chat-input, #chat-form button').prop('disabled', true);
                }
            })
            .catch(error => showUploadStatus(`Delete failed: ${error.message}`, true));
    });
    $('#workspace-tabs').on('click', '.workspace-tab', function() {
        showWorkspaceView($(this).data('view'));
    });
    $('#settings-open').on('click', openSettingsModal);
    $('#settings-close').on('click', closeSettingsModal);
    $('#settings-modal').on('click', function(e) {
        if (e.target === this) closeSettingsModal();
    });
    $('#settings-reset-form').on('click', loadSettings);
    $('#settings-form').on('submit', function(e) {
        e.preventDefault();
        setSettingsStatus('Saving settings...');
        fetch('/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(collectSettingsPayload()),
        })
            .then(response => response.json().then(data => ({ ok: response.ok, data })))
            .then(({ ok, data }) => {
                if (!ok || data.error) throw new Error(data.error || 'Failed to save settings.');
                setSettingsStatus('Settings saved. New AI requests will use the updated provider.');
                refreshRuntimeConfig();
                loadSettings();
            })
            .catch(error => setSettingsStatus(error.message, true));
    });
    $('#recovery-build').on('click', function() {
        refreshRecoveryPanel(true, true);
    });
    $('#recovery-ai-types').on('click', function() {
        buildAiTypes();
    });
    $('#recovery-ai-renames').on('click', function() {
        buildAiRenames();
    });
    $('#recovery-files').on('click', '.recovery-file', function() {
        openRecoveryFile($(this).data('name'));
    });
    $('#analysis-sidebar-toggle').on('click', function() {
        $('#analysis-workspace').addClass('navigator-collapsed');
        $('#analysis-sidebar-restore').removeClass('hidden');
    });
    $('#analysis-sidebar-restore').on('click', function() {
        $('#analysis-workspace').removeClass('navigator-collapsed');
        $('#analysis-sidebar-restore').addClass('hidden');
    });
    $('#recovery-preview').on('click', '#code-wrap-toggle', function() {
        codeWrapEnabled = !codeWrapEnabled;
        $('#recovery-preview').toggleClass('code-wrap-enabled', codeWrapEnabled);
        $(this).toggleClass('active', codeWrapEnabled);
    });
    $('#recovery-preview').on('click', '#code-focus-toggle', function() {
        $('#recovery-panel').toggleClass('analysis-focus-mode');
        const isFocused = $('#recovery-panel').hasClass('analysis-focus-mode');
        $(this).text(isFocused ? 'Exit Focus' : 'Focus').toggleClass('active', isFocused);
    });
    $('#recovery-preview').on('click', '.code-link', function(e) {
        e.preventDefault();
        inspectFunction($(this).data('address') || $(this).data('symbol'));
    });
    $('#function-inspector').on('click', '.inspector-open-source', function() {
        const fn = currentFunctionContext && currentFunctionContext.function;
        if (!fn) return;
        pendingSymbolFocus = {
            original: fn.original,
            renamed: fn.renamed,
            address: fn.address,
            sourceFile: fn.source_file,
            renamedActive: !!fn.renamed_active,
            inDraft: !!fn.in_draft,
        };
        openRecoveryFile(fn.source_file || 'recovered_functions.cpp', { focusSymbol: pendingSymbolFocus });
    });
    $('#function-inspector').on('click', '.inspector-chip', function() {
        inspectFunction($(this).data('inspect-symbol'));
    });
    $('#function-inspector').on('click', '.inspector-chat', function() {
        const prompt = promptForFunction($(this).data('mode'));
        if (!prompt) return;
        showWorkspaceView('chat');
        $('#chat-input').val(prompt).trigger('input').focus();
    });
    $(document).on('keydown', function(e) {
        if (e.key === 'Escape' && !$('#settings-modal').hasClass('hidden')) {
            closeSettingsModal();
            return;
        }
        if (e.key === 'Escape' && $('#recovery-panel').hasClass('analysis-focus-mode')) {
            $('#recovery-panel').removeClass('analysis-focus-mode');
            $('#code-focus-toggle').text('Focus').removeClass('active');
        }
    });
    $('#symbol-search').on('input', function() {
        renderSymbolNavigator($(this).val());
    });
    $('#symbol-filters').on('click', '.symbol-filter', function() {
        symbolViewFilter = $(this).data('filter') || 'all';
        $('.symbol-filter').removeClass('active');
        $(this).addClass('active');
        renderSymbolNavigator($('#symbol-search').val());
    });
    $('#symbol-list').on('click', '.symbol-row', function() {
        const rowSymbol = symbolFromRow($(this));
        pendingSymbolFocus = rowSymbol;
        renderSymbolNavigator($('#symbol-search').val());
        inspectFunction(rowSymbol.address || rowSymbol.renamed || rowSymbol.original);
    });
    $('#prompt-bar').on('click', '.prompt-chip', function() {
        $('#chat-input').val($(this).text()).trigger('input').focus();
    });
    $('#chat-log').on('click', '.translate-button', function() {
        translateChatMessage($(this));
    });
    $('#chat-input').on('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            $('#chat-form').submit();
        }
    }).on('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
    });
    $('#chat-form').on('submit', function(e) {
        e.preventDefault();
        const $chatInput = $('#chat-input');
        const message = $chatInput.val().trim();
        if (!message || !currentJobId) return;
        addChatMessage('user', message);
        $chatInput.val('').trigger('input');
        $('#chat-input, #chat-form button').prop('disabled', true);
        const placeholderId = addShimmerPlaceholder();
        const $placeholder = $(`#${placeholderId}`);
        const $responseContainer = $placeholder.find('.p-3');

        let fullResponse = "";
        let toolCallsHtml = "";
        fetch('/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ message: message, job_id: currentJobId })
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            $responseContainer.html('<div class="markdown-content"></div><div class="tool-calls"></div>');
            function read() {
                reader.read().then(({ done, value }) => {
                    if (done) {
                        $('#chat-input, #chat-form button').prop('disabled', false);
                        $('#chat-input').focus();
                        $responseContainer.closest('.chat-bubble').data('raw', fullResponse);
                        if (translatorEnabled && !$responseContainer.find('.translate-button').length) {
                            $responseContainer.append('<div class="chat-actions"><button type="button" class="translate-button">Translate</button></div>');
                        }
                        refreshRecoveryPanel(true, false);
                        return;
                    }
                    const chunk = decoder.decode(value, {stream: true});
                    const lines = chunk.split('\n\n').filter(line => line.trim());
                    lines.forEach(line => {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.substring(6));
                                if (data.type === 'token') {
                                    fullResponse += data.content;
                                    const $content = $responseContainer.find('.markdown-content');
                                    $content.html(marked.parse(fullResponse));
                                    $content.find('code.language-mermaid').each(function(index) {
                                        const $code = $(this);
                                        const graphDef = $code.text();
                                        const $pre = $code.parent();
                                        const uniqueId = `mermaid-${Date.now()}-${index}`;
                                        $pre.replaceWith(`<div class="mermaid" id="${uniqueId}">${graphDef}</div>`);
                                        try {
                                           mermaid.run({ nodes: document.querySelectorAll(`#${uniqueId}`) });
                                        } catch(e) { console.error("Mermaid error", e); }
                                    });
                                    $content.find('pre code').each(function(i, block) {
                                        hljs.highlightElement(block);
                                    });
                                } else if (data.type === 'tool_call') {
                                    toolCallsHtml += `<li>${data.description}</li>`;
                                    $responseContainer.find('.tool-calls').html(`
                                        <div class="tool-event text-xs text-gray-400 mt-3 p-3 rounded">
                                            <div class="text-gray-300 font-medium mb-1">Tool activity</div>
                                            <ul class="list-disc pl-4 space-y-1">${toolCallsHtml}</ul>
                                        </div>
                                    `);
                                    if ((data.description || '').includes('Recovered .h/.cpp')) {
                                        refreshRecoveryPanel(false);
                                    }
                                } else if (data.type === 'error') {
                                    $responseContainer.html(`<div class="text-red-400">ERROR: ${data.content}</div>`);
                                }
                            } catch (e) {
                                console.error("Error parsing stream data:", e, "Data:", line);
                            }
                        }
                    });
                    $('#chat-log').scrollTop($('#chat-log')[0].scrollHeight);
                    read();
                });
            }
            read();
        }).catch(err => {
            console.error("Fetch stream error:", err);
            $responseContainer.html(`<div class="text-red-400">FATAL ERROR: Connection to assistant failed.</div>`);
            $('#chat-input, #chat-form button').prop('disabled', false);
        });
    });
});



