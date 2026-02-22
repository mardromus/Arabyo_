/* Dashboard JavaScript — Silent B/W Theme */
document.addEventListener('DOMContentLoaded', function () {
    console.log('[Arabyo] Dashboard loaded — Silent B/W Theme');

    // Global Chart.js defaults for monochrome
    if (window.Chart) {
        Chart.defaults.color = '#555555';
        Chart.defaults.borderColor = 'rgba(255,255,255,0.04)';
        Chart.defaults.font.family = 'Inter, system-ui, sans-serif';
        Chart.defaults.font.size = 10;
    }

    // Role-based URL persistence: append role to all internal links
    const currentRole = document.body.dataset.role;
    if (currentRole && currentRole !== 'analyst') {
        document.querySelectorAll('a[href^="/"]').forEach(link => {
            const url = new URL(link.href, window.location.origin);
            if (!url.searchParams.has('role')) {
                url.searchParams.set('role', currentRole);
                link.href = url.pathname + url.search;
            }
        });

        // Also update form actions
        document.querySelectorAll('form[action^="/"]').forEach(form => {
            const url = new URL(form.action, window.location.origin);
            if (!url.searchParams.has('role')) {
                url.searchParams.set('role', currentRole);
                form.action = url.pathname + url.search;
            }
        });
    }

    // Full-dataset pipeline (background) status and trigger
    const statusEl = document.getElementById('full-pipeline-status');
    const messageEl = document.getElementById('full-pipeline-message');
    const runFullBtn = document.getElementById('run-full-pipeline-btn');
    let pipelinePollTimer = null;

    function renderPipelineStatus(data) {
        if (!statusEl || !data) return;
        if (data.running) {
            const started = (data.current_run && data.current_run.started_at) ? data.current_run.started_at.slice(0, 19) : '';
            statusEl.textContent = 'Full pipeline running (started at ' + started + '). Check back for completion.';
            statusEl.style.color = '';
            if (!pipelinePollTimer) pipelinePollTimer = setInterval(fetchPipelineStatus, 5000);
        } else {
            if (pipelinePollTimer) { clearInterval(pipelinePollTimer); pipelinePollTimer = null; }
            if (data.last_run && data.last_run.completed_at) {
                const r = data.last_run;
                const txn = r.transactions_scanned != null ? r.transactions_scanned.toLocaleString() : '0';
                const alerts = r.alerts_generated != null ? r.alerts_generated.toLocaleString() : '0';
                statusEl.textContent = 'Last full pipeline: completed ' + r.completed_at.slice(0, 19) + ' — ' + txn + ' txn, ' + alerts + ' alerts.';
            } else {
                statusEl.textContent = '';
            }
            statusEl.style.color = '';
        }
    }

    function fetchPipelineStatus() {
        let statusUrl = '/api/pipeline/status';
        if (currentRole && currentRole !== 'analyst') {
            statusUrl += '?role=' + encodeURIComponent(currentRole);
        }
        fetch(statusUrl, { credentials: 'same-origin' })
            .then(function (res) { return res.json(); })
            .then(renderPipelineStatus)
            .catch(function () { if (statusEl) statusEl.textContent = ''; });
    }

    if (statusEl) fetchPipelineStatus();

    if (runFullBtn) {
        runFullBtn.addEventListener('click', function () {
            if (messageEl) messageEl.textContent = 'Starting…';
            runFullBtn.disabled = true;
            let runUrl = '/api/pipeline/run-full';
            if (currentRole && currentRole !== 'analyst') {
                runUrl += '?role=' + encodeURIComponent(currentRole);
            }
            fetch(runUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            })
                .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
                .then(function (r) {
                    if (r.status === 202) {
                        if (messageEl) messageEl.textContent = 'Full pipeline started. Check status below.';
                        fetchPipelineStatus();
                    } else if (r.status === 409) {
                        if (messageEl) messageEl.textContent = 'A full pipeline run is already in progress.';
                    } else {
                        if (messageEl) messageEl.textContent = r.body.message || r.body.error || 'Request failed.';
                    }
                })
                .catch(function () { if (messageEl) messageEl.textContent = 'Request failed.'; })
                .finally(function () {
                    runFullBtn.disabled = false;
                    setTimeout(function () { if (messageEl) messageEl.textContent = ''; }, 8000);
                });
        });
    }
});
