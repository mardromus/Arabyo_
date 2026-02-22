(function () {
    var form = document.getElementById('simulationForm');
    var runBtn = document.getElementById('runBtn');
    var simProgress = document.getElementById('simProgress');
    var simError = document.getElementById('simError');

    function getRole() {
        var el = document.body && document.body.getAttribute('data-role');
        return el || 'analyst';
    }

    function loadHistory() {
        var el = document.getElementById('historyList');
        if (!el) return;
        var role = getRole();
        var histUrl = '/api/simulation/history';
        if (role && role !== 'analyst') {
            histUrl += '?role=' + encodeURIComponent(role);
        }
        fetch(histUrl)
            .then(function (r) { return r.json(); })
            .then(function (d) {
                var runs = d.runs || [];
                if (runs.length === 0) {
                    el.innerHTML = '<p class="empty-state">No runs yet.</p>';
                    return;
                }
                el.innerHTML = '<table class="data-table"><thead><tr><th>Date</th><th>Ruleset</th><th>Period</th><th>Baseline</th><th>Simulated</th><th></th></tr></thead><tbody>' +
                    runs.map(function (r) {
                        return '<tr>' +
                            '<td>' + (r.created_at || '').slice(0, 16) + '</td>' +
                            '<td class="mono">' + (r.ruleset_id || '') + '</td>' +
                            '<td>' + (r.start_date || '') + ' to ' + (r.end_date || '') + '</td>' +
                            '<td>' + (r.baseline_alerts || 0) + '</td>' +
                            '<td>' + (r.simulated_alerts || 0) + '</td>' +
                            '<td><a href="/simulation/results/' + (r.simulation_id || '') + '" class="btn btn-sm">View</a></td>' +
                            '</tr>';
                    }).join('') +
                    '</tbody></table>';
            })
            .catch(function () { el.innerHTML = '<p>Failed to load history.</p>'; });
    }

    if (form) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            simError.style.display = 'none';
            simProgress.style.display = 'flex';
            runBtn.disabled = true;
            var payload = {
                ruleset_id: document.getElementById('ruleset_id').value,
                start_date: document.getElementById('start_date').value,
                end_date: document.getElementById('end_date').value,
                include_ml: document.getElementById('include_ml').checked,
                include_graph: document.getElementById('include_graph').checked
            };
            var role = getRole();
            var runUrl = '/api/simulation/run';
            if (role && role !== 'analyst') {
                runUrl += '?role=' + encodeURIComponent(role);
            }
            fetch(runUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
                .then(function (r) {
                    if (!r.ok) return r.json().then(function (d) { throw new Error(d.error || 'Failed'); });
                    return r.json();
                })
                .then(function (d) {
                    if (d.simulation_id) {
                        window.location.href = '/simulation/results/' + d.simulation_id;
                    } else {
                        simError.textContent = 'Unexpected response';
                        simError.style.display = 'block';
                    }
                })
                .catch(function (err) {
                    simError.textContent = err.message || 'Request failed';
                    simError.style.display = 'block';
                })
                .finally(function () {
                    simProgress.style.display = 'none';
                    runBtn.disabled = false;
                });
        });
    }

    loadHistory();
})();
