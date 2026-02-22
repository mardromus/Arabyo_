/**
 * Rule Sets UI — activate, compare, snapshot
 */
(function () {
    function getRole() {
        var el = document.body && document.body.getAttribute('data-role');
        return el || 'analyst';
    }

    // Activate button (list page)
    document.querySelectorAll('.activate-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = this.getAttribute('data-ruleset-id');
            if (!id) return;
            if (!confirm('Activate this rule set? It will supersede the current active set for this policy.')) return;
            var role = getRole();
            var activateUrl = '/api/rulesets/' + encodeURIComponent(id) + '/activate';
            if (role && role !== 'analyst') {
                activateUrl += '?role=' + encodeURIComponent(role);
            }
            fetch(activateUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d.error) alert(d.error);
                    else window.location.reload();
                })
                .catch(function () { alert('Request failed'); });
        });
    });

    // Compare link: prefill id1 when clicking "Compare" on a row
    document.querySelectorAll('.compare-link').forEach(function (a) {
        a.addEventListener('click', function (e) {
            var id = this.getAttribute('data-ruleset-id');
            var id1 = document.getElementById('diff-id1');
            if (id1) id1.value = id;
        });
    });
})();
