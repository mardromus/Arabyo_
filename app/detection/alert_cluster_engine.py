"""Alert Cluster Resolution Engine — groups similar alerts for bulk analyst review.

Clusters alerts by multi-signal similarity (rule context, risk scores, behavioral features,
graph proximity) and enables bulk resolution with full audit traceability.

Design Principles:
 - Never hide individual alerts
 - Clustering is explainable (top similarity drivers stored)
 - Analyst can always drill down
 - No automatic silent closures
 - Full per-alert auditability preserved
"""
import json
import hashlib
import logging
import numpy as np
from datetime import datetime
from collections import Counter
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler

from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────────

CLUSTER_DDL = """
CREATE TABLE IF NOT EXISTS alert_clusters (
    cluster_id      TEXT PRIMARY KEY,
    cluster_size    INTEGER DEFAULT 0,
    mean_risk       REAL DEFAULT 0,
    max_risk        REAL DEFAULT 0,
    min_risk        REAL DEFAULT 0,
    priority_score  REAL DEFAULT 0,
    dominant_rule   TEXT,
    dominant_severity TEXT,
    rule_homogeneity REAL DEFAULT 0,
    time_span_hours REAL DEFAULT 0,
    explanation     TEXT,
    status          TEXT DEFAULT 'open',
    resolved_by     TEXT,
    resolved_at     TEXT,
    resolution      TEXT,
    resolution_notes TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    version         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alert_cluster_members (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id      TEXT NOT NULL,
    alert_id        INTEGER NOT NULL,
    confidence      REAL DEFAULT 1.0,
    is_noise        INTEGER DEFAULT 0,
    UNIQUE(cluster_id, alert_id)
);

CREATE TABLE IF NOT EXISTS cluster_resolutions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id      TEXT NOT NULL,
    action          TEXT NOT NULL,
    performed_by    TEXT DEFAULT 'system',
    performed_at    TEXT DEFAULT (datetime('now')),
    notes           TEXT,
    alerts_affected INTEGER DEFAULT 0,
    before_status   TEXT,
    after_status    TEXT,
    details         TEXT
);

CREATE INDEX IF NOT EXISTS idx_acm_cluster ON alert_cluster_members(cluster_id);
CREATE INDEX IF NOT EXISTS idx_acm_alert ON alert_cluster_members(alert_id);
CREATE INDEX IF NOT EXISTS idx_ac_status ON alert_clusters(status);
CREATE INDEX IF NOT EXISTS idx_ac_priority ON alert_clusters(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_cr_cluster ON cluster_resolutions(cluster_id);
"""


def ensure_cluster_schema():
    """Create cluster tables if they don't exist."""
    conn = get_connection()
    try:
        with conn.cursor() as c:
            for stmt in CLUSTER_DDL.strip().split(';'):
                s = stmt.strip()
                if s:
                    c.execute(s)
        conn.commit()
    finally:
        release_connection(conn)


# ── Priority Weights (configurable) ──────────────────────────────

PRIORITY_WEIGHTS = {
    'mean_risk': 0.35,
    'anomaly_density': 0.25,
    'graph_risk': 0.20,
    'size_weight': 0.20,
}

MAX_CLUSTER_SIZE = 500   # Safety cap
MIN_CLUSTER_SIZE = 3     # Minimum for a meaningful cluster


# ── Alert Clustering Engine ──────────────────────────────────────

class AlertClusterEngine:
    """Clusters alerts by multi-signal similarity for bulk resolution."""

    def __init__(self, n_clusters=None):
        self.n_clusters = n_clusters
        self.scaler = StandardScaler()

    def run(self, target_clusters=None):
        """Run full alert clustering pipeline.

        1. Load all pending alerts
        2. Build feature vectors
        3. Cluster with KMeans
        4. Compute cluster metadata + explainability
        5. Persist clusters

        Returns: dict with cluster_count, alert_count, noise_count
        """
        ensure_cluster_schema()

        # Load alerts
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, account_id, rule_score, ml_score, graph_score,
                           fusion_score, severity, triggered_rules, explanation
                    FROM alerts
                    WHERE status = 'pending'
                    ORDER BY fusion_score DESC
                """)
                alerts = [dict(r) for r in cur.fetchall()]
        finally:
            release_connection(conn)

        if not alerts:
            return {'cluster_count': 0, 'alert_count': 0, 'noise_count': 0}

        print(f"[AlertCluster] Clustering {len(alerts):,} alerts...")

        # Build feature matrix
        features, alert_ids = self._build_features(alerts)

        if len(features) < MIN_CLUSTER_SIZE:
            return {'cluster_count': 0, 'alert_count': len(alerts), 'noise_count': 0}

        # Determine optimal k
        n = len(features)
        if target_clusters:
            k = target_clusters
        elif self.n_clusters:
            k = self.n_clusters
        else:
            # Heuristic: sqrt(N/2), capped
            k = max(10, min(200, int(np.sqrt(n / 2))))

        k = min(k, n // MIN_CLUSTER_SIZE)

        # Scale features
        X = self.scaler.fit_transform(features)

        # Cluster
        print(f"[AlertCluster] KMeans with k={k}...")
        kmeans = MiniBatchKMeans(n_clusters=k, random_state=42, batch_size=1024, n_init=3)
        labels = kmeans.fit_predict(X)

        # Compute distances for confidence scores
        distances = kmeans.transform(X)
        min_distances = distances.min(axis=1)
        max_dist = min_distances.max() + 1e-8
        confidences = 1.0 - (min_distances / max_dist)

        # Identify noise (low-confidence outliers)
        noise_threshold = np.percentile(confidences, 5)
        is_noise = confidences < noise_threshold

        # Build cluster metadata
        clusters = {}
        for i, (alert_id, label, conf, noise) in enumerate(
                zip(alert_ids, labels, confidences, is_noise)):
            cid = f"CLU-{label:04d}"
            if cid not in clusters:
                clusters[cid] = {
                    'members': [],
                    'alerts_data': [],
                }
            clusters[cid]['members'].append({
                'alert_id': alert_id,
                'confidence': float(conf),
                'is_noise': bool(noise),
            })
            clusters[cid]['alerts_data'].append(alerts[i])

        # Compute per-cluster metadata and explainability
        cluster_records = []
        for cid, data in clusters.items():
            meta = self._compute_cluster_metadata(cid, data)
            cluster_records.append(meta)

        # Persist
        self._save_clusters(cluster_records, clusters)

        noise_count = int(is_noise.sum())
        print(f"[AlertCluster] Created {len(cluster_records)} clusters, "
              f"{noise_count} noise alerts, "
              f"avg size {len(alerts) / max(len(cluster_records), 1):.1f}")

        return {
            'cluster_count': len(cluster_records),
            'alert_count': len(alerts),
            'noise_count': noise_count,
        }

    def _build_features(self, alerts):
        """Build numerical feature matrix from alerts."""
        features = []
        alert_ids = []

        # Encode severity as numeric
        sev_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

        # Collect all unique rule IDs for one-hot encoding
        all_rules = set()
        for a in alerts:
            rules = json.loads(a.get('triggered_rules', '[]')) if a.get('triggered_rules') else []
            all_rules.update(rules)
        rule_list = sorted(all_rules)
        rule_idx = {r: i for i, r in enumerate(rule_list)}

        for a in alerts:
            # Core scores
            vec = [
                a.get('rule_score', 0),
                a.get('ml_score', 0),
                a.get('graph_score', 0),
                a.get('fusion_score', 0),
                sev_map.get(a.get('severity', 'low'), 1),
            ]

            # Cluster context from explanation
            expl = {}
            if a.get('explanation'):
                try:
                    expl = json.loads(a['explanation'])
                except (json.JSONDecodeError, TypeError):
                    pass

            vec.extend([
                expl.get('cluster_risk', 0),
                expl.get('cluster_size', 0) / 1000.0,  # Normalize
                1.0 if expl.get('network_flag') else 0.0,
            ])

            # Rule one-hot (sparse but informative)
            rule_vec = [0.0] * min(len(rule_list), 30)  # Cap at 30 rule features
            rules = json.loads(a.get('triggered_rules', '[]')) if a.get('triggered_rules') else []
            for r in rules:
                idx = rule_idx.get(r)
                if idx is not None and idx < 30:
                    rule_vec[idx] = 1.0
            vec.extend(rule_vec)

            features.append(vec)
            alert_ids.append(a['id'])

        return np.array(features, dtype=np.float64), alert_ids

    def _compute_cluster_metadata(self, cid, data):
        """Compute cluster-level risk scores, priority, and explainability."""
        alerts_data = data['alerts_data']
        members = data['members']

        # Risk scores
        fusions = [a.get('fusion_score', 0) for a in alerts_data]
        rules_scores = [a.get('rule_score', 0) for a in alerts_data]
        ml_scores = [a.get('ml_score', 0) for a in alerts_data]
        graph_scores = [a.get('graph_score', 0) for a in alerts_data]
        severities = [a.get('severity', 'low') for a in alerts_data]

        mean_risk = np.mean(fusions)
        max_risk = np.max(fusions)
        min_risk = np.min(fusions)

        # Rule analysis
        all_rules = []
        for a in alerts_data:
            rules = json.loads(a.get('triggered_rules', '[]')) if a.get('triggered_rules') else []
            all_rules.extend(rules)
        rule_counts = Counter(all_rules)
        dominant_rule = rule_counts.most_common(1)[0][0] if rule_counts else 'none'
        rule_homogeneity = (rule_counts.most_common(1)[0][1] / max(len(alerts_data), 1)
                            if rule_counts else 0)

        # Severity analysis
        sev_counts = Counter(severities)
        dominant_severity = sev_counts.most_common(1)[0][0]

        # Anomaly density (fraction above 0.5 fusion)
        anomaly_density = sum(1 for f in fusions if f > 0.5) / max(len(fusions), 1)

        # Graph risk concentration
        graph_risk = np.mean(graph_scores) if graph_scores else 0

        # Size weight (larger clusters more important, diminishing returns)
        size_weight = min(1.0, np.log1p(len(alerts_data)) / 5.0)

        # Priority score
        priority = (
            PRIORITY_WEIGHTS['mean_risk'] * mean_risk +
            PRIORITY_WEIGHTS['anomaly_density'] * anomaly_density +
            PRIORITY_WEIGHTS['graph_risk'] * graph_risk +
            PRIORITY_WEIGHTS['size_weight'] * size_weight
        )

        # Accounts analysis
        accounts = [a.get('account_id', '') for a in alerts_data]
        unique_accounts = list(set(accounts))
        top_accounts = Counter(accounts).most_common(5)

        # Explainability — why these alerts are grouped
        reasons = []
        if rule_homogeneity > 0.7:
            reasons.append(f"{rule_homogeneity*100:.0f}% share rule '{dominant_rule}'")
        if anomaly_density > 0.5:
            reasons.append(f"High anomaly density ({anomaly_density*100:.0f}%)")
        if len(unique_accounts) < len(alerts_data) * 0.5:
            reasons.append(f"Concentrated in {len(unique_accounts)} accounts")

        avg_conf = np.mean([m['confidence'] for m in members])
        if avg_conf > 0.8:
            reasons.append(f"High embedding similarity ({avg_conf:.0%})")

        sev_pct = sev_counts.most_common(1)[0][1] / len(alerts_data)
        if sev_pct > 0.8:
            reasons.append(f"{sev_pct*100:.0f}% are {dominant_severity} severity")

        if graph_risk > 0.3:
            reasons.append(f"Elevated graph risk ({graph_risk:.2f})")

        if not reasons:
            reasons.append("Similar risk profile and feature space proximity")

        return {
            'cluster_id': cid,
            'cluster_size': len(alerts_data),
            'mean_risk': round(mean_risk, 4),
            'max_risk': round(max_risk, 4),
            'min_risk': round(min_risk, 4),
            'priority_score': round(priority, 4),
            'dominant_rule': dominant_rule,
            'dominant_severity': dominant_severity,
            'rule_homogeneity': round(rule_homogeneity, 4),
            'explanation': json.dumps({
                'cluster_reason': reasons,
                'rule_distribution': dict(rule_counts.most_common(5)),
                'severity_distribution': dict(sev_counts),
                'top_accounts': [{'account': a, 'count': c} for a, c in top_accounts],
                'unique_accounts': len(unique_accounts),
                'anomaly_density': round(anomaly_density, 4),
                'graph_risk': round(graph_risk, 4),
                'avg_confidence': round(avg_conf, 4),
            }),
            'members': members,
        }

    def _save_clusters(self, cluster_records, clusters_data):
        """Persist clusters and membership to database."""
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Clear previous clusters
                cur.execute("DELETE FROM alert_cluster_members")
                cur.execute("DELETE FROM alert_clusters WHERE status = 'open'")

                for rec in cluster_records:
                    cur.execute("""
                        INSERT INTO alert_clusters
                        (cluster_id, cluster_size, mean_risk, max_risk, min_risk,
                         priority_score, dominant_rule, dominant_severity,
                         rule_homogeneity, explanation, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open')
                        ON CONFLICT (cluster_id) DO UPDATE SET
                            cluster_size = EXCLUDED.cluster_size,
                            mean_risk = EXCLUDED.mean_risk,
                            max_risk = EXCLUDED.max_risk,
                            priority_score = EXCLUDED.priority_score,
                            explanation = EXCLUDED.explanation
                    """, [
                        rec['cluster_id'], rec['cluster_size'],
                        rec['mean_risk'], rec['max_risk'], rec['min_risk'],
                        rec['priority_score'], rec['dominant_rule'],
                        rec['dominant_severity'], rec['rule_homogeneity'],
                        rec['explanation'],
                    ])

                    for m in rec['members']:
                        cur.execute("""
                            INSERT INTO alert_cluster_members
                            (cluster_id, alert_id, confidence, is_noise)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (cluster_id, alert_id) DO NOTHING
                        """, [rec['cluster_id'], m['alert_id'],
                              m['confidence'], 1 if m['is_noise'] else 0])

            conn.commit()
            print(f"[AlertCluster] Saved {len(cluster_records)} clusters to database")
        finally:
            release_connection(conn)


# ── Cluster Resolution ────────────────────────────────────────────

class ClusterResolution:
    """Handles bulk alert resolution at cluster level with full audit trail."""

    ALLOWED_ACTIONS = {'confirm', 'dismiss', 'escalate', 'split', 'mark_partial'}

    @staticmethod
    def resolve_cluster(cluster_id, action, performed_by='analyst',
                        notes='', alert_overrides=None):
        """Resolve all alerts in a cluster with a single action.

        Args:
            cluster_id: which cluster
            action: confirm | dismiss | escalate | split | mark_partial
            performed_by: analyst identifier
            notes: resolution notes
            alert_overrides: dict {alert_id: override_action} for partial resolution

        Returns: dict with success, alerts_affected
        """
        if action not in ClusterResolution.ALLOWED_ACTIONS:
            return {'success': False, 'error': f'Invalid action. Allowed: {ClusterResolution.ALLOWED_ACTIONS}'}

        conn = get_connection()
        try:
            # Get cluster
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM alert_clusters WHERE cluster_id = %s", [cluster_id])
                cluster = cur.fetchone()
            if not cluster:
                return {'success': False, 'error': 'Cluster not found'}

            before_status = cluster['status']

            # Map action to alert status
            alert_status_map = {
                'confirm': 'confirmed',
                'dismiss': 'dismissed',
                'escalate': 'escalated',
                'split': 'pending',       # Split doesn't change alert status
                'mark_partial': 'pending', # Handled per-alert via overrides
            }
            new_alert_status = alert_status_map[action]

            # Get member alerts
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT alert_id FROM alert_cluster_members
                    WHERE cluster_id = %s
                """, [cluster_id])
                member_ids = [r['alert_id'] for r in cur.fetchall()]

            if not member_ids:
                return {'success': False, 'error': 'Cluster has no members'}

            # Apply resolution to individual alerts
            now = datetime.now().isoformat()
            affected = 0

            with conn.cursor() as cur:
                for aid in member_ids:
                    # Check for per-alert override
                    effective_action = action
                    effective_status = new_alert_status
                    if alert_overrides and str(aid) in alert_overrides:
                        override = alert_overrides[str(aid)]
                        effective_action = override
                        effective_status = alert_status_map.get(override, new_alert_status)

                    if effective_status != 'pending':
                        cur.execute("""
                            UPDATE alerts
                            SET status = %s, reviewed_by = %s, reviewed_at = %s,
                                review_action = %s, review_notes = %s
                            WHERE id = %s AND status = 'pending'
                        """, [effective_status, performed_by, now,
                              effective_action, f"Cluster {cluster_id}: {notes}",
                              aid])
                        affected += cur.rowcount

                # Update cluster status
                cluster_status = 'resolved' if action != 'split' else 'split'
                cur.execute("""
                    UPDATE alert_clusters
                    SET status = %s, resolved_by = %s, resolved_at = %s,
                        resolution = %s, resolution_notes = %s
                    WHERE cluster_id = %s
                """, [cluster_status, performed_by, now, action, notes, cluster_id])

                # Audit log
                cur.execute("""
                    INSERT INTO cluster_resolutions
                    (cluster_id, action, performed_by, notes,
                     alerts_affected, before_status, after_status, details)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, [cluster_id, action, performed_by, notes,
                      affected, before_status, cluster_status,
                      json.dumps({
                          'member_count': len(member_ids),
                          'overrides': alert_overrides or {},
                      })])

            conn.commit()

            return {
                'success': True,
                'cluster_id': cluster_id,
                'action': action,
                'alerts_affected': affected,
                'total_members': len(member_ids),
            }
        finally:
            release_connection(conn)

    @staticmethod
    def split_cluster(cluster_id, group_a_ids, group_b_ids,
                      performed_by='analyst', reason=''):
        """Split a cluster into two new clusters.

        Never deletes — creates two new clusters from the original.
        """
        conn = get_connection()
        try:
            # Verify original cluster
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM alert_clusters WHERE cluster_id = %s", [cluster_id])
                original = cur.fetchone()
            if not original:
                return {'success': False, 'error': 'Cluster not found'}

            new_cid_a = f"{cluster_id}-A"
            new_cid_b = f"{cluster_id}-B"

            with conn.cursor() as cur:
                # Create two new clusters (copies of original metadata, will be recomputed)
                for new_cid, member_ids in [(new_cid_a, group_a_ids), (new_cid_b, group_b_ids)]:
                    cur.execute("""
                        INSERT INTO alert_clusters
                        (cluster_id, cluster_size, mean_risk, max_risk, min_risk,
                         priority_score, dominant_rule, dominant_severity,
                         rule_homogeneity, explanation, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open')
                    """, [new_cid, len(member_ids),
                          original['mean_risk'], original['max_risk'], original['min_risk'],
                          original['priority_score'], original['dominant_rule'],
                          original['dominant_severity'], original['rule_homogeneity'],
                          json.dumps({'split_from': cluster_id, 'reason': reason})])

                    for aid in member_ids:
                        cur.execute("""
                            INSERT INTO alert_cluster_members (cluster_id, alert_id, confidence)
                            VALUES (%s, %s, 1.0)
                        """, [new_cid, aid])

                # Mark original as split
                cur.execute("""
                    UPDATE alert_clusters SET status = 'split',
                        resolution_notes = %s
                    WHERE cluster_id = %s
                """, [f"Split into {new_cid_a} and {new_cid_b}: {reason}", cluster_id])

                # Audit
                cur.execute("""
                    INSERT INTO cluster_resolutions
                    (cluster_id, action, performed_by, notes, alerts_affected, details)
                    VALUES (%s, 'split', %s, %s, %s, %s)
                """, [cluster_id, performed_by, reason, len(group_a_ids) + len(group_b_ids),
                      json.dumps({'new_a': new_cid_a, 'new_b': new_cid_b,
                                  'group_a_size': len(group_a_ids),
                                  'group_b_size': len(group_b_ids)})])

            conn.commit()
            return {
                'success': True,
                'original': cluster_id,
                'cluster_a': new_cid_a,
                'cluster_b': new_cid_b,
            }
        finally:
            release_connection(conn)


# ── Query Helpers ─────────────────────────────────────────────────

def list_clusters(status='open', limit=50, offset=0):
    """List alert clusters sorted by priority."""
    ensure_cluster_schema()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if status == 'all':
                cur.execute("""
                    SELECT * FROM alert_clusters
                    ORDER BY priority_score DESC
                    LIMIT %s OFFSET %s
                """, [limit, offset])
            else:
                cur.execute("""
                    SELECT * FROM alert_clusters
                    WHERE status = %s
                    ORDER BY priority_score DESC
                    LIMIT %s OFFSET %s
                """, [status, limit, offset])
            rows = cur.fetchall()

        result = []
        for r in rows:
            d = dict(r)
            if d.get('explanation'):
                try:
                    d['explanation'] = json.loads(d['explanation'])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result
    finally:
        release_connection(conn)


def get_cluster_detail(cluster_id):
    """Get cluster detail with member alerts."""
    ensure_cluster_schema()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alert_clusters WHERE cluster_id = %s", [cluster_id])
            cluster = cur.fetchone()
            if not cluster:
                return None

            result = dict(cluster)
            if result.get('explanation'):
                try:
                    result['explanation'] = json.loads(result['explanation'])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Get member alerts with full details
            cur.execute("""
                SELECT acm.alert_id, acm.confidence, acm.is_noise,
                       a.account_id, a.rule_score, a.ml_score, a.graph_score,
                       a.fusion_score, a.severity, a.status, a.triggered_rules
                FROM alert_cluster_members acm
                JOIN alerts a ON a.id = acm.alert_id
                WHERE acm.cluster_id = %s
                ORDER BY a.fusion_score DESC
            """, [cluster_id])
            members = []
            for m in cur.fetchall():
                md = dict(m)
                if md.get('triggered_rules'):
                    try:
                        md['triggered_rules'] = json.loads(md['triggered_rules'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                members.append(md)
            result['members'] = members

        return result
    finally:
        release_connection(conn)


def get_cluster_metrics():
    """Get cluster system metrics for monitoring dashboard."""
    ensure_cluster_schema()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Total clusters
            cur.execute("SELECT COUNT(*) as cnt FROM alert_clusters")
            total = cur.fetchone()['cnt']

            # By status
            cur.execute("SELECT status, COUNT(*) as cnt FROM alert_clusters GROUP BY status")
            by_status = {r['status']: r['cnt'] for r in cur.fetchall()}

            # Average cluster size
            cur.execute("SELECT AVG(cluster_size) as avg_size, MAX(cluster_size) as max_size FROM alert_clusters")
            sizes = cur.fetchone()

            # Total alerts clustered
            cur.execute("SELECT COUNT(DISTINCT alert_id) as cnt FROM alert_cluster_members")
            alerts_clustered = cur.fetchone()['cnt']

            # Noise ratio
            cur.execute("SELECT COUNT(*) as cnt FROM alert_cluster_members WHERE is_noise = 1")
            noise = cur.fetchone()['cnt']

            # Resolution stats
            cur.execute("""
                SELECT action, COUNT(*) as cnt, SUM(alerts_affected) as total_affected
                FROM cluster_resolutions
                GROUP BY action
            """)
            resolution_stats = {r['action']: {'count': r['cnt'], 'alerts': r['total_affected'] or 0}
                                for r in cur.fetchall()}

            # Cluster purity (rule homogeneity)
            cur.execute("SELECT AVG(rule_homogeneity) as avg_purity FROM alert_clusters")
            purity = cur.fetchone()['avg_purity'] or 0

            return {
                'total_clusters': total,
                'by_status': by_status,
                'avg_cluster_size': round(sizes['avg_size'] or 0, 1),
                'max_cluster_size': sizes['max_size'] or 0,
                'alerts_clustered': alerts_clustered,
                'noise_count': noise,
                'noise_ratio': round(noise / max(alerts_clustered, 1), 4),
                'resolution_stats': resolution_stats,
                'avg_cluster_purity': round(purity, 4),
                'workload_reduction': f"{(1 - total / max(alerts_clustered, 1)) * 100:.0f}%"
                    if alerts_clustered > 0 and total > 0 else "0%",
            }
    finally:
        release_connection(conn)


def get_resolution_history(cluster_id=None, limit=50):
    """Get resolution audit trail."""
    ensure_cluster_schema()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if cluster_id:
                cur.execute("""
                    SELECT * FROM cluster_resolutions
                    WHERE cluster_id = %s ORDER BY performed_at DESC LIMIT %s
                """, [cluster_id, limit])
            else:
                cur.execute("""
                    SELECT * FROM cluster_resolutions
                    ORDER BY performed_at DESC LIMIT %s
                """, [limit])
            rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get('details'):
                try:
                    d['details'] = json.loads(d['details'])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result
    finally:
        release_connection(conn)
