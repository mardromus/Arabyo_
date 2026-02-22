"""Risk fusion engine — combines rule, ML, graph, and cluster signals into unified alert scores.

Includes an AdaptiveAlertController that uses quantile-based thresholding
to reliably target a configurable alert volume (~10K by default).
"""
import json
import numpy as np
from datetime import datetime
from app.db import get_connection, release_connection
from app.config import ALERT_THRESHOLD, TARGET_ALERT_VOLUME, CLUSTER_RISK_BOOST


class FusionEngine:
    """Merges signals from all detection engines into a unified risk score."""

    WEIGHTS = {
        'rule': 0.40,
        'ml': 0.35,
        'graph': 0.25,
    }

    def __init__(self):
        self.alerts = []

    def fuse(self, rule_violations, ml_risks, graph_risks,
             cluster_info=None, target_alerts=None):
        """Combine all detection signals into unified alerts.

        Args:
            rule_violations: list of dicts from RuleEngine.evaluate_all()
            ml_risks: DataFrame with account_id + ml_risk from MLEngine
            graph_risks: dict from GraphEngine.analyze()
            cluster_info: DataFrame with account_id, cluster_id, cluster_risk, network_flag
            target_alerts: override for TARGET_ALERT_VOLUME

        Returns:
            List of alert dicts, sorted by fusion_score descending
        """
        target = target_alerts or TARGET_ALERT_VOLUME

        print(f"[Fusion] Combining {len(rule_violations)} rule violations, "
              f"{ml_risks.shape[0] if ml_risks is not None and hasattr(ml_risks, 'shape') else 0} ML scores, "
              f"{len(graph_risks) if graph_risks else 0} graph scores")

        # Index ML risks by account_id
        ml_index = {}
        if ml_risks is not None and hasattr(ml_risks, 'empty') and not ml_risks.empty:
            for _, row in ml_risks.iterrows():
                ml_index[row['account_id']] = float(row.get('ml_risk', 0))

        # Index cluster info
        cluster_index = {}
        if cluster_info is not None and hasattr(cluster_info, 'empty') and not cluster_info.empty:
            for _, row in cluster_info.iterrows():
                cluster_index[row['account_id']] = {
                    'cluster_id': int(row.get('cluster_id', 0)),
                    'cluster_risk': float(row.get('cluster_risk', 0)),
                    'cluster_size': int(row.get('cluster_size', 0)),
                    'network_flag': bool(row.get('network_flag', False)),
                }

        # Collect all unique accounts from all sources
        all_accounts = set()

        # From rule violations
        rule_account_scores = {}
        rule_account_evidence = {}
        for v in rule_violations:
            acct = v.get('evidence', {}).get('account') or v.get('evidence', {}).get('from_account', '')
            if not acct:
                continue
            all_accounts.add(acct)

            if acct not in rule_account_scores:
                rule_account_scores[acct] = 0
                rule_account_evidence[acct] = []

            rule_account_scores[acct] = max(rule_account_scores[acct], v.get('rule_score', 0))
            rule_account_evidence[acct].append({
                'rule_id': v.get('rule_id', ''),
                'rule_name': v.get('rule_name', ''),
                'severity': v.get('severity', 'medium'),
                'evidence': v.get('evidence', {}),
                'transaction_id': v.get('transaction_id'),
            })

        all_accounts.update(ml_index.keys())
        all_accounts.update(graph_risks.keys())

        # Compute raw fusion scores for ALL accounts
        account_scores = {}
        for acct in all_accounts:
            rule_score = rule_account_scores.get(acct, 0)
            ml_score = ml_index.get(acct, 0)
            graph_val = (graph_risks or {}).get(acct)
            if isinstance(graph_val, dict):
                graph_score = graph_val.get('risk_score', 0)
            elif isinstance(graph_val, (int, float)):
                graph_score = float(graph_val)
            else:
                graph_score = 0

            fusion_score = (
                self.WEIGHTS['rule'] * rule_score +
                self.WEIGHTS['ml'] * ml_score +
                self.WEIGHTS['graph'] * graph_score
            )

            # Cluster boost
            ci = cluster_index.get(acct)
            if ci and ci.get('network_flag'):
                fusion_score += CLUSTER_RISK_BOOST * ci['cluster_risk']
                fusion_score = min(1.0, fusion_score)

            account_scores[acct] = {
                'rule_score': rule_score,
                'ml_score': ml_score,
                'graph_score': graph_score,
                'fusion_score': fusion_score,
                'cluster_info': ci or {},
            }

        # Adaptive threshold: quantile-based cutoff to hit target alert volume
        all_fusion = np.array([v['fusion_score'] for v in account_scores.values()])

        if len(all_fusion) > 0 and target > 0:
            # Dynamic cutoff: pick the quantile that gives us ~target alerts
            quantile = max(0.0, 1.0 - target / len(all_fusion))
            dynamic_threshold = np.quantile(all_fusion, quantile)
            # Apply risk floor
            effective_threshold = max(ALERT_THRESHOLD, dynamic_threshold)
        else:
            effective_threshold = ALERT_THRESHOLD

        print(f"[Fusion] Adaptive threshold: {effective_threshold:.4f} "
              f"(target={target:,}, total_accounts={len(all_fusion):,})")

        # Generate alerts for accounts above threshold
        alerts = []
        for acct, scores in account_scores.items():
            if scores['fusion_score'] < effective_threshold:
                continue

            ci = scores['cluster_info']
            severity = self._classify_severity(
                scores['fusion_score'], scores['rule_score'],
                scores['ml_score'], scores['graph_score']
            )

            triggered = [e['rule_id'] for e in rule_account_evidence.get(acct, [])]

            alerts.append({
                'account_id': acct,
                'rule_score': round(scores['rule_score'], 4),
                'ml_score': round(scores['ml_score'], 4),
                'graph_score': round(scores['graph_score'], 4),
                'fusion_score': round(scores['fusion_score'], 4),
                'severity': severity,
                'triggered_rules': triggered,
                'rule_evidence': rule_account_evidence.get(acct, []),
                'graph_data': graph_risks.get(acct, {}),
                'cluster_id': ci.get('cluster_id', -1),
                'cluster_risk': ci.get('cluster_risk', 0),
                'cluster_size': ci.get('cluster_size', 0),
                'network_flag': ci.get('network_flag', False),
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
            })

        # Sort by fusion score
        alerts.sort(key=lambda x: x['fusion_score'], reverse=True)
        self.alerts = alerts

        print(f"[Fusion] Generated {len(alerts):,} alerts above threshold {effective_threshold:.4f}")

        # Severity breakdown
        sev_counts = {}
        for a in alerts:
            sev_counts[a['severity']] = sev_counts.get(a['severity'], 0) + 1
        for sev, count in sorted(sev_counts.items()):
            print(f"  {sev}: {count:,}")

        network_flagged = sum(1 for a in alerts if a.get('network_flag'))
        print(f"  network-flagged: {network_flagged:,}")

        return alerts

    def _classify_severity(self, fusion, rule, ml, graph):
        """Classify alert severity based on scores."""
        if fusion > 0.85 or (rule > 0.8 and ml > 0.7):
            return 'critical'
        elif fusion > 0.7 or rule > 0.6:
            return 'high'
        elif fusion > 0.55:
            return 'medium'
        else:
            return 'low'

    def save_alerts_to_db(self, alerts=None, rule_set_version=None):
        """Persist alerts to the database."""
        alerts = alerts or self.alerts
        if rule_set_version is None:
            try:
                from app.policy_engine.rule_set_manager import RuleSetManager
                rule_set_version = RuleSetManager.get_active_ruleset_global()
            except Exception:
                rule_set_version = None
        conn = get_connection()

        try:
            with conn.cursor() as cur:
                # Clear old pending alerts
                cur.execute("DELETE FROM alerts WHERE status = 'pending'")

                for alert in alerts:
                    cur.execute("""
                        INSERT INTO alerts (account_id, rule_score, ml_score, graph_score,
                            fusion_score, severity, status, triggered_rules, explanation, rule_set_version)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        alert['account_id'],
                        alert['rule_score'],
                        alert['ml_score'],
                        alert['graph_score'],
                        alert['fusion_score'],
                        alert['severity'],
                        alert['status'],
                        json.dumps(alert.get('triggered_rules', [])),
                        json.dumps({
                            'rule_evidence': alert.get('rule_evidence', []),
                            'graph_data': alert.get('graph_data', {}),
                            'cluster_id': alert.get('cluster_id', -1),
                            'cluster_risk': alert.get('cluster_risk', 0),
                            'cluster_size': alert.get('cluster_size', 0),
                            'network_flag': alert.get('network_flag', False),
                        }, default=str),
                        rule_set_version,
                    ))

            conn.commit()
            print(f"[Fusion] Saved {len(alerts):,} alerts to database")
        finally:
            release_connection(conn)
