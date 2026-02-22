"""Explainability engine — generates audit-ready explanation packages per alert."""
import json
from app.db import get_connection, release_connection


class ExplainabilityEngine:
    """Generates comprehensive explanations for each alert."""

    def __init__(self, ml_engine=None, graph_engine=None):
        self.ml_engine = ml_engine
        self.graph_engine = graph_engine

    def explain_alert(self, alert):
        """Generate a full explanation package for an alert.
        
        Args:
            alert: Alert dict from the fusion engine
            
        Returns:
            dict with explanation components
        """
        account_id = alert.get('account_id', '')

        explanation = {
            'account_id': account_id,
            'fusion_score': alert.get('fusion_score', 0),
            'severity': alert.get('severity', 'medium'),
            'summary': '',
            'components': {},
        }

        # 1. Policy Clause — original rule source text
        policy_clauses = []
        for evidence in alert.get('rule_evidence', []):
            rule_id = evidence.get('rule_id', '')
            rule_data = self._get_rule_details(rule_id)
            if rule_data:
                policy_clauses.append({
                    'rule_id': rule_id,
                    'rule_name': evidence.get('rule_name', ''),
                    'source_document': rule_data.get('source_document', ''),
                    'source_page': rule_data.get('source_page', 0),
                    'source_text': rule_data.get('source_text', ''),
                    'severity': evidence.get('severity', 'medium'),
                })
        explanation['components']['policy_clauses'] = policy_clauses

        # 2. Triggered Rules — DSL rules that matched
        explanation['components']['triggered_rules'] = alert.get('triggered_rules', [])

        # 3. Evidence Rows — actual transaction data
        evidence_rows = self._get_evidence_transactions(alert)
        explanation['components']['evidence_rows'] = evidence_rows

        # 4. SHAP Feature Attribution (if ML engine available)
        shap_data = {}
        if self.ml_engine and self.ml_engine.features_df is not None:
            matching = self.ml_engine.features_df[
                self.ml_engine.features_df['account_id'] == account_id
            ]
            if not matching.empty:
                idx = matching.index[0]
                shap_data = self.ml_engine.explain(idx)
        explanation['components']['shap_attribution'] = shap_data

        # 5. Graph Path — network context
        graph_data = {}
        if self.graph_engine:
            graph_data = self.graph_engine.get_account_risk(account_id)
            graph_data['neighbors'] = self.graph_engine.get_neighbors(account_id, depth=1)
        explanation['components']['graph_path'] = graph_data

        # 6. Counterfactual Explanation
        counterfactual = self._generate_counterfactual(alert)
        explanation['components']['counterfactual'] = counterfactual

        # 7. Confidence Score
        confidence = self._compute_confidence(alert)
        explanation['components']['confidence'] = confidence

        # Generate summary
        explanation['summary'] = self._generate_summary(explanation)

        return explanation

    def _get_rule_details(self, rule_id):
        """Fetch rule details from database."""
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=None) as cur:
                cur.execute("SELECT * FROM rules WHERE id = %s", [rule_id])
                row = cur.fetchone()
                return dict(row) if row else {}
        finally:
            release_connection(conn)

    def _get_evidence_transactions(self, alert):
        """Get the actual transaction rows that triggered the alert."""
        conn = get_connection()
        account_id = alert.get('account_id', '')
        
        # Parse account_id (format: bankid_accountnum)
        parts = account_id.split('_', 1)
        if len(parts) != 2:
            return []

        bank_id, account_num = parts

        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=None) as cur:
                cur.execute("""
                    SELECT * FROM transactions
                    WHERE (from_bank = %s AND from_account = %s)
                       OR (to_bank = %s AND to_account = %s)
                    ORDER BY amount_paid DESC
                    LIMIT 20
                """, [bank_id, account_num, bank_id, account_num])
                return [dict(r) for r in cur.fetchall()]
        finally:
            release_connection(conn)

    def _generate_counterfactual(self, alert):
        """Generate 'what-if' explanation: what would need to change to not flag."""
        changes = []
        
        if alert.get('rule_score', 0) > 0:
            for evidence in alert.get('rule_evidence', []):
                ev = evidence.get('evidence', {})
                if 'amount_paid' in ev:
                    # Find the threshold from the rule
                    rule_data = self._get_rule_details(evidence.get('rule_id', ''))
                    if rule_data:
                        conditions = json.loads(rule_data.get('conditions', '[]'))
                        for cond in conditions:
                            if cond.get('field') in ('amount_paid', 'amount_received') and cond.get('operator') == '>':
                                threshold = cond['value']
                                actual = ev.get('amount_paid', 0)
                                changes.append({
                                    'factor': f"Transaction amount (${actual:,.2f})",
                                    'current': actual,
                                    'required': threshold,
                                    'change': f"Would need to be below ${threshold:,.2f} to pass",
                                })

        if alert.get('ml_score', 0) > 0.5:
            changes.append({
                'factor': 'ML Risk Score',
                'current': alert['ml_score'],
                'required': 0.3,
                'change': 'Behavioral patterns (transaction velocity, amount variance) would need to normalize',
            })

        if alert.get('graph_score', 0) > 0.5:
            changes.append({
                'factor': 'Network Risk Score',
                'current': alert['graph_score'],
                'required': 0.3,
                'change': 'Account connectivity and centrality in transaction network is elevated',
            })

        return {
            'changes_needed': changes,
            'summary': f"{len(changes)} factor(s) would need to change to remove this alert",
        }

    def _compute_confidence(self, alert):
        """Compute confidence score based on signal agreement."""
        scores = [
            alert.get('rule_score', 0),
            alert.get('ml_score', 0),
            alert.get('graph_score', 0),
        ]

        # How many engines agree this is risky (>0.5)
        agreement = sum(1 for s in scores if s > 0.5)
        
        # Base confidence from agreement
        if agreement == 3:
            confidence = 95
        elif agreement == 2:
            confidence = 80
        elif agreement == 1:
            confidence = 60
        else:
            confidence = 40

        # Adjust by fusion score
        confidence = min(99, int(confidence * (0.5 + 0.5 * alert.get('fusion_score', 0))))

        return {
            'score': confidence,
            'agreement': f"{agreement}/3 engines agree",
            'level': 'High' if confidence > 80 else 'Medium' if confidence > 60 else 'Low',
        }

    def _generate_summary(self, explanation):
        """Generate a human-readable summary."""
        comps = explanation['components']
        parts = []

        parts.append(f"Account {explanation['account_id']} flagged with "
                     f"{explanation['severity'].upper()} severity "
                     f"(score: {explanation['fusion_score']:.2f}).")

        n_rules = len(comps.get('triggered_rules', []))
        if n_rules:
            parts.append(f"Violated {n_rules} compliance rule(s).")

        n_evidence = len(comps.get('evidence_rows', []))
        if n_evidence:
            parts.append(f"{n_evidence} related transactions identified.")

        conf = comps.get('confidence', {})
        if conf:
            parts.append(f"Confidence: {conf.get('score', 0)}% ({conf.get('agreement', '')}).")

        return " ".join(parts)
