"""Deterministic rule engine — translates Rule DSL to SQL queries against PostgreSQL."""
import json
from app.db import get_connection, release_connection


class RuleEngine:
    """Evaluates rules from the Rule DSL against the transaction database."""

    def __init__(self, ruleset_id=None):
        """
        Args:
            ruleset_id: If set, load only rules in this rule set (for simulation/replay).
                        Otherwise load all active rules.
        """
        self.conn = get_connection()
        self.cur = self.conn.cursor(cursor_factory=None)
        self.ruleset_id = ruleset_id
        self.rules = self._load_rules()

    def _load_rules(self):
        """Load rules: from ruleset_id, or from active rulesets, or fallback to rules with status='active'."""
        if self.ruleset_id:
            from app.policy_engine.rule_set_manager import RuleSetManager
            rs = RuleSetManager.get_ruleset(self.ruleset_id)
            if not rs or not rs.get("rule_ids"):
                self.rules = []
                return []
            rule_ids = rs["rule_ids"]
            placeholders = ",".join(["%s"] * len(rule_ids))
            self.cur.execute(
                f"SELECT * FROM rules WHERE id IN ({placeholders}) AND is_deleted = 0",
                rule_ids,
            )
        else:
            # Prefer rules from active rulesets; fallback to status='active' for legacy
            from app.policy_engine.rule_set_manager import RuleSetManager
            active_ids = RuleSetManager.get_active_rule_ids_global()
            if active_ids:
                placeholders = ",".join(["%s"] * len(active_ids))
                self.cur.execute(
                    f"SELECT * FROM rules WHERE id IN ({placeholders}) AND is_deleted = 0",
                    active_ids,
                )
            else:
                self.cur.execute("SELECT * FROM rules WHERE status IN ('active', 'approved') AND is_deleted = 0")
        rows = self.cur.fetchall()
        rules = []
        for row in rows:
            r = dict(row)
            r['conditions'] = json.loads(r['conditions']) if r['conditions'] else []
            rules.append(r)
        return rules

    def evaluate_all(self):
        """Evaluate all active rules and return violations."""
        all_violations = []

        for rule in self.rules:
            try:
                violations = self._evaluate_rule(rule)
                all_violations.extend(violations)
            except Exception as e:
                print(f"[RuleEngine] Error evaluating rule {rule['id']}: {e}")

        # Deduplicate by transaction_id, merge rule hits
        merged = {}
        for v in all_violations:
            txn_id = v['transaction_id']
            if txn_id in merged:
                merged[txn_id]['triggered_rules'].append(v['rule_id'])
                merged[txn_id]['rule_score'] = min(1.0, merged[txn_id]['rule_score'] + 0.2)
            else:
                merged[txn_id] = v

        print(f"[RuleEngine] Found {len(merged)} transactions with rule violations")
        return list(merged.values())

    def _evaluate_rule(self, rule):
        """Evaluate a single rule against the database."""
        rule_type = rule.get('rule_type', '')

        if rule_type == 'threshold':
            return self._eval_threshold(rule)
        elif rule_type == 'velocity':
            return self._eval_velocity(rule)
        elif rule_type == 'cross_border':
            return self._eval_cross_border(rule)
        elif rule_type == 'payment_format':
            return self._eval_payment_format(rule)
        elif rule_type == 'pattern':
            return self._eval_pattern(rule)
        else:
            return []

    def _fetchall(self, sql, params=None):
        """Execute SQL with %s placeholders and return list of dicts."""
        self.cur.execute(sql, params or [])
        return self.cur.fetchall()

    def _eval_threshold(self, rule):
        """Evaluate a simple threshold rule."""
        conditions = rule.get('conditions', [])
        where_clauses = []
        params = []

        for cond in conditions:
            field = cond.get('field', '')
            op = cond.get('operator', '')
            value = cond.get('value')

            if field in ('amount_paid', 'amount_received') and op == '>':
                where_clauses.append(f"{field} > %s")
                params.append(value)
            elif field == 'payment_format' and op == '==':
                where_clauses.append("payment_format = %s")
                params.append(value)

        if not where_clauses:
            return []

        sql = f"SELECT * FROM transactions WHERE {' AND '.join(where_clauses)} LIMIT 5000"
        rows = self._fetchall(sql, params)

        severity_score = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
        violations = []
        for row in rows:
            account_id = f"{row['from_bank']}_{row['from_account']}"
            violations.append({
                'transaction_id': row['id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': severity_score.get(rule.get('severity', 'medium'), 0.6),
                'severity': rule.get('severity', 'medium'),
                'evidence': {
                    'account': account_id,
                    'amount_paid': row['amount_paid'],
                    'from_account': row['from_account'],
                    'to_account': row['to_account'],
                    'timestamp': row['timestamp'],
                },
            })
        return violations

    def _eval_velocity(self, rule):
        """Evaluate velocity/structuring rules using window queries."""
        conditions = rule.get('conditions', [])
        count_threshold = None
        amount_threshold = None
        direction = 'outgoing'

        for cond in conditions:
            if cond.get('field') == 'transaction_count':
                count_threshold = cond.get('value')
            elif cond.get('field') == 'cumulative_amount':
                amount_threshold = cond.get('value')
            elif cond.get('field') == 'direction':
                direction = cond.get('value', 'outgoing')

        if direction == 'outgoing':
            group_col = "from_bank || '_' || from_account"
        else:
            group_col = "to_bank || '_' || to_account"

        if count_threshold:
            # PostgreSQL: HAVING must reference aggregate directly
            sql = f"""
                SELECT {group_col} as acct, COUNT(*) as txn_count,
                       SUM(amount_paid) as total_amount,
                       MIN(id) as sample_txn_id
                FROM transactions
                GROUP BY {group_col}
                HAVING COUNT(*) > %s
                LIMIT 3000
            """
            rows = self._fetchall(sql, [count_threshold])
        elif amount_threshold:
            sql = f"""
                SELECT {group_col} as acct, COUNT(*) as txn_count,
                       SUM(amount_paid) as total_amount,
                       MIN(id) as sample_txn_id
                FROM transactions
                GROUP BY {group_col}
                HAVING SUM(amount_paid) > %s
                LIMIT 3000
            """
            rows = self._fetchall(sql, [amount_threshold])
        else:
            return []

        severity_score = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
        violations = []
        for row in rows:
            account_id = row['acct']
            violations.append({
                'transaction_id': row['sample_txn_id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': severity_score.get(rule.get('severity', 'medium'), 0.6),
                'severity': rule.get('severity', 'medium'),
                'evidence': {
                    'account': account_id,
                    'transaction_count': row['txn_count'],
                    'total_amount': float(row['total_amount']),
                },
            })
        return violations

    def _eval_cross_border(self, rule):
        """Evaluate cross-border rules (from_bank != to_bank)."""
        conditions = rule.get('conditions', [])
        amount_threshold = 0
        for cond in conditions:
            if cond.get('field') in ('amount_paid', 'amount_received') and cond.get('operator') == '>':
                amount_threshold = cond.get('value', 0)

        sql = """
            SELECT * FROM transactions
            WHERE from_bank != to_bank AND amount_paid > %s
            LIMIT 5000
        """
        rows = self._fetchall(sql, [amount_threshold])

        violations = []
        for row in rows:
            account_id = f"{row['from_bank']}_{row['from_account']}"
            violations.append({
                'transaction_id': row['id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': 0.6,
                'severity': rule.get('severity', 'medium'),
                'evidence': {
                    'account': account_id,
                    'amount_paid': row['amount_paid'],
                    'from_bank': row['from_bank'],
                    'to_bank': row['to_bank'],
                    'timestamp': row['timestamp'],
                },
            })
        return violations

    def _eval_payment_format(self, rule):
        """Evaluate payment-format-specific rules."""
        conditions = rule.get('conditions', [])
        fmt = None
        amount_threshold = 0
        for cond in conditions:
            if cond.get('field') == 'payment_format':
                fmt = cond.get('value', '')
            elif cond.get('field') == 'amount_paid' and cond.get('operator') == '>':
                amount_threshold = cond.get('value', 0)

        if not fmt:
            return []

        sql = """
            SELECT * FROM transactions
            WHERE payment_format = %s AND amount_paid > %s
            LIMIT 5000
        """
        rows = self._fetchall(sql, [fmt, amount_threshold])

        violations = []
        for row in rows:
            account_id = f"{row['from_bank']}_{row['from_account']}"
            violations.append({
                'transaction_id': row['id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': 0.5,
                'severity': rule.get('severity', 'medium'),
                'evidence': {
                    'account': account_id,
                    'amount_paid': row['amount_paid'],
                    'payment_format': row['payment_format'],
                    'timestamp': row['timestamp'],
                },
            })
        return violations

    def _eval_pattern(self, rule):
        """Evaluate pattern-based rules (round-trip, fan-out, etc.)."""
        conditions = rule.get('conditions', [])
        pattern = None
        for cond in conditions:
            if cond.get('field') == 'pattern':
                pattern = cond.get('value')

        if pattern == 'round_trip':
            return self._detect_round_trips(rule)
        elif pattern in ('fan_out', 'fan_in'):
            return self._detect_fan_patterns(rule, pattern)
        elif pattern == 'self_transfer':
            return self._detect_self_transfers(rule)
        return []

    def _detect_round_trips(self, rule):
        """Detect A→B followed by B→A."""
        sql = """
            SELECT t1.id as id1, t1.from_bank, t1.from_account, t1.to_account,
                   t1.amount_paid, t1.timestamp
            FROM transactions t1
            INNER JOIN transactions t2 ON t1.from_account = t2.to_account
                AND t1.to_account = t2.from_account
                AND t1.from_bank = t2.to_bank
                AND t1.to_bank = t2.from_bank
                AND t2.timestamp > t1.timestamp
            LIMIT 2000
        """
        rows = self._fetchall(sql)
        violations = []
        for row in rows:
            account_id = f"{row['from_bank']}_{row['from_account']}"
            violations.append({
                'transaction_id': row['id1'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': 0.8,
                'severity': 'high',
                'evidence': {
                    'account': account_id,
                    'pattern': 'round_trip',
                    'from_account': row['from_account'],
                    'to_account': row['to_account'],
                    'amount': float(row['amount_paid']),
                },
            })
        return violations

    def _detect_fan_patterns(self, rule, pattern_type):
        """Detect fan-out (1→many) or fan-in (many→1)."""
        if pattern_type == 'fan_out':
            sql = """
                SELECT from_bank || '_' || from_account as acct,
                       COUNT(DISTINCT to_bank || '_' || to_account) as distinct_targets,
                       MIN(id) as sample_id
                FROM transactions
                GROUP BY acct
                HAVING COUNT(DISTINCT to_bank || '_' || to_account) > 10
                LIMIT 2000
            """
        else:
            sql = """
                SELECT to_bank || '_' || to_account as acct,
                       COUNT(DISTINCT from_bank || '_' || from_account) as distinct_sources,
                       MIN(id) as sample_id
                FROM transactions
                GROUP BY acct
                HAVING COUNT(DISTINCT from_bank || '_' || from_account) > 10
                LIMIT 2000
            """

        rows = self._fetchall(sql)
        violations = []
        for row in rows:
            account_id = row['acct']
            violations.append({
                'transaction_id': row['sample_id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': 0.7,
                'severity': 'medium',
                'evidence': {
                    'account': account_id,
                    'pattern': pattern_type,
                    'count': row['distinct_targets'] if pattern_type == 'fan_out' else row['distinct_sources'],
                },
            })
        return violations

    def _detect_self_transfers(self, rule):
        """Detect self-transfers (same sender and receiver)."""
        sql = """
            SELECT * FROM transactions
            WHERE from_bank = to_bank AND from_account = to_account
            AND amount_paid > 1000
            LIMIT 3000
        """
        rows = self._fetchall(sql)
        violations = []
        for row in rows:
            account_id = f"{row['from_bank']}_{row['from_account']}"
            violations.append({
                'transaction_id': row['id'],
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'triggered_rules': [rule['id']],
                'rule_score': 0.6,
                'severity': 'medium',
                'evidence': {
                    'account': account_id,
                    'pattern': 'self_transfer',
                    'amount': float(row['amount_paid']),
                    'from_account': row['from_account'],
                },
            })
        return violations

    def close(self):
        self.cur.close()
        release_connection(self.conn)
