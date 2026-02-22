"""Replay engine — evaluate rules against historical transactions (no alerts created)."""
from typing import List, Optional

from app.db import get_connection, release_connection
from app.detection.rule_engine import RuleEngine


def _fetchall(conn, sql, params=None):
    with conn.cursor() as c:
        c.execute(sql, params or [])
        return [dict(r) for r in c.fetchall()]


class ReplayEngine:
    """Evaluates specific rules against historical transactions and returns violations."""

    @staticmethod
    def get_transaction_ids_in_date_range(start_date: str, end_date: str) -> List[int]:
        """Return transaction ids with timestamp in [start_date, end_date] (inclusive)."""
        conn = get_connection()
        try:
            # timestamp is TEXT; compare date part
            rows = _fetchall(
                conn,
                "SELECT id FROM transactions WHERE date(timestamp) >= date(%s) AND date(timestamp) <= date(%s)",
                (start_date, end_date),
            )
            return [r["id"] for r in rows if r.get("id") is not None]
        finally:
            release_connection(conn)

    @staticmethod
    def replay_rules(
        ruleset_id: Optional[str],
        start_date: str,
        end_date: str,
    ) -> List[dict]:
        """
        Evaluate rules (current active if ruleset_id is None, else the given ruleset)
        and return violations only for transactions in the date range.
        Does not create alerts.
        """
        txn_ids = ReplayEngine.get_transaction_ids_in_date_range(start_date, end_date)
        if not txn_ids:
            return []
        txn_set = set(txn_ids)
        engine = RuleEngine(ruleset_id=ruleset_id)
        try:
            all_violations = engine.evaluate_all()
        finally:
            engine.close()
        # Keep only violations whose transaction is in range
        filtered = [v for v in all_violations if v.get("transaction_id") in txn_set]
        return filtered
