"""Regulatory impact simulator — retroactive analysis of rule changes on historical data."""
import json
import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from app.db import get_connection, release_connection
from app.simulation.replay_engine import ReplayEngine
from app.simulation.metrics import MetricsCalculator

logger = logging.getLogger(__name__)


def _fetchone(conn, sql, params=None):
    with conn.cursor() as c:
        c.execute(sql, params or [])
        row = c.fetchone()
        return dict(row) if row else None


@dataclass
class SimulationResult:
    """Result of an impact simulation run."""
    simulation_id: str
    ruleset_id: str
    start_date: str
    end_date: str
    baseline_alerts: int
    simulated_alerts: int
    newly_flagged: int
    no_longer_flagged: int
    net_change: int
    percent_change: float
    high_risk_impact: dict
    workload_estimate: dict
    transactions_in_range: int
    transaction_sample: List[dict]
    false_positive_impact: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)


class ImpactSimulator:
    """Runs retrospective simulation of rule changes on historical transactions."""

    @staticmethod
    def simulate_rule_change(
        ruleset_id: str,
        historical_start_date: str,
        historical_end_date: str,
        include_ml: bool = False,
        include_graph: bool = False,
        avg_minutes_per_alert: float = 15,
        transaction_sample_size: int = 20,
    ) -> SimulationResult:
        """
        Run baseline (current active rules) and simulated (proposed ruleset) on historical
        transactions in the date range; return comparison metrics.
        """
        # Transaction count in range
        txn_ids = ReplayEngine.get_transaction_ids_in_date_range(
            historical_start_date, historical_end_date
        )
        transactions_in_range = len(txn_ids)

        # Baseline: current active rules
        baseline_violations = ReplayEngine.replay_rules(
            None, historical_start_date, historical_end_date
        )
        # Simulated: proposed ruleset
        simulated_violations = ReplayEngine.replay_rules(
            ruleset_id, historical_start_date, historical_end_date
        )

        metrics = MetricsCalculator.calculate_impact_metrics(
            baseline_violations,
            simulated_violations,
            transactions_in_range=transactions_in_range,
            avg_minutes_per_alert=avg_minutes_per_alert,
        )

        # Sample of "newly flagged" (accounts in simulated but not baseline)
        baseline_accounts = {
            (v.get("evidence") or {}).get("account") or (v.get("evidence") or {}).get("from_account")
            for v in baseline_violations
        }
        simulated_accounts = {
            (v.get("evidence") or {}).get("account") or (v.get("evidence") or {}).get("from_account")
            for v in simulated_violations
        }
        newly_accounts = simulated_accounts - baseline_accounts
        transaction_sample = []
        if newly_accounts and transaction_sample_size > 0:
            conn = get_connection()
            try:
                # Get a few sample transactions for newly flagged accounts
                placeholders = ",".join(["%s"] * min(len(newly_accounts), 10))
                # account_id format is bank_account
                parts_list = [a.split("_", 1) for a in list(newly_accounts)[:10] if "_" in a]
                if parts_list:
                    bank_ids = [p[0] for p in parts_list]
                    acc_nums = [p[1] for p in parts_list]
                    # Simple sample: one txn per account from our range
                    rows = []
                    for bid, anum in zip(bank_ids[:5], acc_nums[:5]):
                        row = _fetchone(
                            conn,
                            """SELECT id, timestamp, from_bank, from_account, to_bank, to_account, amount_paid
                               FROM transactions
                               WHERE (from_bank = %s AND from_account = %s) OR (to_bank = %s AND to_account = %s)
                               AND date(timestamp) >= date(%s) AND date(timestamp) <= date(%s)
                               LIMIT 1""",
                            (bid, anum, bid, anum, historical_start_date, historical_end_date),
                        )
                        if row:
                            rows.append(row)
                    transaction_sample = rows[:transaction_sample_size]
            finally:
                release_connection(conn)

        sim_id = str(uuid.uuid4())
        return SimulationResult(
            simulation_id=sim_id,
            ruleset_id=ruleset_id,
            start_date=historical_start_date,
            end_date=historical_end_date,
            baseline_alerts=metrics["baseline_alerts"],
            simulated_alerts=metrics["simulated_alerts"],
            newly_flagged=metrics["newly_flagged"],
            no_longer_flagged=metrics["no_longer_flagged"],
            net_change=metrics["net_change"],
            percent_change=metrics["percent_change"],
            high_risk_impact=metrics["high_risk_impact"],
            workload_estimate=metrics["workload_estimate"],
            transactions_in_range=metrics["transactions_in_range"],
            transaction_sample=transaction_sample,
            false_positive_impact=metrics.get("false_positive_impact"),
        )

    @staticmethod
    def save_simulation_run(result: SimulationResult, created_by: str = "system") -> None:
        """Persist simulation result to simulation_runs table."""
        from app.simulation.report_generator import generate_executive_summary
        result_dict = result.to_dict()
        result_dict["executive_summary"] = generate_executive_summary(result_dict)
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO simulation_runs
                       (simulation_id, ruleset_id, start_date, end_date, baseline_alerts, simulated_alerts, results_json, created_by, status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'completed')""",
                    (
                        result.simulation_id,
                        result.ruleset_id,
                        result.start_date,
                        result.end_date,
                        result.baseline_alerts,
                        result.simulated_alerts,
                        json.dumps(result_dict, default=str),
                        created_by,
                    ),
                )
            conn.commit()
        finally:
            release_connection(conn)

    @staticmethod
    def get_simulation_run(simulation_id: str) -> Optional[dict]:
        """Load a simulation run by id."""
        conn = get_connection()
        try:
            row = _fetchone(
                conn,
                "SELECT * FROM simulation_runs WHERE simulation_id = %s",
                (simulation_id,),
            )
            if not row:
                return None
            if row.get("results_json"):
                try:
                    row["results"] = json.loads(row["results_json"])
                except (TypeError, json.JSONDecodeError):
                    row["results"] = {}
            return row
        finally:
            release_connection(conn)

    @staticmethod
    def list_simulation_runs(limit: int = 50) -> List[dict]:
        """List recent simulation runs."""
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT simulation_id, ruleset_id, start_date, end_date, baseline_alerts, simulated_alerts, created_at, created_by, status FROM simulation_runs ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
                return [dict(r) for r in cur.fetchall()]
        finally:
            release_connection(conn)
