"""Metrics for impact simulation — workload, severity breakdown, false positive impact."""
from typing import Any, Dict, List


def _account_from_violation(v: dict) -> str:
    """Canonical account id from a violation (bank_account)."""
    ev = v.get("evidence") or {}
    return ev.get("account") or ev.get("from_account") or ""


class MetricsCalculator:
    """Compute impact metrics from baseline vs simulated violations."""

    @staticmethod
    def _unique_accounts(violations: List[dict]) -> set:
        out = set()
        for v in violations:
            acct = _account_from_violation(v)
            if acct:
                out.add(acct)
        return out

    @staticmethod
    def calculate_impact_metrics(
        baseline_violations: List[dict],
        simulated_violations: List[dict],
        transactions_in_range: int = 0,
        avg_minutes_per_alert: float = 15,
    ) -> dict:
        """
        Compare baseline vs simulated violations and return impact metrics.
        baseline_violations: violations from current active rules in date range.
        simulated_violations: violations from proposed ruleset in same date range.
        """
        baseline_accounts = MetricsCalculator._unique_accounts(baseline_violations)
        simulated_accounts = MetricsCalculator._unique_accounts(simulated_violations)
        baseline_count = len(baseline_accounts)
        simulated_count = len(simulated_accounts)
        newly_flagged = simulated_accounts - baseline_accounts
        no_longer_flagged = baseline_accounts - simulated_accounts
        net_change = simulated_count - baseline_count
        percent_change = (
            (net_change / baseline_count * 100.0) if baseline_count else (100.0 if simulated_count else 0.0)
        )

        # Severity breakdown (from violations: count accounts by max severity)
        def severity_per_account(violations: List[dict]) -> Dict[str, int]:
            order = ["critical", "high", "medium", "low"]

            def rank(s: str) -> int:
                return order.index(s) if s in order else 2  # medium

            by_acct = {}
            for v in violations:
                acct = _account_from_violation(v)
                if not acct:
                    continue
                sev = (v.get("severity") or "medium").lower()
                if acct not in by_acct or rank(sev) < rank(by_acct[acct]):
                    by_acct[acct] = sev
            out = {s: 0 for s in order}
            for s in by_acct.values():
                if s in out:
                    out[s] += 1
            return out

        baseline_severity = severity_per_account(baseline_violations)
        simulated_severity = severity_per_account(simulated_violations)
        high_risk_impact = {
            "baseline": baseline_severity,
            "simulated": simulated_severity,
            "critical_delta": simulated_severity.get("critical", 0) - baseline_severity.get("critical", 0),
            "high_delta": simulated_severity.get("high", 0) - baseline_severity.get("high", 0),
        }

        # Workload estimate
        additional_alerts = len(newly_flagged)  # approximate
        hours_per_day = MetricsCalculator.estimate_workload(
            simulated_count, avg_minutes_per_alert=avg_minutes_per_alert
        )
        baseline_hours = MetricsCalculator.estimate_workload(
            baseline_count, avg_minutes_per_alert=avg_minutes_per_alert
        )
        workload_estimate = {
            "additional_alerts_total": additional_alerts,
            "additional_alerts_per_day": additional_alerts / 30.0 if additional_alerts else 0,
            "estimated_hours_per_day": hours_per_day,
            "baseline_hours_per_day": baseline_hours,
            "hours_delta": hours_per_day - baseline_hours,
        }

        return {
            "baseline_alerts": baseline_count,
            "simulated_alerts": simulated_count,
            "newly_flagged": len(newly_flagged),
            "no_longer_flagged": len(no_longer_flagged),
            "net_change": net_change,
            "percent_change": round(percent_change, 2),
            "high_risk_impact": high_risk_impact,
            "workload_estimate": workload_estimate,
            "transactions_in_range": transactions_in_range,
        }

    @staticmethod
    def estimate_workload(
        alert_count: int,
        avg_minutes_per_alert: float = 15,
        working_days_per_month: float = 22,
    ) -> float:
        """Rough hours per day to handle alert_count alerts (spread over month)."""
        if alert_count <= 0:
            return 0.0
        total_minutes = alert_count * avg_minutes_per_alert
        # Spread over working days
        minutes_per_day = total_minutes / working_days_per_month
        return round(minutes_per_day / 60.0, 2)
