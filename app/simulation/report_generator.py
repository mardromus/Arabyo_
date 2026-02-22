"""Simulation report generator — executive summary and PDF export."""
import os
from datetime import datetime
from typing import Any, Dict

from app.config import REPORTS_DIR


def generate_executive_summary(simulation_result: Dict[str, Any]) -> str:
    """Produce a short, user-friendly executive summary from simulation metrics."""
    baseline = simulation_result.get("baseline_alerts", 0)
    simulated = simulation_result.get("simulated_alerts", 0)
    newly = simulation_result.get("newly_flagged", 0)
    no_longer = simulation_result.get("no_longer_flagged", 0)
    pct = simulation_result.get("percent_change", 0)
    wl = simulation_result.get("workload_estimate") or {}
    hrs = wl.get("estimated_hours_per_day", 0)
    hrs_delta = wl.get("hours_delta", 0)
    hr = simulation_result.get("high_risk_impact") or {}
    high_delta = hr.get("high_delta", 0) + hr.get("critical_delta", 0)

    lines = [
        "Policy Update Impact Summary",
        "",
        f"- {pct:+.1f}% change in alert volume (baseline: {baseline}, simulated: {simulated}).",
        f"- {newly} previously non-flagged transactions would now be flagged.",
        f"- {no_longer} previously flagged transactions would no longer be flagged.",
        f"- Estimated alert volume change: {pct:+.1f}%.",
        f"- High-risk segment impact: {high_delta:+.0f}.",
        f"- Estimated analyst workload: {hrs:.1f} hours/day ({hrs_delta:+.1f} vs baseline).",
        "",
        "Recommendation: Review threshold and rule parameters to balance detection vs workload."
    ]
    return "\n".join(lines)


def generate_pdf_report(simulation_result: Dict[str, Any], simulation_id: str) -> str:
    """Generate a PDF report for the simulation. (DEPRECATED - Use HTML Printing Engine)"""
    raise NotImplementedError("Legacy ReportLab export is deprecated. Use the new /report HTML endpoint.")
