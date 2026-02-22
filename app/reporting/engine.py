import datetime
import json
from typing import Dict, Any, List

def format_timestamp(ts_str: str) -> str:
    """Format ISO timestamp or similar string into human-readable date/time."""
    if not ts_str: return "N/A"
    try:
        if isinstance(ts_str, str) and "T" in ts_str:
            dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    return str(ts_str)

def generate_alert_report_data(alert: Any, transactions: List[Any], xai_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms internal alert constructs into a flat, template-friendly
    context dictionary suitable for the HTML/PDF report.
    """
    
    # 1. Executive Summary
    exec_summary = xai_data.get('human_summary', "No summary generated.")
    
    # 2. Risk Overview
    risk_overview = {
        "fusion_score": getattr(alert, 'fusion_score', 0.0),
        "rule_score": getattr(alert, 'rule_score', 0.0),
        "ml_score": getattr(alert, 'ml_score', 0.0),
        "graph_score": getattr(alert, 'graph_score', 0.0),
        "severity": getattr(alert, 'severity', 'Unknown').upper(),
        "confidence": xai_data.get('confidence', 'Unknown'),
        "status": getattr(alert, 'status', 'Pending').title()
    }
    
    # 3. Key Risk Drivers
    risk_drivers = xai_data.get('risk_drivers', [])
    
    # 4. Evidence (Transactions)
    formatted_txns = []
    for t in transactions:
        formatted_txns.append({
            "timestamp": getattr(t, 'timestamp', ''),
            "from_account": f"{getattr(t, 'from_bank', '')}/{getattr(t, 'from_account', '')}",
            "to_account": f"{getattr(t, 'to_bank', '')}/{getattr(t, 'to_account', '')}",
            "amount": f"${getattr(t, 'amount_paid', 0.0):,.2f}",
            "format": getattr(t, 'payment_format', ''),
            "is_laundering": getattr(t, 'is_laundering', False)
        })
        
    # 5. Network / Anomaly Insight
    graph_insight = None
    if xai_data.get('graph_context', {}).get('has_graph_risk'):
        graph_insight = xai_data['graph_context'].get('summary')
        
    anomaly_insight = None
    if xai_data.get('anomaly_context', {}).get('has_anomaly'):
        anomaly_insight = xai_data['anomaly_context'].get('summary')
        
    # 6. Recommended Actions
    actions = xai_data.get('recommended_actions', [])
    
    # 7. Audit & Traceability
    audit_trail = {
        "report_generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "alert_id": getattr(alert, 'id', 'N/A'),
        "account_id": getattr(alert, 'account_id', 'N/A'),
        "rule_version": "v2.1",
        "ml_version": "v1.4",
        "xai_engine": xai_data.get('source', "Explainability Engine v1.0")
    }
    
    return {
        "title": f"Investigation Report - Alert #{getattr(alert, 'id', 'N/A')}",
        "type": "SINGLE_ALERT",
        "alert": alert,
        "executive_summary": exec_summary,
        "risk_overview": risk_overview,
        "risk_drivers": risk_drivers,
        "transactions": formatted_txns,
        "graph_insight": graph_insight,
        "anomaly_insight": anomaly_insight,
        "actions": actions,
        "audit": audit_trail
    }

def generate_cluster_report_data(cluster: Any, alerts_in_cluster: List[Any], xai_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms internal cluster constructs into template-friendly context.
    """
    
    # 1. Executive Summary
    exec_summary = xai_data.get('cluster_summary', "No summary generated for this cluster.")
    
    # 2. Risk Overview
    risk_overview = {
        "mean_risk": getattr(cluster, 'mean_risk', 0.0),
        "max_risk": getattr(cluster, 'max_risk', 0.0),
        "priority_score": getattr(cluster, 'priority_score', 0.0),
        "severity": xai_data.get('risk_assessment', {}).get('level', 'Unknown').upper(),
        "total_alerts": getattr(cluster, 'size', 0),
        "purity": f"{getattr(cluster, 'rule_homogeneity', 0.0) * 100:.0f}%"
    }
    
    # 3. Key Findings (Dominant Pattern, Severities)
    findings = []
    pat = xai_data.get('dominant_pattern')
    if pat:
        findings.append({
            "label": "Dominant Pattern",
            "value": pat.get('label', pat.get('pattern', 'Unknown')),
            "description": pat.get('description', '')
        })
        
    risk_assm = xai_data.get('risk_assessment')
    if risk_assm:
        findings.append({
            "label": "High-Risk Concentration",
            "value": f"{risk_assm.get('high_risk_percentage', 0)}%",
            "description": risk_assm.get('assessment', '')
        })
    
    # 4. Evidence (Alerts in Cluster)
    formatted_alerts = []
    for a in alerts_in_cluster:
        formatted_alerts.append({
            "id": getattr(a, 'id', ''),
            "account": getattr(a, 'account_id', ''),
            "severity": getattr(a, 'severity', '').upper(),
            "fusion_score": f"{getattr(a, 'fusion_score', 0.0):.3f}",
            "created_at": format_timestamp(getattr(a, 'created_at', ''))
        })
        
    # 5. Network / Behaviors
    commonalities = [c.get('description', '') for c in xai_data.get('key_commonalities', [])]
    
    # 6. Recommended Actions
    actions = xai_data.get('recommended_actions', [])
    
    # 7. Audit & Traceability
    audit_trail = {
        "report_generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "cluster_id": getattr(cluster, 'id', 'N/A'),
        "cluster_algorithm": getattr(cluster, 'cluster_algorithm', 'HDBSCAN'),
        "xai_engine": "Explainability Engine v1.0"
    }
    
    return {
        "title": f"Cluster Investigation Report - CLU-{getattr(cluster, 'id', 'N/A')}",
        "type": "CLUSTER",
        "cluster": cluster,
        "executive_summary": exec_summary,
        "risk_overview": risk_overview,
        "findings": findings,
        "alerts": formatted_alerts,
        "commonalities": commonalities,
        "actions": actions,
        "audit": audit_trail
    }

def generate_executive_report_data(all_alerts: List[Any], all_clusters: List[Any], system_stats: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms system-wide data into an executive summary context.
    """
    total_alerts = len(all_alerts)
    critical_alerts = sum(1 for a in all_alerts if getattr(a, 'severity', '').lower() == 'critical')
    high_alerts = sum(1 for a in all_alerts if getattr(a, 'severity', '').lower() == 'high')
    
    total_clusters = len(all_clusters)
    
    # Simple top rules driven
    # In a full app, this would query the DB for rule hit frequencies.
    top_rules = [
        {"name": "Grey List Transfer Velocity", "hits": int(total_alerts * 0.35)},
        {"name": "Dormant Account Activation", "hits": int(total_alerts * 0.20)},
        {"name": "Structuring / Smurfing", "hits": int(total_alerts * 0.15)}
    ]
    
    # 1. Executive Summary
    exec_summary = f"System analysis covering {total_alerts:,} total alerts, grouped into {total_clusters:,} behavioral clusters. Critical and High severity alerts account for {(critical_alerts + high_alerts) / max(1, total_alerts) * 100:.1f}% of the current workload. Immediate attention recommended for the top {min(3, total_clusters)} high-risk clusters."
    
    # 2. Risk Overview
    risk_overview = {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "total_clusters": total_clusters,
        "avg_fusion_score": sum(getattr(a, 'fusion_score', 0) for a in all_alerts) / max(1, total_alerts),
        "system_status": system_stats.get('status', 'Operational')
    }
    
    # 3. Workload Reduction
    reduction = 0.0
    if total_alerts > 0:
        reduction = (1.0 - (total_clusters / float(total_alerts))) * 100
    
    # 4. Audit & Traceability
    audit_trail = {
        "report_generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "report_scope": "Global",
        "engine_version": "v2.1.0"
    }

    return {
        "title": "Executive Risk & Workload Summary",
        "type": "EXECUTIVE",
        "executive_summary": exec_summary,
        "risk_overview": risk_overview,
        "top_rules": top_rules,
        "audit": audit_trail
    }

def generate_simulation_report_data(run: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms simulator execution data into a template-friendly context
    for the HTML/PDF engine. Includes run dates and delta metrics.
    """
    
    # 1. Executive Summary
    exec_summary = results.get('executive_summary', 'No summary generated.')
    
    # 2. Risk Overview (Sim Deltas)
    risk_overview = {
        "baseline_alerts": results.get('baseline_alerts', 0),
        "simulated_alerts": results.get('simulated_alerts', 0),
        "net_change": results.get('percent_change', 0.0),
        "newly_flagged": results.get('newly_flagged', 0),
        "no_longer_flagged": results.get('no_longer_flagged', 0),
        "transactions_in_range": results.get('transactions_in_range', 0),
    }
    
    # 3. Workload Delta
    wl = results.get('workload_estimate') or {}
    workload_delta = {
        "estimated_hours_per_day": wl.get('estimated_hours_per_day', 0.0),
        "hours_delta": wl.get('hours_delta', 0.0),
        "additional_alerts_total": wl.get('additional_alerts_total', 0)
    }
    
    # 4. Severity Deltas
    hr = results.get('high_risk_impact') or {}
    baseline_hr = hr.get('baseline') or {}
    simulated_hr = hr.get('simulated') or {}
    
    severities = []
    for sev in ['critical', 'high', 'medium', 'low']:
        b = baseline_hr.get(sev, 0)
        s = simulated_hr.get(sev, 0)
        severities.append({
            "level": sev.title(),
            "baseline": b,
            "simulated": s,
            "delta": s - b,
            "delta_str": f"+{s-b}" if (s-b) > 0 else str(s-b)
        })
        
    # 5. Transactions
    sample = results.get('transaction_sample') or []
    formatted_sample = []
    for t in sample:
        formatted_sample.append({
            "id": str(t.get('id', '')),
            "timestamp": format_timestamp(t.get('timestamp', '')),
            "from_account": f"{t.get('from_bank', '')}/{t.get('from_account', '')}",
            "to_account": f"{t.get('to_bank', '')}/{t.get('to_account', '')}",
            "amount": f"${t.get('amount_paid', 0.0):,.2f}"
        })
        
    created_at_raw = run.get('created_at', None)
    if not created_at_raw:
        # Fallback if DB doesn't project it, though it should. 
        created_at_raw = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
    audit_trail = {
        "report_generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "simulation_execution_date": format_timestamp(created_at_raw),
        "simulation_id": run.get('simulation_id', 'Unknown'),
        "ruleset_id": run.get('ruleset_id', 'Unknown'),
        "historical_period": f"{run.get('start_date', '')} to {run.get('end_date', '')}"
    }
    
    return {
        "title": f"Impact Simulation: {run.get('ruleset_id', 'Unknown')}",
        "type": "SIMULATION",
        "executive_summary": exec_summary,
        "risk_overview": risk_overview,
        "workload": workload_delta,
        "severities": severities,
        "sample": formatted_sample,
        "audit": audit_trail
    }
