"""Explainability & Action Intelligence Layer.

Converts ML, rule, and graph signals into clear human narratives
and provides actionable investigation guidance for analysts.

Design: Never fabricates facts. All explanations are evidence-backed
with numeric values and rule references. Confidence is always stated.
"""
import json
import math
import logging
from collections import Counter

from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)

# ── Confidence Labels ─────────────────────────────────────────────

def _confidence_label(score):
    if score >= 0.7: return 'High'
    if score >= 0.4: return 'Medium'
    return 'Low'

def _severity_color(sev):
    return {'critical': '#ef4444', 'high': '#f59e0b', 'medium': '#6366f1', 'low': '#22c55e'}.get(sev, '#94a3b8')


# ── PART 1: Single Alert Explainability ───────────────────────────

def explain_alert(alert_id):
    """Generate full human-readable explanation for a single alert.

    Returns dict with human_summary, risk_drivers, rule_triggered,
    anomaly_context, graph_context, confidence, recommended_actions.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Fetch alert
            cur.execute("SELECT * FROM alerts WHERE id = %s", [alert_id])
            alert = cur.fetchone()
            if not alert:
                return {'error': f'Alert {alert_id} not found'}
            alert = dict(alert)

            # Fetch triggered rules
            rule_ids = []
            try:
                rule_ids = json.loads(alert.get('triggered_rules', '[]') or '[]')
            except (json.JSONDecodeError, TypeError):
                pass

            rules = []
            if rule_ids:
                placeholders = ",".join(["%s"] * len(rule_ids))
                cur.execute(f"SELECT * FROM rules WHERE id IN ({placeholders})", rule_ids)
                rules = [dict(r) for r in cur.fetchall()]

            # Fetch explanation data
            expl_data = {}
            try:
                expl_data = json.loads(alert.get('explanation', '{}') or '{}')
            except (json.JSONDecodeError, TypeError):
                pass

            # Fetch account transactions for context
            cur.execute("""
                SELECT COUNT(*) as txn_count, AVG(amount_paid) as avg_amount,
                       MAX(amount_paid) as max_amount, MIN(timestamp) as first_txn,
                       MAX(timestamp) as last_txn
                FROM transactions WHERE from_account = %s OR to_account = %s
            """, [alert.get('account_id', ''), alert.get('account_id', '')])
            acct_stats = dict(cur.fetchone())

    finally:
        release_connection(conn)

    # Build risk drivers
    risk_drivers = _compute_risk_drivers(alert, rules, expl_data)

    # Build human summary
    human_summary = _generate_alert_summary(alert, rules, risk_drivers, acct_stats, expl_data)

    # Build rule context
    rule_context = _build_rule_context(rules)

    # Build graph context
    graph_context = _build_graph_context(alert, expl_data)

    # Build anomaly context
    anomaly_context = _build_anomaly_context(alert, acct_stats, expl_data)

    # Build recommended actions
    actions = _recommend_alert_actions(alert, rules, risk_drivers, expl_data)

    # Confidence
    confidence = _confidence_label(alert.get('fusion_score', 0))

    # Priority
    priority = _compute_priority(alert)

    return {
        'alert_id': alert_id,
        'human_summary': human_summary,
        'risk_drivers': risk_drivers,
        'rule_triggered': rule_context,
        'anomaly_context': anomaly_context,
        'graph_context': graph_context,
        'confidence': confidence,
        'confidence_score': round(alert.get('fusion_score', 0), 4),
        'priority': priority,
        'recommended_actions': actions,
        'severity': alert.get('severity', 'medium'),
        'source': f"Explainability Engine v1.0 — Alert #{alert_id}",
    }


def _compute_risk_drivers(alert, rules, expl_data):
    """Compute ranked risk drivers with numeric contributions."""
    drivers = []

    rule_score = alert.get('rule_score', 0)
    ml_score = alert.get('ml_score', 0)
    graph_score = alert.get('graph_score', 0)
    fusion = alert.get('fusion_score', 0)

    # Rule contribution
    if rule_score > 0.1:
        rule_names = [r['name'] for r in rules[:2]] if rules else ['compliance rule']
        drivers.append({
            'factor': f"Rule violation: {', '.join(rule_names)}",
            'contribution': round(rule_score * 0.4, 3),
            'raw_score': round(rule_score, 4),
            'type': 'rule',
        })

    # ML anomaly
    if ml_score > 0.1:
        desc = 'behavioral anomaly detected'
        if ml_score > 0.7:
            desc = 'strong behavioral anomaly — activity deviates significantly from normal'
        elif ml_score > 0.4:
            desc = 'moderate behavioral anomaly detected by ML model'
        drivers.append({
            'factor': f"ML anomaly: {desc}",
            'contribution': round(ml_score * 0.35, 3),
            'raw_score': round(ml_score, 4),
            'type': 'ml',
        })

    # Graph risk
    if graph_score > 0.1:
        desc = 'network risk detected'
        if graph_score > 0.5:
            desc = 'high-risk network position — connected to suspicious cluster'
        elif graph_score > 0.3:
            desc = 'elevated network risk — unusual connectivity patterns'
        drivers.append({
            'factor': f"Graph analysis: {desc}",
            'contribution': round(graph_score * 0.25, 3),
            'raw_score': round(graph_score, 4),
            'type': 'graph',
        })

    # Cluster boost
    cluster_risk = expl_data.get('cluster_risk', 0)
    if cluster_risk > 0.2:
        drivers.append({
            'factor': f"Cluster risk boost: account belongs to a high-risk behavioral group",
            'contribution': round(cluster_risk * 0.15, 3),
            'raw_score': round(cluster_risk, 4),
            'type': 'cluster',
        })

    # Network flag
    if expl_data.get('network_flag'):
        drivers.append({
            'factor': "Network flag: account connected to known suspicious network",
            'contribution': 0.05,
            'raw_score': 1.0,
            'type': 'network',
        })

    # Sort by contribution
    drivers.sort(key=lambda d: d['contribution'], reverse=True)
    return drivers


def _generate_alert_summary(alert, rules, risk_drivers, acct_stats, expl_data):
    """Generate a plain-English investigator-tone summary."""
    parts = []

    severity = alert.get('severity', 'medium')
    fusion = alert.get('fusion_score', 0)
    account = alert.get('account_id', 'unknown')

    # Opening
    sev_desc = {'critical': 'critical', 'high': 'high-risk', 'medium': 'moderate', 'low': 'low-risk'}
    parts.append(f"This is a {sev_desc.get(severity, 'moderate')} alert for account {account[:16]} "
                 f"with a composite risk score of {fusion:.3f}.")

    # Rule explanation
    if rules:
        rule_names = [r['name'] for r in rules[:3]]
        sev_rules = [r for r in rules if r.get('severity') in ('critical', 'high')]
        if sev_rules:
            parts.append(f"The transaction triggered {len(rules)} compliance rule(s), "
                         f"including {rule_names[0]}, which has {sev_rules[0].get('severity', 'high')} severity.")
        else:
            parts.append(f"The transaction triggered {len(rules)} rule(s): {', '.join(rule_names)}.")

    # Top drivers
    if risk_drivers:
        top = risk_drivers[0]
        parts.append(f"The primary risk driver is {top['factor'].lower()} "
                     f"(contributing +{top['contribution']:.3f} to the risk score).")

    # Account context
    txn_count = acct_stats.get('txn_count', 0)
    if txn_count and txn_count > 0:
        avg_amt = acct_stats.get('avg_amount', 0)
        parts.append(f"The account has {txn_count:,} transactions on record with an average value of ${avg_amt:,.2f}.")

    # Graph context
    if alert.get('graph_score', 0) > 0.3:
        parts.append("Graph analysis indicates elevated network risk — "
                     "the account is positioned within a suspicious community.")

    return " ".join(parts)


def _build_rule_context(rules):
    """Build structured rule context."""
    if not rules:
        return {'rules': [], 'summary': 'No specific rules triggered.'}

    rule_info = []
    for r in rules:
        conditions = {}
        try:
            conditions = json.loads(r.get('conditions', '{}') or '{}')
        except (json.JSONDecodeError, TypeError):
            pass

        rule_info.append({
            'id': r['id'],
            'name': r['name'],
            'type': r.get('rule_type', 'unknown'),
            'severity': r.get('severity', 'medium'),
            'confidence': r.get('confidence', 0),
            'source': r.get('source_document', ''),
            'page': r.get('source_page', 0),
            'conditions_summary': _summarize_conditions(conditions),
        })

    return {
        'rules': rule_info,
        'summary': f"{len(rules)} rule(s) triggered: {', '.join(r['name'] for r in rules[:3])}",
    }


def _summarize_conditions(conditions):
    """Summarize rule conditions in plain English."""
    if not conditions:
        return 'No specific conditions documented.'

    parts = []
    if isinstance(conditions, dict):
        for key, val in list(conditions.items())[:5]:
            if isinstance(val, dict):
                op = val.get('operator', '=')
                threshold = val.get('value', val.get('threshold', ''))
                parts.append(f"{key} {op} {threshold}")
            else:
                parts.append(f"{key}: {val}")
    elif isinstance(conditions, list):
        for c in conditions[:5]:
            if isinstance(c, dict):
                parts.append(c.get('description', str(c)))
            else:
                parts.append(str(c))

    return "; ".join(parts) if parts else 'Complex conditions — see rule detail.'


def _build_graph_context(alert, expl_data):
    """Build graph context explanation."""
    graph_score = alert.get('graph_score', 0)
    if graph_score < 0.05:
        return {'has_graph_risk': False, 'summary': 'No significant graph risk detected.'}

    community = expl_data.get('community', -1)
    cluster_size = expl_data.get('cluster_size', 0)

    parts = []
    if graph_score > 0.5:
        parts.append("The account is positioned in a high-risk network community.")
    elif graph_score > 0.2:
        parts.append("The account shows moderate network connectivity risk.")

    if community >= 0:
        parts.append(f"Community ID: {community}.")
    if cluster_size > 0:
        parts.append(f"Part of a behavioral cluster of {cluster_size} accounts.")

    if expl_data.get('network_flag'):
        parts.append("Flagged as connected to a known suspicious network.")

    return {
        'has_graph_risk': True,
        'graph_score': round(graph_score, 4),
        'community_id': community,
        'cluster_size': cluster_size,
        'summary': " ".join(parts),
    }


def _build_anomaly_context(alert, acct_stats, expl_data):
    """Build anomaly context from ML signals."""
    ml_score = alert.get('ml_score', 0)
    if ml_score < 0.1:
        return {'has_anomaly': False, 'summary': 'No significant behavioral anomaly.'}

    parts = []
    if ml_score > 0.7:
        parts.append(f"Strong anomaly detected (ML score: {ml_score:.3f}).")
        parts.append("The transaction pattern deviates significantly from expected behavior.")
    elif ml_score > 0.4:
        parts.append(f"Moderate anomaly detected (ML score: {ml_score:.3f}).")
    else:
        parts.append(f"Mild anomaly signal (ML score: {ml_score:.3f}).")

    return {
        'has_anomaly': True,
        'ml_score': round(ml_score, 4),
        'summary': " ".join(parts),
    }


def _recommend_alert_actions(alert, rules, risk_drivers, expl_data):
    """Generate recommended next actions for an alert."""
    actions = []
    severity = alert.get('severity', 'medium')
    fusion = alert.get('fusion_score', 0)

    # Always suggest review
    if rules:
        actions.append({
            'action': 'Review triggered compliance rules and verify conditions',
            'priority': 'High' if severity in ('critical', 'high') else 'Medium',
            'rationale': f"{len(rules)} rule(s) violated — verify against policy requirements",
        })

    # Account review
    actions.append({
        'action': 'Review account transaction history for unusual patterns',
        'priority': 'High' if fusion > 0.5 else 'Medium',
        'rationale': 'Assess whether recent activity represents a change from normal behavior',
    })

    # Counterparty check
    if alert.get('graph_score', 0) > 0.2:
        actions.append({
            'action': 'Investigate counterparty accounts and network connections',
            'priority': 'High',
            'rationale': 'Elevated graph risk suggests suspicious network relationships',
        })

    # KYC review for high risk
    if severity in ('critical', 'high'):
        actions.append({
            'action': 'Consider requesting updated KYC documentation',
            'priority': 'Medium',
            'rationale': 'High-risk alert may warrant refreshed due diligence',
        })

    # Escalation for critical
    if severity == 'critical' or fusion > 0.8:
        actions.append({
            'action': 'Consider escalation to senior compliance officer',
            'priority': 'High',
            'rationale': f"Critical risk level (fusion score: {fusion:.3f}) may warrant senior review",
        })

    # Monitoring
    if alert.get('ml_score', 0) > 0.5:
        actions.append({
            'action': 'Flag account for enhanced monitoring over the next 30 days',
            'priority': 'Medium',
            'rationale': 'ML anomaly suggests evolving behavioral pattern worth tracking',
        })

    # Network investigation
    if expl_data.get('network_flag'):
        actions.append({
            'action': 'Examine full network graph for connected suspicious activity',
            'priority': 'High',
            'rationale': 'Account connected to known suspicious network',
        })

    return actions


def _compute_priority(alert):
    fusion = alert.get('fusion_score', 0)
    severity = alert.get('severity', 'medium')
    sev_weight = {'critical': 1.0, 'high': 0.75, 'medium': 0.5, 'low': 0.25}.get(severity, 0.5)
    score = fusion * 0.6 + sev_weight * 0.4
    if score > 0.7: return 'High Priority'
    if score > 0.4: return 'Medium Priority'
    return 'Low Priority'


# ── PART 2: Cluster Explainability ────────────────────────────────

PATTERN_TEMPLATES = {
    'structuring': 'Multiple transactions just below reporting thresholds, suggesting deliberate structuring to avoid detection.',
    'fan_out': 'Funds dispersed from a central account to many recipients, indicative of fund distribution or layering.',
    'fan_in': 'Multiple sources funneling funds into a single account, possibly consolidation of illicit proceeds.',
    'burst_activity': 'Sudden spike in transaction volume or value within a short time window.',
    'high_velocity': 'Rapid fund movement between tightly connected accounts, suggesting layering or pass-through activity.',
    'mule_network': 'Interconnected accounts with similar patterns suggesting coordinated money mule activity.',
    'mixed_risk': 'Alerts with varying risk profiles grouped by behavioral similarity.',
}


def explain_cluster(cluster_id):
    """Generate full human-readable explanation for an alert cluster.

    Returns dict with cluster_summary, dominant_pattern, key_commonalities,
    risk_assessment, analyst_priority, recommended_actions.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Fetch cluster
            cur.execute("SELECT * FROM alert_clusters WHERE cluster_id = %s", [cluster_id])
            cluster = cur.fetchone()
            if not cluster:
                return {'error': f'Cluster {cluster_id} not found'}
            cluster = dict(cluster)

            # Parse stored explanation
            stored_expl = {}
            try:
                stored_expl = json.loads(cluster.get('explanation', '{}') or '{}')
            except (json.JSONDecodeError, TypeError):
                pass

            # Fetch member alerts with details
            cur.execute("""
                SELECT a.id, a.account_id, a.fusion_score, a.rule_score, a.ml_score,
                       a.graph_score, a.severity, a.triggered_rules, a.status
                FROM alert_cluster_members acm
                JOIN alerts a ON a.id = acm.alert_id
                WHERE acm.cluster_id = %s
                ORDER BY a.fusion_score DESC
            """, [cluster_id])
            members = [dict(r) for r in cur.fetchall()]

    finally:
        release_connection(conn)

    # Detect dominant pattern
    dominant_pattern = _detect_pattern(cluster, members, stored_expl)

    # Key commonalities
    commonalities = _find_commonalities(cluster, members, stored_expl)

    # Build cluster summary
    cluster_summary = _generate_cluster_summary(cluster, members, dominant_pattern, commonalities, stored_expl)

    # Risk assessment
    risk_assessment = _cluster_risk_assessment(cluster, members)

    # Recommended actions
    actions = _recommend_cluster_actions(cluster, members, dominant_pattern, risk_assessment)

    # Priority
    priority = cluster.get('priority_score', 0)
    if priority > 0.6:
        priority_label = 'High Priority'
    elif priority > 0.3:
        priority_label = 'Medium Priority'
    else:
        priority_label = 'Low Priority'

    return {
        'cluster_id': cluster_id,
        'cluster_summary': cluster_summary,
        'dominant_pattern': dominant_pattern,
        'key_commonalities': commonalities,
        'risk_assessment': risk_assessment,
        'analyst_priority': priority_label,
        'priority_score': round(cluster.get('priority_score', 0), 4),
        'recommended_actions': actions,
        'member_count': len(members),
        'source': f'Explainability Engine v1.0 — Cluster {cluster_id}',
    }


def _detect_pattern(cluster, members, stored_expl):
    """Detect the dominant pattern in a cluster."""
    homogeneity = cluster.get('rule_homogeneity', 0)
    mean_risk = cluster.get('mean_risk', 0)
    dominant_rule = cluster.get('dominant_rule', '')

    # Analyze rule distribution
    all_rules = []
    for m in members:
        try:
            rules = json.loads(m.get('triggered_rules', '[]') or '[]')
            all_rules.extend(rules)
        except (json.JSONDecodeError, TypeError):
            pass

    unique_accounts = len(set(m.get('account_id', '') for m in members))
    cluster_size = len(members)

    # Pattern detection logic
    if homogeneity > 0.85 and 'threshold' in dominant_rule.lower():
        pattern = 'structuring'
        confidence = homogeneity
    elif unique_accounts < cluster_size * 0.3 and cluster_size > 5:
        pattern = 'fan_out'
        confidence = 1 - (unique_accounts / max(cluster_size, 1))
    elif unique_accounts < 3 and cluster_size > 10:
        pattern = 'fan_in'
        confidence = 0.8
    elif mean_risk > 0.6 and homogeneity > 0.7:
        pattern = 'high_velocity'
        confidence = mean_risk
    elif homogeneity > 0.7:
        pattern = 'burst_activity'
        confidence = homogeneity
    elif mean_risk > 0.5:
        pattern = 'mule_network'
        confidence = mean_risk * 0.8
    else:
        pattern = 'mixed_risk'
        confidence = 0.5

    return {
        'pattern': pattern,
        'label': pattern.replace('_', ' ').title(),
        'description': PATTERN_TEMPLATES.get(pattern, 'Grouped by behavioral similarity.'),
        'confidence': round(confidence, 3),
        'confidence_label': _confidence_label(confidence),
    }


def _find_commonalities(cluster, members, stored_expl):
    """Find key commonalities across cluster members."""
    commonalities = []

    # Shared rule
    homogeneity = cluster.get('rule_homogeneity', 0)
    if homogeneity > 0.5:
        commonalities.append({
            'type': 'shared_rule',
            'description': f"{homogeneity*100:.0f}% of alerts triggered by the same rule ({cluster.get('dominant_rule', 'unknown')})",
            'strength': round(homogeneity, 3),
        })

    # Severity consistency
    sev_counts = Counter(m.get('severity', 'low') for m in members)
    top_sev, top_count = sev_counts.most_common(1)[0] if sev_counts else ('low', 0)
    sev_ratio = top_count / max(len(members), 1)
    if sev_ratio > 0.7:
        commonalities.append({
            'type': 'severity_consistency',
            'description': f"{sev_ratio*100:.0f}% of alerts are {top_sev} severity",
            'strength': round(sev_ratio, 3),
        })

    # Account concentration
    accounts = [m.get('account_id', '') for m in members]
    unique = len(set(accounts))
    if unique < len(members) * 0.5:
        commonalities.append({
            'type': 'account_concentration',
            'description': f"Activity concentrated in {unique} accounts ({len(members)} alerts)",
            'strength': round(1 - unique / max(len(members), 1), 3),
        })

    # Risk profile similarity
    fusions = [m.get('fusion_score', 0) for m in members]
    if fusions:
        std = float(max(0.001, (sum((f - sum(fusions)/len(fusions))**2 for f in fusions) / len(fusions)) ** 0.5))
        if std < 0.1:
            commonalities.append({
                'type': 'risk_similarity',
                'description': f"Tight risk profile (std dev: {std:.4f})",
                'strength': round(1 - std * 5, 3),
            })

    # Top accounts from stored explanation
    top_accounts = stored_expl.get('top_accounts', [])
    if top_accounts and len(top_accounts) > 0:
        top_acct = top_accounts[0]
        if top_acct.get('count', 0) > 3:
            commonalities.append({
                'type': 'shared_entity',
                'description': f"Account {top_acct['account']} appears in {top_acct['count']} alerts",
                'strength': round(min(1.0, top_acct['count'] / 10), 3),
            })

    return commonalities


def _generate_cluster_summary(cluster, members, pattern, commonalities, stored_expl):
    """Generate plain-English cluster summary."""
    size = len(members)
    dom_rule = cluster.get('dominant_rule', 'unknown')
    dom_sev = cluster.get('dominant_severity', 'medium')
    mean_risk = cluster.get('mean_risk', 0)
    unique_accounts = stored_expl.get('unique_accounts', len(set(m.get('account_id', '') for m in members)))

    parts = []

    # Opening
    parts.append(f"This cluster contains {size} alerts grouped by behavioral and risk similarity.")

    # Pattern
    parts.append(f"The dominant pattern detected is **{pattern['label']}** "
                 f"(confidence: {pattern['confidence_label']}) — {pattern['description']}")

    # Risk summary
    if mean_risk > 0.6:
        parts.append(f"The cluster has an elevated average risk score of {mean_risk:.3f}, "
                     f"indicating significant suspicious activity concentration.")
    elif mean_risk > 0.3:
        parts.append(f"The cluster shows moderate risk (avg: {mean_risk:.3f}).")

    # Key details
    if cluster.get('rule_homogeneity', 0) > 0.7:
        parts.append(f"Most alerts ({cluster['rule_homogeneity']*100:.0f}%) "
                     f"are triggered by rule {dom_rule}, suggesting a systematic pattern.")

    parts.append(f"The activity spans {unique_accounts} unique accounts, "
                 f"with the majority classified as {dom_sev} severity.")

    return " ".join(parts)


def _cluster_risk_assessment(cluster, members):
    """Assess cluster risk level."""
    mean_risk = cluster.get('mean_risk', 0)
    max_risk = cluster.get('max_risk', 0)
    size = len(members)

    # Risk level
    if mean_risk > 0.6 or max_risk > 0.8:
        level = 'High'
        assessment = 'This cluster represents significant risk requiring prompt investigation.'
    elif mean_risk > 0.3:
        level = 'Medium'
        assessment = 'This cluster shows moderate risk. Review within standard SLA.'
    else:
        level = 'Low'
        assessment = 'This cluster represents low risk. Consider batch processing.'

    # Concentration risk
    fusions = [m.get('fusion_score', 0) for m in members]
    high_risk_pct = sum(1 for f in fusions if f > 0.5) / max(len(fusions), 1)

    return {
        'level': level,
        'assessment': assessment,
        'mean_risk': round(mean_risk, 4),
        'max_risk': round(max_risk, 4),
        'high_risk_percentage': round(high_risk_pct * 100, 1),
        'cluster_size': size,
    }


def _recommend_cluster_actions(cluster, members, pattern, risk_assessment):
    """Generate recommended actions for a cluster."""
    actions = []
    level = risk_assessment['level']
    pat = pattern['pattern']

    # Pattern-specific actions
    if pat == 'structuring':
        actions.append({
            'action': 'Review transactions against reporting thresholds — possible structuring',
            'priority': 'High',
            'rationale': 'Consistent sub-threshold transactions may indicate deliberate avoidance',
        })
    elif pat in ('fan_out', 'fan_in'):
        actions.append({
            'action': 'Map complete fund flow path to identify origin/destination',
            'priority': 'High',
            'rationale': f"{'Distribution' if pat == 'fan_out' else 'Consolidation'} pattern detected",
        })
    elif pat == 'mule_network':
        actions.append({
            'action': 'Investigate all accounts as potential money mule network',
            'priority': 'High',
            'rationale': 'Coordinated activity patterns suggest organized operation',
        })

    # General cluster actions
    actions.append({
        'action': 'Investigate shared entities and common beneficiaries',
        'priority': 'High' if level == 'High' else 'Medium',
        'rationale': 'Identify whether alerts share counterparties or intermediaries',
    })

    actions.append({
        'action': 'Prioritize top-risk members for individual deep dive',
        'priority': 'Medium',
        'rationale': f"Focus on the {min(5, len(members))} highest-scoring alerts first",
    })

    if level == 'High':
        actions.append({
            'action': 'Consider escalating the cluster as a potential case',
            'priority': 'High',
            'rationale': f"High risk assessment ({risk_assessment['mean_risk']:.3f} avg) warrants senior review",
        })

    actions.append({
        'action': 'Monitor cluster for growth — set alert if new members join',
        'priority': 'Low',
        'rationale': 'Expanding clusters may indicate ongoing activity',
    })

    return actions
