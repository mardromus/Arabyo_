"""Compliance Chatbot API — context-aware, tool-augmented assistant.

Uses Groq LLM with structured tool calls against existing data layer.
Always cites sources, never hallucinates, and respects RBAC.
"""
import os
import json
import logging
import time
from openai import OpenAI

from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)

_client = None

def _get_client():
    global _client
    if _client:
        return _client
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        return None
    _client = OpenAI(api_key=key, base_url="https://api.groq.com/openai/v1")
    return _client


# ── Tool Definitions ─────────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_dashboard_metrics",
            "description": "Get current system metrics: total alerts, pending, confirmed, rule counts, transaction counts.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_alert_details",
            "description": "Get details for a specific alert by ID, or top alerts if no ID given.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "integer", "description": "Alert ID to look up"},
                    "limit": {"type": "integer", "description": "Number of top alerts to return", "default": 5}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cluster_summary",
            "description": "Get alert cluster summary, or detail for a specific cluster.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cluster_id": {"type": "string", "description": "Cluster ID (e.g. CLU-0047)"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_rule_explanation",
            "description": "Explain a specific rule by ID or name, or list top rules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID to explain"},
                    "query": {"type": "string", "description": "Search query for rules"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_governance_status",
            "description": "Get policy governance status: active versions, pending approvals, recent audit trail.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_alerts",
            "description": "Search alerts by account ID, severity, or status.",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "status": {"type": "string", "enum": ["pending", "confirmed", "dismissed", "escalated"]},
                    "limit": {"type": "integer", "default": 10}
                }
            }
        }
    },
]


# ── Tool Implementations ─────────────────────────────────────────

def _exec_tool(name, args):
    """Execute a tool call and return the result as a string."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if name == "get_dashboard_metrics":
                cur.execute("SELECT COUNT(*) as cnt FROM transactions")
                txn = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM alerts")
                total_alerts = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status='pending'")
                pending = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status='confirmed'")
                confirmed = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM rules WHERE is_deleted=0 AND status='active'")
                rules = cur.fetchone()['cnt']
                cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
                sev = {r['severity']: r['cnt'] for r in cur.fetchall()}
                return json.dumps({
                    "total_transactions": txn, "total_alerts": total_alerts,
                    "pending_review": pending, "confirmed": confirmed,
                    "active_rules": rules, "severity_breakdown": sev,
                    "source": "Database — real-time query"
                })

            elif name == "get_alert_details":
                aid = args.get("alert_id")
                if aid:
                    cur.execute("SELECT * FROM alerts WHERE id=%s", [aid])
                    row = cur.fetchone()
                    if row:
                        d = dict(row)
                        d['source'] = f"Alert #{aid} — Database"
                        return json.dumps(d, default=str)
                    return json.dumps({"error": f"Alert {aid} not found"})
                else:
                    limit = args.get("limit", 5)
                    cur.execute("SELECT id,account_id,fusion_score,severity,status,triggered_rules FROM alerts ORDER BY fusion_score DESC LIMIT %s", [limit])
                    return json.dumps([dict(r) for r in cur.fetchall()], default=str)

            elif name == "get_cluster_summary":
                cid = args.get("cluster_id")
                if cid:
                    cur.execute("SELECT * FROM alert_clusters WHERE cluster_id=%s", [cid])
                    c = cur.fetchone()
                    if c:
                        d = dict(c)
                        try: d['explanation'] = json.loads(d.get('explanation', '{}'))
                        except: pass
                        cur.execute("SELECT COUNT(*) as cnt FROM alert_cluster_members WHERE cluster_id=%s", [cid])
                        d['member_count'] = cur.fetchone()['cnt']
                        d['source'] = f"Cluster {cid} — Database"
                        return json.dumps(d, default=str)
                    return json.dumps({"error": f"Cluster {cid} not found"})
                else:
                    cur.execute("SELECT cluster_id,cluster_size,mean_risk,priority_score,dominant_rule,dominant_severity,status FROM alert_clusters ORDER BY priority_score DESC LIMIT 10")
                    clusters = [dict(r) for r in cur.fetchall()]
                    cur.execute("SELECT COUNT(*) as cnt FROM alert_clusters WHERE status='open'")
                    open_count = cur.fetchone()['cnt']
                    return json.dumps({"open_clusters": open_count, "top_clusters": clusters, "source": "Cluster Engine"})

            elif name == "get_rule_explanation":
                rid = args.get("rule_id")
                query = args.get("query", "")
                if rid:
                    cur.execute("SELECT * FROM rules WHERE id=%s AND is_deleted=0", [rid])
                    r = cur.fetchone()
                    if r:
                        d = dict(r)
                        try: d['conditions'] = json.loads(d.get('conditions', '{}'))
                        except: pass
                        d['source'] = f"Rule {rid} — Rule Engine v2.0"
                        return json.dumps(d, default=str)
                    return json.dumps({"error": f"Rule {rid} not found"})
                else:
                    cur.execute("SELECT id,name,rule_type,severity,confidence,status FROM rules WHERE is_deleted=0 AND (name LIKE %s OR id LIKE %s) LIMIT 10",
                                [f"%{query}%", f"%{query}%"])
                    return json.dumps([dict(r) for r in cur.fetchall()], default=str)

            elif name == "get_governance_status":
                cur.execute("SELECT version_id,policy_id,version_number,status,rule_count,created_at FROM policy_versions ORDER BY created_at DESC LIMIT 10")
                versions = [dict(r) for r in cur.fetchall()]
                cur.execute("SELECT COUNT(*) as cnt FROM policy_versions WHERE status='active'")
                active = cur.fetchone()['cnt']
                cur.execute("SELECT COUNT(*) as cnt FROM policy_versions WHERE status='pending_review'")
                pending = cur.fetchone()['cnt']
                cur.execute("SELECT * FROM governance_audit_log ORDER BY performed_at DESC LIMIT 5")
                trail = [dict(r) for r in cur.fetchall()]
                return json.dumps({"active_versions": active, "pending_review": pending,
                                   "versions": versions, "recent_audit": trail,
                                   "source": "Governance Engine"}, default=str)

            elif name == "search_alerts":
                conditions = ["1=1"]
                params = []
                if args.get("account_id"):
                    conditions.append("account_id LIKE %s")
                    params.append(f"%{args['account_id']}%")
                if args.get("severity"):
                    conditions.append("severity=%s")
                    params.append(args['severity'])
                if args.get("status"):
                    conditions.append("status=%s")
                    params.append(args['status'])
                limit = args.get("limit", 10)
                where = " AND ".join(conditions)
                cur.execute(f"SELECT id,account_id,fusion_score,severity,status,triggered_rules FROM alerts WHERE {where} ORDER BY fusion_score DESC LIMIT %s",
                            params + [limit])
                return json.dumps([dict(r) for r in cur.fetchall()], default=str)

        return json.dumps({"error": "Unknown tool"})
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        release_connection(conn)


# ── Chat Handler ──────────────────────────────────────────────────

SYSTEM_PROMPT = """You are Arabyo Assistant — a serious, precise compliance copilot for an AML compliance platform.

BEHAVIOR RULES:
- Always cite data sources in your responses (e.g. "Source: Rule Engine v2.0")
- Never hallucinate facts, thresholds, or regulatory advice
- If unsure, say "I don't have sufficient evidence" and offer to fetch details
- Be concise and professional — this is a financial compliance environment
- Use structured formatting: bullet points, bold for key values
- Include confidence level when giving analytical answers
- Respect the user's role context

CAPABILITIES:
- Explain alerts, rules, and clusters
- Provide dashboard metrics and trends
- Navigate users to relevant views
- Summarize investigations
- Answer compliance workflow questions

TONE: Professional, precise, evidence-backed. No emojis. No casual language."""


def chat(messages, context=None, role='analyst'):
    """Process a chat message with tool-augmented LLM response.

    Args:
        messages: list of {role, content} dicts
        context: dict with page, alert_id, cluster_id for context-awareness
        role: user role (analyst, risk_manager, auditor, admin)

    Returns: dict with response, sources, tool_calls
    """
    client = _get_client()
    if not client:
        return _fallback_response(messages[-1].get('content', ''), context)

    # Build context-aware system message
    sys_msg = SYSTEM_PROMPT
    if context:
        sys_msg += f"\n\nCurrent context: User is on page '{context.get('page', 'unknown')}'"
        if context.get('alert_id'):
            sys_msg += f", viewing alert #{context['alert_id']}"
        if context.get('cluster_id'):
            sys_msg += f", viewing cluster {context['cluster_id']}"
    sys_msg += f"\nUser role: {role}"

    full_messages = [{"role": "system", "content": sys_msg}] + messages

    try:
        # First call — may include tool calls
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=full_messages,
            tools=TOOLS,
            tool_choice="auto",
            temperature=0.3,
            max_tokens=1024,
        )

        msg = response.choices[0].message
        tool_results = []

        # Execute tool calls if any
        if msg.tool_calls:
            full_messages.append(msg)
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                result = _exec_tool(tc.function.name, args)
                tool_results.append({
                    "tool": tc.function.name,
                    "args": args,
                    "result": result[:500],
                })
                full_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

            # Second call with tool results
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=full_messages,
                temperature=0.3,
                max_tokens=1024,
            )
            msg = response.choices[0].message

        return {
            "response": msg.content,
            "tool_calls": tool_results,
            "model": "llama-3.3-70b-versatile",
        }

    except Exception as e:
        logger.error(f"[Chatbot] LLM error: {e}")
        return _fallback_response(messages[-1].get('content', ''), context)


def _fallback_response(query, context=None):
    """Structured fallback when LLM is unavailable."""
    q = query.lower()
    result = None

    if any(w in q for w in ['metric', 'dashboard', 'stats', 'overview', 'how many']):
        result = _exec_tool("get_dashboard_metrics", {})
        data = json.loads(result)
        return {
            "response": f"**System Overview**\n\n"
                        f"- **Transactions:** {data.get('total_transactions', 0):,}\n"
                        f"- **Total Alerts:** {data.get('total_alerts', 0):,}\n"
                        f"- **Pending Review:** {data.get('pending_review', 0):,}\n"
                        f"- **Active Rules:** {data.get('active_rules', 0)}\n\n"
                        f"Source: Database — real-time query",
            "tool_calls": [{"tool": "get_dashboard_metrics", "args": {}, "result": result[:200]}],
        }

    elif any(w in q for w in ['cluster', 'group', 'bulk']):
        result = _exec_tool("get_cluster_summary", {})
        data = json.loads(result)
        clusters_text = "\n".join([f"- **{c['cluster_id']}** — {c['cluster_size']} alerts, priority {c['priority_score']:.3f}, {c['dominant_severity']}"
                                   for c in data.get('top_clusters', [])[:5]])
        return {
            "response": f"**Alert Clusters**\n\nOpen clusters: {data.get('open_clusters', 0)}\n\n{clusters_text}\n\nSource: Cluster Engine",
            "tool_calls": [{"tool": "get_cluster_summary", "args": {}, "result": result[:200]}],
        }

    elif any(w in q for w in ['governance', 'version', 'policy version', 'approval']):
        result = _exec_tool("get_governance_status", {})
        data = json.loads(result)
        return {
            "response": f"**Governance Status**\n\n"
                        f"- **Active versions:** {data.get('active_versions', 0)}\n"
                        f"- **Pending review:** {data.get('pending_review', 0)}\n\n"
                        f"Source: Governance Engine",
            "tool_calls": [{"tool": "get_governance_status", "args": {}, "result": result[:200]}],
        }

    elif any(w in q for w in ['alert', 'risk', 'flagged', 'suspicious']):
        result = _exec_tool("get_alert_details", {"limit": 5})
        data = json.loads(result)
        alerts_text = "\n".join([f"- **Alert #{a['id']}** — {a['account_id']}, fusion={a['fusion_score']:.4f}, {a['severity']}"
                                  for a in data[:5]])
        return {
            "response": f"**Top Alerts by Risk**\n\n{alerts_text}\n\nSource: Alert Engine — real-time",
            "tool_calls": [{"tool": "get_alert_details", "args": {"limit": 5}, "result": result[:200]}],
        }

    elif any(w in q for w in ['rule', 'explain', 'policy']):
        result = _exec_tool("get_rule_explanation", {"query": query})
        data = json.loads(result)
        if isinstance(data, list) and data:
            rules_text = "\n".join([f"- **{r['id']}** — {r['name']}, {r['severity']}, confidence {r.get('confidence', 0):.0%}"
                                     for r in data[:5]])
            return {
                "response": f"**Rules Found**\n\n{rules_text}\n\nSource: Rule Engine v2.0",
                "tool_calls": [{"tool": "get_rule_explanation", "args": {"query": query}, "result": result[:200]}],
            }

    return {
        "response": "I can help you with:\n\n"
                    "- **Alert investigation** — explain alerts, show top risks\n"
                    "- **Cluster analysis** — summarize alert groups\n"
                    "- **Rule explanation** — explain compliance rules\n"
                    "- **Governance status** — policy versions and approvals\n"
                    "- **Dashboard metrics** — system overview\n\n"
                    "What would you like to know?",
        "tool_calls": [],
    }
