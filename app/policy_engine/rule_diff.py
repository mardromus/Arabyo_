"""Rule diff engine — compare rules and rulesets with structured diff output."""
import json
from typing import Any, Optional

from app.db import get_connection, release_connection
from app.policy_engine.rule_set_manager import RuleSetManager


def _cur(conn):
    return conn.cursor(cursor_factory=None)


def _fetchone(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        row = c.fetchone()
        return dict(row) if row else None


def _fetchall(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        return [dict(r) for r in c.fetchall()]


def _normalize_rule(r: dict) -> dict:
    """Normalize rule dict for comparison (e.g. parse conditions JSON)."""
    out = dict(r)
    if isinstance(out.get("conditions"), str):
        try:
            out["conditions"] = json.loads(out["conditions"]) if out["conditions"] else []
        except (TypeError, json.JSONDecodeError):
            out["conditions"] = []
    return out


def _condition_key(c: dict) -> str:
    """Stable key for a condition for matching."""
    return f"{c.get('field', '')}|{c.get('operator', '')}|{json.dumps(c.get('value'), sort_keys=True)}"


class RuleDiffEngine:
    """Compare rules and rulesets; produce structured diffs and HTML visualization."""

    # Fields to include in rule comparison (exclude timestamps, internal ids for "modified")
    RULE_COMPARE_FIELDS = (
        "name", "source_document", "source_page", "source_text",
        "rule_type", "conditions", "severity", "version", "status",
        "confidence", "review_required", "ambiguous", "policy_version", "effective_date",
    )

    @staticmethod
    def diff_rules(rule1: dict, rule2: dict) -> dict:
        """
        Compare two rule dicts. Returns:
        - added_fields: keys only in rule2
        - removed_fields: keys only in rule1
        - modified_fields: { field: {'old': v1, 'new': v2} }
        - conditions_diff: { 'added': [...], 'removed': [...], 'modified': [...] }
        """
        r1 = _normalize_rule(rule1)
        r2 = _normalize_rule(rule2)
        keys1 = set(r1.keys())
        keys2 = set(r2.keys())
        added_fields = list(keys2 - keys1)
        removed_fields = list(keys1 - keys2)
        common = keys1 & keys2
        modified_fields = {}
        for k in common:
            if k in ("conditions", "rule_data"):
                continue
            v1, v2 = r1.get(k), r2.get(k)
            if v1 != v2:
                modified_fields[k] = {"old": v1, "new": v2}

        # Conditions diff
        cond1 = r1.get("conditions") or []
        cond2 = r2.get("conditions") or []
        if not isinstance(cond1, list):
            cond1 = []
        if not isinstance(cond2, list):
            cond2 = []
        map1 = {_condition_key(c): c for c in cond1}
        map2 = {_condition_key(c): c for c in cond2}
        added_cond = [map2[k] for k in map2 if k not in map1]
        removed_cond = [map1[k] for k in map1 if k not in map2]
        modified_cond = []
        for k in map1:
            if k in map2 and map1[k] != map2[k]:
                modified_cond.append({"old": map1[k], "new": map2[k]})

        return {
            "added_fields": added_fields,
            "removed_fields": removed_fields,
            "modified_fields": modified_fields,
            "conditions_diff": {
                "added": added_cond,
                "removed": removed_cond,
                "modified": modified_cond,
            },
        }

    @staticmethod
    def diff_rulesets(ruleset_id_1: str, ruleset_id_2: str) -> dict:
        """
        Compare two rulesets. Returns per-rule diffs for common rules,
        plus added/removed rule ids and full rule lists for UI.
        """
        summary = RuleSetManager.compare_rulesets(ruleset_id_1, ruleset_id_2)
        if "error" in summary:
            return summary

        conn = get_connection()
        try:
            def load_rules(rule_ids: list) -> dict:
                if not rule_ids:
                    return {}
                placeholders = ",".join(["%s"] * len(rule_ids))
                rows = _fetchall(conn, f"SELECT * FROM rules WHERE id IN ({placeholders})", rule_ids)
                return {r["id"]: _normalize_rule(r) for r in rows}

            rules1 = load_rules(summary["rule_ids_1"])
            rules2 = load_rules(summary["rule_ids_2"])
        finally:
            release_connection(conn)

        rule_diffs = {}
        for rid in summary["common"]:
            r1 = rules1.get(rid)
            r2 = rules2.get(rid)
            if r1 and r2:
                rule_diffs[rid] = RuleDiffEngine.diff_rules(r1, r2)

        return {
            "ruleset_1_id": ruleset_id_1,
            "ruleset_2_id": ruleset_id_2,
            "added_in_2": summary["added_in_2"],
            "removed_in_2": summary["removed_in_2"],
            "common": summary["common"],
            "rule_diffs": rule_diffs,
            "rules_1": {k: _normalize_rule(v) for k, v in rules1.items()},
            "rules_2": {k: _normalize_rule(v) for k, v in rules2.items()},
        }

    @staticmethod
    def visualize_diff(diff: dict, format: str = "html") -> str:
        """Generate human-readable diff. format: 'html' or 'markdown'."""
        if "error" in diff:
            return f"<p>Error: {diff['error']}</p>" if format == "html" else f"Error: {diff['error']}"

        out = []
        if format == "html":
            out.append("<div class='rule-diff'>")
            out.append(f"<p><strong>Added rules in second ruleset:</strong> {len(diff.get('added_in_2', []))}</p>")
            out.append(f"<p><strong>Removed rules in second ruleset:</strong> {len(diff.get('removed_in_2', []))}</p>")
            out.append(f"<p><strong>Common rules (compared):</strong> {len(diff.get('rule_diffs', {}))}</p>")
            for rule_id, rd in diff.get("rule_diffs", {}).items():
                if not rd.get("modified_fields") and not rd.get("conditions_diff", {}).get("added") and not rd.get("conditions_diff", {}).get("removed") and not rd.get("conditions_diff", {}).get("modified"):
                    continue
                out.append(f"<div class='rule-diff-block'><strong>Rule: {rule_id}</strong>")
                for field, change in rd.get("modified_fields", {}).items():
                    out.append(f"<div class='diff-line'><span class='field'>{field}</span>: ")
                    out.append(f"<span class='old'>{_escape(str(change['old']))}</span> → ")
                    out.append(f"<span class='new'>{_escape(str(change['new']))}</span></div>")
                cd = rd.get("conditions_diff", {})
                if cd.get("added"):
                    out.append("<div class='cond-added'>Conditions added: " + _escape(json.dumps(cd["added"])) + "</div>")
                if cd.get("removed"):
                    out.append("<div class='cond-removed'>Conditions removed: " + _escape(json.dumps(cd["removed"])) + "</div>")
                if cd.get("modified"):
                    out.append("<div class='cond-modified'>Conditions modified: " + _escape(json.dumps(cd["modified"])) + "</div>")
                out.append("</div>")
            out.append("</div>")
            return "\n".join(out)
        else:
            out.append(f"Added in second: {diff.get('added_in_2', [])}")
            out.append(f"Removed in second: {diff.get('removed_in_2', [])}")
            for rule_id, rd in diff.get("rule_diffs", {}).items():
                if rd.get("modified_fields") or rd.get("conditions_diff", {}).get("added") or rd.get("conditions_diff", {}).get("removed"):
                    out.append(f"\nRule {rule_id}:")
                    out.append(f"  Modified: {rd.get('modified_fields', {})}")
                    out.append(f"  Conditions: {rd.get('conditions_diff', {})}")
            return "\n".join(out)


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
