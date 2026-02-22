"""Rule set versioning — groups of rules by policy version with activate/rollback."""
import json
import logging
from typing import Optional

from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)


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


def _execute_rowcount(conn, sql, params=None):
    with conn.cursor() as c:
        c.execute(sql, params or [])
        return c.rowcount


class RuleSetManager:
    """Manages rule set versions: create, activate, snapshot, and compare."""

    @staticmethod
    def _next_ruleset_version(conn, policy_id: str) -> str:
        """Get next version string (v1.0 -> v1.1 -> v1.2 -> v2.0)."""
        row = _fetchone(
            conn,
            "SELECT ruleset_version FROM rule_sets WHERE policy_id = %s ORDER BY created_at DESC LIMIT 1",
            (policy_id,),
        )
        if not row or not row.get("ruleset_version"):
            return "v1.0"
        v = row["ruleset_version"].replace("v", "")
        try:
            parts = v.split(".")
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            return f"v{major}.{minor + 1}"
        except (ValueError, IndexError):
            return "v1.1"

    @staticmethod
    def create_ruleset(
        policy_id: str,
        policy_version: str,
        rule_ids: list,
        description: Optional[str] = None,
        created_by: str = "system",
    ) -> str:
        """Create a new rule set version. Returns ruleset id (e.g. POL-ABC-RULESET-v1.3)."""
        conn = get_connection()
        try:
            next_ver = RuleSetManager._next_ruleset_version(conn, policy_id)
            ruleset_id = f"{policy_id}-RULESET-{next_ver}"
            rule_ids_json = json.dumps(rule_ids) if rule_ids else "[]"
            with _cur(conn) as c:
                c.execute(
                    """INSERT INTO rule_sets
                        (id, policy_id, policy_version, ruleset_version, rule_ids, created_by, status, description)
                        VALUES (%s, %s, %s, %s, %s, %s, 'draft', %s)""",
                    (
                        ruleset_id,
                        policy_id,
                        policy_version,
                        next_ver,
                        rule_ids_json,
                        created_by,
                        description or "",
                    ),
                )
            conn.commit()
            logger.info(f"[RuleSetManager] Created ruleset {ruleset_id} with {len(rule_ids)} rules")
            return ruleset_id
        finally:
            release_connection(conn)

    @staticmethod
    def get_ruleset(ruleset_id: str) -> Optional[dict]:
        """Retrieve a rule set by id. rule_ids is parsed from JSON."""
        conn = get_connection()
        try:
            row = _fetchone(conn, "SELECT * FROM rule_sets WHERE id = %s", (ruleset_id,))
            if not row:
                return None
            try:
                row["rule_ids"] = json.loads(row["rule_ids"]) if row.get("rule_ids") else []
            except (TypeError, json.JSONDecodeError):
                row["rule_ids"] = []
            return row
        finally:
            release_connection(conn)

    @staticmethod
    def get_active_ruleset(policy_id: str) -> Optional[dict]:
        """Get current active rule set for a policy."""
        conn = get_connection()
        try:
            row = _fetchone(
                conn,
                "SELECT * FROM rule_sets WHERE policy_id = %s AND status = 'active' ORDER BY created_at DESC LIMIT 1",
                (policy_id,),
            )
            if not row:
                return None
            try:
                row["rule_ids"] = json.loads(row["rule_ids"]) if row.get("rule_ids") else []
            except (TypeError, json.JSONDecodeError):
                row["rule_ids"] = []
            return row
        finally:
            release_connection(conn)

    @staticmethod
    def get_active_ruleset_global() -> Optional[str]:
        """Get a single active ruleset id for the app (e.g. for alert tagging). Prefer first policy's active set."""
        conn = get_connection()
        try:
            row = _fetchone(
                conn,
                "SELECT id FROM rule_sets WHERE status = 'active' ORDER BY created_at DESC LIMIT 1",
                (),
            )
            return row["id"] if row else None
        finally:
            release_connection(conn)

    @staticmethod
    def get_active_rule_ids_global() -> list:
        """Get the union of rule_ids from all active rulesets. Used by RuleEngine when no ruleset_id specified."""
        conn = get_connection()
        try:
            rows = _fetchall(
                conn,
                "SELECT id, rule_ids FROM rule_sets WHERE status = 'active' ORDER BY created_at DESC",
                (),
            )
            all_ids = set()
            for row in rows:
                try:
                    ids = json.loads(row["rule_ids"]) if row.get("rule_ids") else []
                    all_ids.update(ids)
                except (TypeError, json.JSONDecodeError):
                    pass
            return list(all_ids)
        finally:
            release_connection(conn)

    @staticmethod
    def activate_ruleset(ruleset_id: str) -> bool:
        """Mark this rule set as active; supersede other active sets for same policy; sync rule status."""
        conn = get_connection()
        try:
            rs = _fetchone(conn, "SELECT policy_id, rule_ids FROM rule_sets WHERE id = %s", (ruleset_id,))
            if not rs:
                return False
            policy_id = rs["policy_id"]
            try:
                new_rule_ids = json.loads(rs["rule_ids"]) if rs.get("rule_ids") else []
            except (TypeError, json.JSONDecodeError):
                new_rule_ids = []

            # Get superseded ruleset's rule_ids (same policy, was active)
            old_rs = _fetchone(
                conn,
                "SELECT rule_ids FROM rule_sets WHERE policy_id = %s AND status = 'active' AND id != %s LIMIT 1",
                (policy_id, ruleset_id),
            )
            old_rule_ids = []
            if old_rs and old_rs.get("rule_ids"):
                try:
                    old_rule_ids = json.loads(old_rs["rule_ids"])
                except (TypeError, json.JSONDecodeError):
                    pass

            with _cur(conn) as c:
                c.execute(
                    "UPDATE rule_sets SET status = 'superseded' WHERE policy_id = %s AND status = 'active'",
                    (policy_id,),
                )
                c.execute(
                    "UPDATE rule_sets SET status = 'active' WHERE id = %s",
                    (ruleset_id,),
                )
                # Sync rule status: new ruleset's rules -> active; old ruleset's rules (not in new) -> inactive
                if old_rule_ids:
                    to_inactive = [rid for rid in old_rule_ids if rid not in new_rule_ids]
                    if to_inactive:
                        ph = ",".join(["%s"] * len(to_inactive))
                        c.execute(
                            f"UPDATE rules SET status = 'inactive', updated_at = datetime('now') WHERE id IN ({ph}) AND is_deleted = 0",
                            to_inactive,
                        )
                if new_rule_ids:
                    ph = ",".join(["%s"] * len(new_rule_ids))
                    c.execute(
                        f"UPDATE rules SET status = 'active', updated_at = datetime('now') WHERE id IN ({ph}) AND is_deleted = 0",
                        new_rule_ids,
                    )
            conn.commit()
            logger.info(f"[RuleSetManager] Activated ruleset {ruleset_id}, synced {len(new_rule_ids)} rules")
            return True
        finally:
            release_connection(conn)

    @staticmethod
    def create_snapshot(ruleset_id: str) -> int:
        """Create immutable snapshot of all rules in this rule set. Returns number of rules snapshotted."""
        conn = get_connection()
        try:
            rs = RuleSetManager.get_ruleset(ruleset_id)
            if not rs or not rs.get("rule_ids"):
                return 0
            rule_ids = rs["rule_ids"]
            if not rule_ids:
                return 0
            placeholders = ",".join(["%s"] * len(rule_ids))
            rules = _fetchall(
                conn,
                f"SELECT * FROM rules WHERE id IN ({placeholders})",
                rule_ids,
            )
            count = 0
            with _cur(conn) as c:
                for r in rules:
                    r_dict = dict(r)
                    rule_data = json.dumps(r_dict)
                    c.execute(
                        "INSERT INTO rule_snapshots (rule_id, ruleset_id, rule_data) VALUES (%s, %s, %s)",
                        (r["id"], ruleset_id, rule_data),
                    )
                    count += 1
            conn.commit()
            logger.info(f"[RuleSetManager] Snapshot created for {ruleset_id}: {count} rules")
            return count
        finally:
            release_connection(conn)

    @staticmethod
    def list_rulesets(policy_id: Optional[str] = None, limit: int = 100) -> list:
        """List rule sets, optionally filtered by policy_id."""
        conn = get_connection()
        try:
            if policy_id:
                return _fetchall(
                    conn,
                    "SELECT * FROM rule_sets WHERE policy_id = %s ORDER BY created_at DESC LIMIT %s",
                    (policy_id, limit),
                )
            return _fetchall(
                conn,
                "SELECT * FROM rule_sets ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
        finally:
            release_connection(conn)

    @staticmethod
    def compare_rulesets(ruleset_id_1: str, ruleset_id_2: str) -> dict:
        """Return high-level comparison (rule id sets). Full diff is done by RuleDiffEngine."""
        rs1 = RuleSetManager.get_ruleset(ruleset_id_1)
        rs2 = RuleSetManager.get_ruleset(ruleset_id_2)
        if not rs1 or not rs2:
            return {"error": "One or both rulesets not found"}
        set1 = set(rs1.get("rule_ids") or [])
        set2 = set(rs2.get("rule_ids") or [])
        return {
            "ruleset_1_id": ruleset_id_1,
            "ruleset_2_id": ruleset_id_2,
            "rule_ids_1": list(set1),
            "rule_ids_2": list(set2),
            "added_in_2": list(set2 - set1),
            "removed_in_2": list(set1 - set2),
            "common": list(set1 & set2),
        }
