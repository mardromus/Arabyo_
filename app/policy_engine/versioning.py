"""Policy Versioning & Rule Registry — Module 4.

Provides full lifecycle governance for policies and rules:
- PolicyRegistry: versioned policy documents with checksums
- RuleRegistry: dedup, supersession, soft delete, rollback, lineage
- AuditLogger: immutable audit trail for all extraction decisions

v3.0 — PostgreSQL-compatible, regulator-grade, compliance-safe, idempotent.
"""
import hashlib
import json
import logging
from datetime import datetime
from typing import Optional

from app.db import get_connection, release_connection
from app.policy_engine.schemas import ExtractedRule, RuleStatus

logger = logging.getLogger(__name__)


# ── helpers ──────────────────────────────────────────────────────────

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


def _execute_returning(conn, sql, params=None):
    """Execute an INSERT … RETURNING id and return the new id."""
    with conn.cursor() as c:
        c.execute(sql, params or [])
        row = c.fetchone()
        return row[0] if row else None


def _execute_rowcount(conn, sql, params=None):
    """Execute an UPDATE/DELETE and return the number of affected rows."""
    with conn.cursor() as c:
        c.execute(sql, params or [])
        return c.rowcount


# ── Upsert helper for rules ───────────────────────────────────────────

_RULE_UPSERT = """
    INSERT INTO rules (id, name, source_document, source_page, source_text,
        rule_type, conditions, severity, version, status,
        confidence, review_required, ambiguous, rule_hash,
        policy_version, effective_date)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        source_document = EXCLUDED.source_document,
        source_page = EXCLUDED.source_page,
        source_text = EXCLUDED.source_text,
        rule_type = EXCLUDED.rule_type,
        conditions = EXCLUDED.conditions,
        severity = EXCLUDED.severity,
        version = EXCLUDED.version,
        status = EXCLUDED.status,
        confidence = EXCLUDED.confidence,
        review_required = EXCLUDED.review_required,
        ambiguous = EXCLUDED.ambiguous,
        rule_hash = EXCLUDED.rule_hash,
        policy_version = EXCLUDED.policy_version,
        effective_date = EXCLUDED.effective_date,
        updated_at = NOW()
"""


def _rule_params(d):
    return (
        d["rule_id"], d["name"], d.get("source_document", ""),
        d.get("source_page", 0), d.get("source_text", ""),
        d["rule_type"], json.dumps(d["conditions"]),
        d["severity"], d.get("version", "1.0"),
        d.get("status", "draft"),
        d.get("confidence", 0.0),
        1 if d.get("review_required") else 0,
        1 if d.get("ambiguous") else 0,
        d.get("rule_hash", ""),
        d.get("policy_version", ""),
        d.get("effective_date", ""),
    )


# ── Audit Logger ──────────────────────────────────────────────────

class AuditLogger:
    """Immutable audit trail for all policy/rule lifecycle events."""

    @staticmethod
    def log(action: str, policy_id: Optional[str] = None,
            rule_id: Optional[str] = None, details: Optional[dict] = None,
            performed_by: str = "system") -> int:
        """Record an audit event. Returns the new entry ID."""
        conn = get_connection()
        try:
            entry_id = _execute_returning(conn, """
                INSERT INTO extraction_audit_log
                    (policy_id, rule_id, action, details, performed_by)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                policy_id, rule_id, action,
                json.dumps(details or {}, default=str),
                performed_by,
            ))
            conn.commit()
            logger.info(f"[Audit] {action}: policy={policy_id}, rule={rule_id}, by={performed_by}")
            return entry_id or 0
        finally:
            release_connection(conn)

    @staticmethod
    def get_trail(policy_id: Optional[str] = None,
                  rule_id: Optional[str] = None,
                  limit: int = 100) -> list:
        """Retrieve audit trail, newest first."""
        conn = get_connection()
        try:
            conditions = []
            params = []
            if policy_id:
                conditions.append("policy_id = %s")
                params.append(policy_id)
            if rule_id:
                conditions.append("rule_id = %s")
                params.append(rule_id)

            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.append(limit)

            rows = _fetchall(conn, f"""
                SELECT id, policy_id, rule_id, action, details, performed_by, created_at
                FROM extraction_audit_log
                {where}
                ORDER BY created_at DESC
                LIMIT %s
            """, params)

            result = []
            for r in rows:
                r['details'] = json.loads(r['details']) if r.get('details') else {}
                r['created_at'] = str(r.get('created_at', ''))
                result.append(r)
            return result
        finally:
            release_connection(conn)


# ── Policy Registry ──────────────────────────────────────────────

class PolicyRegistry:
    """Manages policy documents with versioning, checksums, and status lifecycle."""

    @staticmethod
    def compute_checksum(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def register_policy(filename: str, raw_text: str, page_count: int,
                        policy_id: Optional[str] = None,
                        uploaded_by: str = "system") -> dict:
        """Register a new policy document or a new version of an existing one."""
        checksum = PolicyRegistry.compute_checksum(raw_text)

        if not policy_id:
            policy_id = f"POL-{hashlib.sha256(filename.encode()).hexdigest()[:8].upper()}"

        conn = get_connection()
        try:
            # Check for duplicate content (idempotent)
            existing = _fetchone(conn,
                "SELECT id, version FROM policy_documents WHERE checksum = %s",
                (checksum,))

            if existing:
                logger.info(f"[PolicyRegistry] Duplicate content (checksum match), "
                            f"returning existing version {existing['version']}")
                return {
                    "policy_id": policy_id,
                    "version": existing["version"],
                    "checksum": checksum,
                    "status": "existing",
                    "db_id": existing["id"],
                }

            # Determine version number
            latest = _fetchone(conn,
                "SELECT version FROM policy_documents WHERE policy_id = %s "
                "ORDER BY uploaded_at DESC LIMIT 1",
                (policy_id,))

            if latest:
                v_num = latest["version"].replace("v", "")
                try:
                    major, minor = v_num.split(".")
                    new_version = f"v{major}.{int(minor) + 1}"
                except (ValueError, IndexError):
                    new_version = "v1.1"
            else:
                new_version = "v1.0"

            # Insert — RETURNING id
            db_id = _execute_returning(conn, """
                INSERT INTO policy_documents
                    (policy_id, filename, version, checksum, raw_text, page_count,
                     uploaded_by, policy_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'draft')
                RETURNING id
            """, (policy_id, filename, new_version, checksum, raw_text,
                  page_count, uploaded_by))
            conn.commit()

            result = {
                "policy_id": policy_id,
                "version": new_version,
                "checksum": checksum,
                "status": "draft",
                "db_id": db_id,
            }

            AuditLogger.log("register_policy", policy_id=policy_id,
                            details={"version": new_version, "checksum": checksum[:16],
                                     "filename": filename, "pages": page_count},
                            performed_by=uploaded_by)
            return result
        finally:
            release_connection(conn)

    @staticmethod
    def resolve_policy_id(identifier: str) -> Optional[str]:
        """Resolve policy identifier (numeric id or policy_id string) to canonical policy_id.
        For legacy rows with NULL policy_id, backfills POL-LEGACY-{id}.
        """
        if not identifier:
            return None
        conn = get_connection()
        try:
            # If it looks like a numeric id, look up by id
            if str(identifier).isdigit():
                row = _fetchone(conn, "SELECT id, policy_id FROM policy_documents WHERE id = %s", (int(identifier),))
                if not row:
                    return None
                pid = row.get("policy_id")
                if pid:
                    return pid
                # Backfill legacy row
                backfill = f"POL-LEGACY-{row['id']}"
                with conn.cursor() as c:
                    c.execute("UPDATE policy_documents SET policy_id = %s WHERE id = %s", (backfill, row["id"]))
                conn.commit()
                return backfill
            # Assume it's already policy_id
            return identifier
        finally:
            release_connection(conn)

    @staticmethod
    def approve_policy(policy_id: str, performed_by: str = "system") -> bool:
        resolved = PolicyRegistry.resolve_policy_id(policy_id)
        if not resolved:
            return False
        policy_id = resolved
        conn = get_connection()
        try:
            rowcount = _execute_rowcount(conn,
                "UPDATE policy_documents SET policy_status = 'approved' "
                "WHERE policy_id = %s AND (policy_status = 'draft' OR policy_status IS NULL)",
                (policy_id,))
            conn.commit()
            if rowcount > 0:
                AuditLogger.log("approve_policy", policy_id=policy_id,
                                performed_by=performed_by)
                # Auto-activate latest ruleset for this policy so rules take effect
                try:
                    from app.policy_engine.rule_set_manager import RuleSetManager
                    rs = _fetchone(conn,
                        "SELECT id FROM rule_sets WHERE policy_id = %s ORDER BY created_at DESC LIMIT 1",
                        (policy_id,))
                    if rs and rs.get("id"):
                        RuleSetManager.activate_ruleset(rs["id"])
                        logger.info(f"[PolicyRegistry] Auto-activated ruleset {rs['id']} for approved policy")
                except Exception as e:
                    logger.warning(f"[PolicyRegistry] Could not auto-activate ruleset: {e}")
                return True
            return False
        finally:
            release_connection(conn)

    @staticmethod
    def retire_policy(policy_id: str, performed_by: str = "system") -> bool:
        resolved = PolicyRegistry.resolve_policy_id(policy_id)
        if not resolved:
            return False
        policy_id = resolved
        conn = get_connection()
        try:
            rowcount = _execute_rowcount(conn,
                "UPDATE policy_documents SET policy_status = 'retired' "
                "WHERE policy_id = %s AND (policy_status IN ('draft', 'approved') OR policy_status IS NULL)",
                (policy_id,))
            conn.commit()
            if rowcount > 0:
                AuditLogger.log("retire_policy", policy_id=policy_id,
                                performed_by=performed_by)
                return True
            return False
        finally:
            release_connection(conn)

    @staticmethod
    def get_policy(policy_id: str) -> Optional[dict]:
        conn = get_connection()
        try:
            return _fetchone(conn,
                "SELECT * FROM policy_documents WHERE policy_id = %s "
                "ORDER BY uploaded_at DESC LIMIT 1",
                (policy_id,))
        finally:
            release_connection(conn)

    @staticmethod
    def get_all_versions(policy_id: str) -> list:
        conn = get_connection()
        try:
            return _fetchall(conn,
                "SELECT * FROM policy_documents WHERE policy_id = %s "
                "ORDER BY uploaded_at DESC",
                (policy_id,))
        finally:
            release_connection(conn)

    @staticmethod
    def delete_policy(policy_id: str, performed_by: str = "system") -> bool:
        """Permanently delete a policy, its PDF file, and all associated rules."""
        resolved = PolicyRegistry.resolve_policy_id(policy_id)
        if not resolved:
            return False
        policy_id = resolved
        
        conn = get_connection()
        try:
            # 1. Get filenames to delete
            docs = _fetchall(conn, "SELECT filename FROM policy_documents WHERE policy_id = %s", (policy_id,))
            filenames = [d["filename"] for d in docs]
            
            if not filenames:
                return False

            # 2. Delete rules associated with these filenames
            from app.db import execute
            placeholders = ",".join(["%s"] * len(filenames))
            execute(f"DELETE FROM rules WHERE source_document IN ({placeholders})", filenames)
            
            # 3. Delete policy documents
            execute("DELETE FROM policy_documents WHERE policy_id = %s", [policy_id])
            
            # 4. Remove physical files
            from app.config import POLICIES_DIR
            import os
            for fname in filenames:
                fpath = os.path.join(POLICIES_DIR, fname)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                        logger.info(f"[PolicyRegistry] Deleted file: {fpath}")
                    except Exception as e:
                        logger.error(f"[PolicyRegistry] Failed to delete file {fpath}: {e}")

            AuditLogger.log("delete_policy", policy_id=policy_id, 
                            details={"filenames": filenames}, performed_by=performed_by)
            return True
        finally:
            release_connection(conn)

    @staticmethod
    def delete_all_data(performed_by: str = "system") -> bool:
        """Wipe ALL policies and rules (nuclear option)."""
        from app.db import execute
        from app.config import POLICIES_DIR
        import os
        
        conn = get_connection()
        try:
            # Get all filenames
            docs = _fetchall(conn, "SELECT filename FROM policy_documents")
            filenames = [d["filename"] for d in docs]
            
            execute("DELETE FROM rules")
            execute("DELETE FROM rule_lineage")
            execute("DELETE FROM rule_sets")
            execute("DELETE FROM policy_documents")
            
            # Remove files
            for fname in filenames:
                fpath = os.path.join(POLICIES_DIR, fname)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
            
            AuditLogger.log("wipe_all_policies", details={"count": len(filenames)}, performed_by=performed_by)
            return True
        finally:
            release_connection(conn)


# ── Rule Registry ────────────────────────────────────────────────

class RuleRegistry:
    """Manages rule lifecycle with dedup, supersession, lineage, and soft delete."""

    @staticmethod
    def register_rules(rules, policy_id: str, policy_version: str = "v1.0") -> dict:
        """DEPRECATED: Use RuleService.create_rules() with a hard version_id constraint."""
        raise NotImplementedError(
            "Standalone rule registration is deprecated. "
            "Use app.policy_engine.rule_service.RuleService.create_rules(version_id, rules) instead."
        )

    @staticmethod
    def supersede_rule(old_rule_id: str, new_rule,
                       reason: str = "policy update",
                       performed_by: str = "system") -> bool:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE rules SET status = 'superseded', updated_at = NOW() "
                    "WHERE id = %s AND is_deleted = 0",
                    (old_rule_id,))

                d = new_rule.to_legacy_dict()
                cur.execute(_RULE_UPSERT, _rule_params(d))

                cur.execute("""
                    INSERT INTO rule_lineage (parent_rule_id, child_rule_id, change_reason)
                    VALUES (%s, %s, %s)
                """, (old_rule_id, new_rule.rule_id, reason))
            
            # Fetch policy_id for audit logging
            # (Reverted: rules table has no policy_id column)

            conn.commit()
        finally:
            release_connection(conn)

        AuditLogger.log("supersede_rule", rule_id=old_rule_id,
                        details={"new_rule_id": new_rule.rule_id, "reason": reason},
                        performed_by=performed_by)
        return True

    @staticmethod
    def soft_delete_rule(rule_id: str, reason: str = "manual deletion",
                         performed_by: str = "system") -> bool:
        conn = get_connection()
        try:
            rowcount = _execute_rowcount(conn,
                "UPDATE rules SET is_deleted = 1, deleted_at = NOW(), "
                "status = 'inactive', updated_at = NOW() "
                "WHERE id = %s AND is_deleted = 0",
                (rule_id,))
            conn.commit()
            if rowcount > 0:
                AuditLogger.log("soft_delete_rule", rule_id=rule_id,
                                details={"reason": reason},
                                performed_by=performed_by)
                return True
            return False
        finally:
            release_connection(conn)

    @staticmethod
    def approve_rule(rule_id: str, performed_by: str = "system") -> bool:
        conn = get_connection()
        try:
            rowcount = _execute_rowcount(conn,
                "UPDATE rules SET status = 'approved', updated_at = NOW() "
                "WHERE id = %s AND status IN ('draft', 'review') AND is_deleted = 0",
                (rule_id,))
            conn.commit()
            if rowcount > 0:
                AuditLogger.log("approve_rule", rule_id=rule_id,
                                performed_by=performed_by)
                return True
            return False
        finally:
            release_connection(conn)

    @staticmethod
    def reject_rule(rule_id: str, reason: str = "",
                    performed_by: str = "system") -> bool:
        conn = get_connection()
        try:
            rowcount = _execute_rowcount(conn,
                "UPDATE rules SET status = 'inactive', updated_at = NOW() "
                "WHERE id = %s AND is_deleted = 0",
                (rule_id,))
            conn.commit()
            if rowcount > 0:
                AuditLogger.log("reject_rule", rule_id=rule_id,
                                details={"reason": reason},
                                performed_by=performed_by)
                return True
            return False
        finally:
            release_connection(conn)

    @staticmethod
    def get_rule_lineage(rule_id: str) -> dict:
        """Trace the full lineage chain for a rule."""
        conn = get_connection()
        try:
            ancestors = _fetchall(conn, """
                SELECT parent_rule_id, child_rule_id, change_reason, created_at
                FROM rule_lineage
                WHERE child_rule_id = %s
                ORDER BY created_at ASC
            """, (rule_id,))

            descendants = _fetchall(conn, """
                SELECT parent_rule_id, child_rule_id, change_reason, created_at
                FROM rule_lineage
                WHERE parent_rule_id = %s
                ORDER BY created_at ASC
            """, (rule_id,))

            return {
                "rule_id": rule_id,
                "ancestors": ancestors,
                "descendants": descendants,
            }
        finally:
            release_connection(conn)

    @staticmethod
    def rollback_to_version(policy_id: str, target_version: str,
                            performed_by: str = "system") -> dict:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE rules SET status = 'inactive', updated_at = NOW()
                    WHERE source_document IN (
                        SELECT filename FROM policy_documents WHERE policy_id = %s
                    ) AND policy_version > %s AND is_deleted = 0
                """, (policy_id, target_version))

                cur.execute("""
                    UPDATE rules SET status = 'active', updated_at = NOW()
                    WHERE source_document IN (
                        SELECT filename FROM policy_documents WHERE policy_id = %s
                    ) AND policy_version = %s AND is_deleted = 0
                """, (policy_id, target_version))
                reactivated = cur.rowcount

            conn.commit()

            AuditLogger.log("rollback", policy_id=policy_id,
                            details={"target_version": target_version,
                                     "reactivated_rules": reactivated},
                            performed_by=performed_by)

            return {"policy_id": policy_id, "target_version": target_version,
                    "reactivated": reactivated}
        finally:
            release_connection(conn)

    @staticmethod
    def get_active_rules(policy_id: Optional[str] = None) -> list:
        conn = get_connection()
        try:
            if policy_id:
                return _fetchall(conn, """
                    SELECT * FROM rules
                    WHERE is_deleted = 0 AND source_document IN (
                        SELECT filename FROM policy_documents WHERE policy_id = %s
                    )
                    ORDER BY created_at DESC
                """, (policy_id,))
            else:
                return _fetchall(conn,
                    "SELECT * FROM rules WHERE is_deleted = 0 ORDER BY created_at DESC")
        finally:
            release_connection(conn)
