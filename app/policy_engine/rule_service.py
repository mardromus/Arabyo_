"""Rule Service - Enforces strict rule-to-policy lineage and lifecycle constraints.

All rule creations and updates must pass through this service to ensure they are
rigidly bound to an existing, valid policy version.
"""
import json
import logging
from typing import List, Dict, Any

from app.db import get_connection, release_connection
from app.policy_engine.versioning import AuditLogger

logger = logging.getLogger(__name__)


class RuleService:
    """Service for managing Rules, strictly tied to policy versions."""

    @staticmethod
    def create_rules(version_id: str, rules_data: List[Dict[str, Any]], created_by: str = "system") -> int:
        """Create or update rules, strictly attaching them to a policy version_id.
        
        Args:
            version_id: The mandatory policy version ID this rule belongs to.
            rules_data: List of rule dictionaries to insert/upsert.
            created_by: The user or system creating the rule.
            
        Returns:
            Number of rules inserted/upserted.
            
        Raises:
            ValueError: If version_id is invalid or missing.
        """
        if not version_id:
            raise ValueError("version_id is strictly required to create rules. Standalone rules are prohibited.")

        conn = get_connection()
        try:
            # 1. Validate version_id exists
            with conn.cursor() as c:
                c.execute("SELECT status FROM policy_versions WHERE version_id = %s", [version_id])
                row = c.fetchone()
                if not row:
                    raise ValueError(f"Invalid version_id '{version_id}'. Policy version does not exist.")
                
                # Rule creation might happen during 'draft' or 'pending_review' stages but must be tied!
                policy_status = row['status'] if isinstance(row, dict) else row[0]
            
            # 2. Upsert Rules
            upsert_sql = """
                INSERT INTO rules (id, version_id, name, source_document, source_page, source_text,
                    rule_type, conditions, severity, version, status,
                    confidence, review_required, ambiguous, rule_hash,
                    policy_version, effective_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    version_id = EXCLUDED.version_id,
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
                    updated_at = datetime('now')
            """
            
            upserted_count = 0
            with conn.cursor() as c:
                for d in rules_data:
                    params = (
                        d["rule_id"], version_id, d["name"], d.get("source_document", ""),
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
                    c.execute(upsert_sql, params)
                    upserted_count += 1
                    
                    AuditLogger.log(
                        action="rule_created",
                        rule_id=d["rule_id"],
                        details={"version_id": version_id, "name": d["name"]},
                        performed_by=created_by
                    )

            conn.commit()
            logger.info(f"[RuleService] Upserted {upserted_count} rules under version_id {version_id}.")
            return upserted_count

        finally:
            release_connection(conn)

    @staticmethod
    def retire_rules_for_policy(version_id: str, retired_by: str = "system") -> int:
        """Soft-delete/retire all rules associated with a specific policy version."""
        conn = get_connection()
        try:
            with conn.cursor() as c:
                c.execute("""
                    UPDATE rules 
                    SET status = 'retired', 
                        is_deleted = 1, 
                        deleted_at = datetime('now')
                    WHERE version_id = %s AND status != 'retired'
                """, [version_id])
                retired_count = c.rowcount
            
            conn.commit()
            
            if retired_count > 0:
                logger.info(f"[RuleService] Retired {retired_count} rules for version_id {version_id}.")
                AuditLogger.log(
                    action="rules_retired_cascade",
                    details={"version_id": version_id, "count": retired_count},
                    performed_by=retired_by
                )
            
            return retired_count
        finally:
            release_connection(conn)

    @staticmethod
    def get_rules_by_version(version_id: str) -> List[Dict[str, Any]]:
        """Retrieve all rules strictly bound to a policy version."""
        conn = get_connection()
        try:
            with conn.cursor() as c:
                c.execute("SELECT * FROM rules WHERE version_id = %s", [version_id])
                rows = c.fetchall()
            return [dict(r) for r in rows] if rows else []
        finally:
            release_connection(conn)
