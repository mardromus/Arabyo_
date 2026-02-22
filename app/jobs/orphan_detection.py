"""Orphan Detection Background Job.

Scans the governance database for disjointed rules, detached policy versions,
and orphaned rules (e.g., rules whose parent policy was retired but were not
caught by the cascade).

This can be run via cron, Celery, or an Admin API endpoint.
"""
import logging
from datetime import datetime

from app.db import get_connection, release_connection
from app.policy_engine.versioning import AuditLogger

logger = logging.getLogger(__name__)


def run_orphan_detection() -> dict:
    """Run the orphan detection sweep across the Rules and Policy databases.
    
    Returns a summary dict of orphans detected and quarantined.
    """
    logger.info("[OrphanDetection] Starting governance anomaly sweep...")
    conn = get_connection()
    stats = {
        "rules_flagged_for_review": 0,
        "rules_quarantined": 0,
        "anomalies_found": []
    }
    
    try:
        with conn.cursor() as c:
            # 1. Rules without a valid policy version (Orphans)
            # Should be caught by FK, but good for data integrity checks
            c.execute("""
                SELECT r.id, r.version_id 
                FROM rules r
                LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                WHERE pv.version_id IS NULL AND r.is_deleted = 0
            """)
            orphans = c.fetchall()
            for row in orphans:
                r_id = row['id']
                # Quarantine them
                c.execute("""
                    UPDATE rules 
                    SET status = 'retired', is_deleted = 1, review_required = 1,
                        updated_at = datetime('now')
                    WHERE id = %s
                """, [r_id])
                stats["rules_quarantined"] += 1
                stats["anomalies_found"].append(f"Quarantined orphan rule: {r_id}")
                AuditLogger.log("orphan_quarantined", rule_id=r_id, details={'issue': 'No parent policy version'})

            # 2. Rules active but their policy is retired
            c.execute("""
                SELECT r.id, r.version_id, pv.status as policy_status
                FROM rules r
                JOIN policy_versions pv ON r.version_id = pv.version_id
                WHERE r.is_deleted = 0 AND r.status = 'active' AND pv.status = 'retired'
            """)
            retired_orphans = c.fetchall()
            for row in retired_orphans:
                r_id = row['id']
                v_id = row['version_id']
                c.execute("""
                    UPDATE rules 
                    SET status = 'retired', is_deleted = 1, updated_at = datetime('now')
                    WHERE id = %s
                """, [r_id])
                stats["rules_quarantined"] += 1
                stats["anomalies_found"].append(f"Retired stale rule: {r_id} (Policy {v_id} is retired)")
                AuditLogger.log("stale_rule_retired", rule_id=r_id, details={'policy_version': v_id})

            # 3. Rules belonging to a draft policy but marked active
            c.execute("""
                SELECT r.id, r.version_id, pv.status as policy_status
                FROM rules r
                JOIN policy_versions pv ON r.version_id = pv.version_id
                WHERE r.is_deleted = 0 AND r.status = 'active' AND pv.status IN ('draft', 'pending_review')
            """)
            premature_rules = c.fetchall()
            for row in premature_rules:
                r_id = row['id']
                v_id = row['version_id']
                # Revert to draft/review flagged
                c.execute("""
                    UPDATE rules 
                    SET status = 'draft', review_required = 1, updated_at = datetime('now')
                    WHERE id = %s
                """, [r_id])
                stats["rules_flagged_for_review"] += 1
                stats["anomalies_found"].append(f"Flagged premature rule: {r_id} (Policy {v_id} is not approved)")
                AuditLogger.log("premature_rule_flagged", rule_id=r_id, details={'policy_version': v_id})

        conn.commit()
        logger.info(f"[OrphanDetection] Sweep complete. Quarantined: {stats['rules_quarantined']}, "
                    f"Flagged: {stats['rules_flagged_for_review']}")
        return stats

    except Exception as e:
        conn.rollback()
        logger.error(f"[OrphanDetection] Failed during sweep: {e}")
        raise
    finally:
        release_connection(conn)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_orphan_detection()
    print(f"Results: {results}")
