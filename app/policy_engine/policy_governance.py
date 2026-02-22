"""Policy Governance — regulator-grade version lifecycle, approval workflow, and impact analysis.

Builds on top of the existing PolicyRegistry, RuleRegistry, RuleSetManager, and AuditLogger
to provide:
  - Immutable policy version snapshots with state machine (draft → pending_review → approved → active → retired)
  - Maker-checker approval workflow with comment trail
  - Safe rollback (creates new version, never mutates history)
  - Rule impact analysis before activation
  - Version diff engine integration
"""
import json
import hashlib
import logging
from datetime import datetime
from typing import Optional

from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)


def _cur(conn):
    return conn.cursor()


def _fetchone(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        return c.fetchone()


def _fetchall(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        return c.fetchall()


# ── Schema Migration ──────────────────────────────────────────────

GOVERNANCE_DDL = """
CREATE TABLE IF NOT EXISTS policy_versions (
    version_id          TEXT PRIMARY KEY,
    policy_id           TEXT NOT NULL,
    version_number      TEXT NOT NULL,
    checksum_hash       TEXT,
    source_document_uri TEXT,
    extraction_model    TEXT DEFAULT 'groq-gpt-oss-120b',
    created_at          TEXT DEFAULT (datetime('now')),
    created_by          TEXT DEFAULT 'system',
    status              TEXT DEFAULT 'draft',
    effective_from      TEXT,
    effective_to        TEXT,
    change_summary      TEXT,
    parent_version_id   TEXT,
    rule_count          INTEGER DEFAULT 0,
    approval_comment    TEXT,
    approved_by         TEXT,
    approved_at         TEXT
);

CREATE TABLE IF NOT EXISTS governance_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id      TEXT,
    policy_id       TEXT,
    action          TEXT NOT NULL,
    old_status      TEXT,
    new_status      TEXT,
    details         TEXT,
    performed_by    TEXT DEFAULT 'system',
    performed_at    TEXT DEFAULT (datetime('now')),
    ip_address      TEXT,
    system_version  TEXT DEFAULT '2.0'
);

CREATE INDEX IF NOT EXISTS idx_pv_policy ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_pv_status ON policy_versions(status);
CREATE INDEX IF NOT EXISTS idx_gov_audit_version ON governance_audit_log(version_id);
CREATE INDEX IF NOT EXISTS idx_gov_audit_policy ON governance_audit_log(policy_id);
"""


def ensure_governance_schema():
    """Create governance tables if they don't exist."""
    conn = get_connection()
    try:
        with _cur(conn) as c:
            for statement in GOVERNANCE_DDL.strip().split(';'):
                stmt = statement.strip()
                if stmt:
                    c.execute(stmt)
        conn.commit()
    finally:
        release_connection(conn)


# ── State Machine ─────────────────────────────────────────────────

VALID_TRANSITIONS = {
    'draft':          ['pending_review'],
    'pending_review': ['approved', 'draft'],   # Can reject back to draft
    'approved':       ['active', 'retired'],
    'active':         ['retired'],
    'retired':        [],                       # Terminal state
}

STATUS_DISPLAY = {
    'draft': '📝 Draft',
    'pending_review': '🔍 Pending Review',
    'approved': '✅ Approved',
    'active': '🟢 Active',
    'retired': '📦 Retired',
}


class PolicyGovernance:
    """Regulator-grade policy version lifecycle management."""

    # ── Version Creation ──────────────────────────────────────────

    @staticmethod
    def create_version(policy_id, source_document='', raw_text='',
                       change_summary='', created_by='system',
                       parent_version_id=None):
        """Create a new immutable policy version snapshot.

        Returns: version_id string
        """
        ensure_governance_schema()
        conn = get_connection()
        try:
            # Get next version number
            row = _fetchone(conn,
                "SELECT version_number FROM policy_versions WHERE policy_id = %s ORDER BY rowid DESC LIMIT 1",
                [policy_id])
            if row:
                parts = row['version_number'].replace('v', '').split('.')
                major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
                next_version = f"v{major}.{minor + 1}"
            else:
                next_version = "v1.0"

            # Compute checksum
            checksum = hashlib.sha256(f"{policy_id}:{next_version}:{raw_text[:1000]}".encode()).hexdigest()[:16]

            # Build version_id
            version_id = f"{policy_id}-{next_version}"

            # Count rules for this policy
            rule_count_row = _fetchone(conn,
                "SELECT COUNT(*) as cnt FROM rules WHERE source_document LIKE %s AND is_deleted = 0",
                [f"%{source_document}%"])
            rule_count = rule_count_row['cnt'] if rule_count_row else 0

            # If no parent specified, link to the most recent version
            if not parent_version_id and row:
                prev = _fetchone(conn,
                    "SELECT version_id FROM policy_versions WHERE policy_id = %s ORDER BY rowid DESC LIMIT 1",
                    [policy_id])
                parent_version_id = prev['version_id'] if prev else None

            with _cur(conn) as c:
                c.execute("""
                    INSERT INTO policy_versions
                    (version_id, policy_id, version_number, checksum_hash,
                     source_document_uri, created_by, status, change_summary,
                     parent_version_id, rule_count)
                    VALUES (%s, %s, %s, %s, %s, %s, 'draft', %s, %s, %s)
                """, [version_id, policy_id, next_version, checksum,
                      source_document, created_by, change_summary,
                      parent_version_id, rule_count])

                # Audit log
                c.execute("""
                    INSERT INTO governance_audit_log
                    (version_id, policy_id, action, new_status, details, performed_by)
                    VALUES (%s, %s, 'version_created', 'draft', %s, %s)
                """, [version_id, policy_id,
                      json.dumps({'version': next_version, 'checksum': checksum,
                                  'rule_count': rule_count, 'parent': parent_version_id}),
                      created_by])

            conn.commit()
            logger.info(f"[Governance] Created version {version_id} for policy {policy_id}")
            return version_id

        finally:
            release_connection(conn)

    # ── Status Transitions ────────────────────────────────────────

    @staticmethod
    def transition_status(version_id, new_status, performed_by='system',
                          comment='', ip_address=None):
        """Transition a policy version to a new status (state machine enforced).

        Returns: dict with success, old_status, new_status
        """
        ensure_governance_schema()
        conn = get_connection()
        try:
            row = _fetchone(conn,
                "SELECT status, policy_id FROM policy_versions WHERE version_id = %s",
                [version_id])
            if not row:
                return {'success': False, 'error': 'Version not found'}

            old_status = row['status']
            policy_id = row['policy_id']

            allowed = VALID_TRANSITIONS.get(old_status, [])
            if new_status not in allowed:
                return {
                    'success': False,
                    'error': f"Cannot transition from '{old_status}' to '{new_status}'. "
                             f"Allowed: {allowed}"
                }

            # Approval-specific fields
            updates = {'status': new_status}
            if new_status == 'approved':
                updates['approved_by'] = performed_by
                updates['approved_at'] = datetime.now().isoformat()
                updates['approval_comment'] = comment
            elif new_status == 'active':
                updates['effective_from'] = datetime.now().isoformat()
                # Deactivate any other active version for this policy
                with _cur(conn) as c:
                    c.execute("""
                        UPDATE policy_versions SET status = 'retired',
                            effective_to = %s
                        WHERE policy_id = %s AND status = 'active' AND version_id != %s
                    """, [datetime.now().isoformat(), policy_id, version_id])

            # Apply the transition
            set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
            params = list(updates.values()) + [version_id]

            with _cur(conn) as c:
                c.execute(f"UPDATE policy_versions SET {set_clause} WHERE version_id = %s", params)

                # Audit log
                c.execute("""
                    INSERT INTO governance_audit_log
                    (version_id, policy_id, action, old_status, new_status,
                     details, performed_by, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, [version_id, policy_id, f'status_{new_status}',
                      old_status, new_status,
                      json.dumps({'comment': comment}), performed_by, ip_address])

            conn.commit()
            logger.info(f"[Governance] {version_id}: {old_status} → {new_status} by {performed_by}")
            return {'success': True, 'old_status': old_status, 'new_status': new_status}

        finally:
            release_connection(conn)

    # ── Convenience Methods ───────────────────────────────────────

    @staticmethod
    def submit_for_review(version_id, performed_by='system', comment=''):
        """Submit a draft version for review (initiates Maker-Checker workflow)."""
        from app.policy_engine.approval_workflow import ApprovalWorkflow
        ApprovalWorkflow.submit_for_approval('policy_version', version_id, performed_by, comment)
        return PolicyGovernance.transition_status(
            version_id, 'pending_review', performed_by, comment)

    @staticmethod
    def approve(version_id, performed_by='system', comment=''):
        """Approve a version pending review (Maker-Checker). Fails if maker == checker."""
        from app.policy_engine.approval_workflow import ApprovalWorkflow
        ApprovalWorkflow.approve('policy_version', version_id, performed_by, comment)
        return PolicyGovernance.transition_status(
            version_id, 'approved', performed_by, comment)

    @staticmethod
    def reject(version_id, performed_by='system', comment=''):
        """Reject a version pending review."""
        from app.policy_engine.approval_workflow import ApprovalWorkflow
        ApprovalWorkflow.reject('policy_version', version_id, performed_by, comment)
        return PolicyGovernance.transition_status(
            version_id, 'draft', performed_by, comment)

    @staticmethod
    def activate(version_id, performed_by='system', comment=''):
        """Activate an approved version (deactivates previous active version)."""
        result = PolicyGovernance.transition_status(
            version_id, 'active', performed_by, comment)
        if result.get('success'):
            # Sync rule sets
            try:
                from app.policy_engine.rule_set_manager import RuleSetManager
                conn = get_connection()
                try:
                    row = _fetchone(conn,
                        "SELECT policy_id FROM policy_versions WHERE version_id = %s",
                        [version_id])
                    if row:
                        # Activate the corresponding rule set
                        rulesets = _fetchall(conn,
                            "SELECT id FROM rule_sets WHERE policy_id = %s AND status != 'active' ORDER BY created_at DESC LIMIT 1",
                            [row['policy_id']])
                        for rs in rulesets:
                            RuleSetManager.activate_ruleset(rs['id'])
                finally:
                    release_connection(conn)
            except Exception as e:
                logger.warning(f"[Governance] Rule set sync failed: {e}")
        return result

    @staticmethod
    def retire(version_id, performed_by='system', comment=''):
        """Retire a version and cascade retirement to all its associated rules."""
        result = PolicyGovernance.transition_status(
            version_id, 'retired', performed_by, comment)
        if result.get('success'):
            from app.policy_engine.rule_service import RuleService
            RuleService.retire_rules_for_policy(version_id, performed_by)
        return result

    # ── Rollback ──────────────────────────────────────────────────

    @staticmethod
    def rollback(version_id, performed_by='system', reason=''):
        """Rollback to a previous version by creating a new version from it.

        NEVER mutates history — creates a new version entry.
        """
        ensure_governance_schema()
        conn = get_connection()
        try:
            row = _fetchone(conn,
                "SELECT * FROM policy_versions WHERE version_id = %s", [version_id])
            if not row:
                return {'success': False, 'error': 'Version not found'}

            policy_id = row['policy_id']

            # Create new version as rollback
            new_version_id = PolicyGovernance.create_version(
                policy_id=policy_id,
                source_document=row.get('source_document_uri', ''),
                change_summary=f"Rollback to {version_id}. Reason: {reason}",
                created_by=performed_by,
                parent_version_id=version_id,
            )

            # Auto-approve and activate the rollback version
            PolicyGovernance.transition_status(new_version_id, 'pending_review', performed_by,
                                               f'Rollback from {version_id}')
            PolicyGovernance.transition_status(new_version_id, 'approved', performed_by,
                                               f'Auto-approved rollback to {version_id}')
            PolicyGovernance.transition_status(new_version_id, 'active', performed_by,
                                               f'Rollback activated: {reason}')

            # Audit
            conn2 = get_connection()
            try:
                with _cur(conn2) as c:
                    c.execute("""
                        INSERT INTO governance_audit_log
                        (version_id, policy_id, action, details, performed_by)
                        VALUES (%s, %s, 'rollback', %s, %s)
                    """, [new_version_id, policy_id,
                          json.dumps({'rolled_back_to': version_id, 'reason': reason}),
                          performed_by])
                conn2.commit()
            finally:
                release_connection(conn2)

            return {
                'success': True,
                'new_version_id': new_version_id,
                'rolled_back_to': version_id,
            }
        finally:
            release_connection(conn)

    # ── Impact Analysis ───────────────────────────────────────────

    @staticmethod
    def impact_analysis(version_id):
        """Compute expected impact of activating a policy version.

        Returns: dict with alert_delta, affected_accounts, risk_shift, rule_coverage
        """
        ensure_governance_schema()
        conn = get_connection()
        try:
            version = _fetchone(conn,
                "SELECT * FROM policy_versions WHERE version_id = %s", [version_id])
            if not version:
                return {'error': 'Version not found'}

            policy_id = version['policy_id']

            # Current active version
            active = _fetchone(conn,
                "SELECT * FROM policy_versions WHERE policy_id = %s AND status = 'active'",
                [policy_id])

            # Count rules in this version
            new_rules = _fetchone(conn,
                "SELECT COUNT(*) as cnt FROM rules WHERE is_deleted = 0 AND status = 'active'",
                [])
            new_rule_count = new_rules['cnt'] if new_rules else 0

            # Current alerts
            alert_row = _fetchone(conn,
                "SELECT COUNT(*) as cnt FROM alerts", [])
            current_alerts = alert_row['cnt'] if alert_row else 0

            # Severity distribution
            severity_rows = _fetchall(conn,
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity", [])
            severity_dist = {r['severity']: r['cnt'] for r in severity_rows}

            # Rule type distribution
            type_rows = _fetchall(conn,
                "SELECT rule_type, COUNT(*) as cnt FROM rules WHERE is_deleted = 0 AND status = 'active' GROUP BY rule_type", [])
            rule_types = {r['rule_type']: r['cnt'] for r in type_rows}

            # Estimate impact
            estimated_change = 0
            if active:
                old_rule_count = active.get('rule_count', 0) or 0
                rule_delta = new_rule_count - old_rule_count
                estimated_change = int(rule_delta * (current_alerts / max(old_rule_count, 1)) * 0.3)

            return {
                'version_id': version_id,
                'policy_id': policy_id,
                'status': version['status'],
                'rule_count': new_rule_count,
                'current_active_version': active['version_id'] if active else None,
                'current_alert_count': current_alerts,
                'estimated_alert_delta': estimated_change,
                'severity_distribution': severity_dist,
                'rule_type_coverage': rule_types,
                'risk_assessment': 'low' if abs(estimated_change) < 100 else
                                   'medium' if abs(estimated_change) < 1000 else 'high',
            }
        finally:
            release_connection(conn)

    # ── Query Methods ─────────────────────────────────────────────

    @staticmethod
    def get_version(version_id):
        """Get a specific policy version."""
        ensure_governance_schema()
        conn = get_connection()
        try:
            row = _fetchone(conn,
                "SELECT * FROM policy_versions WHERE version_id = %s", [version_id])
            return dict(row) if row else None
        finally:
            release_connection(conn)

    @staticmethod
    def list_versions(policy_id=None, limit=50):
        """List policy versions, optionally filtered by policy_id."""
        ensure_governance_schema()
        conn = get_connection()
        try:
            if policy_id:
                rows = _fetchall(conn,
                    "SELECT * FROM policy_versions WHERE policy_id = %s ORDER BY created_at DESC LIMIT %s",
                    [policy_id, limit])
            else:
                rows = _fetchall(conn,
                    "SELECT * FROM policy_versions ORDER BY created_at DESC LIMIT %s",
                    [limit])
            return [dict(r) for r in rows]
        finally:
            release_connection(conn)

    @staticmethod
    def get_active_version(policy_id):
        """Get the active version for a policy."""
        ensure_governance_schema()
        conn = get_connection()
        try:
            row = _fetchone(conn,
                "SELECT * FROM policy_versions WHERE policy_id = %s AND status = 'active'",
                [policy_id])
            return dict(row) if row else None
        finally:
            release_connection(conn)

    @staticmethod
    def get_audit_trail(version_id=None, policy_id=None, limit=100):
        """Get immutable audit trail for governance actions."""
        ensure_governance_schema()
        conn = get_connection()
        try:
            if version_id:
                rows = _fetchall(conn,
                    "SELECT * FROM governance_audit_log WHERE version_id = %s ORDER BY performed_at DESC LIMIT %s",
                    [version_id, limit])
            elif policy_id:
                rows = _fetchall(conn,
                    "SELECT * FROM governance_audit_log WHERE policy_id = %s ORDER BY performed_at DESC LIMIT %s",
                    [policy_id, limit])
            else:
                rows = _fetchall(conn,
                    "SELECT * FROM governance_audit_log ORDER BY performed_at DESC LIMIT %s",
                    [limit])
            return [dict(r) for r in rows]
        finally:
            release_connection(conn)

    @staticmethod
    def get_version_diff(version_id_1, version_id_2):
        """Get diff between two policy versions using the existing RuleDiffEngine."""
        conn = get_connection()
        try:
            # Get rulesets for each version
            rs1 = _fetchone(conn,
                "SELECT id FROM rule_sets WHERE policy_version = (SELECT version_number FROM policy_versions WHERE version_id = %s) LIMIT 1",
                [version_id_1])
            rs2 = _fetchone(conn,
                "SELECT id FROM rule_sets WHERE policy_version = (SELECT version_number FROM policy_versions WHERE version_id = %s) LIMIT 1",
                [version_id_2])

            if not rs1 or not rs2:
                return {'error': 'Rule sets not found for these versions',
                        'version_1': version_id_1, 'version_2': version_id_2}

            from app.policy_engine.rule_diff import RuleDiffEngine
            return RuleDiffEngine.diff_rulesets(rs1['id'], rs2['id'])
        finally:
            release_connection(conn)

    # ── Bulk Operations ───────────────────────────────────────────

    @staticmethod
    def sync_from_existing():
        """Create governance versions from existing policy_documents for migration.

        This bootstraps the governance system from the existing pipeline data.
        """
        ensure_governance_schema()
        conn = get_connection()
        try:
            # Get all existing policy documents
            docs = _fetchall(conn,
                "SELECT DISTINCT policy_id, filename, version, checksum FROM policy_documents WHERE policy_id IS NOT NULL ORDER BY uploaded_at",
                [])

            created = 0
            for doc in docs:
                pid = doc['policy_id']
                # Check if version already exists
                existing = _fetchone(conn,
                    "SELECT version_id FROM policy_versions WHERE policy_id = %s AND version_number = %s",
                    [pid, doc.get('version', 'v1.0')])
                if existing:
                    continue

                version_id = f"{pid}-{doc.get('version', 'v1.0')}"

                # Count rules for this document
                rule_count_row = _fetchone(conn,
                    "SELECT COUNT(*) as cnt FROM rules WHERE source_document = %s AND is_deleted = 0",
                    [doc['filename']])
                rule_count = rule_count_row['cnt'] if rule_count_row else 0

                with _cur(conn) as c:
                    c.execute("""
                        INSERT INTO policy_versions
                        (version_id, policy_id, version_number, checksum_hash,
                         source_document_uri, status, rule_count, effective_from)
                        VALUES (%s, %s, %s, %s, %s, 'active', %s, %s)
                        ON CONFLICT (version_id) DO NOTHING
                    """, [version_id, pid, doc.get('version', 'v1.0'),
                          doc.get('checksum', ''), doc.get('filename', ''),
                          rule_count, datetime.now().isoformat()])

                    c.execute("""
                        INSERT INTO governance_audit_log
                        (version_id, policy_id, action, new_status, details, performed_by)
                        VALUES (%s, %s, 'migrated', 'active', %s, 'system')
                    """, [version_id, pid,
                          json.dumps({'source': 'migration', 'filename': doc.get('filename', '')})])

                created += 1

            conn.commit()
            logger.info(f"[Governance] Synced {created} versions from existing policy documents")
            return created

        finally:
            release_connection(conn)
