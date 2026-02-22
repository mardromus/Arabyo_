"""Maker-Checker Approval Workflow for Governance.

Enforces strict separation of duties: the user submitting an artifact for 
approval (Maker) cannot be the same user who approves it (Checker).
"""
import logging
from app.db import get_connection, release_connection

logger = logging.getLogger(__name__)


class ApprovalWorkflow:
    """Manages maker-checker approvals for governance entities."""

    @staticmethod
    def submit_for_approval(entity_type: str, entity_id: str, submitter: str, comments: str = "") -> int:
        """Submit an entity for review."""
        conn = get_connection()
        try:
            with conn.cursor() as c:
                # Cancel any existing pending requests for this entity
                c.execute("""
                    UPDATE governance_approvals 
                    SET status = 'cancelled' 
                    WHERE entity_type = %s AND entity_id = %s AND status = 'pending'
                """, [entity_type, entity_id])
                
                # Insert new request
                c.execute("""
                    INSERT INTO governance_approvals (entity_type, entity_id, submitter, comments, status)
                    VALUES (%s, %s, %s, %s, 'pending')
                    RETURNING id
                """, [entity_type, entity_id, submitter, comments])
                
                row = c.fetchone()
                approval_id = row['id'] if isinstance(row, dict) else row[0]
                
            conn.commit()
            logger.info(f"[ApprovalWorkflow] {submitter} submitted {entity_type} {entity_id} for approval.")
            return approval_id
        finally:
            release_connection(conn)

    @staticmethod
    def approve(entity_type: str, entity_id: str, reviewer: str, comments: str = "") -> bool:
        """Approve a pending request. Fails if reviewer == submitter."""
        conn = get_connection()
        try:
            with conn.cursor() as c:
                c.execute("""
                    SELECT id, submitter FROM governance_approvals 
                    WHERE entity_type = %s AND entity_id = %s AND status = 'pending'
                    ORDER BY submitted_at DESC LIMIT 1
                """, [entity_type, entity_id])
                
                req = c.fetchone()
                if not req:
                    raise ValueError(f"No pending approval request found for {entity_type} {entity_id}")
                
                req_dict = dict(req) if not isinstance(req, dict) else req
                submitter = req_dict['submitter']
                approval_id = req_dict['id']
                
                if submitter == reviewer:
                    raise PermissionError(f"Maker-Checker Violation: {reviewer} cannot approve their own submission.")
                
                c.execute("""
                    UPDATE governance_approvals
                    SET status = 'approved', reviewer = %s, reviewed_at = datetime('now'), comments = %s
                    WHERE id = %s
                """, [reviewer, comments, approval_id])
                
            conn.commit()
            logger.info(f"[ApprovalWorkflow] {reviewer} approved {entity_type} {entity_id}.")
            return True
        finally:
            release_connection(conn)

    @staticmethod
    def reject(entity_type: str, entity_id: str, reviewer: str, comments: str = "") -> bool:
        """Reject a pending request."""
        if not comments:
            raise ValueError("Comments are required when rejecting an approval.")
            
        conn = get_connection()
        try:
            with conn.cursor() as c:
                c.execute("""
                    SELECT id FROM governance_approvals 
                    WHERE entity_type = %s AND entity_id = %s AND status = 'pending'
                    ORDER BY submitted_at DESC LIMIT 1
                """, [entity_type, entity_id])
                
                req = c.fetchone()
                if not req:
                    raise ValueError(f"No pending approval request found for {entity_type} {entity_id}")
                
                req_id = req['id'] if isinstance(req, dict) else req[0]
                
                c.execute("""
                    UPDATE governance_approvals
                    SET status = 'rejected', reviewer = %s, reviewed_at = datetime('now'), comments = %s
                    WHERE id = %s
                """, [reviewer, comments, req_id])
                
            conn.commit()
            logger.info(f"[ApprovalWorkflow] {reviewer} rejected {entity_type} {entity_id}.")
            return True
        finally:
            release_connection(conn)
