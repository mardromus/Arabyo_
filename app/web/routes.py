"""Flask web application routes for the compliance dashboard — PostgreSQL backend."""
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session, g

from app.config import (
    BASE_DIR,
    DATASET_DIR,
    DB_PATH,
    TRANSACTIONS_CSV,
    ACCOUNTS_CSV,
    REPORTS_DIR,
    POLICIES_DIR,
    DATABASE_URL,
    FIREBASE_CONFIG,
    FIREBASE_AUTH_DISABLED,
)
from app.db import get_connection, release_connection, query, execute


def _cur(conn):
    return conn.cursor(cursor_factory=None)


def _fetchall(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        return [dict(r) for r in c.fetchall()]


def _fetchone(conn, sql, params=None):
    with _cur(conn) as c:
        c.execute(sql, params or [])
        row = c.fetchone()
        return dict(row) if row else None


def _validate_dataset_path(path, name):
    """Validate that path resolves under BASE_DIR or DATASET_DIR. Returns (ok, resolved_path, error)."""
    if not path or not (path := str(path).strip()):
        return True, None, None  # optional
    try:
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(BASE_DIR, path))
        resolved = os.path.realpath(os.path.abspath(path))
        base_real = os.path.realpath(BASE_DIR)
        ds_real = os.path.realpath(DATASET_DIR)
        ok = (
            resolved == base_real or resolved.startswith(base_real + os.sep) or
            resolved.startswith(base_real + "/") or
            resolved == ds_real or resolved.startswith(ds_real + os.sep) or
            resolved.startswith(ds_real + "/")
        )
        if not ok:
            return False, None, f"{name} path must be under project or Dataset directory"
        return True, resolved, None
    except Exception as e:
        return False, None, str(e)


def _chat_help_reply(message: str) -> str:
    """Rule-based help replies for the Control Center chatbot. Case-insensitive keyword match."""
    m = message.lower()
    if not m:
        return "Type a question about policies, rules, or how to use this Control Center."
    if any(w in m for w in ('upload', 'add policy', 'new policy', 'pdf')):
        return (
            "To upload a policy: use **Upload Version** in the Policy Overview bar. "
            "Supported format is PDF. After upload, rules can be extracted from the document. "
            "You can also use the legacy Policies page at /policies for bulk upload."
        )
    if any(w in m for w in ('rule', 'extract', 'derived')):
        return (
            "Rules are compliance rules extracted from policy documents. Each rule has severity, "
            "confidence, conditions, and a link to the source clause (Policy Traceability). "
            "Click a row in the Rules table to open the Rule Intelligence drawer and see derivation, "
            "DSL, and performance. Ambiguous rules are flagged for review."
        )
    if any(w in m for w in ('version', 'compare', 'compare version')):
        return (
            "Use **Compare Versions** in the Policy Overview bar to diff two policy versions. "
            "Version history is available per policy. Admin users can roll back to a previous version."
        )
    if any(w in m for w in ('rule set', 'ruleset', 'create rule set')):
        return (
            "A **Rule Set** groups rules for a policy version. Use **Create Rule Set** (admin or risk manager) "
            "to snapshot the current rules. You can then activate a rule set for monitoring and compare sets."
        )
    if any(w in m for w in ('severity', 'critical', 'high', 'medium', 'low')):
        return (
            "Rule severity: **Critical** (highest), **High**, **Medium**, **Low**. "
            "It reflects the impact of a violation. Use the table column or the Rule drawer to see severity."
        )
    if any(w in m for w in ('confidence', 'ambiguity', 'ambiguous')):
        return (
            "**Confidence** is how sure the system is that the rule was correctly extracted (0–100%). "
            "**Ambiguity** means the source text was unclear; such rules are flagged for human review."
        )
    if any(w in m for w in ('traceability', 'source', 'clause', 'policy trace')):
        return (
            "**Policy Traceability** in the Rule drawer shows the original document, page number, "
            "and the exact clause the rule was derived from. Use **View in Document** to open the PDF."
        )
    if any(w in m for w in ('role', 'permission', 'admin', 'auditor', 'analyst')):
        return (
            "Roles: **Admin** (edit, approve, rollback), **Risk manager** (approve, simulate, create rule sets), "
            "**Analyst** (view, filter), **Auditor** (read-only). Your role controls which actions you see."
        )
    if any(w in m for w in ('simulate', 'simulation')):
        return (
            "Use **Simulate** in the Rule drawer (admin/risk manager) or the Simulation page to run rules "
            "against sample data and see impact before activating a rule set."
        )
    if any(w in m for w in ('help', 'how', 'what can you', 'what do you')):
        return (
            "I can help with: uploading policies, understanding rules and severity, comparing versions, "
            "rule sets, policy traceability, roles and permissions, and simulation. Ask something like: "
            "'How do I upload a policy?' or 'What is rule traceability?'"
        )
    return (
        "I'm the Control Center help assistant. Ask about **uploading policies**, **rules and severity**, "
        "**comparing versions**, **rule sets**, **traceability**, **roles**, or **simulation**. "
        "If your question wasn't answered, try rephrasing or ask 'What can you help with?'"
    )


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
                static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    app.secret_key = os.environ.get('SECRET_KEY', 'compliance-agent-secret-2024')

    # Auth imports
    from app.auth.firebase_auth import (
        init_firebase, verify_token, get_user_role,
        _get_current_user_from_session,
    )

    # Ensure schema exists on startup
    try:
        from app.db import init_db
        init_db()
    except Exception as e:
        app.logger.warning(f'[startup] DB init warning: {e}')

    # Seed demo data if running on Railway/cloud with empty DB
    try:
        from seed_demo import seed_demo_data
        seed_demo_data()
    except Exception as e:
        app.logger.warning(f'[startup] Demo seed warning (non-fatal): {e}')

    # ------------------------------------------------------------------
    # AUTH — require login unless disabled or public route
    # ------------------------------------------------------------------
    @app.before_request
    def require_auth():
        if FIREBASE_AUTH_DISABLED:
            # Auto-inject a default session user so the app works without login
            if 'user' not in session:
                role = request.args.get('role', 'admin')
                if role not in ('admin', 'analyst', 'risk_manager', 'auditor'):
                    role = 'admin'
                session['user'] = {'email': 'demo@arabyo.ai', 'name': 'Demo User', 'role': role}
            return None
        if request.endpoint in ('login', 'logout', 'api_session'):
            return None
        if request.path.startswith('/static/'):
            return None
        user = _get_current_user_from_session(session)
        if not user:
            session['next'] = request.url
            return redirect(url_for('login'))

    # ------------------------------------------------------------------
    # TEMPLATE CONTEXT — role & pipeline status for all templates
    # ------------------------------------------------------------------
    @app.context_processor
    def inject_global_context():
        if FIREBASE_AUTH_DISABLED:
            # Read role from session first, then URL param fallback, default admin
            stored_role = session.get('user', {}).get('role', 'admin')
            user_role = request.args.get('role', stored_role)
            if user_role not in ('admin', 'analyst', 'risk_manager', 'auditor'):
                user_role = 'admin'
            # Keep session in sync with URL param override
            if 'user' in session:
                session['user']['role'] = user_role
            current_user = None
        else:
            user = _get_current_user_from_session(session)
            user_role = user.get('role', 'analyst') if user else 'analyst'
            current_user = user
        try:
            conn = get_connection()
            row = _fetchone(conn, "SELECT COUNT(*) as cnt FROM alerts WHERE status='pending'")
            pending_count = row['cnt'] if row else 0
        except Exception:
            pending_count = 0
        finally:
            try:
                release_connection(conn)
            except Exception:
                pass
        return {
            'user_role': user_role,
            'current_user': current_user,
            'pipeline_status': 'active',
            'pending_count': pending_count,
            'auth_enabled': not FIREBASE_AUTH_DISABLED,
        }

    # ------------------------------------------------------------------
    # LOGIN / LOGOUT
    # ------------------------------------------------------------------
    @app.route('/login')
    def login():
        # Login page removed — redirect directly to dashboard
        return redirect(url_for('dashboard'))

    @app.route('/logout')
    def logout():
        session.pop('user', None)
        session.pop('next', None)
        return redirect(url_for('dashboard'))

    @app.route('/set-role', methods=['POST'])
    def set_role():
        """Persist role selection in session (no login required)."""
        role = request.form.get('role', 'admin')
        if role not in ('admin', 'analyst', 'risk_manager', 'auditor'):
            role = 'admin'
        if 'user' not in session:
            session['user'] = {'email': 'demo@arabyo.ai', 'name': 'Demo User', 'role': role}
        else:
            session['user']['role'] = role
        session.modified = True
        next_url = request.form.get('next') or '/'
        return redirect(next_url)

    @app.route('/admin/users')
    def admin_users():
        """Admin: user role management."""
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return redirect(url_for('dashboard'))
        if FIREBASE_AUTH_DISABLED and request.args.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        conn = get_connection()
        try:
            users = _fetchall(conn, "SELECT * FROM user_roles ORDER BY role, email")
        finally:
            release_connection(conn)
        return render_template('admin_users.html', users=users)

    @app.route('/admin/users/add', methods=['POST'])
    def admin_users_add():
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return jsonify({'error': 'Admin required'}), 403
        email = (request.form.get('email') or '').strip().lower()
        role = (request.form.get('role') or 'analyst').strip().lower()
        if not email:
            return redirect(url_for('admin_users'))
        if role not in ('admin', 'analyst', 'risk_manager', 'auditor'):
            role = 'analyst'
        execute("""
            INSERT INTO user_roles (email, role)
            VALUES (%s, %s)
            ON CONFLICT (email) DO UPDATE SET role=excluded.role, updated_at=datetime('now')
        """, [email, role])
        return redirect(url_for('admin_users'))

    @app.route('/admin/users/delete', methods=['POST'])
    def admin_users_delete():
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return jsonify({'error': 'Admin required'}), 403
        email = (request.form.get('email') or '').strip().lower()
        if email:
            execute("DELETE FROM user_roles WHERE email = %s", [email])
        return redirect(url_for('admin_users'))

    @app.route('/admin/dataset')
    def admin_dataset():
        """Admin: data sources / import dataset settings."""
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return redirect(url_for('dashboard'))
        if FIREBASE_AUTH_DISABLED and request.args.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return render_template('dataset_settings.html', **{
            'transactions_csv': TRANSACTIONS_CSV,
            'accounts_csv': ACCOUNTS_CSV,
            'database_path': DB_PATH,
        })

    @app.route('/api/dataset/config')
    def api_dataset_config():
        """Admin-only: return current dataset config (transactions_csv, accounts_csv, database_path)."""
        if FIREBASE_AUTH_DISABLED:
            if request.args.get('role', 'analyst') != 'admin':
                return jsonify({'error': 'Admin required'}), 403
        else:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') != 'admin':
                return jsonify({'error': 'Admin required'}), 403
        return jsonify({
            'transactions_csv': TRANSACTIONS_CSV,
            'accounts_csv': ACCOUNTS_CSV,
            'database_path': DB_PATH,
        })

    @app.route('/api/session', methods=['POST'])
    def api_session():
        """Exchange Firebase ID token for server session. Returns user + role."""
        if FIREBASE_AUTH_DISABLED:
            return jsonify({'error': 'Firebase auth is disabled'}), 400
        data = request.get_json() or {}
        id_token = data.get('idToken') or data.get('id_token')
        if not id_token:
            return jsonify({'error': 'Missing idToken'}), 400
        claims, token_error = verify_token(id_token)
        if not claims:
            messages = {
                'expired': 'Your session expired. Please sign in again.',
                'invalid': 'Invalid or expired token. Please sign in again.',
                'unavailable': 'Authentication service unavailable. Try again later.',
                'firebase_not_installed': 'Firebase Admin SDK is not installed. Run: pip install firebase-admin',
                'service_account_not_found': 'Service account file not found. Add credentials/firebase-adminsdk.json (download from Firebase Console → Project Settings → Service accounts).',
                'service_account_invalid': 'Service account file is invalid or incomplete. Re-download the JSON key from Firebase Console.',
                'init_error': 'Firebase could not start. Check server logs.',
            }
            return jsonify({
                'error': messages.get(token_error, 'Authentication service unavailable. Try again later.'),
                'code': token_error or 'invalid',
            }), 401
        role = get_user_role(claims.get('email', ''))
        user = {
            'uid': claims.get('uid'),
            'email': claims.get('email'),
            'name': claims.get('name'),
            'role': role,
        }
        session['user'] = user
        next_url = session.pop('next', None) or '/'
        return jsonify({'user': user, 'next': next_url})

    # ------------------------------------------------------------------
    # DASHBOARD
    # ------------------------------------------------------------------
    @app.route('/')
    def dashboard():
        """Main compliance dashboard."""
        conn = get_connection()
        try:
            def cnt(sql):
                return (_fetchone(conn, sql) or {}).get('cnt', 0)

            stats = {
                'total_txn':      cnt("SELECT COUNT(*) as cnt FROM transactions"),
                'total_alerts':   cnt("SELECT COUNT(*) as cnt FROM alerts"),
                'pending':        cnt("SELECT COUNT(*) as cnt FROM alerts WHERE status='pending'"),
                'confirmed':      cnt("SELECT COUNT(*) as cnt FROM alerts WHERE review_action='confirm'"),
                'dismissed':      cnt("SELECT COUNT(*) as cnt FROM alerts WHERE review_action='dismiss'"),
                'total_rules':    cnt("SELECT COUNT(*) as cnt FROM rules WHERE status='active'"),
                'total_policies': cnt("SELECT COUNT(*) as cnt FROM policy_documents"),
            }

            severity_rows = _fetchall(conn, "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
            stats['severity'] = {r['severity']: r['cnt'] for r in severity_rows}

            recent_alerts = _fetchall(conn, "SELECT * FROM alerts ORDER BY fusion_score DESC LIMIT 10")
            stats['recent_alerts'] = recent_alerts

            top_accounts = _fetchall(conn, """
                SELECT account_id, fusion_score, rule_score, ml_score, graph_score, severity
                FROM alerts ORDER BY fusion_score DESC LIMIT 10
            """)
            stats['top_accounts'] = top_accounts

            launder_row = _fetchone(conn, "SELECT SUM(is_laundering) as launder_count FROM transactions")
            stats['known_laundering'] = (launder_row or {}).get('launder_count') or 0

            last_scan = _fetchone(conn,
                "SELECT completed_at, transactions_scanned, alerts_generated FROM monitoring_runs WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1")
            stats['last_scan'] = last_scan

        finally:
            release_connection(conn)

        return render_template('dashboard.html', stats=stats)

    # ------------------------------------------------------------------
    # ALERTS
    # ------------------------------------------------------------------
    @app.route('/alerts')
    def alerts_list():
        """Paginated alert list."""
        page = int(request.args.get('page', 1))
        per_page = 20
        severity_filter = request.args.get('severity', '')
        status_filter = request.args.get('status', '')
        rule_set_version = request.args.get('rule_set_version', '').strip() or None

        conn = get_connection()
        try:
            where = []
            params = []
            if severity_filter:
                where.append("severity = %s")
                params.append(severity_filter)
            if status_filter:
                where.append("status = %s")
                params.append(status_filter)
            if rule_set_version:
                where.append("rule_set_version = %s")
                params.append(rule_set_version)

            where_clause = " WHERE " + " AND ".join(where) if where else ""

            total = (_fetchone(conn,
                f"SELECT COUNT(*) as cnt FROM alerts{where_clause}", params) or {}).get('cnt', 0)

            alerts = _fetchall(conn,
                f"SELECT * FROM alerts{where_clause} ORDER BY fusion_score DESC LIMIT %s OFFSET %s",
                params + [per_page, (page - 1) * per_page])

        finally:
            release_connection(conn)

        return render_template('alerts.html',
                               alerts=alerts,
                               page=page, per_page=per_page, total=total,
                               severity_filter=severity_filter,
                               status_filter=status_filter,
                               rule_set_version=rule_set_version)

    @app.route('/alerts/<int:alert_id>')
    def alert_detail(alert_id):
        """Alert detail with full explanation."""
        conn = get_connection()
        try:
            alert = _fetchone(conn, "SELECT * FROM alerts WHERE id = %s", [alert_id])
            if not alert:
                return "Alert not found", 404

            alert['triggered_rules_list'] = json.loads(alert.get('triggered_rules') or '[]')
            alert['explanation_data'] = json.loads(alert.get('explanation') or '{}')

            account_id = alert.get('account_id', '')
            parts = account_id.split('_', 1)
            transactions = []
            if len(parts) == 2:
                bank_id, acct_num = parts
                transactions = _fetchall(conn, """
                    SELECT * FROM transactions
                    WHERE (from_bank = %s AND from_account = %s)
                       OR (to_bank = %s AND to_account = %s)
                    ORDER BY amount_paid DESC LIMIT 25
                """, [bank_id, acct_num, bank_id, acct_num])

            rules = []
            for rule_id in alert['triggered_rules_list']:
                r = _fetchone(conn, """
                    SELECT r.*, pv.version_id as gov_version_id, pv.status as gov_status
                    FROM rules r
                    LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                    WHERE r.id = %s
                """, [rule_id])
                if r:
                    rules.append(r)

            review_history = _fetchall(conn, """
                SELECT * FROM alert_review_history
                WHERE alert_id = %s
                ORDER BY performed_at DESC
            """, [alert_id])

        finally:
            release_connection(conn)

        return render_template('alert_detail.html',
                               alert=alert, transactions=transactions, rules=rules,
                               review_history=review_history or [])

    @app.route('/alerts/<int:alert_id>/review', methods=['POST'])
    def review_alert(alert_id):
        """Human review action on an alert."""
        action = request.form.get('action', '')
        notes = request.form.get('notes', '')
        user = _get_current_user_from_session(session)
        if FIREBASE_AUTH_DISABLED:
            reviewer = request.form.get('reviewer', 'analyst')
            role = request.args.get('role', request.form.get('role', 'analyst'))
        else:
            reviewer = user.get('email') or user.get('name', 'analyst') if user else 'unknown'
            role = user.get('role', 'analyst') if user else 'analyst'

        if action not in ('confirm', 'dismiss', 'escalate'):
            return jsonify({'error': 'Invalid action'}), 400

        status = 'confirmed' if action == 'confirm' else 'dismissed' if action == 'dismiss' else 'escalated'

        execute("""
            UPDATE alerts SET status=%s, review_action=%s, review_notes=%s,
                reviewed_by=%s, reviewed_at=NOW()
            WHERE id=%s
        """, [status, action, notes, reviewer, alert_id])

        execute("""
            INSERT INTO alert_review_history (alert_id, action, performed_by, notes)
            VALUES (%s, %s, %s, %s)
        """, [alert_id, action, reviewer, notes])

        if FIREBASE_AUTH_DISABLED:
            return redirect(url_for('alert_detail', alert_id=alert_id, role=role))
        return redirect(url_for('alert_detail', alert_id=alert_id))

    # ------------------------------------------------------------------
    # ALERT CLUSTERS PAGE
    # ------------------------------------------------------------------
    @app.route('/clusters')
    def clusters_page():
        """Alert cluster resolution interface."""
        return render_template('clusters.html')

    # ------------------------------------------------------------------
    # GOVERNANCE PAGE
    # ------------------------------------------------------------------
    @app.route('/governance')
    def governance_page():
        """Policy governance — version lifecycle, approvals, audit trail."""
        return render_template('governance.html')

    # ------------------------------------------------------------------
    # POLICIES
    # ------------------------------------------------------------------
    @app.route('/policies')
    def policies():
        """View uploaded policies and extracted rules."""
        sort_by = request.args.get('sort', 'severity')  # severity, confidence, status, type, date
        order = request.args.get('order', 'desc')  # asc, desc
        
        conn = get_connection()
        try:
            policy_docs = _fetchall(conn, "SELECT * FROM policy_documents ORDER BY uploaded_at DESC")
            # Backfill policy_id for legacy rows so approve/retire work
            for p in policy_docs:
                if not p.get('policy_id'):
                    backfill = f"POL-LEGACY-{p['id']}"
                    execute("UPDATE policy_documents SET policy_id = %s WHERE id = %s", [backfill, p['id']])
                    p['policy_id'] = backfill
            
            # Build sorting SQL
            sort_map = {
                'severity': 'severity',
                'confidence': 'confidence',
                'status': 'status',
                'type': 'rule_type',
                'date': 'created_at',
                'name': 'name',
            }
            sort_col = sort_map.get(sort_by, 'severity')
            order_dir = 'DESC' if order == 'desc' else 'ASC'
            
            # Severity ordering (critical > high > medium > low)
            if sort_by == 'severity':
                rules_raw = _fetchall(conn, """
                    SELECT r.*, pv.version_id as gov_version_id, pv.status as gov_status
                    FROM rules r
                    LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                """)
                severity_order_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                for r in rules_raw:
                    r['_severity_order'] = severity_order_map.get(r.get('severity', 'medium'), 0)
                rules = sorted(rules_raw, key=lambda x: (x.get('_severity_order', 0), x.get('name', '')), reverse=(order == 'desc'))
            else:
                rules = _fetchall(conn, f"""
                    SELECT r.*, pv.version_id as gov_version_id, pv.status as gov_status
                    FROM rules r
                    LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                    ORDER BY r.{sort_col} {order_dir}, r.name ASC
                """)
            
            # Generate summaries for each rule
            for rule in rules:
                rule['summary'] = _generate_rule_summary(rule)
        finally:
            release_connection(conn)

        return render_template('policies.html', 
                              policies=policy_docs, 
                              rules=rules,
                              sort_by=sort_by,
                              order=order)

    def _generate_rule_summary(rule):
        """Generate a simple-word summary of how the rule is applicable, with PDF reference."""
        rule_type = rule.get('rule_type', '')
        conditions_str = rule.get('conditions', '[]')
        try:
            conditions = json.loads(conditions_str) if isinstance(conditions_str, str) else (conditions_str or [])
        except (json.JSONDecodeError, TypeError):
            conditions = []
        
        severity = rule.get('severity', 'medium')
        source_doc = rule.get('source_document', 'Unknown')
        source_page = rule.get('source_page', 0)
        
        # Rule type explanation
        type_explanations = {
            'threshold': 'flags transactions that exceed a monetary threshold',
            'velocity': 'detects rapid transactions or structuring patterns',
            'cross_border': 'monitors cross-border transfers',
            'pattern': 'identifies suspicious transaction patterns',
            'payment_format': 'checks specific payment methods',
            'dormant_account': 'monitors activity in dormant accounts',
        }
        type_desc = type_explanations.get(rule_type, 'monitors transactions')
        
        # Extract key conditions
        amount_threshold = None
        count_threshold = None
        time_window = None
        payment_format = None
        pattern = None
        
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            field = cond.get('field', '')
            value = cond.get('value')
            operator = cond.get('operator', '')
            
            if field in ('amount_paid', 'amount_received', 'cumulative_amount') and isinstance(value, (int, float)):
                amount_threshold = value
            elif field == 'transaction_count' and isinstance(value, (int, float)):
                count_threshold = value
            elif field == 'time_window' and isinstance(value, dict):
                time_window = value
            elif field == 'payment_format':
                payment_format = value
            elif field == 'pattern':
                pattern = value
        
        # Build summary
        summary_parts = []
        summary_parts.append(f"<strong>What it does:</strong> This rule {type_desc}.")
        
        # Condition details
        condition_details = []
        if amount_threshold:
            condition_details.append(f"amounts exceed ${amount_threshold:,.0f}")
        if count_threshold:
            if time_window:
                tw_val = time_window.get('value', '')
                tw_unit = time_window.get('unit', 'days')
                condition_details.append(f"more than {count_threshold} transactions within {tw_val} {tw_unit}")
            else:
                condition_details.append(f"more than {count_threshold} transactions")
        if payment_format:
            condition_details.append(f"{payment_format} payment method")
        if pattern:
            pattern_names = {
                'round_trip': 'round-trip transactions (money sent and received back)',
                'fan_out': 'fan-out patterns (one account sending to many)',
                'fan_in': 'fan-in patterns (many accounts sending to one)',
                'self_transfer': 'self-transfers (same sender and receiver)',
                'layering': 'layering patterns',
            }
            condition_details.append(pattern_names.get(pattern, pattern))
        
        if condition_details:
            summary_parts.append(f"<strong>When triggered:</strong> When {', '.join(condition_details)}.")
        
        # Severity
        severity_desc = {
            'critical': 'immediate action required',
            'high': 'urgent review needed',
            'medium': 'requires review',
            'low': 'monitoring recommended',
        }
        summary_parts.append(f"<strong>Severity:</strong> {severity} ({severity_desc.get(severity, 'standard')}).")
        
        # Reference - link to PDF file if available
        pdf_file = os.path.join(POLICIES_DIR, source_doc)
        if os.path.exists(pdf_file):
            pdf_url = url_for('serve_policy_pdf', filename=source_doc)
            summary_parts.append(f"<strong>Source:</strong> <a href='{pdf_url}' target='_blank' class='rule-pdf-link'>{source_doc}</a>, page {source_page}.")
        else:
            summary_parts.append(f"<strong>Source:</strong> {source_doc}, page {source_page}.")
        
        return " ".join(summary_parts)

    @app.route('/policies/upload', methods=['POST'])
    def upload_policy():
        """Upload and process a new policy PDF using the full pipeline."""
        from app.policy_engine.pipeline import PolicyPipeline

        file = request.files.get('policy_file')
        if not file or not file.filename.endswith('.pdf'):
            return redirect(url_for('policies'))

        filepath = os.path.join(POLICIES_DIR, file.filename)
        file.save(filepath)

        pipeline = PolicyPipeline()
        pipeline.process(filepath)

        return redirect(url_for('policies'))

    @app.route('/api/policies')
    def api_policies_list():
        """JSON: list all policy documents and rules (for React Control Center)."""
        conn = get_connection()
        try:
            policy_docs = _fetchall(conn, "SELECT * FROM policy_documents ORDER BY uploaded_at DESC")
            for p in policy_docs:
                if not p.get('policy_id'):
                    backfill = f"POL-LEGACY-{p['id']}"
                    execute("UPDATE policy_documents SET policy_id = %s WHERE id = %s", [backfill, p['id']])
                    p['policy_id'] = backfill
            rules = _fetchall(conn, """
                SELECT r.*, pv.version_id as gov_version_id, pv.status as gov_status
                FROM rules r
                LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                WHERE r.is_deleted = 0 
                ORDER BY r.created_at DESC
            """)
            for rule in rules:
                rule['summary'] = _generate_rule_summary(rule)
            return jsonify({'policy_docs': policy_docs, 'rules': rules})
        finally:
            release_connection(conn)

    @app.route('/api/policies/extract', methods=['POST'])
    def api_extract_policy():
        """JSON API: extract rules from an uploaded policy PDF."""
        from app.policy_engine.pipeline import PolicyPipeline

        file = request.files.get('file')
        policy_id = request.form.get('policy_id', '')

        if not file or not file.filename.endswith('.pdf'):
            return jsonify({'error': 'No PDF file provided'}), 400

        filepath = os.path.join(POLICIES_DIR, file.filename)
        file.save(filepath)

        pipeline = PolicyPipeline()
        result = pipeline.process(filepath, policy_id=policy_id or None)

        return jsonify({
            'success': result.success,
            'policy_id': result.policy_id,
            'rules_count': len(result.rules),
            'rules': [r.to_legacy_dict() for r in result.rules],
            'metrics': result.metrics.model_dump(),
            'error': result.error,
        })

    @app.route('/api/policies/<int:policy_id>/rules')
    def api_policy_rules(policy_id):
        """Get rules for a specific policy document."""
        conn = get_connection()
        try:
            policy = _fetchone(conn, "SELECT * FROM policy_documents WHERE id = %s", [policy_id])
            if not policy:
                return jsonify({'error': 'Policy not found'}), 404

            rules = _fetchall(conn, """
                SELECT r.*, pv.version_id as gov_version_id, pv.status as gov_status
                FROM rules r
                LEFT JOIN policy_versions pv ON r.version_id = pv.version_id
                WHERE r.source_document = %s AND r.is_deleted = 0 
                ORDER BY r.id
            """, [policy['filename']])
        finally:
            release_connection(conn)

        return jsonify({'policy': policy, 'rules': rules})

    @app.route('/api/rules/<rule_id>/approve', methods=['POST'])
    def api_approve_rule(rule_id):
        if not FIREBASE_AUTH_DISABLED:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') not in ('admin', 'risk_manager'):
                return jsonify({'error': 'Admin or Risk Manager role required'}), 403
        try:
            from app.policy_engine.versioning import RuleRegistry
            performed_by = request.args.get('role', 'admin') if FIREBASE_AUTH_DISABLED else 'system'
            success = RuleRegistry.approve_rule(rule_id, performed_by=performed_by)
            if success:
                return jsonify({'status': 'approved', 'rule_id': rule_id})
            return jsonify({'error': 'Rule not found or already approved'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/rules/<rule_id>/reject', methods=['POST'])
    def api_reject_rule(rule_id):
        if not FIREBASE_AUTH_DISABLED:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') not in ('admin', 'risk_manager'):
                return jsonify({'error': 'Admin or Risk Manager role required'}), 403
        try:
            from app.policy_engine.versioning import RuleRegistry
            data = request.get_json(force=True) if request.is_json else {}
            reason = data.get('reason', '') if data else ''
            performed_by = request.args.get('role', 'admin') if FIREBASE_AUTH_DISABLED else 'system'
            success = RuleRegistry.reject_rule(rule_id, reason=reason, performed_by=performed_by)
            if success:
                return jsonify({'status': 'rejected', 'rule_id': rule_id})
            return jsonify({'error': 'Rule not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/policies/<policy_id>/versions')
    def api_policy_versions(policy_id):
        from app.policy_engine.versioning import PolicyRegistry
        versions = PolicyRegistry.get_all_versions(policy_id)
        return jsonify({'policy_id': policy_id, 'versions': versions})

    @app.route('/api/policies/<policy_id>/approve', methods=['POST'])
    def api_approve_policy(policy_id):
        if not FIREBASE_AUTH_DISABLED:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') not in ('admin', 'risk_manager'):
                return jsonify({'error': 'Admin or Risk Manager role required'}), 403
        try:
            from app.policy_engine.versioning import PolicyRegistry
            performed_by = request.args.get('role', 'admin') if FIREBASE_AUTH_DISABLED else 'system'
            success = PolicyRegistry.approve_policy(policy_id, performed_by=performed_by)
            if success:
                return jsonify({'status': 'approved', 'policy_id': policy_id})
            return jsonify({'error': 'Policy not found or not in draft status'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/policies/<policy_id>/retire', methods=['POST'])
    def api_retire_policy(policy_id):
        if not FIREBASE_AUTH_DISABLED:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') not in ('admin', 'risk_manager'):
                return jsonify({'error': 'Admin or Risk Manager role required'}), 403
        try:
            from app.policy_engine.versioning import PolicyRegistry
            performed_by = request.args.get('role', 'admin') if FIREBASE_AUTH_DISABLED else 'system'
            success = PolicyRegistry.retire_policy(policy_id, performed_by=performed_by)
            if success:
                return jsonify({'status': 'retired', 'policy_id': policy_id})
            return jsonify({'error': 'Policy not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/policies/<policy_id>/delete', methods=['POST'])
    def api_policy_delete(policy_id):
        """Admin only: Permanently delete a policy and all its rules."""
        from app.auth.firebase_auth import _get_current_user_from_session
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return jsonify({'error': 'Admin required'}), 403
        try:
            from app.policy_engine.versioning import PolicyRegistry
            performed_by = 'admin'
            success = PolicyRegistry.delete_policy(policy_id, performed_by=performed_by)
            if success:
                return jsonify({'status': 'deleted', 'policy_id': policy_id})
            return jsonify({'error': 'Policy not found or could not be deleted'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/policies/clear-all', methods=['POST'])
    def api_policies_clear_all():
        """Admin only: radioactive wipe of all policies and rules."""
        from app.auth.firebase_auth import _get_current_user_from_session
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return jsonify({'error': 'Admin required'}), 403
        try:
            from app.policy_engine.versioning import PolicyRegistry
            performed_by = 'admin'
            success = PolicyRegistry.delete_all_data(performed_by=performed_by)
            if success:
                return jsonify({'status': 'wiped'})
            return jsonify({'error': 'Failed to wipe data'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/rules/<rule_id>/lineage')
    def api_rule_lineage(rule_id):
        from app.policy_engine.versioning import RuleRegistry
        lineage = RuleRegistry.get_rule_lineage(rule_id)
        return jsonify(lineage)

    @app.route('/api/audit/<policy_id>')
    def api_audit_trail(policy_id):
        from app.policy_engine.versioning import AuditLogger
        limit = request.args.get('limit', 100, type=int)
        trail = AuditLogger.get_trail(policy_id=policy_id, limit=limit)
        return jsonify({'policy_id': policy_id, 'audit_trail': trail})

    @app.route('/api/chat', methods=['POST'])
    def api_chat():
        """Process chatbot messages with tool-augmented LLM."""
        from app.web.chatbot import chat
        data = request.get_json(force=True) or {}
        # Support both old {message} and new {messages} format
        messages = data.get('messages', [])
        if not messages and data.get('message'):
            messages = [{'role': 'user', 'content': data['message']}]
        context = data.get('context', {})
        role = data.get('role', request.args.get('role', 'analyst'))
        result = chat(messages, context, role)
        # Backward compat: also include 'reply' key
        result['reply'] = result.get('response', '')
        return jsonify(result)

    # ------------------------------------------------------------------
    # AUDIT TRAIL
    # ------------------------------------------------------------------
    @app.route('/audit')
    def audit_trail_page():
        """Forensic audit trail view."""
        action_filter = request.args.get('action', '')
        search_query = request.args.get('q', '')

        conn = get_connection()
        try:
            sql = "SELECT * FROM extraction_audit_log"
            params = []
            conditions = []

            if action_filter:
                conditions.append("action = %s")
                params.append(action_filter)
            if search_query:
                conditions.append(
                    "(policy_id ILIKE %s OR rule_id ILIKE %s OR performed_by ILIKE %s)"
                )
                like = f'%{search_query}%'
                params.extend([like, like, like])

            if conditions:
                sql += " WHERE " + " AND ".join(conditions)

            sql += " ORDER BY created_at DESC LIMIT 200"
            entries = _fetchall(conn, sql, params)
            audit_entries = []
            for entry in entries:
                # Normalise: use created_at as display timestamp
                entry['timestamp'] = str(entry.get('created_at', ''))
                if entry.get('details') and isinstance(entry['details'], str):
                    try:
                        entry['details'] = json.loads(entry['details'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                audit_entries.append(entry)
        except Exception as e:
            app.logger.error(f'[audit] query error: {e}')
            audit_entries = []
        finally:
            release_connection(conn)

        return render_template('audit.html',
                               audit_entries=audit_entries,
                               action_filter=action_filter,
                               search_query=search_query)

    # ------------------------------------------------------------------
    # RULESETS (version control for policy-derived rules)
    # ------------------------------------------------------------------
    @app.route('/rulesets')
    def rulesets_page():
        """List rule sets and manage versions."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        policy_id = request.args.get('policy_id', '').strip() or None
        rulesets = RuleSetManager.list_rulesets(policy_id=policy_id)
        for rs in rulesets:
            try:
                rs["rule_ids"] = json.loads(rs["rule_ids"]) if isinstance(rs.get("rule_ids"), str) else (rs.get("rule_ids") or [])
            except (TypeError, json.JSONDecodeError):
                rs["rule_ids"] = []
        return render_template('rulesets.html', rulesets=rulesets, policy_id=policy_id)

    @app.route('/rulesets/<ruleset_id>')
    def ruleset_detail(ruleset_id):
        """Single rule set detail with rules and audit info."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        rs = RuleSetManager.get_ruleset(ruleset_id)
        if not rs:
            return "Rule set not found", 404
        conn = get_connection()
        try:
            rule_ids = rs.get('rule_ids') or []
            rules = []
            if rule_ids:
                placeholders = ','.join(['%s'] * len(rule_ids))
                rules = _fetchall(conn, f"SELECT * FROM rules WHERE id IN ({placeholders})", rule_ids)
            alert_count = _fetchone(conn,
                "SELECT COUNT(*) as cnt FROM alerts WHERE rule_set_version = %s", (ruleset_id,)) or {}
            rs['rules'] = rules
            rs['alert_count'] = alert_count.get('cnt', 0)
        finally:
            release_connection(conn)
        return render_template('ruleset_detail.html', ruleset=rs)

    @app.route('/rulesets/diff')
    def ruleset_diff_page():
        """Compare two rule sets (ids via query params)."""
        id1 = request.args.get('id1', '').strip()
        id2 = request.args.get('id2', '').strip()
        if not id1 or not id2:
            return redirect(url_for('rulesets_page'))
        from app.policy_engine.rule_diff import RuleDiffEngine
        diff = RuleDiffEngine.diff_rulesets(id1, id2)
        diff_html = RuleDiffEngine.visualize_diff(diff, format='html') if 'error' not in diff else ''
        return render_template('ruleset_diff.html', diff=diff, diff_html=diff_html, id1=id1, id2=id2)

    @app.route('/api/rulesets')
    def api_rulesets_list():
        """List all rule sets (optional policy_id filter)."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        policy_id = request.args.get('policy_id', '').strip() or None
        limit = request.args.get('limit', 100, type=int)
        rulesets = RuleSetManager.list_rulesets(policy_id=policy_id, limit=limit)
        return jsonify({'rulesets': rulesets})

    @app.route('/api/rulesets/<ruleset_id>')
    def api_ruleset_detail(ruleset_id):
        """Get rule set details."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        rs = RuleSetManager.get_ruleset(ruleset_id)
        if not rs:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(rs)

    @app.route('/api/rulesets/<ruleset_id>/diff/<ruleset_id_2>')
    def api_ruleset_diff(ruleset_id, ruleset_id_2):
        """Compare two rule sets."""
        from app.policy_engine.rule_diff import RuleDiffEngine
        diff = RuleDiffEngine.diff_rulesets(ruleset_id, ruleset_id_2)
        return jsonify(diff)

    @app.route('/api/policies/<policy_id>/rulesets')
    def api_policy_rulesets(policy_id):
        """Get all rule sets for a policy."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        rulesets = RuleSetManager.list_rulesets(policy_id=policy_id)
        return jsonify({'policy_id': policy_id, 'rulesets': rulesets})

    @app.route('/api/rulesets/<ruleset_id>/activate', methods=['POST'])
    def api_ruleset_activate(ruleset_id):
        """Activate a rule set (admin only)."""
        from app.auth.firebase_auth import _get_current_user_from_session
        user = _get_current_user_from_session(session)
        if not FIREBASE_AUTH_DISABLED and (not user or user.get('role') != 'admin'):
            return jsonify({'error': 'Admin required'}), 403
        if FIREBASE_AUTH_DISABLED and request.args.get('role') != 'admin':
            return jsonify({'error': 'Admin required'}), 403
        from app.policy_engine.rule_set_manager import RuleSetManager
        ok = RuleSetManager.activate_ruleset(ruleset_id)
        if not ok:
            return jsonify({'error': 'Rule set not found'}), 404
        return jsonify({'status': 'activated', 'ruleset_id': ruleset_id})

    @app.route('/api/rulesets/<ruleset_id>/snapshot', methods=['GET', 'POST'])
    def api_ruleset_snapshot(ruleset_id):
        """Create or view snapshot. POST to create, GET returns last snapshot info."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        if request.method == 'POST':
            count = RuleSetManager.create_snapshot(ruleset_id)
            return jsonify({'status': 'created', 'rules_snapshotted': count})
        rs = RuleSetManager.get_ruleset(ruleset_id)
        if not rs:
            return jsonify({'error': 'Not found'}), 404
        conn = get_connection()
        try:
            snap_count = _fetchone(conn,
                "SELECT COUNT(*) as cnt FROM rule_snapshots WHERE ruleset_id = %s", (ruleset_id,)) or {}
        finally:
            release_connection(conn)
        return jsonify({'ruleset_id': ruleset_id, 'snapshot_count': snap_count.get('cnt', 0)})

    # ------------------------------------------------------------------
    # IMPACT SIMULATOR
    # ------------------------------------------------------------------
    @app.route('/simulation')
    def simulation_page():
        """Impact simulator: configure and run retrospective rule analysis."""
        from app.policy_engine.rule_set_manager import RuleSetManager
        rulesets = RuleSetManager.list_rulesets(limit=200)
        return render_template('simulation.html', rulesets=rulesets)

    @app.route('/simulation/results/<simulation_id>')
    def simulation_results_page(simulation_id):
        """View simulation results."""
        from app.simulation.impact_simulator import ImpactSimulator
        run = ImpactSimulator.get_simulation_run(simulation_id)
        if not run:
            return "Simulation not found", 404
        results = run.get("results") or run.get("results_json")
        if isinstance(results, str):
            try:
                results = json.loads(results)
            except (TypeError, json.JSONDecodeError):
                results = {}
        return render_template('simulation_results.html', run=run, results=results)

    @app.route('/api/simulation/run', methods=['POST'])
    def api_simulation_run():
        """Run impact simulation. JSON body: ruleset_id, start_date, end_date, include_ml?, include_graph?."""
        from app.auth.firebase_auth import _get_current_user_from_session
        from app.simulation.impact_simulator import ImpactSimulator
        data = request.get_json() or {}
        ruleset_id = (data.get("ruleset_id") or "").strip()
        start_date = (data.get("start_date") or "").strip()
        end_date = (data.get("end_date") or "").strip()
        if not ruleset_id or not start_date or not end_date:
            return jsonify({"error": "ruleset_id, start_date, end_date required"}), 400
        user = _get_current_user_from_session(session)
        created_by = (user.get("email") or user.get("name") or "system") if user else "system"
        try:
            result = ImpactSimulator.simulate_rule_change(
                ruleset_id, start_date, end_date,
                include_ml=data.get("include_ml", False),
                include_graph=data.get("include_graph", False),
            )
            ImpactSimulator.save_simulation_run(result, created_by=created_by)
            return jsonify(result.to_dict())
        except Exception as e:
            app.logger.exception(e)
            return jsonify({"error": str(e)}), 500

    @app.route('/api/simulation/<simulation_id>')
    def api_simulation_get(simulation_id):
        """Get simulation result by id."""
        from app.simulation.impact_simulator import ImpactSimulator
        run = ImpactSimulator.get_simulation_run(simulation_id)
        if not run:
            return jsonify({"error": "Not found"}), 404
        return jsonify(run)

    @app.route('/api/simulation/history')
    def api_simulation_history():
        """List past simulation runs."""
        from app.simulation.impact_simulator import ImpactSimulator
        limit = request.args.get("limit", 50, type=int)
        runs = ImpactSimulator.list_simulation_runs(limit=limit)
        return jsonify({"runs": runs})

    @app.route('/api/simulation/<simulation_id>/report', methods=['GET'])
    def api_simulation_report(simulation_id):
        """Export simulation report natively to HTML/PDF Print dialog."""
        from app.simulation.impact_simulator import ImpactSimulator
        from app.reporting.engine import generate_simulation_report_data
        
        run = ImpactSimulator.get_simulation_run(simulation_id)
        if not run:
            return "Simulation not found", 404
            
        results = run.get("results") or {}
        if isinstance(run.get("results_json"), str):
            try:
                results = json.loads(run["results_json"])
            except (TypeError, json.JSONDecodeError):
                pass
                
        ctx = generate_simulation_report_data(run, results)
        auto_print = request.args.get('print', '1') == '1'
        return render_template('reports/simulation_report.html', ctx=ctx, auto_print=auto_print)

    # ------------------------------------------------------------------
    # REPORTS
    # ------------------------------------------------------------------
    @app.route('/reports')
    def reports():
        """View and generate reports."""
        conn = get_connection()
        try:
            report_list = _fetchall(conn, "SELECT * FROM audit_reports ORDER BY generated_at DESC")
        finally:
            release_connection(conn)

        return render_template('reports.html', reports=report_list)

    @app.route('/reports/generate/<report_type>')
    def generate_report(report_type):
        """Generate a report."""
        from app.explainability.report_gen import generate_alert_report, generate_summary_report
        try:
            if report_type == 'summary':
                generate_summary_report()
            elif report_type.startswith('alert_'):
                parts = report_type.split('_')
                alert_id = int(parts[-1])
                generate_alert_report(alert_id)
        except Exception as e:
            app.logger.error(f'[report] generation error: {e}')

        return redirect(url_for('reports'))

    @app.route('/reports/download/<filename>')
    def download_report(filename):
        """Download a generated report PDF."""
        return send_from_directory(REPORTS_DIR, filename, as_attachment=True)

    @app.route('/policies/files/<filename>')
    def serve_policy_pdf(filename):
        """Serve policy PDF files."""
        return send_from_directory(POLICIES_DIR, filename, as_attachment=False)

    # ------------------------------------------------------------------
    # API ENDPOINTS
    # ------------------------------------------------------------------
    @app.route('/api/stats')
    def api_stats():
        """JSON API for dashboard charts."""
        conn = get_connection()
        try:
            severity = _fetchall(conn, "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
            score_dist = _fetchall(conn, """
                SELECT
                    CASE
                        WHEN fusion_score >= 0.9 THEN '0.9-1.0'
                        WHEN fusion_score >= 0.8 THEN '0.8-0.9'
                        WHEN fusion_score >= 0.7 THEN '0.7-0.8'
                        WHEN fusion_score >= 0.6 THEN '0.6-0.7'
                        ELSE '0.5-0.6'
                    END as bucket,
                    COUNT(*) as cnt
                FROM alerts
                GROUP BY bucket
                ORDER BY bucket
            """)
            signal_avgs = _fetchone(conn, """
                SELECT ROUND(AVG(rule_score)::numeric, 3) as avg_rule,
                       ROUND(AVG(ml_score)::numeric, 3) as avg_ml,
                       ROUND(AVG(graph_score)::numeric, 3) as avg_graph
                FROM alerts
            """)
        finally:
            release_connection(conn)

        signal_avgs_dict = {}
        if signal_avgs:
            signal_avgs_dict = {
                'avg_rule': float(signal_avgs.get('avg_rule') or 0),
                'avg_ml': float(signal_avgs.get('avg_ml') or 0),
                'avg_graph': float(signal_avgs.get('avg_graph') or 0),
            }

        return jsonify({
            'severity': {r['severity']: r['cnt'] for r in severity},
            'score_distribution': {r['bucket']: r['cnt'] for r in score_dist},
            'signal_averages': signal_avgs_dict,
        })

    @app.route('/api/ingest', methods=['POST'])
    def api_ingest():
        """Admin-only: bulk-load CSV transactions into the database.

        Batch ingest behavior:
        - First "Load data" or default call: initial load (append); tables may be empty or pre-filled.
        - Subsequent calls: append mode — new rows are added; re-running with the same CSV may create duplicates.
        - Full replace: pass ?truncate=true or JSON body {"truncate": true} to clear transactions and accounts, then load (use for "Reload data").
        Optional: ?limit=N to cap rows for testing.
        Optional JSON body: transactions_csv, accounts_csv — paths relative to project or Dataset.
        """
        if FIREBASE_AUTH_DISABLED:
            if request.args.get('role', 'analyst') != 'admin':
                return jsonify({'error': 'Admin role required'}), 403
        else:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') != 'admin':
                return jsonify({'error': 'Admin role required'}), 403

        limit = request.args.get('limit', None, type=int)
        data = request.get_json(silent=True) or {}
        truncate_first = (
            request.args.get('truncate', '').lower() == 'true' or
            data.get('truncate') is True
        )
        transactions_csv = data.get('transactions_csv')
        accounts_csv = data.get('accounts_csv')

        # Validate custom paths
        ok, txn_path, err = _validate_dataset_path(transactions_csv, 'transactions_csv')
        if not ok:
            return jsonify({'status': 'error', 'message': err}), 400
        ok, acc_path, err = _validate_dataset_path(accounts_csv, 'accounts_csv')
        if not ok:
            return jsonify({'status': 'error', 'message': err}), 400

        try:
            from app.data_layer.loader import setup_database
            n_txn, n_acc = setup_database(
                limit=limit,
                truncate_first=truncate_first,
                transactions_csv=txn_path or transactions_csv,
                accounts_csv=acc_path or accounts_csv,
            )
            resp = {
                'status': 'success',
                'transactions_loaded': n_txn,
                'accounts_loaded': n_acc,
            }
            if txn_path:
                resp['transactions_csv'] = txn_path
            if acc_path:
                resp['accounts_csv'] = acc_path
            return jsonify(resp)
        except Exception as e:
            app.logger.error(f'[ingest] error: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/streaming/ingest', methods=['POST'])
    def api_streaming_ingest():
        """Push a single transaction event to Kafka (transactions.incoming) for testing or upstream push."""
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'JSON body required'}), 400
        try:
            from app.streaming.kafka_producer import send_transaction_event
            key = data.get('account_id') or (f"{data.get('from_bank', '')}_{data.get('from_account', '')}" if data.get('from_bank') or data.get('from_account') else None)
            ok = send_transaction_event(data, key=key)
            if not ok:
                return jsonify({'status': 'error', 'message': 'Kafka unavailable or send failed'}), 503
            return jsonify({'status': 'success', 'message': 'Event published to transactions.incoming'})
        except Exception as e:
            app.logger.error(f'[streaming/ingest] error: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/streaming/metrics')
    def api_streaming_metrics():
        """Streaming metrics: throughput, latency, processed/failed counts, optional consumer lag."""
        try:
            from app.streaming.metrics import get_metrics
            return jsonify(get_metrics())
        except Exception as e:
            app.logger.error(f'[streaming/metrics] error: {e}')
            return jsonify({'error': str(e)}), 500

    @app.route('/api/pipeline/run-full', methods=['POST'])
    def api_pipeline_run_full():
        """Admin-only: start full-dataset pipeline in background (load + scan). Returns 202 when started."""
        if FIREBASE_AUTH_DISABLED:
            if request.args.get('role', 'analyst') != 'admin':
                return jsonify({'error': 'Admin role required'}), 403
        else:
            user = _get_current_user_from_session(session)
            if not user or user.get('role') != 'admin':
                return jsonify({'error': 'Admin role required'}), 403
        try:
            from app.pipeline.background_run import start_full_pipeline
            started, message, run_id = start_full_pipeline()
            if not started:
                return jsonify({'error': message or 'Full pipeline already in progress', 'status': 'busy'}), 409
            return jsonify({
                'status': 'started',
                'run_id': run_id,
                'message': 'Full dataset pipeline running in background.',
            }), 202
        except Exception as e:
            app.logger.error(f'[pipeline/run-full] error: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/pipeline/status')
    def api_pipeline_status():
        """Full-pipeline run status: running, run_id, last_run, current_run."""
        try:
            from app.pipeline.background_run import get_full_pipeline_status
            return jsonify(get_full_pipeline_status())
        except Exception as e:
            app.logger.error(f'[pipeline/status] error: {e}')
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        """Trigger a compliance scan — rule engine + optional ML/graph signals."""
        from app.detection.rule_engine import RuleEngine
        from app.detection.fusion import FusionEngine
        import pandas as pd

        try:
            # Log scan start — use RETURNING id for PostgreSQL
            conn = get_connection()
            try:
                with _cur(conn) as c:
                    c.execute(
                        "INSERT INTO monitoring_runs (run_type, status) VALUES ('manual', 'running') RETURNING id"
                    )
                    run_id = c.fetchone()[0]
                conn.commit()
            finally:
                release_connection(conn)

            # 1. Rule engine
            engine = RuleEngine()
            violations = engine.evaluate_all()
            engine.close()

            # 2. ML signal — load saved model if available
            ml_risks = None
            try:
                from app.detection.ml_engine import MLEngine
                from app.config import MODELS_DIR
                model_path = os.path.join(MODELS_DIR, 'lgbm_model.pkl')
                if os.path.exists(model_path):
                    ml = MLEngine()
                    if ml.load_model():
                        ml_risks = ml.predict_risks()
            except Exception as ml_err:
                app.logger.warning(f'[scan] ML signal unavailable: {ml_err}')

            # 3. Graph signal
            graph_risks = {}
            try:
                from app.detection.graph_engine import GraphEngine
                graph = GraphEngine()
                graph_risks = graph.analyze()
            except Exception as ge:
                app.logger.warning(f'[scan] Graph signal unavailable: {ge}')

            # 4. Fuse
            fusion = FusionEngine()
            alerts = fusion.fuse(
                violations,
                ml_risks if ml_risks is not None else pd.DataFrame(),
                graph_risks or {},
            )
            fusion.save_alerts_to_db(alerts)

            # Update run record
            execute("""
                UPDATE monitoring_runs
                SET completed_at=NOW(), transactions_scanned=%s,
                    alerts_generated=%s, status='completed'
                WHERE id=%s
            """, [len(violations), len(alerts), run_id])

            return jsonify({
                'status': 'success',
                'violations_found': len(violations),
                'alerts_generated': len(alerts),
                'ml_available': ml_risks is not None,
                'graph_available': bool(graph_risks),
            })
        except Exception as e:
            app.logger.error(f'[scan] error: {e}')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ── GOVERNANCE API ────────────────────────────────────────────

    @app.route('/api/governance/versions', methods=['GET', 'POST'])
    def governance_versions():
        """List or create policy versions."""
        from app.policy_engine.policy_governance import PolicyGovernance
        if request.method == 'POST':
            data = request.get_json(force=True)
            try:
                version_id = PolicyGovernance.create_version(
                    policy_id=data['policy_id'],
                    source_document=data.get('source_document', ''),
                    change_summary=data.get('change_summary', ''),
                    created_by=data.get('created_by', 'system'),
                )
                return jsonify({'status': 'success', 'version_id': version_id})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 400
        else:
            policy_id = request.args.get('policy_id')
            versions = PolicyGovernance.list_versions(policy_id)
            return jsonify(versions)

    @app.route('/api/governance/versions/<version_id>')
    def governance_version_detail(version_id):
        """Get version detail."""
        from app.policy_engine.policy_governance import PolicyGovernance
        v = PolicyGovernance.get_version(version_id)
        if not v:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(v)

    @app.route('/api/governance/versions/<version_id>/submit-review', methods=['POST'])
    def governance_submit_review(version_id):
        """Submit a draft version for review."""
        from app.policy_engine.policy_governance import PolicyGovernance
        data = request.get_json(force=True) if request.is_json else {}
        try:
            result = PolicyGovernance.submit_for_review(
                version_id,
                performed_by=data.get('performed_by', request.args.get('role', 'system')),
                comment=data.get('comment', ''),
            )
            return jsonify(result), 200 if result.get('success') else 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/governance/versions/<version_id>/approve', methods=['POST'])
    def governance_approve(version_id):
        """Approve a version (maker-checker)."""
        from app.policy_engine.policy_governance import PolicyGovernance
        data = request.get_json(force=True) if request.is_json else {}
        try:
            result = PolicyGovernance.approve(
                version_id,
                performed_by=data.get('performed_by', request.args.get('role', 'system')),
                comment=data.get('comment', ''),
            )
            return jsonify(result), 200 if result.get('success') else 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/governance/versions/<version_id>/activate', methods=['POST'])
    def governance_activate(version_id):
        """Activate an approved version."""
        from app.policy_engine.policy_governance import PolicyGovernance
        data = request.get_json(force=True) if request.is_json else {}
        try:
            result = PolicyGovernance.activate(
                version_id,
                performed_by=data.get('performed_by', request.args.get('role', 'system')),
                comment=data.get('comment', ''),
            )
            return jsonify(result), 200 if result.get('success') else 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/governance/versions/<version_id>/rollback', methods=['POST'])
    def governance_rollback(version_id):
        """Rollback to this version (creates new version, never mutates history)."""
        from app.policy_engine.policy_governance import PolicyGovernance
        data = request.get_json(force=True) if request.is_json else {}
        try:
            result = PolicyGovernance.rollback(
                version_id,
                performed_by=data.get('performed_by', request.args.get('role', 'system')),
                reason=data.get('reason', ''),
            )
            return jsonify(result), 200 if result.get('success') else 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @app.route('/api/governance/versions/<version_id>/impact')
    def governance_impact(version_id):
        """Impact analysis before activating a version."""
        from app.policy_engine.policy_governance import PolicyGovernance
        return jsonify(PolicyGovernance.impact_analysis(version_id))

    @app.route('/api/governance/versions/<version_id>/diff/<version_id_2>')
    def governance_diff(version_id, version_id_2):
        """Diff between two versions."""
        from app.policy_engine.policy_governance import PolicyGovernance
        return jsonify(PolicyGovernance.get_version_diff(version_id, version_id_2))

    @app.route('/api/governance/audit')
    def governance_audit():
        """Immutable governance audit trail."""
        from app.policy_engine.policy_governance import PolicyGovernance
        version_id = request.args.get('version_id')
        policy_id = request.args.get('policy_id')
        return jsonify(PolicyGovernance.get_audit_trail(version_id, policy_id))

    @app.route('/api/governance/sync', methods=['POST'])
    def governance_sync():
        """Sync governance system from existing policy documents."""
        from app.policy_engine.policy_governance import PolicyGovernance
        count = PolicyGovernance.sync_from_existing()
        return jsonify({'status': 'success', 'versions_created': count})

    # ── ALERT CLUSTER RESOLUTION API ──────────────────────────────

    @app.route('/api/alerts/clusters')
    def api_alert_clusters():
        """List alert clusters sorted by priority."""
        from app.detection.alert_cluster_engine import list_clusters
        status = request.args.get('status', 'open')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        return jsonify(list_clusters(status, limit, offset))

    @app.route('/api/alerts/clusters/run', methods=['POST'])
    def api_run_alert_clustering():
        """Run alert clustering on pending alerts."""
        from app.detection.alert_cluster_engine import AlertClusterEngine
        data = request.get_json(force=True) if request.is_json else {}
        engine = AlertClusterEngine()
        result = engine.run(target_clusters=data.get('target_clusters'))
        return jsonify(result)

    @app.route('/api/clusters/<cluster_id>')
    def api_cluster_detail(cluster_id):
        """Get cluster detail with member alerts."""
        from app.detection.alert_cluster_engine import get_cluster_detail
        detail = get_cluster_detail(cluster_id)
        if not detail:
            return jsonify({'error': 'Cluster not found'}), 404
        return jsonify(detail)

    @app.route('/api/clusters/<cluster_id>/resolve', methods=['POST'])
    def api_resolve_cluster(cluster_id):
        """Resolve a cluster (confirm/dismiss/escalate/mark_partial)."""
        from app.detection.alert_cluster_engine import ClusterResolution
        data = request.get_json(force=True)
        result = ClusterResolution.resolve_cluster(
            cluster_id=cluster_id,
            action=data['action'],
            performed_by=data.get('performed_by', request.args.get('role', 'analyst')),
            notes=data.get('notes', ''),
            alert_overrides=data.get('alert_overrides'),
        )
        return jsonify(result), 200 if result.get('success') else 400

    @app.route('/api/clusters/<cluster_id>/split', methods=['POST'])
    def api_split_cluster(cluster_id):
        """Split a cluster into two groups."""
        from app.detection.alert_cluster_engine import ClusterResolution
        data = request.get_json(force=True)
        result = ClusterResolution.split_cluster(
            cluster_id=cluster_id,
            group_a_ids=data['group_a'],
            group_b_ids=data['group_b'],
            performed_by=data.get('performed_by', 'analyst'),
            reason=data.get('reason', ''),
        )
        return jsonify(result), 200 if result.get('success') else 400

    @app.route('/api/clusters/metrics')
    def api_cluster_metrics():
        """Get cluster system metrics."""
        from app.detection.alert_cluster_engine import get_cluster_metrics
        return jsonify(get_cluster_metrics())

    @app.route('/api/clusters/history')
    def api_cluster_history():
        """Get resolution audit trail."""
        from app.detection.alert_cluster_engine import get_resolution_history
        cluster_id = request.args.get('cluster_id')
        return jsonify(get_resolution_history(cluster_id))

    # ── EXPLAINABILITY API ───────────────────────────────────────

    @app.route('/api/alerts/<int:alert_id>/explain')
    def api_explain_alert(alert_id):
        """Get human-readable explanation for an alert."""
        from app.detection.explainability import explain_alert
        return jsonify(explain_alert(alert_id))

    @app.route('/api/clusters/<cluster_id>/explain')
    def api_explain_cluster(cluster_id):
        """Get human-readable explanation for a cluster."""
        from app.detection.explainability import explain_cluster
        return jsonify(explain_cluster(cluster_id))

    # ── REPORTING ENGINE API ─────────────────────────────────────

    @app.route('/api/alerts/<int:alert_id>/report')
    def api_alert_report(alert_id):
        from app.detection.explainability import explain_alert
        from app.reporting.engine import generate_alert_report_data
        from app.db import get_connection, release_connection
        
        conn = get_connection()
        try:
            alert_dict = _fetchone(conn, "SELECT * FROM alerts WHERE id = %s", [alert_id])
            if not alert_dict:
                return "Alert not found", 404
                
            txns_dict = _fetchall(conn, """
                SELECT * FROM transactions 
                WHERE (from_account = %s OR to_account = %s)
                ORDER BY timestamp DESC LIMIT 50
            """, [alert_dict['account_id'], alert_dict['account_id']])
        finally:
            release_connection(conn)
            
        xai_data = explain_alert(alert_id)
        
        class _Proxy: pass
        
        alert_obj = _Proxy()
        alert_obj.__dict__.update(alert_dict)
        
        txn_objs = []
        for t in txns_dict:
            obj = _Proxy()
            obj.__dict__.update(t)
            txn_objs.append(obj)
            
        ctx = generate_alert_report_data(alert_obj, txn_objs, xai_data)
        auto_print = request.args.get('print', '1') == '1'
        return render_template('reports/alert_report.html', ctx=ctx, auto_print=auto_print)

    @app.route('/api/clusters/<cluster_id>/report')
    def api_cluster_report(cluster_id):
        from app.detection.alert_cluster_engine import get_cluster_detail
        from app.detection.explainability import explain_cluster
        from app.reporting.engine import generate_cluster_report_data
        
        detail = get_cluster_detail(cluster_id)
        if not detail:
            return "Cluster not found", 404
            
        xai_data = explain_cluster(cluster_id)
        
        class _ClusterProxy:
            pass
        cluster_obj = _ClusterProxy()
        for k, v in detail.items():
            if k != 'members':
                setattr(cluster_obj, k, v)
            
        class _AlertProxy:
            pass
        alerts_list = []
        for a_dict in detail.get('members', []):
            a = _AlertProxy()
            for k, v in a_dict.items():
                setattr(a, k, v)
            alerts_list.append(a)
            
        ctx = generate_cluster_report_data(cluster_obj, alerts_list, xai_data)
        auto_print = request.args.get('print', '1') == '1'
        return render_template('reports/cluster_report.html', ctx=ctx, auto_print=auto_print)

    @app.route('/api/reports/executive')
    def api_executive_report():
        from app.detection.alert_cluster_engine import list_clusters
        from app.reporting.engine import generate_executive_report_data
        from app.db import get_connection, release_connection
        
        conn = get_connection()
        try:
            alerts_dict = _fetchall(conn, "SELECT * FROM alerts")
        finally:
            release_connection(conn)
            
        clusters_data = list_clusters('open', limit=1000)
        
        class _Proxy: pass
        alert_objs = []
        for a in alerts_dict:
            obj = _Proxy()
            obj.__dict__.update(a)
            alert_objs.append(obj)
            
        ctx = generate_executive_report_data(alert_objs, clusters_data, {'status': 'Operational'})
        auto_print = request.args.get('print', '1') == '1'
        return render_template('reports/executive_report.html', ctx=ctx, auto_print=auto_print)

    return app

