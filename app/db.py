"""Database connection and query helpers — SQLite backend with psycopg2-compatible API.

This module provides a psycopg2-style interface backed by SQLite so that all
application code written for psycopg2 (cursor(), %s placeholders, RealDictCursor,
NOW(), RETURNING id, ILIKE, ::numeric casts) works transparently without any
changes to the callers.

Works on any platform (ARM, x86, etc.) — SQLite is built into Python.
"""
import os
import re
import sqlite3
import threading
from app.config import DB_PATH

# ── SQL dialect translator ─────────────────────────────────────────────────

def _translate(sql: str) -> str:
    """Convert PostgreSQL-isms to SQLite-compatible SQL."""
    # %s → ?
    sql = sql.replace('%s', '?')
    # NOW() → datetime('now')
    sql = re.sub(r'\bNOW\(\)', "datetime('now')", sql, flags=re.IGNORECASE)
    # ILIKE → LIKE  (SQLite LIKE is already case-insensitive for ASCII)
    sql = re.sub(r'\bILIKE\b', 'LIKE', sql, flags=re.IGNORECASE)
    # Remove PostgreSQL type casts: ::numeric, ::text, ::int, etc.
    sql = re.sub(r'::\w+', '', sql)
    # BIGSERIAL → INTEGER (in DDL)
    sql = re.sub(r'\bBIGSERIAL\b', 'INTEGER', sql, flags=re.IGNORECASE)
    # DOUBLE PRECISION → REAL
    sql = re.sub(r'\bDOUBLE PRECISION\b', 'REAL', sql, flags=re.IGNORECASE)
    # TIMESTAMPTZ → TEXT
    sql = re.sub(r'\bTIMESTAMPTZ\b', 'TEXT', sql, flags=re.IGNORECASE)
    # BIGINT → INTEGER
    sql = re.sub(r'\bBIGINT\b', 'INTEGER', sql, flags=re.IGNORECASE)
    # BOOLEAN → INTEGER
    sql = re.sub(r'\bBOOLEAN\b', 'INTEGER', sql, flags=re.IGNORECASE)
    # FOREIGN KEY constraints — SQLite supports them but they must be enabled
    # (we enable them per-connection so they're fine to keep)
    # ON CONFLICT (col) DO UPDATE SET ... — SQLite 3.24+ supports upsert natively
    # updated_at = NOW() inside ON CONFLICT → updated_at = datetime('now') (already done above)
    return sql


def _extract_returning(sql: str):
    """Strip RETURNING clause and return (cleaned_sql, returning_col_or_None)."""
    m = re.search(r'\bRETURNING\s+(\w+)\s*$', sql.strip(), re.IGNORECASE)
    if m:
        col = m.group(1)
        sql = re.sub(r'\s*RETURNING\s+\w+\s*$', '', sql.strip(), flags=re.IGNORECASE)
        return sql, col
    return sql, None


# ── Dict cursor wrapper ────────────────────────────────────────────────────

class _DictCursor:
    """sqlite3 cursor wrapper that mimics psycopg2 RealDictCursor."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self._returning_col = None
        self.lastrowid = None
        self.rowcount = 0

    # context manager support — used as  `with conn.cursor(...) as cur:`
    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self._cur.close()
        except Exception:
            pass

    def execute(self, sql, params=None):
        sql, self._returning_col = _extract_returning(sql)
        sql = _translate(sql)
        params = list(params) if params else []
        self._cur.execute(sql, params)
        self.lastrowid = self._cur.lastrowid
        self.rowcount = self._cur.rowcount
        return self

    def fetchone(self):
        if self._returning_col:
            # Simulate RETURNING id → return lastrowid as tuple
            return (self.lastrowid,)
        row = self._cur.fetchone()
        if row is None:
            return None
        desc = self._cur.description
        if desc:
            return {desc[i][0]: row[i] for i in range(len(desc))}
        return row

    def fetchall(self):
        rows = self._cur.fetchall()
        if not rows:
            return []
        desc = self._cur.description
        if desc:
            return [{desc[i][0]: r[i] for i in range(len(desc))} for r in rows]
        return rows

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass


# ── Connection wrapper ─────────────────────────────────────────────────────

class _DictConnection:
    """sqlite3 connection wrapper that mimics a psycopg2 connection."""

    def __init__(self, raw_conn: sqlite3.Connection):
        self._conn = raw_conn

    def cursor(self, cursor_factory=None):
        # cursor_factory is ignored — always returns our DictCursor
        return _DictCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    # autocommit property (psycopg2 compat)
    @property
    def autocommit(self):
        return self._conn.isolation_level is None

    @autocommit.setter
    def autocommit(self, val):
        if val:
            self._conn.isolation_level = None
        else:
            self._conn.isolation_level = ''


# ── Thread-local connection pool ───────────────────────────────────────────
# SQLite doesn't support a real pool, but Flask uses threads so we give each
# thread its own long-lived connection.

_local = threading.local()


def _open_connection() -> _DictConnection:
    raw = sqlite3.connect(DB_PATH, check_same_thread=False)
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA synchronous=NORMAL")
    raw.execute("PRAGMA foreign_keys=ON")
    return _DictConnection(raw)


def get_connection() -> _DictConnection:
    """Get (or create) a per-thread SQLite connection."""
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = _open_connection()
    return _local.conn


def release_connection(conn):
    """No-op for SQLite — the thread-local connection stays open."""
    pass  # connection is reused per thread


# ── Schema ─────────────────────────────────────────────────────────────────

def init_schema(conn):
    """Create all tables if they don't exist (SQLite DDL)."""
    # Use executescript for multi-statement DDL — it auto-commits
    ddl = """
    CREATE TABLE IF NOT EXISTS transactions (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp        TEXT,
        from_bank        TEXT,
        from_account     TEXT,
        to_bank          TEXT,
        to_account       TEXT,
        amount_received  REAL,
        receiving_currency TEXT,
        amount_paid      REAL,
        payment_currency TEXT,
        payment_format   TEXT,
        is_laundering    INTEGER
    );

    CREATE TABLE IF NOT EXISTS accounts (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        bank_name      TEXT,
        bank_id        TEXT,
        account_number TEXT,
        entity_id      TEXT,
        entity_name    TEXT
    );

    CREATE TABLE IF NOT EXISTS rules (
        id               TEXT PRIMARY KEY,
        version_id       TEXT NOT NULL DEFAULT 'legacy-v0.0' REFERENCES policy_versions(version_id),
        name             TEXT NOT NULL,
        source_document  TEXT,
        source_page      INTEGER,
        source_text      TEXT,
        rule_type        TEXT,
        conditions       TEXT,
        severity         TEXT,
        version          TEXT DEFAULT '1.0',
        status           TEXT DEFAULT 'active',
        confidence       REAL DEFAULT 0.0,
        review_required  INTEGER DEFAULT 0,
        ambiguous        INTEGER DEFAULT 0,
        rule_hash        TEXT,
        policy_version   TEXT,
        effective_date   TEXT,
        is_deleted       INTEGER DEFAULT 0,
        deleted_at       TEXT,
        created_at       TEXT DEFAULT (datetime('now')),
        updated_at       TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id  INTEGER,
        account_id      TEXT,
        rule_score      REAL DEFAULT 0,
        ml_score        REAL DEFAULT 0,
        graph_score     REAL DEFAULT 0,
        fusion_score    REAL DEFAULT 0,
        severity        TEXT,
        status          TEXT DEFAULT 'pending',
        triggered_rules TEXT,
        explanation     TEXT,
        created_at      TEXT DEFAULT (datetime('now')),
        reviewed_by     TEXT,
        reviewed_at     TEXT,
        review_action   TEXT,
        review_notes    TEXT,
        rule_set_version TEXT
    );

    CREATE TABLE IF NOT EXISTS policy_documents (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        policy_id     TEXT,
        filename      TEXT NOT NULL,
        version       TEXT DEFAULT 'v1.0',
        checksum      TEXT,
        raw_text      TEXT,
        page_count    INTEGER,
        uploaded_by   TEXT DEFAULT 'system',
        policy_status TEXT DEFAULT 'draft',
        uploaded_at   TEXT DEFAULT (datetime('now')),
        status        TEXT DEFAULT 'processed'
    );

    CREATE TABLE IF NOT EXISTS rule_lineage (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_rule_id  TEXT NOT NULL,
        child_rule_id   TEXT NOT NULL,
        change_reason   TEXT,
        source_clause   TEXT,
        policy_version  TEXT,
        created_at      TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS extraction_audit_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        policy_id    TEXT,
        rule_id      TEXT,
        action       TEXT NOT NULL,
        details      TEXT,
        performed_by TEXT DEFAULT 'system',
        created_at   TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS monitoring_runs (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        run_type             TEXT,
        started_at           TEXT DEFAULT (datetime('now')),
        completed_at         TEXT,
        transactions_scanned INTEGER,
        alerts_generated     INTEGER,
        status               TEXT DEFAULT 'running'
    );

    CREATE TABLE IF NOT EXISTS audit_reports (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        report_type  TEXT,
        filename     TEXT,
        generated_at TEXT DEFAULT (datetime('now')),
        alert_ids    TEXT,
        summary      TEXT
    );

    CREATE TABLE IF NOT EXISTS user_roles (
        email       TEXT PRIMARY KEY,
        role        TEXT NOT NULL DEFAULT 'analyst',
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS alert_review_history (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id     INTEGER NOT NULL,
        action       TEXT NOT NULL,
        performed_by TEXT NOT NULL,
        performed_at TEXT DEFAULT (datetime('now')),
        notes        TEXT,
        FOREIGN KEY (alert_id) REFERENCES alerts(id)
    );

    CREATE TABLE IF NOT EXISTS rule_sets (
        id               TEXT PRIMARY KEY,
        policy_id        TEXT NOT NULL,
        policy_version   TEXT NOT NULL,
        ruleset_version  TEXT NOT NULL,
        rule_ids         TEXT,
        created_at       TEXT DEFAULT (datetime('now')),
        created_by       TEXT,
        status           TEXT DEFAULT 'draft',
        description      TEXT
    );

    CREATE TABLE IF NOT EXISTS rule_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id     TEXT NOT NULL,
        ruleset_id  TEXT NOT NULL,
        rule_data   TEXT,
        snapshot_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS simulation_runs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        simulation_id  TEXT UNIQUE NOT NULL,
        ruleset_id     TEXT NOT NULL,
        start_date     TEXT NOT NULL,
        end_date       TEXT NOT NULL,
        baseline_alerts INTEGER,
        simulated_alerts INTEGER,
        results_json   TEXT,
        created_at     TEXT DEFAULT (datetime('now')),
        created_by     TEXT,
        status         TEXT DEFAULT 'completed'
    );

    CREATE TABLE IF NOT EXISTS governance_approvals (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type    TEXT NOT NULL,
        entity_id      TEXT NOT NULL,
        submitter      TEXT NOT NULL,
        reviewer       TEXT,
        status         TEXT DEFAULT 'pending',
        comments       TEXT,
        submitted_at   TEXT DEFAULT (datetime('now')),
        reviewed_at    TEXT
    );
    """
    conn._conn.executescript(ddl)


def _migrate_governance_v2(conn):
    """Safely migrate SQLite database to enforce version_id foreign keys and maker-checker tables."""
    raw = conn._conn
    cur = raw.cursor()
    
    # 1. Ensure governance schema exists so policy_versions is available
    try:
        from app.policy_engine.policy_governance import ensure_governance_schema
        ensure_governance_schema()
    except Exception:
        pass
        
    # 2. Add legacy policy version to satisfy FK constraint for orphaned rules
    cur.execute("""
        INSERT OR IGNORE INTO policy_versions (version_id, policy_id, version_number, status, created_by)
        VALUES ('legacy-v0.0', 'legacy', 'v0.0', 'approved', 'system')
    """)
    conn.commit()
    
    # 3. Check if rules table needs recreating (to add FK)
    cur.execute("PRAGMA table_info(rules)")
    columns = [row[1] for row in cur.fetchall()]
    
    if "version_id" not in columns:
        cur.execute("PRAGMA foreign_keys=OFF")
        
        cur.execute("""
        CREATE TABLE rules_new (
            id               TEXT PRIMARY KEY,
            version_id       TEXT NOT NULL DEFAULT 'legacy-v0.0' REFERENCES policy_versions(version_id),
            name             TEXT NOT NULL,
            source_document  TEXT,
            source_page      INTEGER,
            source_text      TEXT,
            rule_type        TEXT,
            conditions       TEXT,
            severity         TEXT,
            version          TEXT DEFAULT '1.0',
            status           TEXT DEFAULT 'active',
            confidence       REAL DEFAULT 0.0,
            review_required  INTEGER DEFAULT 0,
            ambiguous        INTEGER DEFAULT 0,
            rule_hash        TEXT,
            policy_version   TEXT,
            effective_date   TEXT,
            is_deleted       INTEGER DEFAULT 0,
            deleted_at       TEXT,
            created_at       TEXT DEFAULT (datetime('now')),
            updated_at       TEXT DEFAULT (datetime('now'))
        )
        """)
        
        cur.execute("""
        INSERT INTO rules_new (
            id, name, source_document, source_page, source_text, rule_type,
            conditions, severity, version, status, confidence, review_required,
            ambiguous, rule_hash, policy_version, effective_date, is_deleted,
            deleted_at, created_at, updated_at
        )
        SELECT 
            id, name, source_document, source_page, source_text, rule_type,
            conditions, severity, version, status, confidence, review_required,
            ambiguous, rule_hash, policy_version, effective_date, is_deleted,
            deleted_at, created_at, updated_at
        FROM rules
        """)
        
        cur.execute("DROP TABLE rules")
        cur.execute("ALTER TABLE rules_new RENAME TO rules")
        cur.execute("PRAGMA foreign_keys=ON")
        conn.commit()
        
    # 4. Add new columns to rule_lineage
    cur.execute("PRAGMA table_info(rule_lineage)")
    lineage_cols = [row[1] for row in cur.fetchall()]
    if "source_clause" not in lineage_cols:
        cur.execute("ALTER TABLE rule_lineage ADD COLUMN source_clause TEXT")
    if "policy_version" not in lineage_cols:
        cur.execute("ALTER TABLE rule_lineage ADD COLUMN policy_version TEXT")
    
    conn.commit()
    cur.close()


def _ensure_alerts_rule_set_version(conn):
    """Add rule_set_version column to alerts if missing (migration for existing DBs)."""
    raw = conn._conn
    cur = raw.cursor()
    cur.execute("PRAGMA table_info(alerts)")
    rows = cur.fetchall()
    names = [row[1] for row in rows]
    if "rule_set_version" not in names:
        cur.execute("ALTER TABLE alerts ADD COLUMN rule_set_version TEXT")
        conn.commit()
    cur.close()


def create_indexes(conn):
    """Create performance indexes after data load."""
    _ensure_alerts_rule_set_version(conn)
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_txn_from       ON transactions(from_bank, from_account)",
        "CREATE INDEX IF NOT EXISTS idx_txn_to         ON transactions(to_bank, to_account)",
        "CREATE INDEX IF NOT EXISTS idx_txn_timestamp  ON transactions(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_txn_amount     ON transactions(amount_paid)",
        "CREATE INDEX IF NOT EXISTS idx_txn_laundering ON transactions(is_laundering)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts(status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_score   ON alerts(fusion_score DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_rule_set_version ON alerts(rule_set_version)",
        "CREATE INDEX IF NOT EXISTS idx_accounts_num   ON accounts(account_number)",
        "CREATE INDEX IF NOT EXISTS idx_review_history_alert ON alert_review_history(alert_id)",
    ]
    with conn.cursor() as cur:
        for idx in indexes:
            cur.execute(idx)
    conn.commit()


def init_db():
    """Convenience: get connection, create schema + indexes."""
    conn = get_connection()
    init_schema(conn)
    try:
        _migrate_governance_v2(conn)
    except Exception as e:
        print(f"[DB] Governance v2 migration failed: {e}")
        
    try:
        create_indexes(conn)
    except Exception:
        pass  # indexes may fail if table is empty — not critical
    print(f"[DB] SQLite schema ready at {DB_PATH}")


# ── Query helpers ──────────────────────────────────────────────────────────

def query(sql, params=None):
    """Execute a read query; returns list of dicts. Accepts %s placeholders."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(sql, params or [])
        return cur.fetchall()


def execute(sql, params=None):
    """Execute a write query; returns last inserted rowid (or None)."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or [])
            lastid = cur.lastrowid
        conn.commit()
        return lastid
    except Exception:
        conn.rollback()
        raise
