"""Load CSV dataset into SQLite using SQLAlchemy + pandas chunked writes.

Batch ingest: setup_database(truncate_first=False) by default — append to existing
transactions/accounts. Use truncate_first=True for a full replace (clear then load).
Chunked reads (CHUNK_SIZE) are used for large CSVs; re-running ingest with the same
CSV in append mode may create duplicate rows unless truncate is used for a clean reload.
"""

import pandas as pd
import os
import time
from sqlalchemy import create_engine, text
from app.config import (
    BASE_DIR,
    DATASET_DIR,
    TRANSACTIONS_CSV,
    ACCOUNTS_CSV,
    DATABASE_URL,
    CHUNK_SIZE,
)
from app.db import get_connection, init_schema, create_indexes, release_connection


COLUMN_MAP_ACCOUNTS = {
    "Bank Name": "bank_name",
    "Bank ID": "bank_id",
    "Account Number": "account_number",
    "Entity ID": "entity_id",
    "Entity Name": "entity_name",
}


def _get_engine():
    """SQLAlchemy engine for pandas to_sql bulk writes."""
    return create_engine(DATABASE_URL)


def load_transactions(conn=None, csv_path=None, chunk_size=None, limit=None):
    """Load transactions CSV into PostgreSQL in chunks via SQLAlchemy.

    Args:
        conn: ignored (kept for API compat) — uses SQLAlchemy engine internally
        csv_path: Path to transactions CSV
        chunk_size: Number of rows per chunk
        limit: Max rows to load (None = all)
    """
    csv_path = csv_path or TRANSACTIONS_CSV
    chunk_size = chunk_size or CHUNK_SIZE

    if not os.path.exists(csv_path):
        print(f"[Loader] CSV not found: {csv_path}")
        return 0

    print(f"[Loader] Loading transactions from: {csv_path}")
    print(f"[Loader] Chunk size: {chunk_size:,}")

    # The CSV has duplicate "Account" columns — we rename them
    col_names = [
        "Timestamp", "From Bank", "From Account", "To Bank", "To Account",
        "Amount Received", "Receiving Currency", "Amount Paid",
        "Payment Currency", "Payment Format", "Is Laundering"
    ]

    total_rows = 0
    start_time = time.time()
    engine = _get_engine()

    reader = pd.read_csv(
        csv_path,
        chunksize=chunk_size,
        header=0,
        names=col_names,
        dtype={
            "From Bank": str, "From Account": str,
            "To Bank": str, "To Account": str,
            "Payment Format": str, "Payment Currency": str,
            "Receiving Currency": str,
        },
        low_memory=False,
    )

    for i, chunk in enumerate(reader):
        chunk = chunk.rename(columns={
            "Timestamp": "timestamp",
            "From Bank": "from_bank",
            "From Account": "from_account",
            "To Bank": "to_bank",
            "To Account": "to_account",
            "Amount Received": "amount_received",
            "Receiving Currency": "receiving_currency",
            "Amount Paid": "amount_paid",
            "Payment Currency": "payment_currency",
            "Payment Format": "payment_format",
            "Is Laundering": "is_laundering",
        })

        chunk["amount_received"] = pd.to_numeric(chunk["amount_received"], errors="coerce").fillna(0)
        chunk["amount_paid"] = pd.to_numeric(chunk["amount_paid"], errors="coerce").fillna(0)
        chunk["is_laundering"] = pd.to_numeric(chunk["is_laundering"], errors="coerce").fillna(0).astype(int)

        chunk.to_sql("transactions", engine, if_exists="append", index=False)

        total_rows += len(chunk)
        elapsed = time.time() - start_time
        rate = total_rows / elapsed if elapsed > 0 else 0
        print(f"  Chunk {i+1}: {total_rows:,} rows loaded ({rate:,.0f} rows/sec)")

        if limit and total_rows >= limit:
            print(f"[Loader] Reached limit of {limit:,} rows")
            break

    elapsed = time.time() - start_time
    print(f"[Loader] Loaded {total_rows:,} transactions in {elapsed:.1f}s")
    return total_rows


def load_accounts(conn=None, csv_path=None):
    """Load accounts CSV into PostgreSQL."""
    csv_path = csv_path or ACCOUNTS_CSV

    if not os.path.exists(csv_path):
        print(f"[Loader] CSV not found: {csv_path}")
        return 0

    print(f"[Loader] Loading accounts from: {csv_path}")
    start_time = time.time()

    col_names = ["Bank Name", "Bank ID", "Account Number", "Entity ID", "Entity Name"]
    df = pd.read_csv(csv_path, header=0, names=col_names, dtype=str, low_memory=False)
    df = df.rename(columns=COLUMN_MAP_ACCOUNTS)

    engine = _get_engine()
    df.to_sql("accounts", engine, if_exists="append", index=False)

    elapsed = time.time() - start_time
    print(f"[Loader] Loaded {len(df):,} accounts in {elapsed:.1f}s")
    return len(df)


def _resolve_csv_path(path, fallback):
    """Resolve relative path against BASE_DIR or DATASET_DIR; absolute paths pass through."""
    if not path:
        return fallback
    p = path.strip()
    if not p:
        return fallback
    if not os.path.isabs(p):
        # relative: try under DATASET_DIR first, then BASE_DIR
        for root in (DATASET_DIR, BASE_DIR):
            candidate = os.path.normpath(os.path.join(root, p))
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
        candidate = os.path.normpath(os.path.join(BASE_DIR, p))
        return os.path.abspath(candidate)
    return os.path.abspath(p)


def setup_database(limit=None, truncate_first=False, transactions_csv=None, accounts_csv=None):
    """Full database setup: schema + optional truncate + data load + indexes.
    Default truncate_first=False: append to existing data (one-time load friendly).
    Set truncate_first=True for full replace (clear tables then load).
    Optional transactions_csv and accounts_csv: override dataset paths (relative or absolute).
    """
    print("=" * 60)
    print("  COMPLIANCE AGENT — DATABASE SETUP (SQLite)")
    print("=" * 60)

    txn_path = _resolve_csv_path(transactions_csv, TRANSACTIONS_CSV)
    acc_path = _resolve_csv_path(accounts_csv, ACCOUNTS_CSV)

    # 1. Ensure schema exists
    conn = get_connection()
    try:
        print("\n[1/4] Creating schema...")
        init_schema(conn)
    finally:
        release_connection(conn)

    # 2. Optionally clear tables for a clean reload
    if truncate_first:
        engine = _get_engine()
        with engine.connect() as c:
            c.execute(text("DELETE FROM transactions"))
            c.execute(text("DELETE FROM accounts"))
            c.commit()
        print("[Loader] Tables cleared for clean reload.")


    # 3. Load transactions
    print("\n[2/4] Loading transactions...")
    n_txn = load_transactions(csv_path=txn_path, limit=limit)

    # 4. Load accounts
    print("\n[3/4] Loading accounts...")
    n_acc = load_accounts(csv_path=acc_path)

    # 5. Create indexes
    conn = get_connection()
    try:
        print("\n[4/4] Creating indexes...")
        create_indexes(conn)
        conn.commit()
    finally:
        release_connection(conn)

    print("\n" + "=" * 60)
    print("  SETUP COMPLETE")
    print(f"  Transactions: {n_txn:,}")
    print(f"  Accounts:     {n_acc:,}")
    print(f"  Database:     {DATABASE_URL}")
    print("=" * 60)

    return n_txn, n_acc
