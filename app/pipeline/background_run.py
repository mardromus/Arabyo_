"""
Run the full main dataset through the pipeline in a background thread.
Loads all transactions (truncate + full load), then runs rule engine, ML train, graph, fusion.
"""
import logging
import threading
from typing import Tuple

from app.db import get_connection, release_connection, execute, query

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_running_run_id: int | None = None


def _run_full_pipeline(run_id: int) -> None:
    """Background thread: full load then run_pipeline(skip_setup=True). Updates monitoring_runs."""
    global _running_run_id
    try:
        from app.data_layer.loader import setup_database
        from run_pipeline import run_pipeline

        logger.info("[Pipeline] Full load starting (run_id=%s)", run_id)
        setup_database(limit=None, truncate_first=True)

        logger.info("[Pipeline] Running pipeline (skip_setup=True)")
        result = run_pipeline(skip_setup=True)
        alerts_count = result.get("alerts_count", 0) if isinstance(result, dict) else len(result)
        violations_count = result.get("violations_count", 0) if isinstance(result, dict) else 0

        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM transactions")
                row = cur.fetchone()
            txn_count = (row or {}).get("cnt", 0)
        finally:
            release_connection(conn)

        execute(
            """
            UPDATE monitoring_runs
            SET completed_at = NOW(), transactions_scanned = %s,
                alerts_generated = %s, status = 'completed'
            WHERE id = %s
            """,
            [txn_count, alerts_count, run_id],
        )
        logger.info("[Pipeline] Full pipeline completed run_id=%s, txn=%s, alerts=%s", run_id, txn_count, alerts_count)
    except Exception as e:
        logger.exception("[Pipeline] Full pipeline failed: %s", e)
        try:
            execute(
                "UPDATE monitoring_runs SET status = 'failed', completed_at = NOW() WHERE id = %s",
                [run_id],
            )
        except Exception:
            pass
    finally:
        with _lock:
            if _running_run_id == run_id:
                _running_run_id = None


def start_full_pipeline() -> Tuple[bool, str | None, int | None]:
    """
    Start a full-dataset pipeline run in a background thread.
    Returns (started, message, run_id).
    If already running: started=False, message="...", run_id=None.
    If started: started=True, message=None, run_id=<id>.
    """
    global _running_run_id
    with _lock:
        if _running_run_id is not None:
            return False, "Full pipeline already in progress", None
        run_id = execute(
            "INSERT INTO monitoring_runs (run_type, status) VALUES (%s, %s)",
            ["full_pipeline", "running"],
        )
        if not run_id:
            return False, "Failed to create run record", None
        _running_run_id = run_id

    thread = threading.Thread(target=_run_full_pipeline, args=(run_id,), daemon=True)
    thread.start()
    return True, None, run_id


def get_full_pipeline_status() -> dict:
    """
    Return running state and last completed full_pipeline run.
    Keys: running (bool), run_id (int|None), last_run (dict|None), current_run (dict|None).
    On startup, any stale 'running' row (no active thread) is marked 'failed'.
    """
    with _lock:
        running = _running_run_id is not None
        run_id = _running_run_id

    if not running:
        try:
            execute(
                "UPDATE monitoring_runs SET status = %s WHERE run_type = %s AND status = %s",
                ["failed", "full_pipeline", "running"],
            )
        except Exception:
            pass

    rows = query(
        "SELECT id, started_at, completed_at, transactions_scanned, alerts_generated, status "
        "FROM monitoring_runs WHERE run_type = %s ORDER BY id DESC LIMIT 2",
        ["full_pipeline"],
    )
    current_run = None
    last_run = None
    for r in (rows or []):
        if r.get("status") == "running":
            current_run = r
        elif r.get("status") == "completed" and last_run is None:
            last_run = r

    return {
        "running": running,
        "run_id": run_id,
        "current_run": current_run,
        "last_run": last_run,
    }
