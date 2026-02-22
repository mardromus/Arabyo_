"""Data quality checks on the loaded transaction dataset — PostgreSQL backend."""
from app.db import get_connection, release_connection


def run_quality_checks():
    """Run comprehensive data quality checks and return a report."""
    conn = get_connection()
    report = {
        "total_transactions": 0,
        "total_accounts": 0,
        "checks": [],
        "issues": [],
        "summary": "",
    }

    def fetchone(sql, params=None):
        with conn.cursor(cursor_factory=None) as cur:
            cur.execute(sql, params or [])
            row = cur.fetchone()
            return dict(row) if row else {}

    def fetchall(sql, params=None):
        with conn.cursor(cursor_factory=None) as cur:
            cur.execute(sql, params or [])
            return [dict(r) for r in cur.fetchall()]

    try:
        # --- Basic counts ---
        report["total_transactions"] = fetchone("SELECT COUNT(*) as cnt FROM transactions").get("cnt", 0)
        report["total_accounts"] = fetchone("SELECT COUNT(*) as cnt FROM accounts").get("cnt", 0)

        # --- Check 1: Null/zero amounts ---
        zero_count = fetchone(
            "SELECT COUNT(*) as cnt FROM transactions WHERE amount_paid IS NULL OR amount_paid = 0"
        ).get("cnt", 0)
        report["checks"].append({
            "name": "Zero/Null Amount Paid",
            "count": zero_count,
            "pct": round(zero_count / max(report["total_transactions"], 1) * 100, 2),
            "status": "warning" if zero_count > 0 else "pass",
        })

        # --- Check 2: Negative amounts ---
        neg_count = fetchone(
            "SELECT COUNT(*) as cnt FROM transactions WHERE amount_paid < 0"
        ).get("cnt", 0)
        report["checks"].append({
            "name": "Negative Amount Paid",
            "count": neg_count,
            "status": "fail" if neg_count > 0 else "pass",
        })

        # --- Check 3: Missing timestamps ---
        null_ts = fetchone(
            "SELECT COUNT(*) as cnt FROM transactions WHERE timestamp IS NULL OR timestamp = ''"
        ).get("cnt", 0)
        report["checks"].append({
            "name": "Missing Timestamp",
            "count": null_ts,
            "status": "fail" if null_ts > 0 else "pass",
        })

        # --- Check 4: Laundering label distribution ---
        rows = fetchall("SELECT is_laundering, COUNT(*) as cnt FROM transactions GROUP BY is_laundering")
        report["checks"].append({
            "name": "Laundering Label Distribution",
            "distribution": {str(r["is_laundering"]): r["cnt"] for r in rows},
            "status": "info",
        })

        # --- Check 5: Currency distribution ---
        rows = fetchall(
            "SELECT payment_currency, COUNT(*) as cnt FROM transactions "
            "GROUP BY payment_currency ORDER BY cnt DESC LIMIT 10"
        )
        report["checks"].append({
            "name": "Top Payment Currencies",
            "distribution": {r["payment_currency"]: r["cnt"] for r in rows},
            "status": "info",
        })

        # --- Check 6: Payment format distribution ---
        rows = fetchall(
            "SELECT payment_format, COUNT(*) as cnt FROM transactions "
            "GROUP BY payment_format ORDER BY cnt DESC"
        )
        report["checks"].append({
            "name": "Payment Format Distribution",
            "distribution": {r["payment_format"]: r["cnt"] for r in rows},
            "status": "info",
        })

        # --- Check 7: Date range ---
        row = fetchone("SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts FROM transactions")
        report["checks"].append({
            "name": "Date Range",
            "min": str(row.get("min_ts", "")),
            "max": str(row.get("max_ts", "")),
            "status": "info",
        })

        # --- Check 8: Amount statistics ---
        row = fetchone(
            "SELECT AVG(amount_paid) as avg_amt, MAX(amount_paid) as max_amt, "
            "MIN(amount_paid) as min_amt FROM transactions WHERE amount_paid > 0"
        )
        report["checks"].append({
            "name": "Amount Statistics",
            "avg": round(float(row["avg_amt"]), 2) if row.get("avg_amt") else 0,
            "max": row.get("max_amt"),
            "min": row.get("min_amt"),
            "status": "info",
        })

        # Compile issues
        for check in report["checks"]:
            if check["status"] in ("fail", "warning"):
                report["issues"].append(f"{check['name']}: {check.get('count', 'N/A')} records")

        passed = sum(1 for c in report["checks"] if c["status"] == "pass")
        failed = sum(1 for c in report["checks"] if c["status"] == "fail")
        report["summary"] = (
            f"{passed} passed, {failed} failed, {len(report['issues'])} warnings. "
            f"{report['total_transactions']:,} transactions, {report['total_accounts']:,} accounts."
        )

    finally:
        release_connection(conn)

    return report
