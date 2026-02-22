"""
Run the full alert generation pipeline:
1. Activate all draft rule sets so the rule engine can use them
2. Load LI-Small transaction data (if not already loaded)
3. Run the compliance scan (rule engine + fusion) to generate alerts
4. Print alert summary
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(__file__))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from app.db import get_connection, init_schema, release_connection, execute


def main():
    print("=" * 70)
    print("  ALERT GENERATION PIPELINE")
    print("=" * 70)

    # ── Step 0: Init schema ───────────────────────────────────────
    conn = get_connection()
    init_schema(conn)
    release_connection(conn)

    # ── Step 1: Check if transactions are loaded ──────────────────
    print("\n[Step 1] Checking transaction data...")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM transactions")
            row = cur.fetchone()
            txn_count = row["cnt"] if row else 0
    finally:
        release_connection(conn)

    if txn_count == 0:
        print(f"  No transactions found in DB. Loading LI-Small dataset...")
        from app.data_layer.loader import setup_database
        li_txn_csv = os.path.join(os.path.dirname(__file__), "Dataset", "LI-Small_Trans.csv")
        li_acc_csv = os.path.join(os.path.dirname(__file__), "Dataset", "LI-Small_accounts.csv")

        if os.path.exists(li_txn_csv) and os.path.exists(li_acc_csv):
            setup_database(
                limit=None,
                truncate_first=True,
                transactions_csv=li_txn_csv,
                accounts_csv=li_acc_csv,
            )
            conn = get_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) as cnt FROM transactions")
                    row = cur.fetchone()
                    txn_count = row["cnt"] if row else 0
            finally:
                release_connection(conn)
        else:
            print(f"  ERROR: LI-Small CSV files not found!")
            return 1

    print(f"  ✓ {txn_count:,} transactions in database")

    # ── Step 2: Check rules ───────────────────────────────────────
    print("\n[Step 2] Checking extracted rules...")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM rules WHERE is_deleted = 0")
            row = cur.fetchone()
            rule_count = row["cnt"] if row else 0

            cur.execute("SELECT COUNT(*) as cnt FROM rules WHERE status IN ('active', 'approved') AND is_deleted = 0")
            row = cur.fetchone()
            active_count = row["cnt"] if row else 0

            cur.execute("SELECT COUNT(*) as cnt FROM rules WHERE status = 'draft' AND is_deleted = 0")
            row = cur.fetchone()
            draft_count = row["cnt"] if row else 0
    finally:
        release_connection(conn)

    print(f"  Total rules: {rule_count}")
    print(f"  Active/Approved: {active_count}")
    print(f"  Draft: {draft_count}")

    if rule_count == 0:
        print("  No rules found! Run 'python run_extraction.py' first to extract rules from policies.")
        return 1

    # ── Step 3: Activate all draft rules ──────────────────────────
    if draft_count > 0 and active_count == 0:
        print(f"\n[Step 3] Activating {draft_count} draft rules...")
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Activate all draft rules
                cur.execute("UPDATE rules SET status = 'active' WHERE status = 'draft' AND is_deleted = 0")
                activated = cur.rowcount

                # Also activate any draft rule sets
                cur.execute("UPDATE rule_sets SET status = 'active' WHERE status = 'draft'")
                rulesets_activated = cur.rowcount
            conn.commit()
        finally:
            release_connection(conn)
        print(f"  ✓ Activated {activated} rules and {rulesets_activated} rule sets")
    else:
        print(f"\n[Step 3] Rules already active ({active_count} rules)")

    # ── Step 4: Show which rules are active ───────────────────────
    print("\n[Step 4] Active rules:")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, rule_type, severity, conditions 
                FROM rules 
                WHERE status IN ('active', 'approved') AND is_deleted = 0
                ORDER BY severity DESC, name
            """)
            rules = cur.fetchall()
            for r in rules:
                conds = json.loads(r["conditions"]) if r["conditions"] else []
                cond_str = ""
                if conds:
                    c = conds[0]
                    if isinstance(c, dict):
                        cond_str = f" ({c.get('metric', '?')} {c.get('operator', '?')} {c.get('value', '?')})"
                print(f"  [{r['id']}] {r['name']} | {r['rule_type']} | {r['severity']}{cond_str}")
    finally:
        release_connection(conn)

    # ── Step 5: Run the compliance scan ───────────────────────────
    print(f"\n[Step 5] Running compliance scan...")
    import pandas as pd
    from app.detection.rule_engine import RuleEngine
    from app.detection.fusion import FusionEngine

    # Rule engine
    engine = RuleEngine()
    print(f"  Rule engine loaded {len(engine.rules)} rules")
    violations = engine.evaluate_all()
    engine.close()
    print(f"  ✓ Found {len(violations)} rule violations")

    # ML signal (optional)
    ml_risks = None
    try:
        from app.detection.ml_engine import MLEngine
        from app.config import MODELS_DIR
        model_path = os.path.join(MODELS_DIR, 'lgbm_model.pkl')
        if os.path.exists(model_path):
            ml = MLEngine()
            if ml.load_model():
                ml_risks = ml.predict_risks()
                print(f"  ✓ ML risks: {ml_risks.shape[0]} accounts scored")
    except Exception as ml_err:
        print(f"  ML signal unavailable: {ml_err}")

    # Graph signal (optional)
    graph_risks = {}
    try:
        from app.detection.graph_engine import GraphEngine
        graph = GraphEngine()
        graph_risks = graph.analyze()
        print(f"  ✓ Graph risks: {len(graph_risks)} accounts scored")
    except Exception as ge:
        print(f"  Graph signal unavailable: {ge}")

    # Fuse
    fusion = FusionEngine()
    alerts = fusion.fuse(
        violations,
        ml_risks if ml_risks is not None else pd.DataFrame(),
        graph_risks or {},
    )
    fusion.save_alerts_to_db(alerts)

    # ── Step 6: Print alerts ──────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"  ALERT RESULTS")
    print(f"{'=' * 70}")
    print(f"  Total violations:  {len(violations)}")
    print(f"  Total alerts:      {len(alerts)}")

    if alerts:
        print(f"\n  Top 20 Alerts (sorted by fusion score):")
        print(f"  {'Account':<20} {'Fusion':<8} {'Rule':<8} {'ML':<8} {'Graph':<8} {'Severity':<10} {'Triggered Rules'}")
        print(f"  {'─'*20} {'─'*8} {'─'*8} {'─'*8} {'─'*8} {'─'*10} {'─'*30}")
        for a in alerts[:20]:
            triggered = ", ".join(a.get("triggered_rules", [])[:3])
            print(f"  {a['account_id']:<20} {a['fusion_score']:<8.4f} {a['rule_score']:<8.4f} "
                  f"{a['ml_score']:<8.4f} {a['graph_score']:<8.4f} {a['severity']:<10} {triggered}")

        # Severity breakdown
        sev = {}
        for a in alerts:
            sev[a['severity']] = sev.get(a['severity'], 0) + 1
        print(f"\n  Severity Breakdown:")
        for s in ['critical', 'high', 'medium', 'low']:
            if s in sev:
                print(f"    {s}: {sev[s]}")

    print(f"\n  ✓ Alerts saved to database — view them at http://localhost:5000/alerts")
    print(f"{'=' * 70}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
