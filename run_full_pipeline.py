"""
Unified High-Volume Alert Generation Pipeline.

Orchestrates the full detection stack:
1. Feature engineering + ML training (IsolationForest + LightGBM)
2. Graph analysis (PageRank + centrality + communities)
3. Account clustering (KMeans behavioral clustering)
4. Rule engine evaluation
5. Adaptive fusion (quantile-based targeting to ~10K alerts)
6. Alert persistence + summary
"""
import os
import sys
import time
import json

sys.path.insert(0, os.path.dirname(__file__))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import pandas as pd
import numpy as np
from app.db import get_connection, init_schema, release_connection, execute
from app.config import TARGET_ALERT_VOLUME


def main():
    start = time.time()

    print("=" * 70)
    print("  🧠 HIGH-VOLUME ALERT GENERATION PIPELINE")
    print(f"  Target: ~{TARGET_ALERT_VOLUME:,} alerts")
    print("=" * 70)

    # ── Init ──────────────────────────────────────────────────────
    conn = get_connection()
    init_schema(conn)
    release_connection(conn)

    # Check transactions
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM transactions")
            txn_count = cur.fetchone()["cnt"]
    finally:
        release_connection(conn)

    if txn_count == 0:
        print("ERROR: No transactions loaded! Run 'python load_small.py' first.")
        return 1

    print(f"\n[Data] {txn_count:,} transactions in database")

    # Activate any draft rules
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE rules SET status = 'active' WHERE status = 'draft' AND is_deleted = 0")
            activated = cur.rowcount
            cur.execute("UPDATE rule_sets SET status = 'active' WHERE status = 'draft'")
        conn.commit()
    finally:
        release_connection(conn)
    if activated > 0:
        print(f"[Rules] Activated {activated} draft rules")

    # ══════════════════════════════════════════════════════════════
    # LAYER 1 — ML ENGINE (IsolationForest + LightGBM)
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  LAYER 1: ML Engine (IsolationForest + LightGBM)")
    print(f"{'─' * 70}")

    from app.detection.ml_engine import MLEngine

    ml = MLEngine()
    features_df = ml.train()

    if features_df is not None and not features_df.empty:
        ml_risks = features_df[['account_id', 'ml_risk']].copy()
        print(f"  ✓ {len(ml_risks):,} accounts scored")
        print(f"  High-risk (>0.7): {(ml_risks['ml_risk'] > 0.7).sum():,}")
        print(f"  Medium-risk (>0.4): {(ml_risks['ml_risk'] > 0.4).sum():,}")
    else:
        ml_risks = pd.DataFrame()
        print("  ⚠ ML engine returned no features")

    # ══════════════════════════════════════════════════════════════
    # LAYER 2 — GRAPH ENGINE
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  LAYER 2: Graph Engine (PageRank + Centrality + Communities)")
    print(f"{'─' * 70}")

    graph_risks = {}
    try:
        from app.detection.graph_engine import GraphEngine
        graph = GraphEngine()
        graph_risks = graph.analyze()
        print(f"  ✓ {len(graph_risks):,} accounts scored")
        high_graph = sum(1 for v in graph_risks.values()
                         if (v.get('risk_score', 0) if isinstance(v, dict) else v) > 0.5)
        print(f"  High-risk (>0.5): {high_graph:,}")
    except Exception as e:
        print(f"  ⚠ Graph engine error: {e}")

    # ══════════════════════════════════════════════════════════════
    # LAYER 3 — CLUSTER ENGINE
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  LAYER 3: Cluster Engine (KMeans Behavioral Clustering)")
    print(f"{'─' * 70}")

    cluster_df = pd.DataFrame()
    try:
        from app.detection.cluster_engine import ClusterEngine
        cluster_eng = ClusterEngine(n_clusters=50)
        if features_df is not None and not features_df.empty:
            cluster_df = cluster_eng.fit(features_df, graph_risks)
            print(f"  ✓ {len(cluster_df):,} accounts clustered")
        else:
            print("  ⚠ No features for clustering — skipped")
    except Exception as e:
        print(f"  ⚠ Clustering error: {e}")

    # ══════════════════════════════════════════════════════════════
    # LAYER 4 — RULE ENGINE
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  LAYER 4: Rule Engine (Deterministic Policy Rules)")
    print(f"{'─' * 70}")

    from app.detection.rule_engine import RuleEngine
    engine = RuleEngine()
    print(f"  Loaded {len(engine.rules)} rules")
    violations = engine.evaluate_all()
    engine.close()
    print(f"  ✓ {len(violations):,} rule violations found")

    # ══════════════════════════════════════════════════════════════
    # LAYER 5 — ADAPTIVE FUSION
    # ══════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print(f"  LAYER 5: Adaptive Fusion (Target: ~{TARGET_ALERT_VOLUME:,} alerts)")
    print(f"{'─' * 70}")

    from app.detection.fusion import FusionEngine
    fusion = FusionEngine()
    alerts = fusion.fuse(
        rule_violations=violations,
        ml_risks=ml_risks if not ml_risks.empty else pd.DataFrame(),
        graph_risks=graph_risks or {},
        cluster_info=cluster_df[['account_id', 'cluster_id', 'cluster_risk', 'cluster_size', 'network_flag']]
            if not cluster_df.empty and 'cluster_id' in cluster_df.columns else None,
        target_alerts=TARGET_ALERT_VOLUME,
    )
    fusion.save_alerts_to_db(alerts)

    # ══════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════
    elapsed = time.time() - start

    print(f"\n\n{'=' * 70}")
    print("  📊 PIPELINE RESULTS")
    print(f"{'=' * 70}")
    print(f"  Transactions scanned:  {txn_count:,}")
    print(f"  ML accounts scored:    {len(ml_risks):,}")
    print(f"  Graph accounts scored: {len(graph_risks):,}")
    print(f"  Rule violations:       {len(violations):,}")
    print(f"  Total alerts:          {len(alerts):,}")
    print(f"  Total time:            {elapsed:.1f}s")

    # Severity breakdown
    if alerts:
        sev = {}
        for a in alerts:
            sev[a['severity']] = sev.get(a['severity'], 0) + 1
        print(f"\n  Severity Breakdown:")
        for s in ['critical', 'high', 'medium', 'low']:
            if s in sev:
                print(f"    {s}: {sev[s]:,}")

        # Source analysis
        rule_triggered = sum(1 for a in alerts if a['rule_score'] > 0)
        ml_triggered = sum(1 for a in alerts if a['ml_score'] > 0.3)
        graph_triggered = sum(1 for a in alerts if a['graph_score'] > 0.3)
        cluster_flagged = sum(1 for a in alerts if a.get('network_flag'))

        print(f"\n  Alert Sources:")
        print(f"    Rule signal:     {rule_triggered:,}")
        print(f"    ML signal:       {ml_triggered:,}")
        print(f"    Graph signal:    {graph_triggered:,}")
        print(f"    Network-flagged: {cluster_flagged:,}")

        # Top 10 alerts
        print(f"\n  Top 10 Alerts:")
        print(f"  {'Account':<22} {'Fusion':<8} {'Rule':<8} {'ML':<8} {'Graph':<8} {'Severity':<10} {'Cluster'}")
        print(f"  {'─'*22} {'─'*8} {'─'*8} {'─'*8} {'─'*8} {'─'*10} {'─'*10}")
        for a in alerts[:10]:
            c = f"C{a.get('cluster_id', '?')}"
            print(f"  {a['account_id']:<22} {a['fusion_score']:<8.4f} {a['rule_score']:<8.4f} "
                  f"{a['ml_score']:<8.4f} {a['graph_score']:<8.4f} {a['severity']:<10} {c}")

    print(f"\n  ✓ View alerts at http://localhost:5000/alerts")
    print(f"{'=' * 70}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
