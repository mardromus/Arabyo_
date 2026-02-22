"""Full compliance pipeline orchestrator — runs the entire detection pipeline end to end."""
import sys
import os
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.db import get_connection, init_schema, release_connection
from app.config import POLICIES_DIR


def run_pipeline(skip_setup=False, skip_ml=False, skip_graph=False, limit=None):
    """Execute the full compliance pipeline."""
    start = time.time()
    
    print("=" * 60)
    print("  Arabyo -- Full Pipeline Run")
    print("=" * 60)
    
    # -------------------------------------------------------------------
    # 1. Database setup (if needed)
    
    # -------------------------------------------------------------------
    conn = get_connection()
    init_schema(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM transactions")
        row = cur.fetchone()
    txn_count = row['cnt'] if row else 0
    release_connection(conn)

    if txn_count == 0 and not skip_setup:
        print("\n[1/6] Loading dataset into database...")
        from app.data_layer.loader import setup_database
        setup_database(limit=limit, truncate_first=True)
    else:
        print(f"\n[1/6] Database ready ({txn_count:,} transactions)")

    # -------------------------------------------------------------------
    # 2. Policy ingestion (via PolicyPipeline for versioning + rule sets)
    # -------------------------------------------------------------------
    print("\n[2/6] Ingesting policies...")
    from app.policy_engine.pipeline import PolicyPipeline
    
    if os.path.exists(POLICIES_DIR):
        pipeline = PolicyPipeline(use_llm=True, use_ocr=True, save_to_db=True, save_to_json=True)
        pdfs = [os.path.join(POLICIES_DIR, f) for f in os.listdir(POLICIES_DIR) if f.endswith('.pdf')]
        if pdfs:
            all_rules = []
            from app.policy_engine.rule_set_manager import RuleSetManager
            
            for result in pipeline.process_batch(pdfs):
                if result.success:
                    print(f"  {result.filename}: {len(result.rules)} rules")
                    all_rules.extend(result.rules)
                    
                    # Wire into RuleEngine via RuleSetManager
                    rule_ids = [r.rule_id for r in result.rules]
                    if rule_ids:
                        ruleset_id = RuleSetManager.create_ruleset(
                            policy_id=result.policy_id,
                            policy_version="v1.0",
                            rule_ids=rule_ids,
                            description=f"Initial pipeline ruleset for {result.filename}",
                            created_by="pipeline",
                        )
                        RuleSetManager.activate_ruleset(ruleset_id)
                        print(f"  Activated ruleset {ruleset_id}")
                else:
                    print(f"  {result.filename}: failed - {result.error}")
        else:
            print("  No policy PDFs found. Run: python create_policies.py")
    else:
        print("  Policies dir not found")

    # -------------------------------------------------------------------
    # 3. Rule engine
    # -------------------------------------------------------------------
    print("\n[3/6] Running rule engine...")
    from app.detection.rule_engine import RuleEngine
    
    engine = RuleEngine()
    violations = engine.evaluate_all()
    engine.close()
    print(f"  Found {len(violations)} rule violations")

    # -------------------------------------------------------------------
    # 4. ML engine
    # -------------------------------------------------------------------
    ml_features = None
    if not skip_ml:
        print("\n[4/6] Training ML models...")
        try:
            from app.detection.ml_engine import MLEngine
            ml = MLEngine()
            ml_features = ml.train()
            print(f"  ML engine trained on {len(ml_features):,} accounts")
        except Exception as e:
            print(f"  ML engine error: {e}")
    else:
        print("\n[4/6] ML engine skipped")

    # -------------------------------------------------------------------
    # 5. Graph engine
    # -------------------------------------------------------------------
    graph_risks = {}
    if not skip_graph:
        print("\n[5/6] Running graph analysis...")
        try:
            from app.detection.graph_engine import GraphEngine
            graph = GraphEngine()
            graph.build_graph()
            graph_risks = graph.analyze()
            print(f"  Analyzed {len(graph_risks):,} nodes")
        except Exception as e:
            print(f"  Graph engine error: {e}")
    else:
        print("\n[5/6] Graph analysis skipped")

    # -------------------------------------------------------------------
    # 6. Risk fusion + alerts
    # -------------------------------------------------------------------
    print("\n[6/6] Fusing risk signals...")
    from app.detection.fusion import FusionEngine
    
    fusion = FusionEngine()
    alerts = fusion.fuse(violations, ml_features, graph_risks)
    fusion.save_alerts_to_db(alerts)

    elapsed = time.time() - start
    
    print()
    print("=" * 60)
    print(f"  Pipeline complete in {elapsed:.1f}s")
    print(f"  {len(violations)} violations -> {len(alerts)} alerts")
    print(f"  Start dashboard: python run.py")
    print("=" * 60)

    return {
        "alerts": alerts,
        "violations_count": len(violations),
        "alerts_count": len(alerts),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the compliance pipeline')
    parser.add_argument('--skip-setup', action='store_true', help='Skip DB setup')
    parser.add_argument('--skip-ml', action='store_true', help='Skip ML training')
    parser.add_argument('--skip-graph', action='store_true', help='Skip graph analysis')
    parser.add_argument('--limit', type=int, default=None, help='Limit rows loaded')
    
    args = parser.parse_args()
    run_pipeline(
        skip_setup=args.skip_setup,
        skip_ml=args.skip_ml,
        skip_graph=args.skip_graph,
        limit=args.limit,
    )
    