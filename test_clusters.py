"""Test alert clustering + resolution end-to-end."""
import sys, os, json, traceback
sys.path.insert(0, os.path.dirname(__file__))
try:
    from dotenv import load_dotenv
    load_dotenv()
except: pass

from app.detection.alert_cluster_engine import (
    AlertClusterEngine, ClusterResolution,
    list_clusters, get_cluster_detail, get_cluster_metrics,
    get_resolution_history, ensure_cluster_schema
)

try:
    print("=" * 70)
    print("  ALERT CLUSTER RESOLUTION - END-TO-END TEST")
    print("=" * 70)

    # Step 1: Run clustering
    print("\n[1] Running alert clustering...")
    engine = AlertClusterEngine()
    result = engine.run()
    print(f"  Clusters: {result['cluster_count']}")
    print(f"  Alerts clustered: {result['alert_count']}")
    print(f"  Noise alerts: {result['noise_count']}")

    # Step 2: List clusters
    print("\n[2] Top 10 clusters by priority:")
    clusters = list_clusters(limit=10)
    for c in clusters:
        expl = c.get('explanation', {})
        reasons = expl.get('cluster_reason', []) if isinstance(expl, dict) else []
        reason_str = reasons[0] if reasons else ''
        print(f"  {c['cluster_id']} | size={c['cluster_size']:>4} | "
              f"risk={c['mean_risk']:.4f} | priority={c['priority_score']:.4f} | "
              f"{c['dominant_severity']:>8} | {reason_str[:50]}")

    # Step 3: Get detail of top cluster
    if clusters:
        top_cid = clusters[0]['cluster_id']
        print(f"\n[3] Cluster detail: {top_cid}")
        detail = get_cluster_detail(top_cid)
        expl = detail.get('explanation', {})
        if isinstance(expl, dict):
            print(f"  Reasons: {expl.get('cluster_reason', [])}")
            print(f"  Rule distribution: {expl.get('rule_distribution', {})}")
            print(f"  Top accounts: {expl.get('top_accounts', [])[:3]}")
        print(f"  Members: {len(detail.get('members', []))}")
        for m in detail.get('members', [])[:3]:
            print(f"    Alert {m['alert_id']} | {m['account_id']} | "
                  f"fusion={m['fusion_score']:.4f} | {m['severity']} | "
                  f"conf={m['confidence']:.3f}")

    # Step 4: Test bulk resolution
    if len(clusters) >= 2:
        resolve_cid = clusters[-1]['cluster_id']  # Lowest priority cluster
        print(f"\n[4] Resolving cluster {resolve_cid} (dismiss)...")
        r = ClusterResolution.resolve_cluster(
            resolve_cid, 'dismiss',
            performed_by='analyst@example.com',
            notes='Low-risk cluster, bulk dismissed for demo'
        )
        print(f"  Result: {r}")

    # Step 5: Test escalation
    if len(clusters) >= 3:
        escalate_cid = clusters[0]['cluster_id']  # Highest priority
        print(f"\n[5] Escalating cluster {escalate_cid}...")
        r = ClusterResolution.resolve_cluster(
            escalate_cid, 'escalate',
            performed_by='analyst@example.com',
            notes='High-risk cluster, needs senior review'
        )
        print(f"  Result: {r}")

    # Step 6: Metrics
    print(f"\n[6] Cluster metrics:")
    metrics = get_cluster_metrics()
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # Step 7: Resolution history
    print(f"\n[7] Resolution history:")
    history = get_resolution_history(limit=5)
    for h in history:
        print(f"  {h['performed_at']} | {h['cluster_id']} | {h['action']} | "
              f"by {h['performed_by']} | affected {h['alerts_affected']}")

    print(f"\n{'=' * 70}")
    print("  ALL TESTS PASSED!")
    print(f"{'=' * 70}")

except Exception:
    traceback.print_exc()
    sys.exit(1)
