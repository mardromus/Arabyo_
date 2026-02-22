import sys, os
sys.path.insert(0, os.path.dirname(__file__))
try:
    from dotenv import load_dotenv
    load_dotenv()
except: pass
from app.db import get_connection, release_connection

conn = get_connection()
try:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM alerts")
    print(f"TOTAL ALERTS: {cur.fetchone()['cnt']}")

    cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity ORDER BY cnt DESC")
    for r in cur.fetchall():
        print(f"  {r['severity']}: {r['cnt']}")

    cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE fusion_score > 0.7")
    print(f"\nCRITICAL+HIGH (fusion > 0.7): {cur.fetchone()['cnt']}")

    cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE fusion_score > 0.55")
    print(f"MEDIUM+ (fusion > 0.55): {cur.fetchone()['cnt']}")

    cur.execute("SELECT account_id, fusion_score, rule_score, ml_score, graph_score, severity FROM alerts ORDER BY fusion_score DESC LIMIT 10")
    print(f"\nTOP 10 ALERTS:")
    for r in cur.fetchall():
        print(f"  {r['account_id']:<25} fusion={r['fusion_score']:.4f}  rule={r['rule_score']:.4f}  ml={r['ml_score']:.4f}  graph={r['graph_score']:.4f}  {r['severity']}")
finally:
    release_connection(conn)
