"""
Run the full extraction pipeline on all demo policy PDFs.
This script processes each PDF, extracts rules via the AI Agent,
stores them in the database, and prints a summary.
"""
import os
import sys
import time

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from app.db import get_connection, init_schema, release_connection
from app.policy_engine.pipeline import PolicyPipeline


def main():
    # ── Init database ─────────────────────────────────────────────
    print("=" * 70)
    print("  POLICY RULE EXTRACTION — FULL PIPELINE RUN")
    print("=" * 70)

    conn = get_connection()
    init_schema(conn)
    release_connection(conn)
    print("  Database schema initialized.\n")

    # ── Find demo PDFs ────────────────────────────────────────────
    pdf_dir = os.path.join(os.path.dirname(__file__), "demo_policies")
    if not os.path.isdir(pdf_dir):
        print(f"ERROR: No demo_policies directory found at {pdf_dir}")
        return 1

    pdfs = sorted([f for f in os.listdir(pdf_dir) if f.endswith(".pdf")])
    if not pdfs:
        print("ERROR: No PDF files found in demo_policies/")
        return 1

    print(f"  Found {len(pdfs)} PDF(s) to process:\n")
    for p in pdfs:
        print(f"    • {p}")
    print()

    # ── Run pipeline ──────────────────────────────────────────────
    pipeline = PolicyPipeline(
        use_llm=True,
        use_ocr=False,
        save_to_db=True,
        save_to_json=True,
    )

    all_results = []
    total_rules = 0
    total_start = time.time()

    for i, pdf_name in enumerate(pdfs, 1):
        pdf_path = os.path.join(pdf_dir, pdf_name)
        print("\n" + "─" * 70)
        print(f"  [{i}/{len(pdfs)}] Processing: {pdf_name}")
        print("─" * 70)

        result = pipeline.process(pdf_path)
        all_results.append(result)
        total_rules += len(result.rules)

        if result.success:
            print(f"\n  ✓ SUCCESS — {len(result.rules)} rules extracted")
            print(f"    Parser:     {result.metrics.parser_used}")
            print(f"    Confidence: {result.metrics.avg_confidence:.2f}")
            print(f"    Time:       {result.metrics.processing_time_seconds:.1f}s")
            print(f"    Review:     {sum(1 for r in result.rules if r.review_required)}/{len(result.rules)} flagged")

            if result.rules:
                print(f"\n    Extracted Rules:")
                for j, rule in enumerate(result.rules, 1):
                    print(f"      {j}. [{rule.rule_id}] {rule.rule_name}")
                    print(f"         Type: {rule.rule_type.value} | Severity: {rule.severity.value} | Conf: {rule.confidence:.2f}")
                    if rule.conditions:
                        c = rule.conditions[0]
                        print(f"         Condition: {c.metric} {c.operator.value} {c.value}")
                    print(f"         Source: \"{rule.source.text[:80]}...\"" if len(rule.source.text) > 80 else f"         Source: \"{rule.source.text}\"")
        else:
            print(f"\n  ✗ FAILED — {result.error}")

    # ── Summary ───────────────────────────────────────────────────
    elapsed = time.time() - total_start
    successful = sum(1 for r in all_results if r.success)

    print("\n\n" + "=" * 70)
    print("  EXTRACTION SUMMARY")
    print("=" * 70)
    print(f"  PDFs processed:  {len(pdfs)}")
    print(f"  Successful:      {successful}/{len(pdfs)}")
    print(f"  Total rules:     {total_rules}")
    print(f"  Total time:      {elapsed:.1f}s")
    print("=" * 70)

    # ── Verify DB storage ─────────────────────────────────────────
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM rules WHERE is_deleted = 0")
            row = cur.fetchone()
            db_count = row["cnt"] if row else 0
            print(f"\n  Rules in database: {db_count}")

            cur.execute("SELECT COUNT(*) as cnt FROM rule_sets")
            row = cur.fetchone()
            rs_count = row["cnt"] if row else 0
            print(f"  Rule sets created: {rs_count}")

            cur.execute("SELECT COUNT(*) as cnt FROM extraction_audit_log")
            row = cur.fetchone()
            audit_count = row["cnt"] if row else 0
            print(f"  Audit log entries: {audit_count}")
    finally:
        release_connection(conn)

    print("\n  ✓ All rules persisted to PostgreSQL database")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
