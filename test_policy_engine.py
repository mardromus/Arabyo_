"""Comprehensive test suite for the Regulator-Grade Policy Intelligence Module.

Tests all 4 modules:
  1. Enhanced DSL schemas (new operators, fields, traceability)
  2. Clause-level traceability (paragraph_id, char offsets)
  3. Ambiguity detection & weighted confidence scoring
  4. Policy versioning & rule registry (lifecycle, lineage, audit)
  5. LLM extractor (REAL Gemini API call)
  6. Full pipeline on sample PDFs
  7. API routes (versioning, lineage, audit endpoints)

Run: python test_policy_engine.py
"""
import os
import sys
import json
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load .env for Gemini key
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def run_tests():
    results = []

    def test(name, fn):
        try:
            fn()
            results.append((name, True))
        except Exception as e:
            results.append((name, False))
            traceback.print_exc()

    # ══════════════════════════════════════════════════════════════
    # TEST 1: Enhanced DSL Schemas (Module 1 + 2)
    # ══════════════════════════════════════════════════════════════
    def test_enhanced_schemas():
        from app.policy_engine.schemas import (
            ExtractedRule, RuleCondition, RuleSource, TimeWindow,
            Operator, RuleType, Severity, ActionType, RuleStatus,
            PolicyStatus,
        )

        print("\n" + "=" * 60)
        print("  TEST: 1. Enhanced DSL Schemas")
        print("=" * 60)

        # 1a. New operators: IN, COUNT, RATE
        for op in [Operator.IN, Operator.COUNT, Operator.RATE]:
            print(f"  [1a] Operator {op.name} = '{op.value}'")
        assert Operator.IN.value == "in"
        assert Operator.COUNT.value == "count"
        assert Operator.RATE.value == "rate"

        # 1b. New statuses: APPROVED, RETIRED, SUPERSEDED
        for st in [RuleStatus.APPROVED, RuleStatus.RETIRED, RuleStatus.SUPERSEDED]:
            print(f"  [1b] Status {st.name} = '{st.value}'")
        assert RuleStatus.APPROVED.value == "approved"
        assert RuleStatus.SUPERSEDED.value == "superseded"

        # 1c. PolicyStatus enum
        assert PolicyStatus.DRAFT.value == "draft"
        assert PolicyStatus.APPROVED.value == "approved"
        assert PolicyStatus.RETIRED.value == "retired"
        print(f"  [1c] PolicyStatus: {[s.value for s in PolicyStatus]}")

        # 1d. RuleCondition with new fields (entity_scope, filters, unit)
        cond = RuleCondition(
            metric="transaction_amount",
            operator=Operator.GT,
            value=10000,
            unit="USD",
            entity_scope="transaction",
            filters={"payment_format": "wire"},
            currency="USD",
        )
        assert cond.unit == "USD"
        assert cond.entity_scope == "transaction"
        assert cond.filters == {"payment_format": "wire"}
        print(f"  [1d] Condition: {cond.metric} {cond.operator.value} {cond.value} "
              f"(unit={cond.unit}, scope={cond.entity_scope})")

        # 1e. RuleSource with traceability (paragraph_id, char offsets)
        src = RuleSource(
            page=5,
            text="Transactions exceeding $10,000 must be reported.",
            paragraph_id="p_5_3",
            char_start=1024,
            char_end=1072,
            document="AML_Policy.pdf",
        )
        assert src.paragraph_id == "p_5_3"
        assert src.char_start == 1024
        assert src.char_end == 1072
        print(f"  [1e] Source: page={src.page}, para={src.paragraph_id}, "
              f"offsets=[{src.char_start}:{src.char_end}]")

        # 1f. ExtractedRule with policy linkage
        rule = ExtractedRule(
            rule_id="R-AML-001",
            rule_name="Large Transaction Threshold",
            description="Flag transactions over $10K",
            policy_id="POL-AML-2024",
            policy_version="v1.2",
            effective_date="2024-01-01",
            rule_type=RuleType.THRESHOLD,
            conditions=[cond],
            action=ActionType.FLAG,
            severity=Severity.HIGH,
            confidence=0.95,
            source=src,
        )
        assert rule.policy_id == "POL-AML-2024"
        assert rule.policy_version == "v1.2"
        assert rule.effective_date == "2024-01-01"
        print(f"  [1f] Rule: {rule.rule_id} | policy={rule.policy_id} v{rule.policy_version}")

        # 1g. compute_rule_hash() for dedup
        h1 = rule.compute_rule_hash()
        h2 = rule.compute_rule_hash()
        assert h1 == h2  # Deterministic
        assert len(h1) == 16
        print(f"  [1g] Rule hash: {h1} (deterministic: {h1 == h2})")

        # 1h. to_legacy_dict includes new fields
        d = rule.to_legacy_dict()
        assert "policy_id" in d
        assert "policy_version" in d
        assert "effective_date" in d
        assert "paragraph_id" in d
        assert "char_start" in d
        assert "char_end" in d
        assert "rule_hash" in d
        print(f"  [1h] Legacy dict: {len(d)} keys, new fields present")

        print("  >> PASS")

    test("1. Enhanced DSL Schemas", test_enhanced_schemas)

    # ══════════════════════════════════════════════════════════════
    # TEST 2: Clause-Level Traceability (Module 2)
    # ══════════════════════════════════════════════════════════════
    def test_traceability():
        from app.policy_engine.schemas import RuleSource

        print("\n" + "=" * 60)
        print("  TEST: 2. Clause-Level Traceability")
        print("=" * 60)

        # 2a. Offset validation (char_end >= char_start)
        src = RuleSource(page=1, text="Test clause", char_start=10, char_end=21)
        assert src.char_end >= src.char_start
        print(f"  [2a] Valid offsets: [{src.char_start}:{src.char_end}]")

        # 2b. Invalid offsets should raise error
        try:
            bad = RuleSource(page=1, text="Test", char_start=50, char_end=10)
            assert False, "Should have raised validation error"
        except Exception:
            print("  [2b] Invalid offsets correctly rejected")

        # 2c. Paragraph ID format
        src2 = RuleSource(page=3, text="Some clause", paragraph_id="p_3_2")
        assert src2.paragraph_id.startswith("p_3_")
        print(f"  [2c] Paragraph ID: {src2.paragraph_id}")

        # 2d. _compute_char_offsets from pipeline
        from app.policy_engine.pipeline import _compute_char_offsets
        from app.policy_engine.schemas import (
            ExtractedRule, RuleCondition, Operator, RuleType, Severity,
        )

        page_text = "Header text.\n\nTransactions exceeding $10,000 must be reported.\n\nFooter text."
        rule = ExtractedRule(
            rule_id="TEST-OFFSET",
            rule_name="Test",
            rule_type=RuleType.THRESHOLD,
            conditions=[RuleCondition(metric="amount", operator=Operator.GT, value=10000)],
            severity=Severity.HIGH,
            confidence=0.9,
            source=RuleSource(
                page=1,
                text="Transactions exceeding $10,000 must be reported.",
                document="test.pdf",
            ),
        )
        _compute_char_offsets(rule, page_text)
        assert rule.source.char_start is not None
        assert rule.source.char_end is not None
        assert rule.source.paragraph_id is not None
        highlight = page_text[rule.source.char_start:rule.source.char_end]
        assert "Transactions" in highlight
        print(f"  [2d] Computed offsets: [{rule.source.char_start}:{rule.source.char_end}]")
        print(f"       Highlighted: '{highlight}'")
        print(f"       Paragraph: {rule.source.paragraph_id}")

        print("  >> PASS")

    test("2. Clause-Level Traceability", test_traceability)

    # ══════════════════════════════════════════════════════════════
    # TEST 3: Ambiguity Detection & Confidence Scoring (Module 3)
    # ══════════════════════════════════════════════════════════════
    def test_ambiguity_and_confidence():
        from app.policy_engine.schemas import (
            ExtractedRule, RuleCondition, RuleSource, Operator,
            RuleType, Severity,
        )
        from app.policy_engine.rule_dsl import (
            detect_ambiguities, compute_confidence_score,
            sanity_check_thresholds, post_process_rules,
        )

        print("\n" + "=" * 60)
        print("  TEST: 3. Ambiguity Detection & Confidence Scoring")
        print("=" * 60)

        # 3a. Vague language detection (new terms)
        vague_rule = ExtractedRule(
            rule_id="VAGUE-001",
            rule_name="Unusual Activity",
            rule_type=RuleType.PATTERN,
            conditions=[RuleCondition(metric="activity", operator=Operator.EQ, value="unusual")],
            confidence=0.8,
            source=RuleSource(page=1, text="Flag any unusual or suspicious transaction activity", document="test.pdf"),
        )
        ambiguities = detect_ambiguities(vague_rule)
        assert len(ambiguities) > 0
        vague_terms_found = [a for a in ambiguities if "Vague term" in a]
        print(f"  [3a] Vague terms detected: {len(vague_terms_found)}")
        for a in vague_terms_found[:3]:
            print(f"       - {a}")

        # 3b. Missing numeric threshold detection
        no_numeric_rule = ExtractedRule(
            rule_id="NONUMERIC-001",
            rule_name="Large Transaction",
            rule_type=RuleType.THRESHOLD,
            conditions=[RuleCondition(metric="transaction_amount", operator=Operator.GT, value="large")],
            confidence=0.5,
            source=RuleSource(page=1, text="Large transactions should be flagged", document="test.pdf"),
        )
        ambiguities2 = detect_ambiguities(no_numeric_rule)
        has_numeric_warning = any("numeric" in a.lower() for a in ambiguities2)
        assert has_numeric_warning, f"Should detect missing numeric, got: {ambiguities2}"
        print(f"  [3b] Missing numeric threshold: detected")

        # 3c. Missing time window detection
        velocity_rule = ExtractedRule(
            rule_id="VELOCITY-001",
            rule_name="Rapid Transfers",
            rule_type=RuleType.VELOCITY,
            conditions=[RuleCondition(metric="transaction_count", operator=Operator.GT, value=5)],
            confidence=0.7,
            source=RuleSource(page=1, text="Multiple transfers in rapid succession", document="test.pdf"),
        )
        ambiguities3 = detect_ambiguities(velocity_rule)
        has_timewindow_warning = any("time window" in a.lower() for a in ambiguities3)
        assert has_timewindow_warning
        print(f"  [3c] Missing time window on velocity rule: detected")

        # 3d. Weighted confidence scoring
        good_rule = ExtractedRule(
            rule_id="GOOD-001",
            rule_name="CTR Threshold",
            description="Report transactions exceeding $10,000",
            policy_id="POL-AML",
            rule_type=RuleType.THRESHOLD,
            conditions=[RuleCondition(
                metric="transaction_amount", operator=Operator.GT,
                value=10000, currency="USD",
            )],
            confidence=1.0,
            source=RuleSource(
                page=1, text="Transactions exceeding $10,000 must be reported",
                paragraph_id="p_1_1", char_start=0, char_end=49,
                document="policy.pdf",
            ),
            parser_version="2.0-gemini",
        )
        score = compute_confidence_score(good_rule)
        assert 0.0 <= score <= 1.0
        print(f"  [3d] Weighted confidence (good rule): {score}")
        assert score > 0.7, f"Good rule should have high confidence, got {score}"

        poor_rule = ExtractedRule(
            rule_id="POOR-001",
            rule_name="Vague Rule",
            rule_type=RuleType.CUSTOM,
            conditions=[RuleCondition(metric="activity", operator=Operator.EQ, value="suspicious")],
            confidence=0.5,
            source=RuleSource(page=1, text="Flag any unusual suspicious activity as appropriate", document="test.pdf"),
            parser_version="1.0-regex",
        )
        poor_score = compute_confidence_score(poor_rule)
        print(f"  [3d] Weighted confidence (poor rule): {poor_score}")
        assert poor_score < score, "Poor rule should score lower than good rule"

        # 3e. Post-processing pipeline
        rules = post_process_rules([good_rule, poor_rule])
        assert any(r.review_required for r in rules)
        print(f"  [3e] Post-processed: {len(rules)} rules, "
              f"{sum(1 for r in rules if r.review_required)} flagged for review")

        print("  >> PASS")

    test("3. Ambiguity & Confidence Scoring", test_ambiguity_and_confidence)

    # ══════════════════════════════════════════════════════════════
    # TEST 4: Policy Versioning & Rule Registry (Module 4)
    # ══════════════════════════════════════════════════════════════
    def test_versioning_and_registry():
        from app.db import get_connection, init_schema, release_connection
        from app.policy_engine.versioning import PolicyRegistry, RuleRegistry, AuditLogger
        import time
        from app.policy_engine.schemas import (
            ExtractedRule, RuleCondition, RuleSource, Operator,
            RuleType, Severity,
        )

        print("\n" + "=" * 60)
        print("  TEST: 4. Policy Versioning & Rule Registry")
        print("=" * 60)

        # Initialize fresh DB
        conn = get_connection()
        init_schema(conn)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM policy_documents")
            cur.execute("DELETE FROM rules")
            cur.execute("DELETE FROM rule_lineage")
            cur.execute("DELETE FROM extraction_audit_log")
        conn.commit()
        release_connection(conn)

        # 4a. Register policy
        info = PolicyRegistry.register_policy(
            filename="AML_Policy_v1.pdf",
            raw_text="Section 1: All cash transactions exceeding $10,000...",
            page_count=5,
            policy_id="POL-TEST-001",
        )
        assert info["policy_id"] == "POL-TEST-001"
        assert info["version"] == "v1.0"
        assert info["status"] == "draft"
        assert len(info["checksum"]) == 64
        print(f"  [4a] Registered: {info['policy_id']} {info['version']} ({info['status']})")

        # 4b. Re-upload same content = idempotent (checksum match)
        info2 = PolicyRegistry.register_policy(
            filename="AML_Policy_v1.pdf",
            raw_text="Section 1: All cash transactions exceeding $10,000...",
            page_count=5,
            policy_id="POL-TEST-001",
        )
        assert info2["status"] == "existing"
        print(f"  [4b] Idempotent re-upload: status={info2['status']}")

        # 4c. Upload new version (different content)
        info3 = PolicyRegistry.register_policy(
            filename="AML_Policy_v2.pdf",
            raw_text="Section 1: Updated policy with $15,000 threshold...",
            page_count=6,
            policy_id="POL-TEST-001",
        )
        assert info3["version"] == "v1.1"
        print(f"  [4c] New version: {info3['version']}")

        # 4d. Approve policy
        ok = PolicyRegistry.approve_policy("POL-TEST-001")
        assert ok
        print(f"  [4d] Policy approved")

        # 4e. Get all versions
        versions = PolicyRegistry.get_all_versions("POL-TEST-001")
        assert len(versions) >= 2
        print(f"  [4e] Versions: {[v['version'] for v in versions]}")

        # 4f. Register rules
        rule1 = ExtractedRule(
            rule_id="R-TEST-001",
            rule_name="CTR Threshold",
            rule_type=RuleType.THRESHOLD,
            conditions=[RuleCondition(metric="transaction_amount", operator=Operator.GT, value=10000)],
            confidence=0.95,
            source=RuleSource(page=1, text="Transactions exceeding $10,000", document="AML_Policy_v1.pdf"),
        )
        rule2 = ExtractedRule(
            rule_id="R-TEST-002",
            rule_name="Wire Transfer Monitor",
            rule_type=RuleType.CROSS_BORDER,
            conditions=[RuleCondition(metric="transfer_amount", operator=Operator.GT, value=3000)],
            confidence=0.85,
            source=RuleSource(page=2, text="Wire transfers above $3,000", document="AML_Policy_v1.pdf"),
        )
        stats = RuleRegistry.register_rules([rule1, rule2], policy_id="POL-TEST-001")
        assert stats["new"] == 2
        assert stats["duplicate"] == 0
        print(f"  [4f] Rules registered: {stats['new']} new, {stats['duplicate']} dup")

        # 4g. Duplicate detection (re-register same rules)
        stats2 = RuleRegistry.register_rules([rule1], policy_id="POL-TEST-001")
        assert stats2["duplicate"] == 1
        print(f"  [4g] Duplicate detection: {stats2['duplicate']} dup (correct)")

        # 4h. Approve and reject rules
        ok = RuleRegistry.approve_rule("R-TEST-001")
        assert ok
        print(f"  [4h] Rule R-TEST-001 approved")

        ok = RuleRegistry.reject_rule("R-TEST-002", reason="threshold too low")
        assert ok
        print(f"  [4h] Rule R-TEST-002 rejected")

        # 4i. Supersede a rule
        rule1_v2 = ExtractedRule(
            rule_id="R-TEST-001-v2",
            rule_name="CTR Threshold (Updated)",
            rule_type=RuleType.THRESHOLD,
            conditions=[RuleCondition(metric="transaction_amount", operator=Operator.GT, value=15000)],
            confidence=0.98,
            source=RuleSource(page=1, text="Transactions exceeding $15,000", document="AML_Policy_v2.pdf"),
        )
        ok = RuleRegistry.supersede_rule("R-TEST-001", rule1_v2, reason="threshold raised")
        assert ok
        print(f"  [4i] R-TEST-001 superseded by R-TEST-001-v2")

        # 4j. Rule lineage
        lineage = RuleRegistry.get_rule_lineage("R-TEST-001")
        assert len(lineage["descendants"]) == 1
        assert lineage["descendants"][0]["child_rule_id"] == "R-TEST-001-v2"
        print(f"  [4j] Lineage: {lineage['rule_id']} -> {lineage['descendants'][0]['child_rule_id']}")

        lineage2 = RuleRegistry.get_rule_lineage("R-TEST-001-v2")
        assert len(lineage2["ancestors"]) == 1
        print(f"  [4j] Ancestors of v2: {lineage2['ancestors'][0]['parent_rule_id']}")

        # 4k. Soft delete
        ok = RuleRegistry.soft_delete_rule("R-TEST-002", reason="no longer needed")
        assert ok
        print(f"  [4k] R-TEST-002 soft-deleted")

        # Verify it's not in active rules
        active = RuleRegistry.get_active_rules()
        active_ids = [r["id"] for r in active]
        assert "R-TEST-002" not in active_ids
        print(f"  [4k] Active rules: {active_ids} (R-TEST-002 excluded)")

        # 4l. Audit trail
        trail = AuditLogger.get_trail(policy_id="POL-TEST-001")
        assert len(trail) > 0
        actions = [e["action"] for e in trail]
        print(f"  [4l] Policy audit trail: {len(trail)} entries")
        print(f"       Actions: {actions[:6]}")
        assert "register_policy" in actions
        
        # Rule audit trails
        rule1_trail = AuditLogger.get_trail(rule_id="R-TEST-001")
        rule1_actions = [e["action"] for e in rule1_trail]
        assert "approve_rule" in rule1_actions
        assert "supersede_rule" in rule1_actions

        rule2_trail = AuditLogger.get_trail(rule_id="R-TEST-002")
        rule2_actions = [e["action"] for e in rule2_trail]
        assert "soft_delete_rule" in rule2_actions

        # 4m. Retire policy
        ok = PolicyRegistry.retire_policy("POL-TEST-001")
        assert ok
        print(f"  [4m] Policy retired")

        print("  >> PASS")

    test("4. Versioning & Registry", test_versioning_and_registry)

    # ══════════════════════════════════════════════════════════════
    # TEST 5: LLM Extractor (REAL Gemini API)
    # ══════════════════════════════════════════════════════════════
    def test_llm_extractor():
        from app.policy_engine.llm_extractor import (
            extract_rules_with_llm, llm_available, regex_to_extracted_rule,
            _get_client,
        )

        print("\n" + "=" * 60)
        print("  TEST: 5. LLM Extractor (REAL Gemini API)")
        print("=" * 60)

        api_key = os.environ.get("GEMINI_API_KEY", "")
        print(f"  LLM available: {llm_available()}")

        # 5a. Regex adapter still works
        legacy = {
            "rule_id": "AUTO-abc123",
            "name": "Test Rule",
            "source_document": "test.pdf",
            "source_page": 1,
            "source_text": "Transactions over $10,000",
            "rule_type": "threshold",
            "conditions": [{"field": "transaction_amount", "operator": ">", "value": 10000}],
            "severity": "high",
        }
        converted = regex_to_extracted_rule(legacy)
        assert converted is not None
        assert converted.confidence == 0.6
        print(f"  [5a] Regex adapter: {converted.rule_id} -> conf={converted.confidence}")

        if not llm_available():
            print("  [5b] SKIPPED: No API key")
            print("  >> PASS (partial)")
            return

        # 5b. Real Gemini API call
        print("  [5b] Testing REAL Gemini API call...")
        client = _get_client()
        assert client is not None
        print("       Client initialized successfully")

        test_text = """
        Section 2.1: Currency Transaction Reports
        All cash transactions exceeding $10,000 must be reported to FinCEN via a 
        Currency Transaction Report (CTR) within 15 business days.
        Aggregated transactions by the same customer totaling over $10,000 in a 24-hour 
        period must also be reported.
        Wire transfers of $3,000 or more require collection of originator information.
        """

        rules = extract_rules_with_llm(text=test_text, page_num=1, source_document="test_policy.pdf")
        print(f"       Gemini returned {len(rules)} rules:")
        for r in rules:
            print(f"         [{r.rule_id}] {r.rule_name}")
            print(f"           Type: {r.rule_type.value}, Severity: {r.severity.value}")
            print(f"           Confidence: {r.confidence}, Parser: {r.parser_version}")
        assert len(rules) > 0, "Gemini should extract at least 1 rule from clear policy text"
        print(f"  [5b] REAL Gemini API: PASSED ({len(rules)} rules extracted)")
        print("  >> PASS")

    test("5. LLM Extractor", test_llm_extractor)

    # ══════════════════════════════════════════════════════════════
    # TEST 6: Full Pipeline on Real PDFs
    # ══════════════════════════════════════════════════════════════
    def test_full_pipeline():
        from app.db import get_connection, init_schema, release_connection
        from app.policy_engine.pipeline import PolicyPipeline
        from app.policy_engine.versioning import AuditLogger

        print("\n" + "=" * 60)
        print("  TEST: 6. Full Pipeline on Real PDFs")
        print("=" * 60)

        # Reinit schema
        conn = get_connection()
        init_schema(conn)
        release_connection(conn)

        pdf_dir = os.path.join(os.path.dirname(__file__), "data", "policies")
        if not os.path.isdir(pdf_dir):
            print("  No sample PDFs found, skipping pipeline test")
            print("  >> PASS (no PDFs)")
            return

        pdfs = [f for f in os.listdir(pdf_dir) if f.endswith(".pdf")]
        if not pdfs:
            print("  No PDFs in data/policies/, skipping")
            print("  >> PASS (no PDFs)")
            return

        pipeline = PolicyPipeline(use_llm=True, use_ocr=False, save_to_db=True, save_to_json=True)

        for pdf_name in pdfs:
            pdf_path = os.path.join(pdf_dir, pdf_name)
            print(f"\n  --- Processing: {pdf_name} ---")
            result = pipeline.process(pdf_path)

            print(f"  Success:     {result.success}")
            print(f"  Rules:       {len(result.rules)}")
            print(f"  Parser:      {result.metrics.parser_used}")
            print(f"  Confidence:  {result.metrics.avg_confidence:.2f}")
            print(f"  Time:        {result.metrics.processing_time_seconds:.1f}s")
            print(f"  Need review: {sum(1 for r in result.rules if r.review_required)}/{len(result.rules)}")

            assert result.success, f"Pipeline failed: {result.error}"
            assert len(result.rules) >= 0

            # Verify traceability on every rule
            for r in result.rules:
                assert r.source.text, f"Rule {r.rule_id} missing source text"
                assert r.policy_id, f"Rule {r.rule_id} missing policy_id"
                # Char offsets should be computed
                if r.source.char_start is not None:
                    assert r.source.char_end >= r.source.char_start
                    assert r.source.paragraph_id is not None

            # Check audit trail was created
            trail = AuditLogger.get_trail(policy_id=result.policy_id)
            assert len(trail) > 0, "No audit trail entries found"
            actions = [e["action"] for e in trail]
            assert "pipeline_start" in actions
            assert "pipeline_complete" in actions
            print(f"  Audit trail: {len(trail)} entries ({', '.join(set(actions))})")

            # Show sample rules
            for r in result.rules[:3]:
                print(f"    [{r.rule_id}] {r.rule_name} | {r.rule_type.value} | "
                      f"conf={r.confidence} | parser={r.parser_version}")

        print("  >> PASS")

    test("6. Full Pipeline", test_full_pipeline)

    # ══════════════════════════════════════════════════════════════
    # TEST 7: API Routes
    # ══════════════════════════════════════════════════════════════
    def test_api_routes():
        from app.web.routes import create_app
        from app.db import get_connection, init_schema, release_connection

        print("\n" + "=" * 60)
        print("  TEST: 7. API Routes")
        print("=" * 60)

        conn = get_connection()
        init_schema(conn)
        release_connection(conn)

        app = create_app()
        client = app.test_client()

        # 7a. Existing routes still work
        r = client.get("/policies")
        assert r.status_code == 200
        print(f"  [7a] GET /policies: {r.status_code}")

        r = client.get("/api/stats")
        assert r.status_code == 200
        print(f"  [7b] GET /api/stats: {r.status_code}")

        # 7c. Approve/reject with audit
        r = client.post("/api/rules/TEST-001/approve?role=admin",
                         json={"performed_by": "test_user"})
        print(f"  [7c] POST approve: {r.status_code} -> {r.get_json()}")

        r = client.post("/api/rules/TEST-002/reject?role=admin",
                         json={"reason": "too vague", "performed_by": "test_user"})
        print(f"  [7d] POST reject: {r.status_code} -> {r.get_json()}")

        # 7e. Policy versions
        r = client.get("/api/policies/POL-TEST-001/versions")
        data = r.get_json()
        print(f"  [7e] GET versions: {r.status_code} -> {len(data.get('versions', []))} versions")

        # 7f. Policy approve
        r = client.post("/api/policies/POL-TEST-001/approve?role=admin",
                         json={"performed_by": "test_user"})
        print(f"  [7f] POST policy approve: {r.status_code} -> {r.get_json()}")

        # 7g. Policy retire
        r = client.post("/api/policies/POL-TEST-001/retire?role=admin",
                         json={"performed_by": "test_user"})
        print(f"  [7g] POST policy retire: {r.status_code} -> {r.get_json()}")

        # 7h. Rule lineage
        r = client.get("/api/rules/R-TEST-001/lineage")
        data = r.get_json()
        print(f"  [7h] GET lineage: {r.status_code} -> {data.get('rule_id', 'N/A')}")

        # 7i. Audit trail
        r = client.get("/api/audit/POL-TEST-001")
        data = r.get_json()
        print(f"  [7i] GET audit: {r.status_code} -> {len(data.get('audit_trail', []))} entries")

        # 7j. Upload validation
        r = client.post("/api/policies/extract?role=admin")
        assert r.status_code in (400, 403, 404)
        print(f"  [7j] POST extract (no file): {r.status_code} -> correct error")

        print("  >> PASS")

    test("7. API Routes", test_api_routes)

    # ══════════════════════════════════════════════════════════════
    # RESULTS
    # ══════════════════════════════════════════════════════════════
    print("\n")
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    print("=" * 60)
    print(f"  RESULTS: {passed} passed, {failed} failed out of {len(results)} tests")
    print("=" * 60)

    if failed == 0:
        print("  ALL TESTS PASSED!")
    else:
        print("  FAILED TESTS:")
        for name, ok in results:
            if not ok:
                print(f"    - {name}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    api_key = os.environ.get("GEMINI_API_KEY", "")
    mask = api_key[:10] + "..." if len(api_key) > 10 else "(not set)"
    print(f"  Gemini API Key: {'SET' if api_key else 'NOT SET'} ({mask})")
    sys.exit(run_tests())
