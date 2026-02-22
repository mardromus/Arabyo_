"""End-to-end policy extraction pipeline orchestrator.

Coordinates: PDF ingestion -> text cleaning -> OCR fallback -> LLM/regex
extraction -> validation -> post-processing -> versioned storage.

v3.0 -- Regulator-grade: integrates PolicyRegistry, RuleRegistry,
        AuditLogger for versioned, auditable, idempotent processing.
"""
import os
import time
import logging
import hashlib
from typing import Optional

from app.policy_engine.schemas import (
    ExtractedRule, ExtractionResult, ExtractionMetrics,
)
from app.policy_engine.pdf_ingester import extract_text_from_pdf, extract_sections
from app.policy_engine.text_cleaner import clean_document
from app.policy_engine.ocr_engine import is_page_scanned, ocr_pdf_page, ocr_available
from app.policy_engine.llm_extractor import (
    extract_rules_with_llm, regex_to_extracted_rule, llm_available,
)
from app.policy_engine.rule_parser import extract_rules_from_text
from app.policy_engine.rule_dsl import (
    post_process_rules, save_rules, save_rules_to_db,
)
from app.policy_engine.versioning import PolicyRegistry, RuleRegistry, AuditLogger
from app.db import get_connection, execute

logger = logging.getLogger(__name__)


class PolicyPipeline:
    """Production pipeline for policy document processing.
    
    Usage:
        pipeline = PolicyPipeline()
        result = pipeline.process("path/to/policy.pdf")
        print(result.metrics)
    """

    def __init__(self, use_llm: bool = True, use_ocr: bool = True,
                 save_to_db: bool = True, save_to_json: bool = True):
        """
        Args:
            use_llm: Enable LLM extraction (requires GEMINI_API_KEY)
            use_ocr: Enable OCR for scanned PDFs (requires Tesseract)
            save_to_db: Persist rules to SQLite
            save_to_json: Save rules to data/rules.json
        """
        self.use_llm = use_llm and llm_available()
        self.use_ocr = use_ocr and ocr_available()
        self.save_to_db = save_to_db
        self.save_to_json = save_to_json

        parser_name = "gemini-llm" if self.use_llm else "regex"
        logger.info(f"[Pipeline] Initialized -- parser={parser_name}, ocr={self.use_ocr}")

    def process(self, pdf_path: str, policy_id: Optional[str] = None) -> ExtractionResult:
        """Run the full extraction pipeline on a PDF.
        
        Args:
            pdf_path: Absolute or relative path to the PDF file
            policy_id: Optional custom ID; auto-generated from filename hash if None
            
        Returns:
            ExtractionResult with rules, metrics, and audit trail
        """
        start_time = time.time()
        filename = os.path.basename(pdf_path)

        if not policy_id:
            file_hash = hashlib.md5(filename.encode()).hexdigest()[:8]
            policy_id = f"POL-{file_hash}"

        result = ExtractionResult(
            policy_id=policy_id,
            filename=filename,
        )

        try:
            # ── Step 1: Extract text from PDF ──────────────────────
            print(f"[Pipeline] Step 1/6: Extracting text from {filename}...")
            extraction = extract_text_from_pdf(pdf_path)
            pages_raw = extraction["pages"]
            total_pages = len(pages_raw)

            if total_pages == 0:
                result.error = "PDF has no pages"
                result.success = False
                return result

            # ── Step 2: Register policy (versioned) ───────────────
            print(f"[Pipeline] Step 2/6: Registering policy version...")
            full_text = extraction.get("full_text", "")
            policy_info = PolicyRegistry.register_policy(
                filename=filename,
                raw_text=full_text[:10000],  # Store first 10K chars
                page_count=total_pages,
                policy_id=policy_id,
            )
            policy_version = policy_info["version"]
            print(f"  Policy: {policy_id} {policy_version} "
                  f"(checksum: {policy_info['checksum'][:12]}...)")

            AuditLogger.log("pipeline_start", policy_id=policy_id,
                            details={"filename": filename, "pages": total_pages,
                                     "version": policy_version, "llm": self.use_llm})

            # ── Step 3: OCR for scanned pages ─────────────────────
            ocr_pages = 0
            print(f"[Pipeline] Step 3/6: Checking for scanned pages...")

            for i, page in enumerate(pages_raw):
                if is_page_scanned(page["text"]):
                    if self.use_ocr:
                        print(f"  Page {page['page_num']}: scanned -- running OCR...")
                        ocr_result = ocr_pdf_page(pdf_path, page["page_num"])
                        if ocr_result["ocr_used"] and ocr_result["text"]:
                            pages_raw[i]["text"] = ocr_result["text"]
                            ocr_pages += 1
                    else:
                        print(f"  Page {page['page_num']}: scanned -- OCR unavailable, skipping")

            # ── Step 4: Clean text ────────────────────────────────
            print(f"[Pipeline] Step 4/6: Cleaning text ({total_pages} pages)...")
            cleaned_pages = clean_document(pages_raw)

            # ── Step 5: Extract rules ─────────────────────────────
            print(f"[Pipeline] Step 5/6: Extracting rules...")
            all_rules: list[ExtractedRule] = []

            for page in cleaned_pages:
                page_text = page["text"]
                page_num = page["page_num"]

                if len(page_text.strip()) < 30:
                    continue

                if self.use_llm:
                    # LLM extraction (primary)
                    rules = extract_rules_with_llm(
                        text=page_text,
                        page_num=page_num,
                        source_document=filename,
                    )
                    if rules:
                        # Stamp policy linkage and compute char offsets
                        for r in rules:
                            r.policy_id = policy_id
                            r.policy_version = policy_version
                            _compute_char_offsets(r, page_text)
                        all_rules.extend(rules)
                        print(f"  Page {page_num}: {len(rules)} rules (LLM)")
                        continue

                # Regex extraction (fallback or primary)
                legacy_rules = extract_rules_from_text(
                    page_text,
                    source_document=filename,
                    page_num=page_num,
                )
                for lr in legacy_rules:
                    converted = regex_to_extracted_rule(lr)
                    if converted:
                        converted.policy_id = policy_id
                        converted.policy_version = policy_version
                        _compute_char_offsets(converted, page_text)
                        all_rules.append(converted)

                if legacy_rules:
                    print(f"  Page {page_num}: {len(legacy_rules)} rules (regex)")

            # ── Step 6: Post-process & store ──────────────────────
            print(f"[Pipeline] Step 6/6: Post-processing {len(all_rules)} rules...")

            # Deduplicate by rule_id
            seen_ids = set()
            unique_rules = []
            for rule in all_rules:
                if rule.rule_id not in seen_ids:
                    seen_ids.add(rule.rule_id)
                    unique_rules.append(rule)
            all_rules = unique_rules

            # Run post-processing (ambiguity, sanity, conflicts)
            all_rules = post_process_rules(all_rules)

            # Store (legacy)
            if self.save_to_json and all_rules:
                save_rules(all_rules)

            # Store via strictly governed Service Layer (versioned, deduped, audited)
            if self.save_to_db and all_rules:
                from app.policy_engine.policy_governance import PolicyGovernance
                from app.policy_engine.rule_service import RuleService
                
                # 1. Create the immutable Policy Version container
                version_id = PolicyGovernance.create_version(
                    policy_id=policy_id,
                    source_document=filename,
                    raw_text=full_text[:1000],
                    change_summary=f"Automated pipeline ingestion",
                    created_by="system"
                )
                
                # 2. Transform Pydantic models for insertion
                rules_data = []
                for r in all_rules:
                    d = r.to_legacy_dict() if hasattr(r, 'to_legacy_dict') else (r.model_dump() if hasattr(r, 'model_dump') else dict(r))
                    
                    # Ensure RuleService gets the ID correctly
                    d["rule_id"] = d.get("rule_id") or d.get("id") or "AUTO-XXX"
                    d["status"] = "draft"
                    rules_data.append(d)
                
                # 3. Create strictly-coupled rules via Service
                upserted = RuleService.create_rules(version_id, rules_data)
                print(f"  Service: {upserted} rules inserted under governed version {version_id}")
                
                # For backwards compatibility with older testing routes
                from app.policy_engine.rule_set_manager import RuleSetManager
                ruleset_id = RuleSetManager.create_ruleset(
                    policy_id=policy_id,
                    policy_version=policy_version,
                    rule_ids=[r["rule_id"] for r in rules_data],
                    description=f"Extracted from {filename} ({version_id})",
                    created_by="system",
                )
                print(f"  Legacy Rule set: {ruleset_id} created (Draft State - requires Admin Activation)")

            AuditLogger.log("pipeline_complete", policy_id=policy_id,
                            details={"rules": len(all_rules),
                                     "version": policy_version,
                                     "elapsed_s": round(time.time() - start_time, 1)})

            # Compute metrics
            elapsed = time.time() - start_time
            result.rules = all_rules
            result.metrics.parser_used = "gemini-llm" if self.use_llm else "regex"
            result.metrics.compute(all_rules, total_pages, ocr_pages, elapsed)
            result.success = True

            print(f"\n[Pipeline] Complete -- {len(all_rules)} rules in {elapsed:.1f}s")
            print(f"  Avg confidence: {result.metrics.avg_confidence:.2f}")
            print(f"  Ambiguity rate: {result.metrics.ambiguity_rate:.0%}")
            print(f"  OCR pages: {ocr_pages}/{total_pages}")

            if any(r.review_required for r in all_rules):
                review_count = sum(1 for r in all_rules if r.review_required)
                print(f"  ! {review_count} rules flagged for human review")

        except FileNotFoundError:
            result.error = f"File not found: {pdf_path}"
            result.success = False
            logger.error(result.error)

        except Exception as e:
            result.error = str(e)
            result.success = False
            logger.error(f"Pipeline error: {e}", exc_info=True)
            AuditLogger.log("pipeline_error", policy_id=policy_id,
                            details={"error": str(e)})

        return result

    def process_batch(self, pdf_paths: list[str]) -> list[ExtractionResult]:
        """Process multiple PDFs sequentially.
        
        Returns list of ExtractionResult, one per PDF.
        """
        results = []
        for i, path in enumerate(pdf_paths, 1):
            print(f"\n{'='*50}")
            print(f"  Processing {i}/{len(pdf_paths)}: {os.path.basename(path)}")
            print(f"{'='*50}")
            result = self.process(path)
            results.append(result)
        return results


# ── Helper: Compute character offsets for traceability ────────────

def _compute_char_offsets(rule: ExtractedRule, page_text: str) -> None:
    """Compute char_start, char_end, and paragraph_id for a rule's source.
    
    Finds the source text within the page text and records the exact
    character offsets for UI highlighting and audit traceability.
    """
    source_text = rule.source.text
    if not source_text or not page_text:
        return

    # Try exact match first
    idx = page_text.find(source_text)
    if idx >= 0:
        rule.source.char_start = idx
        rule.source.char_end = idx + len(source_text)
    else:
        # Try normalized match (whitespace-insensitive)
        import re
        normalized_source = re.sub(r'\s+', ' ', source_text.strip())
        normalized_page = re.sub(r'\s+', ' ', page_text.strip())
        idx = normalized_page.find(normalized_source)
        if idx >= 0:
            rule.source.char_start = idx
            rule.source.char_end = idx + len(normalized_source)

    # Compute paragraph_id from page number and paragraph position
    if rule.source.char_start is not None:
        # Count paragraphs before this offset
        text_before = page_text[:rule.source.char_start]
        para_count = text_before.count('\n\n') + 1
        rule.source.paragraph_id = f"p_{rule.source.page}_{para_count}"
    else:
        # Fallback: assign based on position in page
        rule.source.paragraph_id = f"p_{rule.source.page}_0"
