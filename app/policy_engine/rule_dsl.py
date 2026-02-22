"""Rule DSL schema definition, validation, storage, and post-processing.

v3.0 — Regulator-grade enhancements:
  - Weighted confidence scoring (5 factors)
  - Expanded vague term detection
  - Missing field detection (time window, entity, unit)
  - Duplicate/conflict detection
  - Threshold sanity checks
"""
import json
import os
import logging
import hashlib
from datetime import datetime
from difflib import SequenceMatcher
from typing import Optional

from app.config import RULES_FILE
from app.db import get_connection
from app.policy_engine.schemas import (
    ExtractedRule, RuleType, Severity, RuleStatus,
    ExtractionMetrics,
)

logger = logging.getLogger(__name__)

# ── Legacy Constants (kept for backward compat) ───────────────────

VALID_RULE_TYPES = [e.value for e in RuleType]
VALID_SEVERITIES = [e.value for e in Severity]
VALID_STATUSES = [e.value for e in RuleStatus]


# ── Pydantic-based Validation ─────────────────────────────────────

def validate_rule(rule) -> tuple[bool, list[str]]:
    """Validate a rule — accepts both ExtractedRule and legacy dict.
    
    Returns:
        (is_valid, errors) tuple
    """
    if isinstance(rule, ExtractedRule):
        return (True, [])

    # Legacy dict validation
    errors = []
    required_fields = ["rule_id", "name", "rule_type", "conditions", "severity"]

    for field in required_fields:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    if rule.get("rule_type") and rule["rule_type"] not in VALID_RULE_TYPES:
        errors.append(f"Invalid rule_type: {rule['rule_type']}")

    if rule.get("severity") and rule["severity"] not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: {rule['severity']}")

    if rule.get("conditions"):
        for i, cond in enumerate(rule["conditions"]):
            if not isinstance(cond, dict):
                errors.append(f"Condition {i} must be a dict")
            elif "field" not in cond or "operator" not in cond:
                errors.append(f"Condition {i} missing 'field' or 'operator'")

    return (len(errors) == 0, errors)


# ── Ambiguity Detection ───────────────────────────────────────────

VAGUE_TERMS = [
    # Modal/hedging
    "may", "should", "might", "could", "approximately", "around",
    "roughly", "generally", "usually", "typically", "sometimes",
    "as appropriate", "as needed", "where applicable",
    # Subjective magnitude (CRITICAL — these are where systems fail)
    "large", "unusual", "frequent", "significant", "excessive",
    "reasonable", "adequate", "appropriate", "substantial", "considerable",
    "minimal", "material", "notable", "abnormal", "irregular",
    "high-risk", "suspicious",
]


def detect_ambiguities(rule) -> list[str]:
    """Detect potential ambiguities in a rule.
    
    Checks:
    - Vague language in source text
    - Missing numeric threshold
    - Missing time window when implied
    - Entity unclear
    - Unit missing for monetary values
    - Multiple conflicting interpretations possible
    
    Returns:
        List of ambiguity warning strings
    """
    warnings = []

    # Get source text and conditions
    if isinstance(rule, ExtractedRule):
        source = rule.source.text.lower()
        rule_type = rule.rule_type.value
        conditions = rule.conditions
    else:
        source = rule.get("source_text", "").lower()
        rule_type = rule.get("rule_type", "")
        conditions = rule.get("conditions", [])

    # 1. Vague language detection
    for term in VAGUE_TERMS:
        if f" {term} " in f" {source} ":
            warnings.append(f"Vague term '{term}' -- enforcement may be inconsistent")

    # 2. Missing numeric threshold
    if rule_type == "threshold":
        has_numeric = False
        if isinstance(rule, ExtractedRule):
            has_numeric = any(
                isinstance(c.value, (int, float)) for c in conditions
            )
        else:
            has_numeric = any(
                isinstance(c.get("value"), (int, float))
                for c in conditions if isinstance(c, dict)
            )
        if not has_numeric:
            warnings.append("Threshold rule missing explicit numeric value -- never invent thresholds")

    # 3. Missing time window when implied (velocity rules)
    if rule_type == "velocity":
        has_time_window = False
        if isinstance(rule, ExtractedRule):
            has_time_window = any(c.time_window is not None for c in conditions)
        else:
            has_time_window = any(
                c.get("time_window") is not None
                for c in conditions if isinstance(c, dict)
            )
        if not has_time_window:
            warnings.append("Velocity rule missing time window -- temporal scope undefined")

    # 4. Entity unclear
    if isinstance(rule, ExtractedRule):
        has_entity_scope = any(c.entity_scope is not None for c in conditions)
        if not has_entity_scope and not rule.entities:
            warnings.append("Entity scope unclear -- which entity does this rule apply to?")

    # 5. Unit missing for monetary values
    if isinstance(rule, ExtractedRule):
        for c in conditions:
            if c.metric in ("transaction_amount", "amount_paid", "amount_received",
                            "cumulative_amount") and c.currency is None and c.unit is None:
                warnings.append(f"Missing currency/unit for monetary metric '{c.metric}'")
                break

    return warnings


# ── Weighted Confidence Scoring ───────────────────────────────────

def compute_confidence_score(rule: ExtractedRule) -> float:
    """Compute a weighted confidence score based on 5 factors.

    Factors and weights:
    - Extraction certainty (0.30) -- LLM vs regex
    - Numeric presence    (0.25) -- explicit thresholds?
    - Clause clarity      (0.20) -- vague term count
    - Schema completeness (0.15) -- all fields populated?
    - Parser agreement    (0.10) -- would both parsers agree?

    Returns:
        Confidence score between 0.0 and 1.0
    """
    scores = {}

    # Factor 1: Extraction certainty (0.30)
    if "gemini" in rule.parser_version.lower():
        scores["extraction_certainty"] = 1.0
    elif "regex" in rule.parser_version.lower():
        scores["extraction_certainty"] = 0.5
    else:
        scores["extraction_certainty"] = 0.3

    # Factor 2: Numeric presence (0.25)
    numeric_conditions = sum(
        1 for c in rule.conditions if isinstance(c.value, (int, float))
    )
    total_conditions = len(rule.conditions)
    scores["numeric_presence"] = (
        numeric_conditions / total_conditions if total_conditions > 0 else 0.0
    )

    # Factor 3: Clause clarity (0.20)
    source = rule.source.text.lower()
    vague_count = sum(1 for t in VAGUE_TERMS if f" {t} " in f" {source} ")
    scores["clause_clarity"] = max(0.0, 1.0 - (vague_count * 0.2))

    # Factor 4: Schema completeness (0.15)
    filled_fields = 0
    total_fields = 8
    if rule.description:
        filled_fields += 1
    if rule.policy_id:
        filled_fields += 1
    if rule.source.paragraph_id:
        filled_fields += 1
    if rule.source.char_start is not None:
        filled_fields += 1
    if rule.severity != Severity.MEDIUM:  # Non-default
        filled_fields += 1
    if rule.action:
        filled_fields += 1
    if any(c.time_window for c in rule.conditions):
        filled_fields += 1
    if any(c.currency or c.unit for c in rule.conditions):
        filled_fields += 1
    scores["schema_completeness"] = filled_fields / total_fields

    # Factor 5: Parser agreement proxy (0.10)
    # If source text contains clear numeric patterns, both parsers would agree
    import re
    has_clear_numbers = bool(re.search(r'\$[\d,]+|\d{3,}', rule.source.text))
    has_clear_keywords = any(
        kw in rule.source.text.lower()
        for kw in ["must", "shall", "required", "prohibited", "exceeding"]
    )
    if has_clear_numbers and has_clear_keywords:
        scores["parser_agreement"] = 1.0
    elif has_clear_numbers or has_clear_keywords:
        scores["parser_agreement"] = 0.6
    else:
        scores["parser_agreement"] = 0.2

    # Weighted sum
    weights = {
        "extraction_certainty": 0.30,
        "numeric_presence": 0.25,
        "clause_clarity": 0.20,
        "schema_completeness": 0.15,
        "parser_agreement": 0.10,
    }

    confidence = sum(scores[k] * weights[k] for k in weights)
    return round(min(1.0, max(0.0, confidence)), 3)


# ── Post-Processing: Duplicate Detection ──────────────────────────

def _text_similarity(a: str, b: str) -> float:
    """Compute similarity ratio between two strings."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def detect_duplicate_rules(rules: list[ExtractedRule],
                            threshold: float = 0.85) -> list[tuple[str, str, float]]:
    """Find duplicate rules based on source text similarity.
    
    Returns:
        List of (rule_id_a, rule_id_b, similarity) tuples
    """
    duplicates = []
    for i, a in enumerate(rules):
        for b in rules[i+1:]:
            sim = _text_similarity(a.source.text, b.source.text)
            if sim >= threshold:
                duplicates.append((a.rule_id, b.rule_id, round(sim, 3)))
    return duplicates


# ── Post-Processing: Conflict Detection ──────────────────────────

def detect_conflicts(rules: list[ExtractedRule]) -> list[dict]:
    """Detect rules with conflicting conditions.
    
    E.g., two threshold rules on the same metric with contradictory operators.
    """
    conflicts = []
    by_type = {}
    for r in rules:
        by_type.setdefault(r.rule_type, []).append(r)

    for rule_type, group in by_type.items():
        for i, a in enumerate(group):
            for b in group[i+1:]:
                for ca in a.conditions:
                    for cb in b.conditions:
                        if ca.metric == cb.metric:
                            # Same metric, check for contradictions
                            if (ca.operator.value in (">", ">=") and
                                    cb.operator.value in ("<", "<=") and
                                    isinstance(ca.value, (int, float)) and
                                    isinstance(cb.value, (int, float))):
                                if ca.value > cb.value:
                                    conflicts.append({
                                        "rule_a": a.rule_id,
                                        "rule_b": b.rule_id,
                                        "metric": ca.metric,
                                        "issue": f"{a.rule_id} requires {ca.metric} {ca.operator.value} {ca.value} "
                                                 f"but {b.rule_id} requires {cb.operator.value} {cb.value}",
                                    })
    return conflicts


# ── Post-Processing: Threshold Sanity ─────────────────────────────

def sanity_check_thresholds(rule: ExtractedRule) -> list[str]:
    """Check that thresholds are within sane ranges.
    
    Returns list of warning strings.
    """
    warnings = []
    for cond in rule.conditions:
        if isinstance(cond.value, (int, float)):
            if cond.value < 0:
                warnings.append(
                    f"Negative threshold ({cond.value}) on {cond.metric} -- likely extraction error"
                )
            if cond.metric in ("transaction_amount", "amount_paid", "amount_received",
                               "cumulative_amount"):
                if cond.value > 1_000_000_000:
                    warnings.append(
                        f"Extremely high threshold ({cond.value:,.0f}) on {cond.metric}"
                    )
            if cond.metric == "transaction_count":
                if cond.value > 10_000:
                    warnings.append(
                        f"Very high transaction count threshold ({cond.value})"
                    )
        if cond.time_window:
            if cond.time_window.value > 365 and cond.time_window.unit == "day":
                warnings.append(
                    f"Time window over 1 year ({cond.time_window}) may be too broad"
                )
    return warnings


# ── Full Post-Processing ─────────────────────────────────────────

def post_process_rules(rules: list[ExtractedRule]) -> list[ExtractedRule]:
    """Run all post-processing steps on extracted rules.
    
    - Weighted confidence re-scoring
    - Sanity check thresholds
    - Detect and flag ambiguities
    - Detect duplicates and mark them
    - Update review_required flags
    
    Returns the same list with updated flags.
    """
    # 1. Per-rule checks
    for rule in rules:
        # Recompute confidence with weighted scoring
        weighted_conf = compute_confidence_score(rule)
        # Blend: keep LLM confidence if higher, but apply weighted floor
        rule.confidence = round(max(weighted_conf, min(rule.confidence, weighted_conf * 1.2)), 3)

        # Ambiguity detection
        ambiguities = detect_ambiguities(rule)
        if ambiguities:
            rule.ambiguous = True
            rule.ambiguity_reasons.extend(ambiguities)

        # Threshold sanity
        threshold_warnings = sanity_check_thresholds(rule)
        if threshold_warnings:
            rule.ambiguity_reasons.extend(threshold_warnings)
            rule.confidence = min(rule.confidence, 0.6)

        # Re-trigger auto-review logic
        if rule.confidence < 0.7 or rule.ambiguous:
            rule.review_required = True
            if rule.status == RuleStatus.ACTIVE:
                rule.status = RuleStatus.REVIEW

    # 2. Cross-rule checks
    duplicates = detect_duplicate_rules(rules)
    if duplicates:
        dup_ids = set()
        for a_id, b_id, sim in duplicates:
            dup_ids.add(b_id)  # Flag the second one
            logger.info(f"Duplicate rules: {a_id} <-> {b_id} (sim={sim})")

        for rule in rules:
            if rule.rule_id in dup_ids:
                rule.ambiguity_reasons.append("Possible duplicate of another rule")
                rule.review_required = True

    conflicts = detect_conflicts(rules)
    for conflict in conflicts:
        logger.warning(f"Rule conflict: {conflict['issue']}")
        for rule in rules:
            if rule.rule_id in (conflict["rule_a"], conflict["rule_b"]):
                rule.ambiguity_reasons.append(f"Conflict: {conflict['issue']}")
                rule.review_required = True

    return rules


# ── Storage ──────────────────────────────────────────────────────

def save_rules(rules, filepath: Optional[str] = None) -> list[dict]:
    """Save rules to JSON file. Accepts ExtractedRule objects or legacy dicts."""
    filepath = filepath or RULES_FILE
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    output = []
    for rule in rules:
        if isinstance(rule, ExtractedRule):
            d = rule.to_legacy_dict()
        else:
            d = rule
        
        # Add validation metadata
        is_valid, errors = validate_rule(rule)
        ambiguities = detect_ambiguities(rule)
        d["_validation"] = {
            "is_valid": is_valid,
            "errors": errors,
            "ambiguities": ambiguities,
            "validated_at": datetime.now().isoformat(),
        }
        output.append(d)

    with open(filepath, "w") as f:
        json.dump(output, f, indent=2, default=str)

    valid_count = sum(1 for d in output if d["_validation"]["is_valid"])
    print(f"[Rules] Saved {len(output)} rules ({valid_count} valid) to {filepath}")
    return output


def load_rules(filepath: Optional[str] = None) -> list[dict]:
    """Load rules from JSON file."""
    filepath = filepath or RULES_FILE
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r") as f:
        return json.load(f)


def save_rules_to_db(rules) -> int:
    """Persist rules to PostgreSQL database. 
    
    DEPRECATED: Standalone rule creation is no longer allowed.
    All rules must be strictly bound to a policy version_id.
    Use app.policy_engine.rule_service.RuleService.create_rules() instead.
    """
    raise NotImplementedError(
        "Direct rule insertion is prohibited. Rules must be tied to a policy version_id. "
        "Use RuleService.create_rules(version_id, rules) instead."
    )
