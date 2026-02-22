"""LLM-powered semantic rule extraction via Groq (OpenAI-compatible).

Uses the Groq API with model openai/gpt-oss-120b for fast inference.
Falls back to regex parser when LLM is unavailable.

Guardrails:
- Forces JSON-only output
- Cross-validates numeric thresholds against source text
- Marks uncertain fields as ambiguous
- Preserves exact source sentences
"""
import os
import re
import json
import logging
import hashlib
from typing import Optional

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    _env_path = os.path.join(os.path.dirname(__file__), '..', '..', '.env')
    if os.path.exists(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _key, _val = _line.split('=', 1)
                    os.environ.setdefault(_key.strip(), _val.strip())


from app.policy_engine.schemas import (
    ExtractedRule, RuleCondition, RuleSource, TimeWindow,
    RuleType, Severity, ActionType, Operator, RuleStatus,
)
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ── LLM Output Schemas ───────────────────────────────────────────
class LLMTimeWindow(BaseModel):
    value: int
    unit: str

class LLMCondition(BaseModel):
    metric: str
    operator: str
    value: float
    time_window: LLMTimeWindow | None = None
    aggregation: str | None = None
    currency: str | None = None

class LLMRule(BaseModel):
    rule_id: str | None = None
    rule_name: str
    description: str
    entities: list[str] | None = None
    rule_type: str
    conditions: list[LLMCondition]
    action: str
    severity: str
    confidence: float
    ambiguous: bool
    ambiguity_reasons: list[str] | None = None
    source_text: str

# ── Groq Client (OpenAI-compatible) ──────────────────────────────

_groq_client = None

def _get_groq_client():
    """Lazy-initialize the Groq OpenAI-compatible client."""
    global _groq_client
    if _groq_client is not None:
        return _groq_client

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        logger.warning("GROQ_API_KEY not set -- LLM extraction disabled")
        return None

    try:
        from openai import OpenAI
        _groq_client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        return _groq_client
    except Exception as e:
        logger.error(f"Failed to initialize Groq client: {e}")
        return None


def llm_available() -> bool:
    """Check if LLM extraction is available."""
    return bool(os.environ.get("GROQ_API_KEY", ""))


# ── Prompt Template ───────────────────────────────────────────────

EXTRACTION_PROMPT = """You are a senior compliance analyst specializing in Anti-Money Laundering (AML) regulations. 
Your task is to extract **enforceable compliance rules** from the following policy text.

## IMPORTANT INSTRUCTIONS:
1. Extract ONLY concrete, enforceable rules with specific thresholds, limits, or patterns
2. Do NOT hallucinate numbers — only use thresholds that appear in the text
3. If a rule is vague or uncertain, set "ambiguous": true and explain why
4. Preserve the EXACT source sentence for each rule
5. Output ONLY valid JSON — no markdown, no explanation text

## Policy Text (Page {page_num}):
---
{text}
---

## Required JSON Output Schema:
Return a JSON array of rules. Each rule must have this EXACT structure:
[
  {{
    "rule_id": "unique-id-string",
    "rule_name": "Human-readable name",
    "description": "What this rule enforces",
    "entities": ["account", "transaction"],
    "rule_type": "threshold|velocity|cross_border|pattern|payment_format|dormant_account|custom",
    "conditions": [
      {{
        "metric": "field name (e.g. transaction_amount, transaction_count)",
        "operator": ">|>=|<|<=|==|!=|within|matches|contains|between",
        "value": 10000,
        "time_window": {{"value": 24, "unit": "hour"}} or null,
        "aggregation": "sum|count|avg|max|min|distinct" or null
      }}
    ],
    "action": "flag|report|block|escalate|monitor",
    "severity": "critical|high|medium|low",
    "confidence": 0.0 to 1.0,
    "ambiguous": false,
    "ambiguity_reasons": [],
    "source_text": "exact sentence from the policy"
  }}
]

If there are NO extractable rules in this text, return an empty array: []
RESPOND WITH ONLY THE JSON ARRAY. NO OTHER TEXT. DO NOT WRAP IN MARKDOWN."""


# ── LLM Extraction ────────────────────────────────────────────────

def extract_rules_with_llm(text: str, page_num: int = 1,
                            source_document: str = "",
                            max_retries: int = 2) -> list[ExtractedRule]:
    """Extract rules from text using Groq LLM (fast inference).
    
    Args:
        text: Cleaned policy text (typically one page)
        page_num: Page number for traceability
        source_document: Filename of the source PDF
        max_retries: Number of retry attempts on failure
        
    Returns:
        List of validated ExtractedRule objects
    """
    client = _get_groq_client()
    if client is None:
        return []

    prompt = EXTRACTION_PROMPT.format(page_num=page_num, text=text)

    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[
                    {"role": "system", "content": "You are a compliance rule extraction engine. Output ONLY valid JSON arrays. No markdown, no explanation."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=4096,
            )

            raw_json = response.choices[0].message.content.strip()

            # Clean potential markdown wrapping
            if raw_json.startswith("```"):
                raw_json = re.sub(r"^```(?:json)?\s*", "", raw_json)
                raw_json = re.sub(r"\s*```$", "", raw_json)

            rules_data = json.loads(raw_json, strict=False)

            if not isinstance(rules_data, list):
                rules_data = [rules_data]

            # Convert to Pydantic models with validation
            rules = []
            for rd in rules_data:
                rule = _parse_llm_rule(rd, page_num, source_document, text)
                if rule:
                    rules.append(rule)

            return rules

        except json.JSONDecodeError as e:
            logger.warning(f"LLM returned invalid JSON (attempt {attempt+1}): {e}")
            if attempt == max_retries:
                logger.error("LLM JSON parsing failed after retries")
                return []

        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt+1}): {e}")
            if attempt == max_retries:
                logger.error(f"LLM extraction failed after retries: {e}")
                return []

    return []


def _parse_llm_rule(data: dict, page_num: int,
                     source_document: str, page_text: str) -> Optional[ExtractedRule]:
    """Convert raw LLM JSON output to a validated ExtractedRule.
    
    Applies guardrails: threshold cross-validation, ambiguity detection.
    """
    try:
        # Parse conditions
        conditions = []
        for cd in data.get("conditions", []):
            tw = None
            if cd.get("time_window") and isinstance(cd["time_window"], dict):
                try:
                    tw = TimeWindow(
                        value=int(cd["time_window"].get("value", 0)),
                        unit=cd["time_window"].get("unit", "day"),
                    )
                except Exception:
                    tw = None

            # Map operator string
            op_str = cd.get("operator", ">")
            try:
                operator = Operator(op_str)
            except ValueError:
                operator = Operator.GT

            conditions.append(RuleCondition(
                metric=cd.get("metric", "unknown"),
                operator=operator,
                value=cd.get("value", 0),
                time_window=tw,
                aggregation=cd.get("aggregation"),
                currency=cd.get("currency"),
            ))

        if not conditions:
            return None

        # Map rule_type
        rt_str = data.get("rule_type", "custom")
        try:
            rule_type = RuleType(rt_str)
        except ValueError:
            rule_type = RuleType.CUSTOM

        # Map severity
        sev_str = data.get("severity", "medium")
        try:
            severity = Severity(sev_str)
        except ValueError:
            severity = Severity.MEDIUM

        # Map action
        act_str = data.get("action", "flag")
        try:
            action = ActionType(act_str)
        except ValueError:
            action = ActionType.FLAG

        # Extract source text
        source_text = data.get("source_text", "")
        if not source_text or source_text not in page_text:
            source_text = source_text or page_text[:500]

        # Confidence
        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        # Ambiguity
        ambiguous = bool(data.get("ambiguous", False))
        ambiguity_reasons = data.get("ambiguity_reasons", [])
        if not isinstance(ambiguity_reasons, list):
            ambiguity_reasons = []

        # Guardrail: cross-validate numeric thresholds against source text
        for cond in conditions:
            if isinstance(cond.value, (int, float)) and cond.value > 0:
                val_str = str(int(cond.value)) if cond.value == int(cond.value) else str(cond.value)
                val_formatted = f"{int(cond.value):,}"
                if val_str not in page_text and val_formatted not in page_text:
                    ambiguous = True
                    ambiguity_reasons.append(
                        f"Threshold {cond.value} not found in source text — possible hallucination"
                    )
                    confidence = min(confidence, 0.5)

        # Generate deterministic rule_id
        rule_id = data.get("rule_id", "")
        if not rule_id or rule_id in ("", "unique-id-string"):
            content_hash = hashlib.md5(
                f"{source_document}:{page_num}:{source_text[:100]}".encode()
            ).hexdigest()[:8]
            rule_id = f"LLM-{rule_type.value[:3].upper()}-{content_hash}"

        return ExtractedRule(
            rule_id=rule_id,
            rule_name=data.get("rule_name", f"{rule_type.value.replace('_', ' ').title()} Rule"),
            description=data.get("description", ""),
            entities=data.get("entities", ["transaction"]),
            rule_type=rule_type,
            conditions=conditions,
            action=action,
            severity=severity,
            confidence=confidence,
            ambiguous=ambiguous,
            ambiguity_reasons=ambiguity_reasons,
            source=RuleSource(
                page=page_num,
                text=source_text,
                document=source_document,
            ),
            version="2.0",
            status=RuleStatus.DRAFT,
            parser_version="2.0-groq",
        )

    except Exception as e:
        logger.warning(f"Failed to parse LLM rule: {e}")
        return None


# ── Regex Fallback Adapter ────────────────────────────────────────

def regex_to_extracted_rule(legacy_rule: dict) -> Optional[ExtractedRule]:
    """Convert a legacy regex-extracted rule dict to the new ExtractedRule schema.
    
    This adapter allows the existing rule_parser.py to produce output
    compatible with the new pipeline.
    """
    try:
        # Map conditions
        conditions = []
        for cond in legacy_rule.get("conditions", []):
            op_str = cond.get("operator", ">")
            try:
                operator = Operator(op_str)
            except ValueError:
                operator = Operator.GT

            tw = None
            if cond.get("field") == "time_window" and isinstance(cond.get("value"), dict):
                try:
                    tw = TimeWindow(
                        value=int(cond["value"].get("value", 0)),
                        unit=cond["value"].get("unit", "day"),
                    )
                except Exception:
                    pass
                continue  # Time window conditions are metadata, not standalone

            value = cond.get("value", 0)

            conditions.append(RuleCondition(
                metric=cond.get("field", "unknown"),
                operator=operator,
                value=value,
                time_window=tw,
            ))

        # If time window was found but no condition has it, attach to first condition
        for cond in legacy_rule.get("conditions", []):
            if cond.get("field") == "time_window" and isinstance(cond.get("value"), dict):
                tw_val = cond["value"]
                try:
                    tw = TimeWindow(value=int(tw_val.get("value", 0)),
                                     unit=tw_val.get("unit", "day"))
                    if conditions:
                        conditions[0].time_window = tw
                except Exception:
                    pass

        if not conditions:
            return None

        # Map rule_type
        try:
            rule_type = RuleType(legacy_rule.get("rule_type", "custom"))
        except ValueError:
            rule_type = RuleType.CUSTOM

        # Map severity
        try:
            severity = Severity(legacy_rule.get("severity", "medium"))
        except ValueError:
            severity = Severity.MEDIUM

        return ExtractedRule(
            rule_id=legacy_rule.get("rule_id", "UNKNOWN"),
            rule_name=legacy_rule.get("name", "Unknown Rule"),
            description="",
            entities=["transaction"],
            rule_type=rule_type,
            conditions=conditions,
            action=ActionType.FLAG,
            severity=severity,
            confidence=0.6,  # Regex extraction has lower confidence than LLM
            ambiguous=False,
            source=RuleSource(
                page=legacy_rule.get("source_page", 1),
                text=legacy_rule.get("source_text", ""),
                document=legacy_rule.get("source_document", ""),
            ),
            version="1.0",
            status=RuleStatus.DRAFT,
            parser_version="1.0-regex",
        )

    except Exception as e:
        logger.warning(f"Failed to convert legacy rule: {e}")
        return None
