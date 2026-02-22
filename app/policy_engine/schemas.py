"""Pydantic schemas for the Policy Intelligence Module.

Defines strict, validated data models for extracted rules, conditions,
policy documents, and extraction results. All models are regulator-friendly
with full source traceability, clause-level offsets, and audit metadata.

v3.0 — Regulator-grade: enhanced DSL, clause-level traceability,
       policy versioning fields, weighted confidence scoring.
"""
from __future__ import annotations
import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


# ── Enums ──────────────────────────────────────────────────────────

class RuleType(str, Enum):
    THRESHOLD = "threshold"
    VELOCITY = "velocity"
    CROSS_BORDER = "cross_border"
    PATTERN = "pattern"
    PAYMENT_FORMAT = "payment_format"
    DORMANT_ACCOUNT = "dormant_account"
    CUSTOM = "custom"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    RETIRED = "retired"
    SUPERSEDED = "superseded"


class ActionType(str, Enum):
    FLAG = "flag"
    REPORT = "report"
    BLOCK = "block"
    ESCALATE = "escalate"
    MONITOR = "monitor"


class Operator(str, Enum):
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="
    EQ = "=="
    NEQ = "!="
    IN = "in"
    COUNT = "count"
    RATE = "rate"
    WITHIN = "within"
    MATCHES = "matches"
    CONTAINS = "contains"
    BETWEEN = "between"


class PolicyStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    RETIRED = "retired"


# ── Core Models ────────────────────────────────────────────────────

class TimeWindow(BaseModel):
    """Time window specification for velocity/aggregation rules."""
    value: int = Field(..., gt=0, description="Numeric value of the window")
    unit: str = Field(..., pattern=r"^(minute|hour|day|week|month|year)$",
                      description="Time unit")

    def __str__(self) -> str:
        return f"{self.value} {self.unit}{'s' if self.value > 1 else ''}"


class RuleCondition(BaseModel):
    """A single condition within a rule — supports full DSL operators."""
    metric: str = Field(..., description="The field/metric being evaluated, e.g. 'transaction_amount'")
    operator: Operator = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Threshold or reference value")
    unit: Optional[str] = Field(None, description="Unit of measurement (e.g. 'USD', 'days', 'count')")
    time_window: Optional[TimeWindow] = Field(None, description="Time window for aggregation")
    aggregation: Optional[str] = Field(None, pattern=r"^(sum|count|avg|max|min|distinct)$",
                                        description="Aggregation function if applicable")
    entity_scope: Optional[str] = Field(None, description="Entity scope (e.g. 'transaction', 'account', 'customer')")
    filters: Optional[dict[str, Any]] = Field(None, description="Additional filter conditions as key-value pairs")
    currency: Optional[str] = Field(None, description="Currency for monetary values (ISO 4217)")

    @field_validator("value", mode="before")
    @classmethod
    def coerce_value(cls, v: Any) -> Any:
        """Allow numeric strings to be cast."""
        if isinstance(v, str):
            try:
                cleaned = v.replace(",", "").replace("$", "").strip()
                if "." in cleaned:
                    return float(cleaned)
                return int(cleaned)
            except ValueError:
                pass
        return v


class RuleSource(BaseModel):
    """Provenance information — clause-level traceability with character offsets.

    Every rule MUST be traceable to exact policy text. Source text is verbatim.
    Immutable after creation.
    """
    page: int = Field(..., ge=1, description="1-indexed page number")
    text: str = Field(..., min_length=1, description="Original source sentence/clause (verbatim)")
    paragraph_id: Optional[str] = Field(None, description="Paragraph identifier, e.g. 'p_5_3'")
    char_start: Optional[int] = Field(None, ge=0, description="Start character offset in page text")
    char_end: Optional[int] = Field(None, ge=0, description="End character offset in page text")
    section: Optional[str] = Field(None, description="Section heading the text belongs to")
    bbox: Optional[list[float]] = Field(None, description="Bounding box [x0, y0, x1, y1]")
    document: Optional[str] = Field(None, description="Source document filename")

    @model_validator(mode="after")
    def validate_offsets(self) -> "RuleSource":
        """Ensure char_end >= char_start if both are set."""
        if self.char_start is not None and self.char_end is not None:
            if self.char_end < self.char_start:
                raise ValueError("char_end must be >= char_start")
        return self


class ExtractedRule(BaseModel):
    """A fully validated rule extracted from a policy document.

    This is the primary data contract for the policy pipeline.
    Every extracted rule carries full traceability, confidence metadata,
    policy versioning, and audit fields.
    """
    # ── Identity
    rule_id: str = Field(..., min_length=1, description="Unique rule identifier")
    rule_name: str = Field(..., min_length=1, description="Human-readable rule name")
    description: str = Field("", description="Extended description of what the rule checks")

    # ── Policy linkage
    policy_id: Optional[str] = Field(None, description="Parent policy document ID")
    policy_version: Optional[str] = Field(None, description="Version of the source policy")
    effective_date: Optional[str] = Field(None, description="ISO date when the rule takes effect")

    # ── Rule definition
    entities: list[str] = Field(default_factory=lambda: ["transaction"],
                                description="Entity types involved (account, transaction, etc.)")
    rule_type: RuleType = Field(..., description="Classification of the rule")
    conditions: list[RuleCondition] = Field(..., min_length=1, description="Rule conditions")
    action: ActionType = Field(ActionType.FLAG, description="Action to take when violated")
    severity: Severity = Field(Severity.MEDIUM, description="Severity of the violation")

    # ── Confidence & ambiguity
    confidence: float = Field(..., ge=0.0, le=1.0,
                               description="Extraction confidence score (0-1)")
    ambiguous: bool = Field(False, description="Whether the rule has ambiguous language")
    review_required: bool = Field(False, description="Whether human review is needed")
    ambiguity_reasons: list[str] = Field(default_factory=list,
                                          description="Reasons for ambiguity flag")

    # ── Traceability
    source: RuleSource = Field(..., description="Traceability to original document")

    # ── Lifecycle
    version: str = Field("1.0", description="Rule version")
    status: RuleStatus = Field(RuleStatus.DRAFT, description="Lifecycle status")
    extracted_at: str = Field(default_factory=lambda: datetime.now().isoformat(),
                               description="ISO timestamp of extraction")
    parser_version: str = Field("2.0", description="Version of the extraction parser")

    @model_validator(mode="after")
    def flag_low_confidence_for_review(self) -> "ExtractedRule":
        """Auto-flag rules with low confidence or ambiguity for human review."""
        if self.confidence < 0.7 or self.ambiguous:
            self.review_required = True
            if self.status == RuleStatus.ACTIVE:
                self.status = RuleStatus.REVIEW
        return self

    def compute_rule_hash(self) -> str:
        """Compute a deterministic hash of the rule content for dedup."""
        content = json.dumps({
            "conditions": [c.model_dump() for c in self.conditions],
            "rule_type": self.rule_type.value,
            "action": self.action.value,
            "severity": self.severity.value,
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_legacy_dict(self) -> dict:
        """Convert to the legacy dict format expected by rule_engine.py and save_rules_to_db."""
        conditions_legacy = []
        for c in self.conditions:
            cond = {
                "field": c.metric,
                "operator": c.operator.value,
                "value": c.value,
            }
            if c.unit:
                cond["unit"] = c.unit
            if c.time_window:
                cond["time_window"] = {"value": c.time_window.value, "unit": c.time_window.unit}
            if c.aggregation:
                cond["aggregation"] = c.aggregation
            if c.entity_scope:
                cond["entity_scope"] = c.entity_scope
            if c.filters:
                cond["filters"] = c.filters
            conditions_legacy.append(cond)

        return {
            "rule_id": self.rule_id,
            "name": self.rule_name,
            "source_document": self.source.document or "",
            "source_page": self.source.page,
            "source_text": self.source.text,
            "paragraph_id": self.source.paragraph_id,
            "char_start": self.source.char_start,
            "char_end": self.source.char_end,
            "rule_type": self.rule_type.value,
            "conditions": conditions_legacy,
            "severity": self.severity.value,
            "version": self.version,
            "status": self.status.value,
            "confidence": self.confidence,
            "ambiguous": self.ambiguous,
            "review_required": self.review_required,
            "description": self.description,
            "action": self.action.value,
            "extracted_at": self.extracted_at,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "effective_date": self.effective_date,
            "rule_hash": self.compute_rule_hash(),
        }


# ── Extraction Result ──────────────────────────────────────────────

class ExtractionMetrics(BaseModel):
    """Metrics from a single extraction run."""
    total_pages: int = 0
    pages_with_rules: int = 0
    rules_extracted: int = 0
    rules_per_page: float = 0.0
    avg_confidence: float = 0.0
    ambiguity_rate: float = 0.0
    ocr_pages: int = 0
    ocr_usage_rate: float = 0.0
    processing_time_seconds: float = 0.0
    parser_used: str = "regex"
    warnings: list[str] = Field(default_factory=list)

    def compute(self, rules: list[ExtractedRule], total_pages: int,
                ocr_pages: int, elapsed: float) -> None:
        """Compute all derived metrics from raw data."""
        self.total_pages = total_pages
        self.rules_extracted = len(rules)
        self.ocr_pages = ocr_pages
        self.processing_time_seconds = round(elapsed, 2)

        if total_pages > 0:
            self.ocr_usage_rate = round(ocr_pages / total_pages, 3)
            pages_set = {r.source.page for r in rules}
            self.pages_with_rules = len(pages_set)
            self.rules_per_page = round(len(rules) / total_pages, 2)

        if rules:
            self.avg_confidence = round(
                sum(r.confidence for r in rules) / len(rules), 3
            )
            self.ambiguity_rate = round(
                sum(1 for r in rules if r.ambiguous) / len(rules), 3
            )


class ExtractionResult(BaseModel):
    """Complete output of a policy extraction run."""
    policy_id: str
    filename: str
    rules: list[ExtractedRule] = Field(default_factory=list)
    metrics: ExtractionMetrics = Field(default_factory=ExtractionMetrics)
    processed_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    success: bool = True
    error: Optional[str] = None

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json(indent=2)
