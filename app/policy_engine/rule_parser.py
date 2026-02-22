"""Extract enforceable rules from policy text using regex/NLP patterns."""
import re
import json
import hashlib
from datetime import datetime


# Pattern library for detecting rule components
AMOUNT_PATTERN = r'\$[\d,]+(?:\.\d{2})?(?:\s*(?:USD|US Dollar|EUR|Euro|GBP))?'
THRESHOLD_PATTERN = r'(?:exceed|greater than|more than|above|over|surpass)\w*\s+' + AMOUNT_PATTERN
TIME_WINDOW_PATTERN = r'(?:within|in|during|per)\s+(?:a\s+)?(\d+)[\s-]*(hour|day|week|month|minute)s?(?:\s+(?:period|window))?'
COUNT_PATTERN = r'(?:more than|exceed|greater than|over|at least)\s+(\d+)\s+(?:outgoing\s+)?(?:transaction|transfer|payment|account)s?'
RULE_ID_PATTERN = r'Rule\s+[\w.-]+(?:\s*:)?'


def extract_rules_from_text(text, source_document="", page_num=0):
    """Extract structured rules from policy text.
    
    Uses regex patterns to identify:
    - Monetary thresholds
    - Time windows
    - Transaction counts / velocity limits
    - Rule references
    - Severity indicators
    """
    rules = []
    
    # Split into sentences/clauses for granular matching
    sentences = re.split(r'[.;]\s+|•\s+|Rule\s+', text)
    
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 20:
            continue
            
        rule = _try_extract_rule(sentence, source_document, page_num)
        if rule:
            rules.append(rule)
    
    return rules


def _try_extract_rule(sentence, source_document, page_num):
    """Try to extract a structured rule from a single sentence."""
    
    # Extract rule ID if present
    rule_id_match = re.search(r'([\w.-]+)\s*:', sentence)
    
    # Extract monetary amounts
    amounts = re.findall(r'\$([\d,]+(?:\.\d{2})?)', sentence)
    amounts = [float(a.replace(',', '')) for a in amounts]
    
    # Extract time windows
    time_match = re.search(TIME_WINDOW_PATTERN, sentence, re.IGNORECASE)
    time_window = None
    if time_match:
        time_window = {
            "value": int(time_match.group(1)),
            "unit": time_match.group(2).lower(),
        }
    
    # Extract count thresholds
    count_match = re.search(COUNT_PATTERN, sentence, re.IGNORECASE)
    count_threshold = int(count_match.group(1)) if count_match else None
    
    # Determine rule type
    rule_type = _classify_rule_type(sentence, amounts, time_window, count_threshold)
    if not rule_type:
        return None
    
    # Build conditions
    conditions = _build_conditions(sentence, amounts, time_window, count_threshold, rule_type)
    if not conditions:
        return None
    
    # Determine severity
    severity = _extract_severity(sentence)
    
    # Generate rule ID
    if rule_id_match:
        rule_id = rule_id_match.group(1).strip()
        # Clean up and prefix
        rule_id = re.sub(r'[^a-zA-Z0-9.-]', '', rule_id)
    else:
        # Auto-generate from content hash
        content_hash = hashlib.md5(sentence.encode()).hexdigest()[:6]
        rule_id = f"AUTO-{content_hash}"
    
    # Clean rule name from sentence
    name = _extract_rule_name(sentence, rule_type)
    
    return {
        "rule_id": rule_id,
        "name": name,
        "source_document": source_document,
        "source_page": page_num,
        "source_text": sentence[:500],  # Truncate very long text
        "rule_type": rule_type,
        "conditions": conditions,
        "severity": severity,
        "version": "1.0",
        "status": "active",
        "extracted_at": datetime.now().isoformat(),
    }


def _classify_rule_type(sentence, amounts, time_window, count_threshold):
    """Classify what type of rule this sentence describes."""
    s = sentence.lower()
    
    # Velocity / structuring rules
    if time_window and (count_threshold or amounts):
        if any(w in s for w in ['structuring', 'smurfing', 'cumulative', 'velocity']):
            return "velocity"
        if count_threshold:
            return "velocity"
        if amounts and time_window:
            return "velocity"
    
    # Threshold rules (simple amount check)
    if amounts and not time_window and not count_threshold:
        if any(w in s for w in ['exceed', 'greater', 'more than', 'above', 'over', 'surpass']):
            return "threshold"
    
    # Pattern rules
    if any(w in s for w in ['round-trip', 'round trip', 'cycle', 'fan-out', 'fan-in',
                             'fan out', 'fan in', 'layering', 'self-transfer']):
        return "pattern"
    
    # Cross-border rules
    if any(w in s for w in ['cross-border', 'cross border', 'different jurisdiction',
                             'foreign', 'international']):
        return "cross_border"
    
    # Payment format rules
    if any(w in s for w in ['wire transfer', 'cheque', 'check', 'ach', 'cash']):
        if amounts:
            return "payment_format"
    
    # Dormant account rules
    if any(w in s for w in ['dormant', 'inactive', 'reactivat']):
        return "dormant_account"
    
    # If we have significant conditions but couldn't classify
    if amounts and any(w in s for w in ['flag', 'must', 'report', 'review', 'escalat']):
        return "threshold"
    
    return None


def _build_conditions(sentence, amounts, time_window, count_threshold, rule_type):
    """Build structured conditions from extracted components."""
    conditions = []
    s = sentence.lower()
    
    if rule_type == "threshold":
        if amounts:
            field = "amount_paid"
            if 'receiv' in s:
                field = "amount_received"
            conditions.append({
                "field": field,
                "operator": ">",
                "value": max(amounts),  # Use the primary threshold
            })
        # Check for payment format filter
        for fmt in ['cheque', 'wire', 'ach', 'cash', 'reinvestment']:
            if fmt in s:
                conditions.append({
                    "field": "payment_format",
                    "operator": "==",
                    "value": fmt.capitalize(),
                })

    elif rule_type == "velocity":
        if count_threshold:
            conditions.append({
                "field": "transaction_count",
                "operator": ">",
                "value": count_threshold,
            })
        if amounts:
            conditions.append({
                "field": "cumulative_amount",
                "operator": ">",
                "value": max(amounts),
            })
        if time_window:
            conditions.append({
                "field": "time_window",
                "operator": "within",
                "value": time_window,
            })
        # Direction
        if any(w in s for w in ['outgoing', 'sends', 'initiates', 'originating']):
            conditions.append({"field": "direction", "operator": "==", "value": "outgoing"})
        elif any(w in s for w in ['incoming', 'receives', 'receiving', 'inbound']):
            conditions.append({"field": "direction", "operator": "==", "value": "incoming"})

    elif rule_type == "cross_border":
        conditions.append({
            "field": "is_cross_border",
            "operator": "==",
            "value": True,
        })
        if amounts:
            conditions.append({
                "field": "amount_paid",
                "operator": ">",
                "value": min(amounts),
            })

    elif rule_type == "pattern":
        pattern_name = "unknown"
        if 'round-trip' in s or 'round trip' in s or 'cycle' in s:
            pattern_name = "round_trip"
        elif 'fan-out' in s or 'fan out' in s:
            pattern_name = "fan_out"
        elif 'fan-in' in s or 'fan in' in s:
            pattern_name = "fan_in"
        elif 'self-transfer' in s or 'self transfer' in s:
            pattern_name = "self_transfer"
        elif 'layer' in s:
            pattern_name = "layering"
        
        conditions.append({
            "field": "pattern",
            "operator": "matches",
            "value": pattern_name,
        })
        if time_window:
            conditions.append({
                "field": "time_window",
                "operator": "within",
                "value": time_window,
            })
        if amounts:
            conditions.append({
                "field": "amount_paid",
                "operator": ">",
                "value": min(amounts),
            })

    elif rule_type == "payment_format":
        for fmt in ['Wire', 'Cheque', 'ACH', 'Cash', 'Reinvestment']:
            if fmt.lower() in s:
                conditions.append({
                    "field": "payment_format",
                    "operator": "==",
                    "value": fmt,
                })
                break
        if amounts:
            conditions.append({
                "field": "amount_paid",
                "operator": ">",
                "value": max(amounts),
            })

    elif rule_type == "dormant_account":
        conditions.append({
            "field": "account_status",
            "operator": "==",
            "value": "dormant",
        })
        if amounts:
            conditions.append({
                "field": "amount_paid",
                "operator": ">",
                "value": max(amounts),
            })

    return conditions if conditions else None


def _extract_severity(sentence):
    """Extract severity level from sentence."""
    s = sentence.lower()
    if any(w in s for w in ['critical', 'immediate', 'urgent', '1 hour', 'known laundering']):
        return "critical"
    if any(w in s for w in ['high', 'escalat', '4 hour', 'senior']):
        return "high"
    if any(w in s for w in ['medium', 'moderate', '24 hour', 'review']):
        return "medium"
    if any(w in s for w in ['low', 'monitor', 'anomaly']):
        return "low"
    # Default based on content
    amounts = re.findall(r'\$([\d,]+)', sentence)
    if amounts:
        max_amt = max(float(a.replace(',', '')) for a in amounts)
        if max_amt >= 100000:
            return "critical"
        if max_amt >= 50000:
            return "high"
        if max_amt >= 10000:
            return "medium"
    return "medium"


def _extract_rule_name(sentence, rule_type):
    """Generate a human-readable rule name."""
    s = sentence.lower()
    type_labels = {
        "threshold": "Transaction Threshold",
        "velocity": "Velocity/Structuring",
        "cross_border": "Cross-Border",
        "pattern": "Behavioral Pattern",
        "payment_format": "Payment Format",
        "dormant_account": "Dormant Account",
    }
    base = type_labels.get(rule_type, "Compliance Rule")
    
    # Add specificity
    amounts = re.findall(r'\$([\d,]+)', sentence)
    if amounts:
        base += f" (${amounts[0]})"
    
    return base


def parse_policy_to_rules(policy_data):
    """Parse an ingested policy document into structured rules.
    
    Args:
        policy_data: Output from pdf_ingester.ingest_pdf()
        
    Returns:
        List of rule dicts
    """
    all_rules = []
    seen_ids = set()
    
    for page in policy_data.get("pages", []):
        rules = extract_rules_from_text(
            page["text"],
            source_document=policy_data.get("filename", ""),
            page_num=page["page_num"],
        )
        for rule in rules:
            # Deduplicate by rule_id
            if rule["rule_id"] not in seen_ids:
                seen_ids.add(rule["rule_id"])
                all_rules.append(rule)
    
    return all_rules
