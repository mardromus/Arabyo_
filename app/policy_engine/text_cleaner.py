"""Text cleaning pipeline for policy document text.

Normalizes whitespace, removes headers/footers/page numbers,
segments sentences, and detects clause boundaries.
"""
import re
from collections import Counter
from typing import Optional


# ── Header/Footer Detection ───────────────────────────────────────

def _detect_repeated_lines(pages: list[dict], threshold: float = 0.5) -> set[str]:
    """Identify lines that appear on many pages (likely headers/footers).
    
    A line appearing on > threshold fraction of pages is flagged.
    """
    if not pages:
        return set()

    line_counter: Counter = Counter()
    for page in pages:
        # Deduplicate lines within a page before counting
        unique_lines = set()
        for line in page.get("text", "").split("\n"):
            normalized = re.sub(r"\s+", " ", line.strip().lower())
            if len(normalized) > 3:
                unique_lines.add(normalized)
        line_counter.update(unique_lines)

    min_count = max(2, int(len(pages) * threshold))
    return {line for line, count in line_counter.items() if count >= min_count}


# ── Page Number Removal ───────────────────────────────────────────

PAGE_NUM_PATTERNS = [
    r"^\s*-?\s*\d{1,4}\s*-?\s*$",                    # standalone "3", "- 3 -"
    r"^\s*page\s+\d{1,4}\s*(of\s+\d{1,4})?\s*$",     # "Page 3 of 10"
    r"^\s*\d{1,4}\s*/\s*\d{1,4}\s*$",                 # "3/10"
]


def _remove_page_numbers(text: str) -> str:
    """Remove standalone page number lines."""
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        is_page_num = any(
            re.match(p, line.strip(), re.IGNORECASE) for p in PAGE_NUM_PATTERNS
        )
        if not is_page_num:
            cleaned.append(line)
    return "\n".join(cleaned)


# ── Whitespace Normalization ──────────────────────────────────────

def _normalize_whitespace(text: str) -> str:
    """Normalize spaces, tabs, and excessive newlines."""
    # Replace tabs with spaces
    text = text.replace("\t", " ")
    # Collapse multiple spaces into one
    text = re.sub(r"[ ]{2,}", " ", text)
    # Collapse 3+ newlines into 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Remove trailing whitespace per line
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines)


# ── Sentence Segmentation ────────────────────────────────────────

SENTENCE_END = re.compile(
    r"(?<=[.!?;])"            # After punctuation
    r"(?:\s+)"                # Followed by whitespace
    r"(?=[A-Z\d•\-\(\[])"    # Followed by capital letter, digit, bullet, etc.
)

CLAUSE_MARKERS = re.compile(
    r"(?:^|\n)\s*"
    r"(?:"
    r"(?:\d+[\.\)]\s+)"           # "1. " or "1) "
    r"|(?:[a-z][\.\)]\s+)"       # "a. " or "a) "
    r"|(?:[ivxlc]+[\.\)]\s+)"    # "iii. "
    r"|(?:•\s+)"                  # bullet
    r"|(?:[-–—]\s+)"             # dash
    r"|(?:Rule\s+[\w.-]+\s*:)"   # Rule ID: 
    r")",
    re.IGNORECASE,
)


def segment_sentences(text: str) -> list[str]:
    """Split text into individual sentences/clauses.
    
    Uses punctuation-based splitting with awareness of abbreviations
    and common policy document formatting.
    """
    if not text.strip():
        return []

    # First split on obvious clause markers (numbered items, bullets)
    parts = CLAUSE_MARKERS.split(text)
    
    sentences = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Further split on sentence-ending punctuation
        sub_sentences = SENTENCE_END.split(part)
        for s in sub_sentences:
            s = s.strip()
            if len(s) >= 15:  # Minimum meaningful sentence length
                sentences.append(s)
    
    return sentences


def detect_clauses(text: str) -> list[dict]:
    """Detect clause boundaries with positional info.
    
    Returns list of dicts with 'text', 'start_char', 'end_char', 'clause_id'.
    """
    clauses = []
    # Pattern: numbered or lettered items
    pattern = re.compile(
        r"(?:(?:^|\n)\s*"
        r"(?:\d+[\.\)]\s+|[a-z][\.\)]\s+|[ivxlc]+[\.\)]\s+|•\s+|[-–—]\s+|Rule\s+[\w.-]+\s*:\s*)"
        r")"
        r"(.*?)(?=(?:\n\s*(?:\d+[\.\)]\s|[a-z][\.\)]\s|•\s|[-–—]\s|Rule\s))|$)",
        re.DOTALL | re.IGNORECASE,
    )

    for i, match in enumerate(pattern.finditer(text)):
        clause_text = match.group(0).strip()
        if len(clause_text) >= 15:
            clauses.append({
                "text": clause_text,
                "start_char": match.start(),
                "end_char": match.end(),
                "clause_id": f"clause_{i+1}",
            })

    # If no structured clauses found, treat whole paragraphs as clauses
    if not clauses:
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        offset = 0
        for i, para in enumerate(paragraphs):
            start = text.find(para, offset)
            clauses.append({
                "text": para,
                "start_char": start,
                "end_char": start + len(para),
                "clause_id": f"para_{i+1}",
            })
            offset = start + len(para)

    return clauses


# ── Main Cleaning Pipeline ────────────────────────────────────────

def clean_page_text(text: str, repeated_lines: Optional[set[str]] = None) -> str:
    """Clean a single page of extracted text.
    
    Args:
        text: Raw extracted text
        repeated_lines: Set of normalized lines to remove (headers/footers)
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""

    # Remove NUL bytes and control characters
    text = text.replace("\x00", "")
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", text)

    # Remove page numbers
    text = _remove_page_numbers(text)

    # Remove repeated header/footer lines
    if repeated_lines:
        lines = text.split("\n")
        cleaned_lines = []
        for line in lines:
            normalized = re.sub(r"\s+", " ", line.strip().lower())
            if normalized not in repeated_lines:
                cleaned_lines.append(line)
        text = "\n".join(cleaned_lines)

    # Normalize whitespace
    text = _normalize_whitespace(text)

    return text.strip()


def clean_document(pages: list[dict]) -> list[dict]:
    """Clean all pages of a document.
    
    Args:
        pages: List of page dicts with 'page_num' and 'text' keys
        
    Returns:
        List of cleaned page dicts with added 'sentences' and 'clauses'
    """
    # Detect repeated lines across pages
    repeated = _detect_repeated_lines(pages)

    cleaned_pages = []
    for page in pages:
        clean_text = clean_page_text(page["text"], repeated)
        sentences = segment_sentences(clean_text)
        clauses = detect_clauses(clean_text)

        cleaned_pages.append({
            "page_num": page["page_num"],
            "text": clean_text,
            "original_text": page["text"],
            "sentences": sentences,
            "clauses": clauses,
        })

    return cleaned_pages
