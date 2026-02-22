"""PDF policy document ingestion using pdfplumber."""
import pdfplumber
import os
import re
from datetime import datetime


def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file, page by page.
    
    Returns:
        dict with keys: filename, pages (list of {page_num, text}), 
              full_text, page_count, metadata
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    filename = os.path.basename(pdf_path)
    pages = []
    full_text_parts = []

    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages):
            text = page.extract_text() or ""
            # Clean up common OCR/extraction artifacts
            text = re.sub(r'\s+', ' ', text).strip()
            text = text.replace('\x00', '')
            
            pages.append({
                "page_num": i + 1,
                "text": text,
            })
            full_text_parts.append(text)

    return {
        "filename": filename,
        "filepath": pdf_path,
        "pages": pages,
        "full_text": "\n\n".join(full_text_parts),
        "page_count": len(pages),
        "extracted_at": datetime.now().isoformat(),
    }


def extract_sections(full_text):
    """Split extracted text into logical sections based on headings.
    
    Looks for patterns like "1. SECTION TITLE", "SECTION TITLE", numbered headings, etc.
    """
    # Pattern: number + dot + space + UPPERCASE WORDS
    section_pattern = r'(\d+\.?\s+[A-Z][A-Z\s&,/()-]+)'
    
    parts = re.split(section_pattern, full_text)
    
    sections = []
    current_title = "PREAMBLE"
    current_text = ""

    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Check if this part looks like a section heading
        if re.match(r'^\d+\.?\s+[A-Z]', part) and len(part) < 100:
            # Save previous section
            if current_text.strip():
                sections.append({
                    "title": current_title.strip(),
                    "text": current_text.strip(),
                })
            current_title = part
            current_text = ""
        else:
            current_text += " " + part

    # Save last section
    if current_text.strip():
        sections.append({
            "title": current_title.strip(),
            "text": current_text.strip(),
        })

    return sections


def ingest_pdf(pdf_path):
    """Full ingestion pipeline: extract text → split sections → return structured data."""
    extraction = extract_text_from_pdf(pdf_path)
    sections = extract_sections(extraction["full_text"])
    
    return {
        **extraction,
        "sections": sections,
    }
