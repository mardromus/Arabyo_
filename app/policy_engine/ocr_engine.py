"""OCR fallback engine for scanned PDF pages.

Uses Tesseract OCR via pytesseract with image preprocessing.
Gracefully degrades if system dependencies are not installed.
"""
import os
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional dependency detection ──────────────────────────────────
HAS_TESSERACT = False
HAS_PDF2IMAGE = False

try:
    import pytesseract
    # Quick check: can we call tesseract?
    pytesseract.get_tesseract_version()
    HAS_TESSERACT = True
except Exception:
    logger.info("pytesseract/Tesseract not available — OCR disabled")

try:
    from pdf2image import convert_from_path
    HAS_PDF2IMAGE = True
except ImportError:
    logger.info("pdf2image not available — scanned-PDF conversion disabled")

try:
    from PIL import Image, ImageFilter, ImageOps
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ── Text Density Heuristic ─────────────────────────────────────────
MIN_CHARS_PER_PAGE = 50  # Pages with fewer chars are considered scanned


def is_page_scanned(text: str) -> bool:
    """Heuristic: a page with very little extractable text is likely scanned."""
    cleaned = re.sub(r"\s+", "", text)
    return len(cleaned) < MIN_CHARS_PER_PAGE


def ocr_available() -> bool:
    """Check whether OCR is available on this system."""
    return HAS_TESSERACT and HAS_PDF2IMAGE and HAS_PIL


# ── Image Preprocessing ───────────────────────────────────────────

def preprocess_image(image: "Image.Image") -> "Image.Image":
    """Apply preprocessing to improve OCR accuracy.
    
    Steps: grayscale → auto-contrast → sharpen → binarize
    """
    if not HAS_PIL:
        return image

    # Convert to grayscale
    img = image.convert("L")

    # Auto-contrast (improves faded scans)
    img = ImageOps.autocontrast(img, cutoff=1)

    # Sharpen to enhance text edges
    img = img.filter(ImageFilter.SHARPEN)

    # Binarize with adaptive-like thresholding
    threshold = 140
    img = img.point(lambda p: 255 if p > threshold else 0, mode="1")

    return img


# ── Core OCR Functions ─────────────────────────────────────────────

def ocr_image(image: "Image.Image", lang: str = "eng") -> dict:
    """Run Tesseract OCR on a single PIL image.
    
    Returns:
        dict with 'text' and 'confidence' keys
    """
    if not HAS_TESSERACT:
        return {"text": "", "confidence": 0.0}

    # Preprocess
    processed = preprocess_image(image)

    # Extract text
    text = pytesseract.image_to_string(processed, lang=lang)

    # Get per-word confidence data
    try:
        data = pytesseract.image_to_data(processed, lang=lang,
                                          output_type=pytesseract.Output.DICT)
        confidences = [int(c) for c in data["conf"] if int(c) > 0]
        avg_conf = sum(confidences) / len(confidences) / 100.0 if confidences else 0.0
    except Exception:
        avg_conf = 0.5  # Fallback confidence

    return {
        "text": text.strip(),
        "confidence": round(avg_conf, 3),
    }


def ocr_pdf_page(pdf_path: str, page_num: int, lang: str = "eng",
                  dpi: int = 300) -> dict:
    """OCR a single page of a PDF.
    
    Args:
        pdf_path: Path to the PDF file
        page_num: 1-indexed page number
        lang: Tesseract language code
        dpi: Resolution for PDF-to-image conversion
        
    Returns:
        dict with 'text', 'confidence', 'ocr_used' keys
    """
    if not ocr_available():
        return {"text": "", "confidence": 0.0, "ocr_used": False}

    try:
        # Convert single page to image (1-indexed first/last)
        images = convert_from_path(
            pdf_path,
            first_page=page_num,
            last_page=page_num,
            dpi=dpi,
        )
        if not images:
            return {"text": "", "confidence": 0.0, "ocr_used": False}

        result = ocr_image(images[0], lang=lang)
        result["ocr_used"] = True
        return result

    except Exception as e:
        logger.warning(f"OCR failed for page {page_num} of {pdf_path}: {e}")
        return {"text": "", "confidence": 0.0, "ocr_used": False}


def ocr_full_pdf(pdf_path: str, lang: str = "eng",
                  dpi: int = 300) -> list[dict]:
    """OCR all pages of a PDF.
    
    Returns:
        List of dicts per page with 'page_num', 'text', 'confidence', 'ocr_used'
    """
    if not ocr_available():
        logger.warning("OCR not available — returning empty results")
        return []

    try:
        images = convert_from_path(pdf_path, dpi=dpi)
    except Exception as e:
        logger.error(f"Failed to convert PDF to images: {e}")
        return []

    results = []
    for i, img in enumerate(images):
        r = ocr_image(img, lang=lang)
        results.append({
            "page_num": i + 1,
            "text": r["text"],
            "confidence": r["confidence"],
            "ocr_used": True,
        })

    return results
