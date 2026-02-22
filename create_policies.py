#!/usr/bin/env python
"""Generate sample AML policy PDFs for testing the compliance agent."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from app.config import POLICIES_DIR


def create_aml_policy():
    """Create the main AML Transaction Monitoring Policy PDF."""
    filepath = os.path.join(POLICIES_DIR, "AML_Transaction_Monitoring_Policy.pdf")
    doc = SimpleDocTemplate(filepath, pagesize=letter,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                  fontSize=18, spaceAfter=20,
                                  textColor=HexColor('#1a237e'))
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
                                    fontSize=13, spaceAfter=10, spaceBefore=15,
                                    textColor=HexColor('#283593'))
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'],
                                 fontSize=10, spaceAfter=8, leading=14)
    rule_style = ParagraphStyle('RuleStyle', parent=styles['Normal'],
                                 fontSize=10, spaceAfter=6, leading=13,
                                 leftIndent=20, bulletIndent=10)

    elements = []

    # Title
    elements.append(Paragraph("ANTI-MONEY LAUNDERING (AML)<br/>TRANSACTION MONITORING POLICY", title_style))
    elements.append(Paragraph("Document Reference: AML-POL-2024-001 | Version 3.2 | Effective Date: January 1, 2024", body_style))
    elements.append(Spacer(1, 12))

    # Section 1
    elements.append(Paragraph("1. PURPOSE AND SCOPE", heading_style))
    elements.append(Paragraph(
        "This policy establishes the compliance framework for monitoring financial transactions "
        "in accordance with the Bank Secrecy Act (BSA), USA PATRIOT Act, and Financial Action Task Force (FATF) "
        "recommendations. All financial transactions processed through our systems must be screened "
        "against the rules defined herein. Violations must be reported to the compliance officer within 24 hours.",
        body_style))

    # Section 2 - Large Transaction Thresholds
    elements.append(Paragraph("2. LARGE TRANSACTION THRESHOLDS", heading_style))
    elements.append(Paragraph(
        "The following thresholds apply to all transaction types and must trigger automatic flagging:",
        body_style))
    elements.append(Paragraph("• <b>Rule 2.1</b>: Any single transaction where the amount paid exceeds $10,000 USD "
                               "(or equivalent in foreign currency) must be flagged for review and a Currency "
                               "Transaction Report (CTR) must be filed.", rule_style))
    elements.append(Paragraph("• <b>Rule 2.2</b>: Any single transaction where the amount paid exceeds $50,000 USD "
                               "must be flagged as HIGH severity and escalated to the Senior Compliance Officer "
                               "within 4 hours.", rule_style))
    elements.append(Paragraph("• <b>Rule 2.3</b>: Cross-border transactions where the amount exceeds $5,000 USD "
                               "must be flagged. A cross-border transaction is defined as a transaction where the "
                               "originating bank and receiving bank are in different jurisdictions.", rule_style))

    # Section 3 - Velocity / Structuring
    elements.append(Paragraph("3. STRUCTURING AND VELOCITY RULES", heading_style))
    elements.append(Paragraph(
        "Structuring (also known as 'smurfing') is the practice of breaking a large transaction into "
        "smaller ones to evade reporting thresholds. The following velocity rules detect potential structuring:",
        body_style))
    elements.append(Paragraph("• <b>Rule 3.1</b>: If a single account initiates more than 5 outgoing transfers "
                               "within a 24-hour period, the account must be flagged for structuring review.", rule_style))
    elements.append(Paragraph("• <b>Rule 3.2</b>: If a single account receives funds from more than 3 distinct "
                               "accounts within a 24-hour period, flag as potential layering activity (fan-in pattern).", rule_style))
    elements.append(Paragraph("• <b>Rule 3.3</b>: If the total cumulative amount of transactions from a single "
                               "account exceeds $20,000 USD within a 24-hour window, regardless of individual "
                               "transaction sizes, the account must be flagged for potential structuring.", rule_style))

    # Section 4 - Behavioral / Pattern
    elements.append(Paragraph("4. BEHAVIORAL AND PATTERN RULES", heading_style))
    elements.append(Paragraph(
        "The following rules target suspicious behavioral patterns indicative of money laundering:",
        body_style))
    elements.append(Paragraph("• <b>Rule 4.1</b>: Round-trip transactions — if funds are sent from Account A to "
                               "Account B and then returned from Account B to Account A within 7 days, "
                               "the transaction pair must be flagged.", rule_style))
    elements.append(Paragraph("• <b>Rule 4.2</b>: Rapid succession — if an account sends more than 3 transactions "
                               "within a 1-hour window, all transactions in that window must be flagged.", rule_style))
    elements.append(Paragraph("• <b>Rule 4.3</b>: Currency conversion anomaly — transactions involving conversion "
                               "between more than 2 different currencies within a single day from the same account "
                               "must be flagged.", rule_style))

    # Section 5 - Payment Format
    elements.append(Paragraph("5. PAYMENT FORMAT RULES", heading_style))
    elements.append(Paragraph("• <b>Rule 5.1</b>: Wire transfers exceeding $3,000 USD to a new beneficiary "
                               "(first-time recipient for the sender) must receive enhanced due diligence.", rule_style))
    elements.append(Paragraph("• <b>Rule 5.2</b>: Cheque payments exceeding $8,000 USD must be flagged. "
                               "Cheques are considered higher risk due to delayed clearing.", rule_style))

    # Section 6 - Severity Classification
    elements.append(Paragraph("6. SEVERITY CLASSIFICATION", heading_style))
    data = [
        ['Severity', 'Criteria', 'Response Time'],
        ['CRITICAL', 'Amount > $100,000 or known laundering pattern', '1 hour'],
        ['HIGH', 'Amount > $50,000 or multiple rule violations', '4 hours'],
        ['MEDIUM', 'Amount > $10,000 or velocity threshold breach', '24 hours'],
        ['LOW', 'Pattern anomaly below monetary thresholds', '48 hours'],
    ]
    table = Table(data, colWidths=[1.2*inch, 3.5*inch, 1.3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#283593')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f5f5f5'), HexColor('#ffffff')]),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    # Section 7
    elements.append(Paragraph("7. REPORTING AND AUDIT REQUIREMENTS", heading_style))
    elements.append(Paragraph(
        "All flagged transactions must be documented with: (a) the specific rule violated, "
        "(b) the evidence data supporting the violation, (c) the confidence score of the detection, "
        "and (d) any remediation actions taken. Monthly compliance summary reports must be generated "
        "for the Board of Directors. All records must be retained for a minimum of 5 years.",
        body_style))

    doc.build(elements)
    print(f"[Policy] ✅ Created: {filepath}")
    return filepath


def create_kyc_policy():
    """Create the KYC Account Verification Policy PDF."""
    filepath = os.path.join(POLICIES_DIR, "KYC_Account_Policy.pdf")
    doc = SimpleDocTemplate(filepath, pagesize=letter,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                  fontSize=18, spaceAfter=20,
                                  textColor=HexColor('#1b5e20'))
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
                                    fontSize=13, spaceAfter=10, spaceBefore=15,
                                    textColor=HexColor('#2e7d32'))
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'],
                                 fontSize=10, spaceAfter=8, leading=14)
    rule_style = ParagraphStyle('RuleStyle', parent=styles['Normal'],
                                 fontSize=10, spaceAfter=6, leading=13,
                                 leftIndent=20, bulletIndent=10)

    elements = []

    elements.append(Paragraph("KNOW YOUR CUSTOMER (KYC)<br/>ACCOUNT VERIFICATION POLICY", title_style))
    elements.append(Paragraph("Document Reference: KYC-POL-2024-001 | Version 2.1 | Effective Date: January 1, 2024", body_style))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("1. ENTITY VERIFICATION", heading_style))
    elements.append(Paragraph("• <b>Rule KYC-1.1</b>: All accounts must be associated with a verified entity "
                               "(Corporation, Sole Proprietorship, or Individual). Accounts without entity "
                               "verification must be restricted from transactions exceeding $1,000 USD.", rule_style))
    elements.append(Paragraph("• <b>Rule KYC-1.2</b>: Entities classified as 'Shell Company' or with entity names "
                               "containing 'Offshore' must undergo enhanced due diligence before any transaction "
                               "is processed.", rule_style))

    elements.append(Paragraph("2. DORMANT ACCOUNT RULES", heading_style))
    elements.append(Paragraph("• <b>Rule KYC-2.1</b>: An account is considered dormant if it has had no transactions "
                               "for 90 consecutive days. Dormant accounts that suddenly resume activity with "
                               "transactions exceeding $5,000 USD must be flagged for compliance review.", rule_style))
    elements.append(Paragraph("• <b>Rule KYC-2.2</b>: Dormant accounts that resume with more than 3 transactions "
                               "in the first 24 hours of reactivation must be escalated to HIGH severity.", rule_style))

    elements.append(Paragraph("3. ACCOUNT RELATIONSHIP RULES", heading_style))
    elements.append(Paragraph("• <b>Rule KYC-3.1</b>: If a single entity controls more than 10 accounts across "
                               "multiple banks, all transactions from those accounts must receive enhanced monitoring.", rule_style))
    elements.append(Paragraph("• <b>Rule KYC-3.2</b>: Self-transfers (same entity sending and receiving) that "
                               "exceed $15,000 USD must be flagged as potential layering.", rule_style))

    doc.build(elements)
    print(f"[Policy] ✅ Created: {filepath}")
    return filepath


if __name__ == "__main__":
    os.makedirs(POLICIES_DIR, exist_ok=True)
    create_aml_policy()
    create_kyc_policy()
    print("\n[Policy] All sample policies generated successfully!")
