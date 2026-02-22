import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

policies = {
    "01_AML_Core_Policy": """
# Anti-Money Laundering (AML) Compliance Policy v1.0

## 1. Introduction
This enterprise policy defines the core structural controls required to mitigate money laundering risks across all retail and institutional banking platforms.

[PAGEBREAK]

## 2. Threshold-Based Controls
The following hard limits must be placed on transaction flows:

- **Large Cash Transactions**: Any single transaction exceeding $15,000 USD must be immediately flagged for manual AML review by the compliance operations team.
- **Velocity Monitoring**: If a single customer orchestrates more than 10 separate transactions within a rolling 24-hour period, their account must be temporarily suspended for investigation.

[PAGEBREAK]

## 3. Account-Level Controls
- **Dormant Account Reactivation**: If an account has been dormant (0 transactions) for greater than 365 days, any subsequent transaction over $1,000 USD will automatically trigger an escalation to the risk team.

## 4. Enforcement
Violations of these thresholds will result in automated blockages natively enforced by the core banking engine.
""",
    
    "02_CrossBorder_Wire_Policy": """
# 1. Scope
This document outlines the monitoring parameters for Cross-Border Payments to prevent illicit international capital flight. 

[PAGEBREAK]

# 2. Key Corridors & Watchlists
Transactions originating from or destined to High-Risk Jurisdictions must be subjected to Enhanced Due Diligence (EDD).

- **Rule CB-01**: Any outward remittance exceeding €50,000 to non-cooperative jurisdictions (as defined by FATF) will be instantly halted.
- **Rule CB-02**: If a single customer initiates over 5 cross-border wire transfers in a 48-hour period, their international transfer privileges must be temporarily paused.

[PAGEBREAK]

# 3. Operations
The Swift operations desk must refer all halted transactions to the Level 2 AML review team for final disposition.
""",

    "03_ML_Governance": """
# Machine Learning Model Governance & Anomaly Constraints

As the organization adopts AI anomaly detection (via LightGBM features), we must impose hard deterministic fallbacks when models predict extreme outliers. These are safeguards to ensure ML models do not operate unchecked.

[PAGEBREAK]

## Governance Rules
1. If the ML Engine outputs an anomaly score (risk score) strictly greater than 0.95 for any single transaction, the final fused Alert must automatically be escalated to 'Critical' severity, regardless of rule engine findings.

[PAGEBREAK]

## Human in the Loop (HITL)
Transactions flagged by the ML model with scores > 0.8 but < 0.95 require manual verification by Level 1 analysts before an external SAR is generated.
""",

    "04_Network_Graph_Anomalies": """
# Network/Graph Anomaly Detection Policy v3.2

Our transaction network must be constantly scanned for structural anomalies that suggest layering or multi-hop laundering chains. We employ PageRank, cycle detection, and betweenness centrality to identify high-risk nodes.

[PAGEBREAK]

## Network Risk Thresholds
- **High PageRank**: Any account whose normalized network PageRank exceeds a centrality score of 0.85 must be flagged for secondary review, regardless of transaction volume.

[PAGEBREAK]

## Cycle and Mule Detection
- **Micro-Structuring Cycles**: Any cyclic transaction path (A -> B -> C -> A) that involves more than 3 accounts and totals greater than $5,000 USD within a single week is considered critical and must trigger an immediate asset block on all accounts involved.
"""
}

styles = getSampleStyleSheet()
styleN = styles["Normal"]
styleH1 = styles["Heading1"]
styleH2 = styles["Heading2"]

# Increase font sizes slightly for enterprise feel
styleN.fontSize = 11
styleN.leading = 14
styleH1.fontSize = 16
styleH2.fontSize = 13
styleH2.spaceBefore = 12
styleH2.spaceAfter = 6

base_dir = r"C:\Users\kusha\Desktop\sEM 6\Hackathon\Hackspace 2.0\Project\demo_policies"

for name, content in policies.items():
    pdf_path = os.path.join(base_dir, f"{name}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    story = []
    
    parts = content.strip().split("[PAGEBREAK]")
    
    for page_idx, page_content in enumerate(parts):
        lines = page_content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                story.append(Spacer(1, 12))
            elif line.startswith("# "):
                story.append(Paragraph(line[2:], styleH1))
                story.append(Spacer(1, 12))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], styleH2))
            elif line.startswith("- "):
                # Handle basic bolding in bullet points (rudimentary html translation for reportlab)
                text = line[2:]
                text = text.replace("**", "<b>", 1).replace("**", "</b>", 1)
                story.append(Paragraph(f"• {text}", styleN))
            else:
                story.append(Paragraph(line, styleN))
        
        if page_idx < len(parts) - 1:
            story.append(PageBreak())
            
    doc.build(story)
    print(f"Generated multi-page PDF: {pdf_path}")
