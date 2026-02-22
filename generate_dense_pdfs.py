import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

policies = {
    "01_AML_Core_Policy_Detailed": """
# Global Anti-Money Laundering (AML) & Counter-Terrorist Financing (CTF) Enterprise Policy v3.4

## 1. Executive Summary and Scope
This document outlines the mandatory structural controls, thresholds, and governance required to mitigate illicit financial flows, money laundering (ML), and terrorist financing (TF) globally. The policies dictated herein apply absolutely to all retail banking, commercial lending, institutional wealth management, and digital asset custody platforms operated by the Group. 

All regional compliance officers are required to enforce these standards as a baseline. Where local jurisdictional law (e.g., BaFin, FCA, FinCEN, MAS) requires stricter limits, the local laws shall invariably supersede this internal document.

[PAGEBREAK]

## 2. Risk Appetite and Zero-Tolerance Framework
The Group operates strictly on a "Zero-Tolerance" framework regarding knowing and willful facilitation of financial crime. Any employee found actively circumventing these controls is subject to immediate dismissal and referral to law enforcement.

The Risk Appetite Statement (RAS), approved by the Board of Directors on Q1 2025, requires our transaction monitoring systems to maintain a False Positive rate of less than 85% and a True Positive conversion rate to SARs of no less than 4.5%.

## 3. Core Domestic Threshold-Based Controls
The following hard limits must be operationalized within the Core Banking Engine (CBE) and the automated Transaction Monitoring System (TMS). These limits cannot be overridden without explicit sign-off from a Managing Director (MD) of Compliance.

### 3.1. Currency Transaction Reports (CTR) and Large Cash Movements
Cash continues to represent the highest vector for placement-stage money laundering.
- **Rule AML-101**: Any single physical cash deposit, withdrawal, or exchange exceeding $10,000 USD (or local equivalent) must automatically generate a Currency Transaction Report (CTR) within 24 hours of the clearing date.
- **Rule AML-102**: Any aggregate cash transactions by a single customer entity that sum to greater than $15,000 USD over a rolling 3-day window must trigger a mandatory Level 2 AML analyst review.

[PAGEBREAK]

### 3.2. Structuring and Smurfing Topologies
Violators frequently attempt to evade the $10,000 CTR limit by breaking cash deposits into smaller chunks (structuring).
- **Rule AML-103**: If a customer orchestrates 3 or more separate cash deposits exactly between $9,000 and $9,999 USD within a 7-day window, the system must immediately auto-file a Suspicious Activity Report (SAR) citing "Potential Structuring."
- **Rule AML-104**: Consecutive ATM withdrawals totaling over $5,000 USD across 5 or more different ATM terminals within a 12-hour window must result in an immediate temporary card freeze.

## 4. Account Velocity and Behavioral Baselines
Accounts deviating from normal expected activity must be flagged.

- **Rule AML-201 (High Velocity)**: If an account orchestrates more than 50 separate incoming transfers in a rolling 24-hour period, their account must be transitioned to "Restricted-Receive-Only" status pending investigation.
- **Rule AML-202 (Rapid Drain)**: If an account receives a wire transfer exceeding $100,000 USD and then subsequently transfers out 90% or more of that principal balance within exactly 2 hours, it must trigger a "Pass-Through" critical alert.

[PAGEBREAK]

## 5. Account Lifecycle Management
Dormant or historically inactive accounts represent a unique risk when suddenly reactivated.

- **Rule AML-301 (Dormant Reactivation)**: If a corporate account has exhibited 0 transaction volume (complete dormancy) for greater than 365 days, any subsequent outbound transaction over $2,500 USD must be held in quarantine for 48 hours and requires two-factor telephonic verification from the primary signatory.

## 6. Audit and Testing Frequency
The automated implementation of these rules must be validated against a golden-source test dataset quarterly. Findings from the internal audit teams must be remediated within 30 days.
""",
    
    "02_CrossBorder_Wire_Policy_Detailed": """
# Cross-Border Payment and SWIFT Message Screening Protocol v2.1

## 1. Introduction to Jurisdiction Risk
Cross-border payments inherently carry a geometric increase in AML/CTF exposure compared to domestic rails. The lack of standard international KYC homogenization necessitates aggressive defensive posturing on our Nostro and Vostro clearing accounts.

## 2. FATF High-Risk and Non-Cooperative Jurisdictions
The Financial Action Task Force (FATF) routinely publishes the "Black List" and "Grey List". The Group dynamically subscribes to these feeds via an API connection to the World-Check database.

[PAGEBREAK]

### 2.1. Absolute Prohibitions (Black List)
Transactions involving North Korea (DPRK), Iran, and Myanmar are strictly prohibited.
- **Rule CB-001**: Any transaction, regardless of size, originating from, destined to, or routing through a sanctioned FATF Blacklist country must be instantly and permanently rejected by the SWIFT gateway.

### 2.2. Enhanced Due Diligence (Grey List)
Transactions involving jurisdictions under increased monitoring require heightened scrutiny.
- **Rule CB-101**: Any outward remittance exceeding €25,000 destined for a FATF Grey-Listed jurisdiction must be held in a suspense account until a Level 2 Risk Officer manually clears the beneficiary.
- **Rule CB-102**: If a single customer initiates over 5 cross-border wire transfers to any combination of Grey-Listed nations within a 48-hour period, their international transfer privileges must be suspended.

[PAGEBREAK]

## 3. High-Risk Corridors and Trade-Based ML (TBML)
Trade-based money laundering often involves exploiting specific geographic corridors known for drug trafficking or illicit goods.

- **Rule CB-201**: Foreign Exchange (FX) transactions above $100,000 USD equivalent where the source currency is MXN, COP, or RUB MUST trigger a manual review within 2 hours.
- **Rule CB-202**: Any payment referencing "scrap metal", "precious gems", or "used automobiles" in the SWIFT MT103 field 70 (Remittance Information) exceeding $50,000 USD must generate a TBML flag.

## 4. Correspondent Banking Anomalies
We must monitor the behavior of respondent banks utilizing our infrastructure.
- **Rule CB-301**: If a respondent bank's monthly wire volume experiences a sudden week-over-week spike exceeding 300% moving average, funding must be paused pending a request for information (RFI) regarding the source of the sustained volume.
""",

    "03_ML_Governance_Detailed": """
# Artificial Intelligence & Machine Learning (AI/ML) Governance Framework

## 1. Purpose of the Framework
As the bank modernizes its compliance tech stack, we are increasingly relying on unsupervised and supervised Machine Learning (e.g., LightGBM, Random Forests, Autoencoders) to detect unknown, non-linear laundering networks. 

However, regulatory expectations demand explainability. "Black-box" decisions cannot unilaterally freeze assets without a deterministic safety net. This policy establishes the hard guardrails around our AI deployments.

[PAGEBREAK]

## 2. ML System Calibration and Drift
Models must be constantly monitored for concept drift. 
Baseline model metrics require minimum precision of 80% and recall of 90% during backtesting. If the daily feedback loop indicates that the True Positive rate of model-generated alerts drops below 5% over a 14-day window, the model must be taken offline and the backup rules-engine must assume primary processing.

## 3. Deterministic Overrides and Governance Rules
We must impose hard constraints on how ML outputs are utilized in production. Model outputs are typically expressed as an "Anomaly Score" ranging from 0.0 (normal) to 1.0 (highly anomalous).

### 3.1. Critical Anomalies
- **Rule MLG-01**: If the LightGBM Engine outputs an anomaly risk score strictly greater than 0.95 for any single transaction, the final fused Alert must automatically be escalated to 'Critical' severity, and the corresponding user account must be subjected to an automatic soft-freeze.
- **Rule MLG-02**: If an account receives 3 or more transactions within 24 hours that all score > 0.85 by the ML Engine, an immediate SAR must be drafted.

[PAGEBREAK]

### 3.2. Model Degradation Protocols
- **Rule MLG-03**: In the event the data science platform reports a model drift alert (where feature drift > 15%), all anomaly scores between 0.80 and 0.95 will be automatically suppressed (ignored) until the model is formally retrained, to prevent false positive flooding.

## 4. Human in the Loop (HITL) Requirements
Automated machine decisions cannot result in external regulatory filings without human oversight.
- **Rule MLG-04**: Transactions flagged by the ML model with scores between 0.80 and 0.95 require manual verification by Level 1 analysts, who must document their reasoning before releasing the funds or filing a SAR.
""",

    "04_Network_Graph_Anomalies_Detailed": """
# Network Intelligence and Graph Anomaly Detection Standard

## 1. Graph Data Architecture
Launderers operate in networks. Analyzing isolated transactions is insufficient. The bank has deployed a Graph Convolutional Network (GCN) built on top of a neo4j datastore to analyze edges (transactions) and nodes (accounts). 

Our graph operates dynamically, refreshing centrality metrics, community partitions (Louvain), and shortest-path topologies every 15 minutes.

[PAGEBREAK]

## 2. Centrality and Node Importance Thresholds
Accounts that act as central hubs or crucial bridges within the transaction graph pose intense systemic risk.

- **Rule NET-01 (High PageRank)**: Any account whose normalized network PageRank exceeds a centrality score of 0.85 must be automatically flagged for secondary review, regardless of its total transaction volume or dollar value.
- **Rule NET-02 (Betweenness Centrality)**: If an account's betweenness centrality score spikes by more than 50% in a 7-day period, indicating it has suddenly become a critical bridge between previously disconnected communities, a "Bridge Node" alert must be generated.

[PAGEBREAK]

## 3. Topologies of Laundering
Specific structural configurations in the graph strongly correlate with placement and layering techniques.

### 3.1. Cyclical Transfers
- **Rule NET-03 (Micro-Structuring Cycles)**: Any fully closed cyclical transaction path (e.g., A -> B -> C -> D -> A) that involves more than 3 distinct accounts and where the total flow exceeds $5,000 USD within a single week is considered critical. This must trigger an immediate asset block on all accounts involved in the cycle.

### 3.2. Funnel Accounts and Money Mules
- **Rule NET-04 (Mule Hubs)**: Individual retail accounts that receive incoming funds from more than 50 distinct sender accounts in a 24-hour window, and subsequently disburse 90% or more of those total funds outward within exactly 1 hour to an overseas entity, are highly indicative of money mule aggregators. These accounts will be immediately locked and designated "High Risk Hubs."

## 4. Remediation
Network alerts are often complex and require specialized investigators trained in network analysis tools. Standard Level 1 analysts must instantly escalate any 'Critical' network alerts to the Financial Intelligence Unit (FIU).
"""
}

styles = getSampleStyleSheet()
styleN = styles["Normal"]
styleH1 = styles["Heading1"]
styleH2 = styles["Heading2"]
styleH3 = styles["Heading3"]

# Enterprise font sizing
styleN.fontSize = 11
styleN.leading = 15
styleN.spaceAfter = 8

styleH1.fontSize = 18
styleH1.leading = 22
styleH1.spaceAfter = 16

styleH2.fontSize = 14
styleH2.leading = 18
styleH2.spaceBefore = 16
styleH2.spaceAfter = 12

styleH3.fontSize = 12
styleH3.leading = 16
styleH3.spaceBefore = 12
styleH3.spaceAfter = 8
styleH3.textColor = colors.HexColor("#333333")

base_dir = r"C:\Users\kusha\Desktop\sEM 6\Hackathon\Hackspace 2.0\Project\demo_policies"
if not os.path.exists(base_dir):
    os.makedirs(base_dir)

for name, content in policies.items():
    pdf_path = os.path.join(base_dir, f"{name}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                            rightMargin=50, leftMargin=50,
                            topMargin=50, bottomMargin=50)
    story = []
    
    parts = content.strip().split("[PAGEBREAK]")
    
    for page_idx, page_content in enumerate(parts):
        lines = page_content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            elif line.startswith("# "):
                story.append(Paragraph(line[2:], styleH1))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], styleH2))
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], styleH3))
            elif line.startswith("- "):
                text = line[2:]
                text = text.replace("**", "<b>", 1).replace("**", "</b>", 1)
                story.append(Paragraph(f"• {text}", styleN))
            else:
                story.append(Paragraph(line, styleN))
        
        if page_idx < len(parts) - 1:
            story.append(PageBreak())
            
    doc.build(story)
    print(f"Generated comprehensive multi-page PDF: {pdf_path}")
