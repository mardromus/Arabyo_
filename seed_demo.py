"""
Demo data seeder for Railway/cloud deployments.
Auto-seeds synthetic AML transactions, accounts, alerts and rules
when the database is empty, so the dashboard has data to show.

Called automatically from routes.py on startup if transactions table is empty.
"""
import random
import json
from datetime import datetime, timedelta


BANKS = ["CHASE", "HSBC", "BARCLAYS", "DEUTSCHE", "CITI", "SANTANDER", "UBS", "BNP", "WELLS", "NOMURA"]
CURRENCIES = ["USD", "EUR", "GBP", "CHF", "JPY", "SGD", "AED", "HKD"]
FORMATS = ["Wire", "ACH", "SWIFT", "Cash", "Cheque", "Credit Card", "Crypto"]
PATTERNS = {
    "structuring": ("Structured cash deposits just below $10k reporting threshold", "high"),
    "layering":    ("Rapid cross-border wire layering through shell accounts", "critical"),
    "smurfing":    ("Multiple small amounts from different senders to one account", "high"),
    "round_trip":  ("Funds return to originator via circular route", "critical"),
    "dormant":     ("Sudden large transaction from previously dormant account", "medium"),
    "normal":      ("Routine business payment within expected parameters", "low"),
}

ALERT_RULES = [
    ("AML-001", "Large Cash Transaction >$10k", "threshold", "high"),
    ("AML-002", "Rapid Velocity: >20 tx in 24h", "velocity", "high"),
    ("AML-003", "Cross-Border High-Risk Jurisdiction", "cross_border", "critical"),
    ("AML-004", "Round-Trip Circular Flow", "pattern", "critical"),
    ("AML-005", "Structuring Below Threshold", "pattern", "medium"),
]


def _rand_account():
    return f"ACC-{random.randint(100000, 999999)}"


def _rand_date(days_back=90):
    base = datetime.now() - timedelta(days=random.randint(0, days_back))
    return base.strftime("%Y-%m-%d %H:%M:%S")


def seed_demo_data():
    """Seed synthetic demo data if transactions table is empty."""
    try:
        from app.db import get_connection, execute, query, init_db
        import sqlite3

        init_db()
        conn = get_connection()

        # Check if already seeded
        rows = query("SELECT COUNT(*) as cnt FROM transactions")
        if rows and rows[0].get("cnt", 0) > 0:
            return  # already has data

        print("[seed] Seeding demo data for Railway deployment...")
        random.seed(42)

        # ── 1. Insert accounts ────────────────────────────────────────────
        accounts = []
        for i in range(60):
            bank = random.choice(BANKS)
            acc = _rand_account()
            accounts.append((bank, acc))
            execute(
                "INSERT OR IGNORE INTO accounts (bank_name, bank_id, account_number, entity_id, entity_name) VALUES (%s,%s,%s,%s,%s)",
                [bank, f"BNK-{i:03d}", acc, f"ENT-{i:03d}", f"Entity {i:03d} Ltd"]
            )

        # ── 2. Insert transactions ────────────────────────────────────────
        tx_ids = []
        for i in range(500):
            from_bank, from_acc = random.choice(accounts)
            to_bank, to_acc = random.choice(accounts)
            while to_acc == from_acc:
                to_bank, to_acc = random.choice(accounts)

            # 8% laundering rate
            is_launder = 1 if random.random() < 0.08 else 0
            if is_launder:
                amount = random.choice([
                    random.uniform(9000, 9999),   # structuring
                    random.uniform(50000, 500000), # large
                    random.uniform(100, 500),      # smurfing
                ])
            else:
                amount = random.uniform(500, 25000)

            currency = random.choice(CURRENCIES)
            fmt = random.choice(FORMATS)
            ts = _rand_date()

            execute(
                """INSERT INTO transactions
                   (timestamp, from_bank, from_account, to_bank, to_account,
                    amount_received, receiving_currency, amount_paid, payment_currency,
                    payment_format, is_laundering)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                [ts, from_bank, from_acc, to_bank, to_acc,
                 round(amount, 2), currency, round(amount * random.uniform(0.97, 1.03), 2),
                 currency, fmt, is_launder]
            )
            rows = query("SELECT last_insert_rowid() as id")
            if rows:
                tx_ids.append((rows[0]["id"], from_acc, is_launder))

        # ── 3. Insert alerts ──────────────────────────────────────────────
        alert_candidates = [(tid, acc, il) for tid, acc, il in tx_ids if il == 1]
        # Also add some false positives
        non_launder = [(tid, acc, il) for tid, acc, il in tx_ids if il == 0]
        alert_candidates += random.sample(non_launder, min(15, len(non_launder)))
        random.shuffle(alert_candidates)

        severities = ["critical", "high", "medium", "low"]
        statuses = ["pending", "pending", "pending", "dismissed", "escalated"]

        for tx_id, acc_id, is_launder in alert_candidates[:50]:
            rule_id, rule_name, rule_type, sev = random.choice(ALERT_RULES)
            if is_launder:
                sev = random.choice(["critical", "high", "high", "medium"])
            else:
                sev = random.choice(["medium", "low", "low"])

            ml_score = round(random.uniform(0.6, 0.95) if is_launder else random.uniform(0.1, 0.4), 3)
            graph_score = round(random.uniform(0.4, 0.9) if is_launder else random.uniform(0.05, 0.3), 3)
            rule_score = round(random.uniform(0.5, 1.0) if is_launder else random.uniform(0.1, 0.5), 3)
            fusion = round((ml_score * 0.35 + graph_score * 0.25 + rule_score * 0.40), 3)

            status = random.choice(statuses)
            ts = _rand_date()

            triggered = json.dumps([{
                "rule_id": rule_id,
                "rule_name": rule_name,
                "rule_type": rule_type,
                "severity": sev,
                "score": rule_score
            }])

            explanation = json.dumps({
                "summary": f"Account {acc_id} triggered {rule_name}. ML risk score: {ml_score:.0%}. Graph centrality elevated.",
                "risk_factors": [
                    {"factor": rule_name, "score": rule_score, "weight": 0.40},
                    {"factor": "ML Anomaly Score", "score": ml_score, "weight": 0.35},
                    {"factor": "Graph Centrality", "score": graph_score, "weight": 0.25},
                ],
                "policy_citations": [f"{rule_id}: {rule_name}"],
                "recommendation": "Investigate transaction history and counterparty relationships."
            })

            execute(
                """INSERT INTO alerts
                   (transaction_id, account_id, rule_score, ml_score, graph_score,
                    fusion_score, severity, status, triggered_rules, explanation, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                [tx_id, acc_id, rule_score, ml_score, graph_score,
                 fusion, sev, status, triggered, explanation, ts]
            )

        # ── 4. Insert demo rules ──────────────────────────────────────────
        # First ensure a legacy policy version exists
        execute(
            """INSERT OR IGNORE INTO policy_versions
               (version_id, policy_id, version_number, status, created_by, rule_count)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            ["legacy-v0.0", "demo-policy-001", "v1.0", "active", "system", len(ALERT_RULES)]
        )

        for rule_id, rule_name, rule_type, severity in ALERT_RULES:
            conditions = json.dumps([{
                "metric": "transaction_amount" if rule_type == "threshold" else "transaction_count",
                "operator": ">=",
                "value": 10000 if rule_type == "threshold" else 20,
                "window": None if rule_type == "threshold" else "24h"
            }])
            execute(
                """INSERT OR IGNORE INTO rules
                   (id, version_id, name, rule_type, conditions, severity, status, confidence, source_document)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                [rule_id, "legacy-v0.0", rule_name, rule_type, conditions, severity, "active", 0.95, "AML Policy Manual v1.0"]
            )

        conn._conn.commit()
        print(f"[seed] ✓ Seeded: 500 transactions, {len(alert_candidates[:50])} alerts, {len(ALERT_RULES)} rules, 60 accounts")

    except Exception as e:
        print(f"[seed] Warning (non-fatal): {e}")
