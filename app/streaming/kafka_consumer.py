"""
Kafka consumer: subscribe to transactions.incoming, validate -> DB insert -> rule/ML/graph -> fusion -> produce to scored/alerts.
Runs as a separate process (e.g. python -m app.streaming.kafka_consumer) or can be started from a runner script.
"""
import json
import logging
import time
from typing import Optional

from app.streaming.kafka_config import (
    KAFKA_TOPIC_INCOMING,
    KAFKA_TOPIC_SCORED,
    KAFKA_TOPIC_ALERTS,
    get_consumer_config,
)
from app.streaming.schema import TransactionEvent
from app.streaming.metrics import record_latency, record_processed, record_failed

logger = logging.getLogger(__name__)

try:
    from confluent_kafka import Consumer, Producer
    _KAFKA_AVAILABLE = True
except ImportError:
    Consumer = Producer = None
    _KAFKA_AVAILABLE = False


def _insert_transaction(row: dict) -> Optional[int]:
    """Insert one transaction row; returns new id or None."""
    from app.db import execute
    sql = """
        INSERT INTO transactions (timestamp, from_bank, from_account, to_bank, to_account,
            amount_received, receiving_currency, amount_paid, payment_currency, payment_format, is_laundering)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = [
        row["timestamp"], row["from_bank"], row["from_account"], row["to_bank"], row["to_account"],
        row["amount_received"], row["receiving_currency"], row["amount_paid"], row["payment_currency"],
        row["payment_format"], row["is_laundering"],
    ]
    return execute(sql, params)


def _run_pipeline_for_account(account_id: str, new_txn_id: int):
    """
    Run rule engine, ML, graph, fusion; return (scored_payload, alert_payload or None).
    scored_payload: dict with transaction info + rule_score, ml_score, graph_score, fusion_score.
    alert_payload: dict for alerts.generated if fusion above threshold, else None.
    """
    from app.detection.rule_engine import RuleEngine
    from app.detection.fusion import FusionEngine
    from app.config import ALERT_THRESHOLD
    import pandas as pd

    engine = RuleEngine()
    try:
        violations = engine.evaluate_all()
    finally:
        engine.close()

    # Restrict to our new transaction
    violations = [v for v in violations if v.get("transaction_id") == new_txn_id]

    ml_risks = None
    try:
        from app.detection.ml_engine import MLEngine
        import os
        from app.config import MODELS_DIR
        model_path = os.path.join(MODELS_DIR, "lgbm_model.pkl")
        if os.path.exists(model_path):
            ml = MLEngine()
            if ml.load_model():
                ml_risks = ml.predict_risks()
    except Exception as e:
        logger.debug("ML signal unavailable: %s", e)

    if ml_risks is None:
        ml_risks = pd.DataFrame()

    graph_risks = {}
    try:
        from app.detection.graph_engine import GraphEngine
        graph = GraphEngine()
        if graph.has_graph():
            graph_risks = graph.analyze()
    except Exception as e:
        logger.debug("Graph signal unavailable: %s", e)

    fusion = FusionEngine()
    alerts = fusion.fuse(violations, ml_risks, graph_risks or {})

    # Scores for our account (from fusion weights)
    rule_score = 0
    for v in violations:
        ev = v.get("evidence", {})
        acct = ev.get("account") or ev.get("from_account", "")
        if acct == account_id:
            rule_score = max(rule_score, v.get("rule_score", 0))

    ml_score = 0
    if not ml_risks.empty and "account_id" in ml_risks.columns:
        row = ml_risks[ml_risks["account_id"] == account_id]
        if not row.empty:
            ml_score = float(row.iloc[0].get("ml_risk", 0))

    graph_score = 0
    if account_id in (graph_risks or {}):
        g = graph_risks[account_id]
        graph_score = g.get("risk_score", 0) if isinstance(g, dict) else float(g)

    w = FusionEngine.WEIGHTS
    fusion_score = w["rule"] * rule_score + w["ml"] * ml_score + w["graph"] * graph_score

    alert_for_account = next((a for a in alerts if a.get("account_id") == account_id), None)

    scored_payload = {
        "account_id": account_id,
        "transaction_id": new_txn_id,
        "rule_score": round(rule_score, 4),
        "ml_score": round(ml_score, 4),
        "graph_score": round(graph_score, 4),
        "fusion_score": round(fusion_score, 4),
    }

    alert_payload = None
    if alert_for_account and fusion_score >= ALERT_THRESHOLD:
        alert_payload = {
            "account_id": account_id,
            "transaction_id": new_txn_id,
            "rule_score": alert_for_account.get("rule_score"),
            "ml_score": alert_for_account.get("ml_score"),
            "graph_score": alert_for_account.get("graph_score"),
            "fusion_score": alert_for_account.get("fusion_score"),
            "severity": alert_for_account.get("severity"),
            "triggered_rules": alert_for_account.get("triggered_rules", []),
        }

    return scored_payload, alert_payload


def _produce_scored_and_alert(producer, original_payload: dict, scored_payload: dict, alert_payload: Optional[dict]):
    """Produce to transactions.scored and optionally to alerts.generated."""
    out = {**original_payload, **scored_payload}
    producer.produce(KAFKA_TOPIC_SCORED, value=json.dumps(out).encode("utf-8"), key=scored_payload.get("account_id", "").encode("utf-8"))
    producer.poll(0)
    if alert_payload:
        producer.produce(KAFKA_TOPIC_ALERTS, value=json.dumps(alert_payload).encode("utf-8"), key=alert_payload.get("account_id", "").encode("utf-8"))
        producer.poll(0)


def process_message(value_bytes: bytes) -> bool:
    """
    Process one message: validate -> insert -> pipeline -> produce.
    Returns True on success, False on validation/processing error (caller should not commit).
    """
    try:
        payload = json.loads(value_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning("Invalid message JSON: %s", e)
        record_failed()
        return False

    try:
        event = TransactionEvent.model_validate(payload)
    except Exception as e:
        logger.warning("Schema validation failed: %s", e)
        record_failed()
        return False

    row = event.to_db_row()
    try:
        new_id = _insert_transaction(row)
    except Exception as e:
        logger.exception("DB insert failed: %s", e)
        record_failed()
        return False

    if new_id is None:
        record_failed()
        return False

    account_id = event.account_id or f"{event.from_bank}_{event.from_account}"
    start = time.perf_counter()
    try:
        scored_payload, alert_payload = _run_pipeline_for_account(account_id, new_id)
    except Exception as e:
        logger.exception("Pipeline failed: %s", e)
        record_failed()
        return False

    # Add original payload for scored topic (optional; we already have scores)
    original = payload.copy()
    original["db_id"] = new_id

    if not _KAFKA_AVAILABLE:
        record_processed()
        record_latency(time.perf_counter() - start)
        return True

    try:
        from app.streaming.kafka_config import get_producer_config
        producer = Producer(get_producer_config())
        _produce_scored_and_alert(producer, original, scored_payload, alert_payload)
        producer.flush(timeout=10)
    except Exception as e:
        logger.exception("Produce failed: %s", e)
        record_failed()
        return False

    record_processed()
    record_latency(time.perf_counter() - start)
    return True


def run_consumer(group_id: str = None):
    """Run the consumer loop: subscribe to transactions.incoming, process each message, commit after success."""
    if not _KAFKA_AVAILABLE:
        logger.error("confluent_kafka not available; cannot run consumer")
        return

    config = get_consumer_config(group_id=group_id)
    consumer = Consumer(config)
    consumer.subscribe([KAFKA_TOPIC_INCOMING])

    logger.info("Consumer subscribed to %s (group %s)", KAFKA_TOPIC_INCOMING, config["group.id"])

    while True:
        try:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                logger.warning("Consumer error: %s", msg.error())
                continue

            ok = process_message(msg.value())
            if ok:
                consumer.commit(message=msg)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.exception("Consumer loop error: %s", e)

    consumer.close()
    logger.info("Consumer stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_consumer()
