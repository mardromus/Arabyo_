"""Kafka producer for publishing incoming transaction events."""
import json
import logging
from app.streaming.kafka_config import KAFKA_TOPIC_INCOMING, get_producer_config

logger = logging.getLogger(__name__)

try:
    from confluent_kafka import Producer
    _KAFKA_AVAILABLE = True
except ImportError:
    Producer = None
    _KAFKA_AVAILABLE = False


def send_transaction_event(payload: dict, key: str = None) -> bool:
    """
    Serialize payload to JSON and send to transactions.incoming.
    key: optional partition key (e.g. account_id for ordering per account).
    Returns True if sent (or queued), False if Kafka unavailable.
    """
    if not _KAFKA_AVAILABLE:
        logger.warning("confluent_kafka not available; transaction event not sent")
        return False

    topic = KAFKA_TOPIC_INCOMING
    config = get_producer_config()
    try:
        producer = Producer(config)
        key_bytes = key.encode("utf-8") if key else None
        value = json.dumps(payload).encode("utf-8")
        producer.produce(topic, value=value, key=key_bytes)
        producer.flush(timeout=10)
        return True
    except Exception as e:
        logger.exception("Failed to send transaction event to Kafka: %s", e)
        return False


def send_transaction_event_async(payload: dict, key: str = None) -> bool:
    """
    Queue transaction event for send (non-blocking). Use for high throughput.
    key: optional partition key (e.g. account_id).
    """
    if not _KAFKA_AVAILABLE:
        return False
    topic = KAFKA_TOPIC_INCOMING
    config = get_producer_config()
    try:
        producer = Producer(config)
        key_bytes = key.encode("utf-8") if key else None
        value = json.dumps(payload).encode("utf-8")
        producer.produce(topic, value=value, key=key_bytes)
        return True
    except Exception as e:
        logger.exception("Failed to produce transaction event: %s", e)
        return False
