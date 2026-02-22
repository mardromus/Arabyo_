"""Kafka client configuration from environment / app config."""
from app.config import (
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC_INCOMING,
    KAFKA_TOPIC_SCORED,
    KAFKA_TOPIC_ALERTS,
    KAFKA_GROUP_ID,
)

__all__ = [
    "KAFKA_BOOTSTRAP_SERVERS",
    "KAFKA_TOPIC_INCOMING",
    "KAFKA_TOPIC_SCORED",
    "KAFKA_TOPIC_ALERTS",
    "KAFKA_GROUP_ID",
]


def get_producer_config():
    """Config dict for confluent_kafka Producer."""
    return {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
    }


def get_consumer_config(group_id=None):
    """Config dict for confluent_kafka Consumer (at-least-once: enable.auto.commit=false)."""
    return {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": group_id or KAFKA_GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }
