"""
Streaming metrics: consumer lag, throughput, processing latency, failed count.
In-memory store; can be replaced with Prometheus client later.
"""
import time
import threading
from collections import deque

_lock = threading.Lock()
_processed_count = 0
_failed_count = 0
_latencies: deque = deque(maxlen=10000)  # last N latencies in seconds
_start_time = time.perf_counter()
_consumer_lag: dict = {}


def record_processed():
    global _processed_count
    with _lock:
        _processed_count += 1


def record_failed():
    global _failed_count
    with _lock:
        _failed_count += 1


def record_latency(seconds: float):
    with _lock:
        _latencies.append(seconds)


def get_throughput() -> float:
    """Messages per second (processed) since process start."""
    with _lock:
        elapsed = time.perf_counter() - _start_time
        return _processed_count / elapsed if elapsed > 0 else 0.0


def get_processed_count() -> int:
    with _lock:
        return _processed_count


def get_failed_count() -> int:
    with _lock:
        return _failed_count


def get_latency_stats() -> dict:
    """Returns avg, p95, p99 (seconds) from recent latencies."""
    with _lock:
        if not _latencies:
            return {"avg_s": 0, "p95_s": 0, "p99_s": 0, "n": 0}
        arr = sorted(_latencies)
        n = len(arr)
        avg = sum(arr) / n
        p95 = arr[int(n * 0.95)] if n >= 20 else arr[-1]
        p99 = arr[int(n * 0.99)] if n >= 100 else arr[-1]
        return {"avg_s": round(avg, 4), "p95_s": round(p95, 4), "p99_s": round(p99, 4), "n": n}


def get_metrics() -> dict:
    """Full metrics dict for /api/streaming/metrics."""
    throughput = get_throughput()
    latency = get_latency_stats()
    out = {
        "throughput_mps": round(throughput, 2),
        "processed_total": get_processed_count(),
        "failed_total": get_failed_count(),
        "latency_s": latency,
    }
    lag = get_consumer_lag()
    if lag:
        out["consumer_lag"] = lag
    return out


def set_consumer_lag(lag_per_partition: dict):
    """Store consumer lag per partition (call from consumer if desired)."""
    global _consumer_lag
    _consumer_lag = lag_per_partition


def get_consumer_lag() -> dict:
    """Current offset lag per partition (if set)."""
    return _consumer_lag
