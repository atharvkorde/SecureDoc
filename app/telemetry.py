"""In-memory, thread-safe telemetry for SecureDoc educational workspace.

Stores only aggregate counters and non-sensitive event metadata (operation,
algorithm, byte length, timestamp, and outcome). Never stores document contents,
ciphertexts, private keys, or shared secrets.
"""
from collections import deque
from datetime import datetime, timezone
import threading


class SecurityTelemetry:
    """Thread-safe in-memory tracker for SecureDoc API operations."""

    def __init__(self, max_events: int = 50):
        self._lock = threading.Lock()
        self._events: deque[dict] = deque(maxlen=max_events)
        self._next_id = 1
        self._counts = {
            "total_processed": 0,
            "encrypted_documents": 0,
            "decrypted_documents": 0,
            "verified_documents": 0,
            "integrity_failures": 0,
            "signatures_created": 0,
            "hashes_computed": 0,
            "hmacs_generated": 0,
        }

    def record(
        self,
        *,
        operation: str,
        algorithm: str,
        success: bool,
        byte_count: int = 0,
        detail: str = "",
        category: str = "general",
    ) -> dict:
        event = {
            "id": 0,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "operation": operation,
            "algorithm": algorithm,
            "status": "success" if success else "failure",
            "bytes": max(0, int(byte_count)),
            "detail": detail,
        }
        with self._lock:
            event["id"] = self._next_id
            self._next_id += 1
            self._counts["total_processed"] += 1

            if category == "encrypt" and success:
                self._counts["encrypted_documents"] += 1
            elif category == "decrypt" and success:
                self._counts["decrypted_documents"] += 1
            elif category == "decrypt" and not success:
                self._counts["integrity_failures"] += 1
            elif category == "verify":
                if success:
                    self._counts["verified_documents"] += 1
                else:
                    self._counts["integrity_failures"] += 1
            elif category == "sign" and success:
                self._counts["signatures_created"] += 1
            elif category == "hash" and success:
                self._counts["hashes_computed"] += 1
            elif category == "hmac" and success:
                self._counts["hmacs_generated"] += 1

            self._events.appendleft(event)
            return dict(event)

    def metrics(self) -> dict:
        with self._lock:
            return dict(self._counts)

    def events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._events)[: max(1, min(limit, 50))]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            for key in self._counts:
                self._counts[key] = 0
