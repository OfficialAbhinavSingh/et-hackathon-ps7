"""Append-only, hash-chained audit log — genuinely tamper-evident.

The byte-format is a CONTRACT with the frontend (frontend/src/data/hashChain.ts): the
dashboard re-verifies this chain client-side, so the hash input must match exactly:

    entry_hash = sha256_hex( prev_hash + canonical(entry) )
    canonical  = compact JSON (no whitespace) of exactly, in this order:
                 {"audit_log_id","timestamp","event_id","action","actor","detail"}
    genesis prev_hash = ""   (empty string)

`ensure_ascii=False` + `separators=(",",":")` makes Python's json match JS `JSON.stringify`
byte-for-byte (including raw non-ASCII). Persisted as JSONL so the chain survives a restart.
See finalplan §10.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = ""
CANONICAL_FIELDS = ("audit_log_id", "timestamp", "event_id", "action", "actor", "detail")


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)

    def _canonical(self, entry: dict) -> str:
        ordered = {field: entry[field] for field in CANONICAL_FIELDS}
        return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)

    def _hash(self, prev_hash: str, entry: dict) -> str:
        return hashlib.sha256((prev_hash + self._canonical(entry)).encode("utf-8")).hexdigest()

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open() as f:
            return [json.loads(line) for line in f if line.strip()]

    def append(
        self,
        event_id: str,
        action: str,
        actor: str,
        detail: str,
        timestamp: str | None = None,
    ) -> dict:
        existing = self.read_all()
        prev_hash = existing[-1]["entry_hash"] if existing else GENESIS
        entry = {
            "audit_log_id": f"aud_{len(existing) + 1:04d}",
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "action": action,
            "actor": actor,
            "detail": detail,
        }
        record = {**entry, "prev_hash": prev_hash, "entry_hash": self._hash(prev_hash, entry)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def verify(self) -> bool:
        """Recompute the chain from genesis; any break means tampering."""
        prev = GENESIS
        for record in self.read_all():
            if record["prev_hash"] != prev:
                return False
            if self._hash(prev, record) != record["entry_hash"]:
                return False
            prev = record["entry_hash"]
        return True
