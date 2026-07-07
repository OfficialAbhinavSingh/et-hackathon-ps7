"""Append-only, hash-chained audit log — genuinely tamper-evident.

Each record stores sha256(prev_hash + entry). Change any past entry and its hash
no longer matches, so `verify()` fails — you can *prove* tamper-evidence, not just
claim it. Persisted as JSONL so the chain survives a restart. See finalplan §10.
"""

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)

    def _hash(self, prev_hash: str, entry: dict) -> str:
        payload = prev_hash + json.dumps(entry, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _last_hash(self) -> str:
        last = GENESIS # GENESIS is basically 64 zeros
        for record in self.read_all():
            last = record["entry_hash"]
        return last

    def append(self, entry: dict) -> dict:
        prev_hash = self._last_hash()
        record = {
            "prev_hash": prev_hash,
            "entry": entry,
            "entry_hash": self._hash(prev_hash, entry),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open() as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify(self) -> bool:
        """Recompute the chain from genesis; any break means tampering."""
        prev = GENESIS
        for record in self.read_all():
            if record["prev_hash"] != prev:
                return False
            if self._hash(record["prev_hash"], record["entry"]) != record["entry_hash"]:
                return False
            prev = record["entry_hash"]
        return True
