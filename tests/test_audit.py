import hashlib
import json

from orchestrator.audit import AuditLog

GENESIS = ""
CANONICAL_FIELDS = ("audit_log_id", "timestamp", "event_id", "action", "actor", "detail")


def _frontend_canonical(rec):
    """Reproduce hashChain.ts canonicalize(): compact JSON, fixed field order, raw UTF-8."""
    ordered = {k: rec[k] for k in CANONICAL_FIELDS}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def test_first_entry_links_to_genesis_and_is_numbered(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    rec = log.append(event_id="evt_0001", action="isolate_host", actor="system", detail="T1048")
    assert rec["prev_hash"] == GENESIS
    assert rec["audit_log_id"] == "aud_0001"
    assert len(rec["entry_hash"]) == 64


def test_each_entry_links_to_the_previous(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append(event_id="evt_0001", action="isolate_host", actor="system", detail="a")
    second = log.append(event_id="evt_0002", action="block_ip", actor="system", detail="b")
    assert second["prev_hash"] == first["entry_hash"]
    assert second["audit_log_id"] == "aud_0002"


def test_verify_true_for_untampered_log(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(event_id="evt_0001", action="isolate_host", actor="system", detail="a")
    log.append(event_id="evt_0002", action="block_ip", actor="system", detail="b")
    assert log.verify() is True


def test_verify_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(event_id="evt_0001", action="monitor", actor="system", detail="a")
    log.append(event_id="evt_0002", action="block_ip", actor="system", detail="b")

    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "isolate_host"  # tamper a hashed field on disk
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    assert log.verify() is False


def test_entry_hash_byte_matches_frontend_hashchain(tmp_path):
    """The whole tamper-evidence demo depends on this exact byte-format agreeing."""
    log = AuditLog(tmp_path / "audit.jsonl")
    rec = log.append(
        event_id="evt_0001",
        action="isolate_host",
        actor="system",
        detail="T1048 — exfiltration over non-standard port 4444",  # non-ASCII em dash on purpose
        timestamp="2026-07-10T12:00:00Z",
    )
    expected = hashlib.sha256((GENESIS + _frontend_canonical(rec)).encode("utf-8")).hexdigest()
    assert rec["entry_hash"] == expected


def test_read_all_returns_flat_audit_entries(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(event_id="evt_0001", action="isolate_host", actor="system", detail="a")
    (record,) = log.read_all()
    assert set(record) == set(CANONICAL_FIELDS) | {"prev_hash", "entry_hash"}
