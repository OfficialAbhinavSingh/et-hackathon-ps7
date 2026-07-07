import json

from orchestrator.audit import AuditLog

GENESIS = "0" * 64


def test_first_entry_links_to_genesis(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    rec = log.append({"event_id": "evt_0001", "action": "isolate_host"})
    assert rec["prev_hash"] == GENESIS
    assert len(rec["entry_hash"]) == 64


def test_each_entry_links_to_the_previous(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append({"event_id": "evt_0001"})
    second = log.append({"event_id": "evt_0002"})
    assert second["prev_hash"] == first["entry_hash"]


def test_verify_true_for_untampered_log(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"event_id": "evt_0001"})
    log.append({"event_id": "evt_0002"})
    assert log.verify() is True


def test_verify_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"event_id": "evt_0001", "action": "monitor"})
    log.append({"event_id": "evt_0002", "action": "block_ip"})

    # Tamper with a past entry directly on disk.
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["entry"]["action"] = "isolate_host"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    assert log.verify() is False
