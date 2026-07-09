import json
from pathlib import Path

import pytest
import requests

from intel.fetch_sources import (
    CERTIN_SEED_ILLUSTRATIVE,
    fetch_certin,
    parse_attack_bundle,
    parse_cve_response,
    write_slice,
)

SAMPLE_STIX = {
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Exfiltration Over C2 Channel",
            "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1041"}],
        },
        {
            "type": "malware",  # not an attack-pattern — must be skipped
            "name": "irrelevant",
            "description": "irrelevant",
            "external_references": [],
        },
    ]
}

SAMPLE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "descriptions": [{"lang": "en", "value": "Example RCE in a fake product."}],
            }
        }
    ]
}


def test_parse_attack_bundle_extracts_only_techniques_with_mitre_id():
    records = parse_attack_bundle(SAMPLE_STIX)
    assert len(records) == 1
    assert records[0] == {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "source_type": "attack",
    }


def test_parse_cve_response_extracts_english_description():
    records = parse_cve_response(SAMPLE_NVD)
    assert records == [
        {
            "id": "CVE-2023-99999",
            "name": "CVE-2023-99999",
            "description": "Example RCE in a fake product.",
            "source_type": "cve",
        }
    ]


def test_write_slice_is_deterministic_and_capped(tmp_path):
    records = [{"id": f"T{i}", "name": "x", "description": "y", "source_type": "attack"} for i in range(50)]
    out = tmp_path / "slice.json"
    write_slice(records, n=5, path=out)
    saved = json.loads(out.read_text())
    assert len(saved) == 5
    assert saved == records[:5]


def test_fetch_certin_without_url_returns_seed_without_raising():
    assert fetch_certin(url=None) == CERTIN_SEED_ILLUSTRATIVE


def test_fetch_certin_with_url_raises_notimplementederror_when_response_ok(monkeypatch):
    """A URL was explicitly passed and the request succeeded, but no parser exists for the
    response shape — this must fail loudly (NotImplementedError), not be silently swallowed
    into the illustrative seed."""

    class FakeResponse:
        def raise_for_status(self):
            return None

    def fake_get(url, timeout=30):
        return FakeResponse()

    monkeypatch.setattr(requests, "get", fake_get)

    with pytest.raises(NotImplementedError):
        fetch_certin(url="http://example.com/fake")


def test_fetch_certin_with_url_falls_back_on_network_error(monkeypatch):
    """A network-layer failure (timeout, connection error, HTTP error) while fetching a
    real --certin-url should fall back to the seed rather than raising."""

    def fake_get(url, timeout=30):
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(requests, "get", fake_get)

    assert fetch_certin(url="http://example.com/fake") == CERTIN_SEED_ILLUSTRATIVE
