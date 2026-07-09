import json
from pathlib import Path

from intel.fetch_sources import parse_attack_bundle, parse_cve_response, write_slice

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
