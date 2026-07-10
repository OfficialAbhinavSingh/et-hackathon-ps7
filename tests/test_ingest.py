import json

from intel.ingest import build_collection, load_records, query

SAMPLE_RECORDS = [
    {"id": "T1041", "name": "Exfiltration Over C2 Channel",
     "description": "Adversaries steal data over an existing command and control channel.",
     "source_type": "attack"},
    {"id": "T1021", "name": "Remote Services",
     "description": "Adversaries use valid accounts to log into services accessible remotely.",
     "source_type": "attack"},
    {"id": "CVE-2023-99999", "name": "CVE-2023-99999",
     "description": "SQL injection in a fake web product allowing remote code execution.",
     "source_type": "cve"},
]


def test_query_returns_relevant_chunk_for_a_sample_query(tmp_path):
    coll = build_collection(SAMPLE_RECORDS, persist_dir=str(tmp_path / "chroma"))
    results = query(coll, "attacker exfiltrating data through the C2 channel", n_results=1)
    assert len(results) == 1
    assert results[0]["id"] == "T1041"
    assert results[0]["source_type"] == "attack"


def test_query_respects_n_results(tmp_path):
    coll = build_collection(SAMPLE_RECORDS, persist_dir=str(tmp_path / "chroma"))
    results = query(coll, "remote access", n_results=2)
    assert len(results) == 2


def test_metadata_carries_source_type_and_name(tmp_path):
    coll = build_collection(SAMPLE_RECORDS, persist_dir=str(tmp_path / "chroma"))
    results = query(coll, "sql injection remote code execution", n_results=1)
    assert results[0]["source_type"] == "cve"
    assert results[0]["name"] == "CVE-2023-99999"


def test_load_records_concatenates_the_fetched_source_files(tmp_path):
    """The ingest CLI reads the JSON that fetch_sources.py wrote (attack/cve/certin) and
    concatenates them for build_collection. Missing files are skipped, not fatal."""
    (tmp_path / "attack.json").write_text(json.dumps(SAMPLE_RECORDS[:2]))
    (tmp_path / "cve.json").write_text(json.dumps(SAMPLE_RECORDS[2:]))
    # certin.json intentionally absent — must be tolerated

    records = load_records(tmp_path)
    assert len(records) == 3
    assert {r["id"] for r in records} == {"T1041", "T1021", "CVE-2023-99999"}
