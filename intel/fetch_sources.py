"""Fetch MITRE ATT&CK STIX + NVD CVE + CERT-In into data/intel/ (issue #16).

Live network calls are NOT unit-tested — the parse_* functions are pure and tested against
small embedded samples. Run this module directly to actually populate data/intel/:
    .venv/bin/python -m intel.fetch_sources
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import requests

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "intel"
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "data" / "fixtures"

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CERT-In illustrative fallback — NOT verified against a live source. Replace with a real
# fetch (see module docstring) before treating these as citable government advisories.
CERTIN_SEED_ILLUSTRATIVE = [
    {
        "id": "CERTIN-SEED-1",
        "name": "Illustrative advisory placeholder — replace with real CERT-In data",
        "description": "This is a seed record, not verified against a live CERT-In source.",
        "source_type": "certin",
    }
]


# STIX kill_chain_phases use kebab-case phase names; map to the Title Case tactic names the
# frontend's kill-chain grid (frontend/src/lib/mitre.ts KILL_CHAIN) already uses. Phases with
# no frontend column (reconnaissance, resource-development, defense-evasion) fall to "Other",
# same as a technique with no recognized phase at all.
PHASE_TO_TACTIC = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _tactic_for(obj: dict) -> str:
    phases = obj.get("kill_chain_phases", [])
    phase_name = next((p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"), None)
    return PHASE_TO_TACTIC.get(phase_name, "Other")


def parse_attack_bundle(bundle: dict) -> list[dict]:
    """Extract technique (attack-pattern) objects with a MITRE ATT&CK ID."""
    records = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        mitre_id = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not mitre_id:
            continue
        records.append({
            "id": mitre_id,
            "name": obj["name"],
            "description": obj.get("description", ""),
            "source_type": "attack",
            "tactic": _tactic_for(obj),
        })
    return records


def write_tactic_map(records: list[dict], path) -> None:
    """Write {technique_id: tactic} for attack records — consumed by the frontend's MITRE grid
    (frontend/src/lib/mitre.ts) so it covers every real ATT&CK technique the live agent can
    cite, not a hand-maintained whitelist."""
    mapping = {r["id"]: r["tactic"] for r in records if r["source_type"] == "attack"}
    Path(path).write_text(json.dumps(mapping, indent=2, sort_keys=True))


def parse_cve_response(payload: dict) -> list[dict]:
    """Extract id + English description from an NVD CVE API 2.0 response page."""
    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        records.append({
            "id": cve["id"],
            "name": cve["id"],
            "description": desc,
            "source_type": "cve",
        })
    return records


def fetch_attack() -> list[dict]:
    resp = requests.get(ATTACK_STIX_URL, timeout=30)
    resp.raise_for_status()
    return parse_attack_bundle(resp.json())


def fetch_cves(keywords: list[str], per_keyword: int = 5) -> list[dict]:
    """Query NVD by keyword (e.g. attack technique names) — no API key needed at low volume."""
    out: list[dict] = []
    for kw in keywords:
        resp = requests.get(
            NVD_CVE_URL,
            params={"keywordSearch": kw, "resultsPerPage": per_keyword},
            timeout=30,
        )
        resp.raise_for_status()
        out.extend(parse_cve_response(resp.json()))
        time.sleep(6)  # NVD's unauthenticated rate limit is 5 req / 30s
    return out


def fetch_certin(url: str | None = None) -> list[dict]:
    if not url:
        print("no --certin-url given — using illustrative seed, NOT real CERT-In data")
        return CERTIN_SEED_ILLUSTRATIVE

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        print(f"CERT-In fetch failed ({exc}); falling back to illustrative seed")
        return CERTIN_SEED_ILLUSTRATIVE

    # NOTE: parsing depends entirely on the actual page/feed shape at `url` — inspect it
    # and adapt this before relying on it. Left unimplemented on purpose: guessing the
    # shape here would be worse than failing loudly. This must NOT be swallowed — a URL
    # was explicitly passed, so silently falling back to the seed here would hide the gap.
    raise NotImplementedError(
        "fetch_certin: got a response from --certin-url but no parser is written yet — "
        "inspect the response shape and implement parse_certin_response() for it."
    )


def write_slice(records: list[dict], n: int, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records[:n], indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--certin-url", default=None)
    ap.add_argument("--cve-keywords", nargs="+",
                     default=["lateral movement", "data exfiltration", "remote code execution"])
    args = ap.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    attack = fetch_attack()
    (DATA_DIR / "attack.json").write_text(json.dumps(attack, indent=2))
    print(f"ATT&CK: {len(attack)} techniques -> {DATA_DIR / 'attack.json'}")

    cves = fetch_cves(args.cve_keywords)
    (DATA_DIR / "cve.json").write_text(json.dumps(cves, indent=2))
    print(f"CVE: {len(cves)} records -> {DATA_DIR / 'cve.json'}")

    certin = fetch_certin(args.certin_url)
    (DATA_DIR / "certin.json").write_text(json.dumps(certin, indent=2))
    print(f"CERT-In: {len(certin)} records -> {DATA_DIR / 'certin.json'}")

    all_records = attack + cves + certin
    write_slice(all_records, n=15, path=FIXTURES_DIR / "intel_slice.json")
    print(f"committed slice: 15 records -> {FIXTURES_DIR / 'intel_slice.json'}")

    write_tactic_map(attack, FIXTURES_DIR / "mitre_tactics.json")
    print(f"tactic map: {len(attack)} techniques -> {FIXTURES_DIR / 'mitre_tactics.json'}")


if __name__ == "__main__":
    main()
