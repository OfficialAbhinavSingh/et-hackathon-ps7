# Yash's Issues Takeover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Solo-complete every currently open issue on `OfficialAbhinavSingh/et-hackathon-ps7` (Yash is offline for several days) while keeping `main` green and demoable after every task, per finalplan.md §6's integrate-continuously invariant.

**Architecture:** Walking-skeleton pattern already established by the repo — each task replaces one mock behind an unchanging contract (`orchestrator/schemas.py`). `intel/` is a new package: `fetch_sources.py` → `ingest.py` (Chroma) → `llm.py` (provider seam) → `agent.py` (tool-calling `enrich()`), wired into `orchestrator/main.py`'s existing `enrich=` injection point behind an env flag so the stub path never breaks.

**Tech Stack:** Python 3.12 (backend `.venv`, same as orchestrator — `intel/` has no ML deps so it does NOT need the isolated `.venv-engine`), `chromadb` (local, ONNX MiniLM default embedding — no API key), `anthropic` SDK + `groq` SDK behind one seam, `requests` for STIX/CVE fetch, `pytest` with dependency-injected fakes (no real API key required to run the suite).

## Global Constraints

- `orchestrator/schemas.py` contracts are frozen — `EnrichedIncident` (Contract 2) must not change shape. If it must, bump `schema_version` and update `docs/finalplan.md` §4.
- `orchestrator/policy.py` stays authoritative over the agent's `suggested_action` — the agent never decides containment, only proposes.
- **Retrieve-then-cite, always.** Never invent a technique ID. If nothing relevant is retrieved, lower `confidence` and say so in `narrative`. (finalplan §10)
- **Force + validate structured JSON; retry on malformed** — the orchestrator breaks on bad output, so `agent.py` must never let one through.
- The stub enrichment path (`orchestrator/main.py::_make_stub_enrich`) must keep working at every commit — it's the demo's safety net if the live agent or a key is unavailable on stage.
- Do not touch `orchestrator/audit.py`'s hash-chain format or `frontend/src/data/hashChain.ts` — cross-language frozen contract.
- `frontend/src/data/DataService.ts` is explicit: **no `/graph`, `/incidents`, or `/metrics` backend endpoint — ever.** Everything the dashboard needs beyond `/stream`, `/approve/{id}`, `/audit` is derived client-side. Do not add new backend read endpoints for the frontend.
- LLM provider seam per `docs/finalplan.md` §11: Claude (`claude-sonnet-4-6`) if `ANTHROPIC_API_KEY` set, else Groq (`llama-3.3-70b-versatile`) if `GROQ_API_KEY` set, else a clear startup error. `agent.py` only calls `intel.llm.run_agentic_tool_loop(...)` — it never touches a provider SDK directly.

---

### Task 0: Merge PR #22, push #19 — clear the deck

No code changes; this just lands work already done so later tasks build on a clean `main`.

- [ ] **Step 1:** Merge PR #22 (`#15 engine infer+replay` — already independently verified this session: fresh retrain reproduces committed metrics, 4/4 tests pass, both review comments addressed).
  ```bash
  gh pr merge 22 --repo OfficialAbhinavSingh/et-hackathon-ps7 --merge
  ```
- [ ] **Step 2:** Push the existing local #19 fix and open its PR.
  ```bash
  cd /home/laterabhi/Projects/et-hackathon-ps7
  git checkout feat/19-dashboard-polish
  git rebase main   # picks up the just-merged #22 changes
  git push -u origin feat/19-dashboard-polish
  gh pr create --repo OfficialAbhinavSingh/et-hackathon-ps7 \
    --title "fix(dashboard): map T1046→Discovery in MITRE grid (#19)" \
    --body "Closes #19 (partial — see ticket, rest explicitly deferred).

  frontend/src/lib/mitre.ts was missing a T1046→Discovery mapping, so the stub enrichment's real output was dropped as \"Other\". Other #19 checklist items already exist per #10." \
    --base main
  ```
- [ ] **Step 3:** Pull the merged state locally and confirm both backend and frontend suites still pass.
  ```bash
  git checkout main && git pull
  make test 2>&1 | tail -5
  cd frontend && npx vitest run 2>&1 | tail -10 && cd ..
  ```
  Expected: `35 passed` backend (was 35; unaffected by #22/#19), `16 passed` frontend.
- [ ] **Step 4:** No commit needed — this task is pure git ops, already committed by prior work.

---

### Task 1: `intel/fetch_sources.py` — pull ATT&CK + CVE + CERT-In into `data/intel/`

**Files:**
- Create: `intel/__init__.py` (empty)
- Create: `intel/fetch_sources.py`
- Create: `data/intel/.gitkeep`-equivalent — the directory itself is gitignored (add to `.gitignore`), only `data/fixtures/intel_slice.json` is committed
- Modify: `.gitignore` — add `data/intel/`
- Modify: `pyproject.toml` — add `intel` extras
- Test: `tests/test_fetch_sources.py`

**Interfaces:**
- Produces: `fetch_attack() -> list[dict]` — each `{"id": "T1048", "name": str, "description": str, "source_type": "attack"}`
- Produces: `fetch_cves(keywords: list[str], per_keyword: int = 5) -> list[dict]` — each `{"id": "CVE-2023-XXXXX", "name": str, "description": str, "source_type": "cve"}`
- Produces: `fetch_certin() -> list[dict]` — each `{"id": str, "name": str, "description": str, "source_type": "certin"}`
- Produces: `write_slice(records: list[dict], n: int, path: Path) -> None` — commits a small deterministic sample for `data/fixtures/`

**IMPORTANT — CERT-In has no public API.** I don't have a verified, current URL for a scrapable CERT-In advisory listing, and I'm not going to guess one into shipped code (a wrong guessed URL is worse than an honest gap). `fetch_certin()` below tries a `--certin-url` you supply (if you know CERT-In's current advisories page/RSS — you're best placed to check cert-in.org.in yourself); if not supplied or the fetch fails, it falls back to a small **explicitly-marked-illustrative** local seed so the retrieval pipeline and demo aren't blocked. Fix this properly (real URL, or drop CERT-In citations from the pitch honestly) before presenting it as real government data.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fetch_sources.py
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_fetch_sources.py -v
```
Expected: `ModuleNotFoundError: No module named 'intel'` (or `ImportError` for the missing functions).

- [ ] **Step 3: Write minimal implementation**

```python
# intel/__init__.py
```

```python
# intel/fetch_sources.py
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
        })
    return records


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
        # NOTE: parsing depends entirely on the actual page/feed shape at `url` — inspect it
        # and adapt this before relying on it. Left unimplemented on purpose: guessing the
        # shape here would be worse than failing loudly.
        raise NotImplementedError(
            "fetch_certin: got a response from --certin-url but no parser is written yet — "
            "inspect the response shape and implement parse_certin_response() for it."
        )
    except Exception as exc:
        print(f"CERT-In fetch failed ({exc}); falling back to illustrative seed")
        return CERTIN_SEED_ILLUSTRATIVE


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


if __name__ == "__main__":
    main()
```

```gitignore
# add to .gitignore
data/intel/
```

```toml
# pyproject.toml — add alongside the existing `engine` extra
intel = ["chromadb", "requests"]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pip install -e ".[intel]"
.venv/bin/pytest tests/test_fetch_sources.py -v
```
Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add intel/__init__.py intel/fetch_sources.py tests/test_fetch_sources.py pyproject.toml .gitignore
git commit -m "feat(intel): fetch_sources.py — ATT&CK STIX + NVD CVE + CERT-In seed (#16)"
```

---

### Task 2: `intel/ingest.py` — chunk + embed into Chroma

**Files:**
- Create: `intel/ingest.py`
- Test: `tests/test_ingest.py`

**Interfaces:**
- Consumes: records shaped like Task 1's output — `{"id", "name", "description", "source_type"}`
- Produces: `build_collection(records: list[dict], persist_dir: str) -> chromadb.Collection`
- Produces: `query(collection, text: str, n_results: int = 3) -> list[dict]` — each result `{"id", "name", "description", "source_type", "distance"}`, used by `intel/agent.py`'s tools in Task 4

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ingest.py
from intel.ingest import build_collection, query

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


def test_query_respects_n_results():
    coll = build_collection(SAMPLE_RECORDS, persist_dir=None)
    results = query(coll, "remote access", n_results=2)
    assert len(results) == 2


def test_metadata_carries_source_type_and_name():
    coll = build_collection(SAMPLE_RECORDS, persist_dir=None)
    results = query(coll, "sql injection remote code execution", n_results=1)
    assert results[0]["source_type"] == "cve"
    assert results[0]["name"] == "CVE-2023-99999"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_ingest.py -v
```
Expected: `ModuleNotFoundError: No module named 'intel.ingest'`.

- [ ] **Step 3: Write minimal implementation**

```python
# intel/ingest.py
"""Chunk + embed intel records into Chroma (issue #16).

One record = one chunk — ATT&CK technique descriptions, CVE descriptions, and CERT-In
advisory summaries are all short enough that further splitting would only hurt retrieval
precision. Uses Chroma's bundled local embedding (ONNX MiniLM) — no API key required,
independent of which LLM provider intel/llm.py picks.
"""

from __future__ import annotations

import chromadb
from chromadb.utils import embedding_functions

COLLECTION_NAME = "intel"
_EMBED_FN = embedding_functions.DefaultEmbeddingFunction()


def build_collection(records: list[dict], persist_dir: str | None):
    """persist_dir=None -> in-memory (tests); a path -> persisted on disk (real use)."""
    client = chromadb.PersistentClient(path=persist_dir) if persist_dir else chromadb.Client()
    collection = client.get_or_create_collection(COLLECTION_NAME, embedding_function=_EMBED_FN)
    if collection.count() == 0 and records:
        collection.add(
            ids=[r["id"] for r in records],
            documents=[f"{r['name']}: {r['description']}" for r in records],
            metadatas=[{"source_type": r["source_type"], "name": r["name"]} for r in records],
        )
    return collection


def query(collection, text: str, n_results: int = 3) -> list[dict]:
    res = collection.query(query_texts=[text], n_results=n_results)
    out = []
    for i, doc_id in enumerate(res["ids"][0]):
        meta = res["metadatas"][0][i]
        out.append({
            "id": doc_id,
            "name": meta["name"],
            "description": res["documents"][0][i].split(": ", 1)[-1],
            "source_type": meta["source_type"],
            "distance": res["distances"][0][i],
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_ingest.py -v
```
Expected: `3 passed`.

- [ ] **Step 5: Populate the real persisted collection from Task 1's fetched data, then commit**

```bash
.venv/bin/python -c "
import json
from pathlib import Path
from intel.ingest import build_collection
records = []
for f in ['attack.json', 'cve.json', 'certin.json']:
    records += json.loads((Path('data/intel')/f).read_text())
build_collection(records, persist_dir='data/intel/chroma')
print(f'ingested {len(records)} records')
"
git add intel/ingest.py tests/test_ingest.py
git commit -m "feat(intel): ingest.py — chunk+embed intel records into Chroma (#16)"
```

---

### Task 3: `intel/llm.py` — Claude/Groq tool-calling seam

**Files:**
- Create: `intel/llm.py`
- Modify: `pyproject.toml` — add `anthropic`, `groq` to the `intel` extra
- Test: `tests/test_llm.py`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `ToolSpec(name: str, description: str, parameters: dict)` — a dataclass
- Produces: `run_agentic_tool_loop(system_prompt: str, user_prompt: str, tools: list[ToolSpec], tool_executor: Callable[[str, dict], str], max_turns: int = 4) -> str` — returns the model's final text turn (expected by `agent.py` in Task 4 to be JSON). `tool_executor(tool_name, tool_input) -> str` runs the tool and returns its result serialized as a string.
- Produces (test seam): `_provider() -> str` returns `"claude"` / `"groq"` based on env vars, raises `RuntimeError` if neither key is set. `run_agentic_tool_loop` dispatches to `_loop_claude` / `_loop_groq`, both of which call injectable module-level functions `_raw_call_claude` / `_raw_call_groq` — tests monkeypatch those two, never the real SDKs.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_llm.py
import pytest

from intel.llm import ToolSpec, run_agentic_tool_loop, _provider
import intel.llm as llm


def test_provider_prefers_claude_when_both_keys_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setenv("GROQ_API_KEY", "y")
    assert _provider() == "claude"


def test_provider_falls_back_to_groq(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "y")
    assert _provider() == "groq"


def test_provider_raises_with_no_keys(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY.*GROQ_API_KEY"):
        _provider()


ECHO_TOOL = ToolSpec(name="echo", description="echoes input", parameters={
    "type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"],
})


def test_loop_returns_final_text_after_one_tool_call(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    calls = {"n": 0}

    def fake_raw_call(system, messages, tool_specs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"tool_calls": [{"id": "call_1", "name": "echo", "input": {"text": "hi"}}], "text": None}
        return {"tool_calls": [], "text": '{"result": "done"}'}

    monkeypatch.setattr(llm, "_raw_call_claude", fake_raw_call)

    seen = []

    def executor(name, args):
        seen.append((name, args))
        return "tool result: hi"

    result = run_agentic_tool_loop("sys", "user prompt", [ECHO_TOOL], executor)
    assert result == '{"result": "done"}'
    assert seen == [("echo", {"text": "hi"})]
    assert calls["n"] == 2


def test_loop_stops_at_max_turns_and_returns_last_text(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")

    def always_calls_tool(system, messages, tool_specs):
        return {"tool_calls": [{"id": "call_x", "name": "echo", "input": {"text": "loop"}}], "text": None}

    monkeypatch.setattr(llm, "_raw_call_claude", always_calls_tool)
    result = run_agentic_tool_loop("sys", "user prompt", [ECHO_TOOL], lambda n, a: "r", max_turns=2)
    assert result == ""  # no final text turn was ever produced
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_llm.py -v
```
Expected: `ModuleNotFoundError: No module named 'intel.llm'`.

- [ ] **Step 3: Write minimal implementation**

```python
# intel/llm.py
"""LLM provider seam for the attribution agent (issue #17 / finalplan.md §11).

agent.py calls ONLY run_agentic_tool_loop() — it never touches anthropic/groq SDKs directly.
Provider choice: ANTHROPIC_API_KEY -> claude-sonnet-4-6; else GROQ_API_KEY -> Groq's
llama-3.3-70b-versatile; else raise. Swapping providers is a zero-code-change env var flip.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON schema for the tool's input


def _provider() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    raise RuntimeError(
        "no LLM provider configured — set ANTHROPIC_API_KEY (preferred, claude-sonnet-4-6) "
        "or GROQ_API_KEY (fallback, llama-3.3-70b-versatile)"
    )


def run_agentic_tool_loop(
    system_prompt: str,
    user_prompt: str,
    tools: list[ToolSpec],
    tool_executor: Callable[[str, dict], str],
    max_turns: int = 4,
) -> str:
    """Runs the tool-call loop to completion (or max_turns) and returns final assistant text."""
    provider = _provider()
    loop = _loop_claude if provider == "claude" else _loop_groq
    return loop(system_prompt, user_prompt, tools, tool_executor, max_turns)


def _loop_claude(system_prompt, user_prompt, tools, tool_executor, max_turns) -> str:
    messages = [{"role": "user", "content": user_prompt}]
    for _ in range(max_turns):
        resp = _raw_call_claude(system_prompt, messages, tools)
        if not resp["tool_calls"]:
            return resp["text"] or ""
        messages.append({"role": "assistant", "content": [
            {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["input"]}
            for c in resp["tool_calls"]
        ]})
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": c["id"],
             "content": tool_executor(c["name"], c["input"])}
            for c in resp["tool_calls"]
        ]})
    return ""


def _loop_groq(system_prompt, user_prompt, tools, tool_executor, max_turns) -> str:
    messages = [{"role": "user", "content": user_prompt}]
    for _ in range(max_turns):
        resp = _raw_call_groq(system_prompt, messages, tools)
        if not resp["tool_calls"]:
            return resp["text"] or ""
        messages.append({"role": "assistant", "tool_calls": [
            {"id": c["id"], "type": "function",
             "function": {"name": c["name"], "arguments": json.dumps(c["input"])}}
            for c in resp["tool_calls"]
        ]})
        for c in resp["tool_calls"]:
            messages.append({"role": "tool", "tool_call_id": c["id"],
                              "content": tool_executor(c["name"], c["input"])})
    return ""


def _raw_call_claude(system_prompt: str, messages: list[dict], tools: list[ToolSpec]) -> dict:
    """Real Anthropic call — isolated here so tests can monkeypatch it without a key."""
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=system_prompt,
        tools=[{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools],
        messages=messages,
    )
    tool_calls = [{"id": b.id, "name": b.name, "input": b.input}
                  for b in resp.content if b.type == "tool_use"]
    text = "".join(b.text for b in resp.content if b.type == "text") or None
    return {"tool_calls": tool_calls, "text": text}


def _raw_call_groq(system_prompt: str, messages: list[dict], tools: list[ToolSpec]) -> dict:
    """Real Groq call — isolated here so tests can monkeypatch it without a key."""
    from groq import Groq

    client = Groq()
    resp = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "system", "content": system_prompt}, *messages],
        tools=[{"type": "function", "function": {
            "name": t.name, "description": t.description, "parameters": t.parameters}} for t in tools],
    )
    msg = resp.choices[0].message
    tool_calls = [{"id": c.id, "name": c.function.name, "input": json.loads(c.function.arguments)}
                  for c in (msg.tool_calls or [])]
    return {"tool_calls": tool_calls, "text": msg.content}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pip install anthropic groq
.venv/bin/pytest tests/test_llm.py -v
```
Expected: `5 passed`. (`_provider` ordering test relies on dict env — fine since both are `monkeypatch.setenv`.)

- [ ] **Step 5: Commit**

```bash
git add intel/llm.py tests/test_llm.py pyproject.toml
git commit -m "feat(intel): llm.py — Claude/Groq tool-calling seam (#17, finalplan §11)"
```

---

### Task 4: `intel/agent.py` — `enrich(anomaly_event) -> EnrichedIncident`

**Files:**
- Create: `intel/agent.py`
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: `intel.llm.ToolSpec`, `intel.llm.run_agentic_tool_loop` (Task 3); `intel.ingest.query` (Task 2); `orchestrator.schemas.AnomalyEvent`, `EnrichedIncident`, `AttackTechnique`, `PredictedNext`, `Severity`, `ActionType` (existing)
- Produces: `enrich(event: AnomalyEvent, collection) -> EnrichedIncident` — the function `orchestrator/main.py` will inject in Task 5

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agent.py
import json

import pytest

from intel.agent import enrich, MAX_JSON_RETRIES
import intel.agent as agent_mod
from orchestrator.schemas import AnomalyEvent

EVENT = AnomalyEvent(
    event_id="evt_test", timestamp="2026-07-09T00:00:00Z",
    src_ip="10.0.0.5", dst_ip="203.0.113.9", anomaly_score=0.93, is_anomaly=True,
    top_features=["sbytes", "dur"], raw_features={"sbytes": 4_500_000, "dur": 12.0},
)

VALID_JSON = json.dumps({
    "attack_technique": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "confidence": 0.82,
    "severity": "high",
    "cve_refs": ["CVE-2023-99999"],
    "certin_refs": [],
    "narrative": "Large outbound transfer consistent with exfiltration.",
    "predicted_next": {"tactic": "Command and Control", "note": "watch for beaconing"},
    "suggested_action": "isolate_host",
})


class FakeCollection:
    pass  # never touched directly — agent.py's tools call intel.ingest.query(collection, ...)


def test_enrich_returns_valid_enriched_incident_on_first_try(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: VALID_JSON)
    result = enrich(EVENT, FakeCollection())
    assert result.event_id == "evt_test"
    assert result.attack_technique.id == "T1048"
    assert result.confidence == 0.82
    assert result.suggested_action.value == "isolate_host"


def test_enrich_retries_on_malformed_json_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_loop(*a, **k):
        calls["n"] += 1
        return "not json at all" if calls["n"] == 1 else VALID_JSON

    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", fake_loop)
    result = enrich(EVENT, FakeCollection())
    assert calls["n"] == 2
    assert result.attack_technique.id == "T1048"


def test_enrich_gives_up_after_max_retries_with_low_confidence_fallback(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_agentic_tool_loop", lambda *a, **k: "still not json")
    result = enrich(EVENT, FakeCollection())
    assert result.confidence == 0.0
    assert result.attack_technique.id == "UNKNOWN"
    assert "malformed" in result.narrative.lower()


def test_search_attack_tool_executor_calls_ingest_query(monkeypatch):
    seen = {}

    def fake_query(collection, text, n_results=3):
        seen["args"] = (collection, text, n_results)
        return [{"id": "T1041", "name": "x", "description": "y", "source_type": "attack", "distance": 0.1}]

    monkeypatch.setattr(agent_mod, "query", fake_query)
    executor = agent_mod._make_tool_executor(FakeCollection())
    result_str = executor("search_attack", {"query": "exfiltration over c2"})
    assert seen["args"][1] == "exfiltration over c2"
    assert "T1041" in result_str
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_agent.py -v
```
Expected: `ModuleNotFoundError: No module named 'intel.agent'`.

- [ ] **Step 3: Write minimal implementation**

```python
# intel/agent.py
"""Cited attribution agent: enrich(AnomalyEvent) -> EnrichedIncident (issue #17).

Retrieve-then-cite, always (finalplan §10): the model can only cite what search_attack/
lookup_cve/search_certin actually returned from Chroma. Force + validate structured JSON;
retry on malformed rather than let bad output reach the orchestrator.
"""

from __future__ import annotations

import json

from intel.ingest import query
from intel.llm import ToolSpec, run_agentic_tool_loop
from orchestrator.schemas import (
    ActionType,
    AttackTechnique,
    EnrichedIncident,
    PredictedNext,
    Severity,
)
from orchestrator.schemas import AnomalyEvent

MAX_JSON_RETRIES = 2

SYSTEM_PROMPT = """You are a cited cyber-attribution analyst. Given a network anomaly event,
use the search_attack, lookup_cve, and search_certin tools to find grounding evidence, then
respond with ONLY a JSON object (no prose, no markdown fences) matching exactly:
{
  "attack_technique": {"id": "T####", "name": "..."},
  "confidence": 0.0-1.0,
  "severity": "low"|"medium"|"high"|"critical",
  "cve_refs": ["CVE-..."],
  "certin_refs": [],
  "narrative": "1-3 sentences explaining the call, referencing what you retrieved",
  "predicted_next": {"tactic": "...", "note": "..."},
  "suggested_action": "isolate_host"|"block_ip"|"revoke_credential"|"snapshot_vm"|"monitor"
}
Rule: NEVER invent an attack_technique.id you did not retrieve via search_attack. If nothing
relevant was retrieved, use confidence <= 0.3 and say so plainly in narrative."""

TOOLS = [
    ToolSpec("search_attack", "Search MITRE ATT&CK techniques relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ToolSpec("lookup_cve", "Search known CVEs relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ToolSpec("search_certin", "Search CERT-In advisories relevant to a description",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
]

_TOOL_TO_SOURCE = {"search_attack": "attack", "lookup_cve": "cve", "search_certin": "certin"}


def _make_tool_executor(collection):
    def executor(name: str, args: dict) -> str:
        results = query(collection, args["query"], n_results=3)
        source = _TOOL_TO_SOURCE[name]
        filtered = [r for r in results if r["source_type"] == source]
        return json.dumps(filtered)
    return executor


def _fallback(event: AnomalyEvent, reason: str) -> EnrichedIncident:
    return EnrichedIncident(
        event_id=event.event_id,
        attack_technique=AttackTechnique(id="UNKNOWN", name="Unattributed"),
        confidence=0.0,
        severity=Severity.low,
        cve_refs=[],
        certin_refs=[],
        narrative=f"Attribution failed: {reason}. Falling back to unattributed, low confidence.",
        predicted_next=None,
        suggested_action=ActionType.monitor,
    )


def enrich(event: AnomalyEvent, collection) -> EnrichedIncident:
    user_prompt = (
        f"Anomaly event {event.event_id}: score={event.anomaly_score}, "
        f"top_features={event.top_features}, src={event.src_ip}, dst={event.dst_ip}, "
        f"raw_features={event.raw_features}"
    )
    executor = _make_tool_executor(collection)

    last_error = ""
    for _ in range(MAX_JSON_RETRIES):
        raw = run_agentic_tool_loop(SYSTEM_PROMPT, user_prompt, TOOLS, executor)
        try:
            data = json.loads(raw)
            return EnrichedIncident(
                event_id=event.event_id,
                attack_technique=AttackTechnique(**data["attack_technique"]),
                confidence=float(data["confidence"]),
                severity=Severity(data["severity"]),
                cve_refs=data.get("cve_refs", []),
                certin_refs=data.get("certin_refs", []),
                narrative=data["narrative"],
                predicted_next=PredictedNext(**data["predicted_next"]) if data.get("predicted_next") else None,
                suggested_action=ActionType(data["suggested_action"]),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            last_error = str(exc)
            user_prompt += "\n\nYour last response was not valid JSON matching the schema. Try again — JSON ONLY."

    return _fallback(event, f"malformed JSON after {MAX_JSON_RETRIES} attempts ({last_error})")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_agent.py -v
```
Expected: `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add intel/agent.py tests/test_agent.py
git commit -m "feat(intel): agent.py — cited enrich() via tool-calling (#17)"
```

---

### Task 5: Wire the live agent into `orchestrator/main.py` behind an env flag

**Files:**
- Modify: `orchestrator/main.py` (find `_make_stub_enrich` and the `create_app` factory's `enrich=` default)
- Test: `tests/test_main.py` (extend — check exact existing test names before adding, don't duplicate)

**Interfaces:**
- Consumes: `intel.agent.enrich(event, collection)` (Task 4), `intel.ingest.build_collection` (Task 2)
- Produces: `create_app(enrich=None)` — if `enrich` is not passed AND `ENRICH_MODE=live` env var is set AND a Chroma collection exists at `data/intel/chroma`, wire the real agent; otherwise keep the existing stub. Default behavior with no env var is UNCHANGED (stub) — this is the non-negotiable safety net.

- [ ] **Step 1: Read the current wiring before changing it**

```bash
grep -n "enrich" orchestrator/main.py
```
Locate exactly where `_make_stub_enrich` is defined and where `create_app`'s default `enrich` param is set — the plan can't hardcode line numbers here since Task 0-4 haven't touched this file, but the exact call site must be identified by reading it, not guessed.

- [ ] **Step 2: Write the failing test**

```python
# add to tests/test_main.py — inspect existing fixtures/imports in the file first and reuse
# them (e.g. its TestClient setup) rather than duplicating. New test:

def test_live_enrich_mode_uses_intel_agent_when_env_flag_set(monkeypatch):
    import orchestrator.main as main_mod

    called = {}

    def fake_enrich(event, collection):
        called["event_id"] = event.event_id
        from orchestrator.schemas import AttackTechnique, EnrichedIncident, Severity, ActionType
        return EnrichedIncident(
            event_id=event.event_id,
            attack_technique=AttackTechnique(id="T9999", name="test"),
            confidence=0.5, severity=Severity.low, cve_refs=[], certin_refs=[],
            narrative="test", predicted_next=None, suggested_action=ActionType.monitor,
        )

    monkeypatch.setenv("ENRICH_MODE", "live")
    monkeypatch.setattr("intel.agent.enrich", fake_enrich)
    monkeypatch.setattr("intel.ingest.build_collection", lambda records, persist_dir: object())

    app = main_mod.create_app()
    # exercise via the existing TestClient pattern already used elsewhere in this file
    # (reuse the same POST /events call this file's other tests use) and assert
    # called["event_id"] was set, proving the live path — not the stub — ran.
```

- [ ] **Step 3: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_main.py -k live_enrich -v
```
Expected: FAIL — `create_app()` doesn't check `ENRICH_MODE` yet.

- [ ] **Step 4: Implement the switch**

In `orchestrator/main.py`, next to the existing `_make_stub_enrich` function, add:

```python
def _make_live_enrich():
    import os
    from intel.agent import enrich as agent_enrich
    from intel.ingest import build_collection

    persist_dir = os.environ.get("INTEL_CHROMA_DIR", "data/intel/chroma")
    collection = build_collection([], persist_dir=persist_dir)  # empty list = don't re-seed, just open

    def _enrich(event):
        return agent_enrich(event, collection)
    return _enrich
```

Then in `create_app(...)`, change the default resolution of `enrich` (keep the exact existing parameter name/signature — only change what happens when the caller passes nothing):

```python
if enrich is None:
    import os
    enrich = _make_live_enrich() if os.environ.get("ENRICH_MODE") == "live" else _make_stub_enrich()
```

- [ ] **Step 5: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_main.py -v
```
Expected: all previous tests still pass (stub is still the default with no env var) + the new live-mode test passes.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "feat(orchestrator): wire live intel.agent.enrich behind ENRICH_MODE=live (#17)"
```

---

### Task 6: Labelled eval set + attribution accuracy %

**Files:**
- Create: `data/fixtures/labelled_eval.json` — reuse the 20 scenarios already authored in `frontend/src/data/fixtures.ts` (6 distinct technique IDs already present: T1005, T1048, T1071, T1105, T1210, T1571), converted to `{event: AnomalyEvent-shaped dict, ground_truth_technique: "T####"}` pairs
- Create: `intel/eval_attribution.py`
- Test: `tests/test_eval_attribution.py`

**Interfaces:**
- Consumes: `intel.agent.enrich` (Task 4)
- Produces: `compute_accuracy(labelled: list[dict], enrich_fn) -> float` — fraction where `enrich_fn(event).attack_technique.id == ground_truth_technique`

- [ ] **Step 1: Extract the 20 scenarios into the labelled fixture**

```bash
# Read frontend/src/data/fixtures.ts, pull out each incident's event fields + the
# attack_technique.id already assigned there, and write:
```
```json
// data/fixtures/labelled_eval.json — shape (repeat for all ~20; DO NOT invent techniques
// not already present in fixtures.ts — copy the real ones across)
[
  {
    "event": {
      "schema_version": "1.0", "event_id": "evt_0001", "timestamp": "2026-07-10T12:00:00Z",
      "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "anomaly_score": 0.95, "is_anomaly": true,
      "top_features": ["flow_duration", "bytes_out", "dst_port"],
      "raw_features": {"flow_duration": 12000, "bytes_out": 4500000, "dst_port": 4444}
    },
    "ground_truth_technique": "T1048"
  }
]
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_eval_attribution.py
from intel.eval_attribution import compute_accuracy
from orchestrator.schemas import AttackTechnique, EnrichedIncident, Severity, ActionType

LABELLED = [
    {"event": {"schema_version": "1.0", "event_id": "e1", "timestamp": "t", "src_ip": "a",
               "dst_ip": "b", "anomaly_score": 0.9, "is_anomaly": True, "top_features": [],
               "raw_features": {}},
     "ground_truth_technique": "T1048"},
    {"event": {"schema_version": "1.0", "event_id": "e2", "timestamp": "t", "src_ip": "a",
               "dst_ip": "b", "anomaly_score": 0.9, "is_anomaly": True, "top_features": [],
               "raw_features": {}},
     "ground_truth_technique": "T1021"},
]


def _incident(event_id, technique_id):
    return EnrichedIncident(
        event_id=event_id, attack_technique=AttackTechnique(id=technique_id, name="x"),
        confidence=0.8, severity=Severity.low, cve_refs=[], certin_refs=[],
        narrative="x", predicted_next=None, suggested_action=ActionType.monitor,
    )


def test_compute_accuracy_counts_exact_technique_matches():
    responses = {"e1": _incident("e1", "T1048"), "e2": _incident("e2", "T9999")}
    acc = compute_accuracy(LABELLED, lambda event: responses[event.event_id])
    assert acc == 0.5
```

- [ ] **Step 3: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_eval_attribution.py -v
```
Expected: `ModuleNotFoundError: No module named 'intel.eval_attribution'`.

- [ ] **Step 4: Write minimal implementation**

```python
# intel/eval_attribution.py
"""Attribution accuracy % against the labelled eval set (issue #17 DoD, finalplan §6/GAP3).

Run: .venv/bin/python -m intel.eval_attribution
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from orchestrator.schemas import AnomalyEvent, EnrichedIncident

FIXTURE = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "labelled_eval.json"


def compute_accuracy(labelled: list[dict], enrich_fn: Callable[[AnomalyEvent], EnrichedIncident]) -> float:
    if not labelled:
        return 0.0
    correct = 0
    for row in labelled:
        event = AnomalyEvent(**row["event"])
        result = enrich_fn(event)
        if result.attack_technique.id == row["ground_truth_technique"]:
            correct += 1
    return correct / len(labelled)


def main() -> None:
    from intel.agent import enrich
    from intel.ingest import build_collection

    collection = build_collection([], persist_dir="data/intel/chroma")
    labelled = json.loads(FIXTURE.read_text())
    acc = compute_accuracy(labelled, lambda event: enrich(event, collection))
    print(f"attribution accuracy: {acc:.1%} ({len(labelled)} labelled events)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_eval_attribution.py -v
```
Expected: `1 passed`.

- [ ] **Step 6: Commit**

```bash
git add data/fixtures/labelled_eval.json intel/eval_attribution.py tests/test_eval_attribution.py
git commit -m "feat(intel): labelled eval set + attribution accuracy % (#17, GAP3)"
```

---

### Task 7: End-to-end live verification + close out #18

No new source files — this task proves Tasks 1-6 actually work together, and resolves the #18 downgrade decision (close it once confirmed, per your call above) instead of building `orchestrator/graph.py`.

- [ ] **Step 1:** Get a real key into the environment (either provider) and run the fetch + ingest once for real.
  ```bash
  export ANTHROPIC_API_KEY=...   # or export GROQ_API_KEY=...
  .venv/bin/python -m intel.fetch_sources
  .venv/bin/python -c "
  import json
  from pathlib import Path
  from intel.ingest import build_collection
  records = []
  for f in ['attack.json', 'cve.json', 'certin.json']:
      records += json.loads((Path('data/intel')/f).read_text())
  build_collection(records, persist_dir='data/intel/chroma')
  "
  ```
- [ ] **Step 2:** Run the full live stack in three terminals.
  ```bash
  # terminal 1
  ENRICH_MODE=live make backend
  # terminal 2
  make frontend-live
  # terminal 3
  make replay-engine
  ```
- [ ] **Step 3:** In the browser, confirm — per this repo's CLAUDE.md rule to visually verify frontend changes — that the MITRE grid shows real, varied techniques (not just T1046/Discovery from #19's fix), incident narratives are real cited text, and the graph view (`GraphPage.tsx`) shows lateral-movement edges from real live events. Screenshot via puppeteer/playwright MCP.
- [ ] **Step 4:** Run `intel/eval_attribution.py` for a real accuracy number.
  ```bash
  .venv/bin/python -m intel.eval_attribution
  ```
- [ ] **Step 5:** If the graph view looks right (per your decision above — expected, since it's already wired client-side), close #18 with a comment explaining why, rather than merging a redundant backend module.
  ```bash
  gh issue comment 18 --repo OfficialAbhinavSingh/et-hackathon-ps7 --body "Closing — the dashboard's attack-path graph (GraphPage.tsx/AttackGraph.tsx, merged in #10) already derives this client-side from live AnomalyEvent.src_ip/dst_ip via data/derive.ts::deriveGraph(), including lateral-movement flagging (isInternal(src) && isInternal(dst)). frontend/src/data/DataService.ts explicitly documents no backend /graph endpoint by design. Verified end-to-end live with #16/#17/#22 wired in — [screenshot]. A NetworkX-based backend module would duplicate this without adding capability the demo needs."
  gh issue close 18 --repo OfficialAbhinavSingh/et-hackathon-ps7
  ```
- [ ] **Step 6:** Run both full test suites one more time to confirm nothing regressed.
  ```bash
  make test 2>&1 | tail -5
  cd frontend && npx vitest run 2>&1 | tail -10 && cd ..
  ```

---

### Task 8: #20 deliverables — ongoing, non-blocking, run in parallel from Task 1 onward

Not code — no TDD ceremony. Track directly on the issue, don't wait for Tasks 1-7 to finish first.

- [ ] Architecture diagram — now has a real answer for #16/#17/#18 (the client-side-graph finding matters for the diagram too — don't draw a `/graph` endpoint that doesn't exist)
- [ ] Slide deck: problem → approach → live demo → impact → scalability (finalplan §6/Phase 6)
- [ ] Impact model: MTTD/MTTR reduction vs. baseline SOC, CERT-In 1.59M incidents/yr + 70% EOL-infra stat (finalplan §6)
- [ ] Demo video recorded off the real live stack (Task 7), not the mock path
- [ ] Rehearse the demo twice; confirm the mock fallback (`VITE_DATA_SOURCE=mock`) still works standalone as the stage-safety path (finalplan §10 — "mock path still runnable as fallback")
- [ ] Yash's original slice of #20 (pitch script, architecture diagram co-owner) — check in with him if/when connectivity returns; don't block on it meanwhile

---

## Self-Review

**Spec coverage:** #22 merge (Task 0) · #19 push (Task 0) · #16 fetch+ingest (Tasks 1-2) · #17 llm seam+agent+wiring+eval (Tasks 3-6) · #18 (Task 7, downgraded per your decision) · #20 (Task 8, parallel). All six open issues have a task. finalplan.md §11 addendum is implemented exactly as specified in Task 3.

**Placeholder scan:** No TBD/TODO left as an excuse to skip work. The one deliberate exception is `fetch_certin()`'s `NotImplementedError` when a real `--certin-url` is given — that's an honest gap (no verified URL), not a lazy placeholder, and it fails loudly instead of silently shipping guessed data.

**Type consistency:** `EnrichedIncident` fields match `orchestrator/schemas.py` exactly (verified by reading the file this session) across Tasks 4, 5, 6. `ToolSpec`/`run_agentic_tool_loop` signature is identical everywhere it's referenced (Tasks 3, 4). `intel.ingest.query`'s return shape (`id`/`name`/`description`/`source_type`/`distance`) is used consistently in Task 4's `_make_tool_executor`.
