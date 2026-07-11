# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An **AI Security Operations Center** for critical national infrastructure (ET AI Hackathon 2026, PS7). It detects anomalies, explains them as cited incident briefs mapped to MITRE ATT&CK, and proposes containment actions behind a human-approval gate with a tamper-evident audit trail.

`docs/finalplan.md` is the **single source of truth** for scope, the frozen data contracts, the target repo layout, and per-pillar non-negotiables. Read it before any substantial change — it explains *why* the code is shaped the way it is.

## Current state vs. plan

All four pillars from `docs/finalplan.md` are built and wired end-to-end on `main`:
- `engine/` — Isolation Forest detection agent (ML), trained on UNSW-NB15. Built (`preprocess.py`, `train.py`, `infer.py`, `replay.py`). Results in `engine/RESULTS.md`.
- `intel/` — RAG + Claude (`claude-sonnet-4-6`, Groq fallback) attribution agent, retrieve-then-cite over a Chroma index of MITRE ATT&CK STIX + NVD CVE + CERT-In. Built (`fetch_sources.py`, `ingest.py`, `agent.py`, `llm.py`). Wired live behind `ENRICH_MODE=live`; the fixture-based stub enrichment (`orchestrator/main.py:_make_stub_enrich`) remains the default/mock fallback.
- Attack-path / lateral-movement graph — deliberately **not** a backend `orchestrator/graph.py`; built client-side instead (`frontend/src/data/derive.ts::deriveGraph`, rendered in `GraphPage.tsx`). Issue #31 closed as satisfied by this.
- `frontend/` — React 19 + Vite + Tailwind + shadcn dashboard. Fully committed (`package.json`, `src/`). `VITE_DATA_SOURCE=mock|live` seam: mock mode runs off 20 committed fixtures, live mode streams from the real backend via SSE.
- Multi-agent orchestration wrapper (`orchestrator/agents.py::build_orchestration`) — frames Detection → Attribution → Response as three named agents, streamed as a 4th SSE frame, rendered on the Operations page (`AgentOrchestration.tsx`).

Outstanding: architecture diagram, pitch deck, demo video (issue #33 — non-code deliverables, not part of this codebase). PR #35 (real srcip/dstip/ports from the raw UNSW-NB15 dump, replacing the current synthetic-topology inference) is open as a draft, not yet implemented.

The design was "walking skeleton, then swap mocks for real": each pillar replaced a mock behind an unchanging contract, so `main` stayed runnable throughout. When touching a pillar, keep injecting through the existing seams (`enrich=`, `ENRICH_MODE`, `VITE_DATA_SOURCE`) rather than rewriting the pipeline.

## Commands

Setup and tasks go through the `Makefile` (run `make help` to list targets):

- `make setup` — create `.venv`, install backend (editable `-e .[dev]`) + frontend deps
- `make backend` — run FastAPI on `:8000` with auto-reload
- `make test` — backend test suite (`pytest -q`)
- `make replay` — feed `data/fixtures/anomaly_events.json` into a running backend to drive the live feed

Run a single test: `.venv/bin/pytest tests/test_pipeline.py::test_high_risk_event_isolates_the_internal_host_and_holds`

`pyproject.toml` is the single source of truth for Python deps; `requirements.txt` just does `-e .[dev]`. `pythonpath = ["."]` in `pyproject.toml` lets the suite run before an editable install.

## Architecture

The backend runs one anomaly event through a linear pipeline. Trace the flow through these files:

- **`orchestrator/schemas.py`** — the **contract guardian**. The three v1.0 contracts (`AnomalyEvent`, `EnrichedIncident`, `ContainmentAction`) as Pydantic models with frozen enums (`Severity`, `ActionType`, `ActionStatus`). Everything imports this so contracts cannot drift. Any change → bump `schema_version` and update `docs/finalplan.md` §4.
- **`orchestrator/main.py`** — FastAPI app (`create_app`) + endpoints. `POST /events` runs the pipeline and **publishes** three typed frames (`anomaly`, `enriched`, `containment`) to every open `GET /stream` (SSE) connection via an in-memory `Broadcaster` (one `asyncio.Queue` per client). All frames are retained in `messages` and replayed to late/reconnecting clients so the feed is never empty. Enrichment is dependency-injected (`enrich=` param) — this is the seam for the real attribution agent.
- **`orchestrator/pipeline.py`** — the glue: `enrich → decide (policy) → act (playbook) → audit`. `enrich`, `audit`, `playbooks`, and `decide` are all injected so each stays independently testable and swappable.
- **`orchestrator/policy.py`** — the **authoritative** decision table. Pure function `decide(anomaly_score, severity) → Decision(action, requires_human_approval)`. The agent's `suggested_action` is only a hint; this is what actually decides. Keep it a readable table matching §4.
- **`orchestrator/playbooks.py`** — simulated containment. Everything is SIMULATED (sets a status, returns; nothing touches a real firewall/EDR). High-blast-radius actions are held in-memory at `pending_approval` until `approve()` releases them — the graded human-in-the-loop requirement.
- **`orchestrator/audit.py`** — append-only, hash-chained audit log (JSONL). Genuinely tamper-evident: `entry_hash = sha256(prev_hash + canonical(entry))`.

Endpoints: `GET /health` · `POST /events` · `GET /incidents` · `GET /incidents/{id}` · `POST /approve/{id}` · `GET /audit` · `GET /stream` (SSE).

## Critical invariants (breaking these loses the demo)

- **The audit hash format is a cross-language contract** with the frontend (`frontend/src/data/hashChain.ts`, re-verified client-side). The canonical string is compact JSON — `separators=(",",":")`, `ensure_ascii=False` to match JS `JSON.stringify` byte-for-byte — over exactly these fields in this order: `audit_log_id, timestamp, event_id, action, actor, detail`; genesis `prev_hash = ""`. Do not change field order, whitespace, or encoding without updating both sides.
- **`policy.py` is authoritative** for the final action + approval requirement, never the LLM's `suggested_action`.
- **Detection must stay unsupervised** when built (learn "normal", flag deviations; no labelled attack/benign classifier — that would be signature-matching). Report recall + false-positive rate, never accuracy alone.
- **Attribution must retrieve-then-cite** when built. Never invent a technique ID; lower confidence when nothing is retrieved. Force + validate structured JSON, retry on malformed.
- **`top_features` are human-readable names** (`bytes_out`, not a column index); always keep `raw_features`. `src_ip`/`dst_ip` are the attack-path graph edges — carry them from day one.

## Conventions

- Comments explain *why* (the contract, the seam, the invariant), not *what*. Match that density.
- Tests are behavior-named (`test_high_risk_event_isolates_the_internal_host_and_holds`) and use dependency injection with fakes rather than mocking internals. Follow that style.

## Git

The user handles all git operations themselves — do not run git commands.
