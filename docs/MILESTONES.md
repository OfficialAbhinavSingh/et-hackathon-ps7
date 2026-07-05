# MILESTONES — PS7 (2-dev build, Jul 6 → demo)

The schedule we run. Five milestones from mid-foundation to demo day. Each has an owner
split (Dev 1 = Detection & Spine · Dev 2 = Agent & Dashboard), concrete tasks, and a
**Definition of Done (DoD)** — the milestone isn't done until every DoD box is checked.

**Golden rule:** the **mocked end-to-end pipeline must work by M1.** After that, every
milestone swaps a mock for a real component while the mock stays as a stage fallback.

---

## M0 — Contracts frozen as code · **today (Jul 6)**

Get the seam nailed down so both devs build in parallel without blocking.

| Dev 1 (Detection & Spine) | Dev 2 (Agent & Dashboard) |
|---------------------------|---------------------------|
| Scaffold repo: `engine/`, `orchestrator/`, `data/fixtures/`. | Confirm the enriched-incident v1.0 schema (severity, predicted_next, suggested_action). |
| Write `orchestrator/schemas.py` — all 3 v1.0 contracts as Pydantic models. Commit + push. | Stub **20 enriched-incident** JSONs → `data/fixtures/`. |
| Write **20 sample anomaly events** → `data/fixtures/`. | Confirm provider = Claude Sonnet 4.6 (`claude-sonnet-4-6`); load `claude-api` skill. |
| FastAPI health-check endpoint runs. | Vite React app scaffolds and boots. |

**DoD:** `schemas.py` pushed · both fixture files committed · FastAPI boots · React boots ·
both devs agree the three contracts are frozen at v1.0.

---

## M1 — Foundation done, mocks green · **by Jul 8**

Both pillars stand alone; the whole pipeline runs on mocks.

| Dev 1 | Dev 2 |
|-------|-------|
| `preprocess.py` + `train.py`: IsoForest on UNSW-NB15; eval (recall, FPR, ROC-AUC) → `engine/RESULTS.md`. | `fetch_sources.py`: ATT&CK + CVE + CERT-In cached to `data/intel/`. |
| `infer.score()` emits valid anomaly-event JSON; `replay.py` streams events. | `ingest.py`: Chroma index built; retrieval sanity checks pass. |
| `pipeline.py` + `policy.py` + `playbooks.py` + `audit.py`: mocked-enrichment pipeline runs end-to-end (ingest → decide → simulated playbook → hash-chained audit → response). | `agent.enrich()` returns grounded enriched-incident JSON; hand-verify grounding on 5-6 events. |
| Approval gate works (`POST /approve/{id}`); `GET /stream` (SSE) verified via curl/browser. | Retrieval returns correct techniques for the 20 sample events. |

**DoD:** anomaly model trained + eval numbers written · `infer.score()` + `replay.py`
work · orchestrator runs full mocked pipeline · approval gate + audit + SSE verified ·
Chroma index built · `agent.enrich()` returns valid cited JSON · **both can explain their
pillars out loud** (team dry-run).

---

## M2 — Real integration · **Jul 9–12**

Swap mocks for real components. This is where the two tracks meet.

| Dev 1 | Dev 2 |
|-------|-------|
| Replace mock enrichment in `pipeline.py` with a real call to `agent.enrich()`. | Expose `enrich()` as an importable function; harden confidence + grounding. |
| Wire `replay.py` → `POST /events` so the live feed drives the real pipeline. | Populate `predicted_next` (kill-chain next stage). |
| Tune `policy.py` against real severity values coming from the agent. | Handle agent edge cases: nothing retrieved → low confidence, never a fake technique ID. |
| Ship a **demo-ready SSE stream** so Dev 2 can start the dashboard (unblocks M3). | Validate enriched JSON against `schemas.py`; retry on malformed. |

**DoD:** a real anomaly event flows engine → orchestrator → real agent → decision →
simulated action → audit, end-to-end, no mocks in the path · SSE stream emits real
enriched incidents · mock path still runnable as fallback.

---

## M3 — Live dashboard · **Jul 12–15**

Make it visible. Dev 2 leads; Dev 1 supports on backend endpoints.

| Dev 1 | Dev 2 |
|-------|-------|
| Finalize + stabilize `GET /stream`, `/incidents`, `/incidents/{id}`, `/audit`, `POST /approve/{id}`. | D1 live alert feed (EventSource on `/stream`). |
| Fix any CORS / payload-shape issues the frontend hits. | D2 incident detail (technique, confidence, severity, citations, narrative, predicted_next). |
| Ensure audit trail is query-friendly for the audit view. | D3 approval queue with working Approve button; D4 MITRE grid + audit view. |

**DoD:** dashboard renders the live feed while `replay.py` ticks · click-through incident
brief works · approve button releases a held action and the status updates live · MITRE
map + audit trail visible · full happy-path demo runs on one screen.

---

## M4 — Pitch + polish · **Jul 15 → demo day** (co-owned)

| Dev 1 | Dev 2 |
|-------|-------|
| **Impact model:** MTTD/MTTR reduction vs baseline SOC; cite CERT-In 1.59M incidents/yr + 70% EOL-infra stat. | Dashboard polish; demo script + rehearsed click-path. |
| Keep the mock fallback path alive + tested for stage safety. | Slide deck: problem → approach → live demo → impact → scalability. |
| Rehearse explaining IsoForest, the approval gate, tamper-evident audit. | Rehearse explaining ATT&CK, RAG grounding, "predict next stage". |

**DoD:** impact model with defensible numbers · slide deck done · **full demo dry-run
completed at least twice** · fallback path tested · both devs can field technical
questions on any pillar.

---

## Dependency cheat-sheet (who blocks whom)

- **M0 `schemas.py` + fixtures** block everything → do them first, today.
- **Dev 2's stubbed enriched JSONs** unblock Dev 1's mocked pipeline (M1).
- **Dev 1's 20 anomaly events** unblock Dev 2's agent (M1).
- **Dev 1's SSE stream (M2)** unblocks Dev 2's dashboard (M3) → ship it early.
- Nothing else is a hard blocker — that's the point of the mock-first design.
