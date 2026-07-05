# PS7 — AI-Driven Cyber Resilience for Critical National Infrastructure

**ET AI Hackathon 2026 · Team build doc · 2-dev build (foundation → demo)**

> **This doc was re-planned for a 2-person team.** The original 3-dev split (Dev A / B / C)
> has been folded into two owners. See §3. Contracts have been tightened (versioned +
> enums + `severity` + action lifecycle) — see §4, marked **[v1.0]**.

---

## 1. What we are building (one paragraph)

An AI platform that watches network/host telemetry, learns what "normal" looks like,
and flags **behavioural anomalies** (not signature matches). When it sees something
suspicious, an LLM-agent layer explains *why* it is suspicious — mapping the activity
to a **MITRE ATT&CK** technique, pulling the relevant **CVE** and **CERT-In advisory**,
and generating a human-readable incident brief. A **SOAR orchestrator** then proposes
(and in demo, simulates) a containment action — isolate host, block IP, revoke
credential — with a full audit trail and a human-approval gate. The differentiator vs a
plain ML dashboard is the **GenAI reasoning + citation layer** that turns a raw anomaly
score into an analyst-grade explanation and action.

## 2. Why this wins (tie to judging)

Judging weights: Innovation 25 · Business Impact 25 · Technical Excellence 20 · Scalability 15 · UX 15.

- **Innovation** — behavioural anomaly + LLM ATT&CK attribution + auto-containment is more than "another dashboard".
- **Business Impact** — quantify MTTD/MTTR reduction vs baseline SOC. Cite CERT-In (1.59M incidents/yr) and the 70% end-of-life-infra stat from the brief. Build this impact model early, not the last night.
- **Technical Excellence** — real ML on real IDS datasets + RAG + agent orchestration = genuine range.
- **Scalability** — argue the architecture (streaming ingestion, stateless agents) scales; don't need to prove at scale.
- **UX** — clean dashboard: live alert feed, attack timeline, MITRE map, risk-ranked queue.

## 3. The 2-dev split (Approach: "Detection+Spine" / "Reasoning+Face")

Three pillars, two people. Each dev owns two adjacent pillars end-to-end. The JSON
contracts (§4) decouple the two tracks so both build in parallel against mocks.

| Dev | Owns | Pillars | Doc |
|-----|------|---------|-----|
| **Dev 1 — Detection & Spine** | the data path + the glue | Anomaly Detection Engine **+** SOAR Orchestrator/Backend | [`DEV-1-detection-and-spine.md`](DEV-1-detection-and-spine.md) |
| **Dev 2 — Agent & Dashboard** | the intelligence you can see | RAG + LLM Agent **+** React Dashboard | [`DEV-2-agent-and-dashboard.md`](DEV-2-agent-and-dashboard.md) |

**Why this split:** Dev 1's two pieces are both Python and directly coupled (the
orchestrator consumes the anomaly engine's output), so one person holds the whole
detection→action path. Dev 2's two pieces are the GenAI differentiator + the UX that
shows it off — the two headline demo moments, each with a clear owner. Neither blocks
the other during foundation because both mock the other side.

**Shared, late-phase work:** the pitch deck + impact model (§2) is co-owned — see
[`MILESTONES.md`](MILESTONES.md) M4.

## 4. How the pieces talk — the contracts **[v1.0]** (read before coding)

We freeze **JSON contracts** on day 1 so the two tracks build in parallel and mock each
other. `schema_version` is on every payload so mismatches fail loudly. Dev 1 owns these
as **Pydantic models in `orchestrator/schemas.py`** — Dev 2 imports that file so contracts
can't drift.

**Anomaly event** (Dev 1: engine → orchestrator → agent):
```json
{
  "schema_version": "1.0",
  "event_id": "evt_0001",
  "timestamp": "2026-07-10T12:00:00Z",
  "src_ip": "10.0.0.5",
  "dst_ip": "10.0.0.9",
  "anomaly_score": 0.93,
  "is_anomaly": true,
  "top_features": ["flow_duration", "bytes_out", "dst_port"],
  "raw_features": { "flow_duration": 12000, "bytes_out": 4500000, "dst_port": 4444 }
}
```
> **[v1.0] Rule:** `top_features` MUST be human-readable feature names (e.g. `bytes_out`,
> not a one-hot column like `proto_tcp` or an index). The agent reasons over these names.

**Enriched incident** (Dev 2: agent → orchestrator → frontend):
```json
{
  "schema_version": "1.0",
  "event_id": "evt_0001",
  "attack_technique": { "id": "T1048", "name": "Exfiltration Over Alternative Protocol" },
  "confidence": 0.87,
  "severity": "high",
  "cve_refs": ["CVE-2024-1234"],
  "certin_refs": ["CIAD-2024-0012"],
  "narrative": "Large outbound transfer on non-standard port 4444 after hours...",
  "predicted_next": { "tactic": "Lateral Movement", "note": "watch east-west traffic from 10.0.0.5" },
  "suggested_action": "isolate_host"
}
```
> **[v1.0] Added:** `severity` (`low|medium|high|critical`, derived from CVE CVSS or
> technique impact — the orchestrator's policy keys on it). `predicted_next` (stretch,
> optional — `null` if not done). Renamed `recommended_action` → **`suggested_action`** to
> signal it is *advisory*: the orchestrator's policy engine is authoritative (see
> "Decision authority" below).

**Containment action** (Dev 1: orchestrator, simulated):
```json
{
  "schema_version": "1.0",
  "event_id": "evt_0001",
  "action": "isolate_host",
  "target": "10.0.0.5",
  "status": "pending_approval",
  "requires_human_approval": true,
  "actor": "system",
  "audit_log_id": "aud_0001"
}
```
> **[v1.0] Enums frozen:**
> - `action`: `isolate_host` | `block_ip` | `revoke_credential` | `snapshot_vm` | `monitor`
> - `status` (lifecycle): `pending_approval` → `approved` → `simulated_success` | `rejected` | `failed`
> - `actor`: `system` | `human:<name>`

**Decision authority (resolves the old A/B/C ambiguity):** Dev 2's `suggested_action` is a
hint. **Dev 1's `orchestrator/policy.py` is authoritative** — it maps
`(anomaly_score, severity)` → final `action` + `requires_human_approval`. Example policy:
`severity` in {critical, high} and `score ≥ 0.9` → `isolate_host` (needs approval);
`score 0.7–0.9` → `block_ip` (auto); `< 0.7` → `monitor`.

> **Rule:** if a contract changes, bump `schema_version`, announce it in team chat, and
> update this file **and** `schemas.py`. Both devs mock against these until integration.

## 5. Repo layout

```
et-hackathon-ps7/
├── docs/                      # these files
├── data/                      # datasets + cached intel (gitignored — too big)
│   ├── fetch_unsw.py          #   Dev 1: dataset fetch
│   ├── intel/                 #   Dev 2: cached ATT&CK/CVE/CERT-In JSON
│   └── fixtures/              #   COMMITTED small samples: 20 anomaly events + 20 enriched
│                              #   incidents + tiny intel slice (demo reproducibility)
├── engine/                    # Dev 1 — anomaly detection
│   ├── preprocess.py
│   ├── train.py
│   ├── infer.py               #   score(flow) -> anomaly event
│   ├── replay.py              #   emits a live-ish event stream
│   └── model/                 #   isoforest.joblib, scaler.joblib
├── orchestrator/              # Dev 1 — SOAR + backend
│   ├── main.py                #   FastAPI app
│   ├── schemas.py             #   the 3 contracts as Pydantic models (SHARED — Dev 2 imports)
│   ├── pipeline.py            #   enrich -> decide -> playbook -> audit
│   ├── policy.py              #   decision table (authoritative)
│   ├── playbooks.py           #   simulated containment actions
│   └── audit.py               #   append-only, hash-chained audit log
├── intel/                     # Dev 2 — RAG + agent
│   ├── fetch_sources.py       #   MITRE ATT&CK + CVE + CERT-In
│   ├── ingest.py              #   chunk + embed into Chroma
│   ├── agent.py               #   enrich(anomaly_event) -> enriched incident
│   └── prompts/
├── frontend/                  # Dev 2 — React dashboard
└── README.md
```

## 6. Milestones & definition of done

The full-hackathon timeline (foundation → integration → dashboard → pitch), with per-dev
tasks and a "definition of done" for each milestone, lives in
**[`MILESTONES.md`](MILESTONES.md)**. Read it — it is the schedule we run.

## 7. Ground rule on studying

We are **not vibecoding this**. Each dev doc has a **"Study first"** section. Spend the
first chunk of time actually understanding your pillars before writing real code — a
security project with hand-wavy internals gets torn apart by technical judges. The study
list is scoped to only what you need.

## 8. Risk flags (stack is mostly-locked — flagging, not changing)

- **[Dev 1] UNSW-NB15 preprocessing eats time.** Encoding/scaling + a clean normal-only
  split is where the day goes, not the model. Budget for it; get the pipeline working on a
  *subset* before scaling up.
- **[Dev 2] Frontend is a heavy M3 lift on top of RAG.** Mitigation: Dev 1 ships a
  demo-ready SSE stream early (M2) so Dev 2 isn't blocked, and Dev 2 builds a
  dead-simple dashboard first (feed + one incident detail), polishing only if ahead.
- **[Both] Keep the mocked pipeline alive to the end.** It is the on-stage fallback if a
  real component breaks.
