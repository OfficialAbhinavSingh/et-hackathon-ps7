# FINAL PLAN — PS7: AI-Driven Cyber Resilience for Critical National Infrastructure

**ET AI Hackathon 2026 · Problem Statement 7 · Finalized build plan**
**Date:** 2026-07-07 · **Status:** approved, ready to execute

> **This is the single, self-contained source of truth** — what we build, in what order, the
> frozen data contracts (§4), the repo layout (§9), and the per-pillar implementation rules
> (§10). No other planning doc is needed; everything required to start building lives here.
> It folds in the gap analysis against the official PS7 brief (see §2).

---

## 1. What we're building

An **AI Security Operations Center** for critical national infrastructure that **detects,
explains, and responds** to cyberattacks — and *shows its work*. The differentiator vs. a
plain ML dashboard is the **reasoning + citation + auto-containment** layer: it turns a raw
anomaly score into an analyst-grade, cited incident brief mapped to MITRE ATT&CK, then
proposes a containment action behind a human-approval gate with a tamper-evident audit trail.

Presented as a **multi-agent pipeline**:

```
 [1] DETECTION AGENT         [2] ATTRIBUTION &            [4] DASHBOARD
 learn "normal" traffic,         PREDICTION AGENT          live feed · incident
 flag deviations         ──►  RAG over ATT&CK/CVE/     ──► brief · MITRE map ·
 (Isolation Forest,           CERT-In → cited              attack-path graph ·
 unsupervised, no             technique + next-stage       approval queue ·
 signatures)                  prediction                   audit view · metrics
      │                            │                             ▲
      └────────► [3] RESPONSE ORCHESTRATOR AGENT ─────────────────┘
                 policy decides action · human-approval gate above
                 blast-radius threshold · hash-chained audit · SSE stream
                 (FastAPI + Pydantic)
```

## 2. Why this wins — mapped to judging + gap fixes

Judging weights: **Innovation 25 · Business Impact 25 · Technical Excellence 20 · Scalability 15 · UX 15.**

Our gap analysis against the official brief found the foundation on-target but with five
scoreable gaps. This plan closes all five (🎯 markers throughout):

| Gap | What was missing | Fix in this plan |
|-----|------------------|------------------|
| 🎯 **GAP1** | PS asks for "Agentic AI / Multi-Agent Systems"; our docs said "one agent, no swarm" | Framed as 3 coordinating agents (Detection · Attribution · Response) — Phase 4 |
| 🎯 **GAP2** | PS lists Graph AI + Knowledge Graphs; we had none ("a grid, not a fancy graph") | Attack-path / lateral-movement graph from event correlation + STIX edges — Phase 4 |
| 🎯 **GAP3** | Evaluation Focus wants attribution accuracy % + automation coverage %; unmeasured | Labelled eval set + coverage metric, surfaced in UI — Phases 3–4 |
| 🎯 **GAP4** | Challenge statement says "heterogeneous IT **and OT**"; we were IT-only | Telemetry-agnostic ingest in architecture + one OT event + ATT&CK ICS nod — Phase 4 |
| 🎯 **GAP5** | Required deliverables: Architecture Diagram + Demo Video weren't tracked | Both produced — Phase 6 |

**Evaluation-Focus scorecard we are targeting (judges score these directly):**

- ✅ Anomaly detection rate + **false-positive rate** on UNSW-NB15 → `engine/RESULTS.md`
- ✅ **APT attribution accuracy** at MITRE technique level → labelled eval, reported as %
- ✅ **Incident-response automation coverage** → `autonomous_steps / total_steps` as %
- ✅ **MTTD/MTTR** improvement vs. baseline SOC → impact model
- ✅ **Full auditability** → hash-chained, tamper-evident audit log (we exceed the ask)

## 3. Approach — Walking Skeleton, then swap mocks for real

We rejected two common approaches:

- ❌ **Build each pillar fully, then integrate** — integration explodes at the end; nothing
  demoable until the last night.
- ❌ **Demo-first, all mocks** — wins UX, collapses under technical questioning.

We chose: **✅ Walking skeleton → deepen one pillar at a time behind frozen contracts.**

**Golden rule:** *there is always something that runs.* Every phase ends at a **demoable
checkpoint**. We only ever replace **one mock at a time**, behind an unchanging contract, so
`main` stays green and demoable. The mocked path is kept alive to the end as the **on-stage
fallback**.

## 4. The contracts (the seam) — frozen day one

Three JSON contracts, defined here and mirrored as **Pydantic models in
`orchestrator/schemas.py`** (the guardian file — everything imports it so contracts can't
drift). `schema_version: "1.0"` on every payload; any change → bump the version, announce it,
update this section **and** `schemas.py`.

**Contract 1 — Anomaly event** (Detection agent → orchestrator → attribution agent):
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
> **Rules:** `top_features` MUST be human-readable names (`bytes_out`, not `proto_tcp` or a
> column index) — the agent reasons over them. Always keep `raw_features` (the agent needs real
> numbers, not just a score). **`src_ip` + `dst_ip` are the edges of the attack-path graph**
> (🎯 GAP2) — carry them from day one.

**Contract 2 — Enriched incident** (attribution agent → orchestrator → frontend):
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
> **Rules:** `severity` ∈ `low|medium|high|critical` (derive from CVE CVSS / technique impact;
> the policy engine keys on it). `predicted_next` is optional — `null` if not done.
> `suggested_action` is **advisory only** — `policy.py` is authoritative (see below).
> **Fixtures only:** add an optional `ground_truth_technique` field to the 20 enriched fixtures
> so we can compute **attribution accuracy** (🎯 GAP3). Not emitted in production output.

**Contract 3 — Containment action** (orchestrator, simulated):
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
> **Enums frozen:**
> - `action`: `isolate_host` | `block_ip` | `revoke_credential` | `snapshot_vm` | `monitor`
> - `status` (lifecycle): `pending_approval` → `approved` → `simulated_success` | `rejected` | `failed`
> - `actor`: `system` | `human:<name>`

**Decision authority.** The agent's `suggested_action` is a hint. **`orchestrator/policy.py` is
authoritative** — it maps `(anomaly_score, severity)` → final `action` + `requires_human_approval`.
Reference policy table:

| Condition | Action | Human approval? |
|-----------|--------|-----------------|
| `severity` ∈ {critical, high} **and** `score ≥ 0.9` | `isolate_host` | ✅ required |
| `score` 0.7–0.9 | `block_ip` | auto |
| `score < 0.7` | `monitor` | auto |

## 5. The roadmap — 7 phases

**Owner tags:** **[You]** = architect / decide / cut tickets · **[P]** = partner implements
the assigned ticket. 🎯 = closes a PS7 gap. **✅ Checkpoint** = demoable state.

### Phase 0 — Freeze the seam *(first hour)*
- **[You]** Finalize the two contract extensions in §4 (graph edges, eval label).
- **[P]** `orchestrator/schemas.py` — 3 Pydantic models *(issue #3)*.
- **[P]** 20 anomaly-event + 20 enriched-incident fixtures → `data/fixtures/` *(issues #4, #6)*.
- **✅ Checkpoint:** contracts import cleanly; `./dev` boots FastAPI + React.

### Phase 1 — Walking skeleton *(the spine — top priority after contracts)*
- **[P]** Fake anomaly JSON → `POST /events` → **stub** enrichment (fixture, no LLM) →
  `policy.py` decides → **simulated** playbook → **hash-chained** audit → `GET /stream` (SSE)
  → React live feed renders it.
- **[P]** Approval gate: high-blast-radius actions return `pending_approval`; `POST /approve/{id}`
  releases them *(graded requirement — must exist)*.
- **✅ Checkpoint:** open browser → incident appears live → click Approve → status flips.
  **A working demo exists.** Everything after swaps a fake for a real component.

### Phase 2 — Real Detection *(swap the fake event source)*
- **[P]** `preprocess.py` + `train.py`: Isolation Forest on UNSW-NB15, **unsupervised**
  (normal-only fit; labels only for eval, never fed to model). Save scaler + model.
- **[P]** `infer.score(flow) -> anomaly_event`; `top_features` = human-readable z-score
  deviations. `replay.py` streams real events into the live pipe.
- **[P]** Eval → `engine/RESULTS.md`: precision, recall, F1, ROC-AUC, **FPR**. Target: recall
  on attacks ≥ ~0.8 at low FPR — a *defensible* number, not perfection.
- **✅ Checkpoint:** real model drives the live feed. 🎯 GAP3 metric #1 done.

### Phase 3 — Real Attribution Agent *(swap the stub enrichment)* — the differentiator
- **[P]** `fetch_sources.py`: ATT&CK STIX (`mitre/cti`) + NVD CVE + CERT-In → cache to
  `data/intel/`; commit a tiny slice to `data/fixtures/`.
- **[P]** `ingest.py`: chunk + embed into **Chroma** (metadata: `source_type`, `id`, `name`).
- **[P]** `agent.enrich(event)`: Claude (`claude-sonnet-4-6`) tool-calling
  (`search_attack`, `lookup_cve`, `search_certin`) → grounded, **cited** enriched incident.
  Force + validate JSON; retry on malformed. **Grounding rule:** never invent a technique ID;
  low confidence when nothing retrieved. *(Load the `claude-api` skill before coding.)*
- **[You]** Design a ~15-event labelled set → **[P]** compute **attribution accuracy %**
  🎯 GAP3.
- **✅ Checkpoint:** real cited briefs flow end-to-end; mock path still runnable as fallback.

### Phase 4 — The winning bolt-ons *(1st place vs. 4th)*
- 🎯 **GAP1 — Multi-agent framing.** **[You]** present Detection · Attribution/Prediction ·
  Response as three coordinating agents. **[P]** thin orchestration wrapper so it's real, not
  just slides.
- 🎯 **GAP2 — Attack-path graph.** **[P]** correlate events by host → `NetworkX` `src→dst`
  graph → detect **lateral movement** (east-west) → render graph view on the dashboard. STIX
  relationship edges = legitimate "knowledge graph." *Highest visual payoff.*
- 🎯 **GAP3 — Metrics surfaced.** **[P]** show attribution accuracy %, **automation coverage %**
  (`autonomous ÷ total` playbook steps), detection rate/FPR, MTTD/MTTR as live numbers.
- 🎯 **GAP4 — OT nod.** **[You]** architecture shows telemetry-agnostic ingest (IT NetFlow
  demoed live; OT/ICS labeled as same pipeline). **[P]** one OT-flavored event in `replay.py`;
  optional: map one technique to [ATT&CK ICS](https://attack.mitre.org/matrices/ics/).
- **✅ Checkpoint:** demo hits Innovation + every Technical-Excellence metric.

### Phase 5 — Dashboard polish *(UX 15%)*
- **[P]** MITRE technique grid; incident detail (technique, confidence, severity, CVE/CERT-In
  citations, narrative, `predicted_next`); audit-trail view; risk-ranked incident queue.
- **✅ Checkpoint:** full happy-path demo on one screen.

### Phase 6 — Deliverables + pitch *(don't lose easy points)*
- 🎯 **GAP5** — **[You]** Architecture Diagram; **[P]** recorded **Demo Video** *(both required
  deliverables)*.
- **[You]** Impact model: MTTD/MTTR reduction vs. baseline SOC; cite CERT-In 1.59M incidents/yr
  + 70% EOL-infra stat. Slide deck: problem → approach → live demo → impact → scalability.
- **[Both]** Rehearse the demo twice; keep + test the mock fallback path for stage safety.

## 6. Operating workflow (architect + on-demand implementer)

You plan and own the critical path; the partner implements discrete, well-scoped tickets on
request. The loop:

1. **[You]** cut the next ticket as a GitHub issue with a crisp Definition of Done.
   *(Issues #2–#7 exist on GitHub but reference the removed foundation docs — re-point them at
   the relevant §§ of this file, or close and re-cut against this plan.)*
2. **[P]** implements on a short-lived branch → opens a PR.
3. **[You]** review against the DoD → merge to `main` (which stays **green + demoable**).
4. Repeat. **Integrate continuously — never big-bang at the end.**

**Invariant:** only one mock is being replaced at any time, behind an unchanging contract.

## 7. Scope guardrails (what we deliberately do NOT build)

- **Digital Twin** (PS build-area 5) — illustrative, heavy, low marginal points. Skip unless
  far ahead.
- **Full UEBA** (user/device/endpoint profiling) — we do network flows only and *frame* the
  engine as extensible to those signals. Do not build all three telemetry types.
- **Standalone Vulnerability Prioritisation module** (PS area 4) — covered enough via CVE refs
  + `severity` + a risk-ranked queue. No separate module.
- **Real OT/ICS detection** — architecture + narrative nod only (see Phase 4), not a second
  trained model.

## 8. Definition of done (the whole prototype)

- [ ] `schemas.py` + fixtures frozen; `./dev` boots the stack.
- [ ] Walking skeleton: event → decision → simulated action → approval gate → hash-chained
      audit → live SSE feed in the browser.
- [ ] Isolation Forest trained; recall + FPR + ROC-AUC in `RESULTS.md`.
- [ ] `agent.enrich()` returns real, cited enriched incidents; attribution accuracy % reported.
- [ ] Multi-agent framing real (orchestration wrapper), not slideware.
- [ ] Attack-path / lateral-movement graph renders from correlated events.
- [ ] Metrics surfaced: detection rate/FPR, attribution accuracy, automation coverage, MTTD/MTTR.
- [ ] OT nod in architecture + one OT event in replay.
- [ ] Deliverables: Working Prototype · Architecture Diagram · Slide Deck · Demo Video.
- [ ] Mock fallback path tested; demo rehearsed twice.

## 9. Repo layout

```
et-hackathon-ps7/
├── docs/finalplan.md          # this file — the only planning doc
├── data/
│   ├── intel/                 # cached ATT&CK/CVE/CERT-In JSON (gitignored — big)
│   └── fixtures/              # COMMITTED: 20 anomaly events + 20 enriched incidents
│                              #   (+ ground_truth_technique) + tiny intel slice
├── engine/                    # Detection agent (ML)
│   ├── preprocess.py          #   load + encode + scale UNSW-NB15; normal-only split
│   ├── train.py               #   fit IsolationForest; write engine/RESULTS.md
│   ├── infer.py               #   score(flow) -> anomaly-event JSON
│   ├── replay.py              #   stream events (live-ish) into POST /events
│   └── model/                 #   isoforest.joblib, scaler.joblib
├── orchestrator/              # Response orchestrator agent (SOAR + backend)
│   ├── main.py                #   FastAPI app + all endpoints
│   ├── schemas.py             #   the 3 contracts as Pydantic models (SHARED — imported everywhere)
│   ├── pipeline.py            #   enrich -> decide -> playbook -> audit
│   ├── policy.py              #   decision table (authoritative — see §4)
│   ├── playbooks.py           #   simulated containment actions
│   ├── audit.py               #   append-only, hash-chained audit log
│   └── graph.py               #   src->dst correlation → attack-path / lateral movement (🎯 GAP2)
├── intel/                     # Attribution & prediction agent (RAG + LLM)
│   ├── fetch_sources.py       #   MITRE ATT&CK STIX + NVD CVE + CERT-In → data/intel/
│   ├── ingest.py              #   chunk + embed into Chroma
│   ├── agent.py               #   enrich(anomaly_event) -> enriched incident (cited)
│   └── prompts/
├── frontend/                  # React dashboard (Vite + Tailwind + shadcn)
├── dev                        # one-command launcher (starts implemented components, skips the rest)
└── requirements.txt           # backend Python deps
```

**Endpoints the orchestrator exposes:** `GET /health` · `POST /events` · `GET /incidents` ·
`GET /incidents/{id}` · `POST /approve/{id}` · `GET /audit` · `GET /stream` (SSE) ·
`GET /graph` (attack-path).

## 10. Per-pillar implementation rules (non-negotiables)

Fold these into every ticket's Definition of Done. They are the things that lose points if
skipped.

**Detection agent (`engine/`)**
- **Unsupervised only.** Learn "normal", flag deviations. Do **not** train a labelled
  attack/benign classifier — that's signature-matching and kills the "no signatures" story.
- Normal-only train split; labels used for **eval only**, never fed to the model.
- Save the fitted **scaler + model** (`joblib`) so inference applies identical transforms.
- Report **recall + false-positive rate** (+ ROC-AUC). Never accuracy alone. Target recall on
  attacks ≥ ~0.8 at low FPR — a *defensible* number, not perfection.
- `top_features` = human-readable z-score deviations; keep `raw_features` in the event.

**Attribution & prediction agent (`intel/`)**
- **Retrieve first, cite always.** Never invent a technique ID; if nothing relevant is
  retrieved, **lower confidence** and say so. Ungrounded technique IDs = instant credibility loss.
- **Force + validate structured JSON**; retry on malformed (the orchestrator breaks on bad output).
- **One agent, few tools** (`search_attack`, `lookup_cve`, `search_certin`) — but presented as
  one node in the 3-agent pipeline (🎯 GAP1). No 5-agent swarm.
- Provider pinned: **`claude-sonnet-4-6`**. Load the `claude-api` skill before writing agent code.
- Show the confidence score honestly.

**Response orchestrator (`orchestrator/`)**
- `policy.py` is the authoritative decision table (§4). Keep it a readable table.
- **All playbooks are SIMULATED** — they log and return `simulated_success`. Say so on stage
  ("in production this calls the firewall/EDR API").
- **Approval gate:** high-blast-radius actions return `pending_approval` +
  `requires_human_approval: true` and wait for `POST /approve/{id}` before "executing".
- **Hash-chain the audit log:** `hash(prev_hash + entry)` — genuinely tamper-evident, not just
  claimed. Cheap, and a real differentiator.
- `schemas.py` is the contract guardian — bump `schema_version` on any change.

**Dashboard (`frontend/`)**
- Subscribe to `GET /stream` via `EventSource`; **build the live feed first** (it proves the pipe).
- shadcn/Tailwind so time goes to the story, not CSS. MITRE map = a technique grid; add the
  attack-path **graph** view (🎯 GAP2). Don't over-build UI before the pipe works.
