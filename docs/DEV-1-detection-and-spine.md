# Dev 1 — Detection & Spine (Anomaly Engine + SOAR Orchestrator)

**Owner:** _______  ·  **Build window:** Jul 6 → demo

You own **the whole data path**: raw telemetry in → anomaly score → decision → (simulated)
containment → audit trail → live stream to the frontend. That's two of the three pillars
(the ML brain + the backend spine), merged into one track because they're both Python and
directly coupled — the orchestrator consumes the engine's output. You are also the person
who makes **the end-to-end demo actually run**, and you keep the mocked pipeline alive as
the on-stage fallback.

---

## 0. Your one-sentence mission

> Train an **unsupervised** anomaly model that emits the *anomaly event* contract, and a
> **FastAPI** orchestrator that ingests those events, runs enrichment → policy decision →
> approval-gated (simulated) playbook → hash-chained audit log, and streams live incidents
> to the dashboard.

**Why unsupervised:** the brief says detect anomalies *"without relying on known malware
signatures."* A supervised attack/benign classifier is signature-matching in disguise.
Learn "normal", flag deviations — that's the honest answer judges respect.

---

## 1. Study first (≈1 day — split across both pillars, do NOT skip)

### Detection (the ML)
- **Signature vs anomaly detection** — why APTs evade signatures (low-and-slow, novel payloads).
- **Isolation Forest** — isolates anomalies via random splits; anomalies isolate in fewer splits. Fast, no scaling needed, great default. *Start here.* (Autoencoder is a stretch.)
- **Network flow / NetFlow** — a flow = 5-tuple (src IP, dst IP, src port, dst port, protocol) + duration, bytes/packets in/out. You must explain these in the demo.
- **Base-rate problem** — 99% accuracy is useless if 1% false positives = thousands of alerts/day. This is a pitch talking point. (Axelsson's "base rate fallacy in intrusion detection" — summary is enough.)
- **Evaluation** — precision/recall/F1/ROC-AUC + **why recall-on-attacks and false-positive-rate are the two numbers that matter.** Read a confusion matrix.
- Resource: scikit-learn "Novelty and Outlier Detection" + `IsolationForest` docs (short, it's your API). UNSW-NB15 feature description.

### Spine (the backend)
- **SOAR + playbooks** — a playbook is a predefined response sequence (isolate host, block IP, revoke credential, snapshot VM). Read one "what is SOAR" explainer.
- **Human-in-the-loop / blast radius** — low-risk actions auto-run; high-impact actions need approval. This is a **graded requirement** — you must implement the gate.
- **Auditability** — every action logged: who/what/when/why, tamper-evident. Pitch talking point.
- **MTTD / MTTR** — Mean Time To Detect / Respond; our impact model reduces these. Know the definitions cold.
- **FastAPI + Pydantic** — routing, Pydantic models (they enforce our JSON contracts for free), async, background tasks. **SSE** (Server-Sent Events) for pushing live incidents (simpler than WebSockets). **SQLite** (SQLModel/SQLAlchemy) or append-only JSONL for state + audit.

---

## 2. Build tasks

### Track A — Anomaly Engine

**A1 — Load + preprocess (`engine/preprocess.py`)**
- Load UNSW-NB15; select numeric + key categorical features. Encode categoricals, scale numerics (StandardScaler).
- Split into a **normal-only** training set (unsupervised fit) + a held-out **mixed** set (eval only — labels are for scoring, never fed to the model).
- Save the fitted scaler/encoder (`joblib`) so inference uses identical transforms.

**A2 — Train baseline (`engine/train.py`)**
- Fit **IsolationForest** on normal-only data; tune `contamination`, `n_estimators`.
- Save `engine/model/isoforest.joblib`. Print + write eval to `engine/RESULTS.md`: precision, recall, F1, ROC-AUC, **false-positive rate**.
- **Demo-credibility target:** recall on attacks ≥ ~0.8 with a low FPR. Chase a *defensible, explainable* number, not perfection.

**A3 — Inference + attribution (`engine/infer.py`)**
- `score(flow_dict) -> anomaly_event_json`. Normalise the model's raw score to 0–1.
- `top_features`: per-feature deviation from training mean (z-score) is an honest, simple approach (SHAP if ahead). **Must be human-readable names** (contract rule) — the agent reasons over them.
- Emit exactly the **anomaly event contract** (README §4).

**A4 — Replay stream (`engine/replay.py`)**
- Read held-out rows, emit anomaly events one-by-one (small delay) to simulate a **live feed**. This is what makes the dashboard tick. The orchestrator consumes it.

### Track C — SOAR Orchestrator

**C1 — Scaffold + contracts (do FIRST — unblocks Dev 2)**
- Stand up FastAPI (`orchestrator/main.py`). Define **all three contracts as Pydantic models** in `orchestrator/schemas.py` — Dev 2 imports this file so contracts can't drift. Health-check endpoint. Commit + push so the skeleton exists.

**C2 — Ingestion (`POST /events`)**
- Accept + validate an *anomaly event*. In foundation, call **mocked** enrichment (Dev 2's stub JSON). Store the incident, return an ack.

**C3 — Orchestration pipeline (`orchestrator/pipeline.py` + `policy.py`)**
- Per event: enrich (Dev 2) → **decide** (`policy.py`, authoritative — see README §4 Decision authority) → route to playbook. Keep `policy.py` a readable table.

**C4 — Playbook engine (`orchestrator/playbooks.py`)**
- Functions: `isolate_host`, `block_ip`, `revoke_credential`, `snapshot_vm`. **All SIMULATED** — they log and return `status: simulated_success`. Be honest in the demo: "in production this calls the firewall/EDR API; here it's simulated."
- Enforce the **approval gate**: high-blast-radius actions return `status: pending_approval` + `requires_human_approval: true` and wait for `POST /approve/{id}` before "executing".

**C5 — Audit log (`orchestrator/audit.py`)**
- Append every event/decision/action with timestamp, event_id, action, actor, and Dev 2's reasoning/citations. **Hash-chain each entry** (`hash(prev_hash + entry)`) so it's genuinely tamper-evident — cheap, and a real differentiator (don't just *claim* tamper-evident). `GET /audit` returns the trail.

**C6 — Live stream (`GET /stream`, SSE)**
- Push each new enriched incident as it flows through. Frontend endpoints: `GET /incidents`, `GET /incidents/{id}`, `GET /audit`, `POST /approve/{id}`, `GET /stream`.

---

## 3. Your interface to Dev 2

- **You consume:** Dev 2's `agent.enrich(anomaly_event)` output (the *enriched incident*). Until it's live, use their **stubbed enriched JSONs** in `data/fixtures/`.
- **You produce:** the *containment action* JSON + all REST/SSE endpoints the frontend uses.
- **You own `orchestrator/schemas.py`** — guardian of the contracts. If Dev 2 needs a field, they ask, you update the Pydantic model + README + bump `schema_version`, both re-sync.
- **Hand Dev 2 early:** a `data/fixtures/` file of ~20 sample **anomaly events** so they build their agent before your model is ready.
- Because you can mock enrichment, you can build the **entire pipeline end-to-end in foundation** without waiting for Dev 2. Do this.

## 4. Definition of done (see MILESTONES.md for the phased checklist)

- [ ] `schemas.py` with all three v1.0 contracts, shared with Dev 2 (M0).
- [ ] IsolationForest trained; eval numbers in `engine/RESULTS.md`; `infer.score()` returns valid anomaly-event JSON; `replay.py` streams (M1).
- [ ] FastAPI pipeline runs end-to-end with mocked enrichment: event → decision → playbook → audit → response (M1).
- [ ] Approval gate works (`POST /approve/{id}` releases a held action); hash-chained audit; `GET /stream` verified (M1).
- [ ] Real anomaly model + real agent wired in; live `replay.py` feed drives the dashboard (M2).
- [ ] 20 sample anomaly events committed to `data/fixtures/` (M0/M1).

## 5. Pitfalls
- **Don't** train a labelled attack/benign classifier — kills the "no signatures" story.
- **Don't** report only accuracy — always recall + FPR.
- **Don't** claim real containment — everything is simulated; say so on stage.
- **Don't** let contracts drift silently — you're the guardian; bump `schema_version` on every change.
- **Do** keep `raw_features` in the event — Dev 2 needs real numbers to explain, not just a score.
- **Do** build the mocked pipeline early and keep it working — it's the stage fallback.
