# Dev C — SOAR Orchestrator + Backend (the glue & action layer)

**Owner:** _______  ·  **Foundation window:** Jul 4 – Jul 8

You own the **spine**. You take Dev A's anomaly events, send them through Dev B's
enrichment agent, decide on a containment action, (simulate) executing it, log everything
for audit, and expose it all as one clean API the frontend consumes. You are also the
person who makes the **end-to-end demo actually run**. If A and B are the organs, you are
the nervous system.

---

## 0. Your one-sentence mission

> Build a FastAPI service that ingests anomaly events, orchestrates enrichment → decision →
> (simulated) containment via approval-gated playbooks, writes a tamper-evident audit log,
> and streams live incidents to the frontend — implementing the *containment action*
> contract with human-in-the-loop gates.

---

## 1. Study first (≈1 day — you also start scaffolding early)

### 1a. The domain concept
- **What SOAR is** — Security Orchestration, Automation & Response. Understand: a **playbook** is a predefined sequence of response steps (isolate host, block IP, revoke credential, snapshot VM). Read a short "what is SOAR / security playbook" explainer.
- **Human-in-the-loop / blast radius** — the brief demands "human escalation gates for decisions above defined blast radius thresholds." Meaning: low-risk actions auto-run; high-impact actions need approval. You must implement this gate — it's a graded requirement.
- **Auditability** — "full auditability of every automated action." Every action logged: who/what/when/why, immutable-ish. This is a pitch talking point.
- **MTTD / MTTR** — Mean Time To Detect / Respond. Our impact model is built on reducing these. Know the definitions cold.

### 1b. The engineering
- **FastAPI** — routing, Pydantic models (perfect for enforcing our JSON contracts), async endpoints, background tasks. Read the FastAPI tutorial (first half).
- **Pydantic models** — define the three contracts (anomaly event, enriched incident, containment action) as Pydantic models = free validation. This is your leverage point for keeping the team's contracts honest.
- **Server-Sent Events (SSE) or WebSockets** — how to push live incidents to the React frontend as the replay stream ticks. SSE is simpler; start there.
- **A simple state store** — SQLite (via SQLModel/SQLAlchemy) or even JSON files for the audit log + incident history. Don't over-engineer; SQLite is plenty.
- **Rule engine basics** — a decision function mapping (anomaly_score, technique severity) → action + whether approval is required. Just clean `if/elif` is fine; frame it as a policy table.

**Study resources (free):**
- FastAPI official tutorial + Pydantic docs.
- Any "what is SOAR / security playbook" explainer (Palo Alto / IBM glossaries are concise).
- MDN / FastAPI docs on Server-Sent Events.
- SQLModel quickstart.

---

## 2. Build tasks (Jul 4 – Jul 8)

### Task C1 — Scaffold + contracts (Jul 4, do this first, unblocks everyone)
- Stand up FastAPI app (`orchestrator/main.py`).
- Define **all three JSON contracts as Pydantic models** in `orchestrator/schemas.py`. Share this file — A and B import it so contracts can't drift.
- Health-check endpoint. Commit + push so the repo skeleton exists for the team.

### Task C2 — Ingestion endpoint (`POST /events`)
- Accepts an *anomaly event* (validated by Pydantic).
- For foundation phase, call a **mocked** enrichment (Dev B's stub JSON) — swap to the real agent at integration.
- Stores the incident, returns an ack.

### Task C3 — Orchestration pipeline (`orchestrator/pipeline.py`)
- For each event: enrich (Dev B) → decide action (rule engine) → route to playbook.
- **Decision policy** (`orchestrator/policy.py`): e.g. score ≥ 0.9 + high-severity technique → `isolate_host` (needs approval); score 0.7–0.9 → `block_ip` (auto); < 0.7 → `monitor`. Make this a readable table.

### Task C4 — Playbook engine (`orchestrator/playbooks.py`)
- Implement playbooks as functions: `isolate_host`, `block_ip`, `revoke_credential`, `snapshot_vm`.
- **These are SIMULATED** — they log the action and return `simulated_success`. We are NOT touching real infrastructure (and shouldn't claim to). Be honest in the demo: "in production this calls the firewall/EDR API; here it's simulated." Judges respect honesty over fake claims.
- Enforce the **human-approval gate**: high-blast-radius actions return `requires_human_approval: true` and wait for a `POST /approve/{id}` before "executing".

### Task C5 — Audit log (`orchestrator/audit.py`)
- Every event, decision, and action appended to an audit store (SQLite table or append-only JSONL) with timestamp, event_id, action, actor (system/human), and the reasoning/citations from Dev B.
- Endpoint `GET /audit` to retrieve the trail. This is a demo highlight — show the full paper trail.

### Task C6 — Live stream to frontend (`GET /stream`)
- SSE endpoint that pushes each new enriched incident as it flows through, so the dashboard updates live while Dev A's `replay.py` feeds events.
- Endpoints the frontend needs: `GET /incidents`, `GET /incidents/{id}`, `GET /audit`, `POST /approve/{id}`, `GET /stream`.

---

## 3. Your interface to the rest of the team

- **You consume:** Dev A's *anomaly event* (and their `replay.py` stream) + Dev B's `enrich()` output.
- **You produce:** the *containment action* JSON + all the REST/SSE endpoints the frontend uses.
- **You own the shared `schemas.py`** — you are the guardian of the contracts. If A or B needs a field, they ask you, you update the Pydantic model + the README, everyone re-syncs.
- Because you can mock both A and B (their stub JSONs), you can build the **entire pipeline end-to-end in foundation phase** without waiting for their real models. Do this — a working mocked pipeline by Jul 8 means Phase 2 is just swapping mocks for real components.

---

## 4. Definition of done (Jul 8 EOD)

- [ ] FastAPI app runs; `schemas.py` with all three contracts as Pydantic models, shared with A and B.
- [ ] `POST /events` ingests + validates anomaly events.
- [ ] Pipeline runs end-to-end with **mocked** enrichment: event → decision → playbook → audit → response.
- [ ] Human-approval gate works (`POST /approve/{id}` releases a held action).
- [ ] Audit log writes and `GET /audit` returns the trail.
- [ ] `GET /stream` (SSE) pushes live incidents; verified with a curl / browser test.
- [ ] You can explain, out loud, SOAR, the approval-gate logic, and the MTTD/MTTR story (team dry-run).

## 5. Pitfalls
- **Don't** claim real containment — everything is simulated; say so. False claims of touching live infra = credibility death.
- **Don't** let contracts drift silently — you are the guardian; announce every schema change.
- **Don't** block the demo on real A/B components — keep the mocks working so you always have a fallback path if their pieces break on stage.
- **Do** build the audit log early — it's a differentiator (the brief stresses auditability) and easy to under-prioritize.
- **Do** make the approval gate visible in the API — it directly answers a graded requirement.
