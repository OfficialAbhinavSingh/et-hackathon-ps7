# PS7 — AI-Driven Cyber Resilience for Critical National Infrastructure

**ET AI Hackathon 2026 · Team build doc · Foundation phase (Jul 4 – Jul 8)**

---

## 1. What we are building (one paragraph)

An AI platform that watches network/host telemetry, learns what "normal" looks like,
and flags **behavioural anomalies** (not signature matches). When it sees something
suspicious, an LLM-agent layer explains *why* it is suspicious — mapping the activity
to a **MITRE ATT&CK** technique, pulling the relevant **CVE** and **CERT-In advisory**,
and generating a human-readable incident brief. A **SOAR orchestrator** then proposes
(and in demo, simulates) a containment action — isolate host, block IP, revoke
credential — with a full audit trail. The differentiator vs a plain ML dashboard is the
**GenAI reasoning + citation layer** that turns a raw anomaly score into an analyst-grade
explanation and action.

## 2. Why this wins (tie to judging)

Judging weights: Innovation 25 · Business Impact 25 · Technical Excellence 20 · Scalability 15 · UX 15.

- **Innovation** — behavioural anomaly + LLM ATT&CK attribution + auto-containment is more than "another dashboard".
- **Business Impact** — quantify MTTD/MTTR reduction vs baseline SOC. Cite CERT-In (1.59M incidents/yr) and the 70% end-of-life-infra stat from the brief. Build this impact model early, not the last night.
- **Technical Excellence** — real ML on real IDS datasets + RAG + agent orchestration = genuine range.
- **Scalability** — argue the architecture (streaming ingestion, stateless agents) scales; don't need to prove at scale.
- **UX** — clean dashboard: live alert feed, attack timeline, MITRE map, risk-ranked queue.

## 3. The 3-dev split

The main engine has three pillars. Each dev owns one pillar end-to-end during the
foundation phase, then we integrate. Frontend + pitch/impact-model are shared work in
later phases (see main timeline).

| Dev | Pillar | Doc |
|-----|--------|-----|
| **Dev A** | Anomaly Detection Engine (the ML brain) | [`DEV-A-anomaly-detection.md`](DEV-A-anomaly-detection.md) |
| **Dev B** | RAG + LLM Agent (the reasoning + attribution layer) | [`DEV-B-rag-agent.md`](DEV-B-rag-agent.md) |
| **Dev C** | SOAR Orchestrator + Backend (the glue + action layer) | [`DEV-C-orchestrator-backend.md`](DEV-C-orchestrator-backend.md) |

## 4. How the pieces talk (the contracts — read this before coding)

We agree on **JSON contracts** on day 1 so the three of us can build in parallel and
mock each other's outputs. These are the interfaces:

**Anomaly event (Dev A → Dev C → Dev B):**
```json
{
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

**Enriched incident (Dev B → Dev C → frontend):**
```json
{
  "event_id": "evt_0001",
  "attack_technique": { "id": "T1048", "name": "Exfiltration Over Alternative Protocol" },
  "confidence": 0.87,
  "cve_refs": ["CVE-2024-1234"],
  "certin_refs": ["CIAD-2024-0012"],
  "narrative": "Large outbound transfer on non-standard port 4444 after hours...",
  "recommended_action": "isolate_host"
}
```

**Containment action (Dev C, executed/simulated):**
```json
{
  "event_id": "evt_0001",
  "action": "isolate_host",
  "target": "10.0.0.5",
  "status": "simulated_success",
  "requires_human_approval": true,
  "audit_log_id": "aud_0001"
}
```

> **Rule:** if a contract changes, announce it in the team chat + update this file. Everyone mocks against these until integration day.

## 5. Repo layout (agreed day 1)

```
et-hackathon-ps7/
├── docs/                      # these files
├── data/                      # datasets (gitignored — too big), scripts to fetch
├── engine/                    # Dev A — anomaly detection
│   ├── train.py
│   ├── infer.py
│   └── model/
├── intel/                     # Dev B — RAG + agent
│   ├── ingest_attack.py       # MITRE ATT&CK + CERT-In + CVE into vector DB
│   ├── agent.py
│   └── prompts/
├── orchestrator/              # Dev C — SOAR + backend
│   ├── main.py                # FastAPI app
│   ├── playbooks.py
│   └── audit.py
├── frontend/                  # shared (later phase) — React dashboard
└── README.md
```

## 6. Foundation-phase definition of done (by Jul 8 EOD)

- **Dev A:** anomaly model trains on the chosen IDS dataset and emits the *anomaly event* JSON for a stream of test rows.
- **Dev B:** vector DB loaded with ATT&CK + CERT-In + CVE; agent answers "given these features, which ATT&CK technique + CVE + advisory?" and returns the *enriched incident* JSON.
- **Dev C:** FastAPI skeleton runs; accepts an anomaly event, calls a (mocked) intel + playbook, writes an audit log entry, returns the *containment action* JSON.
- **All three contracts frozen and mocked**, so Phase 2 (Jul 9-15) is pure wiring + depth.

## 7. Ground rule on studying

We are **not vibecoding this**. Each dev doc has a **"Study first"** section. Spend the
first ~1.5 days actually understanding your pillar before writing real code — a security
project with hand-wavy internals gets torn apart by technical judges. Study list is
scoped to only what you need, not a CS degree.
