# Dev 2 — Agent & Dashboard (RAG+LLM Agent + React Frontend)

**Owner:** _______  ·  **Build window:** Jul 6 → demo

You own **the intelligence you can see**: the GenAI reasoning layer that turns a raw
anomaly score into an analyst-grade, cited explanation — and the dashboard that shows it
off. That's two pillars (the RAG agent + the frontend), merged because together they are
the two headline demo moments: *"the AI explained the attack"* and *"look at it happen
live."* This is our differentiator vs a plain ML dashboard.

---

## 0. Your one-sentence mission

> Build a RAG knowledge base over **MITRE ATT&CK + CERT-In advisories + NVD CVE**, an LLM
> agent that takes an *anomaly event* and returns a grounded *enriched incident* JSON
> (technique, confidence, severity, CVE/CERT-In refs, narrative, suggested action) — every
> claim cited, not hallucinated — and a **React dashboard** that renders the live incident
> feed, MITRE map, incident brief, and approval queue off the orchestrator's SSE stream.

---

## 1. Study first (≈1 day — split across both pillars, do NOT skip)

### The security domain (you must sound credible)
- **MITRE ATT&CK** — the most important thing to learn. Tactics (the "why": Exfiltration, Lateral Movement) vs Techniques (the "how": T1048) vs sub-techniques. Browse attack.mitre.org ~1h, click through 5-6 techniques.
- **Kill chain** — recon → initial access → execution → persistence → lateral movement → exfiltration. Judges love "predict the next stage" — that's `predicted_next`.
- **CVE + CVSS** — a vuln is *how* an attacker achieves a technique; CVSS = severity (feeds our `severity` field).
- **CERT-In** — India's national CERT; advisories (CIAD-xxxx). The India-specific angle judges reward.

### RAG mechanics
- **Embeddings + cosine similarity + chunking** — why we chunk (one technique/CVE/advisory ≈ one chunk) and retrieve top-k.
- **Vector DB** — **Chroma** (zero-setup local, recommended). pgvector/Pinecone are alternatives.
- **Retrieve-then-generate** — retrieve relevant chunks, stuff into prompt, LLM answers *from them*. Grounding + citations + no stale knowledge. The brief demands "full auditability" — a cited agent beats one that asserts.

### Agent + provider
- **Tool-calling** — the LLM calls `search_attack(query)`, `lookup_cve(keywords)`, `search_certin(query)` and uses results. **Keep it simple: one agent, 2-3 tools.** Judges penalize "agent-washing" — don't build a swarm you can't debug at 2am.
- **Structured output** — force JSON (function-calling / JSON mode) so the orchestrator gets a clean *enriched incident*. Validate; retry on malformed.
- **Provider: use the latest Claude models.** Default to **Claude Sonnet 4.6** (`claude-sonnet-4-6`) — fast + capable — for the agent. Pin this exact id so both devs use the same model. Learn the Anthropic Messages API, tool use, and structured output. **Before writing agent code, load the `claude-api` skill** for current model ids, tool-use, and structured-output patterns — don't code the API from memory.

### Frontend
- **React** (Vite) + a fetch of the SSE stream (`EventSource`) — read the orchestrator's `GET /stream` and append incidents live.
- Keep it lean: a component library (e.g. shadcn/Tailwind) so you spend time on the *story*, not CSS. A MITRE map can be a simple technique grid, not a fancy graph, for v1.

---

## 2. Build tasks

### Track B — RAG + Agent

**B1 — Gather corpus (`intel/fetch_sources.py`)**
- **ATT&CK:** download STIX JSON from the `mitre/cti` GitHub repo (Enterprise). Parse techniques → `{id, name, tactic, description, platforms, detection}`.
- **NVD CVE:** hit the NVD API, pull a few hundred recent CVEs → `{id, description, cvss_score, references}`. Respect rate limits (no key = 5 req/30s) — **fetch once, cache to disk.**
- **CERT-In:** cache 20–50 advisory pages → `{id, title, description, affected, date}`. Don't hammer it live.
- Raw JSON in `data/intel/` (gitignored). **Commit a tiny slice to `data/fixtures/`** for reproducible demos.

**B2 — Vector index (`intel/ingest.py`)**
- Chunk each source (one technique/CVE/advisory ≈ one chunk; split long text). Embed, store in **Chroma** with metadata (`source_type`, `id`, `name`).
- Sanity check: query "data exfiltration over unusual port" → should retrieve T1048 and friends.

**B3 — Enrichment agent (`intel/agent.py`)**
- Input: an *anomaly event* (Dev 1's contract). Build a query from `top_features` + `raw_features` (e.g. "outbound flow, port 4444, large bytes_out, after hours").
- Tools: `search_attack(query)`, `lookup_cve(keywords)`, `search_certin(query)`.
- LLM reasons over retrieved context → **enriched incident** JSON (README §4): technique, confidence, **severity** (derive from CVE CVSS / technique impact), cve_refs, certin_refs, narrative, `suggested_action`. **Force + validate structured JSON; retry on malformed.**
- **Grounding rule:** the `narrative` must reference retrieved facts; if nothing relevant retrieved, say so and **lower confidence — never invent a technique ID.**

**B4 — Predict next stage (stretch, high-value)**
- From the technique's kill-chain position, fill `predicted_next` (likely next tactic + a defensive note). Strong pitch moment: "we don't just detect, we anticipate."

### Track D — React Dashboard

**D1 — Shell + live feed** — Vite React app; subscribe to `GET /stream` via `EventSource`; render a live **alert feed** as incidents arrive. *(Build this first — proves the pipe end-to-end.)*
**D2 — Incident detail** — click an incident → show the brief: technique + MITRE id, confidence, severity, CVE/CERT-In citations, narrative, `predicted_next`.
**D3 — Approval queue** — list actions with `status: pending_approval`; an **Approve** button hits `POST /approve/{id}`; reflect the status change. (Directly shows the graded human-in-the-loop requirement.)
**D4 — MITRE map + audit view** — a technique grid highlighting seen techniques; an **audit trail** view off `GET /audit` (the tamper-evident paper trail — a demo highlight).

---

## 3. Your interface to Dev 1

- **You consume:** Dev 1's *anomaly event* JSON (use their `data/fixtures/` 20-event sample to build before their model is live) + all orchestrator REST/SSE endpoints.
- **You produce:** `agent.enrich(anomaly_event) -> enriched incident` (Dev 1 imports/calls it) + the dashboard.
- **Import `orchestrator/schemas.py`** — Dev 1 owns it; don't redefine contracts. Need a field? Ask Dev 1, they bump `schema_version`.
- **Hand Dev 1 early:** stubbed **enriched-incident** JSONs for the 20 sample events (`data/fixtures/`) so their pipeline runs before your agent is live.

## 4. Definition of done (see MILESTONES.md for the phased checklist)

- [ ] 20 stubbed enriched incidents committed to `data/fixtures/`, given to Dev 1 (M0).
- [ ] ATT&CK + CVE + CERT-In fetched/cached; Chroma index built; retrieval sanity checks pass (M1).
- [ ] `agent.enrich(event)` returns valid *enriched incident* JSON with real technique IDs + citations; grounding verified by hand on 5-6 events (M1).
- [ ] Agent wired into the live orchestrator pipeline; `predicted_next` populated (M2).
- [ ] React dashboard: live feed + incident detail + approval button + MITRE/audit views, driven by the live SSE stream (M3).

## 5. Pitfalls
- **Don't** let the LLM answer from memory — always retrieve first, cite always. Ungrounded technique IDs = instant credibility loss.
- **Don't** build a 5-agent swarm. One agent, few tools.
- **Don't** hammer CERT-In / NVD live during the demo — cache everything, commit a fixture.
- **Don't** over-build the UI before the pipe works — get the live feed rendering first, polish later.
- **Do** force + validate structured JSON — Dev 1's pipeline breaks on malformed output.
- **Do** show the confidence score — honest uncertainty scores better than fake certainty.
