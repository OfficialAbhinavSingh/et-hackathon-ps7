# Dev B — RAG + LLM Agent (the reasoning & attribution layer)

**Owner:** _______  ·  **Foundation window:** Jul 4 – Jul 8

You own the layer that turns a raw anomaly score into an **analyst-grade explanation**.
This is our GenAI differentiator — the reason we beat a plain ML dashboard. Given an
anomaly event, your agent says: *"this looks like MITRE ATT&CK technique T1048
(exfiltration over alternative protocol), here's the matching CVE and the CERT-In advisory,
and here's a plain-English incident brief."* With citations.

---

## 0. Your one-sentence mission

> Build a RAG knowledge base over **MITRE ATT&CK + CERT-In advisories + NVD CVE data**,
> and an LLM agent that takes an *anomaly event* and returns an *enriched incident* JSON
> (technique, confidence, CVE refs, CERT-In refs, narrative, recommended action) — every
> claim grounded in a retrieved source, not hallucinated.

---

## 1. Study first (≈1.5 days — do NOT skip)

### 1a. The security domain (you must sound credible)
- **MITRE ATT&CK framework** — the single most important thing to learn. Understand: Tactics (the "why" — e.g. Exfiltration, Lateral Movement) vs Techniques (the "how" — e.g. T1048) vs sub-techniques. Browse attack.mitre.org for 1 hour, click through 5-6 techniques, read their descriptions. You'll be mapping anomalies to these IDs.
- **The kill chain / attack progression** — recon → initial access → execution → persistence → lateral movement → exfiltration. Judges love "predict the next stage" — that's this.
- **What a CVE is** — Common Vulnerabilities and Exposures; CVSS severity score; how a CVE relates to a technique (a vuln is *how* an attacker achieves a technique).
- **What CERT-In is** — India's national cyber incident response team; they publish advisories (CIAD-xxxx). This is the "India-specific" angle judges will reward.

### 1b. The RAG mechanics
- **Embeddings + vector similarity** — what an embedding is, cosine similarity, why we chunk documents. Read: any "RAG in 10 minutes" explainer + your embedding provider's docs.
- **Chunking strategies** — why chunk size + overlap matter; each ATT&CK technique ≈ one natural chunk.
- **Vector DBs** — pick one: **pgvector** (if we already have Postgres), **Chroma** (zero-setup local, recommended for a hackathon), or Weaviate/Pinecone (managed). Chroma is the fastest to stand up.
- **Retrieval-then-generate** — retrieve top-k relevant chunks, stuff into prompt, LLM answers *from* them. Understand why this beats asking the LLM cold (grounding, citations, no stale knowledge).
- **Why grounding/citation matters here** — the brief demands "full auditability of every automated action." An agent that cites its source beats one that just asserts.

### 1c. Agent basics
- **Tool-calling / function-calling** — how an LLM calls a function (e.g. `search_attack(query)`, `lookup_cve(id)`) and uses the result. Read your framework's tool-use docs.
- **Framework choice** — **LangGraph** or **CrewAI** or plain LangChain, or even raw API calls with a tool loop. For a hackathon, **keep it simple**: a single agent with 2-3 tools beats a sprawling multi-agent graph you can't debug. Only go multi-agent if you can justify *why* (judges penalize "agent-washing").
- **Prompt engineering + structured output** — forcing JSON output (function-calling or JSON mode) so Dev C gets a clean *enriched incident* object.

### 1d. Provider (use the latest Claude models)
- Default to the current Claude Sonnet for the agent (fast + capable). Learn: the Anthropic Messages API, tool use, and JSON/structured output. If we build with the Claude Agent SDK, read its quickstart.

**Study resources (free):**
- attack.mitre.org (browse) + the **ATT&CK STIX data** on the mitre/cti GitHub repo (this is your corpus).
- NVD CVE API docs (nvd.nist.gov/developers) — no key needed for basic use.
- CERT-In advisories page (cert-in.org.in) — read publicly; cache pages locally, don't hammer it.
- Your vector DB's quickstart (Chroma recommended).
- Anthropic API docs: Messages, tool use, structured output.

---

## 2. Build tasks (Jul 4 – Jul 8)

### Task B1 — Gather the corpus (`intel/fetch_sources.py`)
- **MITRE ATT&CK:** clone/download the STIX JSON from the `mitre/cti` GitHub repo (Enterprise ATT&CK). Parse techniques → `{id, name, tactic, description, platforms, detection}`.
- **NVD CVE:** hit the NVD CVE API, pull a few hundred recent CVEs → `{id, description, cvss_score, references}`. Cache to disk (respect rate limits: no key = 5 req/30s).
- **CERT-In:** scrape/cache a set of advisory pages → `{id, title, description, affected, date}`. Keep it modest (20-50 advisories is plenty for demo).
- Store raw JSON in `data/intel/` (gitignored).

### Task B2 — Build the vector index (`intel/ingest.py`)
- Chunk each source (one technique / one CVE / one advisory ≈ one chunk; split long descriptions).
- Embed with your chosen embedding model; store in Chroma with metadata (`source_type`, `id`, `name`).
- Sanity check: query "data exfiltration over unusual port" → should retrieve T1048 and related.

### Task B3 — The enrichment agent (`intel/agent.py`)
- Input: an *anomaly event* (from Dev A's contract).
- The agent's job:
  1. Build a query from `top_features` + `raw_features` (e.g. "outbound flow, port 4444, large bytes_out, after hours").
  2. **Tool: `search_attack(query)`** → retrieve candidate ATT&CK techniques.
  3. **Tool: `lookup_cve(keywords)`** → retrieve relevant CVEs.
  4. **Tool: `search_certin(query)`** → retrieve relevant CERT-In advisories.
  5. LLM reasons over retrieved context and produces the **enriched incident** JSON (README §4): technique, confidence, cve_refs, certin_refs, narrative, recommended_action.
- **Force structured JSON output.** Validate it. Retry on malformed.
- **Grounding rule:** the `narrative` must reference retrieved facts; if nothing relevant retrieved, say so and lower confidence — never invent a technique ID.

### Task B4 — "Predict next stage" (stretch, high-value)
- Given the mapped technique's position in the kill chain, have the agent name the *likely next tactic* and a defensive action. This is a strong demo/pitch moment ("we don't just detect, we anticipate").

---

## 3. Your interface to the rest of the team

- **You consume:** Dev A's *anomaly event* JSON. Use their 20-event sample file to build before their model is ready.
- **You produce:** the *enriched incident* JSON. Freeze this schema Jul 4.
- **Dev C** calls your `agent.enrich(anomaly_event)` and passes `recommended_action` into the playbook engine.
- Give Dev C a stub: hard-coded enriched-incident JSON for the 20 sample events, so they can wire the pipeline before your agent is live.

---

## 4. Definition of done (Jul 8 EOD)

- [ ] ATT&CK + CVE + CERT-In fetched and cached.
- [ ] Vector index built; retrieval sanity checks pass.
- [ ] `agent.enrich(event)` returns valid *enriched incident* JSON with real technique IDs + citations.
- [ ] Grounding verified: agent cites retrieved sources, doesn't hallucinate technique IDs (test 5-6 events by hand).
- [ ] Stubbed enriched incidents handed to Dev C.
- [ ] You can explain, out loud, MITRE ATT&CK, what RAG is, and why grounding matters (team dry-run).

## 5. Pitfalls
- **Don't** let the LLM answer from its own memory — always retrieve first, cite always. Ungrounded technique IDs = instant credibility loss.
- **Don't** build a 5-agent swarm you can't debug at 2am. One agent, few tools.
- **Don't** hammer CERT-In / NVD live during the demo — cache everything locally.
- **Do** force structured JSON and validate it — Dev C's pipeline breaks on malformed output.
- **Do** keep a confidence score and show it — honest uncertainty scores better than fake certainty.
