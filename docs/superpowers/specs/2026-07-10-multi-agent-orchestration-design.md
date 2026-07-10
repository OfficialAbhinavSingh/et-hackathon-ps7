# Multi-Agent Orchestration Wrapper (#28) — Design Spec

**Date:** 2026-07-10
**Issue:** #28 — "Multi-agent orchestration wrapper" (finalplan §Phase 4, GAP1)
**Status:** approved design, pre-implementation

## Goal

Make the Detection → Attribution → Response flow that *already runs* linearly into three
**named, observable coordinating agents** — real runtime data, streamed live per event,
rendered on the dashboard. Closes GAP1 ("Agentic AI / Multi-Agent Systems") so the demo shows
real multi-agent hand-off, not a slide.

## Non-negotiable constraints (from CLAUDE.md / finalplan §4)

- The **3 frozen contracts** (`AnomalyEvent`, `EnrichedIncident`, `ContainmentAction`) do NOT
  change. `AgentActivity` (below) is a **new observability model**, not a core contract.
- **`policy.py` stays authoritative.** The orchestration view only *reports* the action policy
  already decided; it decides nothing.
- **Audit hash format untouched.** Orchestration is a live SSE frame, never an audit entry.
- **Pipeline decision logic unchanged** — the only pipeline change is an optional timing
  collector (no new branching, no behaviour change when unused).
- **Mock/live seam parity.** Flipping `VITE_DATA_SOURCE` stays zero-component-change: both
  `MockDataService` and `HttpDataService` produce equivalent orchestration data.
- Thin wrapper — **exactly 3 agents**, no framework/message-bus/swarm. Prediction is part of
  the Attribution agent's output (`predicted_next`), not a 4th agent.

## Architecture / data flow

```
engine POST /events
  → pipeline.process(event, timings={})        # timings dict filled in-place, optional
       ├ Attribution  (enrich)   → timings["attribution_ms"]
       └ Response      (decide+act) → timings["response_ms"]
  → main.py /events handler:
       activities = build_orchestration(event, incident, action, timings)
       publish {kind:"anomaly"}, {kind:"enriched"}, {kind:"containment"},
               {kind:"orchestration", payload:{event_id, activities}}   # 4th frame, last
  → SSE → HttpDataService.ingest() attaches activities to IncidentView.orchestration
  → AgentOrchestration panel (Operations page) renders the 3-agent hand-off strip, live
```

Detection latency is not measurable inside the orchestrator (scoring happens in `engine/`), so
the Detection agent shows its **result** (flagged / score / top features) with **no fabricated
ms** — honest over invented. Attribution and Response show real measured ms.

## The new observability model

Backend `orchestrator/agents.py`, mirrored in frontend `types/contracts.ts`:

```
AgentActivity:
  agent_id: "detection" | "attribution" | "response"
  name:     str   # "Detection Agent" | "Attribution & Prediction Agent" | "Response Orchestrator Agent"
  stage:    int   # 1 | 2 | 3  (kill-chain order, drives left→right layout)
  status:   "ok" | "pending" | "unknown"   # drives icon: ✓ / ⏳ / ⚠
  summary:  str   # human line: "flagged · score 0.97" | "T1498 · conf 0.70" | "isolate_host · pending approval"
  elapsed_ms: int | None   # None for detection (measured in engine, not here)
```

Status rules: Detection always `ok` (event arrived; is_anomaly is in the summary).
Attribution `ok` unless `attack_technique.id == "UNKNOWN"` → `unknown`. Response `pending`
when `status == pending_approval`, else `ok`.

The orchestration frame `payload` is `{event_id: str, activities: AgentActivity[]}` — carries
`event_id` so the frontend keys it to the right incident (matches existing `msg.payload.event_id`).

## Components

### Backend

- **`orchestrator/agents.py` (new):** `AGENTS` static metadata (id/name/role per agent);
  `AgentActivity` Pydantic model; `build_orchestration(event, incident, action, timings) ->
  list[AgentActivity]` — pure function, assembles the 3 activities from real runtime objects.
- **`orchestrator/pipeline.py` (minimal):** `process(event, timings=None)`. When a dict is
  passed, fill `timings["attribution_ms"]` (around `enrich`) and `timings["response_ms"]`
  (around `decide`+playbook) via `time.perf_counter()`. `timings=None` (default) → byte-identical
  behaviour; existing tests calling `process(event)` unaffected.
- **`orchestrator/main.py` (change `/events`):** pass a `timings={}` dict into `process`, call
  `build_orchestration`, publish the 4th `orchestration` frame after the existing three; it is
  appended to `messages` for late-client replay exactly like the others.

### Frontend (built here; Yash's #10 domain, approved to proceed while he is offline)

- **`types/contracts.ts`:** add `AgentActivity` interface + optional `orchestration?:
  AgentActivity[]` on `IncidentView`.
- **`data/http/HttpDataService.ts`:** extend `StreamMessage` with the `orchestration` kind;
  **fix the ingest branch** — today's final `else` treats any non-anomaly/non-enriched kind as
  `containment`, so it must become explicit (`else if kind === "containment"`) with a new
  `orchestration` branch that sets `view.orchestration = payload.activities` and notifies.
- **`data/mock/MockDataService.ts`:** synthesize an equivalent `activities` array during
  `inject()` (derive from the same fixture event/incident/decision it already computes) and set
  it on the view — mock mode shows the panel identically.
- **`components/AgentOrchestration.tsx` (new):** renders the latest incident's 3-agent strip
  (the approved mockup: numbered agents, ✓/⏳/⚠ status, summary, ms, hand-off arrows). Reads the
  newest `IncidentView` with an `orchestration` field.
- **`pages/Operations.tsx`:** add a slim full-width row for the panel between `MetricsBar` and
  the existing 3-column grid (`grid-rows-[auto_auto_1fr]`).

## Error / edge handling

- Live agent falls back to `UNKNOWN` attribution (existing behaviour) → Attribution shows
  `status:"unknown"` ⚠ with confidence 0 — the panel visibly reflects honest low-confidence.
- Auto-contained (no approval) → Response `status:"ok"` ✓; high-blast-radius → `pending` ⏳.
- Orchestration frame arriving before its `IncidentView` exists: ingest ignores it if no view
  yet (same guard as containment), and the value is replayed from `messages` on reconnect.

## Testing

- **Backend `tests/test_agents.py`:** `build_orchestration` returns 3 activities in stage order;
  correct statuses for (a) normal attributed + auto-contained, (b) `UNKNOWN` attribution, (c)
  pending-approval response; timings passed through; detection `elapsed_ms` is None.
- **Backend `tests/test_main.py` (extend):** `POST /events` publishes a 4th `orchestration`
  frame whose payload has `event_id` + 3 activities; existing stub-path tests still pass.
- **Frontend `HttpDataService` test:** an `orchestration` frame attaches `activities` to the
  right `IncidentView`; a `containment` frame still works (guards the ingest-switch fix).
- **Frontend `AgentOrchestration` test:** renders 3 agents, shows ⚠ for unknown, ⏳ for pending.
- **Live e2e:** run the full stack, screenshot the panel showing real hand-off with a
  pending-approval Response and an UNKNOWN attribution.

## Out of scope (YAGNI)

No agent framework / message bus / swarm. No conditional re-routing or bidirectional
coordination (user chose "frame the existing flow"). No new REST endpoint (uses `/stream`). No
change to the 3 core contracts, policy authority, or audit chain.
