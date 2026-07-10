# Multi-Agent Orchestration Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present the existing Detection→Attribution→Response pipeline flow as three named, observable coordinating agents — real runtime data streamed live per event and rendered on the dashboard (closes finalplan GAP1).

**Architecture:** A pure backend helper (`orchestrator/agents.py`) assembles one `AgentActivity` per stage from the real `event`/`incident`/`action` objects. The `/events` handler publishes these as a 4th SSE frame (`kind:"orchestration"`) after the existing three. The frontend attaches the activities to the accumulated `IncidentView` and a new panel renders the hand-off strip. Additive only — no core-contract, policy, audit, or pipeline-logic change.

**Tech Stack:** Python 3.14 / FastAPI / Pydantic v2 (backend `.venv`); React + TS + Vite / Vitest (frontend). Tests: `pytest` backend, `vitest` frontend.

## Global Constraints

- The 3 frozen contracts (`AnomalyEvent`, `EnrichedIncident`, `ContainmentAction` in `orchestrator/schemas.py`) MUST NOT change. `AgentActivity` is a new stream-only observability model, NOT a core contract.
- `policy.py` stays authoritative — orchestration only *reports* the decided action, decides nothing.
- Audit hash format untouched — orchestration is an SSE frame, never an audit entry.
- Pipeline decision logic unchanged — the only pipeline edit is an optional `timings` dict; `timings=None` (default) must be byte-identical to today.
- Mock/live seam parity — both `MockDataService` and `HttpDataService` produce equivalent orchestration data; flipping `VITE_DATA_SOURCE` stays zero-component-change.
- Exactly 3 agents. `agent_id ∈ {"detection","attribution","response"}`; `status ∈ {"ok","pending","unknown"}`; `stage ∈ {1,2,3}`.
- Agent display names (verbatim): `"Detection Agent"`, `"Attribution & Prediction Agent"`, `"Response Orchestrator Agent"`.
- Detection `elapsed_ms` is `None` on the backend (scoring happens in `engine/`, not the orchestrator) — never fabricate a detection latency.
- Run backend tests with `.venv/bin/pytest`; frontend with `cd frontend && npx vitest run` and `npx tsc -b --noEmit`.

---

### Task 1: Backend — `orchestrator/agents.py` (AgentActivity + build_orchestration)

**Files:**
- Create: `orchestrator/agents.py`
- Test: `tests/test_agents.py`

**Interfaces:**
- Consumes: `AnomalyEvent`, `EnrichedIncident`, `ContainmentAction`, `ActionStatus` from `orchestrator/schemas.py`.
- Produces: `class AgentActivity(BaseModel)` with fields `agent_id: str`, `name: str`, `stage: int`, `status: str`, `summary: str`, `elapsed_ms: int | None = None`; and `build_orchestration(event, incident, action, timings: dict | None = None) -> list[AgentActivity]` (3 activities, stage order 1→3).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agents.py
from orchestrator.agents import AgentActivity, build_orchestration
from orchestrator.schemas import (
    ActionStatus, ActionType, AnomalyEvent, AttackTechnique,
    ContainmentAction, EnrichedIncident, PredictedNext, Severity,
)


def _event():
    return AnomalyEvent(
        event_id="evt_1", timestamp="t", src_ip="10.0.0.5", dst_ip="203.0.113.9",
        anomaly_score=0.97, is_anomaly=True, top_features=["bytes_out"], raw_features={},
    )


def _incident(technique_id="T1498", confidence=0.7):
    return EnrichedIncident(
        event_id="evt_1", attack_technique=AttackTechnique(id=technique_id, name="x"),
        confidence=confidence, severity=Severity.high, cve_refs=[], certin_refs=[],
        narrative="n", predicted_next=PredictedNext(tactic="Impact", note="z"),
        suggested_action=ActionType.isolate_host,
    )


def _action(status=ActionStatus.pending_approval, requires_approval=True):
    return ContainmentAction(
        event_id="evt_1", action=ActionType.isolate_host, target="10.0.0.5",
        status=status, requires_human_approval=requires_approval,
        actor="system", audit_log_id="aud_0001",
    )


def test_build_orchestration_returns_three_agents_in_stage_order():
    acts = build_orchestration(_event(), _incident(), _action(),
                               {"attribution_ms": 1200, "response_ms": 3})
    assert [a.agent_id for a in acts] == ["detection", "attribution", "response"]
    assert [a.stage for a in acts] == [1, 2, 3]
    assert acts[0].name == "Detection Agent"
    assert acts[1].name == "Attribution & Prediction Agent"
    assert acts[2].name == "Response Orchestrator Agent"


def test_detection_has_no_backend_latency_and_reports_score():
    det = build_orchestration(_event(), _incident(), _action(), {})[0]
    assert det.status == "ok"
    assert det.elapsed_ms is None
    assert "0.97" in det.summary and "flagged" in det.summary


def test_attribution_status_is_unknown_for_unattributed_incident():
    acts = build_orchestration(_event(), _incident(technique_id="UNKNOWN", confidence=0.0),
                               _action(), {"attribution_ms": 900})
    attr = acts[1]
    assert attr.status == "unknown"
    assert attr.elapsed_ms == 900
    assert "unattributed" in attr.summary


def test_attribution_status_ok_carries_technique_and_confidence():
    attr = build_orchestration(_event(), _incident(), _action(), {"attribution_ms": 1200})[1]
    assert attr.status == "ok"
    assert "T1498" in attr.summary and "0.70" in attr.summary


def test_response_pending_when_action_awaits_approval():
    resp = build_orchestration(_event(), _incident(),
                               _action(ActionStatus.pending_approval, True),
                               {"response_ms": 5})[2]
    assert resp.status == "pending"
    assert "pending approval" in resp.summary
    assert resp.elapsed_ms == 5


def test_response_ok_when_auto_contained():
    resp = build_orchestration(_event(), _incident(),
                               _action(ActionStatus.simulated_success, False), {})[2]
    assert resp.status == "ok"
    assert "simulated_success" in resp.summary
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_agents.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'orchestrator.agents'`.

- [ ] **Step 3: Write minimal implementation**

```python
# orchestrator/agents.py
"""Multi-agent orchestration wrapper (#28, finalplan GAP1).

The Detection -> Attribution -> Response flow already runs linearly through the pipeline;
this presents it as three NAMED coordinating agents by assembling one AgentActivity per stage
from the real runtime objects. Pure observability: it decides nothing (policy.py stays
authoritative) and adds no core contract — AgentActivity is a stream-only model, separate from
the three frozen contracts in schemas.py.
"""

from __future__ import annotations

from pydantic import BaseModel

from orchestrator.schemas import (
    ActionStatus,
    AnomalyEvent,
    ContainmentAction,
    EnrichedIncident,
)


class AgentActivity(BaseModel):
    agent_id: str            # "detection" | "attribution" | "response"
    name: str
    stage: int               # 1..3 — kill-chain order, drives left->right layout
    status: str              # "ok" | "pending" | "unknown" — drives the UI icon
    summary: str
    elapsed_ms: int | None = None  # None for detection: scored in engine/, not measurable here


def build_orchestration(
    event: AnomalyEvent,
    incident: EnrichedIncident,
    action: ContainmentAction,
    timings: dict | None = None,
) -> list[AgentActivity]:
    timings = timings or {}

    detection = AgentActivity(
        agent_id="detection", name="Detection Agent", stage=1, status="ok",
        summary=f"{'flagged' if event.is_anomaly else 'normal'} · score {event.anomaly_score}",
        elapsed_ms=None,
    )

    attributed = incident.attack_technique.id != "UNKNOWN"
    attribution = AgentActivity(
        agent_id="attribution", name="Attribution & Prediction Agent", stage=2,
        status="ok" if attributed else "unknown",
        summary=(f"{incident.attack_technique.id} · conf {incident.confidence:.2f}"
                 if attributed else f"unattributed · conf {incident.confidence:.2f}"),
        elapsed_ms=timings.get("attribution_ms"),
    )

    pending = action.status == ActionStatus.pending_approval
    response = AgentActivity(
        agent_id="response", name="Response Orchestrator Agent", stage=3,
        status="pending" if pending else "ok",
        summary=(f"{action.action.value} · pending approval" if pending
                 else f"{action.action.value} · {action.status.value}"),
        elapsed_ms=timings.get("response_ms"),
    )

    return [detection, attribution, response]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_agents.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/agents.py tests/test_agents.py
git commit -m "feat(orchestrator): agents.py — AgentActivity + build_orchestration (#28)"
```

---

### Task 2: Backend — pipeline timing hook + `/events` orchestration frame

**Files:**
- Modify: `orchestrator/pipeline.py` (add optional `timings` param to `process`)
- Modify: `orchestrator/main.py` (publish 4th `orchestration` frame in `/events`)
- Test: `tests/test_main.py` (extend), `tests/test_pipeline.py` (add one timing test — file already exists)

**Interfaces:**
- Consumes: `build_orchestration` and `AgentActivity` from Task 1.
- Produces: `Pipeline.process(event, timings: dict | None = None)` filling `timings["attribution_ms"]` and `timings["response_ms"]`; a 4th published frame `{"kind":"orchestration","payload":{"event_id": str, "activities":[...]}}`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_pipeline.py` — reuse the file's existing `build(tmp_path, incident)`, `make_event(score)`, and `make_incident(severity)` helpers (already defined at the top of that file):

```python
def test_process_fills_timings_dict_when_provided(tmp_path):
    pipeline, _, _ = build(tmp_path, make_incident("high"))
    timings = {}
    pipeline.process(make_event(0.8), timings=timings)
    assert "attribution_ms" in timings and "response_ms" in timings
    assert isinstance(timings["attribution_ms"], int)
```

Add to `tests/test_main.py`:

```python
def test_events_publishes_orchestration_frame_with_three_agents(tmp_path):
    app = create_app(audit_path=tmp_path / "audit.jsonl", enrich=critical_enrich)
    client = TestClient(app)
    queue = app.state.broadcaster.subscribe()
    client.post("/events", json=EVENT)
    frames = [queue.get_nowait() for _ in range(4)]
    assert [f["kind"] for f in frames] == ["anomaly", "enriched", "containment", "orchestration"]
    payload = frames[3]["payload"]
    assert payload["event_id"] == "evt_0001"
    assert [a["agent_id"] for a in payload["activities"]] == ["detection", "attribution", "response"]
    assert payload["activities"][2]["status"] == "pending"  # critical -> isolate_host -> pending
```

And update the existing backlog test to expect the 4th frame:

```python
def test_frames_are_recorded_for_reconnect_backlog(tmp_path):
    app = create_app(audit_path=tmp_path / "audit.jsonl", enrich=critical_enrich)
    client = TestClient(app)
    client.post("/events", json=EVENT)
    kinds = [m["kind"] for m in app.state.messages]
    assert kinds == ["anomaly", "enriched", "containment", "orchestration"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_main.py -q tests/test_pipeline.py -q`
Expected: FAIL — new orchestration frame not published (`ValueError`/empty queue on the 4th `get_nowait`), backlog test sees only 3 kinds, `timings` stays empty.

- [ ] **Step 3: Write the implementation**

In `orchestrator/pipeline.py`, add the import at the top with the other imports:

```python
from time import perf_counter
```

Replace the `process` method body with (only the timing lines are new; decision logic is identical):

```python
    def process(self, event, timings=None) -> dict:
        _t0 = perf_counter()
        incident = self.enrich(event)
        if timings is not None:
            timings["attribution_ms"] = round((perf_counter() - _t0) * 1000)
        _t1 = perf_counter()
        decision = self.decide(event.anomaly_score, incident.severity)
        requires_approval = decision.requires_human_approval
        status = (
            ActionStatus.pending_approval if requires_approval else ActionStatus.simulated_success
        )
        target = _target_for(decision.action, event)
        detail = (
            f"{incident.attack_technique.id} ({incident.severity.value}, "
            f"conf {incident.confidence:.2f}) -> {decision.action.value} on {target}; "
            f"{incident.narrative}"
        )
        record = self.audit.append(
            event_id=event.event_id,
            action=decision.action.value,
            actor="system",
            detail=detail,
        )
        action = self.playbooks.run(
            action=decision.action,
            event_id=event.event_id,
            target=target,
            requires_human_approval=requires_approval,
            audit_log_id=record["audit_log_id"],
        )
        if timings is not None:
            timings["response_ms"] = round((perf_counter() - _t1) * 1000)
        return {"incident": incident, "action": action}
```

In `orchestrator/main.py`, add to the schema import line the `AgentActivity` is not needed here; add this import near the other `from orchestrator...` imports:

```python
from orchestrator.agents import build_orchestration
```

Replace the `/events` handler with:

```python
    @app.post("/events")
    async def ingest(event: AnomalyEvent):
        timings: dict = {}
        result = pipeline.process(event, timings=timings)
        incident_obj = result["incident"]
        action_obj = result["action"]
        incident = incident_obj.model_dump(mode="json")
        action = action_obj.model_dump(mode="json")
        incidents[event.event_id] = {"incident": incident, "action": action}
        activities = build_orchestration(event, incident_obj, action_obj, timings)
        # Four typed frames the dashboard accumulates by event_id (contract with frontend).
        await publish({"kind": "anomaly", "payload": event.model_dump(mode="json")})
        await publish({"kind": "enriched", "payload": incident})
        await publish({"kind": "containment", "payload": action})
        await publish({"kind": "orchestration", "payload": {
            "event_id": event.event_id,
            "activities": [a.model_dump(mode="json") for a in activities],
        }})
        return {"event_id": event.event_id, "status": action["status"]}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest -q --ignore=tests/test_engine_infer.py`
Expected: PASS (all backend tests, including the updated backlog test and the two new ones).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/pipeline.py orchestrator/main.py tests/test_main.py tests/test_pipeline.py
git commit -m "feat(orchestrator): publish orchestration frame + per-stage timings (#28)"
```

---

### Task 3: Frontend — contracts + HttpDataService ingest

**Files:**
- Modify: `frontend/src/types/contracts.ts` (add `AgentActivity`, `IncidentView.orchestration`)
- Modify: `frontend/src/data/http/HttpDataService.ts` (StreamMessage + ingest switch fix + orchestration branch)
- Test: `frontend/src/data/http/HttpDataService.test.ts` (extend)

**Interfaces:**
- Produces: `AgentActivity` TS interface; optional `IncidentView.orchestration?: AgentActivity[]`; HttpDataService handling of `{kind:"orchestration"}` frames.
- Consumes (from Task 2, over the wire): frame `{kind:"orchestration", payload:{event_id, activities}}`.

- [ ] **Step 1: Write the failing test**

Add to `frontend/src/data/http/HttpDataService.test.ts` (it already defines `ANOMALY`, `ENRICHED`, `CONTAINMENT`, `FakeEventSource`, and a `svc`/`es` setup — reuse the same pattern as the existing "verifies… audit" / approve tests):

```ts
  it("attaches orchestration activities to the incident view", () => {
    const svc = new HttpDataService("http://api.test");
    svc.start();
    const es = FakeEventSource.instances[0];
    es.send({ kind: "anomaly", payload: ANOMALY });
    es.send({ kind: "enriched", payload: ENRICHED });
    es.send({ kind: "containment", payload: CONTAINMENT });
    es.send({
      kind: "orchestration",
      payload: {
        event_id: ANOMALY.event_id,
        activities: [
          { agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok", summary: "flagged", elapsed_ms: null },
          { agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2, status: "ok", summary: "T1", elapsed_ms: 1200 },
          { agent_id: "response", name: "Response Orchestrator Agent", stage: 3, status: "pending", summary: "isolate", elapsed_ms: 3 },
        ],
      },
    });
    const view = svc.getIncident(ANOMALY.event_id);
    expect(view?.orchestration?.length).toBe(3);
    expect(view?.orchestration?.[2].status).toBe("pending");
    // containment still works after the switch change (guards the ingest-branch fix)
    expect(view?.containment?.status).toBe(CONTAINMENT.status);
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/data/http/HttpDataService.test.ts`
Expected: FAIL — `orchestration` frame hits the current `else` branch (mis-handled as containment); `view.orchestration` is undefined.

- [ ] **Step 3: Write the implementation**

In `frontend/src/types/contracts.ts`, add after the `PredictedNext` interface:

```ts
/** Stage of the 3-agent orchestration view (#28). Observability only — not a core contract. */
export interface AgentActivity {
  agent_id: "detection" | "attribution" | "response";
  name: string;
  stage: number; // 1..3
  status: "ok" | "pending" | "unknown";
  summary: string;
  elapsed_ms: number | null; // null for detection (scored in engine/, not the orchestrator)
}
```

In the same file, add the optional field to `IncidentView`:

```ts
export interface IncidentView {
  event: AnomalyEvent;
  incident: EnrichedIncident;
  containment?: ContainmentAction;
  /** 3-agent hand-off view for this event (#28), set when the orchestration frame arrives. */
  orchestration?: AgentActivity[];
}
```

In `frontend/src/data/http/HttpDataService.ts`, add `AgentActivity` to the type import from `../../types/contracts`, then extend the `StreamMessage` union:

```ts
type StreamMessage =
  | { kind: "anomaly"; payload: AnomalyEvent }
  | { kind: "enriched"; payload: EnrichedIncident }
  | { kind: "containment"; payload: ContainmentAction }
  | { kind: "orchestration"; payload: { event_id: string; activities: AgentActivity[] } };
```

Replace the final `else` block in `ingest()` (the containment branch) with an explicit branch plus the orchestration branch:

```ts
    } else if (msg.kind === "containment") {
      const view = this.state.views.get(id);
      if (!view) return;
      view.containment = msg.payload;
      const t = this.state.timings.get(id);
      if (t) {
        if (!t.actionCreatedAt) t.actionCreatedAt = Date.now();
        if (msg.payload.status === "simulated_success" && !t.resolvedAt) t.resolvedAt = Date.now();
      }
      this.notify(view);
    } else {
      // kind === "orchestration"
      const view = this.state.views.get(id);
      if (!view) return;
      view.orchestration = msg.payload.activities;
      this.notify(view);
    }
```

- [ ] **Step 4: Run test + typecheck**

Run: `cd frontend && npx vitest run src/data/http/HttpDataService.test.ts && npx tsc -b --noEmit`
Expected: PASS + "No errors found".

- [ ] **Step 5: Commit**

```bash
git add frontend/src/types/contracts.ts frontend/src/data/http/HttpDataService.ts frontend/src/data/http/HttpDataService.test.ts
git commit -m "feat(frontend): ingest orchestration frame onto IncidentView (#28)"
```

---

### Task 4: Frontend — MockDataService orchestration parity

**Files:**
- Modify: `frontend/src/data/mock/MockDataService.ts` (set `view.orchestration` in `inject`)
- Test: `frontend/src/data/mock/MockDataService.test.ts` (add one test)

**Interfaces:**
- Consumes: `AgentActivity` (Task 3), `decide` (already imported in this file from `../policy`).
- Produces: `IncidentView.orchestration` populated in mock mode identically to live.

- [ ] **Step 1: Write the failing test**

Add to `frontend/src/data/mock/MockDataService.test.ts` — the file uses `vi.useFakeTimers()` in `beforeEach` and advances with the **async** API `await vi.advanceTimersByTimeAsync(...)`; the test callback must be `async` (match the existing "triggerAttack produces a pending…" test):

```ts
  it("attaches a 3-agent orchestration to each injected incident", async () => {
    const svc = new MockDataService();
    svc.triggerAttack();                        // fires one scripted incident immediately
    await vi.advanceTimersByTimeAsync(2000);    // let attribution + containment land
    const latest = svc.getIncidents()[0];
    expect(latest.orchestration?.length).toBe(3);
    expect(latest.orchestration?.map((a) => a.agent_id)).toEqual(
      ["detection", "attribution", "response"],
    );
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/data/mock/MockDataService.test.ts`
Expected: FAIL — `latest.orchestration` is undefined.

- [ ] **Step 3: Write the implementation**

In `frontend/src/data/mock/MockDataService.ts`, add `AgentActivity` to the type import from `../types/contracts` (the file already imports several types from there). Inside `inject()`, immediately after the `view.containment = containment;` line (and before `this.notify(view);` that follows it), insert:

```ts
      const attributed = incident.attack_technique.id !== "UNKNOWN";
      const activities: AgentActivity[] = [
        {
          agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok",
          summary: `${event.is_anomaly ? "flagged" : "normal"} · score ${event.anomaly_score}`,
          elapsed_ms: null,
        },
        {
          agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2,
          status: attributed ? "ok" : "unknown",
          summary: attributed
            ? `${incident.attack_technique.id} · conf ${incident.confidence.toFixed(2)}`
            : `unattributed · conf ${incident.confidence.toFixed(2)}`,
          elapsed_ms: Math.round(attributionDelay),
        },
        {
          agent_id: "response", name: "Response Orchestrator Agent", stage: 3,
          status: decision.requires_human_approval ? "pending" : "ok",
          summary: decision.requires_human_approval
            ? `${decision.action} · pending approval`
            : `${decision.action} · approved`,
          elapsed_ms: 300,
        },
      ];
      view.orchestration = activities;
```

(`attributionDelay`, `decision`, `incident`, `event`, and `view` are all already in scope at that point in `inject`.)

- [ ] **Step 4: Run test + typecheck**

Run: `cd frontend && npx vitest run src/data/mock/MockDataService.test.ts && npx tsc -b --noEmit`
Expected: PASS + "No errors found".

- [ ] **Step 5: Commit**

```bash
git add frontend/src/data/mock/MockDataService.ts frontend/src/data/mock/MockDataService.test.ts
git commit -m "feat(frontend): mock-mode orchestration parity (#28)"
```

---

### Task 5: Frontend — AgentOrchestration panel + Operations wiring + live verify

**Files:**
- Create: `frontend/src/lib/orchestration.ts` (pure selector — unit-testable without a DOM harness)
- Create: `frontend/src/lib/orchestration.test.ts`
- Create: `frontend/src/components/AgentOrchestration.tsx`
- Modify: `frontend/src/pages/Operations.tsx` (add the panel row)

**Interfaces:**
- Consumes: `IncidentView` with optional `orchestration` (Tasks 3/4); `Panel`, `PanelHeader` from `@/components/ui/primitives`; `cn` from `@/lib/utils`.
- Produces: `latestOrchestration(incidents: IncidentView[]): AgentActivity[] | null`; `<AgentOrchestration incidents={...} />`.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/orchestration.test.ts
import { describe, it, expect } from "vitest";
import { latestOrchestration } from "./orchestration";
import type { IncidentView, AgentActivity } from "@/types/contracts";

const acts: AgentActivity[] = [
  { agent_id: "detection", name: "Detection Agent", stage: 1, status: "ok", summary: "s", elapsed_ms: null },
  { agent_id: "attribution", name: "Attribution & Prediction Agent", stage: 2, status: "ok", summary: "s", elapsed_ms: 1 },
  { agent_id: "response", name: "Response Orchestrator Agent", stage: 3, status: "pending", summary: "s", elapsed_ms: 1 },
];

function view(id: string, orchestration?: AgentActivity[]): IncidentView {
  return {
    event: { schema_version: "1.0", event_id: id, timestamp: "t", src_ip: "a", dst_ip: "b",
             anomaly_score: 0.9, is_anomaly: true, top_features: [], raw_features: {} },
    incident: { schema_version: "1.0", event_id: id, attack_technique: { id: "T1", name: "x" },
                confidence: 0.7, severity: "high", cve_refs: [], certin_refs: [],
                narrative: "n", predicted_next: null, suggested_action: "monitor" },
    orchestration,
  };
}

describe("latestOrchestration", () => {
  it("returns null when no incident has orchestration data", () => {
    expect(latestOrchestration([view("e1")])).toBeNull();
    expect(latestOrchestration([])).toBeNull();
  });

  it("returns the newest incident's activities (list is newest-first)", () => {
    // getIncidents() returns newest-first, so the first with orchestration wins
    expect(latestOrchestration([view("e2", acts), view("e1")])).toEqual(acts);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/lib/orchestration.test.ts`
Expected: FAIL — `Cannot find module './orchestration'`.

- [ ] **Step 3: Write the selector + component + wire the page**

```ts
// frontend/src/lib/orchestration.ts
import type { IncidentView, AgentActivity } from "@/types/contracts";

/** The newest incident's 3-agent hand-off, or null. `incidents` is newest-first (getIncidents). */
export function latestOrchestration(incidents: IncidentView[]): AgentActivity[] | null {
  for (const v of incidents) {
    if (v.orchestration && v.orchestration.length) return v.orchestration;
  }
  return null;
}
```

```tsx
// frontend/src/components/AgentOrchestration.tsx
import type { IncidentView } from "@/types/contracts";
import { latestOrchestration } from "@/lib/orchestration";
import { EmptyState } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const ICON: Record<string, string> = { ok: "✓", pending: "⏳", unknown: "⚠" };
const ICON_COLOR: Record<string, string> = {
  ok: "text-live", pending: "text-sev-high", unknown: "text-sev-critical",
};

export function AgentOrchestration({ incidents }: { incidents: IncidentView[] }) {
  const activities = latestOrchestration(incidents);
  if (!activities) {
    return <EmptyState label="No agent activity yet" hint="Agents light up as events flow through the pipeline" />;
  }
  return (
    <div className="flex items-stretch gap-2 overflow-x-auto p-3">
      {activities.map((a, i) => (
        <div key={a.agent_id} className="flex items-center gap-2">
          <div className="flex min-w-[190px] flex-col gap-0.5 rounded-md border border-line-soft bg-surface-2/50 px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="mono text-[10px] text-ink-faint">
                {String(a.stage).padStart(2, "0")} · {a.name}
              </span>
              <span className={cn("mono text-[12px]", ICON_COLOR[a.status])}>{ICON[a.status]}</span>
            </div>
            <span className="truncate text-[11px] text-ink">{a.summary}</span>
            <span className="mono text-[9px] text-ink-faint">
              {a.elapsed_ms == null ? "—" : `${a.elapsed_ms} ms`}
            </span>
          </div>
          {i < activities.length - 1 && <span className="mono text-ink-faint">→</span>}
        </div>
      ))}
    </div>
  );
}
```

In `frontend/src/pages/Operations.tsx`, add the import:

```tsx
import { AgentOrchestration } from "@/components/AgentOrchestration";
```

Change the outer wrapper's row template from `grid-rows-[auto_1fr]` to `grid-rows-[auto_auto_1fr]` and insert the panel between `<MetricsBar />` and the 3-column `<div>`:

```tsx
    <div className="grid h-full grid-rows-[auto_auto_1fr] gap-3 p-3">
      <MetricsBar />

      <Panel>
        <PanelHeader eyebrow="multi-agent pipeline" title="Agent orchestration" right={<span className="mono text-[10px] text-ink-faint">detection → attribution → response</span>} />
        <AgentOrchestration incidents={incidents} />
      </Panel>

      <div className="grid min-h-0 grid-cols-[minmax(300px,1fr)_1.35fr_1.15fr] gap-3">
        {/* ...existing three panels unchanged... */}
```

(`Panel` and `PanelHeader` are already imported in Operations.tsx.)

- [ ] **Step 4: Run tests + typecheck + full frontend suite**

Run: `cd frontend && npx vitest run && npx tsc -b --noEmit`
Expected: PASS (all frontend tests) + "No errors found".

- [ ] **Step 5: Live end-to-end verification**

Start the stack and drive real events (Groq quota permitting; the panel renders regardless of attribution outcome):

```bash
# backend (live enrichment)
set -a; source .env; set +a
ENRICH_MODE=live .venv/bin/uvicorn orchestrator.main:app --host 0.0.0.0 --port 8000 &
# frontend (live data source)
cd frontend && VITE_DATA_SOURCE=live VITE_API_BASE=http://localhost:8000 npx vite --port 5173 &
# stream a few events
.venv-engine/bin/python -m engine.replay --limit 4 --delay 2 --only-anomalies
```

Open `http://localhost:5173`, confirm the "Agent orchestration" panel shows the three agents with ✓/⏳/⚠ status, summaries, per-stage ms (detection shows "—"), and hand-off arrows. Screenshot it. Also confirm mock mode renders it: `cd frontend && npx vite --port 5174` (default `VITE_DATA_SOURCE=mock`) → panel populated. Stop all background processes when done.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib/orchestration.ts frontend/src/lib/orchestration.test.ts frontend/src/components/AgentOrchestration.tsx frontend/src/pages/Operations.tsx
git commit -m "feat(frontend): AgentOrchestration panel on Operations page (#28)"
```

---

## Self-Review

**Spec coverage:**
- AgentActivity model + build_orchestration → Task 1. ✓
- Pipeline timing hook + orchestration frame → Task 2. ✓
- Frontend contracts + HttpDataService ingest (incl. switch fix) → Task 3. ✓
- Mock parity → Task 4. ✓
- Panel + Operations wiring + live e2e → Task 5. ✓
- Invariants (3 contracts frozen, policy authoritative, audit untouched, pipeline logic unchanged, mock/live parity, 3 agents, verbatim names, detection ms None) → Global Constraints + enforced across tasks. ✓

**Placeholder scan:** No TBD/TODO. Every code step shows full code. Test bodies are concrete. Only intentional prose is "…existing three panels unchanged…" in the JSX insert, which references real unchanged code, not a gap. ✓

**Type consistency:** `AgentActivity` fields identical across Task 1 (Python) and Task 3 (TS mirror): `agent_id`, `name`, `stage`, `status`, `summary`, `elapsed_ms`. `status` values `ok|pending|unknown` consistent everywhere. Frame shape `{event_id, activities}` identical in Task 2 (publish), Task 3 (ingest), and both tests. `build_orchestration(event, incident, action, timings)` signature consistent. `latestOrchestration` used identically in Task 5 selector, test, and component. ✓
