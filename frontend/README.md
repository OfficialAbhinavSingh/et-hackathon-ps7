# SENTINEL — AI-SOC Dashboard (PS7, issue #10)

The analyst-facing dashboard for the AI Security Operations Center: a live incident feed,
MITRE ATT&CK kill-chain grid, attack-path graph, human-in-the-loop approval queue, and a
tamper-evident audit trail. Built to run standalone against a mock today and flip to the
real backend (#11) by changing one environment variable.

## Stack

Vite · React · TypeScript · Tailwind v4 · shadcn-style primitives · React Flow (attack
graph) · Vitest. Fonts self-hosted (Space Grotesk + JetBrains Mono) so the demo works
offline on stage.

## Run

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

Other scripts:

```bash
npm run build          # type-check + production build
npx tsc -b             # type-check only
npx vitest run         # unit tests
```

## Architecture — the swappable seam

Every component talks to **one `DataService` interface** (`src/data/DataService.ts`) — no
component ever calls `fetch` or `EventSource` directly. The implementation is selected at
runtime:

```bash
VITE_DATA_SOURCE=mock   # default — in-memory scripted stream (no backend needed)
VITE_DATA_SOURCE=live   # real backend via EventSource + fetch
VITE_API_BASE=http://localhost:8000   # backend origin for live mode
```

- `src/data/mock/MockDataService.ts` — replays the 20 fixtures, ~4s ticker, plus a manual
  **Trigger Attack** control (scripted T1048 exfiltration on port 4444). Generates the audit
  hash chain locally.
- `src/data/http/HttpDataService.ts` — real `GET /stream` (SSE, reconnect-with-backoff),
  `POST /approve/{id}`, `GET /audit`. **Skeleton — finish when #11 lands.**

Both implementations accumulate the stream by `event_id` into a unified `IncidentView`
(`{ event, incident, containment? }`) and reuse the same pure derivations
(`src/data/derive.ts`) for the incident list, attack graph, and metrics. **Flipping the env
var requires zero component changes.**

Real backend endpoints are only `GET /stream`, `POST /approve/{id}`, `GET /audit`. There is
no `/incidents`, `/graph`, or `/metrics` — those are derived client-side in both modes.

## Views

| Route | View |
|-------|------|
| `/` | Operations — metrics + live feed + kill-chain grid + attack graph, one screen |
| `/incidents`, `/incidents/:id` | Risk-ranked queue → full incident brief |
| `/approvals` | Pending-action queue; approve confirms or corrects the attribution |
| `/graph` | Full attack-path / lateral-movement graph |
| `/audit` | Hash-chained trail + Verify Chain Integrity (with a tamper demo) |

## Metrics (computed from real state transitions, not hardcoded)

- **MTTD** — anomaly occurred → attribution available.
- **MTTR** — action created → simulated_success.
- **Attribution accuracy** — analyst-confirmed-correct techniques over the reviewed subset
  (updates when you approve/correct in the Approvals view; `—` until the first review).
- **Automation coverage** — auto-handled (`monitor` / `block_ip`) over total actions.

## Contracts & coordination with #11 (Dev 1)

`src/types/contracts.ts` mirrors **README §4** (the frozen v1.0 contracts). If
`schema_version` bumps, this file and `orchestrator/schemas.py` change together.

Two seams the backend must match:

1. **Audit serialization** (`src/data/hashChain.ts`): `entry_hash = sha256(prev_hash +
   canonical(entry))`, where `canonical` is the JSON of
   `{audit_log_id, timestamp, event_id, action, actor, detail}` in that exact order with no
   whitespace. `orchestrator/audit.py` must produce byte-identical input.
2. **SSE frame envelope** (`HttpDataService`, marked TODO): assumes each frame is tagged
   `{ kind: "anomaly" | "enriched" | "containment", payload: <contract> }`. Confirm the real
   shape before live wiring.
