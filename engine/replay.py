"""Replay real scored flows into the live pipeline (issue #15).

Scores UNSW-NB15 rows with the trained model (engine/infer.py) and POSTs each resulting
AnomalyEvent to the orchestrator's `POST /events`, pacing them so the dashboard feed ticks
like a live stream. This is what makes the demo move: real detection -> real events ->
orchestrator -> SSE -> dashboard.

Run (orchestrator must be up on :8000):
    .venv/bin/python -m engine.replay --limit 40 --delay 1.5
    .venv/bin/python -m engine.replay --only-anomalies --delay 2
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from engine.infer import load_scorer
from engine.preprocess import load_unsw

DATA = Path(__file__).resolve().parent.parent / "data" / "unsw"
DEFAULT_SOURCE = DATA / "UNSW_NB15_testing-set.csv"


def post_event(url: str, event) -> int:
    body = json.dumps(event.model_dump(mode="json")).encode()
    req = urllib.request.Request(
        f"{url}/events", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    # 30s, not 5s: with ENRICH_MODE=live the orchestrator's POST /events blocks on a real
    # LLM tool-calling round trip (intel.agent.enrich), which can take several seconds —
    # the stub path was instant, the live path isn't.
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SOURCE))
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--limit", type=int, default=40, help="number of events to stream")
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between events")
    ap.add_argument("--only-anomalies", action="store_true", help="stream only flagged anomalies")
    ap.add_argument("--shuffle", action="store_true", default=True)
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    df = load_unsw(args.source)
    if args.shuffle:
        df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    scorer = load_scorer()
    # score a generous slice, then filter/limit (scoring is vectorized & cheap)
    events = scorer.score_frame(df.head(max(args.limit * 4, 200)), id_prefix="evt_live")
    if args.only_anomalies:
        events = [e for e in events if e.is_anomaly]
    events = events[: args.limit]

    print(f"streaming {len(events)} events -> {args.url}/events  (delay {args.delay}s)")
    sent = 0
    for e in events:
        try:
            status = post_event(args.url, e)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            print(f"\n! backend unreachable at {args.url} ({exc}). Is it running? "
                  f"(make backend)  — stopping.")
            break
        sent += 1
        flag = "ANOMALY" if e.is_anomaly else "normal "
        print(f"  [{sent:3d}] {e.event_id} {flag} score={e.anomaly_score:<5} "
              f"{e.src_ip}->{e.dst_ip}:{e.raw_features['dst_port']} top={e.top_features} -> {status}")
        time.sleep(args.delay)
    print(f"done — {sent} events streamed.")


if __name__ == "__main__":
    main()
