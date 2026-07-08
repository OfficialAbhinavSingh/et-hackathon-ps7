"""Contract-correctness tests for the detection engine's inference (issue #15).

The score-value behavior is covered by engine/RESULTS.md; these assert the *shape* the
orchestrator depends on: valid AnomalyEvent, 0-1 score, human-readable top_features (never
one-hot column names), synthesized topology present. Skips cleanly if the model hasn't been
trained (artifacts are gitignored — run `python -m engine.train` first).
"""

import json
from pathlib import Path

import pytest

MODEL_DIR = Path(__file__).resolve().parent.parent / "engine" / "model"
HAS_MODEL = (MODEL_DIR / "isoforest.joblib").exists()
pytestmark = pytest.mark.skipif(not HAS_MODEL, reason="model not trained (run python -m engine.train)")


def test_calibration_is_monotonic_and_bounded():
    from engine.infer import Scorer
    s = Scorer(model=None, pre=None, threshold=0.45, lo=0.35, mid=0.45, hi=0.63)
    xs = [0.30, 0.35, 0.40, 0.45, 0.55, 0.63, 0.80]
    ys = [s.calibrate(x) for x in xs]
    assert ys == sorted(ys)                      # monotonic non-decreasing
    assert all(0.0 <= y <= 1.0 for y in ys)      # bounded
    assert s.calibrate(0.45) == pytest.approx(0.7, abs=1e-6)  # threshold -> block_ip boundary
    assert s.calibrate(1.0) == 1.0 and s.calibrate(0.0) == 0.0


def _synthetic_flow():
    meta = json.loads((MODEL_DIR / "model_meta.json").read_text())
    row = {f: 0.0 for f in meta["numeric_features"]}
    row.update({"proto": "tcp", "service": "-", "state": "FIN"})
    return row


def test_score_emits_valid_contract1_event():
    from engine.infer import load_scorer
    from orchestrator.schemas import AnomalyEvent

    ev = load_scorer().score(_synthetic_flow(), event_id="evt_test_0001")
    assert isinstance(ev, AnomalyEvent)
    assert ev.event_id == "evt_test_0001"
    assert 0.0 <= ev.anomaly_score <= 1.0
    assert isinstance(ev.is_anomaly, bool)
    assert ev.timestamp.endswith("Z")
    assert ev.src_ip.startswith("10.")            # internal source host
    assert "dst_port" in ev.raw_features


def test_top_features_are_human_readable_not_onehot():
    from engine.infer import load_scorer
    scorer = load_scorer()
    ev = scorer.score(_synthetic_flow())
    numeric = set(scorer.pre.numeric_features)
    # every top feature must be a named numeric feature — never a one-hot column (proto_tcp…)
    assert ev.top_features, "expected at least one top feature"
    assert all(f in numeric for f in ev.top_features)
    assert not any(f.startswith(("proto_", "service_", "state_")) for f in ev.top_features)


def test_score_frame_batch_shapes_and_uniqueness():
    import pandas as pd
    from engine.infer import load_scorer

    df = pd.DataFrame([_synthetic_flow() for _ in range(5)])
    events = load_scorer().score_frame(df, id_prefix="evt_batch")
    assert len(events) == 5
    assert len({e.event_id for e in events}) == 5          # unique ids
    assert all(0.0 <= e.anomaly_score <= 1.0 for e in events)
