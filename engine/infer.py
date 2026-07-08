"""Inference + attribution: score a flow -> Contract-1 AnomalyEvent (issue #15).

Loads the model + preprocessor + calibration persisted by train.py and turns a UNSW-NB15
flow row into the exact `AnomalyEvent` the orchestrator ingests. Three things beyond raw
scoring, all required by the contract / downstream:

  1. Calibrated 0-1 anomaly_score — the raw Isolation Forest score is ~0.35-0.63; a 2-segment
     linear map (anchors from train.py) turns it into a confidence where is_anomaly (raw > the
     trained threshold) lines up with score >= 0.7 (block_ip) and the most anomalous flows
     exceed 0.9 (isolate tier, once real severities arrive from the attribution agent).
  2. Human-readable top_features — the 3 numeric features with the largest z-score deviation
     from normal (`sbytes`, `ct_state_ttl`, …), never one-hot column names (Contract-1 rule).
  3. Synthetic network topology — the cleaned UNSW partition carries no src/dst IP or port, so
     we deterministically map each flow onto a small host topology (internal CNI + external
     attackers), including some east-west edges so the attack-path graph shows lateral
     movement. Honest demo dressing; NOT model input, flagged as synthetic.
"""

from __future__ import annotations

import json
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterator, Mapping

import joblib
import numpy as np
import pandas as pd

from orchestrator.schemas import AnomalyEvent

MODEL_DIR = Path(__file__).resolve().parent / "model"

# common destination ports keyed by UNSW `service`; fallback picks from this pool
SERVICE_PORT = {"dns": 53, "http": 80, "https": 443, "ssh": 22, "ftp": 21,
                "ftp-data": 20, "smtp": 25, "pop3": 110, "snmp": 161, "irc": 6667}
PORT_POOL = [443, 80, 22, 3389, 445, 4444, 8080, 53, 23, 21]


def _stable(*parts: object) -> int:
    """Deterministic hash (crc32) — Python's hash() is salted per process, unusable here."""
    return zlib.crc32("|".join(str(p) for p in parts).encode())


@dataclass
class Scorer:
    model: object
    pre: object
    threshold: float
    lo: float
    mid: float
    hi: float

    # ---- calibration ------------------------------------------------------

    def calibrate(self, raw: float) -> float:
        if raw <= self.mid:
            v = 0.7 * (raw - self.lo) / max(self.mid - self.lo, 1e-9)
        else:
            v = 0.7 + 0.3 * (raw - self.mid) / max(self.hi - self.mid, 1e-9)
        return round(min(1.0, max(0.0, v)), 3)

    # ---- synthetic topology (deterministic per flow) ----------------------

    def _topology(self, row: Mapping, i: int, is_anomaly: bool) -> tuple[str, str, int]:
        h = _stable(i, row.get("proto"), row.get("sbytes"), row.get("dur"))
        src = f"10.0.0.{2 + h % 28}"                       # internal CNI host
        if is_anomaly and h % 10 < 3:                       # ~30% of anomalies: east-west
            dst_host = 2 + (h // 7) % 28
            if dst_host == 2 + h % 28:
                dst_host = 2 + (dst_host % 28)              # ensure distinct
            dst = f"10.0.0.{dst_host}"
        elif is_anomaly:                                    # external attacker
            block = "203.0.113" if h % 2 else "198.51.100"
            dst = f"{block}.{10 + h % 80}"
        else:                                               # normal -> internal service
            dst = f"10.0.0.{1 if h % 2 else 2}"
        svc = str(row.get("service", "-")).strip().lower()
        port = SERVICE_PORT.get(svc, PORT_POOL[h % len(PORT_POOL)])
        return src, dst, int(port)

    # ---- scoring ----------------------------------------------------------

    def _events(self, df: pd.DataFrame, id_prefix: str, base_ts: datetime) -> Iterator[AnomalyEvent]:
        raw = -self.model.score_samples(self.pre.transform(df))
        z = self.pre.numeric_zscores(df)
        numf = self.pre.numeric_features
        for i in range(len(df)):
            row = df.iloc[i]
            is_anom = bool(raw[i] > self.threshold)
            top_idx = np.argsort(-np.abs(z[i]))[:3]
            src, dst, port = self._topology(row, i, is_anom)
            raw_features = {numf[j]: round(float(row[numf[j]]), 4) for j in top_idx}
            raw_features["dst_port"] = port
            yield AnomalyEvent(
                schema_version="1.0",
                event_id=f"{id_prefix}_{i:04d}",
                timestamp=(base_ts + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
                src_ip=src,
                dst_ip=dst,
                anomaly_score=self.calibrate(raw[i]),
                is_anomaly=is_anom,
                top_features=[numf[j] for j in top_idx],   # human-readable names only
                raw_features=raw_features,
            )

    def score_frame(self, df: pd.DataFrame, id_prefix: str = "evt", base_ts: datetime | None = None) -> list[AnomalyEvent]:
        base_ts = base_ts or datetime.now(timezone.utc)
        return list(self._events(df.reset_index(drop=True), id_prefix, base_ts))

    def score(self, flow: Mapping, event_id: str = "evt_0001") -> AnomalyEvent:
        """Single-flow entry point: score(flow) -> AnomalyEvent (the DoD signature)."""
        df = pd.DataFrame([dict(flow)])
        ev = next(self._events(df, event_id.rsplit("_", 1)[0] if "_" in event_id else event_id,
                               datetime.now(timezone.utc)))
        return ev.model_copy(update={"event_id": event_id})


_SCORER: Scorer | None = None


def load_scorer() -> Scorer:
    """Lazily load the persisted model/preprocessor/calibration (cached)."""
    global _SCORER
    if _SCORER is None:
        meta = json.loads((MODEL_DIR / "model_meta.json").read_text())
        cal = meta["calibration"]
        _SCORER = Scorer(
            model=joblib.load(MODEL_DIR / "isoforest.joblib"),
            pre=joblib.load(MODEL_DIR / "preprocessor.joblib"),
            threshold=float(meta["threshold"]),
            lo=cal["lo"], mid=cal["mid"], hi=cal["hi"],
        )
    return _SCORER
