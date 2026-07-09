# Detection engine (`engine/`) — #14 / #15

Unsupervised anomaly detection: an **Isolation Forest** trained on UNSW-NB15 that learns
"normal" network flow and flags deviations, emitting the Contract-1 `AnomalyEvent` the
orchestrator ingests. No labelled attack/benign classifier — labels are used only to score.

## Why its own venv

`scikit-learn` has no wheels for the system's Python 3.14, and the ML stack doesn't belong in
the FastAPI runtime. So the engine lives in an isolated **Python 3.12** venv (`.venv-engine`),
separate from the backend's `.venv`. You need `python3.12` on your PATH.

## One-time setup

```bash
make engine-setup          # creates .venv-engine (py3.12) + installs scikit-learn/pandas/numpy/joblib/pydantic
```

## Get the dataset (not committed — too big, gitignored)

Download the two **cleaned** UNSW-NB15 partitions from Kaggle
(<https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15>) — only these two files:

```
data/unsw/UNSW_NB15_training-set.csv
data/unsw/UNSW_NB15_testing-set.csv
```

`make train` validates they're present + correctly shaped before training.

## Train

```bash
make train                 # validates dataset, fits the model, writes engine/RESULTS.md
```

Artifacts land in `engine/model/` (`isoforest.joblib`, `scaler.joblib`, `preprocessor.joblib`,
`model_meta.json`). The `.joblib` binaries are gitignored — regenerate with `make train`.
Current result: **ROC-AUC 0.867**, recall 0.75 @ 10% FPR (full breakdown in `RESULTS.md`).

## Drive the live dashboard with real detections

```bash
make backend               # terminal 1 — orchestrator on :8000
make frontend-live         # terminal 2 — dashboard (live) on :5173
make replay-engine         # terminal 3 — stream real model-scored events into POST /events
```

`make replay` (no `-engine`) is a different thing — it replays the *fixture* JSON, not the
real model. Use `make replay-engine` for real detections.

## Files

| File | Role |
|------|------|
| `preprocess.py` | load UNSW, drop labels, proto top-10 + one-hot, log1p + scale; persisted for identical inference transforms |
| `train.py` | fit on pooled-normal rows, pick Youden operating point, save model + calibration, write `RESULTS.md` |
| `infer.py` | `score(flow) → AnomalyEvent` — calibrated 0–1 score, z-score `top_features`, synthetic IP/port topology |
| `replay.py` | stream scored events into the orchestrator, paced |
| `fetch_unsw.py` | dataset provenance + shape validator (not a downloader) |

## Notes for reviewers / integration (#17)

- The cleaned partition has **no src/dst IP or port** — those are synthesized in `infer.py`
  for the graph (deterministic, flagged synthetic, never model input).
- Enrichment is currently a stub in the orchestrator; real severities/techniques arrive with
  the attribution agent (#17), at which point high-score events reach the `isolate_host`
  approval tier.
- Tests: `make test-engine` (skips cleanly if the model isn't trained).
