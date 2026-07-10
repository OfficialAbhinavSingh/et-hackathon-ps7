# Real Network Identity (IPs/Ports/Attack-Path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `engine/infer.py`'s synthetic src_ip/dst_ip/dst_port topology with the real `srcip/sport/dstip/dsport` fields carried by the raw UNSW-NB15 dataset (`UNSW-NB15_1..4.csv`), so the attack-path graph is built from genuinely captured network identity instead of a deterministic hash.

**Architecture:** Add a raw-format loader (`engine/raw_unsw.py`) that renames the raw dataset's 49 columns onto the same feature names the trained model already expects, keeping `srcip/sport/dstip/dsport` as passthrough identity columns explicitly excluded from the feature matrix (never model inputs — same discipline as today, just real instead of fabricated). `engine/train.py` gains a `--raw` mode that pools directly from the raw files and persists a real-identity eval slice. `engine/infer.py` reads a `topology_source` flag from `model_meta.json` and, when `"real"`, emits the row's actual IP/port instead of hashing one. The cleaned-partition path (today's default) is untouched — this is an additive seam, not a rewrite, matching the project's "swap mocks for real behind an unchanging contract" pattern.

**Tech Stack:** Python 3.12 (`.venv-engine`), pandas, scikit-learn, joblib — all already in place; no new dependencies.

## Global Constraints

- **Detection stays unsupervised.** `IsolationForest` is retrained the same way (fit on pooled normal only, labels for eval only) — no classifier, no signature matching.
- **Identity columns must never enter the feature matrix.** `srcip, sport, dstip, dsport` (and the raw-only `stime, ltime`) are excluded from `numeric_features` via `preprocess.DROP_COLS`, enforced by a test — feeding them to the model would leak lab-testbed IP patterns into "normal" instead of learning real flow behavior.
- **`raw_features` must stay human-readable; `top_features` never one-hot column names** — unchanged Contract-1 rule (`orchestrator/schemas.py`), verified by existing tests.
- **`src_ip`/`dst_ip` remain the attack-path graph edges** — no frontend change needed; `frontend/src/data/derive.ts::deriveGraph()` already consumes whatever IPs arrive on the event stream.
- **The cleaned-partition (synthetic-topology) path must keep working unchanged** — no `--raw` flag, no behavior change, so existing tests/demos aren't disrupted mid-plan.
- **No live downloader** — matches `engine/fetch_unsw.py`'s existing documented stance (Kaggle needs credentials, fragile on demo day); validation-only, manual download.
- Comments explain *why* (the contract, the seam, the invariant), not *what* — match existing file density.

---

## File Structure

| File | Change |
|---|---|
| `engine/raw_unsw.py` | **New.** Raw 49-column loader + rename map + cleaning. |
| `engine/preprocess.py` | Extend `DROP_COLS` with identity/time columns. |
| `engine/fetch_unsw.py` | Add raw-file validation (mirrors existing cleaned-partition validation). |
| `engine/train.py` | Add `--raw` mode: pool directly from raw files, persist eval slice, tag `topology_source` in `model_meta.json`. |
| `engine/infer.py` | `Scorer.topology_source` field; `_topology()` branches to real IP/port when set. |
| `tests/test_raw_unsw.py` | **New.** Loader rename/cleaning tests (tiny synthetic fixture, no real dataset needed). |
| `tests/test_engine_infer.py` | Make the `src_ip` assertion topology-aware; add a real-topology unit test. |
| `engine/README.md` | Document the raw download + `--raw` retrain flow. |

---

### Task 1: Raw UNSW-NB15 loader

**Files:**
- Create: `engine/raw_unsw.py`
- Modify: `engine/preprocess.py` (extend `DROP_COLS`)
- Test: `tests/test_raw_unsw.py`

**Interfaces:**
- Produces: `RAW_COLUMNS: list[str]` (49 names, header order), `IDENTITY_COLS: list[str]` (`["srcip", "sport", "dstip", "dsport"]`), `load_raw_unsw(paths: list[str]) -> pd.DataFrame` — later tasks (`engine/train.py`, `engine/infer.py`) call this and read `IDENTITY_COLS` off the returned frame.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_raw_unsw.py
"""Raw UNSW-NB15 (4-file, real-IP) loader tests — issue #real-topology.

The raw files carry real srcip/sport/dstip/dsport plus a handful of dirty cells
(blank ct_ftp_cmd, is_ftp_login > 1, null attack_cat) that the notebook-documented
cleaning fixes. These tests use a tiny in-memory fixture, not the real 550MB dataset.
"""
import pandas as pd
import pytest

from engine.raw_unsw import IDENTITY_COLS, RAW_COLUMNS, load_raw_unsw


def _write_raw_csv(tmp_path, rows):
    path = tmp_path / "UNSW-NB15_1.csv"
    pd.DataFrame(rows, columns=RAW_COLUMNS).to_csv(path, header=False, index=False)
    return str(path)


def _row(**overrides):
    base = {c: 0 for c in RAW_COLUMNS}
    base.update(proto="udp", state="CON", service="dns", srcip="59.166.0.0", sport=1390,
                dstip="149.171.126.6", dsport=53, attack_cat="", label=0,
                is_ftp_login=0, ct_ftp_cmd=" ")
    base.update(overrides)
    return base


def test_renames_columns_to_match_trained_feature_names(tmp_path):
    path = _write_raw_csv(tmp_path, [_row()])
    df = load_raw_unsw([path])
    # raw names that differ from the cleaned-partition names the model was trained on
    assert "sinpkt" in df.columns and "sintpkt" not in df.columns
    assert "dinpkt" in df.columns and "dintpkt" not in df.columns
    assert "smean" in df.columns and "smeansz" not in df.columns
    assert "dmean" in df.columns and "dmeansz" not in df.columns
    assert "response_body_len" in df.columns and "res_bdy_len" not in df.columns


def test_keeps_identity_columns_present(tmp_path):
    path = _write_raw_csv(tmp_path, [_row()])
    df = load_raw_unsw([path])
    for c in IDENTITY_COLS:
        assert c in df.columns
    assert df.loc[0, "srcip"] == "59.166.0.0"
    assert df.loc[0, "dstip"] == "149.171.126.6"
    assert int(df.loc[0, "dsport"]) == 53


def test_cleans_dirty_ftp_and_attack_cat_cells(tmp_path):
    path = _write_raw_csv(tmp_path, [
        _row(is_ftp_login=4, ct_ftp_cmd=" ", attack_cat=""),
        _row(is_ftp_login=2, ct_ftp_cmd="1", attack_cat=" Generic "),
    ])
    df = load_raw_unsw([path])
    assert df["is_ftp_login"].isin([0, 1]).all()          # >1 clamped to 1
    assert df.loc[0, "ct_ftp_cmd"] == 0                    # blank -> 0
    assert df.loc[1, "ct_ftp_cmd"] == 1
    assert df.loc[0, "attack_cat"] == "normal"              # null/blank -> normal
    assert df.loc[1, "attack_cat"] == "generic"             # stripped + lowercased


def test_drops_raw_only_timestamp_columns(tmp_path):
    path = _write_raw_csv(tmp_path, [_row(stime=1421927414, ltime=1421927414)])
    df = load_raw_unsw([path])
    assert "stime" not in df.columns
    assert "ltime" not in df.columns


def test_concatenates_multiple_files(tmp_path):
    p1 = _write_raw_csv(tmp_path, [_row()])
    p2_path = tmp_path / "UNSW-NB15_2.csv"
    pd.DataFrame([_row(dsport=80)], columns=RAW_COLUMNS).to_csv(p2_path, header=False, index=False)
    df = load_raw_unsw([p1, str(p2_path)])
    assert len(df) == 2


def test_preprocessor_excludes_identity_and_time_cols_from_numeric_features():
    from engine.preprocess import Preprocessor
    import numpy as np

    n = 20
    df = pd.DataFrame({
        "srcip": ["10.0.0.1"] * n, "sport": [1000] * n,
        "dstip": ["10.0.0.2"] * n, "dsport": [80] * n,
        "dur": np.random.rand(n), "sbytes": np.random.rand(n) * 100,
        "proto": ["tcp"] * n, "service": ["http"] * n, "state": ["FIN"] * n,
        "label": [0] * n,
    })
    pre = Preprocessor().fit(df)
    assert "srcip" not in pre.numeric_features
    assert "sport" not in pre.numeric_features
    assert "dstip" not in pre.numeric_features
    assert "dsport" not in pre.numeric_features
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv-engine/bin/pytest tests/test_raw_unsw.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'engine.raw_unsw'`

- [ ] **Step 3: Write minimal implementation**

```python
# engine/raw_unsw.py
"""Loader for the RAW UNSW-NB15 4-CSV format (real srcip/sport/dstip/dsport).

The cleaned partition (`UNSW_NB15_training-set.csv`/`testing-set.csv`, used by
engine/preprocess.py::load_unsw) strips network identity entirely — that's why
engine/infer.py had to synthesize src_ip/dst_ip/dst_port. The RAW 4-file dump
(`UNSW-NB15_1.csv`..`_4.csv`, same Kaggle dataset, header-less, 49 columns) keeps
real srcip/sport/dstip/dsport. This loader renames the raw columns onto the exact
names the trained model's `numeric_features` already use (sintpkt->sinpkt,
smeansz->smean, dmeansz->dmean, res_bdy_len->response_body_len) so
engine/train.py's existing pipeline (Preprocessor, split_normal, ...) works
unchanged against either source. Identity + raw-only timestamp columns are kept
in the returned frame (engine/infer.py reads them for real topology) but excluded
from model features via preprocess.DROP_COLS — never fed to the Isolation Forest.
"""
from __future__ import annotations

import pandas as pd

RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]
IDENTITY_COLS = ["srcip", "sport", "dstip", "dsport"]
_DROP_RAW_ONLY = ["stime", "ltime"]  # epoch timestamps — noise, not a model feature
RENAME_MAP = {
    "sintpkt": "sinpkt",
    "dintpkt": "dinpkt",
    "smeansz": "smean",
    "dmeansz": "dmean",
    "res_bdy_len": "response_body_len",
}


def load_raw_unsw(paths: list[str]) -> pd.DataFrame:
    """Read + concat the raw 4-file dump, renamed onto the trained model's feature names."""
    frames = [pd.read_csv(p, header=None, names=RAW_COLUMNS, low_memory=False) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    df = df.rename(columns=RENAME_MAP)
    df = df.drop(columns=_DROP_RAW_ONLY)

    # is_ftp_login ships with stray 2/4 values (should be binary) — per official cleaning,
    # clamp anything >1 down to 1.
    df["is_ftp_login"] = pd.to_numeric(df["is_ftp_login"], errors="coerce").fillna(0)
    df["is_ftp_login"] = df["is_ftp_login"].clip(upper=1).astype(int)

    # ct_ftp_cmd ships with blank-string cells instead of 0.
    df["ct_ftp_cmd"] = pd.to_numeric(
        df["ct_ftp_cmd"].astype(str).str.strip().replace("", "0"), errors="coerce"
    ).fillna(0).astype(int)

    # attack_cat is null for normal traffic; normalize casing/whitespace for the rest.
    df["attack_cat"] = (
        df["attack_cat"].astype(str).str.strip().replace({"": "normal", "nan": "normal"})
        .str.lower()
    )

    return df
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv-engine/bin/pytest tests/test_raw_unsw.py -v`
Expected: PASS (6 tests)

If `test_preprocessor_excludes_identity_and_time_cols_from_numeric_features` fails, apply the `preprocess.py` change from Step 5 first.

- [ ] **Step 5: Extend `preprocess.py`'s `DROP_COLS`**

In `engine/preprocess.py`, change:
```python
DROP_COLS = ["id", "attack_cat", "label"]
```
to:
```python
# srcip/sport/dstip/dsport/stime/ltime only appear when loading the RAW UNSW format
# (engine/raw_unsw.py) — harmless no-ops against the cleaned partition, which never has
# them. Never model inputs: see CLAUDE.md "src_ip/dst_ip are the attack-path graph edges,
# never model features" invariant.
DROP_COLS = ["id", "attack_cat", "label", "srcip", "sport", "dstip", "dsport", "stime", "ltime"]
```

- [ ] **Step 6: Run the full test to verify it passes**

Run: `.venv-engine/bin/pytest tests/test_raw_unsw.py -v`
Expected: PASS (6/6)

- [ ] **Step 7: Commit**

```bash
git add engine/raw_unsw.py engine/preprocess.py tests/test_raw_unsw.py
git commit -m "feat(engine): add raw UNSW-NB15 loader carrying real srcip/dstip/ports"
```

---

### Task 2: Validate raw dataset presence (`fetch_unsw.py`)

**Files:**
- Modify: `engine/fetch_unsw.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `validate_raw() -> bool`, callable standalone; `main()` reports both cleaned and raw status (raw is optional — absence isn't a hard failure, since the cleaned path must keep working with zero raw files present).

- [ ] **Step 1: Add raw validation, keeping the existing cleaned-partition check untouched**

In `engine/fetch_unsw.py`, add below the existing constants:
```python
RAW_FILES = ["UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"]
RAW_REQUIRED = {"srcip", "sport", "dstip", "dsport", "proto", "state", "sbytes", "dbytes"}
```

Add a new function (raw files are header-less, so read with `header=None` and the known column count):
```python
def validate_raw() -> bool:
    """Optional: real-network-identity mode (issue real-topology). Absence is NOT fatal —
    the cleaned-partition path above works with zero raw files present."""
    from engine.raw_unsw import RAW_COLUMNS

    present = [DATA / n for n in RAW_FILES if (DATA / n).exists()]
    if not present:
        print(f"raw UNSW-NB15 files not found under {DATA} (optional — only needed for "
              f"engine.train --raw). Get them from the same Kaggle dataset:\n"
              f"  https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15\n"
              f"  -> {DATA}/UNSW-NB15_1.csv .. _4.csv")
        return False
    ok = True
    for path in present:
        head = pd.read_csv(path, header=None, names=RAW_COLUMNS, nrows=200)
        missing = RAW_REQUIRED - set(head.columns)
        rows = sum(1 for _ in open(path, encoding="utf-8-sig")) - 0  # no header row to subtract
        status = "OK" if not missing else "BAD SHAPE"
        print(f"{status}: {path.name} — {len(head.columns)} cols, {rows:,} rows"
              + (f", missing {missing}" if missing else ""))
        if missing:
            ok = False
    if len(present) < len(RAW_FILES):
        print(f"({len(present)}/{len(RAW_FILES)} raw files present — engine.train --raw needs all 4)")
    return ok
```

Update `main()`:
```python
def main() -> None:
    print(f"UNSW-NB15 expected at: {DATA}")
    cleaned_ok = validate()
    print()
    validate_raw()
    if not cleaned_ok:
        print(
            "\nDataset not ready. Download the two cleaned partition CSVs:\n"
            "  https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15\n"
            f"  -> {DATA}/UNSW_NB15_training-set.csv\n"
            f"  -> {DATA}/UNSW_NB15_testing-set.csv"
        )
        sys.exit(1)
    print("\ncleaned-partition dataset OK — ready to train (python -m engine.train)")
```

- [ ] **Step 2: Manually verify (no unit test — this is I/O against real files the repo doesn't ship)**

Run: `.venv-engine/bin/python -m engine.fetch_unsw`
Expected: existing cleaned-partition OK output unchanged, plus a new "raw UNSW-NB15 files not found... (optional...)" line, exit code 0 (since cleaned files are present).

- [ ] **Step 3: Commit**

```bash
git add engine/fetch_unsw.py
git commit -m "feat(engine): validate optional raw UNSW-NB15 files for real-topology training"
```

---

### Task 3: `engine/train.py` raw mode

**Files:**
- Modify: `engine/train.py`

**Interfaces:**
- Consumes: `engine.raw_unsw.load_raw_unsw(paths) -> pd.DataFrame` (Task 1), `IDENTITY_COLS` (Task 1).
- Produces: `model_meta.json["topology_source"]` (`"real"` or `"synthetic"`) — Task 4's `engine/infer.py` reads this key. When raw mode runs, also writes `data/unsw/unsw_raw_eval.csv` (header included, identity columns present) — this is what `engine/replay.py --source` points at afterwards.

- [ ] **Step 1: Add the `--raw` argument and branch the data-loading block**

In `engine/train.py`, add the import:
```python
from engine.raw_unsw import IDENTITY_COLS, load_raw_unsw
```

Change the arg parser:
```python
ap.add_argument("--train", default=str(DATA / "UNSW_NB15_training-set.csv"))
ap.add_argument("--test", default=str(DATA / "UNSW_NB15_testing-set.csv"))
ap.add_argument("--raw", nargs="+", default=None,
                help="path(s) to the raw UNSW-NB15_1..4.csv files — real srcip/dstip/ports; "
                     "overrides --train/--test")
args = ap.parse_args()
```

Replace the data-loading block:
```python
if args.raw:
    all_df = load_raw_unsw(args.raw)
    topology_source = "real"
else:
    train_df = load_unsw(args.train)
    test_df = load_unsw(args.test)
    all_df = pd.concat([train_df, test_df], ignore_index=True)
    topology_source = "synthetic"
```
(remove the old unconditional `train_df`/`test_df`/`all_df` lines it replaces)

- [ ] **Step 2: Persist the raw eval slice for replay, after `eval_df` is built**

Right after the existing line
```python
eval_df = pd.concat([eval_normal, attacks], ignore_index=True)
```
add:
```python
if args.raw:
    eval_path = DATA / "unsw_raw_eval.csv"
    eval_df.to_csv(eval_path, index=False)
    print(f"wrote real-identity eval slice -> {eval_path} ({len(eval_df)} rows, "
          f"engine.replay --source {eval_path} streams these)")
```

- [ ] **Step 3: Tag `topology_source` in the persisted meta**

In the `meta = {...}` dict inside `main()`, add the key:
```python
meta = {
    "n_estimators": N_ESTIMATORS,
    "random_state": RANDOM_STATE,
    "score_orientation": "higher_is_more_anomalous (=-score_samples)",
    "threshold": chosen["threshold"],
    "threshold_percentile": chosen["percentile"],
    "roc_auc": roc_auc,
    "numeric_features": pre.numeric_features,
    "proto_top": pre.proto_top,
    "n_transformed_features": int(X_train.shape[1]),
    "topology_source": topology_source,
    "calibration": {
        ...
    },
}
```

- [ ] **Step 4: Update the honest-limitations sentence in `write_results()`**

Change `write_results`'s signature and call site to accept `topology_source`, and swap the fixed sentence:
```python
def write_results(roc_auc, chosen, high_recall, candidates, n_fit_normal, n_eval, n_feats,
                   topology_source) -> None:
    ...
    topology_note = (
        "- **Real network identity:** src/dst IP and port come from the raw UNSW-NB15 "
        "srcip/sport/dstip/dsport columns — never model inputs (see engine/preprocess.py "
        "DROP_COLS), only carried through for the attack-path graph."
        if topology_source == "real" else
        "- The cleaned UNSW partition carries no src/dst IP or port; those are synthesized "
        "at replay time for the demo (#15) and are never model inputs."
    )
    md = f"""...
{topology_note}
"""
```
Update the call site at the end of `main()`:
```python
write_results(roc_auc, chosen, high_recall, candidates, len(fit_normal), len(eval_df),
              X_train.shape[1], topology_source)
```

- [ ] **Step 5: Verify manually (no synthetic unit test — this needs the real dataset; covered by Task 6/7's end-to-end run)**

Run (cleaned path, must still work exactly as before):
```
.venv-engine/bin/python -m engine.train
```
Expected: same output as before this task (no `--raw`, `topology_source` in meta is `"synthetic"`, no `unsw_raw_eval.csv` written).

- [ ] **Step 6: Commit**

```bash
git add engine/train.py
git commit -m "feat(engine): --raw training mode pools real-identity UNSW-NB15 files"
```

---

### Task 4: `engine/infer.py` real-topology branch

**Files:**
- Modify: `engine/infer.py`

**Interfaces:**
- Consumes: `meta["topology_source"]` (Task 3), row's `srcip/dstip/dsport` when present (Task 1's loader keeps these columns).
- Produces: `Scorer.topology_source: str` field, read by `tests/test_engine_infer.py` (Task 6).

- [ ] **Step 1: Add the field and branch `_topology()`**

Change the dataclass:
```python
@dataclass
class Scorer:
    model: object
    pre: object
    threshold: float
    lo: float
    mid: float
    hi: float
    topology_source: str = "synthetic"
```

Replace `_topology()`:
```python
    # ---- topology: real (dataset-carried) or synthetic (deterministic per flow) ----------

    def _topology(self, row: Mapping, i: int, is_anomaly: bool) -> tuple[str, str, int]:
        if self.topology_source == "real":
            return self._real_topology(row)
        return self._synthetic_topology(row, i, is_anomaly)

    def _real_topology(self, row: Mapping) -> tuple[str, str, int]:
        """Real srcip/dstip/dsport carried by the raw UNSW-NB15 loader (engine/raw_unsw.py).
        Never model inputs — see preprocess.DROP_COLS."""
        src = str(row.get("srcip"))
        dst = str(row.get("dstip"))
        port_raw = pd.to_numeric(row.get("dsport"), errors="coerce")
        port = int(port_raw) if pd.notna(port_raw) else 0
        return src, dst, port

    def _synthetic_topology(self, row: Mapping, i: int, is_anomaly: bool) -> tuple[str, str, int]:
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
```

- [ ] **Step 2: Update `raw_features["dst_port"]` comment (honest for both branches)**

Change:
```python
            raw_features["dst_port"] = port  # synthetic demo topology — NOT a captured value
```
to:
```python
            # real srcip/dstip/dsport when topology_source == "real" (engine/raw_unsw.py);
            # otherwise synthetic demo dressing — see Scorer.topology_source.
            raw_features["dst_port"] = port
```

- [ ] **Step 3: Wire `topology_source` through `load_scorer()`**

```python
def load_scorer() -> Scorer:
    global _SCORER
    if _SCORER is None:
        meta = json.loads((MODEL_DIR / "model_meta.json").read_text())
        cal = meta["calibration"]
        _SCORER = Scorer(
            model=joblib.load(MODEL_DIR / "isoforest.joblib"),
            pre=joblib.load(MODEL_DIR / "preprocessor.joblib"),
            threshold=float(meta["threshold"]),
            lo=cal["lo"], mid=cal["mid"], hi=cal["hi"],
            topology_source=meta.get("topology_source", "synthetic"),
        )
    return _SCORER
```

- [ ] **Step 4: Update the module docstring's point 3**

```python
  3. Network topology — src_ip/dst_ip/dst_port. When the model was trained on the RAW
     UNSW-NB15 files (engine/raw_unsw.py, `topology_source: "real"` in model_meta.json), these
     are the flow's actual captured srcip/dstip/dsport — never model inputs (see
     preprocess.DROP_COLS), just carried through for the attack-path graph. When trained on
     the cleaned partition (no IP/port ground truth), we deterministically synthesize a small
     host topology instead — honest demo dressing, flagged in model_meta.json.
```

- [ ] **Step 5: Write the unit test (same `Scorer(model=None, pre=None, ...)` pattern as the existing calibration test)**

Add to `tests/test_engine_infer.py`, anywhere in the file — `pytestmark = pytest.mark.skipif(not HAS_MODEL, ...)` applies module-wide in pytest regardless of definition order, so these (like the existing `test_calibration_is_monotonic_and_bounded`) still skip when no model is trained on disk. That matches this file's stated convention ("skips cleanly if the model hasn't been trained") — no restructuring needed, just add the tests:
```python
def test_real_topology_reads_dataset_ips_when_topology_source_is_real():
    from engine.infer import Scorer
    s = Scorer(model=None, pre=None, threshold=0.45, lo=0.35, mid=0.45, hi=0.63,
               topology_source="real")
    row = {"srcip": "59.166.0.0", "dstip": "149.171.126.6", "dsport": 53}
    src, dst, port = s._topology(row, i=0, is_anomaly=False)
    assert (src, dst, port) == ("59.166.0.0", "149.171.126.6", 53)


def test_real_topology_falls_back_to_port_zero_when_dsport_is_missing():
    from engine.infer import Scorer
    s = Scorer(model=None, pre=None, threshold=0.45, lo=0.35, mid=0.45, hi=0.63,
               topology_source="real")
    row = {"srcip": "59.166.0.0", "dstip": "149.171.126.6", "dsport": "-"}
    _, _, port = s._topology(row, i=0, is_anomaly=False)
    assert port == 0


def test_synthetic_topology_is_the_default_when_topology_source_unset():
    from engine.infer import Scorer
    s = Scorer(model=None, pre=None, threshold=0.45, lo=0.35, mid=0.45, hi=0.63)
    assert s.topology_source == "synthetic"
    src, dst, port = s._topology({"proto": "tcp", "sbytes": 100, "dur": 0.1}, i=0, is_anomaly=False)
    assert src.startswith("10.")
```

- [ ] **Step 6: Run the new tests**

Run: `.venv-engine/bin/pytest tests/test_engine_infer.py -v -k "topology"`
Expected: 3 passed if a model is currently trained on disk (`engine/model/isoforest.joblib` exists), else 3 skipped — same `HAS_MODEL` gate as every other test in this file.

- [ ] **Step 7: Commit**

```bash
git add engine/infer.py tests/test_engine_infer.py
git commit -m "feat(engine): emit real src_ip/dst_ip/dst_port when topology_source is real"
```

---

### Task 5: Fix the topology-coupled assertion in the existing contract test

**Files:**
- Modify: `tests/test_engine_infer.py`

**Interfaces:**
- Consumes: `model_meta.json["topology_source"]` (Task 3/4) — read directly in the test.

**Why this task exists:** `test_score_emits_valid_contract1_event` currently hard-asserts `ev.src_ip.startswith("10.")`, which is only true for the synthetic branch. Whichever model happens to be trained on disk when `make test-engine` runs must not fail this test.

- [ ] **Step 1: Make the assertion topology-aware**

Change:
```python
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
```
to:
```python
def test_score_emits_valid_contract1_event():
    from engine.infer import load_scorer
    from orchestrator.schemas import AnomalyEvent

    scorer = load_scorer()
    ev = scorer.score(_synthetic_flow(), event_id="evt_test_0001")
    assert isinstance(ev, AnomalyEvent)
    assert ev.event_id == "evt_test_0001"
    assert 0.0 <= ev.anomaly_score <= 1.0
    assert isinstance(ev.is_anomaly, bool)
    assert ev.timestamp.endswith("Z")
    if scorer.topology_source == "synthetic":
        assert ev.src_ip.startswith("10.")        # internal CNI host, synthetic branch only
    else:
        assert ev.src_ip                            # real branch: whatever the dataset carried
    assert "dst_port" in ev.raw_features
```

Note: `_synthetic_flow()` builds a flow from `meta["numeric_features"]` only — it has no `srcip`/`dstip` keys, so under a real-topology model this test's `ev.src_ip`/`ev.dst_ip` will be the string `"None"` (from `str(row.get("srcip"))`). That's an accepted gap for this synthetic single-flow helper (real callers always come from `engine.raw_unsw.load_raw_unsw()` rows, which always carry identity columns) — the assertion above only checks truthiness, not shape, deliberately.

- [ ] **Step 2: Run the full engine test file**

Run: `.venv-engine/bin/pytest tests/test_engine_infer.py -v`
Expected: all pass, regardless of which model (`topology_source: real` or `synthetic`) is currently trained on disk.

- [ ] **Step 3: Commit**

```bash
git add tests/test_engine_infer.py
git commit -m "fix(tests): make src_ip assertion topology-aware, not synthetic-only"
```

---

### Task 6: Documentation (`engine/README.md`)

**Files:**
- Modify: `engine/README.md`

- [ ] **Step 1: Read the current file, then add a section documenting the raw/real-topology flow**

Read `engine/README.md` first (not reproduced here — append using its existing section style), adding a section along these lines:

```markdown
## Real network identity (optional)

By default the model trains on the CLEANED UNSW-NB15 partition, which carries no src/dst
IP or port — `engine/infer.py` synthesizes a small deterministic host topology for the demo
(flagged `"topology_source": "synthetic"` in `model_meta.json`).

To use REAL captured IPs/ports/attack-path instead:

1. Download the raw 4-file dump from the same Kaggle dataset:
   https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
   -> `data/unsw/UNSW-NB15_1.csv` .. `_4.csv` (gitignored, ~550MB total)
2. Validate: `.venv-engine/bin/python -m engine.fetch_unsw`
3. Retrain: `.venv-engine/bin/python -m engine.train --raw data/unsw/UNSW-NB15_1.csv data/unsw/UNSW-NB15_2.csv data/unsw/UNSW-NB15_3.csv data/unsw/UNSW-NB15_4.csv`
   (overwrites `engine/model/*` in place — back up the directory first if you want to keep
   the synthetic-topology model, e.g. `cp -r engine/model engine/model.synthetic.bak`)
4. Replay real-identity events: `.venv-engine/bin/python -m engine.replay --source data/unsw/unsw_raw_eval.csv --only-anomalies --delay 2`
```

- [ ] **Step 2: Commit**

```bash
git add engine/README.md
git commit -m "docs(engine): document the real-network-identity (--raw) training flow"
```

---

### Task 7: End-to-end retrain + validate (manual, not a subagent task)

This task needs the real ~550MB dataset and real wall-clock training time — it is run directly (by whoever executes the plan), not dispatched to a subagent.

- [ ] **Step 1:** Download the 4 raw CSVs from the Kaggle dataset into `data/unsw/` (user action — needs Kaggle credentials).
- [ ] **Step 2:** `.venv-engine/bin/python -m engine.fetch_unsw` — confirm raw files show `OK`.
- [ ] **Step 3:** Back up the current model: `cp -r engine/model engine/model.synthetic.bak`
- [ ] **Step 4:** `.venv-engine/bin/python -m engine.train --raw data/unsw/UNSW-NB15_1.csv data/unsw/UNSW-NB15_2.csv data/unsw/UNSW-NB15_3.csv data/unsw/UNSW-NB15_4.csv`
- [ ] **Step 5:** Read `engine/RESULTS.md` — compare ROC-AUC/recall/FPR against the synthetic-partition baseline (0.867 ROC-AUC, recall 0.75@10%FPR per current memory notes) and report honestly, better or worse.
- [ ] **Step 6:** `.venv-engine/bin/python -m pytest tests/test_engine_infer.py tests/test_raw_unsw.py -v` — all green.
- [ ] **Step 7:** Start backend (`make backend`, `ENRICH_MODE=live` if attribution quota allows) + `.venv-engine/bin/python -m engine.replay --source data/unsw/unsw_raw_eval.csv --only-anomalies --delay 2`.
- [ ] **Step 8:** Playwright screenshot of the Operations + Attack Graph pages, confirm real-looking IPs (e.g. `59.166.x.x` / `149.171.126.x`, not `10.0.0.x`/`203.0.113.x`) and real ports flow into the graph edges.
- [ ] **Step 9:** Report actual ROC-AUC/recall/FPR numbers and screenshots to the user — no claim without the number in front of both of us.

---

## Self-Review Notes

- **Spec coverage:** loader (Task 1) → dataset validation (Task 2) → training (Task 3) → inference (Task 4) → test fix (Task 5) → docs (Task 6) → real run + honest numbers (Task 7). Matches every element of the "Level 1" answer given earlier in this conversation.
- **Backward compatibility:** every default arg/behavior for the cleaned-partition path is unchanged; `--raw` is strictly additive. Verified by re-reading `engine/train.py`'s existing call sites — no other file calls `write_results` or constructs `Scorer` with positional args that would break from the added parameter (both are keyword-compatible additions with defaults).
- **No placeholder steps** — every step has literal code or an exact command with expected output.
