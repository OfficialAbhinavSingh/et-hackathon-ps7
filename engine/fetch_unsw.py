"""UNSW-NB15 dataset provenance + validation (issue #14).

NOT a live downloader — the official host is Google Drive behind redirects/quota and Kaggle
needs credentials, both fragile on demo day. Instead this documents the source and validates
that the two cleaned partition CSVs are present and correctly shaped before training.

Manual download (once):
    Kaggle:   https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
              -> UNSW_NB15_training-set.csv  +  UNSW_NB15_testing-set.csv
    Official: https://research.unsw.edu.au/projects/unsw-nb15-dataset
Place both under data/unsw/ (gitignored — too big to commit).

Run:  .venv/bin/python -m engine.fetch_unsw
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data" / "unsw"
FILES = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
# the cleaned partition schema: 45 columns incl label + attack_cat, and no network IDs
EXPECTED_COLS = 45
REQUIRED = {"proto", "service", "state", "label", "attack_cat", "sbytes", "dbytes", "sttl", "dttl"}


def validate() -> bool:
    ok = True
    for name in FILES:
        path = DATA / name
        if not path.exists():
            print(f"MISSING: {path}")
            ok = False
            continue
        head = pd.read_csv(path, nrows=200, encoding="utf-8-sig")
        head.columns = [c.strip() for c in head.columns]
        n = len(head.columns)
        missing = REQUIRED - set(head.columns)
        rows = sum(1 for _ in open(path, encoding="utf-8-sig")) - 1
        status = "OK" if n == EXPECTED_COLS and not missing else "BAD SHAPE"
        print(f"{status}: {name} — {n} cols, {rows:,} rows"
              + (f", missing {missing}" if missing else ""))
        if n != EXPECTED_COLS or missing:
            ok = False
    return ok


def main() -> None:
    print(f"UNSW-NB15 expected at: {DATA}")
    if validate():
        print("dataset OK — ready to train (python -m engine.train)")
    else:
        print(
            "\nDataset not ready. Download the two cleaned partition CSVs:\n"
            "  https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15\n"
            f"  -> {DATA}/UNSW_NB15_training-set.csv\n"
            f"  -> {DATA}/UNSW_NB15_testing-set.csv"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
