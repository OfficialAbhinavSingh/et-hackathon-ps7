"""UNSW-NB15 preprocessing for the unsupervised anomaly engine (issue #14).

Loads the cleaned UNSW-NB15 training/testing partitions, drops non-feature columns
(`id`, `attack_cat`, `label` — labels are for EVAL ONLY, never fed to the model), and
turns a raw flow row into a numeric feature matrix the Isolation Forest can fit.

Encoding decisions (see the ticket discussion):
  - proto (133 values) -> keep top-10 most frequent, bucket the rest as "other", one-hot.
    Prevents feature dilution swamping the forest with 130 near-empty columns.
  - service (~13) + state (~9) -> one-hot fully (low cardinality, signal kept intact).
  - all numeric features -> StandardScaler.

The fitted `Preprocessor` is persisted whole (joblib) so inference (issue #15) applies the
identical transform. It also exposes the scaler's per-feature mean/scale over the NAMED
numeric features, which #15 uses to compute z-score deviations for the contract-legal,
human-readable `top_features` (never one-hot column names).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Columns that are never model inputs. `label`/`attack_cat` exist only so we can SCORE
# the model afterwards — they are never part of X.
DROP_COLS = ["id", "attack_cat", "label"]
CATEGORICAL = ["proto", "service", "state"]
PROTO_TOP_N = 10
OTHER = "other"


def load_unsw(csv_path: str) -> pd.DataFrame:
    """Read a UNSW-NB15 partition CSV. `utf-8-sig` strips the BOM on the header."""
    df = pd.read_csv(csv_path, encoding="utf-8-sig")
    df.columns = [c.strip() for c in df.columns]
    return df


@dataclass
class Preprocessor:
    """Fit on the training partition, then transform any flow the same way."""

    numeric_features: list[str] = field(default_factory=list)
    proto_top: list[str] = field(default_factory=list)
    scaler: StandardScaler | None = None
    encoder: OneHotEncoder | None = None

    # ---- fit / transform ---------------------------------------------------

    def _bucket_proto(self, s: pd.Series) -> pd.Series:
        return s.where(s.isin(self.proto_top), OTHER)

    @staticmethod
    def _numeric_frame(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
        # UNSW ships a few dirty non-numeric cells (e.g. ct_ftp_cmd blanks, is_ftp_login).
        # Coerce hard so the whole matrix is float.
        num = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(float)
        # UNSW flow features (bytes, load, rate, jitter…) are heavy-tailed across many orders
        # of magnitude. log1p compresses that skew so the Isolation Forest can separate
        # attacks — without it ROC-AUC collapses. Clip negatives first (all these are ≥0).
        return np.log1p(num.clip(lower=0.0))

    def fit(self, df: pd.DataFrame) -> "Preprocessor":
        self.numeric_features = [c for c in df.columns if c not in DROP_COLS + CATEGORICAL]

        # top-10 protocols by frequency in the training data; everything else -> "other"
        self.proto_top = df["proto"].value_counts().head(PROTO_TOP_N).index.tolist()

        cat = pd.DataFrame(
            {
                "proto": self._bucket_proto(df["proto"]),
                "service": df["service"],
                "state": df["state"],
            }
        )
        self.encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        self.encoder.fit(cat)

        self.scaler = StandardScaler()
        self.scaler.fit(self._numeric_frame(df, self.numeric_features))
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        assert self.scaler is not None and self.encoder is not None, "call fit() first"
        cat = pd.DataFrame(
            {
                "proto": self._bucket_proto(df["proto"]),
                "service": df["service"],
                "state": df["state"],
            }
        )
        num_scaled = self.scaler.transform(self._numeric_frame(df, self.numeric_features))
        cat_oh = self.encoder.transform(cat)
        return np.hstack([num_scaled, cat_oh])

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    # ---- helpers for inference (#15) --------------------------------------

    def numeric_zscores(self, df: pd.DataFrame) -> np.ndarray:
        """Per-row z-scores over the NAMED numeric features: (x - mean) / scale.

        #15 ranks these by magnitude to produce human-readable `top_features`
        (e.g. `sbytes`, `dur`) — never one-hot column names, per the Contract-1 rule.
        """
        assert self.scaler is not None
        return self.scaler.transform(self._numeric_frame(df, self.numeric_features))

    @property
    def feature_names(self) -> list[str]:
        """Full transformed column order: scaled numerics, then one-hot categoricals."""
        assert self.encoder is not None
        return self.numeric_features + list(self.encoder.get_feature_names_out(CATEGORICAL))


def split_normal(df: pd.DataFrame) -> pd.DataFrame:
    """Rows the model is allowed to learn from: label == 0 (normal traffic) only."""
    return df[df["label"] == 0].copy()
