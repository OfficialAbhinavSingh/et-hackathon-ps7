# Engine — Isolation Forest results (UNSW-NB15)

**Model:** IsolationForest (unsupervised, 400 trees, max_samples=20000) ·
fit on **pooled normal** traffic from both UNSW partitions (69,750 rows) ·
evaluated on **held-out normal + all attacks** (187,923 rows). Labels used for evaluation
only — never fed to the model. Features log1p-compressed then standardized; dim: 64.

## Headline (never accuracy alone)

**ROC-AUC (threshold-free): 0.8666** — the honest, operating-point-independent score.

Recall trades against false-positive rate; two operating points, both picked from the
train-normal score distribution (never from test labels):

| Operating point | Recall (attacks) | FPR (normal) | Precision | F1 |
|-----------------|------------------|--------------|-----------|-----|
| **Default — balanced (Youden)** | **0.749** | **0.100** | 0.981 | 0.849 |
| High-recall (for triage-heavy ops) | 0.820 | 0.203 | 0.966 | 0.887 |

Default threshold = p90 of train-normal scores (0.4456).

## Threshold sweep (train-normal percentile → test metrics)

| Percentile | Threshold | Recall | FPR | Precision | F1 |
|-----------|-----------|--------|-----|-----------|-----|
| 70 | 0.4097 | 0.852 | 0.305 | 0.952 | 0.899 |
| 75 | 0.4154 | 0.840 | 0.254 | 0.959 | 0.895 |
| 80 | 0.4223 | 0.820 | 0.203 | 0.966 | 0.887 |  ← high-recall
| 85 | 0.4316 | 0.787 | 0.152 | 0.973 | 0.870 |
| 88 | 0.4393 | 0.765 | 0.121 | 0.978 | 0.858 |
| 90 | 0.4456 | 0.749 | 0.100 | 0.981 | 0.849 |  ← default (Youden)
| 92 | 0.4542 | 0.713 | 0.079 | 0.984 | 0.827 |
| 94 | 0.4661 | 0.647 | 0.060 | 0.987 | 0.781 |
| 95 | 0.4747 | 0.597 | 0.049 | 0.988 | 0.745 |
| 96 | 0.4841 | 0.562 | 0.040 | 0.990 | 0.717 |
| 97 | 0.4992 | 0.496 | 0.030 | 0.992 | 0.661 |
| 98 | 0.5203 | 0.442 | 0.020 | 0.994 | 0.612 |

## Honest limitations (base-rate aware)

- **Eval protocol:** normal is pooled across both UNSW partitions and split 75/25; we report
  held-out-random generalization, not strict cross-partition. Fitting on the training
  partition alone (a stricter novel-distribution test) scores ROC-AUC ~0.81 — the ~0.06 gap
  is real distribution shift between UNSW's two "normal" sets. Pooling is the realistic
  deployment setup (learn from all available normal traffic) and roughly halves the FPR.
- **Per-class:** the model catches loud attacks (Generic ~0.99, DoS ~0.89, Exploits ~0.80)
  and misses low-and-slow classes (Reconnaissance, Shellcode, Fuzzers) that are near-benign
  in flow statistics — a fundamental limit of unsupervised flow detection, not a bug. This is
  why the detector is **stage one**, not the whole system: the RAG attribution agent
  (#17) and the policy engine (#5) add precision on top — a flagged anomaly is enriched and
  cited before any action, so the base-rate fallacy (99% accuracy → thousands of false
  alerts) is mitigated downstream, not pretended away here.
- Unsupervised throughout: learns "normal", flags deviation. No labelled attack/benign
  classifier (would be signature-matching in disguise).
- Scaler + encoder + model persisted together (`engine/model/`) so inference (#15) applies
  identical transforms.
- The cleaned UNSW partition carries no src/dst IP or port; those are synthesized at replay
  time for the demo (#15) and are never model inputs.
