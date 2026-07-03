# Dev A — Anomaly Detection Engine (the ML brain)

**Owner:** _______  ·  **Foundation window:** Jul 4 – Jul 8

You own the part that turns raw network telemetry into an **anomaly score**. This is the
"detects behaviour, not signatures" claim in the problem statement — the single most
important technical differentiator we get judged on. If this piece is credible, the whole
project is credible.

---

## 0. Your one-sentence mission

> Train an **unsupervised** model on a public intrusion-detection dataset so that, given a
> network flow, it outputs a 0–1 anomaly score, a boolean `is_anomaly`, and the top
> features that drove the score — emitted as the *anomaly event* JSON contract.

Why unsupervised: the problem statement explicitly says detect anomalies **"without
relying on known malware signatures."** Supervised classifiers that learn "attack vs
benign" from labels are basically signature matching in disguise. Unsupervised anomaly
detection (learn "normal", flag deviations) is the honest answer to the brief and the one
judges will respect.

---

## 1. Study first (≈1.5 days — do NOT skip)

You cannot bluff ML in front of security-savvy judges. Learn just these:

### 1a. The problem framing
- **Signature-based vs anomaly-based detection** — understand *why* APTs evade signatures (low-and-slow, novel payloads). Read: any short "IDS anomaly detection" explainer + the intro of the UNSW-NB15 paper.
- **Point vs contextual vs collective anomalies** — know which you're doing (you're doing point/contextual on flow records).
- **Base-rate problem / why false-positive rate matters** — in a SOC, 99% accuracy is useless if 1% false positives = thousands of alerts/day. This is a talking point for the pitch. Read: "base rate fallacy in intrusion detection" (Axelsson's classic idea, summary is enough).

### 1b. The algorithms (learn the intuition, not the math proofs)
- **Isolation Forest** — isolates anomalies by random splits; anomalies get isolated in fewer splits. Fast, no scaling needed, great default. *Start here.*
- **Autoencoder (neural)** — train to reconstruct normal traffic; high reconstruction error = anomaly. More impressive to demo, more work. *Stretch goal.*
- **One-Class SVM / Local Outlier Factor** — know they exist, when they'd beat IsoForest. Optional.
- Resource: scikit-learn "Novelty and Outlier Detection" user-guide page (read it fully — it's short and is literally your API).

### 1c. The data + features
- **Network flow / NetFlow concepts** — what a "flow" is (5-tuple: src IP, dst IP, src port, dst port, protocol), flow duration, bytes/packets in/out. You must be able to explain these features in the demo.
- **Why feature scaling / encoding matters** — categorical (protocol, service) vs numeric features; StandardScaler for numeric.
- Skim the **UNSW-NB15 feature description** (49 features) or **CICIDS2017** column list so you know what each column means.

### 1d. Evaluation
- **Precision / Recall / F1 / ROC-AUC** and why in anomaly detection **recall on attacks + low false-positive rate** are the two numbers that matter (ties to "false negative rate — the metric that saves lives" in adjacent PS framing, and to our impact model).
- **Confusion matrix** reading.

**Study resources (free):**
- scikit-learn docs: Outlier/Novelty detection, IsolationForest.
- UNSW-NB15 dataset page (Kaggle) + the original paper's Section on features.
- CICIDS2017 (Canadian Institute for Cybersecurity) dataset description page.
- "Base rate fallacy" intrusion-detection summary (any blog/paper abstract).

---

## 2. Dataset decision (do this Jul 4)

Pick **ONE** primary dataset. Recommendation: **UNSW-NB15** (cleaner, modern, well-documented, ~2.5M records with a labelled subset for evaluation). CICIDS2017 is a fine alternative (more realistic attack scenarios, larger, messier).

- Download from Kaggle (both are hosted there; licence is fine for a hackathon).
- Keep a **labelled** slice aside — you train unsupervised on *normal* traffic, but you use the labels **only to evaluate** (compute recall/FPR). Never feed labels into the model.

Fetch script goes in `data/fetch_unsw.py` (or manual download + a README note). Data itself is **gitignored** (too big).

---

## 3. Build tasks (Jul 5 – Jul 8)

### Task A1 — Load + preprocess (`engine/preprocess.py`)
- Load dataset, select numeric + key categorical features.
- Encode categoricals (one-hot or ordinal), scale numerics (StandardScaler).
- Split: "normal-only" training set (for unsupervised fit) + held-out mixed set (for eval).
- Save the fitted scaler/encoder (`joblib`) so inference uses identical transforms.

### Task A2 — Train baseline (`engine/train.py`)
- Fit **IsolationForest** on normal-only data. Tune `contamination` and `n_estimators`.
- Save model to `engine/model/isoforest.joblib`.
- Print eval on held-out set: precision, recall, F1, ROC-AUC, false-positive rate.
- **Target for demo credibility:** recall on attacks ≥ ~0.8 with FPR kept low. Don't chase perfection — chase a defensible number you can explain.

### Task A3 — Inference + feature attribution (`engine/infer.py`)
- Function `score(flow_dict) -> anomaly_event_json`.
- Compute `anomaly_score` (normalise the model's raw score to 0–1).
- `top_features`: which features pushed this record toward "anomaly". For IsolationForest use a simple, honest approach — per-feature deviation from the training mean (z-score), or SHAP if you have time. This list feeds Dev B's LLM so it can explain *why*, so it matters.
- Emit exactly the **anomaly event contract** from the README.

### Task A4 — Replay stream (`engine/replay.py`)
- Read held-out rows and emit anomaly events one-by-one (with a small delay) to simulate a **live feed** for the demo. This is what makes the dashboard "tick" live. Dev C consumes this.

### Stretch (only if ahead) — Autoencoder
- Simple Keras/PyTorch autoencoder trained on normal traffic; reconstruction-error threshold = anomaly. Demo two detectors side by side → stronger "Technical Excellence".

---

## 4. Your interface to the rest of the team

- **You produce:** the *anomaly event* JSON (README §4). Freeze this schema Jul 4.
- **You consume:** nothing from B or C during foundation — you can build fully standalone.
- **Dev C** calls your `infer.score()` (or reads your `replay.py` stream).
- **Dev B** uses your `top_features` + `raw_features` to reason about the technique.

Give Dev C a stub early: a JSON file of ~20 sample anomaly events so they can build without waiting for your model.

---

## 5. Definition of done (Jul 8 EOD)

- [ ] UNSW-NB15 (or CICIDS2017) loaded, preprocessed, scaler saved.
- [ ] IsolationForest trained; eval numbers printed and written to `engine/RESULTS.md` (recall, FPR, ROC-AUC).
- [ ] `infer.score()` returns valid anomaly-event JSON for any input row.
- [ ] `replay.py` emits a live-ish stream of events.
- [ ] 20-event sample JSON handed to Dev C.
- [ ] You can explain, out loud, IsolationForest and your eval numbers (dry-run with the team).

## 6. Pitfalls
- **Don't** train on labelled attack/benign as a classifier — kills the "no signatures" story.
- **Don't** report only accuracy — always recall + FPR.
- **Don't** over-engineer the model before the pipeline works end-to-end. Baseline first.
- **Do** keep `raw_features` in the event — Dev B needs real numbers to explain, not just a score.
