# Milestone 1: Reproducible ML Training & Evaluation

## Dataset audit and EDA

The audit used the supplied TON_IoT network flow CSV; the raw file was read only and was not changed.

- Shape: **211,043 rows × 44 columns**.
- Binary target counts: **normal (0): 50,000; attack (1): 161,043**.
- Attack subtypes: backdoor 20,000, ddos 20,000, dos 20,000, injection 20,000, mitm 1,043, normal 50,000, password 20,000, ransomware 20,000, scanning 20,000, xss 20,000.
- Exact repeated raw rows: **20,569**.
- Repeated model-feature rows after leakage exclusions: **105,862**; **8** feature signatures have both labels. These duplicates are kept, but grouped into a single split to prevent identical model inputs crossing partitions.
- `src_ip` has **51** distinct values; its most frequent address has **61,633** records and an attack rate of **99.92%**. This and the 26,628 distinct source ports observed make these fields strong dataset-specific shortcuts rather than robust flow behavior.
- Most-missing fields (empty or `-` placeholders): `ssl_subject` (211,032), `ssl_issuer` (211,032), `http_orig_mime_types` (211,027), `weird_addl` (210,886), `http_resp_mime_types` (210,839), `http_uri` (210,756), `http_user_agent` (210,756), `http_method` (210,756).

## Feature and split design

The target is `label` (0 = normal, 1 = attack). `type` is a subtype directly derived from the binary target and is never passed to preprocessing. The model also excludes `src_ip`, `dst_ip`, `src_port`, DNS query text, SSL subject/issuer, HTTP URI/user-agent/MIME text, and weird-event text because identifiers and sparse payload strings can encode host identity, attack campaign, or collection artifacts. Stable flow measurements and low-cardinality protocol/service descriptors remain available. The resulting feature count is **30**.

The deterministic split uses `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)`: three folds for training, one for validation, and one final test fold. Groups are identical post-exclusion feature rows. The persisted ignored manifest at `data/processed/splits.json` records row indices and the raw-file SHA-256; reruns reuse it and fail if the source fingerprint or seed changes. Preprocessing is fit inside each model pipeline on training rows only.

Categorical missing values use a dedicated sentinel and infrequent-category-aware one-hot encoding; numeric missing values use median imputation with missingness indicators and sparse-compatible scaling. Unknown categories at inference are ignored. All models use a probability threshold of 0.5 for thresholded metrics.

## Validation comparison

Models are ranked by **validation PR-AUC** only. This run's selected validation candidate is **xgboost** (PR-AUC 1.0000). Test scores are not used for selection or tuning.

| Model | Precision | Recall | F1 | PR-AUC | False-positive rate |
|---|---:|---:|---:|---:|---:|
| logistic_regression | 0.9916 | 0.9730 | 0.9822 | 0.9969 | 0.0267 |
| random_forest | 0.9986 | 0.9951 | 0.9968 | 1.0000 | 0.0045 |
| xgboost | 0.9989 | 0.9948 | 0.9969 | 1.0000 | 0.0034 |

## Final test evaluation

The held-out test fold was evaluated once after training and validation-based ranking. It is reported for transparent baseline comparison only; it did not determine model selection.

| Model | Precision | Recall | F1 | PR-AUC | False-positive rate |
|---|---:|---:|---:|---:|---:|
| logistic_regression | 0.9915 | 0.9767 | 0.9840 | 0.9981 | 0.0271 |
| random_forest | 0.9990 | 0.9988 | 0.9989 | 0.9999 | 0.0033 |
| xgboost | 0.9992 | 0.9987 | 0.9989 | 0.9999 | 0.0027 |

### Per-class metrics (held-out test)

| Model | Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|---:|
| logistic_regression | normal (0) | 0.9284 | 0.9729 | 0.9501 | 10000 |
| logistic_regression | attack (1) | 0.9915 | 0.9767 | 0.9840 | 32208 |
| random_forest | normal (0) | 0.9961 | 0.9967 | 0.9964 | 10000 |
| random_forest | attack (1) | 0.9990 | 0.9988 | 0.9989 | 32208 |
| xgboost | normal (0) | 0.9958 | 0.9973 | 0.9966 | 10000 |
| xgboost | attack (1) | 0.9992 | 0.9987 | 0.9989 | 32208 |

## Reproducibility and experiment tracking

- Raw dataset SHA-256: `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`.
- Seed: `42`.
- Split row counts: train 126,627, validation 42,208, test 42,208.
- MLflow experiment: `ton-iot-network-baselines`; each model run records parameters, train/validation/test metrics, and a serialized preprocessing-plus-model pipeline.
- Local MLflow runs are stored in ignored `mlflow.db`, with model artifacts under ignored `mlruns/`; split indices are stored in ignored `data/processed/`.

Commands (from the repository root):

```bash
uv sync
uv run python scripts/audit_dataset.py
uv run pytest
uv run python scripts/train_baselines.py
uv run mlflow server --backend-store-uri sqlite:///mlflow.db --host 127.0.0.1
```

MLflow model artifacts use cloudpickle serialization; only load artifacts from trusted experiment runs.
On macOS, XGBoost may also require the OpenMP runtime (`brew install libomp`).

## Limitations

- This is a random, grouped holdout from a single supplied dataset—not a temporal or cross-device generalization test. Groups prevent exact post-preprocessing feature duplicates crossing partitions, but do not eliminate broader campaign or collection-source correlations.
- Grouped folds can differ slightly in row proportions because identical feature signatures are indivisible.
- Sparse-content and host-identifying columns were excluded conservatively; this may remove useful signals and should be revisited against deployment telemetry and a threat model.
- A 0.5 threshold is a baseline convention, not an operational alert threshold. Threshold and calibration choices require validation data and explicit false-positive cost targets.
- The selected model is a validation-ranked experiment candidate only. No model is promoted based on held-out test performance.
