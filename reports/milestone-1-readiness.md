# Milestone 1 Production-Readiness Review

## Review outcome

**Not ready to claim production detection performance.** The saved models load and return stable probabilities, and the persisted split prevents exact post-exclusion feature signatures from crossing partitions. However, the dataset is scenario-ordered, the evaluation is a random grouped holdout from one testbed, and the trained feature set depends on optional Zeek protocol-log enrichment. These results establish a reproducible baseline, not temporal, host-independent, or deployment generalization.

No model was retrained and no new test-set evaluation was performed for this review.

## Verified implementation and split safeguards

- `label` is the binary target. `type` (normal/attack subtype) and host/payload identifiers are removed by `prepare_features`; neither enters the preprocessing pipeline. The training data has **30 features**.
- The 30-feature identity is recorded in [network-flow-model-input-v1.schema.json](../schemas/network-flow-model-input-v1.schema.json). Automated tests compare its required feature list against the preprocessing result and reject target/leakage fields.
- The actual split is `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)`. Folds 0–2 are combined as train, fold 3 is validation, and fold 4 is the held-out test. Preprocessing is fitted as part of each pipeline on train only. The split manifest is bound to the raw-file SHA-256.
- Independently checked the persisted manifest against the raw file: **126,627 train**, **42,208 validation**, and **42,208 test** rows. Class counts were train 30,000 normal / 96,627 attack; validation and test each 10,000 normal / 32,208 attack.
- Recomputed groups from the 30 model input features: **0** intersecting feature signatures across each pair of partitions (train/validation, train/test, validation/test). All 211,043 row indices occur exactly once. Eight feature signatures have both labels, but each signature remains within a single partition.
- Loaded the latest finished MLflow model for each baseline and called `predict_proba` on 1,024 training rows. Each returned 1,024 probabilities. Repeated and separately reloaded Random Forest predictions differed only by floating-point accumulation: maximum absolute delta **2.22e-16**; Logistic Regression and XGBoost repeat outputs were bit-identical. This supports numerical inference reproducibility, not bit-for-bit determinism across all hardware/runtime combinations.
- The current training script computes test metrics for all three models on every invocation, before it chooses the validation-PR-AUC candidate (although the code does not use test metrics in that choice). The initial Milestone 1 execution also had failed attempts after some models had already been fit and scored. This is a test-set governance weakness: preserve the existing report, do not rerun training for this review, and in future isolate the one-time final evaluation behind an explicit command/recorded evaluation state.

## Leakage and unusually high metrics

**Verified safeguards:** direct target and subtype exclusion, host identifiers and selected payload-like fields excluded, preprocessing fit on train only, deterministic row-grouped splitting, exact feature-signature disjointness, and a preserved final test manifest.

**Verified unresolved correlation risks:**

- No timestamp, connection UID, session ID, device ID, or testbed/scenario identifier exists in the 44-column CSV. The split therefore cannot hold out time windows, sessions, devices, or attack campaigns.
- Rows are strongly scenario ordered: `label` has only **2 transitions** (3 contiguous label runs); `type` has **9 transitions** (10 contiguous subtype runs). For example, one contiguous block is entirely normal, while multiple contiguous blocks are attack-only. Randomly shuffling feature groups across folds allows each partition to contain signatures from these same source blocks.
- Some retained features are near-direct scenario/service proxies in this collection: `dst_port=445` has 13,449 observations and is 100% attack; `dst_port=80` has 70,673 observations and is 99.75% attack; `conn_state=REJ` has 44,852 observations and is 100% attack. These associations are measured on the complete supplied dataset for EDA; they are not proof that any one feature caused the scores.
- The file combines attack subtypes and normal flows from one testbed, and repeated feature signatures are common. Grouping exact inputs avoids duplicate-row leakage but cannot prevent broader campaign, host-role, capture-process, or collection-period correlation.

Consequently, the reported near-perfect holdout metrics can plausibly reflect testbed/scenario regularities. The current data cannot resolve this. Do not use the numbers as a production service-level expectation. Obtain scenario/device/source metadata or a new temporally and operationally independent collection before making generalization claims. Do not revisit the current test split for tuning.

## Live telemetry availability

The schema is a canonical normalized event contract, not proof that the raw network sensor emits every field:

- **Direct connection-log fields:** destination port, protocol, service, duration, originator/responder bytes, connection state, missed bytes, packet counts, and IP-byte counts can be mapped from Zeek `conn.log` (`id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `missed_bytes`, `orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes`). The source/destination direction convention must be fixed and tested by the adapter.
- **Joined protocol-log fields:** DNS fields require `dns.log`; TLS fields require `ssl.log`; HTTP fields require `http.log`; `weird_notice` requires `weird.log`. These records must be correlated to a connection (normally with the Zeek connection UID) before the UID is discarded. Such fields are sparse or absent for most flows in training, and missing values must remain null—not fabricated zeros.
- DNS and TLS booleans are strings in the training data (`T`/`F`); HTTP version is numeric in the loaded frame. The ingestion adapter must normalize deployed Zeek values to those types. Confirm exact log field names, event timing, join behavior, and `weird_notice` semantics against the deployed Zeek version before serving.
- Excluded fields such as source/destination IP, source port, DNS query text, HTTP URI/user-agent, and TLS subject/issuer are not model inputs and must not be added to the request or feature builder.
- If the serving source has only `conn.log`, it cannot supply the full trained contract. Either enrich the event from the protocol logs with training-equivalent null semantics, or train/version a model using only reliably available connection fields. Do not silently synthesize absent values.

## Versioned input contract

[network-flow-model-input-v1.schema.json](../schemas/network-flow-model-input-v1.schema.json) defines schema version `1.0.0`, optional `event_id` and `observed_at` envelope metadata, and exactly 30 required feature keys. Feature values may be null where telemetry is unavailable; unexpected fields are rejected. Event IDs and timestamps are metadata only and are not classifier inputs. FastAPI requests and future Kafka/Zeek normalization should use this same envelope; schema-breaking feature changes require a new version and a corresponding model artifact.

## Focused regression checks

`uv run pytest -q` passes **8 tests**, including the existing preprocessing, split reproducibility/group isolation, prediction-output, and leakage checks, plus checks that the v1 schema exactly matches the train-time feature names and excludes target/identifier fields. The full generated split was separately checked as described above. No independent test-set scoring was run for this review.

## Milestone 2 implementation status

The planned FastAPI inference service, test-set evaluation gate, v1 feature contract, and local Docker container have been implemented. Actual executed checks and remaining risks are documented in [milestone-2-report.md](./milestone-2-report.md).

**Out of scope:** Kafka consumers/producers, Kubernetes, cloud hosting, and automated model promotion. Implement the telemetry join/normalization boundary so Kafka can be added later, but do not add that infrastructure in Milestone 2.
