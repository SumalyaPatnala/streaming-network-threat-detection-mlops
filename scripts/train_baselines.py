from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from threat_detection.training import (
    LEAKAGE_PRONE_COLUMNS,
    TARGET_COLUMN,
    build_preprocessor,
    dataset_fingerprint,
    evaluate_predictions,
    json_safe,
    load_dataset,
    load_or_create_splits,
    maybe_evaluate_final_test,
    prepare_features,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = (
    ROOT
    / "data/raw/Train_Test_datasets/Train_Test_Network_dataset/train_test_network.csv"
)
DEFAULT_REPORT = ROOT / "reports/milestone-1-report.md"
DEFAULT_MANIFEST = ROOT / "data/processed/splits.json"
RANDOM_STATE = 42


def build_models() -> dict[str, Any]:
    return {
        "logistic_regression": LogisticRegression(
            max_iter=1000, solver="lbfgs", random_state=RANDOM_STATE
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "xgboost": XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
    }


def _metrics_for_split(
    model: Pipeline, features: pd.DataFrame, labels: np.ndarray
) -> dict[str, Any]:
    scores = model.predict_proba(features)[:, 1]
    return evaluate_predictions(labels, scores)


def _dataset_eda(frame: pd.DataFrame, features: pd.DataFrame) -> dict[str, Any]:
    target_counts = frame[TARGET_COLUMN].value_counts().sort_index().to_dict()
    type_counts = frame["type"].value_counts().to_dict()
    duplicate_rows = int(frame.duplicated().sum())
    duplicate_feature_rows = int(features.duplicated().sum())
    signature_labels = pd.concat(
        [features, frame[TARGET_COLUMN].rename(TARGET_COLUMN)], axis=1
    ).groupby(list(features.columns), dropna=False, sort=False)[TARGET_COLUMN].nunique()
    mixed_label_signatures = int((signature_labels > 1).sum())

    source_ip_stats: dict[str, Any] | None = None
    if "src_ip" in frame:
        source_stats = frame.groupby("src_ip", dropna=False)[TARGET_COLUMN].agg(
            ["count", "mean"]
        )
        most_common_source = source_stats.sort_values("count", ascending=False).iloc[0]
        source_ip_stats = {
            "distinct": int(frame["src_ip"].nunique(dropna=False)),
            "most_frequent_count": int(most_common_source["count"]),
            "most_frequent_attack_rate": float(most_common_source["mean"]),
        }

    sentinel_counts = frame.isna().sum().sort_values(ascending=False)
    return {
        "rows": len(frame),
        "columns": len(frame.columns),
        "target_counts": {str(key): int(value) for key, value in target_counts.items()},
        "type_counts": {str(key): int(value) for key, value in type_counts.items()},
        "duplicate_rows": duplicate_rows,
        "duplicate_model_feature_rows": duplicate_feature_rows,
        "mixed_label_feature_signatures": mixed_label_signatures,
        "source_ip": source_ip_stats,
        "top_missing": {
            str(key): int(value)
            for key, value in sentinel_counts.head(8).items()
            if value
        },
        "model_feature_count": len(features.columns),
    }


def _format_metrics_table(results: dict[str, Any], split: str) -> str:
    lines = [
        "| Model | Precision | Recall | F1 | PR-AUC | False-positive rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for model_name, result in results.items():
        metrics = result[split]
        lines.append(
            f"| {model_name} | {metrics['precision']:.4f} | "
            f"{metrics['recall']:.4f} | {metrics['f1']:.4f} | "
            f"{metrics['pr_auc']:.4f} | "
            f"{metrics['false_positive_rate']:.4f} |"
        )
    return "\n".join(lines)


def _format_class_metrics(results: dict[str, Any], split: str) -> str:
    lines = [
        "| Model | Class | Precision | Recall | F1 | Support |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for model_name, result in results.items():
        for label, metrics in result[split]["per_class"].items():
            class_name = "normal (0)" if label == "0" else "attack (1)"
            lines.append(
                f"| {model_name} | {class_name} | {metrics['precision']:.4f} | "
                f"{metrics['recall']:.4f} | {metrics['f1']:.4f} | "
                f"{metrics['support']} |"
            )
    return "\n".join(lines)


def generate_report(
    path: Path,
    fingerprint: str,
    eda: dict[str, Any],
    split_sizes: dict[str, int],
    results: dict[str, Any],
    selected_model: str,
    random_state: int,
    final_test_evaluated: bool,
) -> None:
    source = eda["source_ip"]
    top_missing = ", ".join(
        f"`{name}` ({count:,})" for name, count in eda["top_missing"].items()
    )
    test_section = (
        f"""## Final test evaluation

This explicit evaluation was requested for this run. The held-out test fold is not used for model selection.

{_format_metrics_table(results, "test")}

### Per-class metrics (held-out test)

{_format_class_metrics(results, "test")}
"""
        if final_test_evaluated
        else """## Final test evaluation

Not evaluated by this run. The existing final test set has already been evaluated in the original Milestone 1 report and is **not an untouched holdout**. Ordinary training and model comparison use training and validation data only.
"""
    )
    report = f"""# Milestone 1: Reproducible ML Training & Evaluation

## Dataset audit and EDA

The audit used the supplied TON_IoT network flow CSV; the raw file was read only and was not changed.

- Shape: **{eda["rows"]:,} rows × {eda["columns"]} columns**.
- Binary target counts: **normal (0): {eda["target_counts"].get("0", 0):,}; attack (1): {eda["target_counts"].get("1", 0):,}**.
- Attack subtypes: {", ".join(f"{name} {count:,}" for name, count in sorted(eda["type_counts"].items()))}.
- Exact repeated raw rows: **{eda["duplicate_rows"]:,}**.
- Repeated model-feature rows after leakage exclusions: **{eda["duplicate_model_feature_rows"]:,}**; **{eda["mixed_label_feature_signatures"]}** feature signatures have both labels. These duplicates are kept, but grouped into a single split to prevent identical model inputs crossing partitions.
- `src_ip` has **{source["distinct"]:,}** distinct values; its most frequent address has **{source["most_frequent_count"]:,}** records and an attack rate of **{source["most_frequent_attack_rate"]:.2%}**. This and the 26,628 distinct source ports observed make these fields strong dataset-specific shortcuts rather than robust flow behavior.
- Most-missing fields (empty or `-` placeholders): {top_missing}.

## Feature and split design

The target is `label` (0 = normal, 1 = attack). `type` is a subtype directly derived from the binary target and is never passed to preprocessing. The model also excludes `src_ip`, `dst_ip`, `src_port`, DNS query text, SSL subject/issuer, HTTP URI/user-agent/MIME text, and weird-event text because identifiers and sparse payload strings can encode host identity, attack campaign, or collection artifacts. Stable flow measurements and low-cardinality protocol/service descriptors remain available. The resulting feature count is **{eda["model_feature_count"]}**.

The deterministic split uses `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state={random_state})`: three folds for training, one for validation, and one final test fold. Groups are identical post-exclusion feature rows. The persisted ignored manifest at `data/processed/splits.json` records row indices and the raw-file SHA-256; reruns reuse it and fail if the source fingerprint or seed changes. Preprocessing is fit inside each model pipeline on training rows only.

Categorical missing values use a dedicated sentinel and infrequent-category-aware one-hot encoding; numeric missing values use median imputation with missingness indicators and sparse-compatible scaling. Unknown categories at inference are ignored. All models use a probability threshold of 0.5 for thresholded metrics.

## Validation comparison

Models are ranked by **validation PR-AUC** only. This run's selected validation candidate is **{selected_model}** (PR-AUC {results[selected_model]["validation"]["pr_auc"]:.4f}). Test scores are not used for selection or tuning.

{_format_metrics_table(results, "validation")}

{test_section}

## Reproducibility and experiment tracking

- Raw dataset SHA-256: `{fingerprint}`.
- Seed: `{random_state}`.
- Split row counts: {", ".join(f"{name} {count:,}" for name, count in split_sizes.items())}.
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
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")


def run_training(
    data_path: Path,
    report_path: Path,
    manifest_path: Path,
    random_state: int = RANDOM_STATE,
    evaluate_final_test: bool = False,
) -> dict[str, Any]:
    fingerprint = dataset_fingerprint(data_path)
    frame = load_dataset(data_path)
    features = prepare_features(frame)
    labels = frame[TARGET_COLUMN].to_numpy()
    splits = load_or_create_splits(
        frame, manifest_path, fingerprint, random_state=random_state
    )
    indices = splits.as_dict()
    x_train, y_train = features.iloc[indices["train"]], labels[indices["train"]]
    x_validation, y_validation = (
        features.iloc[indices["validation"]],
        labels[indices["validation"]],
    )
    mlflow.set_experiment("ton-iot-network-baselines")
    eda = _dataset_eda(frame, features)
    results: dict[str, Any] = {}
    models = build_models()

    for model_name, estimator in models.items():
        model = Pipeline(
            steps=[
                ("preprocessor", build_preprocessor(x_train)),
                ("classifier", estimator),
            ]
        )
        model.fit(x_train, y_train)
        validation_metrics = _metrics_for_split(model, x_validation, y_validation)
        train_metrics = _metrics_for_split(model, x_train, y_train)
        results[model_name] = {
            "train": train_metrics,
            "validation": validation_metrics,
        }
        if evaluate_final_test:
            test_metrics = maybe_evaluate_final_test(
                True,
                {model_name: model},
                features.iloc[indices["test"]],
                labels[indices["test"]],
            )
            if test_metrics is None:
                raise RuntimeError(
                    "Explicit final-test evaluation unexpectedly returned no metrics"
                )
            results[model_name]["test"] = test_metrics[model_name]

        with mlflow.start_run(run_name=model_name):
            mlflow.log_params(
                {
                    "model": model_name,
                    "random_state": random_state,
                    "split_method": "StratifiedGroupKFold",
                    "n_splits": 5,
                    "train_folds": 3,
                    "threshold": 0.5,
                    "feature_count": len(features.columns),
                    "excluded_columns": ",".join(sorted(LEAKAGE_PRONE_COLUMNS)),
                    "dataset_sha256": fingerprint,
                }
            )
            mlflow.log_params(estimator.get_params(deep=True))
            for split_name, metrics in results[model_name].items():
                flattened = {
                    f"{split_name}_{metric_name}": metric_value
                    for metric_name, metric_value in metrics.items()
                    if isinstance(metric_value, (float, int))
                }
                mlflow.log_metrics(flattened)
                mlflow.log_dict(
                    json_safe(metrics), f"metrics/{split_name}_metrics.json"
                )
            mlflow.sklearn.log_model(
                model,
                artifact_path="model",
                serialization_format="cloudpickle",
            )

    selected_model = max(
        results, key=lambda name: results[name]["validation"]["pr_auc"]
    )
    split_sizes = {name: len(values) for name, values in indices.items()}
    generate_report(
        report_path,
        fingerprint,
        eda,
        split_sizes,
        results,
        selected_model,
        random_state,
        evaluate_final_test,
    )
    summary = {
        "dataset_sha256": fingerprint,
        "eda": eda,
        "split_sizes": split_sizes,
        "selected_by_validation_pr_auc": selected_model,
        "results": results,
        "report": str(report_path),
    }
    print(json.dumps(json_safe(summary), indent=2))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--split-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    parser.add_argument(
        "--evaluate-final-test",
        action="store_true",
        help=(
            "Explicitly evaluate the final test split for audit/reporting only. "
            "This set was already evaluated in Milestone 1 and is not an untouched holdout."
        ),
    )
    args = parser.parse_args()
    run_training(
        args.data,
        args.report,
        args.split_manifest,
        args.seed,
        evaluate_final_test=args.evaluate_final_test,
    )


if __name__ == "__main__":
    main()
