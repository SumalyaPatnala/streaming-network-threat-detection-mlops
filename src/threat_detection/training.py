from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

TARGET_COLUMN = "label"
LEAKAGE_PRONE_COLUMNS = frozenset(
    {
        "label",
        "type",
        "src_ip",
        "dst_ip",
        "src_port",
        "dns_query",
        "ssl_subject",
        "ssl_issuer",
        "http_uri",
        "http_user_agent",
        "http_orig_mime_types",
        "http_resp_mime_types",
        "weird_name",
        "weird_addl",
    }
)
SPLIT_NAMES = ("train", "validation", "test")


@dataclass(frozen=True)
class DatasetSplits:
    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray

    def as_dict(self) -> dict[str, np.ndarray]:
        return {name: getattr(self, name) for name in SPLIT_NAMES}


def load_dataset(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, encoding="utf-8-sig", low_memory=False, na_values=["-", ""])
    required = {TARGET_COLUMN, "type"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing required target columns: {sorted(missing)}")

    labels = set(frame[TARGET_COLUMN].dropna().unique())
    if not labels or not labels.issubset({0, 1}):
        raise ValueError(f"Expected binary 0/1 labels, found: {sorted(labels)}")
    if frame[TARGET_COLUMN].isna().any():
        raise ValueError("Target column contains missing values")

    frame[TARGET_COLUMN] = frame[TARGET_COLUMN].astype("int8")
    return frame


def prepare_features(frame: pd.DataFrame) -> pd.DataFrame:
    if TARGET_COLUMN not in frame:
        raise ValueError(f"Dataset must contain target column {TARGET_COLUMN!r}")
    features = frame.drop(
        columns=[column for column in LEAKAGE_PRONE_COLUMNS if column in frame.columns]
    )
    if features.empty:
        raise ValueError("No model features remain after excluding leakage-prone columns")
    return features.replace({"-": np.nan, "": np.nan})


def dataset_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_grouped_splits(
    frame: pd.DataFrame, random_state: int = 42
) -> DatasetSplits:
    features = prepare_features(frame)
    labels = frame[TARGET_COLUMN].to_numpy()
    groups = pd.util.hash_pandas_object(features, index=False).to_numpy()

    splitter = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=random_state
    )
    fold_assignment = np.full(len(frame), -1, dtype=np.int8)
    for fold, (_, held_out) in enumerate(splitter.split(features, labels, groups)):
        fold_assignment[held_out] = fold
    if np.any(fold_assignment < 0):
        raise RuntimeError("Grouped splitter did not assign every row to a fold")

    splits = DatasetSplits(
        train=np.flatnonzero(fold_assignment < 3),
        validation=np.flatnonzero(fold_assignment == 3),
        test=np.flatnonzero(fold_assignment == 4),
    )
    validate_splits(splits, groups, len(frame))
    return splits


def validate_splits(
    splits: DatasetSplits, groups: np.ndarray, row_count: int
) -> None:
    arrays = splits.as_dict()
    for name, indices in arrays.items():
        if indices.ndim != 1 or len(indices) == 0:
            raise ValueError(f"{name} split must be a non-empty one-dimensional index array")
        if np.any(indices < 0) or np.any(indices >= row_count):
            raise ValueError(f"{name} split contains out-of-range row indices")

    combined = np.concatenate(list(arrays.values()))
    if len(combined) != row_count or len(np.unique(combined)) != row_count:
        raise ValueError("Splits must partition every row exactly once")

    group_sets = {
        name: set(groups[indices].tolist()) for name, indices in arrays.items()
    }
    for first, second in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if group_sets[first].intersection(group_sets[second]):
            raise ValueError(f"Identical feature groups cross {first}/{second} splits")


def load_or_create_splits(
    frame: pd.DataFrame,
    manifest_path: Path,
    data_sha256: str,
    random_state: int = 42,
) -> DatasetSplits:
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            manifest.get("dataset_sha256") != data_sha256
            or manifest.get("random_state") != random_state
            or manifest.get("row_count") != len(frame)
        ):
            raise ValueError(
                f"Existing split manifest {manifest_path} does not match this dataset "
                "and seed. Preserve the original test set or deliberately remove the "
                "manifest to create a new split."
            )
        splits = DatasetSplits(
            **{
                name: np.asarray(manifest["indices"][name], dtype=np.int64)
                for name in SPLIT_NAMES
            }
        )
        validate_splits(
            splits,
            pd.util.hash_pandas_object(prepare_features(frame), index=False).to_numpy(),
            len(frame),
        )
        return splits

    splits = create_grouped_splits(frame, random_state=random_state)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "dataset_sha256": data_sha256,
        "random_state": random_state,
        "row_count": len(frame),
        "split_method": "StratifiedGroupKFold(5): 3 train folds, 1 validation, 1 test",
        "indices": {name: indices.tolist() for name, indices in splits.as_dict().items()},
    }
    temporary_path = manifest_path.with_suffix(f"{manifest_path.suffix}.tmp")
    temporary_path.write_text(json.dumps(manifest), encoding="utf-8")
    temporary_path.replace(manifest_path)
    return splits


def build_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    numeric_columns = list(features.select_dtypes(include=[np.number]).columns)
    categorical_columns = list(
        features.select_dtypes(include=["object", "category", "string", "bool"]).columns
    )
    selected_columns = set(numeric_columns + categorical_columns)
    unhandled_columns = set(features.columns).difference(selected_columns)
    if unhandled_columns:
        raise TypeError(
            f"Unsupported feature dtypes in preprocessing: {sorted(unhandled_columns)}"
        )
    if not selected_columns:
        raise ValueError("Preprocessing requires at least one numeric or categorical feature")

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median", add_indicator=True)),
            ("scaler", StandardScaler(with_mean=False)),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="constant", fill_value="__MISSING__"),
            ),
            (
                "encoder",
                OneHotEncoder(
                    handle_unknown="ignore",
                    min_frequency=20,
                    sparse_output=True,
                ),
            ),
        ]
    )
    transformers = []
    if numeric_columns:
        transformers.append(("numeric", numeric_pipeline, numeric_columns))
    if categorical_columns:
        transformers.append(("categorical", categorical_pipeline, categorical_columns))
    return ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        sparse_threshold=1.0,
        verbose_feature_names_out=False,
    )


def evaluate_predictions(
    labels: np.ndarray, scores: np.ndarray, threshold: float = 0.5
) -> dict[str, Any]:
    labels = np.asarray(labels)
    scores = np.asarray(scores)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape:
        raise ValueError("Labels and scores must be one-dimensional arrays of equal length")
    if len(labels) == 0 or set(np.unique(labels)) != {0, 1}:
        raise ValueError("Evaluation requires non-empty labels containing both classes")
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Prediction scores must be finite probabilities in [0, 1]")

    predictions = (scores >= threshold).astype(np.int8)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predictions, labels=[0, 1], zero_division=0
    )
    true_negative, false_positive, _, _ = confusion_matrix(
        labels, predictions, labels=[0, 1]
    ).ravel()
    result: dict[str, Any] = {
        "precision": float(precision[1]),
        "recall": float(recall[1]),
        "f1": float(f1[1]),
        "pr_auc": float(average_precision_score(labels, scores)),
        "false_positive_rate": float(
            false_positive / (false_positive + true_negative)
        ),
        "support": len(labels),
        "threshold": float(threshold),
        "per_class": {
            str(label): {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate((0, 1))
        },
    }
    return result


class ProbabilityModel(Protocol):
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray: ...


def maybe_evaluate_final_test(
    enabled: bool,
    models: dict[str, ProbabilityModel],
    features: pd.DataFrame,
    labels: np.ndarray,
) -> dict[str, dict[str, Any]] | None:
    if not enabled:
        return None
    return {
        name: evaluate_predictions(labels, model.predict_proba(features)[:, 1])
        for name, model in models.items()
    }


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    return value
