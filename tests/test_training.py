from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from threat_detection.training import (
    LEAKAGE_PRONE_COLUMNS,
    build_preprocessor,
    create_grouped_splits,
    evaluate_predictions,
    load_or_create_splits,
    prepare_features,
)


def _sample_frame(group_count: int = 100) -> pd.DataFrame:
    records: list[dict[str, object]] = []
    for group in range(group_count):
        label = group % 2
        for _ in range(2):
            records.append(
                {
                    "duration": float(group),
                    "proto": "tcp" if label else "udp",
                    "src_ip": f"192.0.2.{group}",
                    "src_port": 40000 + group,
                    "dns_query": f"host-{group}.example",
                    "label": label,
                    "type": "attack" if label else "normal",
                }
            )
    return pd.DataFrame.from_records(records)


def test_preprocessor_imputes_encodes_and_accepts_unseen_categories() -> None:
    frame = pd.DataFrame(
        {
            "numeric": [1.0, np.nan, 3.0, 4.0],
            "category": ["tcp", "udp", np.nan, "tcp"],
        }
    )
    preprocessor = build_preprocessor(frame)
    transformed = preprocessor.fit_transform(frame)
    unseen = preprocessor.transform(
        pd.DataFrame({"numeric": [np.nan], "category": ["icmp"]})
    )

    assert transformed.shape[0] == len(frame)
    assert transformed.shape[1] > 0
    assert unseen.shape == (1, transformed.shape[1])
    dense = transformed.toarray() if sparse.issparse(transformed) else transformed
    assert np.isfinite(dense).all()
    assert (
        preprocessor.named_transformers_["categorical"]
        .named_steps["imputer"]
        .statistics_[0]
        == "__MISSING__"
    )


def test_grouped_splits_are_reproducible_exhaustive_and_group_disjoint() -> None:
    frame = _sample_frame()
    features = prepare_features(frame)
    first = create_grouped_splits(frame, random_state=17)
    second = create_grouped_splits(frame, random_state=17)

    for name, indices in first.as_dict().items():
        np.testing.assert_array_equal(indices, second.as_dict()[name])
        assert len(indices) > 0
    all_indices = np.concatenate(list(first.as_dict().values()))
    np.testing.assert_array_equal(np.sort(all_indices), np.arange(len(frame)))

    groups = pd.util.hash_pandas_object(features, index=False).to_numpy()
    group_sets = [
        set(groups[indices].tolist()) for indices in first.as_dict().values()
    ]
    assert group_sets[0].isdisjoint(group_sets[1])
    assert group_sets[0].isdisjoint(group_sets[2])
    assert group_sets[1].isdisjoint(group_sets[2])


def test_split_manifest_preserves_split_and_rejects_changed_dataset(tmp_path) -> None:
    frame = _sample_frame()
    manifest_path = tmp_path / "splits.json"
    first = load_or_create_splits(frame, manifest_path, "dataset-hash")
    second = load_or_create_splits(frame, manifest_path, "dataset-hash")

    for name, indices in first.as_dict().items():
        np.testing.assert_array_equal(indices, second.as_dict()[name])
    with pytest.raises(ValueError, match="does not match"):
        load_or_create_splits(frame, manifest_path, "different-hash")


def test_prediction_contract_and_binary_metrics() -> None:
    frame = _sample_frame()
    features = prepare_features(frame)
    labels = frame["label"].to_numpy()
    model = Pipeline(
        [
            ("preprocessor", build_preprocessor(features)),
            ("classifier", LogisticRegression(max_iter=1000)),
        ]
    )
    model.fit(features.iloc[:160], labels[:160])
    probabilities = model.predict_proba(features.iloc[160:])[:, 1]
    metrics = evaluate_predictions(labels[160:], probabilities)

    assert probabilities.shape == (40,)
    assert np.isfinite(probabilities).all()
    assert np.all((probabilities >= 0) & (probabilities <= 1))
    assert {"precision", "recall", "f1", "pr_auc", "false_positive_rate"} <= set(
        metrics
    )
    assert set(metrics["per_class"]) == {"0", "1"}
    assert all(
        0.0 <= metrics[key] <= 1.0
        for key in (
            "precision",
            "recall",
            "f1",
            "pr_auc",
            "false_positive_rate",
        )
    )
    with pytest.raises(ValueError, match="probabilities"):
        evaluate_predictions(labels[160:], np.full(40, 2.0))


def test_prepared_features_exclude_targets_and_leakage_prone_columns() -> None:
    frame = _sample_frame()
    features = prepare_features(frame)

    assert not (set(features.columns) & LEAKAGE_PRONE_COLUMNS)
    assert "duration" in features
    assert "proto" in features
