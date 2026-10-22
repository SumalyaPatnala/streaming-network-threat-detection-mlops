from __future__ import annotations

import numpy as np
import pandas as pd

from threat_detection.training import maybe_evaluate_final_test


class UnusedModel:
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        raise AssertionError("final-test predictor must not run unless explicitly enabled")


class FixedModel:
    def __init__(self) -> None:
        self.calls = 0

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        self.calls += 1
        return np.column_stack(
            [np.full(len(features), 0.25), np.full(len(features), 0.75)]
        )


def test_final_test_evaluation_is_disabled_without_explicit_opt_in() -> None:
    result = maybe_evaluate_final_test(
        False,
        {"candidate": UnusedModel()},
        pd.DataFrame({"feature": [1, 2]}),
        np.asarray([0, 1]),
    )

    assert result is None


def test_final_test_evaluation_runs_only_after_explicit_opt_in() -> None:
    model = FixedModel()
    result = maybe_evaluate_final_test(
        True,
        {"candidate": model},
        pd.DataFrame({"feature": [1, 2]}),
        np.asarray([0, 1]),
    )

    assert model.calls == 1
    assert result is not None
    assert result["candidate"]["support"] == 2
