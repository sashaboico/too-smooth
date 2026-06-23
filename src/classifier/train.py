"""Training entrypoint for the TooSmooth explainable classifier.

Skeleton only. The intended pipeline:
  labeled data -> FeatureExtractor -> feature matrix -> sklearn classifier
  -> persisted model + evaluation report (docs/EVAL_RESULTS.md).

We deliberately use an interpretable sklearn model (e.g. logistic regression or a
shallow tree / gradient boosting) so feature contributions stay auditable.
"""

from __future__ import annotations


def load_labeled_data(path: str):
    """Load labeled messages from ``data/labeled/`` into (texts, labels).

    Labels are one of: ``legitimate``, ``human_phishing``, ``ai_phishing``.
    """
    raise NotImplementedError("stub: load_labeled_data not implemented yet")


def build_feature_matrix(texts):
    """Run the FeatureExtractor over every text, returning an (n_samples, n_features) array."""
    raise NotImplementedError("stub: build_feature_matrix not implemented yet")


def train(model_out: str = "data/processed/model.joblib"):
    """Fit the classifier and persist it. Returns the fitted estimator."""
    raise NotImplementedError("stub: train not implemented yet")


if __name__ == "__main__":
    train()
