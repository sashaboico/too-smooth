"""Pipeline components for the TooSmooth classifier.

These live in their own module (not in ``train`` which runs as ``__main__``) so that
pickled models reference a stable import path — ``src.classifier.transformers.
ManipulationFeatureExtractor`` — and can be reloaded by the API/eval processes. A
class or function defined in ``__main__`` cannot be unpickled elsewhere.
"""

from __future__ import annotations

from functools import lru_cache

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from src.features.extract import FeatureExtractor

# One shared, stateless extractor. Feature scores are cached by exact text so that
# cross-validation (which re-runs the pipeline per fold) and the final fits don't
# recompute spaCy for the same document repeatedly.
_FX = FeatureExtractor()


@lru_cache(maxsize=None)
def _cached_scores(text: str) -> tuple[float, ...]:
    scores = _FX.extract_all(text)
    return tuple(scores[name] for name in FeatureExtractor.FEATURE_NAMES)


class ManipulationFeatureExtractor(BaseEstimator, TransformerMixin):
    """sklearn transformer wrapping ``FeatureExtractor`` for use inside a Pipeline.

    ``transform`` maps an iterable of raw texts to an ``(n_samples, 6)`` array of the
    interpretable manipulation scores, so they can be FeatureUnion'd with TF-IDF and
    recomputed from raw text at predict time.
    """

    def fit(self, X, y=None):  # noqa: N803 - sklearn API
        return self

    def transform(self, X):  # noqa: N803 - sklearn API
        return np.array([_cached_scores(str(t)) for t in X], dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FeatureExtractor.FEATURE_NAMES, dtype=object)


def to_dense(X):
    """Densify a (possibly sparse) matrix — GradientBoosting wants dense input."""
    return X.toarray() if hasattr(X, "toarray") else X
