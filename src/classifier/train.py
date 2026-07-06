"""Training entrypoint for the TooSmooth explainable classifier.

Pipeline (per the Day 5 design):

    raw text
      ├─ TfidfVectorizer(max_features=5000, ngram_range=(1,2))   -> sparse lexical features
      └─ ManipulationFeatureExtractor                            -> the 6 interpretable scores
                 └── combined by FeatureUnion ──> classifier

Two classifiers are trained and saved:
  - LogisticRegression  (most interpretable — coefficients per feature)
  - GradientBoosting    (usually higher performance, less transparent)

Both are evaluated with 5-fold StratifiedKFold macro-F1. Macro-F1 weights every
class equally, so the tiny ``ai_phishing`` class actually counts — the whole point.

We deliberately keep an interpretable model in the mix so feature contributions stay
auditable.

Run:
    python -m src.classifier.train                 # default balanced subsample
    python -m src.classifier.train 3000            # cap majority classes at 3000 each
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.utils.class_weight import compute_sample_weight

from src.classifier.data_loader import load_training_data
from src.classifier.transformers import ManipulationFeatureExtractor, to_dense

MODELS_DIR = Path("models")
LR_PATH = MODELS_DIR / "classifier_lr.pkl"
GB_PATH = MODELS_DIR / "classifier_gb.pkl"

# Majority classes are down-sampled to at most this many rows each. The full corpus
# (~145k) is intractable here because the manipulation features run spaCy per document;
# a balanced subsample keeps training fast AND stops the ~123-row ai_phishing class from
# being drowned. Raise it (CLI arg) to trade time for data. All ai_phishing rows are
# always kept.
DEFAULT_MAX_PER_CLASS = 1500
RANDOM_STATE = 42


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        [
            ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ("manipulation", ManipulationFeatureExtractor()),
        ]
    )


def build_lr_pipeline() -> Pipeline:
    # class_weight='balanced' re-weights the loss inversely to class frequency, so the
    # rare ai_phishing class is not ignored in favor of the two large classes.
    return Pipeline(
        [
            ("features", _build_feature_union()),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )


def build_gb_pipeline() -> Pipeline:
    # GradientBoosting has no class_weight param, so we compensate with per-sample
    # weights at fit time (see cross_val_macro_f1 / fit_final). Densify first because
    # GB expects a dense matrix.
    return Pipeline(
        [
            ("features", _build_feature_union()),
            ("densify", FunctionTransformer(to_dense, accept_sparse=True)),
            ("clf", GradientBoostingClassifier(random_state=RANDOM_STATE)),
        ]
    )


def subsample(df, max_per_class: int, seed: int = RANDOM_STATE):
    """Balance the corpus while always keeping every hand-labeled row.

    Corpus rows (the huge ``legitimate`` / ``human_phishing`` classes) are down-sampled
    to at most ``max_per_class`` each. Hand-labeled rows — the 123 ai_phishing examples
    AND the modern SaaS legitimate examples — are kept in full, since a few dozen rows
    dropped into 75k would otherwise be randomly sampled away and never learned.
    """
    if "source" in df.columns:
        corpus = df[df["source"] == "corpus"]
        hand = df[df["source"] == "hand_labeled"]
    else:  # backward-compatible if no source column
        corpus, hand = df, df.iloc[0:0]

    parts = [
        g.sample(min(len(g), max_per_class), random_state=seed)
        for _, g in corpus.groupby("label")
    ]
    parts.append(hand)
    # Shuffle so classes are interleaved, then reset the index.
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)


def cross_val_macro_f1(build_pipeline, X, y, weighted: bool) -> float:
    """5-fold stratified macro-F1. Stratified because the classes are imbalanced.

    When ``weighted`` (GradientBoosting), a balanced ``sample_weight`` is computed on
    each training fold and passed into the classifier step.
    """
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scores = []
    for train_idx, test_idx in skf.split(X, y):
        X_tr, X_te = X[train_idx], X[test_idx]
        y_tr, y_te = y[train_idx], y[test_idx]
        pipe = build_pipeline()
        if weighted:
            w = compute_sample_weight("balanced", y_tr)
            pipe.fit(X_tr, y_tr, clf__sample_weight=w)
        else:
            pipe.fit(X_tr, y_tr)
        scores.append(f1_score(y_te, pipe.predict(X_te), average="macro"))
    return float(np.mean(scores))


def fit_final(build_pipeline, X, y, weighted: bool) -> Pipeline:
    """Fit a fresh pipeline on all available training data, for saving."""
    pipe = build_pipeline()
    if weighted:
        pipe.fit(X, y, clf__sample_weight=compute_sample_weight("balanced", y))
    else:
        pipe.fit(X, y)
    return pipe


def train(max_per_class: int = DEFAULT_MAX_PER_CLASS) -> None:
    df = load_training_data()
    df = subsample(df, max_per_class)
    print(f"\nTraining on a balanced subsample of {len(df):,} rows "
          f"(<= {max_per_class:,} per majority class; all ai_phishing kept):")
    print(df["label"].value_counts().to_string())

    X = df["text"].to_numpy()
    y = df["label"].to_numpy()

    print("\nCross-validating LogisticRegression ...")
    lr_f1 = cross_val_macro_f1(build_lr_pipeline, X, y, weighted=False)
    print("Cross-validating GradientBoosting ...")
    gb_f1 = cross_val_macro_f1(build_gb_pipeline, X, y, weighted=True)

    print("\nFitting final models on all subsampled data ...")
    lr_model = fit_final(build_lr_pipeline, X, y, weighted=False)
    gb_model = fit_final(build_gb_pipeline, X, y, weighted=True)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(lr_model, LR_PATH)
    joblib.dump(gb_model, GB_PATH)

    print("\nTraining complete.")
    print(f"LogisticRegression cross-val F1 (macro): {lr_f1:.2f}")
    print(f"GradientBoosting cross-val F1 (macro): {gb_f1:.2f}")
    print(f"Models saved to {MODELS_DIR}/")


if __name__ == "__main__":
    cap = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_MAX_PER_CLASS
    train(max_per_class=cap)
