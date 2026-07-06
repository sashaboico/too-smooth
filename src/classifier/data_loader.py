"""Unified training-data loader for the TooSmooth classifier.

Merges the labeled data into one ``text, label, source`` table:

  - the cleaned public corpus (``data/processed/cleaned.csv``) — the ``legitimate``
    and ``human_phishing`` classes, produced by the Day 2 pipeline (source ``corpus``).
  - the hand-curated ``ai_phishing`` examples (``data/labeled/ai_phishing_examples.csv``)
    — the third class, which exists in no public corpus (source ``hand_labeled``).
  - modern legitimate SaaS/transactional emails
    (``data/labeled/legitimate_saas_examples.csv``, optional) — added to counter the
    domain-shift false positives on Vercel/GitHub/Stripe-style mail that the 2001-era
    corpus never saw (source ``hand_labeled``).

The ``source`` column lets training always keep the hand-labeled rows through the
balanced subsample instead of randomly dropping them.

Prints the class distribution before returning so the imbalance is visible, and fails
with an actionable message if a required input is missing.

Run standalone to just see the distribution:
    python -m src.classifier.data_loader
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

LABELS = ("legitimate", "human_phishing", "ai_phishing")

DEFAULT_CLEANED = Path("data/processed/cleaned.csv")
DEFAULT_LABELED = Path("data/labeled/ai_phishing_examples.csv")
DEFAULT_SAAS = Path("data/labeled/legitimate_saas_examples.csv")


def _require(path: Path, how_to_fix: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"Required input not found: {path}\n  -> {how_to_fix}"
        )


def _read_labeled(path: Path) -> pd.DataFrame:
    """Read a hand-labeled file, keeping only text + label."""
    return pd.read_csv(path, usecols=["text", "label"], dtype=str, keep_default_na=False)


def load_training_data(
    cleaned_path: Path = DEFAULT_CLEANED,
    labeled_path: Path = DEFAULT_LABELED,
    saas_path: Path = DEFAULT_SAAS,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load and merge all sources into a ``text, label, source`` DataFrame.

    Raises ``FileNotFoundError`` with a clear remediation hint if a required file is
    absent (the SaaS legitimate file is optional). Rows with empty text or an
    out-of-schema label are dropped.
    """
    cleaned_path, labeled_path = Path(cleaned_path), Path(labeled_path)
    saas_path = Path(saas_path)
    _require(cleaned_path, "Run `python -m src.data.clean` to build the cleaned corpus.")
    _require(
        labeled_path,
        "Run `python -m src.data.label_template` and add your ai_phishing examples.",
    )

    cleaned = pd.read_csv(
        cleaned_path, usecols=["text", "label"], dtype=str, keep_default_na=False
    )
    cleaned["source"] = "corpus"

    frames = [cleaned]

    ai = _read_labeled(labeled_path)
    ai["source"] = "hand_labeled"
    frames.append(ai)

    n_saas = 0
    if saas_path.exists():
        saas = _read_labeled(saas_path)
        saas["source"] = "hand_labeled"
        n_saas = len(saas)
        frames.append(saas)

    df = pd.concat(frames, ignore_index=True)
    df["text"] = df["text"].str.strip()
    df["label"] = df["label"].str.strip()

    before = len(df)
    df = df[(df["text"] != "") & df["label"].isin(LABELS)].reset_index(drop=True)
    dropped = before - len(df)

    if verbose:
        n_hand = int((df["source"] == "hand_labeled").sum())
        print(f"Loaded {len(df):,} labeled samples "
              f"({len(cleaned):,} corpus + {len(ai):,} ai_phishing + {n_saas:,} SaaS legit; "
              f"{dropped} dropped as empty/out-of-schema; {n_hand} hand-labeled).")
        print("Class distribution:")
        counts = df["label"].value_counts().reindex(LABELS, fill_value=0)
        for label in LABELS:
            n = int(counts[label])
            print(f"  {label:<16} {n:>8,}  ({n / len(df):.1%})")
        ratio = counts.max() / max(counts.min(), 1)
        print(f"  imbalance ratio (max/min): {ratio:.0f}x")

    return df


if __name__ == "__main__":
    load_training_data()
