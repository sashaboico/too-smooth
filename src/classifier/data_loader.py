"""Unified training-data loader for the TooSmooth classifier.

Merges the two halves of the labeled dataset into one ``text, label`` table:

  - the cleaned public corpus (``data/processed/cleaned.csv``) — the ``legitimate``
    and ``human_phishing`` classes, produced by the Day 2 pipeline.
  - the hand-curated ``ai_phishing`` examples (``data/labeled/ai_phishing_examples.csv``)
    — the third class, which exists in no public corpus.

Prints the class distribution before returning so the imbalance is visible, and fails
with an actionable message if either input is missing.

Run standalone to just see the distribution:
    python -m src.classifier.data_loader
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

LABELS = ("legitimate", "human_phishing", "ai_phishing")

DEFAULT_CLEANED = Path("data/processed/cleaned.csv")
DEFAULT_LABELED = Path("data/labeled/ai_phishing_examples.csv")


def _require(path: Path, how_to_fix: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"Required input not found: {path}\n  -> {how_to_fix}"
        )


def load_training_data(
    cleaned_path: Path = DEFAULT_CLEANED,
    labeled_path: Path = DEFAULT_LABELED,
    verbose: bool = True,
) -> pd.DataFrame:
    """Load and merge both sources into a ``text, label`` DataFrame.

    Raises ``FileNotFoundError`` with a clear remediation hint if either file is
    absent. Rows with empty text or an out-of-schema label are dropped.
    """
    cleaned_path, labeled_path = Path(cleaned_path), Path(labeled_path)
    _require(cleaned_path, "Run `python -m src.data.clean` to build the cleaned corpus.")
    _require(
        labeled_path,
        "Run `python -m src.data.label_template` and add your ai_phishing examples.",
    )

    cleaned = pd.read_csv(
        cleaned_path, usecols=["text", "label"], dtype=str, keep_default_na=False
    )
    labeled = pd.read_csv(
        labeled_path, usecols=["text", "label"], dtype=str, keep_default_na=False
    )

    df = pd.concat([cleaned, labeled], ignore_index=True)
    df["text"] = df["text"].str.strip()
    df["label"] = df["label"].str.strip()

    before = len(df)
    df = df[(df["text"] != "") & df["label"].isin(LABELS)].reset_index(drop=True)
    dropped = before - len(df)

    if verbose:
        print(f"Loaded {len(df):,} labeled samples "
              f"({len(cleaned):,} from cleaned corpus + {len(labeled):,} hand-labeled; "
              f"{dropped} dropped as empty/out-of-schema).")
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
