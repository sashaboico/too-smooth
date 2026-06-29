"""Print a dataset summary: class balance, per-class word counts, totals.

Reads the cleaned corpus (``data/processed/cleaned.csv``) and, if present, folds in
the hand-labeled AI-phishing examples (``data/labeled/ai_phishing_examples.csv``,
skipping any unfilled PLACEHOLDER rows). Run this after adding hand-labeled examples
to confirm the three classes are reasonably balanced before training.

Run:
    python -m src.data.stats
    python -m src.data.stats path/to/some_other.csv
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

from src.data import ingest
from src.data.clean import DEFAULT_CLEANED_OUT
from src.data.label_template import DEFAULT_TEMPLATE_OUT, PLACEHOLDER_PREFIX


def _word_count(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.split().str.len()


def load_for_stats(cleaned_path: Path = DEFAULT_CLEANED_OUT) -> pd.DataFrame:
    """Load cleaned data plus filled-in hand-labeled examples into one frame."""
    frames: list[pd.DataFrame] = []

    if cleaned_path.exists():
        cleaned = pd.read_csv(cleaned_path, dtype={"text": str}, keep_default_na=False)
        frames.append(cleaned)
    else:
        print(f"warning: {cleaned_path} not found — run `python -m src.data.clean` first.")

    if DEFAULT_TEMPLATE_OUT.exists():
        labeled = pd.read_csv(DEFAULT_TEMPLATE_OUT, dtype=str, keep_default_na=False)
        # Drop unfilled placeholder rows so empty templates don't skew the summary.
        labeled = labeled[~labeled["text"].str.startswith(PLACEHOLDER_PREFIX)].copy()
        if not labeled.empty:
            labeled["source"] = "hand_labeled"
            labeled["char_count"] = labeled["text"].str.len()
            labeled["word_count"] = _word_count(labeled["text"])
            frames.append(labeled[ingest.UNIFIED_COLUMNS])
            print(f"Included {len(labeled)} hand-labeled example(s) from {DEFAULT_TEMPLATE_OUT}.")

    if not frames:
        return pd.DataFrame(columns=ingest.UNIFIED_COLUMNS)
    return pd.concat(frames, ignore_index=True)


def print_summary(df: pd.DataFrame) -> None:
    """Print total samples, class distribution, and avg word count per class."""
    total = len(df)
    print("\n=== TooSmooth dataset summary ===")
    print(f"total samples: {total:,}")
    if total == 0:
        print("(no data)")
        return

    if "word_count" not in df.columns:
        df = df.assign(word_count=_word_count(df["text"]))

    print("\nclass distribution:")
    counts = df["label"].value_counts().reindex(ingest.LABELS, fill_value=0)
    avg_words = df.groupby("label")["word_count"].mean()
    print(f"  {'label':<16}{'count':>10}{'share':>9}{'avg_words':>11}")
    for label in ingest.LABELS:
        n = int(counts[label])
        share = n / total
        aw = avg_words.get(label, float("nan"))
        aw_str = f"{aw:>11.1f}" if n else f"{'-':>11}"
        print(f"  {label:<16}{n:>10,}{share:>8.1%}{aw_str}")

    print(f"\noverall avg word count: {df['word_count'].mean():.1f}")

    present = counts[counts > 0]
    if len(present) < len(ingest.LABELS):
        missing = [l for l in ingest.LABELS if counts[l] == 0]
        print(f"note: no samples for {', '.join(missing)} yet.")
    elif present.max() / present.min() > 3:
        print("note: classes are imbalanced (>3x) — consider rebalancing before training.")


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        path = Path(argv[0])
        df = pd.read_csv(path, dtype={"text": str}, keep_default_na=False)
        print(f"Loaded {len(df):,} rows from {path}.")
    else:
        df = load_for_stats()
    print_summary(df)


if __name__ == "__main__":
    main()
