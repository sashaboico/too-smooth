"""Clean and normalize the unified corpus, then persist it for feature extraction.

Pipeline (each step logs how many rows it drops):

  1. Normalize text   - unescape HTML entities, strip HTML tags, replace every URL
                        with ``[URL]`` and every email address with ``[EMAIL]``,
                        collapse whitespace. (No rows dropped; text is rewritten and
                        char/word counts are recomputed.)
  2. Drop empties      - rows that normalized down to nothing.
  3. Deduplicate       - drop rows with identical normalized text.
  4. Min-length filter - drop rows under ``MIN_WORDS`` words (too short to extract the
                        interpretable manipulation features reliably).

Output: ``data/processed/cleaned.csv`` with the same schema as ingest
(text, label, source, char_count, word_count).

Run:
    python -m src.data.clean
"""

from __future__ import annotations

import html
import logging
import re
from pathlib import Path

import pandas as pd

from src.data import ingest

logger = logging.getLogger(__name__)

MIN_WORDS = 20

DEFAULT_UNIFIED_IN = ingest.DEFAULT_UNIFIED_OUT  # data/processed/unified.csv
DEFAULT_CLEANED_OUT = Path("data/processed/cleaned.csv")

# Placeholder tokens. ``[URL]``/``[EMAIL]`` deliberately survive as standalone words:
# the feature extractor reads them as signals ("this message contained a link") without
# leaking the raw destination into the training data.
URL_TOKEN = "[URL]"
EMAIL_TOKEN = "[EMAIL]"

_HTML_TAG_RE = re.compile(r"<[^>]+>")
# URLs first (an email address never starts with a scheme), then bare emails.
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Strip HTML, mask URLs/emails, and collapse whitespace for one message."""
    if not isinstance(text, str):
        return ""
    text = html.unescape(text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _URL_RE.sub(URL_TOKEN, text)
    text = _EMAIL_RE.sub(EMAIL_TOKEN, text)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def clean_dataframe(df: pd.DataFrame, min_words: int = MIN_WORDS) -> pd.DataFrame:
    """Run the full cleaning pipeline on a unified-schema DataFrame."""
    start = len(df)
    logger.info("Starting clean: %d rows", start)

    df = df.copy()
    df["text"] = df["text"].map(normalize_text)

    before = len(df)
    df = df[df["text"] != ""].copy()
    logger.info("Drop empty-after-normalize: -%d (%d remain)", before - len(df), len(df))

    before = len(df)
    df = df.drop_duplicates(subset="text").copy()
    logger.info("Deduplicate on text: -%d (%d remain)", before - len(df), len(df))

    # Recompute counts against the *normalized* text before filtering on length.
    df["char_count"] = df["text"].str.len()
    df["word_count"] = df["text"].str.split().str.len()

    before = len(df)
    df = df[df["word_count"] >= min_words].copy()
    logger.info("Drop < %d words: -%d (%d remain)", min_words, before - len(df), len(df))

    logger.info("Done: %d -> %d rows (%.1f%% retained)", start, len(df), 100 * len(df) / max(start, 1))
    return df[ingest.UNIFIED_COLUMNS].reset_index(drop=True)


def load_unified(unified_in: Path = DEFAULT_UNIFIED_IN) -> pd.DataFrame:
    """Load the cached unified table, rebuilding it from raw if absent."""
    if unified_in.exists():
        logger.info("Reading cached unified table %s", unified_in)
        return pd.read_csv(unified_in, dtype={"text": str}, keep_default_na=False)
    logger.info("No cached unified table; rebuilding from data/raw/ ...")
    return ingest.build_unified_dataframe()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    df = load_unified()
    cleaned = clean_dataframe(df)

    DEFAULT_CLEANED_OUT.parent.mkdir(parents=True, exist_ok=True)
    cleaned.to_csv(DEFAULT_CLEANED_OUT, index=False)
    print(f"\nWrote {len(cleaned):,} cleaned rows -> {DEFAULT_CLEANED_OUT}")


if __name__ == "__main__":
    main()
