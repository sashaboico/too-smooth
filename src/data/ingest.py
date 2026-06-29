"""Load raw phishing/legitimate corpora into one unified DataFrame.

The original target corpus, IWSPA-AP 2018, is access-gated and was never publicly
released (see ``data/raw/SOURCE.md``). In its place ``data/raw/`` holds the
consolidated Kaggle "Phishing Email Dataset", whose component CSVs use several
different schemas:

  - ``text_combined, label``                    (phishing_email.csv)
  - ``subject, body, label``                    (Enron.csv, Ling.csv)
  - ``sender, ..., subject, body, urls, label`` (CEAS_08, Nazario, Nigerian_Fraud, SpamAssasin)

This module reads whatever CSV (or ``.txt``) files live in ``data/raw/``, regardless
of which of those shapes they use, maps their labels onto the TooSmooth 3-class
schema, and returns a single tidy table:

    text, label, source, char_count, word_count

Label mapping (the raw corpus only covers two of the three classes):

    legitimate / 0 / ham   -> legitimate
    phishing   / 1 / spam  -> human_phishing
    ai-generated / 2       -> ai_phishing   (never present in the raw corpus)

Run as a module to build the unified table and cache it to
``data/processed/unified.csv``:

    python -m src.data.ingest
"""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

# --- 3-class schema -------------------------------------------------------

LEGITIMATE = "legitimate"
HUMAN_PHISHING = "human_phishing"
AI_PHISHING = "ai_phishing"
LABELS: tuple[str, ...] = (LEGITIMATE, HUMAN_PHISHING, AI_PHISHING)

# Map every label form we expect to encounter onto the canonical schema. Keys are
# compared lowercased and stripped. Integer labels are stringified before lookup,
# so the raw corpus's 0/1 ints land here too.
_LABEL_ALIASES: dict[str, str] = {
    # legitimate
    "0": LEGITIMATE,
    "legitimate": LEGITIMATE,
    "legit": LEGITIMATE,
    "ham": LEGITIMATE,
    "benign": LEGITIMATE,
    "safe": LEGITIMATE,
    # human phishing
    "1": HUMAN_PHISHING,
    "phishing": HUMAN_PHISHING,
    "phish": HUMAN_PHISHING,
    "spam": HUMAN_PHISHING,
    "human_phishing": HUMAN_PHISHING,
    "malicious": HUMAN_PHISHING,
    # ai phishing
    "2": AI_PHISHING,
    "ai": AI_PHISHING,
    "ai_phishing": AI_PHISHING,
    "ai-generated": AI_PHISHING,
    "ai_generated": AI_PHISHING,
    "generated": AI_PHISHING,
    "llm": AI_PHISHING,
}

# Column name candidates, in priority order.
_TEXT_COLUMNS = ("text", "text_combined", "body", "message", "content", "email")
_LABEL_COLUMNS = ("label", "class", "category", "target", "y")
_SUBJECT_COLUMNS = ("subject", "title")

# Files in data/raw/ that are documentation, not data.
_NON_DATA_FILES = {"SOURCE.md", "README.md", ".gitkeep", ".DS_Store"}

DEFAULT_RAW_DIR = Path("data/raw")
DEFAULT_UNIFIED_OUT = Path("data/processed/unified.csv")
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

UNIFIED_COLUMNS = ["text", "label", "source", "char_count", "word_count"]


# --- label mapping --------------------------------------------------------

def map_label(raw_label: object) -> str | None:
    """Map a raw label value onto the TooSmooth 3-class schema.

    Accepts ints (0/1/2), floats (1.0), or strings ("phishing", "ai-generated").
    Returns one of ``LABELS``, or ``None`` if the value is missing/unrecognized
    (callers drop ``None`` rows rather than guessing).
    """
    if raw_label is None or (isinstance(raw_label, float) and pd.isna(raw_label)):
        return None
    # Normalize "1.0" -> "1" so float-typed integer labels map cleanly.
    if isinstance(raw_label, float) and raw_label.is_integer():
        raw_label = int(raw_label)
    key = str(raw_label).strip().lower()
    mapped = _LABEL_ALIASES.get(key)
    if mapped is None:
        logger.warning("Unrecognized label %r — row will be dropped", raw_label)
    return mapped


# --- column detection -----------------------------------------------------

def _pick(columns: list[str], candidates: tuple[str, ...]) -> str | None:
    """Return the first candidate present in ``columns`` (case-insensitive)."""
    lower = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand in lower:
            return lower[cand]
    return None


def _build_text_series(df: pd.DataFrame) -> pd.Series | None:
    """Assemble the message text from whatever columns a frame provides.

    Prefers a single combined text column. Otherwise joins ``subject`` and ``body``
    (subject first) so authority/personalization signals carried by the subject line
    survive — the merged ``phishing_email.csv`` drops them, but the per-source CSVs
    keep them and the feature extractor cares about them.
    """
    text_col = _pick(list(df.columns), _TEXT_COLUMNS)
    if text_col is not None:
        return df[text_col].fillna("").astype(str)

    subject_col = _pick(list(df.columns), _SUBJECT_COLUMNS)
    body_col = _pick(list(df.columns), ("body", "content", "message"))
    parts = []
    if subject_col is not None:
        parts.append(df[subject_col].fillna("").astype(str))
    if body_col is not None:
        parts.append(df[body_col].fillna("").astype(str))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return (parts[0] + "\n" + parts[1]).str.strip()


# --- per-file loading -----------------------------------------------------

def _finalize(text: pd.Series, labels: pd.Series, source: str) -> pd.DataFrame:
    """Build the unified-schema frame for one source and drop unusable rows."""
    out = pd.DataFrame(
        {
            "text": text.astype(str).str.strip(),
            "label": labels.map(map_label),
            "source": source,
        }
    )
    before = len(out)
    out = out[(out["text"] != "") & out["label"].notna()].copy()
    dropped = before - len(out)
    if dropped:
        logger.info("  %s: dropped %d row(s) with empty text or unmapped label", source, dropped)
    out["char_count"] = out["text"].str.len()
    out["word_count"] = out["text"].str.split().str.len()
    return out[UNIFIED_COLUMNS]


def load_csv_file(path: Path) -> pd.DataFrame:
    """Load one raw CSV into the unified schema. Returns empty frame if unusable."""
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
    except Exception as exc:  # noqa: BLE001 - one bad file shouldn't kill the run
        logger.warning("Failed to read %s: %s", path.name, exc)
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    label_col = _pick(list(df.columns), _LABEL_COLUMNS)
    text = _build_text_series(df)
    if label_col is None or text is None:
        logger.warning(
            "Skipping %s: could not find label and/or text columns in %s",
            path.name,
            list(df.columns),
        )
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    return _finalize(text, df[label_col], source=path.stem)


def load_txt_file(path: Path) -> pd.DataFrame:
    """Load a plain-text email file as a single sample.

    IWSPA-AP shipped one email per ``.txt`` file under ``legit/`` and ``phish/``
    folders, so we infer the label from the path: a ``phish``/``spam``/``ai`` segment
    in the filename or any parent directory wins, else we fall back to ``legit``.
    Unlabelable files are skipped.
    """
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to read %s: %s", path.name, exc)
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    segments = " ".join(p.lower() for p in path.parts)
    if any(tok in segments for tok in ("ai_phish", "ai-phish", "ai_generated", "ai-generated")):
        raw = "ai_phishing"
    elif any(tok in segments for tok in ("phish", "spam", "malicious")):
        raw = "phishing"
    elif any(tok in segments for tok in ("legit", "ham", "benign")):
        raw = "legitimate"
    else:
        logger.warning("Skipping %s: cannot infer label from path", path)
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    return _finalize(pd.Series([body]), pd.Series([raw]), source=path.stem)


# --- PhishTank (optional, best-effort) ------------------------------------

def load_phishtank(url: str = PHISHTANK_URL, timeout: int = 20) -> pd.DataFrame:
    """Attempt to download live PhishTank verified-phishing URLs.

    PhishTank's feed is a list of confirmed phishing *URLs*, so each row becomes a
    one-line ``text`` (the URL) labeled ``human_phishing``. The feed now requires a
    registered API key and frequently returns 403/509, so this is strictly
    best-effort: on any failure (network, auth, rate-limit, parse) it logs a warning
    and returns an empty frame rather than raising.
    """
    try:
        import requests

        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "TooSmooth-research/0.1"})
        resp.raise_for_status()
        df = pd.read_csv(io.StringIO(resp.text), dtype=str, keep_default_na=False)
    except Exception as exc:  # noqa: BLE001 - network/auth/parse all handled the same
        logger.warning("PhishTank download skipped (%s): %s", type(exc).__name__, exc)
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    url_col = _pick(list(df.columns), ("url", "phish_url"))
    if url_col is None or df.empty:
        logger.warning("PhishTank response had no usable 'url' column; skipping")
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    logger.info("PhishTank: fetched %d verified phishing URLs", len(df))
    return _finalize(df[url_col], pd.Series(["phishing"] * len(df)), source="phishtank")


# --- orchestration --------------------------------------------------------

def load_raw_corpus(raw_dir: Path | str = DEFAULT_RAW_DIR) -> pd.DataFrame:
    """Load every CSV/txt sample under ``raw_dir`` into the unified schema."""
    raw_dir = Path(raw_dir)
    if not raw_dir.exists():
        raise FileNotFoundError(f"raw data directory not found: {raw_dir}")

    frames: list[pd.DataFrame] = []
    csv_paths = sorted(raw_dir.glob("*.csv"))
    txt_paths = sorted(raw_dir.rglob("*.txt"))

    for path in csv_paths:
        if path.name in _NON_DATA_FILES:
            continue
        logger.info("Loading %s ...", path.name)
        frame = load_csv_file(path)
        if not frame.empty:
            logger.info("  %s: %d usable rows", path.name, len(frame))
            frames.append(frame)

    for path in txt_paths:
        frame = load_txt_file(path)
        if not frame.empty:
            frames.append(frame)

    if not frames:
        logger.warning("No usable raw data found in %s", raw_dir)
        return pd.DataFrame(columns=UNIFIED_COLUMNS)

    return pd.concat(frames, ignore_index=True)


def build_unified_dataframe(
    raw_dir: Path | str = DEFAULT_RAW_DIR,
    include_phishtank: bool = True,
) -> pd.DataFrame:
    """Build the full unified table from local raw files plus (optional) PhishTank."""
    corpus = load_raw_corpus(raw_dir)
    if include_phishtank:
        phishtank = load_phishtank()
        if not phishtank.empty:
            corpus = pd.concat([corpus, phishtank], ignore_index=True)
    return corpus.reset_index(drop=True)


def _summarize(df: pd.DataFrame) -> str:
    if df.empty:
        return "  (no rows)"
    by_label = df["label"].value_counts().reindex(LABELS, fill_value=0)
    by_source = df["source"].value_counts()
    lines = [f"  total rows: {len(df):,}", "  by label:"]
    lines += [f"    {lbl:<16} {by_label[lbl]:>8,}" for lbl in LABELS]
    lines += ["  by source:"]
    lines += [f"    {src:<16} {cnt:>8,}" for src, cnt in by_source.items()]
    return "\n".join(lines)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    df = build_unified_dataframe()
    print("\nUnified raw corpus:")
    print(_summarize(df))

    DEFAULT_UNIFIED_OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DEFAULT_UNIFIED_OUT, index=False)
    print(f"\nWrote {len(df):,} rows -> {DEFAULT_UNIFIED_OUT}")
    print("Note: sources overlap (phishing_email.csv merges several of the others);")
    print("run `python -m src.data.clean` next to dedupe and normalize.")


if __name__ == "__main__":
    main()
