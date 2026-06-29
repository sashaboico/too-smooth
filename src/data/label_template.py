"""Generate the hand-labeling CSV template for AI-phishing examples.

The ``ai_phishing`` class does not exist in any public corpus (see
``docs/LABELING_GUIDE.md``), so it has to be hand-curated. This writes an empty
template at ``data/labeled/ai_phishing_examples.csv`` for ~150 manually collected
AI-generated phishing samples.

Columns:
  - ``text``          the full message text of the AI-phishing sample.
  - ``label``         always ``ai_phishing`` for this file (kept explicit so the file
                      is self-describing and merges cleanly with other labeled data).
  - ``why_ai``        free-text rationale: *why you judged this AI-authored*, in terms
                      of the authorship tells from the labeling guide (uniform fluency,
                      complete persuasion arc, flawless register, scaled personalization,
                      absence of human error artifacts).
  - ``feature_hints`` comma-separated FeatureExtractor signals this sample exercises
                      (e.g. ``syntactic_smoothness, manipulation_arc_indicators``) —
                      a bridge from your human judgment to the model's features.

Five placeholder rows are written to show the format. Their ``text`` starts with
``PLACEHOLDER`` so downstream tooling (``src.data.stats``) can ignore unfilled rows.
Replace them with real samples; do not leave placeholders in the final file.

Run:
    python -m src.data.label_template
"""

from __future__ import annotations

import csv
from pathlib import Path

DEFAULT_TEMPLATE_OUT = Path("data/labeled/ai_phishing_examples.csv")

FIELDNAMES = ["text", "label", "why_ai", "feature_hints"]
PLACEHOLDER_PREFIX = "PLACEHOLDER"

# Illustrative-only rows: realistic *shapes* of an entry, with the text deliberately
# left as a PLACEHOLDER stub so nothing here pollutes the dataset if accidentally kept.
_EXAMPLE_ROWS = [
    {
        "text": "PLACEHOLDER — paste the full AI-phishing message text here (subject + body).",
        "label": "ai_phishing",
        "why_ai": "Uniform fluency with zero grammar errors and an even, professional "
        "tone throughout; reads machine-smooth rather than rushed.",
        "feature_hints": "syntactic_smoothness, authority_spoofing_signals",
    },
    {
        "text": "PLACEHOLDER — e.g. a flawless 'IT security' password-reset notice with a "
        "complete rapport -> justification -> pressure -> ask arc.",
        "label": "ai_phishing",
        "why_ai": "Complete, well-formed persuasion arc executed in a short message; "
        "human scammers usually jump straight to the ask.",
        "feature_hints": "manipulation_arc_indicators, urgency_signal_density",
    },
    {
        "text": "PLACEHOLDER — e.g. a bank fraud-alert clone reproducing institutional "
        "register perfectly, addressing the recipient by name and role.",
        "label": "ai_phishing",
        "why_ai": "Institutional register reproduced flawlessly plus deep personalization "
        "at apparent scale — an AI-enabled combination.",
        "feature_hints": "authority_spoofing_signals, personalization_depth_score",
    },
    {
        "text": "PLACEHOLDER — e.g. an 'HR benefits' message with calibrated, sustained "
        "emotional pressure and no tonal slips.",
        "label": "ai_phishing",
        "why_ai": "Sustained, well-modulated emotional pressure with consistent register; "
        "the smoothness signature, no human seams.",
        "feature_hints": "emotional_pressure_index, syntactic_smoothness",
    },
    {
        "text": "PLACEHOLDER — e.g. an AI draft with a few injected typos over an otherwise "
        "uniform, advanced-vocabulary body (evasion attempt).",
        "label": "ai_phishing",
        "why_ai": "Errors look superficial over an otherwise uniform, well-arced body — "
        "adversarial 'add typos to dodge too-smooth detection' case.",
        "feature_hints": "syntactic_smoothness, manipulation_arc_indicators",
    },
]


def write_template(path: Path = DEFAULT_TEMPLATE_OUT, overwrite: bool = False) -> Path:
    """Write the template CSV. Refuses to clobber an existing file unless ``overwrite``."""
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists — refusing to overwrite hand-labeled data. "
            "Pass overwrite=True only if you are sure it is unfilled."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(_EXAMPLE_ROWS)
    return path


def main() -> None:
    try:
        out = write_template()
    except FileExistsError as exc:
        print(exc)
        return
    print(f"Wrote labeling template -> {out}")
    print(f"Columns: {', '.join(FIELDNAMES)}")
    print(
        f"{len(_EXAMPLE_ROWS)} placeholder rows included to show the format. "
        "Replace them with ~150 real AI-phishing samples; the why_ai column is your "
        "per-sample rationale (leave nothing as PLACEHOLDER in the final file)."
    )


if __name__ == "__main__":
    main()
