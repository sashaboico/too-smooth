"""Data ingestion, cleaning, and labeling pipeline for TooSmooth.

Submodules:
  - ``ingest``         load raw corpora into a unified DataFrame.
  - ``clean``          normalize text and filter the unified DataFrame.
  - ``label_template`` emit the hand-labeling CSV template for ai_phishing.
  - ``stats``          print a dataset summary (class balance, word counts).

All are runnable as modules, e.g. ``python -m src.data.ingest``.
"""

from __future__ import annotations
