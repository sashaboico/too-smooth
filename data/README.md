# data/

Everything the TooSmooth pipeline reads or writes. **No data is committed** —
`.gitignore` keeps the folders (via `.gitkeep`) but excludes their contents, since
samples may be sensitive. Only provenance docs (`raw/SOURCE.md`, this file) are tracked.

## Layout

| Subfolder | Contents | Produced by |
|-----------|----------|-------------|
| `raw/` | Original, untouched source corpora (one CSV per dataset; `.txt` email dumps also supported). | Downloaded manually — see [`raw/SOURCE.md`](raw/SOURCE.md). |
| `processed/` | Machine-generated tables: `unified.csv` (all sources merged into one schema) and `cleaned.csv` (normalized, deduped, filtered). | `python -m src.data.ingest`, then `python -m src.data.clean`. |
| `labeled/` | Hand-curated labels — currently `ai_phishing_examples.csv`, ~150 manually collected AI-phishing samples with written rationale. | Template from `python -m src.data.label_template`, then filled in by hand. |

## The 3-class schema

Every sample is mapped to one of: `legitimate`, `human_phishing`, `ai_phishing`.
See [`docs/LABELING_GUIDE.md`](../docs/LABELING_GUIDE.md) for the full definitions and
decision tree. Raw label mapping:

| Raw label | TooSmooth class |
|-----------|-----------------|
| `0`, `legitimate`, `ham` | `legitimate` |
| `1`, `phishing`, `spam` | `human_phishing` |
| `2`, `ai-generated`, `ai` | `ai_phishing` |

The base corpus covers only the first two classes. **`ai_phishing` exists in no public
corpus** and is the novel contribution of this project — it lives entirely in
`labeled/ai_phishing_examples.csv` and must be hand-curated.

## Provenance

- **`raw/`** — Consolidated Kaggle "Phishing Email Dataset" (Naser Abdullah Alam,
  CC BY-SA 4.0). The original target, IWSPA-AP 2018, is access-gated and was never
  publicly released; this is the maintained substitute. Full attribution and
  re-download instructions in [`raw/SOURCE.md`](raw/SOURCE.md). Component files overlap
  (`phishing_email.csv` is a merge of several others) — the clean step dedupes them.
- **PhishTank** (optional) — `ingest` will best-effort download verified phishing URLs
  from <https://data.phishtank.com/data/online-valid.csv> if reachable. The feed now
  requires an API key and is often blocked; failure is logged and skipped, never fatal.
- **`labeled/`** — Original work for this project; rationale recorded per-sample in the
  `why_ai` column.

## Pipeline order

```bash
python -m src.data.ingest          # raw/*  ->  processed/unified.csv
python -m src.data.clean           # unified.csv  ->  processed/cleaned.csv
python -m src.data.label_template  # writes labeled/ai_phishing_examples.csv template
python -m src.data.stats           # prints class balance over cleaned + hand-labeled
```
