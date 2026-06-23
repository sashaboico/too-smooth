# data/raw — Source & Provenance

The CSV files in this directory are **not committed** (excluded by `.gitignore`).
This file documents where they came from so the dataset can be reconstructed.

## Dataset

- **Name:** Phishing Email Dataset (consolidated)
- **Author:** Naser Abdullah Alam
- **Source:** https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
- **License:** CC BY-SA 4.0 (attribution + share-alike; commercial use permitted)
- **Retrieved:** 2026-06-23

### Why this dataset (and not IWSPA-AP)

The original target, **IWSPA-AP 2018**, is access-gated — it was only distributed
via EasyChair registration during the 2018 shared task (deadline Jan 28, 2018) and
has no public download. The cited GitHub repo (`vinayakumarr/IWSPA-AP-2018`) contains
only a README, and no genuine Kaggle mirror exists. This consolidated corpus is the
best maintained public substitute.

## How to re-download

Requires the Kaggle CLI and an API token at `~/.kaggle/kaggle.json`.

```bash
python3 -m pip install --user kaggle
python3 -m kaggle datasets download -d naserabdullahalam/phishing-email-dataset \
  -p data/raw --unzip
```

## Files

| File | Rows | Columns | label 0 (legit) / 1 (phish) | Notes |
|------|------|---------|------------------------------|-------|
| `phishing_email.csv` | 82,486 | `text_combined`, `label` | 39,595 / 42,891 | Merged, body-only. Balanced. Good default training table. |
| `CEAS_08.csv` | 39,154 | sender, receiver, date, subject, body, urls, label | 17,312 / 21,842 | Keeps sender/subject/url metadata. |
| `Enron.csv` | 29,767 | subject, body, label | 15,791 / 13,976 | Legit-heavy corporate mail. |
| `SpamAssasin.csv` | 5,809 | sender, receiver, date, subject, body, urls, label | 4,091 / 1,718 | Classic spam/ham. |
| `Nigerian_Fraud.csv` | 3,332 | sender, receiver, date, subject, body, urls, label | 0 / 3,332 | Pure phishing (419 scams). |
| `Ling.csv` | 2,859 | subject, body, label | 2,401 / 458 | Legit-heavy. |
| `Nazario.csv` | 1,565 | sender, receiver, date, subject, body, urls, label | 0 / 1,565 | Pure phishing. |

## Mapping to the TooSmooth 3-class schema

This corpus covers only **two** of the three classes:

- `label 0` → **legitimate**
- `label 1` → **human_phishing**
- **ai_phishing** → NOT in this corpus. Must be sourced/generated separately
  (LLM-produced phishing). This is the novel contribution of the TooSmooth dataset.

Note: the source CSVs retain `sender` / `subject` / `urls` metadata that the merged
`phishing_email.csv` drops — useful for the `authority_spoofing_signals` and
`personalization_depth_score` features. Prefer the source files where that signal matters.

## Attribution (required by CC BY-SA 4.0)

> Phishing Email Dataset by Naser Abdullah Alam, licensed under CC BY-SA 4.0.
> https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
