# models/

Trained, serialized TooSmooth classifiers. The `.pkl` files are **not committed**
(`*.pkl` is gitignored); this README documents how to reproduce them.

## Files

| File | What it is |
|------|------------|
| `classifier_lr.pkl` | `LogisticRegression` pipeline (TF-IDF + 6 manipulation features via `FeatureUnion`). The **interpretable** model — per-feature coefficients are readable, so a verdict can be explained. |
| `classifier_gb.pkl` | `GradientBoostingClassifier` pipeline (same feature union, densified). The **higher-performance** model — usually stronger, but less transparent. |

Both are full sklearn pipelines: they accept **raw text** and handle vectorization +
manipulation-feature extraction internally, so inference is `model.predict([text])`.

## Why two models

The interpretability-vs-performance tradeoff is the whole reason TooSmooth exists. We
keep the logistic-regression model because a defender can read *why* it fired (linear
coefficients over named features); we keep gradient boosting because it typically wins
on raw accuracy. Day 6 evaluation compares them and picks the operating point.

## Training data version

- **Source:** `data/processed/cleaned.csv` (Day 2 pipeline output — `legitimate` +
  `human_phishing`, ~145k rows) merged with `data/labeled/ai_phishing_examples.csv`
  (123 hand-curated `ai_phishing` examples).
- **Balancing:** majority classes down-sampled to ≤1,500 rows each (all 123
  `ai_phishing` kept), because the manipulation features run spaCy per document and the
  full corpus is intractable to cross-validate. Residual imbalance is handled with
  `class_weight='balanced'` (LogisticRegression) and balanced `sample_weight`
  (GradientBoosting) — without this the classifier learns to ignore the rare
  `ai_phishing` class.
- **Validation:** 5-fold `StratifiedKFold`, macro-F1 (weights all three classes equally).

## Date trained

2026-07-01 (initial Day 5 training).

## Reproduce

```bash
python -m src.classifier.train          # default: <=1500 per majority class
python -m src.classifier.train 3000     # raise the cap to trade time for more data
```
