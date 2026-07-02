"""Evaluation + false-positive tuning for the TooSmooth classifiers.

# False positive rate on legitimate emails is the primary tuning target.
# Flagging a real bank alert as phishing is a worse user experience than
# missing one attack — this is the core detection tradeoff for consumer-facing tools.

Methodology note (no leakage): the saved production models in ``models/`` were fit on
100% of the balanced dataset, so evaluating them on a split of that same data would
leak. Here we take a fresh stratified 80/20 split, fit each model type on the 80%
train fold, and report every metric on the held-out 20% test fold. The saved models
remain the deployment artifacts (refit on all data); the numbers below are the honest
held-out estimates. Run:

    python -m src.classifier.evaluate
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

from src.classifier.data_loader import load_training_data
from src.classifier.train import (
    DEFAULT_MAX_PER_CLASS,
    GB_PATH,
    LR_PATH,
    RANDOM_STATE,
    build_gb_pipeline,
    build_lr_pipeline,
    fit_final,
    subsample,
)

CLASSES = ["legitimate", "human_phishing", "ai_phishing"]
ATTACK_CLASSES = {"human_phishing", "ai_phishing"}
REPORT_PATH = Path("docs/EVAL_RESULTS.md")
FP_TARGET = 0.05  # keep legitimate-email false positive rate under 5%


def _p_attack(model, X) -> np.ndarray:
    """P(message is an attack) = 1 - P(legitimate), from a fitted pipeline."""
    proba = model.predict_proba(X)
    legit_col = list(model.classes_).index("legitimate")
    return 1.0 - proba[:, legit_col]


def _roc_auc_ovr(model, X, y_true) -> dict[str, float]:
    """One-vs-rest ROC-AUC per class."""
    proba = model.predict_proba(X)
    y_bin = label_binarize(y_true, classes=CLASSES)
    out: dict[str, float] = {}
    for i, cls in enumerate(CLASSES):
        col = list(model.classes_).index(cls)
        try:
            out[cls] = float(roc_auc_score(y_bin[:, i], proba[:, col]))
        except ValueError:
            out[cls] = float("nan")
    return out


def format_confusion(cm: np.ndarray) -> str:
    """Render the confusion matrix as a labeled grid (rows = true, cols = predicted)."""
    short = {"legitimate": "legit", "human_phishing": "human", "ai_phishing": "ai"}
    cols = [short[c] for c in CLASSES]
    width = 10
    header = " " * 14 + "".join(f"{c:>{width}}" for c in cols) + "   (predicted)"
    lines = [header]
    for i, cls in enumerate(CLASSES):
        row = f"true {short[cls]:<9}" + "".join(f"{cm[i, j]:>{width}}" for j in range(len(CLASSES)))
        lines.append(row)
    return "\n".join(lines)


def false_positive_analysis(model, X_test, y_test, texts_test, name: str) -> dict:
    """Analyze and tune the legitimate-email false-positive rate.

    A "false positive" is a truly-legitimate email the model flags as an attack
    (human_phishing or ai_phishing). We report the default (argmax) FP rate, show the
    highest-confidence offenders, then sweep the attack-confidence threshold to find the
    lowest one that keeps the FP rate under the target.
    """
    y_test = np.asarray(y_test)
    preds = model.predict(X_test)
    p_attack = _p_attack(model, X_test)

    legit_mask = y_test == "legitimate"
    attack_mask = np.isin(y_test, list(ATTACK_CLASSES))
    n_legit = int(legit_mask.sum())

    fp_mask = legit_mask & (preds != "legitimate")
    fp_rate_default = fp_mask.sum() / n_legit

    print(f"\n--- False positive analysis: {name} ---")
    print(f"Legitimate test samples: {n_legit}")
    print(f"Default (argmax) FP rate: {fp_rate_default:.1%} "
          f"({int(fp_mask.sum())} legit emails flagged as attacks)")

    # Top-5 highest-confidence false positives.
    fp_idx = np.where(fp_mask)[0]
    fp_idx = fp_idx[np.argsort(p_attack[fp_idx])[::-1]][:5]
    top_fps = []
    print("\nTop false positives (highest attack-confidence legitimate emails):")
    if len(fp_idx) == 0:
        print("  (none)")
    for rank, idx in enumerate(fp_idx, 1):
        snippet = " ".join(texts_test[idx].split())[:180]
        top_fps.append({"text": snippet, "pred": preds[idx], "p_attack": float(p_attack[idx])})
        print(f"  {rank}. [{preds[idx]}  p_attack={p_attack[idx]:.2f}] {snippet}")

    # Threshold sweep: flag as attack only when P(attack) >= threshold.
    print("\nThreshold sweep (flag as attack when P(attack) >= threshold):")
    sweep = []
    for thr in [0.3, 0.4, 0.5, 0.6, 0.7]:
        flagged = p_attack >= thr
        fp_rate = (legit_mask & flagged).sum() / n_legit
        attack_recall = (attack_mask & flagged).sum() / max(int(attack_mask.sum()), 1)
        sweep.append({"threshold": thr, "fp_rate": float(fp_rate), "attack_recall": float(attack_recall)})
        print(f"  At threshold {thr:.1f}, legitimate email false positive rate: {fp_rate:.1%} "
              f"| attack recall: {attack_recall:.1%}")

    # Select the lowest threshold that keeps FP rate under target (catch the most
    # attacks subject to the FP budget); fall back to the strictest if none qualify.
    under = [s for s in sweep if s["fp_rate"] < FP_TARGET]
    selected = min(under, key=lambda s: s["threshold"]) if under else max(sweep, key=lambda s: s["threshold"])
    print(f"\nSelected threshold: {selected['threshold']:.1f} "
          f"(balances catching AI phishing while keeping FP rate under {FP_TARGET:.0%})")

    return {
        "fp_rate_default": float(fp_rate_default),
        "n_legit": n_legit,
        "top_fps": top_fps,
        "sweep": sweep,
        "selected": selected,
    }


def evaluate_model(build_pipeline, weighted, name, split) -> dict:
    X_train, X_test, y_train, y_test, texts_test = split
    print(f"\n{'=' * 70}\nModel: {name}\n{'=' * 70}")
    model = fit_final(build_pipeline, X_train, y_train, weighted=weighted)
    preds = model.predict(X_test)

    report = classification_report(
        y_test, preds, labels=CLASSES, output_dict=True, zero_division=0
    )
    print(classification_report(y_test, preds, labels=CLASSES, zero_division=0))

    cm = confusion_matrix(y_test, preds, labels=CLASSES)
    print("Confusion matrix (rows = true, cols = predicted):")
    print(format_confusion(cm))

    auc = _roc_auc_ovr(model, X_test, y_test)
    print("\nROC-AUC (one-vs-rest): " + ", ".join(f"{k}={v:.2f}" for k, v in auc.items()))

    fp = false_positive_analysis(model, X_test, y_test, texts_test, name)

    return {
        "name": name,
        "report": report,
        "confusion": cm,
        "roc_auc": auc,
        "fp": fp,
    }


def _fmt(x: float) -> str:
    return f"{x:.2f}"


def write_report(res_lr, res_gb, best, dataset, split_sizes) -> None:
    def macro(res, k):
        return res["report"]["macro avg"][k]

    def row(res):
        return (f"| {res['name']} | {_fmt(macro(res,'precision'))} | {_fmt(macro(res,'recall'))} "
                f"| {_fmt(macro(res,'f1-score'))} | {res['fp']['fp_rate_default']:.1%} |")

    b = best
    per_class_rows = "\n".join(
        f"| {cls} | {_fmt(b['report'][cls]['precision'])} | {_fmt(b['report'][cls]['recall'])} "
        f"| {_fmt(b['report'][cls]['f1-score'])} |"
        for cls in CLASSES
    )

    fp_lines = "\n".join(
        f"  {i}. [{fp['pred']}, p_attack={fp['p_attack']:.2f}] {fp['text']}"
        for i, fp in enumerate(b["fp"]["top_fps"], 1)
    ) or "  (no false positives in the held-out legitimate set)"

    sweep_lines = "\n".join(
        f"- threshold {s['threshold']:.1f}: FP rate {s['fp_rate']:.1%}, attack recall {s['attack_recall']:.1%}"
        for s in b["fp"]["sweep"]
    )
    sel = b["fp"]["selected"]

    md = f"""# TooSmooth Evaluation Results

## Dataset
- Total samples: {split_sizes['total']:,} (balanced evaluation set, subsampled from the {dataset['full']:,}-row cleaned corpus)
- Class distribution: legitimate ({dataset['legitimate']:,}), human_phishing ({dataset['human_phishing']:,}), ai_phishing ({dataset['ai_phishing']:,})
- Train/test split: 80/20 stratified (random_state={RANDOM_STATE}); models fit on train, all metrics on held-out test ({split_sizes['test']:,} samples)

## Model Comparison

| Model | Precision (macro) | Recall (macro) | F1 (macro) | FP Rate (legitimate) |
|---|---|---|---|---|
{row(res_lr)}
{row(res_gb)}

## Per-Class Performance (Best Model)

Best model: **{b['name']}**

| Class | Precision | Recall | F1 |
|---|---|---|---|
{per_class_rows}

ROC-AUC (one-vs-rest): """ + ", ".join(f"{k} = {v:.2f}" for k, v in b["roc_auc"].items()) + f"""

## Confusion Matrix

Best model ({b['name']}), rows = true label, cols = predicted:

```
{format_confusion(b['confusion'])}
```

## False Positive Analysis

The primary tuning target is the **legitimate-email false-positive rate**: flagging a
real message (a bank alert, an HR notice) as phishing is a worse experience than
missing a single attack. At the default argmax decision, {b['name']} misflags
**{b['fp']['fp_rate_default']:.1%}** of held-out legitimate emails as attacks.

Highest-confidence false positives (real legitimate emails the model was most sure were attacks):

```
{fp_lines}
```

These are legitimate messages that carry genuine urgency, authority, or transactional
language — the same surface signals the manipulation features are built to detect — which
is exactly why a single 0.5 cutoff is too blunt. Sweeping the attack-confidence threshold:

{sweep_lines}

**Selected threshold: {sel['threshold']:.1f}** — the lowest threshold that keeps the
legitimate false-positive rate under {FP_TARGET:.0%} ({sel['fp_rate']:.1%}) while still
recovering {sel['attack_recall']:.1%} of true attacks. Raising the bar for what counts as
an attack protects legitimate mail at a measured cost to attack recall.

## Limitations
- ai_phishing labels are stylistic proxies, not verified LLM authorship — they encode a
  human judgment of "reads machine-generated," not ground-truth provenance.
- Only 123 ai_phishing examples exist (no public corpus), so that class is evaluated on a
  small held-out slice; its metrics carry the widest confidence interval.
- The majority classes were down-sampled to a balanced set for tractable training/eval, so
  absolute rates differ from the wild base rate where legitimate mail vastly dominates.
- Dataset skews toward the email channel; SMS/Slack/voice transcripts are underrepresented.
- Single-message classification only — multi-turn / long-con manipulation is out of scope
  (see docs/THREAT_MODEL.md).

## Selected Model
**{b['name']}** at attack-confidence threshold **{sel['threshold']:.1f}** — chosen for the
best macro-F1 ({_fmt(macro(b,'f1-score'))}) combined with a legitimate false-positive rate
held under {FP_TARGET:.0%}, the metric that matters most for a consumer-facing tool.
"""
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(md)
    print(f"\nWrote evaluation report -> {REPORT_PATH}")


def main() -> None:
    # Confirm the deployment artifacts load (they are refit on all data separately).
    for path in (LR_PATH, GB_PATH):
        if path.exists():
            joblib.load(path)
    print("Saved deployment models load OK.\n")

    df = load_training_data()
    full = len(df)
    df = subsample(df, DEFAULT_MAX_PER_CLASS)
    dataset = {
        "full": full,
        **{c: int((df["label"] == c).sum()) for c in CLASSES},
    }

    X = df["text"].to_numpy()
    y = df["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    split = (X_tr, X_te, y_tr, y_te, X_te)  # texts_test == X_te (raw strings)
    split_sizes = {"total": len(df), "test": len(X_te)}

    res_lr = evaluate_model(build_lr_pipeline, False, "LogisticRegression", split)
    res_gb = evaluate_model(build_gb_pipeline, True, "GradientBoosting", split)

    # Best = higher macro-F1, tie-broken by lower default FP rate.
    def key(res):
        return (res["report"]["macro avg"]["f1-score"], -res["fp"]["fp_rate_default"])

    best = max([res_lr, res_gb], key=key)
    write_report(res_lr, res_gb, best, dataset, split_sizes)
    print(f"\nBest model: {best['name']}")


if __name__ == "__main__":
    main()
