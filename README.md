# TooSmooth

![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-009688)
![sklearn](https://img.shields.io/badge/scikit--learn-F7931E)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4)
![MIT License](https://img.shields.io/badge/license-MIT-informational)

An AI-augmented social-engineering detector. It classifies a message as
`legitimate`, `human_phishing`, or `ai_phishing` by extracting interpretable
manipulation features and running them through an explainable classifier — every
verdict ships with the signals that produced it, not just a label.

## Why This Exists

Phishing keeps climbing despite years of awareness training, for one stubborn reason:
attacks target people — the weakest link in any defense system (Jabir et al., 2025).

Generative AI has reshaped that threat. AI-written phishing reads like genuine
correspondence — fluent, with none of the grammatical tells defenders learned to spot —
and it scales: high-volume automation paired with strategic, per-target tailoring that
traditional filters were never built to catch (Jabir et al., 2025). The shift is already
visible in the breach data: 16% of breaches now involve attackers using AI, most often to
power phishing and deepfake attacks, and generative AI has cut the time to craft a
convincing phishing email from roughly 16 hours down to minutes (IBM Cost of a Data
Breach, 2025).

And the stakes are concrete. Phishing was the most common initial attack vector in 2025 —
16% of all breaches — averaging $4.8M per incident (IBM Cost of a Data Breach, 2025).

The old defense — "look for the typos" — stops working once the typos are gone.
TooSmooth detects not just *that* a message is suspicious but *why*, surfacing which
manipulation patterns fired so security teams can triage faster and users can see what
an AI-generated attack actually looks like.

## Architecture

```
   Gmail / any email or DM
          │  (user pastes text)
          ▼
  Chrome Extension (MV3 popup)
          │  POST /analyze { text }
          ▼
   FastAPI backend  ── CORS-enabled for the extension origin
          │
          ▼
  FeatureExtractor (6 interpretable scores)
          +
  TfidfVectorizer (5000 features, 1–2 grams)
          │  FeatureUnion
          ▼
  LogisticRegression  (class_weight="balanced", 0.6 attack-confidence threshold)
          │
          ▼
  Verdict Card: label · risk score (0–100) · per-feature scores + reasons · top flags
```

## How It Works

**Features.** A `FeatureExtractor` computes six interpretable scores, each a float in
`[0, 1]`: urgency signal density, personalization depth, authority-spoofing signals,
emotional pressure, syntactic smoothness (the core "too smooth" AI-authorship tell), and
manipulation-arc structure (rapport → pressure → ask). Each score comes with a
plain-English reason string, so a verdict is always auditable.

**Classifier.** The six feature scores are combined with a TF-IDF vectorizer via
`FeatureUnion` and fed into a `LogisticRegression` classifier — chosen over
`GradientBoosting` for a better legitimate-email false-positive rate at comparable
accuracy (see Evaluation below). The decision threshold is tuned, not left at the
default 0.5 argmax, because flagging a real message costs more than missing one attack.

**API.** A FastAPI service exposes `POST /analyze` (returns label, confidence, risk
score, the 6-feature breakdown, and top flags) and `GET /health`. The model loads once
at startup, CORS is scoped to the extension's origin, and a global exception handler
guarantees no raw traceback ever reaches the client.

**Extension.** A Manifest V3 Chrome extension with a simple paste-text popup — no
content script reading your inbox DOM, no broad host permissions. Paste a message, hit
Analyze (or Cmd/Ctrl+Enter), and get the same explainable verdict card the API returns,
color-coded green/yellow/red by risk score.

## Quickstart

```bash
git clone https://github.com/sashaboico/too-smooth
cd too-smooth
pip install -r requirements.txt
python -m spacy download en_core_web_sm
uvicorn src.api.main:app --reload
# then load extension/ in chrome://extensions (enable Developer mode -> Load unpacked)
```

The API expects a trained model at `models/classifier_lr.pkl`. To train it yourself:

```bash
python -m src.classifier.train
```

See [models/README.md](models/README.md) for the full training-data and reproduction
details.

## Evaluation

Held-out 80/20 stratified split (no leakage — models are refit on the train fold only
for evaluation; see [docs/EVAL_RESULTS.md](docs/EVAL_RESULTS.md) for full methodology,
confusion matrix, and false-positive analysis).

| Model | Precision (macro) | Recall (macro) | F1 (macro) | FP Rate (legitimate) |
|---|---|---|---|---|
| **LogisticRegression** (selected) | 0.91 | 0.96 | 0.93 | 3.9% |
| GradientBoosting | 0.90 | 0.92 | 0.91 | 8.5% |

At the deployed attack-confidence threshold (0.6): **3.3% legitimate false-positive
rate** while still recovering **89.8% of true attacks** — the tradeoff that matters most
for a consumer-facing tool, where flagging a real bank alert is worse than missing one
attack.

## Documentation

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — adversary model, what TooSmooth
  detects and explicitly doesn't, known evasion techniques.
- [docs/LABELING_GUIDE.md](docs/LABELING_GUIDE.md) — the 3-class labeling schema,
  decision tree, and edge cases used to build the training data.
- [docs/EVAL_RESULTS.md](docs/EVAL_RESULTS.md) — full evaluation methodology, per-class
  metrics, confusion matrix, and false-positive threshold tuning.
- [docs/CONVERSATION_GRAPH.md](docs/CONVERSATION_GRAPH.md) — designed-not-built v2
  architecture for multi-turn, long-con manipulation detection.
- [models/README.md](models/README.md) — trained model artifacts and how to reproduce
  them.

## Roadmap

- [x] Single-message classifier (v1 — current)
- [ ] Conversation graph arc detection (v2 — see [docs/CONVERSATION_GRAPH.md](docs/CONVERSATION_GRAPH.md))
- [ ] Multi-channel support (SMS, Slack, voice transcripts)
- [ ] Railway deployment
- [ ] Chrome Web Store publication

## References

- Jabir, R., Le, J., & Nguyen, C. (2025). Phishing Attacks in the Age of Generative
  Artificial Intelligence: A Systematic Review of Human Factors. *AI*, 6(8), 174.
  https://doi.org/10.3390/ai6080174
- IBM Cost of a Data Breach Report (2025). https://www.ibm.com/reports/data-breach
- CrowdStrike, Famous Chollima Adversary Profile.
  https://www.crowdstrike.com/en-us/adversaries/famous-chollima/

## License

[MIT](LICENSE)
