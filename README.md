# TooSmooth

An AI-augmented social-engineering detector. It classifies a message as
`legitimate`, `human_phishing`, or `ai_phishing` by extracting interpretable
manipulation features and running them through an explainable sklearn classifier.

## What it does

Takes a single message (email, DM, SMS) and returns a label plus the per-feature
scores behind that label. The verdict is always accompanied by the signals that
produced it — no black-box embeddings.

## Why it exists

LLMs let attackers mass-produce phishing that is fluent, deeply personalized, and
free of the typos defenders have long relied on. TooSmooth flips that fluency into a
signal: it looks for messages that are *too smooth* to be the human scam they imitate.

## How it works

A `FeatureExtractor` computes six interpretable features (each a float in `[0, 1]`),
which feed an explainable classifier:

- **urgency_signal_density** — time-pressure / scarcity cues per unit of text.
- **personalization_depth_score** — how deeply tailored to a specific recipient.
- **authority_spoofing_signals** — impersonation of a trusted person/brand/institution.
- **emotional_pressure_index** — intensity of fear/greed/guilt/curiosity appeals.
- **syntactic_smoothness** — grammatical fluency and stylistic uniformity (the core
  "too smooth" signal).
- **manipulation_arc_indicators** — presence of a structured rapport → pressure → ask arc.

## Quickstart

```bash
# placeholder — pipeline not yet wired up
pip install -r requirements.txt
uvicorn src.api.main:app --reload
# POST /classify { "text": "..." }  ->  { label, scores, features }
```

## Roadmap

- **Day 1** — repo scaffold, feature stubs, labeling guide. *(current)*
- **Day 2+** — implement the six feature extractors.
- Build and label the dataset (`data/labeled/`).
- Train the explainable classifier (`src/classifier/train.py`); publish
  `docs/EVAL_RESULTS.md`.
- Wire the model into the `/classify` API with per-feature explanations.
- Threat-model writeup and adversarial / evasion testing.
