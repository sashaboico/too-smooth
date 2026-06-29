# TooSmooth

An AI-augmented social-engineering detector. It classifies a message as
`legitimate`, `human_phishing`, or `ai_phishing` by extracting interpretable
manipulation features and running them through an explainable sklearn classifier.

## What it does

Takes a single message (email, DM, SMS) and returns a label plus the per-feature
scores behind that label. The verdict is always accompanied by the signals that
produced it — no black-box embeddings.

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

## References

- Jabir, R., Le, J., & Nguyen, C. (2025). Phishing Attacks in the Age of Generative
  Artificial Intelligence: A Systematic Review of Human Factors. *AI*, 6(8), 174.
  https://doi.org/10.3390/ai6080174
- IBM Cost of a Data Breach Report (2025). https://www.ibm.com/reports/data-breach
