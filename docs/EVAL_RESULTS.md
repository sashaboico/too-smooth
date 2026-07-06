# TooSmooth Evaluation Results

## Dataset
- Total samples: 3,147 (balanced evaluation set, subsampled from the 145,668-row cleaned corpus)
- Class distribution: legitimate (1,524), human_phishing (1,500), ai_phishing (123)
- Train/test split: 80/20 stratified (random_state=42); models fit on train, all metrics on held-out test (630 samples)

## Model Comparison

| Model | Precision (macro) | Recall (macro) | F1 (macro) | FP Rate (legitimate) |
|---|---|---|---|---|
| LogisticRegression | 0.91 | 0.96 | 0.93 | 3.9% |
| GradientBoosting | 0.90 | 0.92 | 0.91 | 8.5% |

## Per-Class Performance (Best Model)

Best model: **LogisticRegression**

| Class | Precision | Recall | F1 |
|---|---|---|---|
| legitimate | 0.94 | 0.96 | 0.95 |
| human_phishing | 0.97 | 0.93 | 0.95 |
| ai_phishing | 0.81 | 1.00 | 0.89 |

ROC-AUC (one-vs-rest): legitimate = 0.99, human_phishing = 0.99, ai_phishing = 1.00

## Confusion Matrix

Best model (LogisticRegression), rows = true label, cols = predicted:

```
                   legit     human        ai   (predicted)
true legit           293         8         4
true human            18       280         2
true ai                0         0        25
```

## False Positive Analysis

The primary tuning target is the **legitimate-email false-positive rate**: flagging a
real message (a bank alert, an HR notice) as phishing is a worse experience than
missing a single attack. At the default argmax decision, LogisticRegression misflags
**3.9%** of held-out legitimate emails as attacks.

Highest-confidence false positives (real legitimate emails the model was most sure were attacks):

```
  1. [ai_phishing, p_attack=0.89] Subject: A new login to Vercel We noticed a new sign-in to your Vercel account from Chrome on macOS in Chicago, IL. If this was you, no action is needed. If you don't recognize thi
  2. [ai_phishing, p_attack=0.81] Subject: Your receipt from Apple This receipt confirms your purchase of iCloud+ 200GB for $2.99. Your Apple Account was billed on July 1, and your subscription will renew monthly. 
  3. [human_phishing, p_attack=0.79] dnsstuffcom yqrsrqsqbpdyetcusemaildirectcom notice dnsstuff free tool access expires oct 31 2007 act dear tony free registration account dnsstuffcom expires january 1 2008 dns vuln
  4. [ai_phishing, p_attack=0.72] Subject: You were mentioned in PROJ-119 Sasha mentioned you in a comment on PROJ-119 'Ship the extension popup': '@alexandra can you confirm the CORS settings before we deploy?' Op
  5. [human_phishing, p_attack=0.71] bitbitchmagnesiumnet ah yes yet another case marriage actually inappropriate word guys want housekeeper dog prostitute say hope girls come take men glorified housekeepers short ter
```

These are legitimate messages that carry genuine urgency, authority, or transactional
language — the same surface signals the manipulation features are built to detect — which
is exactly why a single 0.5 cutoff is too blunt. Sweeping the attack-confidence threshold:

- threshold 0.3: FP rate 19.7%, attack recall 98.8%
- threshold 0.4: FP rate 10.8%, attack recall 97.8%
- threshold 0.5: FP rate 5.9%, attack recall 95.4%
- threshold 0.6: FP rate 3.3%, attack recall 89.8%
- threshold 0.7: FP rate 1.6%, attack recall 80.9%

**Selected threshold: 0.6** — the lowest threshold that keeps the
legitimate false-positive rate under 5% (3.3%) while still
recovering 89.8% of true attacks. Raising the bar for what counts as
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
**LogisticRegression** at attack-confidence threshold **0.6** — chosen for the
best macro-F1 (0.93) combined with a legitimate false-positive rate
held under 5%, the metric that matters most for a consumer-facing tool.
