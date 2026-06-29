# TooSmooth Threat Model

> Skeleton — to be expanded. This file captures *who* we defend against, *what* they
> can do, and *what TooSmooth assumes*.

## Traditional vs AI-Driven Phishing

| Aspect | Traditional Phishing | AI-Driven Phishing |
|---|---|---|
| Message Quality | Generic, grammatical errors | Mimics real communication, no errors |
| Personalisation | Broad, untargeted | Hyper-personalised per victim |
| Scale | Manual, limited | High-volume, automated |
| Targeting | Indiscriminate | Strategic, AI-driven analysis |
| Detection | Easier — errors are signals | Harder — no surface errors to catch |

*Source: Jabir et al. (2025), adapted.*

This table defines the detection gap TooSmooth is built to close.

## Adversary

- **Goal:** trick a recipient into a harmful action (credential entry, payment,
  malware execution, data disclosure).
- **Capabilities:** access to LLMs for fluent, scalable, personalized message
  generation; access to scraped/leaked context for targeting.
- **Not in scope (Day 1):** attachment/binary analysis, link/domain reputation,
  header/transport forensics, account-takeover from a real trusted account.

## What we detect

Manipulation expressed in the **message body**, and the authorship signature
(human vs. AI) of that text. See [LABELING_GUIDE.md](LABELING_GUIDE.md).

## Assumptions & limitations

- Text-only input; one message at a time (no thread/context modeling yet).
- The "too smooth" signal degrades as benign senders also adopt AI drafting —
  smoothness alone is never sufficient; intent features must co-fire.
- Evasion (deliberately injected errors, paraphrase attacks) is an open risk to be
  addressed in adversarial testing.

## TODO

- Attack-surface enumeration per channel (email / SMS / DM).
- Evasion taxonomy and red-team plan.
- False-positive cost analysis (flagging legitimate AI-assisted mail).
