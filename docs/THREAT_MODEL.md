# TooSmooth Threat Model

This document defines *who* TooSmooth defends against, *what it detects*, *what it
explicitly does not do*, and the known ways an attacker can try to evade it.

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

## Adversary Model

- **Goal:** trick a recipient into a harmful action — credential entry, payment,
  malware execution, or disclosure of sensitive data.
- **Capabilities:** access to LLMs for fluent, scalable, personalized message
  generation; access to scraped or leaked context (name, employer, role, recent
  activity) for targeting; access to real brand/institutional register to imitate.
- **Channels in scope:** email and DM/chat-style text (the input the API and
  extension accept — see [CONVERSATION_GRAPH.md](CONVERSATION_GRAPH.md) for the
  multi-turn thread case, which is designed but not built).
- **Sophistication range:** from generic mass-market phishing kits to targeted,
  state-linked social engineering (see [CONVERSATION_GRAPH.md](CONVERSATION_GRAPH.md)
  for FAMOUS CHOLLIMA and Contagious Interview as motivating real-world cases for
  the v2 multi-turn design).

## What TooSmooth Detects

Manipulation expressed in the **message body**, split into two questions (see
[LABELING_GUIDE.md](LABELING_GUIDE.md) for the full schema):

1. **Intent** — does this message carry deceptive social-engineering intent
   (impersonation, manufactured urgency, a credential/payment lure)?
2. **Authorship** — if it's an attack, does the execution read as human-written or
   LLM-generated?

Six interpretable features feed both questions: urgency signal density,
personalization depth, authority-spoofing signals, emotional pressure, syntactic
smoothness, and manipulation-arc structure. Every verdict ships with the feature
scores that produced it — the point is triage-by-explanation, not a black-box
label.

## What TooSmooth Explicitly Does Not Do

- **Not a spam filter.** Bulk unwanted marketing with no deceptive intent is
  `legitimate` by design (see LABELING_GUIDE edge case 4); TooSmooth's target is
  manipulation, not unwanted volume.
- **Not a URL/link scanner.** It does not resolve, sandbox, or reputation-check
  links, attachments, or domains. A message can be flagged purely on textual
  manipulation signal with no link present, and a malicious link inside an
  otherwise-neutral message is out of scope.
- **Not a real-time network or header monitor.** No SPF/DKIM/DMARC validation, no
  transport-layer or header forensics, no account-takeover detection from a
  compromised-but-real sending account.
- **Not attachment/binary analysis.** No file scanning, no static or dynamic
  malware analysis of anything a message links to or carries.
- **Not multi-turn (yet).** v1 scores one message in isolation. The slow-burn,
  trust-building attacks described in CONVERSATION_GRAPH.md are undetectable by
  design until v2 ships.

## Known Evasion Techniques

The hand-labeled `ai_phishing` set deliberately includes an adversarial "oddball"
batch — about a dozen examples built specifically to stress-test the smoothness
signal rather than to look like typical attacks. Three evasion patterns are
represented:

- **Adversarial typo injection.** Attacker-side prompting that scatters
  inconsistent typos over an otherwise structurally complete, well-arced message,
  attempting to fake the human-error tell that `syntactic_smoothness` looks for.
  The labeling guide's tell for this case (edge case 6): the errors are evenly
  distributed over an otherwise-uniform advanced vocabulary and intact persuasion
  structure — genuine careless human typing tends to be inconsistent in different
  ways (missing words, run-ons), not evenly noisy.
- **Low-pressure / casual framing.** Messages written in a deliberately casual,
  lowercase, Slack-DM or texting register ("hey — quick heads up...", "yo, one
  more thing...") to blend the ask into a peer-to-peer tone and avoid the
  institutional-register cues `authority_spoofing_signals` and
  `urgency_signal_density` are tuned to catch.
- **Short-form minimalism.** Terse, fragment-heavy, low-effort-seeming messages
  ("lol my bad", "got it, one more thing") that compress the manipulation arc down
  to something that doesn't visually resemble the classic rapport → pressure → ask
  structure, testing whether `manipulation_arc_indicators` still fires on a
  compressed arc.

These examples exist in training data specifically so the classifier has to learn
past them rather than only ever seeing textbook-clean phishing; the Day 6
evaluation's false-positive analysis (`docs/EVAL_RESULTS.md`) is the other half of
this same exercise — checking that adversarial-looking benign mail (marketing,
transactional receipts) doesn't get swept up alongside real evasion attempts.

## Assumptions & Limitations

- Text-only input; one message at a time — no thread/context modeling in v1.
- The "too smooth" signal degrades as benign senders also adopt AI drafting;
  smoothness alone is never sufficient on its own, intent features must co-fire.
  See LABELING_GUIDE edge case 3.
- The `ai_phishing` class is a small, hand-curated set (123 examples) rather than
  a large public corpus, so its coverage of both attack styles and evasion styles
  is necessarily partial — see `docs/EVAL_RESULTS.md` Limitations.
- Domain shift is an active, ongoing risk: the base corpus is email from the
  2000s–2010s, so modern transactional/SaaS mail (Vercel, GitHub, Stripe-style
  notifications) is a known hard case that requires deliberate hand-labeled
  counter-examples to avoid false-positiving (see `docs/EVAL_RESULTS.md`).
