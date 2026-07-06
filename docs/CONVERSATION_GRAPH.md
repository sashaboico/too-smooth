# TooSmooth v2: Conversation Graph Architecture

> **Status: designed, not built.** This document specifies a v2 architecture that
> extends TooSmooth from single-message classification to multi-turn conversation
> analysis. Nothing in this file is implemented; it exists to show the threat model
> and the implementation path for the next iteration.

## Motivation: Why Single-Message Detection Isn't Enough

TooSmooth v1 scores one message at a time. That works for a spray-and-pray phishing
email, but it is structurally blind to a slower kind of attack: one where no single
message is suspicious, and the attack *is* the shape of the conversation over time.

Two real, DPRK-linked campaigns illustrate this. **FAMOUS CHOLLIMA** (CrowdStrike's name
for a North Korean state-linked adversary active since at least 2018) builds
gen-AI-crafted LinkedIn profiles and identity documents to pose as job candidates,
carries a fake identity through a full interview process — sometimes running real-time
deepfakes on the video call — and gets hired into legitimate companies as a remote IT
worker, which is later used for insider access or salary-funneling. CrowdStrike reported
insiders from this cluster had infiltrated over 320 companies in a 12-month window, a
220% year-over-year increase. A closely related campaign Microsoft tracks as
**Contagious Interview** runs the mirror image: operatives pose as *recruiters*,
courting developers over LinkedIn DMs for days or weeks, before sending a "coding
challenge" or npm package that deploys a backdoor the moment the victim runs it.

Neither campaign depends on a single deceptive message. Each individual DM reads like
ordinary recruiter or candidate outreach — that's the point. The signal is not in what
any one message says; it's in the arc across the thread: the length of the grooming
period, the direction and timing of escalation, the eventual channel switch or ask.
Detection lag compounds the problem — IBM's 2025 Cost of a Data Breach Report puts the
mean time to *identify* a breach at 158 days industry-wide — which is easily enough time
for a slow-burn thread to complete its arc long before anyone reviews the messages that
led to it.

The core insight: **manipulation is a process, not a moment.** v1 answers "is this
message suspicious?" v2 has to answer a different question: "is this *thread* going
somewhere it shouldn't?"

## Graph Schema

### Nodes
Each node represents one message in a conversation thread:

| Field | Type | Description |
|---|---|---|
| message_id | str | Unique identifier |
| text | str | Raw message content |
| timestamp | datetime | When message was sent |
| sender_id | str | Hashed sender identifier |
| toosmooth_scores | dict | All 6 feature scores from v1 |
| risk_score | float | v1 overall risk score 0–100 |
| label | str | v1 predicted label |

### Edges
Edges connect messages in the same conversation thread:

| Field | Type | Description |
|---|---|---|
| time_delta | float | Hours between messages |
| topic_drift | float | Semantic similarity shift between messages |
| escalation_delta | float | Change in risk_score from node A to node B |
| rapport_score | float | Cumulative trust-building signal across thread |

## Trust-Building Arc Detection

**Arc Type 1 — Slow Burn**
Low risk_score messages (< 30) for 3+ exchanges, then sudden escalation.
Signature: flat early graph, sharp edge escalation_delta spike.
Real-world example: Contagious Interview — a fake recruiter builds rapport over
LinkedIn DMs for days or weeks before sending a malicious "coding challenge" repo.

**Arc Type 2 — Authority Ladder**
Each message slightly increases authority_spoofing_signals score.
Sender gradually escalates claimed seniority or urgency.
Signature: monotonically increasing authority scores across nodes.
Real-world example: a FAMOUS CHOLLIMA candidate-persona escalating from "developer
applicant" to "let's discuss my start date and equipment shipping address" once the
process has advanced far enough that skepticism has relaxed.

**Arc Type 3 — Isolation Pattern**
Messages attempt to move conversation off-platform
("let's continue on WhatsApp / personal email").
Signature: channel-switch requests detected via keyword patterns.
Documented in threat intel as a precursor to payload delivery — moving off a monitored
corporate or platform channel removes the thread from any centralized detection surface,
v1 included.

**Arc Type 4 — Pressure Ramp**
urgency_signal_density and emotional_pressure_index scores
increase monotonically across the thread.
Signature: escalating edge escalation_delta values.

## Why Temporal Analysis Catches What v1 Misses

v1 scores each message independently, which means a patient attacker who keeps every
individual message below the detection threshold beats v1 entirely — and both
campaigns above are proof that real adversaries already operate this way. A conversation
graph catches the pattern across messages even when each individual message scores low:
the Slow Burn arc is invisible to v1 at message 4 because message 4 alone is a normal
recruiter follow-up, but a graph tracking escalation_delta over the whole thread flags
the shape immediately. In both the FAMOUS CHOLLIMA and Contagious Interview cases,
individual messages read as unremarkable professional outreach — it's the arc across
days or weeks that is the anomaly, and only a model that looks at the thread as a whole
can see it.

## Implementation Path

### Data Requirements
- Multi-turn conversation datasets (currently the primary bottleneck — no public labeled
  multi-turn social engineering corpus exists)
- Proposed labeling strategy: use v1 to score individual messages, then manually label
  conversation-level outcome (compromised / not compromised)

### Technical Stack
- Graph storage: Neo4j or NetworkX for prototyping
- Arc detection: sliding window across last N messages per sender
- New endpoint: `POST /analyze/thread` accepts array of messages, returns both
  per-message scores and thread-level arc classification
- Integration with v1: v2 calls v1's `/analyze` per message, then runs arc detection on
  the resulting score sequence

### Open Research Questions
- How many messages constitute a meaningful arc? (hypothesis: 3 minimum)
- How to handle multi-sender threads vs. single-sender campaigns?
- Cross-channel arc detection (email → LinkedIn → phone) requires identity resolution
  across platforms

## Relationship to MITRE ATT&CK

| Arc Type | ATT&CK Technique | Why it fits |
|---|---|---|
| Slow Burn | [T1566.003 – Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/) | The lure is delivered through a third-party social/professional platform (LinkedIn DMs), not email — the defining trait of this sub-technique. |
| Slow Burn (setup phase) | [T1585 – Establish Accounts](https://attack.mitre.org/techniques/T1585/) | Both campaigns depend on adversary-controlled recruiter or candidate personas built and aged before outreach begins. |
| Authority Ladder | [T1656 – Impersonation](https://attack.mitre.org/techniques/T1656/) | The technique is explicitly about assuming a false identity or persona to build trust with a target over the course of an operation. |
| Isolation Pattern | [T1534 – Internal Spearphishing](https://attack.mitre.org/techniques/T1534/) | Moving a target off a monitored platform onto a private or lateral channel mirrors this technique's goal of exploiting trust to reach a less-defended surface. |
| Pressure Ramp | [T1566 – Phishing](https://attack.mitre.org/techniques/T1566/) | The escalating urgency/pressure arc is the delivery mechanism for the technique's ultimate goal: getting the target to take the harmful action. |

## Sources

- CrowdStrike, [Famous Chollima Adversary Profile](https://www.crowdstrike.com/en-us/adversaries/famous-chollima/).
- Microsoft Security Blog (2026), [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/).
- IBM, [Cost of a Data Breach Report (2025)](https://www.ibm.com/reports/data-breach).
