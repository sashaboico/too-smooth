"""Interpretable manipulation feature extraction for social-engineering detection.

Each feature is designed to be human-auditable: a defender should be able to read
the score, read the message, and understand *why* the score is what it is. This is
deliberately not a black-box embedding — the whole point of TooSmooth is that the
signals separating AI-generated phishing from human phishing (and from legitimate
mail) are interpretable.

All six features are implemented with real logic. ``explain_all`` returns every
feature's score, a plain-English reason, and a risk level; ``overall_risk_score``
combines them into a single weighted 0–100 risk score (weights are class attributes
so they can be tuned during evaluation).
"""

from __future__ import annotations

import re
import statistics
from functools import lru_cache

# --- shared helpers -------------------------------------------------------

_WORD_RE = re.compile(r"\b\w+\b")
_SENTENCE_SPLIT_RE = re.compile(r"[.!?\n]+")


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text)


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_SPLIT_RE.split(text) if s.strip()]


def _clamp(x: float) -> float:
    """Clamp to the unit interval and coerce to ``float``."""
    return float(min(1.0, max(0.0, x)))


def _count_phrase_hits(text_lower: str, phrases: dict[str, float]) -> tuple[float, list[str]]:
    """Sum the weights of every phrase occurrence, returning (weight, matched phrases).

    Phrases are matched on word boundaries so ``"now"`` does not fire inside
    ``"known"``. Multi-word phrases ("act now", "within 24 hours") are matched literally.
    """
    total = 0.0
    matched: list[str] = []
    for phrase, weight in phrases.items():
        pattern = r"\b" + re.escape(phrase) + r"\b"
        n = len(re.findall(pattern, text_lower))
        if n:
            total += weight * n
            matched.append(phrase)
    return total, matched


@lru_cache(maxsize=1)
def _load_nlp():
    """Load the spaCy ``en_core_web_sm`` pipeline once, or ``None`` if unavailable.

    Loading is cached so we pay the cost a single time per process. We degrade
    gracefully — if spaCy or the model is missing, ``personalization_depth_score``
    falls back to a regex proper-noun heuristic instead of hard-failing — but the
    intended path uses spaCy NER.
    """
    try:
        import spacy

        return spacy.load("en_core_web_sm")
    except Exception:  # noqa: BLE001 - missing lib/model both degrade the same way
        return None


# --- keyword inventories --------------------------------------------------

# Strong, unambiguous time-pressure / scarcity cues (weight 1.0).
_URGENCY_STRONG: dict[str, float] = {
    "act now": 1.0,
    "act fast": 1.0,
    "immediately": 1.0,
    "urgent": 1.0,
    "urgently": 1.0,
    "expires": 1.0,
    "expire": 1.0,
    "expiring": 1.0,
    "deadline": 1.0,
    "last chance": 1.0,
    "final notice": 1.0,
    "final warning": 1.0,
    "within 24 hours": 1.0,
    "within 48 hours": 1.0,
    "right away": 1.0,
    "as soon as possible": 1.0,
    "time-sensitive": 1.0,
    "time sensitive": 1.0,
    "do not delay": 1.0,
    "don't delay": 1.0,
    "before it is too late": 1.0,
    "before it's too late": 1.0,
    "limited time": 1.0,
    "asap": 1.0,
}

# Weaker temporal nudges that only count when piled up (weight 0.5).
_URGENCY_WEAK: dict[str, float] = {
    "now": 0.5,
    "today": 0.5,
    "hurry": 0.5,
    "quickly": 0.5,
    "soon": 0.5,
    "instantly": 0.5,
}

# Consequence / threat language — the stick behind the deadline (weight 1.0).
_CONSEQUENCE: dict[str, float] = {
    "suspended": 1.0,
    "suspend": 1.0,
    "terminated": 1.0,
    "terminate": 1.0,
    "locked": 1.0,
    "lock": 1.0,
    "unauthorized": 1.0,
    "deactivated": 1.0,
    "deactivate": 1.0,
    "disabled": 1.0,
    "blocked": 1.0,
    "restricted": 1.0,
    "permanently closed": 1.0,
    "legal action": 1.0,
    "penalty": 1.0,
}

# Sentence-initial verbs that signal an imperative "do this" command.
_IMPERATIVE_VERBS = frozenset(
    {
        "click", "verify", "confirm", "act", "update", "call", "reply", "send",
        "pay", "log", "login", "review", "respond", "download", "open", "provide",
        "submit", "validate", "ensure", "complete", "follow", "visit", "enter",
        "claim", "reset", "sign", "do", "don't",
    }
)

# Institutional identities an attacker borrows to look legitimate.
_AUTHORITY_INSTITUTION: dict[str, float] = {
    "it department": 1.0,
    "it support": 1.0,
    "help desk": 1.0,
    "helpdesk": 1.0,
    "service desk": 1.0,
    "hr team": 1.0,
    "human resources": 1.0,
    "your bank": 1.0,
    "the bank": 1.0,
    "microsoft support": 1.0,
    "microsoft account": 1.0,
    "apple id": 1.0,
    "apple support": 1.0,
    "paypal": 1.0,
    "amazon": 1.0,
    "google": 1.0,
    "security team": 1.0,
    "support team": 1.0,
    "account team": 1.0,
    "fraud department": 1.0,
    "billing department": 1.0,
    "customer service": 1.0,
    "system administrator": 1.0,
    "administrator": 1.0,
    "irs": 1.0,
    "internal revenue service": 1.0,
    "account security": 1.0,
}

# Credential / identity-verification lures.
_AUTHORITY_CREDENTIAL: dict[str, float] = {
    "verify your identity": 1.0,
    "verify your account": 1.0,
    "verify your information": 1.0,
    "confirm your account": 1.0,
    "confirm your identity": 1.0,
    "confirm your password": 1.0,
    "confirm your details": 1.0,
    "update your password": 1.0,
    "update your payment": 1.0,
    "reset your password": 1.0,
    "validate your account": 1.0,
    "enter your password": 1.0,
    "provide your credentials": 1.0,
    "sign in to verify": 1.0,
    "log in to confirm": 1.0,
}

# Official-sounding boilerplate that borrows institutional register.
_AUTHORITY_BOILERPLATE: dict[str, float] = {
    "on behalf of": 1.0,
    "official notice": 1.0,
    "reference number": 1.0,
    "case number": 1.0,
    "ticket number": 1.0,
    "do not reply": 1.0,
    "automated message": 1.0,
}

# "your account will be suspended unless ..." — the urgency-authority combo.
_AUTHORITY_COMBO_RE = re.compile(
    r"\b(account|access|profile|membership|card)\b[^.!?]{0,60}?"
    r"\b(suspend|lock|terminat|disabl|clos|delet|restrict)",
    re.IGNORECASE,
)

# Specificity markers used by personalization scoring.
_MONEY_RE = re.compile(r"\$\s?\d[\d,]*(?:\.\d+)?|\b\d+\s?(?:dollars|usd)\b", re.IGNORECASE)
_ACCOUNT_RE = re.compile(
    r"\b(?:account|acct|card|ref(?:erence)?|case|ticket|order|invoice)\b[^.\n]{0,15}?\d{3,}"
    r"|\bending in\b\s*\d{2,}"
    r"|\b\d{6,}\b",
    re.IGNORECASE,
)
_DATE_RE = re.compile(
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2}"
    r"|\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b"
    r"|\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*\b",
    re.IGNORECASE,
)
_ADDRESS_RE = re.compile(r"\b(?:you|your|yours|you're|yourself)\b", re.IGNORECASE)
_GREETING_RE = re.compile(
    r"^\s*(?:hi|hello|dear|hey|greetings|good\s+(?:morning|afternoon|evening))\b[\s,]*([A-Z][a-z]+)?",
    re.IGNORECASE,
)

# --- emotional-pressure lexicons -----------------------------------------

# Loss/threat framing (the stick).
_EMOTION_THREAT: dict[str, float] = {
    "suspended": 1.0, "suspend": 1.0, "terminated": 1.0, "terminate": 1.0,
    "legal action": 1.0, "penalty": 1.0, "penalties": 1.0, "consequences": 1.0,
    "consequence": 1.0, "prosecuted": 1.0, "lawsuit": 1.0, "blocked": 1.0,
    "deleted": 1.0, "lose access": 1.0, "unauthorized": 1.0, "breach": 1.0,
    "compromised": 1.0, "fraud": 1.0, "locked": 1.0, "deactivated": 1.0,
    "frozen": 1.0,
}

# Gain/reward framing (the carrot).
_EMOTION_REWARD: dict[str, float] = {
    "bonus": 1.0, "reward": 1.0, "exclusive": 1.0, "selected": 1.0, "winner": 1.0,
    "won": 1.0, "prize": 1.0, "free": 1.0, "gift": 1.0, "congratulations": 1.0,
    "claim": 1.0, "offer": 1.0, "discount": 1.0, "cash": 1.0, "refund": 1.0,
}

# Fear-based time framing (weighted slightly lower; overlaps urgency by design).
_EMOTION_FEAR: dict[str, float] = {
    "immediately": 0.8, "before it's too late": 0.8, "before it is too late": 0.8,
    "final notice": 0.8, "act now": 0.8, "urgent": 0.8, "last chance": 0.8,
    "do not delay": 0.8, "right away": 0.8, "warning": 0.8, "alert": 0.8,
    "important notice": 0.8,
}

# --- manipulation-arc inventories ----------------------------------------

# Context / credibility framing that opens a persuasion arc ("the setup").
_ARC_SETUP: tuple[str, ...] = (
    "this is", "we are", "we noticed", "we detected", "we identified",
    "we have detected", "our records", "as part of", "reaching out",
    "regarding your", "on behalf of", "contacting you", "we wanted to",
    "we want to", "i am",
)

# Call-to-action language that closes a persuasion arc ("the ask"). Note: we use the
# two-word "log in" rather than "login", since the noun "login" ("login activity")
# is not a call-to-action and would misfire.
_CTA_PHRASES: tuple[str, ...] = (
    "click", "verify", "confirm", "log in", "sign in", "call", "reply",
    "pay", "provide", "update your", "follow this link", "link below", "download",
    "review your", "restore", "submit", "validate", "complete the form",
)

# Pressure language for the middle of the arc (union of urgency/threat cues).
_ARC_PRESSURE: tuple[str, ...] = tuple(
    set(_URGENCY_STRONG) | set(_URGENCY_WEAK) | set(_CONSEQUENCE)
    | set(_EMOTION_FEAR) | set(_EMOTION_THREAT)
)


def _earliest_match(sentences_lower: list[str], phrases) -> int | None:
    """Return the index of the first sentence containing any of ``phrases``."""
    for i, sent in enumerate(sentences_lower):
        for phrase in phrases:
            if re.search(r"\b" + re.escape(phrase) + r"\b", sent):
                return i
    return None


def _earliest_ask(sentences_lower: list[str]) -> int | None:
    """Return the index of the first sentence that issues a call-to-action.

    A sentence counts as an "ask" if it opens with an imperative verb or contains
    explicit CTA language ("verify", "click the link below", ...).
    """
    for i, sent in enumerate(sentences_lower):
        first = _words(sent)
        if first and first[0] in _IMPERATIVE_VERBS:
            return i
        for phrase in _CTA_PHRASES:
            if re.search(r"\b" + re.escape(phrase) + r"\b", sent):
                return i
    return None


class FeatureExtractor:
    """Extracts interpretable manipulation features from a single message.

    Usage:
        fx = FeatureExtractor()
        vector = fx.extract_all("Hi Sasha, your account ...")
        detail = fx.explain("Hi Sasha, your account ...")  # scores + plain-English reasons

    All feature methods accept the raw message text and return a float in [0, 1].
    Higher generally means "more of the manipulative property."
    """

    FEATURE_NAMES = (
        "urgency_signal_density",
        "personalization_depth_score",
        "authority_spoofing_signals",
        "emotional_pressure_index",
        "syntactic_smoothness",
        "manipulation_arc_indicators",
    )

    # All six features are now implemented with real logic.
    IMPLEMENTED = FEATURE_NAMES

    # --- tuning constants (class attributes so eval can adjust them) -------

    # Weighted urgency / emotional signals per word that saturate those scores.
    _URGENCY_SATURATION = 0.22
    _EMOTION_SATURATION = 0.14

    # Reference spreads for sentence-length variation; below these reads "smooth".
    _SMOOTHNESS_CV_REF = 0.65
    _SMOOTHNESS_RHYTHM_REF = 0.8

    # Weights for overall_risk_score — must cover every feature, sum ~1.0. Tunable.
    RISK_WEIGHTS = {
        "urgency_signal_density": 0.20,
        "authority_spoofing_signals": 0.20,
        "syntactic_smoothness": 0.20,
        "emotional_pressure_index": 0.15,
        "manipulation_arc_indicators": 0.15,
        "personalization_depth_score": 0.10,
    }

    # score < low -> "low"; < high -> "medium"; otherwise "high".
    RISK_THRESHOLDS = (0.34, 0.67)

    def extract_all(self, text: str) -> dict[str, float]:
        """Run every feature method and return a name -> score mapping.

        Returned in a stable order matching ``FEATURE_NAMES`` so the downstream
        classifier sees a consistent feature vector. Note: this still raises until the
        Day 4 features are implemented, because it invokes every method.
        """
        return {
            "urgency_signal_density": self.urgency_signal_density(text),
            "personalization_depth_score": self.personalization_depth_score(text),
            "authority_spoofing_signals": self.authority_spoofing_signals(text),
            "emotional_pressure_index": self.emotional_pressure_index(text),
            "syntactic_smoothness": self.syntactic_smoothness(text),
            "manipulation_arc_indicators": self.manipulation_arc_indicators(text),
        }

    def explain(self, text: str) -> dict[str, dict[str, object]]:
        """Run the implemented features and return scores with plain-English reasons.

        Returns ``{feature_name: {"score": float, "reason": str}}`` for each Day 3
        feature. The ``reason`` is a one-sentence justification a non-technical reader
        can follow — this is what the verdict-card UI surfaces so a flagged message is
        explainable, not just scored.
        """
        score_u, reason_u = self._urgency(text)
        score_p, reason_p = self._personalization(text)
        score_a, reason_a = self._authority(text)
        return {
            "urgency_signal_density": {"score": score_u, "reason": reason_u},
            "personalization_depth_score": {"score": score_p, "reason": reason_p},
            "authority_spoofing_signals": {"score": score_a, "reason": reason_a},
        }

    # --- Feature 1: urgency ------------------------------------------------

    def urgency_signal_density(self, text: str) -> float:
        """Density of time-pressure and scarcity cues per unit of text.

        Detects: explicit deadlines and scarcity ("act now", "within 24 hours",
        "last chance", "expires"), consequence/threat language ("suspended",
        "locked", "unauthorized"), and imperative commands, normalized by message
        length so short and long messages are comparable.

        Why it matters for AI attacks: LLMs reliably reproduce urgency because it is
        the single most effective phishing lever, but they deploy it *smoothly and
        repeatedly* without the typos a rushed human attacker leaves behind. High
        urgency density combined with high syntactic smoothness is a strong
        AI-phishing tell.

        A high score means the message packs many deadline/threat/command signals
        into little text — manufactured pressure rather than an incidental real
        deadline.

        Returns:
            float in [0, 1]; higher = more urgency pressure per token.
        """
        return self._urgency(text)[0]

    def _urgency(self, text: str) -> tuple[float, str]:
        lower = text.lower()
        words = _words(text)
        n_words = max(len(words), 1)

        strong, m_strong = _count_phrase_hits(lower, _URGENCY_STRONG)
        weak, _ = _count_phrase_hits(lower, _URGENCY_WEAK)
        conseq, m_conseq = _count_phrase_hits(lower, _CONSEQUENCE)

        imperatives = 0
        for sent in _sentences(text):
            first = _words(sent)
            if first and first[0].lower() in _IMPERATIVE_VERBS:
                imperatives += 1
        imperative_weight = min(imperatives, 3) * 0.5

        weighted = strong + weak + conseq + imperative_weight
        density = weighted / n_words
        score = _clamp(density / self._URGENCY_SATURATION)

        n_signals = len(m_strong) + len(m_conseq)
        if score >= 0.6:
            cues = ", ".join((m_strong + m_conseq)[:3]) or "imperative commands"
            reason = f"Dense time-pressure and threat language ({cues}) packed into a short message — manufactured urgency."
        elif n_signals or imperatives:
            reason = "Some urgency cues present, but spread thin relative to message length."
        else:
            reason = "No deadline, threat, or scarcity language detected."
        return score, reason

    # --- Feature 2: personalization ---------------------------------------

    def personalization_depth_score(self, text: str) -> float:
        """How deeply the message is tailored to a specific recipient.

        Detects (via spaCy ``en_core_web_sm`` NER plus regex): named entities
        (PERSON / ORG / GPE), direct-address density ("you" / "your"), specific
        references (dates, dollar amounts, account/reference numbers), and a named
        greeting ("Hi Sasha").

        Why it matters for AI attacks: generative models scaled with scraped or leaked
        context can produce *cheap, deep* personalization at volume — historically a
        marker of expensive spear-phishing. Deep personalization in a
        mass-distribution-shaped message is an AI-enabled capability.

        A high score means the text is heavily tailored to a specific person and their
        details; read alongside the other features, that tailoring is suspicious rather
        than reassuring.

        Returns:
            float in [0, 1]; higher = more recipient-specific tailoring.
        """
        return self._personalization(text)[0]

    def _personalization(self, text: str) -> tuple[float, str]:
        named = self._named_entities(text)
        entity_score = min(1.0, len(named) / 3.0)

        spec_hits = (
            len(_MONEY_RE.findall(text))
            + len(_ACCOUNT_RE.findall(text))
            + len(_DATE_RE.findall(text))
        )
        specificity_score = min(1.0, spec_hits / 2.0)

        addr_count = len(_ADDRESS_RE.findall(text))
        address_score = min(1.0, addr_count / 4.0)

        greeting = _GREETING_RE.match(text)
        if greeting and greeting.group(1):
            greeting_score = 1.0
        elif greeting:
            greeting_score = 0.5
        else:
            greeting_score = 0.0

        score = _clamp(
            0.35 * entity_score
            + 0.25 * specificity_score
            + 0.20 * address_score
            + 0.20 * greeting_score
        )

        if score >= 0.6:
            bits = []
            if named:
                bits.append(f"named entities ({', '.join(named[:3])})")
            if spec_hits:
                bits.append("specific dates/amounts/account numbers")
            if greeting and greeting.group(1):
                bits.append("addresses the recipient by name")
            reason = "Heavily tailored: " + "; ".join(bits) + "."
        elif named or spec_hits or addr_count:
            reason = "Some personalization signals, but generically addressed overall."
        else:
            reason = "Generic, mass-mailing tone with no recipient-specific detail."
        return score, reason

    def _named_entities(self, text: str) -> list[str]:
        """Return PERSON/ORG/GPE entity texts, using spaCy when available.

        Falls back to a capitalized-token heuristic when the spaCy model is missing so
        the feature still produces a signal in degraded environments.
        """
        nlp = _load_nlp()
        if nlp is not None:
            doc = nlp(text)
            return [ent.text for ent in doc.ents if ent.label_ in {"PERSON", "ORG", "GPE"}]
        # Fallback: mid-sentence capitalized word runs are likely proper nouns.
        candidates = re.findall(r"(?<![.!?]\s)(?<!^)\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b", text)
        return [c for c in candidates if len(c) > 2]

    # --- Feature 3: authority spoofing ------------------------------------

    def authority_spoofing_signals(self, text: str) -> float:
        """Signals that the sender is impersonating a trusted authority.

        Detects: institutional identity claims ("IT department", "Microsoft support",
        "your bank", "security team"), credential/verification lures ("verify your
        identity", "confirm your account"), official boilerplate (reference numbers,
        "do not reply"), and the urgency-authority combo ("your account will be
        suspended unless ...").

        Why it matters for AI attacks: LLMs are fluent at mimicking institutional
        register — the exact tone of an HR notice or a bank fraud alert — which
        historically required a human who knew the format. Confident, format-perfect
        authority mimicry paired with a credential ask is easy to mass-produce with AI.

        A high score means the message both claims institutional authority and asks the
        recipient to act on their credentials — the core impersonation pattern.

        Returns:
            float in [0, 1]; higher = stronger authority-impersonation signal.
        """
        return self._authority(text)[0]

    def _authority(self, text: str) -> tuple[float, str]:
        lower = text.lower()
        inst, m_inst = _count_phrase_hits(lower, _AUTHORITY_INSTITUTION)
        cred, m_cred = _count_phrase_hits(lower, _AUTHORITY_CREDENTIAL)
        boiler, _ = _count_phrase_hits(lower, _AUTHORITY_BOILERPLATE)
        combo = 1.0 if _AUTHORITY_COMBO_RE.search(text) else 0.0

        score = _clamp(
            0.40 * min(1.0, inst)
            + 0.40 * min(1.0, cred)
            + 0.30 * combo
            + 0.10 * min(1.0, boiler)
        )

        if score >= 0.6:
            parts = []
            if m_inst:
                parts.append(f"impersonates {m_inst[0]}")
            if m_cred:
                parts.append(f"asks to {m_cred[0]}")
            if combo:
                parts.append("threatens account suspension")
            reason = "Authority impersonation: " + "; ".join(parts) + "."
        elif m_inst or m_cred or combo:
            reason = "Mentions an institution or credential action, but without a full impersonation pattern."
        else:
            reason = "No institutional impersonation or credential-verification lure detected."
        return score, reason

    # --- Feature 4: emotional pressure ------------------------------------

    def emotional_pressure_index(self, text: str) -> float:
        """Intensity of emotional manipulation (fear, greed, threat, reward).

        Detects: threat/loss framing ("suspended", "legal action", "penalty"),
        reward/greed framing ("bonus", "exclusive", "winner", "selected"), and
        fear-based time framing ("immediately", "final notice", "before it's too
        late"). The score is the weighted density of that charged language relative
        to the message's overall length, so a short note saturated with threat/reward
        words scores higher than a long message that mentions one in passing.

        Why it matters for AI attacks: models can calibrate emotional intensity to a
        target persona and sustain it across a whole message without tonal slips.
        Sustained, well-modulated emotional pressure is a smoothness signature.

        A high score means the message leans hard on fear or greed to short-circuit
        deliberate judgment.

        Returns:
            float in [0, 1]; higher = stronger emotional manipulation.
        """
        return self._emotional(text)[0]

    def _emotional(self, text: str) -> tuple[float, str]:
        lower = text.lower()
        n_words = max(len(_words(text)), 1)
        threat, m_threat = _count_phrase_hits(lower, _EMOTION_THREAT)
        reward, m_reward = _count_phrase_hits(lower, _EMOTION_REWARD)
        fear, _ = _count_phrase_hits(lower, _EMOTION_FEAR)

        weighted = threat + reward + fear
        density = weighted / n_words
        score = _clamp(density / self._EMOTION_SATURATION)

        if score >= 0.6:
            if m_threat and m_reward:
                kind = "both fear and reward"
            elif m_reward:
                kind = "reward/greed"
            else:
                kind = "fear/threat"
            cues = ", ".join((m_threat + m_reward)[:3]) or "charged framing"
            reason = f"Heavy {kind} language ({cues}) engineered to override deliberate judgment."
        elif m_threat or m_reward:
            reason = "Some emotionally charged language, but not dominant relative to length."
        else:
            reason = "Neutral, informational tone with little emotional pressure."
        return score, reason

    # --- Feature 5: syntactic smoothness ----------------------------------

    def syntactic_smoothness(self, text: str) -> float:
        """Stylistic uniformity of the text — the signature "too smooth" signal.

        Combines three sub-signals (each in [0, 1], higher = smoother):

        1. **Sentence-length consistency.** We take the coefficient of variation
           (std / mean) of sentence lengths. *Low* variance maps to a *high* score.
           This is the counterintuitive part: human writing naturally mixes short and
           long sentences, so it has high length variance; LLM output tends toward
           uniform, evenly-sized sentences, so *low* variance is the suspicious
           signal, not high. A message where every sentence is nearly the same length
           reads machine-regular.
        2. **Rhythm / burstiness.** Average sentence-to-sentence length change,
           normalized by mean length. Humans write in bursts (a terse line after a
           long one); flat rhythm is smoother and more machine-like.
        3. **Type-token ratio (lexical diversity).** unique words / total words. Very
           high TTR (forced, every-word-unique variation) reads less like the steady,
           moderate diversity of fluent generated prose, so it is treated as slightly
           less smooth.

        Why it matters for AI attacks: human phishing often carries detectable error
        and rhythm artifacts; AI phishing is fluent and uniform by default. Unusually
        high smoothness *combined with* the manipulation features above is the central
        discriminator between ``human_phishing`` and ``ai_phishing``.

        A high score means the prose is unusually even and uniform — fluent in the way
        machine text is fluent.

        Returns:
            float in [0, 1]; higher = smoother / more likely AI-generated.
        """
        return self._smoothness(text)[0]

    def _smoothness(self, text: str) -> tuple[float, str]:
        sentences = _sentences(text)
        lengths = [len(_words(s)) for s in sentences]
        lengths = [n for n in lengths if n > 0]
        words = _words(text)
        n_words = len(words)

        if len(lengths) < 2 or n_words < 8:
            return 0.0, "Too short to assess stylistic smoothness reliably."

        mean = sum(lengths) / len(lengths)
        cv = (statistics.pstdev(lengths) / mean) if mean else 0.0
        variance_smoothness = _clamp(1.0 - cv / self._SMOOTHNESS_CV_REF)

        diffs = [abs(lengths[i] - lengths[i - 1]) for i in range(1, len(lengths))]
        rhythm = (sum(diffs) / len(diffs)) / mean if mean else 0.0
        rhythm_smoothness = _clamp(1.0 - rhythm / self._SMOOTHNESS_RHYTHM_REF)

        ttr = len({w.lower() for w in words}) / n_words
        ttr_smoothness = _clamp(1.0 - max(0.0, ttr - 0.7) / 0.3)

        score = _clamp(
            0.55 * variance_smoothness + 0.30 * rhythm_smoothness + 0.15 * ttr_smoothness
        )

        if score >= 0.6:
            reason = "Unusually uniform sentence length and even rhythm — the flat consistency typical of machine-generated text."
        elif score < 0.3:
            reason = "Bursty, variable sentence rhythm consistent with natural human writing."
        else:
            reason = "Moderately consistent style — neither markedly smooth nor notably bursty."
        return score, reason

    # --- Feature 6: manipulation arc --------------------------------------

    def manipulation_arc_indicators(self, text: str) -> float:
        """Presence of an ordered setup -> pressure -> ask persuasion arc.

        Using sentence-position analysis, detects whether the message (a) opens with
        context/credibility ("this is the IT team", a named greeting, "we noticed"),
        (b) escalates with urgency/stakes in the middle ("your account will be
        suspended"), and (c) closes with a specific call-to-action ("verify", "click
        the link below"). The score rewards both the *presence* of all three stages
        and their correct *ordering* (setup before pressure before ask).

        Why it matters for AI attacks: models trained on persuasive text reproduce
        well-formed narrative arcs consistently, where human attackers more often jump
        straight to the ask. A clean, complete arc executed in a short message suggests
        generated rather than hand-written content.

        A high score means the message walks the reader through a deliberate,
        well-structured persuasion sequence rather than a flat single-note request.

        Returns:
            float in [0, 1]; higher = more complete/ordered persuasion arc.
        """
        return self._arc(text)[0]

    def _arc(self, text: str) -> tuple[float, str]:
        sentences = _sentences(text)
        if not sentences:
            return 0.0, "Empty message — no persuasion arc."
        lower_sents = [s.lower() for s in sentences]

        setup_idx = _earliest_match(lower_sents, _ARC_SETUP)
        if setup_idx is None:
            setup_idx = _earliest_match(lower_sents, _AUTHORITY_INSTITUTION)
        if setup_idx is None and _GREETING_RE.match(text):
            setup_idx = 0
        pressure_idx = _earliest_match(lower_sents, _ARC_PRESSURE)
        ask_idx = _earliest_ask(lower_sents)

        indices = (setup_idx, pressure_idx, ask_idx)
        present = sum(i is not None for i in indices)
        base = present / 3.0
        ordered = (
            None not in indices and setup_idx <= pressure_idx <= ask_idx
        )
        score = _clamp(0.6 * base + 0.4 * (1.0 if ordered else 0.0))

        stages = [
            name
            for name, idx in zip(("setup", "pressure", "ask"), indices)
            if idx is not None
        ]
        if score >= 0.6:
            reason = "Full setup -> pressure -> ask arc: context first, escalating stakes, then a specific request."
        elif stages:
            reason = f"Partial persuasion structure ({' + '.join(stages)}), but not a complete ordered arc."
        else:
            reason = "No structured persuasion arc; flat single-note message."
        return score, reason

    # --- aggregation ------------------------------------------------------

    def _risk_level(self, score: float) -> str:
        low, high = self.RISK_THRESHOLDS
        return "low" if score < low else "medium" if score < high else "high"

    def explain_all(self, text: str) -> dict[str, dict[str, object]]:
        """Run all six features and return scores, reasons, and risk levels.

        Returns ``{feature_name: {"score": float, "reason": str, "risk_level": str}}``
        in the stable ``FEATURE_NAMES`` order. ``risk_level`` is one of
        ``"low" | "medium" | "high"`` per ``RISK_THRESHOLDS``. This is the full
        explainable payload the verdict-card UI renders.
        """
        helpers = {
            "urgency_signal_density": self._urgency,
            "personalization_depth_score": self._personalization,
            "authority_spoofing_signals": self._authority,
            "emotional_pressure_index": self._emotional,
            "syntactic_smoothness": self._smoothness,
            "manipulation_arc_indicators": self._arc,
        }
        out: dict[str, dict[str, object]] = {}
        for name in self.FEATURE_NAMES:
            score, reason = helpers[name](text)
            out[name] = {"score": score, "reason": reason, "risk_level": self._risk_level(score)}
        return out

    def overall_risk_score(self, text: str) -> float:
        """Combine all six feature scores into a single weighted risk score in [0, 100].

        Uses ``RISK_WEIGHTS`` (a class attribute, so weights can be tuned during
        evaluation without touching the feature logic). This is a transparent linear
        blend for triage/explainability — the trained classifier is the actual
        decision model; this score is the human-readable risk dial beside it.
        """
        scores = self.extract_all(text)
        total = sum(self.RISK_WEIGHTS.get(name, 0.0) * scores[name] for name in self.FEATURE_NAMES)
        return _clamp(total) * 100.0
