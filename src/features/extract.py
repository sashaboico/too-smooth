"""Interpretable manipulation feature extraction for social-engineering detection.

Each feature is designed to be human-auditable: a defender should be able to read
the score, read the message, and understand *why* the score is what it is. This is
deliberately not a black-box embedding — the whole point of TooSmooth is that the
signals separating AI-generated phishing from human phishing (and from legitimate
mail) are interpretable.

Day 3 implements the first three features with real logic:
``urgency_signal_density``, ``personalization_depth_score`` and
``authority_spoofing_signals``. The remaining three remain stubs until Day 4.
"""

from __future__ import annotations

import re
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

    # Features implemented with real logic (the rest are Day 4 stubs).
    IMPLEMENTED = (
        "urgency_signal_density",
        "personalization_depth_score",
        "authority_spoofing_signals",
    )

    # Tuning constant: weighted urgency signals per word that saturates the score.
    _URGENCY_SATURATION = 0.22

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

    # --- Day 4 stubs (not implemented yet) --------------------------------

    def emotional_pressure_index(self, text: str) -> float:
        """Intensity of emotional manipulation (fear, greed, guilt, curiosity).

        Detects: fear appeals ("you'll lose access"), greed appeals ("claim your
        reward"), guilt/obligation framing, and curiosity hooks engineered to
        override deliberate judgment.

        Why it matters for AI attacks: models can calibrate emotional intensity to
        a target persona and sustain it across a whole message without tonal slips.
        Sustained, well-modulated emotional pressure is a smoothness signature.

        Returns:
            float in [0, 1]; higher = stronger emotional manipulation.
        """
        raise NotImplementedError("stub: emotional_pressure_index not implemented yet")

    def syntactic_smoothness(self, text: str) -> float:
        """Grammatical fluency and stylistic uniformity of the text.

        Detects: low typo/grammar-error rate, even sentence rhythm, consistent
        register, and absence of the idiosyncratic errors common in human-written
        phishing (especially non-native-speaker attacker artifacts).

        Why it matters for AI attacks: this is the core "too smooth" signal. Human
        phishing often carries detectable language errors; AI phishing is fluent by
        default. Unusually high smoothness *combined with* manipulation features is
        the central discriminator between ``human_phishing`` and ``ai_phishing``.

        Returns:
            float in [0, 1]; higher = smoother / more fluent text.
        """
        raise NotImplementedError("stub: syntactic_smoothness not implemented yet")

    def manipulation_arc_indicators(self, text: str) -> float:
        """Presence of a structured persuasion arc across the message.

        Detects: a deliberate rapport -> trust -> pressure -> call-to-action
        progression, rather than a flat single-note request. Looks at ordering and
        transitions between hook, justification, and ask.

        Why it matters for AI attacks: models trained on persuasive text reproduce
        well-formed narrative arcs consistently, where human attackers more often
        jump straight to the ask. A clean, complete manipulation arc executed in a
        short message suggests generated rather than hand-written content.

        Returns:
            float in [0, 1]; higher = more complete/structured persuasion arc.
        """
        raise NotImplementedError("stub: manipulation_arc_indicators not implemented yet")
