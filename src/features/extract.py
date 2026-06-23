"""Interpretable manipulation feature extraction for social-engineering detection.

Each feature is designed to be human-auditable: a defender should be able to read
the score, read the message, and understand *why* the score is what it is. This is
deliberately not a black-box embedding — the whole point of TooSmooth is that the
signals separating AI-generated phishing from human phishing (and from legitimate
mail) are interpretable.
"""

from __future__ import annotations


class FeatureExtractor:
    """Extracts interpretable manipulation features from a single message.

    Usage:
        fx = FeatureExtractor()
        vector = fx.extract_all("Hi Sasha, your account ...")

    All feature methods accept the raw message text and return a float in [0, 1].
    Higher generally means "more of the manipulative property." None of these are
    implemented yet — they are stubs returning 0.0.
    """

    FEATURE_NAMES = (
        "urgency_signal_density",
        "personalization_depth_score",
        "authority_spoofing_signals",
        "emotional_pressure_index",
        "syntactic_smoothness",
        "manipulation_arc_indicators",
    )

    def extract_all(self, text: str) -> dict[str, float]:
        """Run every feature method and return a name -> score mapping.

        Returned in a stable order matching ``FEATURE_NAMES`` so the downstream
        classifier sees a consistent feature vector.
        """
        return {
            "urgency_signal_density": self.urgency_signal_density(text),
            "personalization_depth_score": self.personalization_depth_score(text),
            "authority_spoofing_signals": self.authority_spoofing_signals(text),
            "emotional_pressure_index": self.emotional_pressure_index(text),
            "syntactic_smoothness": self.syntactic_smoothness(text),
            "manipulation_arc_indicators": self.manipulation_arc_indicators(text),
        }

    def urgency_signal_density(self, text: str) -> float:
        """Density of time-pressure and scarcity cues per unit of text.

        Detects: "act now", "within 24 hours", "your account will be suspended",
        countdown framing, and other artificial-deadline language, normalized by
        message length so short and long messages are comparable.

        Why it matters for AI attacks: LLMs reliably reproduce urgency because it
        is the single most effective phishing lever, but they tend to deploy it
        *smoothly and repeatedly* without the typos or awkward phrasing a rushed
        human attacker leaves behind. High urgency density combined with high
        syntactic smoothness is a strong AI-phishing tell.

        Returns:
            float in [0, 1]; higher = more urgency pressure per token.
        """
        raise NotImplementedError("stub: urgency_signal_density not implemented yet")

    def personalization_depth_score(self, text: str) -> float:
        """How deeply the message is tailored to a specific recipient.

        Detects: use of the recipient's name, role, employer, recent activity, or
        relationship-specific references vs. generic "Dear customer" framing.

        Why it matters for AI attacks: generative models scaled with scraped or
        leaked context can produce *cheap, deep* personalization at volume —
        historically a marker of expensive spear-phishing. A message that is both
        highly personalized and mass-distribution-shaped is suspicious; deep
        personalization at scale is an AI-enabled capability.

        Returns:
            float in [0, 1]; higher = more recipient-specific tailoring.
        """
        raise NotImplementedError("stub: personalization_depth_score not implemented yet")

    def authority_spoofing_signals(self, text: str) -> float:
        """Signals that the sender is impersonating a trusted authority.

        Detects: claimed identity as IT/security/bank/executive/government,
        official-sounding boilerplate, reference/case numbers, and brand or
        title name-dropping intended to borrow legitimacy.

        Why it matters for AI attacks: LLMs are fluent at mimicking institutional
        register — the exact tone of an HR notice or a bank fraud alert — which
        historically required a human who knew the format. Confident, format-perfect
        authority mimicry is easier to mass-produce with AI.

        Returns:
            float in [0, 1]; higher = stronger authority-impersonation signal.
        """
        raise NotImplementedError("stub: authority_spoofing_signals not implemented yet")

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
