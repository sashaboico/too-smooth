"""Tests for the FeatureExtractor.

Contract tests assert method presence, score range, and output shape. Behavioral
tests give each of the six features one obviously high-scoring and one obviously
low-scoring example with hardcoded strings, plus an integration test over the full
explain_all / overall_risk_score aggregation.
"""

import pytest

from src.features.extract import FeatureExtractor

FEATURE_METHODS = [
    "urgency_signal_density",
    "personalization_depth_score",
    "authority_spoofing_signals",
    "emotional_pressure_index",
    "syntactic_smoothness",
    "manipulation_arc_indicators",
]

IMPLEMENTED = list(FEATURE_METHODS)  # all six implemented as of Day 4


@pytest.fixture(scope="module")
def fx():
    return FeatureExtractor()


# --- contract tests -------------------------------------------------------

def test_extractor_exposes_all_feature_methods(fx):
    for name in FEATURE_METHODS:
        assert callable(getattr(fx, name)), f"missing feature method: {name}"


def test_feature_names_match_methods():
    assert set(FeatureExtractor.FEATURE_NAMES) == set(FEATURE_METHODS)


@pytest.mark.parametrize("name", IMPLEMENTED)
def test_implemented_feature_returns_float_in_unit_range(fx, name):
    score = getattr(fx, name)("Hi Sasha, your account will be locked in 24 hours.")
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# --- Feature 1: urgency_signal_density ------------------------------------

def test_urgency_high(fx):
    text = (
        "URGENT: Your account has been flagged. Act now and verify immediately or your "
        "access will be suspended and permanently locked within 24 hours. This is your "
        "final notice — do not delay."
    )
    assert fx.urgency_signal_density(text) > 0.6


def test_urgency_low(fx):
    text = (
        "Hi team, here are the notes from yesterday's planning meeting. Feel free to "
        "share any thoughts whenever you get a chance. Thanks so much for your help."
    )
    assert fx.urgency_signal_density(text) < 0.3


# --- Feature 2: personalization_depth_score -------------------------------

def test_personalization_high(fx):
    text = (
        "Hi Sasha, this is David Chen from the Wells Fargo fraud team in Chicago. Your "
        "checking account ending in 4471 shows a $2,450 charge dated June 28. Please "
        "review your recent statement and confirm whether you authorized this payment."
    )
    assert fx.personalization_depth_score(text) > 0.6


def test_personalization_low(fx):
    text = (
        "The quarterly report has been finalized and uploaded to the shared drive. "
        "Additional context will be circulated in a separate note."
    )
    assert fx.personalization_depth_score(text) < 0.3


# --- Feature 3: authority_spoofing_signals --------------------------------

def test_authority_high(fx):
    text = (
        "This is the Microsoft Account Security Team. We detected unauthorized sign-in "
        "activity. You must verify your identity and confirm your password immediately, "
        "or your account will be suspended unless action is taken within 24 hours."
    )
    assert fx.authority_spoofing_signals(text) > 0.6


def test_authority_low(fx):
    text = (
        "Hey, are we still on for coffee tomorrow morning? Let me know what time works "
        "best and I'll meet you at the usual place."
    )
    assert fx.authority_spoofing_signals(text) < 0.3


# --- Feature 4: emotional_pressure_index ----------------------------------

def test_emotional_high(fx):
    text = (
        "Final notice: your account has been suspended and you now face legal action, "
        "heavy penalties, and immediate termination. But congratulations — you have been "
        "selected as an exclusive winner of a cash reward. Claim your prize immediately "
        "before it's too late."
    )
    assert fx.emotional_pressure_index(text) > 0.6


def test_emotional_low(fx):
    text = (
        "Thanks for sending the agenda. I've added a couple of items and shared the "
        "document with the team for review before our call."
    )
    assert fx.emotional_pressure_index(text) < 0.3


# --- Feature 5: syntactic_smoothness --------------------------------------

def test_smoothness_high(fx):
    # Uniform, evenly-sized, fluent sentences — machine-regular rhythm.
    text = (
        "Our team has reviewed your recent account activity in detail. We identified a "
        "few items that require your attention today. Please review the summary we "
        "prepared for your records. We remain available to assist you at any time."
    )
    assert fx.syntactic_smoothness(text) > 0.6


def test_smoothness_low(fx):
    # Bursty human rhythm: very short lines next to a long rambling one.
    text = (
        "Hey!! So I tried to log in yesterday but it kept failing for some reason and I "
        "got really frustrated after like the tenth attempt honestly. Weird. Can you "
        "help? Thanks a million."
    )
    assert fx.syntactic_smoothness(text) < 0.3


# --- Feature 6: manipulation_arc_indicators -------------------------------

def test_arc_high(fx):
    text = (
        "Hello, this is the IT support team contacting you about your account. We noticed "
        "some unusual login activity on your profile. For your security, your access will "
        "be suspended within 24 hours unless action is taken. Please verify your identity "
        "now by clicking the link below."
    )
    assert fx.manipulation_arc_indicators(text) > 0.6


def test_arc_low(fx):
    text = "Can you send me the Q3 report when you have a chance? Thanks."
    assert fx.manipulation_arc_indicators(text) < 0.3


# --- explain() / explain_all() / overall_risk_score() ---------------------

def test_explain_returns_scores_and_reasons(fx):
    out = fx.explain("Hi Sasha, your account will be suspended unless you verify your identity now.")
    assert set(out) == {
        "urgency_signal_density",
        "personalization_depth_score",
        "authority_spoofing_signals",
    }
    for name, detail in out.items():
        assert isinstance(detail["score"], float)
        assert 0.0 <= detail["score"] <= 1.0
        assert isinstance(detail["reason"], str) and detail["reason"]


def test_explain_all_shape_and_risk_levels(fx):
    out = fx.explain_all("Verify your identity now or your account will be suspended.")
    assert set(out) == set(FEATURE_METHODS)
    for detail in out.values():
        assert 0.0 <= detail["score"] <= 1.0
        assert isinstance(detail["reason"], str) and detail["reason"]
        assert detail["risk_level"] in {"low", "medium", "high"}


def test_known_ai_phishing_scores_high(fx):
    text = (
        "Dear Sasha, this is the Microsoft Account Security Team. We detected an "
        "unauthorized sign-in on your account today. To protect your information, please "
        "verify your identity within 24 hours. Otherwise your account will be suspended "
        "as a security precaution. Click the secure link below to confirm your details now."
    )
    risk = fx.overall_risk_score(text)
    assert 0.0 <= risk <= 100.0
    assert risk > 60
