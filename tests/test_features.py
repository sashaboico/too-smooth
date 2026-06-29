"""Tests for the FeatureExtractor.

Contract tests assert method presence, score range, and output shape so they stay
meaningful as stubs get implemented. Day 3 adds behavioral tests for the first three
features: each has one obviously high-scoring and one obviously low-scoring example,
with hardcoded strings. The three Day 4 features are still stubs and asserted to raise.
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

IMPLEMENTED = [
    "urgency_signal_density",
    "personalization_depth_score",
    "authority_spoofing_signals",
]
STUBBED = [
    "emotional_pressure_index",
    "syntactic_smoothness",
    "manipulation_arc_indicators",
]


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


@pytest.mark.parametrize("name", STUBBED)
def test_stubbed_feature_still_raises(fx, name):
    with pytest.raises(NotImplementedError):
        getattr(fx, name)("anything")


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


# --- explain() ------------------------------------------------------------

def test_explain_returns_scores_and_reasons(fx):
    out = fx.explain("Hi Sasha, your account will be suspended unless you verify your identity now.")
    assert set(out) == set(IMPLEMENTED)
    for name, detail in out.items():
        assert isinstance(detail["score"], float)
        assert 0.0 <= detail["score"] <= 1.0
        assert isinstance(detail["reason"], str) and detail["reason"]
