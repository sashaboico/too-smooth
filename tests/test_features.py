"""Tests for the FeatureExtractor.

These assert the *contract* (method presence, score range, output shape) so they
stay meaningful once the stubs are implemented. The range checks are marked xfail
for now because the methods raise NotImplementedError until Day 2+.
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

SAMPLE = "Hi Sasha, your account will be locked in 24 hours. Verify now to avoid suspension."


def test_extractor_exposes_all_feature_methods():
    fx = FeatureExtractor()
    for name in FEATURE_METHODS:
        assert callable(getattr(fx, name)), f"missing feature method: {name}"


def test_feature_names_match_methods():
    assert set(FeatureExtractor.FEATURE_NAMES) == set(FEATURE_METHODS)


@pytest.mark.parametrize("name", FEATURE_METHODS)
@pytest.mark.xfail(reason="feature logic is stubbed (NotImplementedError) until Day 2+", strict=True)
def test_feature_returns_float_in_unit_range(name):
    fx = FeatureExtractor()
    score = getattr(fx, name)(SAMPLE)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


@pytest.mark.xfail(reason="extract_all depends on stubbed methods", strict=True)
def test_extract_all_returns_all_features():
    fx = FeatureExtractor()
    out = fx.extract_all(SAMPLE)
    assert set(out) == set(FEATURE_METHODS)
