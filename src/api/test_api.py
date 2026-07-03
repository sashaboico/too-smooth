"""API tests using FastAPI's TestClient.

Using the client as a context manager runs the lifespan handler, so the model is
actually loaded before the requests fire.
"""

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["model_version"] == "1.0"


def test_analyze_known_phishing(client):
    text = (
        "Your account has been suspended. Verify your identity immediately or it will be "
        "permanently terminated. Click here now to confirm your password and restore access."
    )
    resp = client.post("/analyze", json={"text": text})
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_score"] > 60
    assert set(body["features"]) == set(
        (
            "urgency_signal_density",
            "personalization_depth_score",
            "authority_spoofing_signals",
            "emotional_pressure_index",
            "syntactic_smoothness",
            "manipulation_arc_indicators",
        )
    )
    assert len(body["top_flags"]) == 2


def test_analyze_known_legitimate(client):
    text = (
        "Hi Mark, thanks for sending over the quarterly numbers. Let's grab coffee Monday "
        "to walk through the deck before the team meeting. Have a great weekend."
    )
    resp = client.post("/analyze", json={"text": text})
    assert resp.status_code == 200
    assert resp.json()["label"] == "legitimate"
