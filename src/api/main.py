"""FastAPI service exposing the TooSmooth classifier.

Skeleton only — the model is not wired up yet. The intended contract:
  POST /classify  { "text": "..." }
    -> { "label": "...", "scores": {...}, "features": {...} }

The ``features`` block is returned alongside the label so the response is
explainable: a defender sees both the verdict and the signals behind it.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="TooSmooth", description="AI-augmented social engineering detector")


class Message(BaseModel):
    text: str


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/classify")
def classify(message: Message):
    """Classify a message as legitimate / human_phishing / ai_phishing.

    Stub: returns a fixed placeholder until the FeatureExtractor and model are wired in.
    """
    raise NotImplementedError("stub: classify not implemented yet")
