"""Pydantic request/response schemas for the TooSmooth API.

Strict by design: every field is typed, and nothing is Optional unless it genuinely
can be absent. The ``protected_namespaces=()`` config lets us use ``model_version`` /
``model_loaded`` field names without colliding with Pydantic's reserved ``model_``
namespace.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    """Body for ``POST /analyze``."""

    text: str = Field(min_length=1, description="The raw message text to analyze.")


class FeatureScore(BaseModel):
    """One interpretable manipulation feature: its score, band, and plain-English reason."""

    score: float = Field(ge=0.0, le=1.0)
    risk_level: str  # "low" | "medium" | "high"
    reason: str


class AnalyzeResponse(BaseModel):
    """Full explainable verdict for a single message."""

    model_config = ConfigDict(protected_namespaces=())

    label: str  # "legitimate" | "human_phishing" | "ai_phishing"
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    features: dict[str, FeatureScore]
    top_flags: list[str]
    model_version: str


class HealthResponse(BaseModel):
    """Body for ``GET /health``."""

    model_config = ConfigDict(protected_namespaces=())

    status: str
    model_loaded: bool
    model_version: str


class RootResponse(BaseModel):
    """Body for ``GET /``."""

    name: str
    version: str
    docs: str
