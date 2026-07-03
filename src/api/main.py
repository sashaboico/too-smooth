"""FastAPI service exposing the TooSmooth classifier.

Contract:
  POST /analyze  { "text": "..." }
    -> label, confidence, risk_score, per-feature breakdown (score/risk_level/reason),
       top_flags, model_version.
  GET  /health   -> liveness + whether the model loaded.
  GET  /         -> service metadata.

The ``features`` block is returned alongside the verdict so the response is
explainable: a defender sees both the label and the interpretable signals behind it —
the ``reason`` strings are what make this different from a black-box spam filter.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import joblib
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.middleware import add_cors
from src.api.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    FeatureScore,
    HealthResponse,
    RootResponse,
)
from src.features.extract import FeatureExtractor

MODEL_VERSION = "1.0"

# LogisticRegression was the best model on Day 6 — higher macro-F1 (0.95 vs 0.94) AND a
# lower legitimate false-positive rate (4.3% vs 8.3%) than GradientBoosting, while staying
# fully interpretable. See docs/EVAL_RESULTS.md.
MODEL_PATH = Path("models/classifier_lr.pkl")

# Attack-confidence decision threshold. We flag a message as an attack only when
# P(attack) = 1 - P(legitimate) >= this value, instead of the default 0.5. Day 6 tuning
# showed 0.6 cuts the legitimate false-positive rate from 5.7% to 2.7% while still
# catching 93.5% of attacks — flagging a real bank alert as phishing is a worse user
# experience than missing one attack. See docs/EVAL_RESULTS.md ("Selected Model").
ATTACK_THRESHOLD = 0.6


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Model file not found: {MODEL_PATH}. Train it first with "
            "`python -m src.classifier.train`."
        )
    app.state.model = joblib.load(MODEL_PATH)
    app.state.extractor = FeatureExtractor()
    yield
    app.state.model = None
    app.state.extractor = None


app = FastAPI(
    title="TooSmooth",
    description="AI-augmented social engineering detector",
    version=MODEL_VERSION,
    lifespan=lifespan,
)
add_cors(app)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never let a raw Python traceback reach the client."""
    return JSONResponse(
        status_code=500,
        content={"error": "Analysis failed", "detail": str(exc), "status_code": 500},
    )


@app.get("/", response_model=RootResponse)
def root() -> RootResponse:
    return RootResponse(name="TooSmooth", version=MODEL_VERSION, docs="/docs")


@app.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    """Liveness probe — reports whether the classifier is loaded."""
    model = getattr(request.app.state, "model", None)
    return HealthResponse(
        status="ok",
        model_loaded=model is not None,
        model_version=MODEL_VERSION,
    )


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    """Classify a message and return the explainable feature breakdown."""
    model = request.app.state.model
    extractor: FeatureExtractor = request.app.state.extractor
    text = req.text

    proba = model.predict_proba([text])[0]
    p = {cls: float(proba[i]) for i, cls in enumerate(model.classes_)}
    p_attack = 1.0 - p.get("legitimate", 0.0)

    # Apply the tuned threshold: only call it an attack above ATTACK_THRESHOLD, then pick
    # the more probable of the two attack classes.
    if p_attack >= ATTACK_THRESHOLD:
        label = "ai_phishing" if p.get("ai_phishing", 0.0) >= p.get("human_phishing", 0.0) else "human_phishing"
    else:
        label = "legitimate"

    confidence = round(p[label], 4)
    risk_score = round(p_attack * 100)  # 0-100 attack risk for the UI meter

    explained = extractor.explain_all(text)
    features = {
        name: FeatureScore(
            score=round(float(detail["score"]), 4),
            risk_level=str(detail["risk_level"]),
            reason=str(detail["reason"]),
        )
        for name, detail in explained.items()
    }
    top_flags = [
        name for name, _ in sorted(explained.items(), key=lambda kv: kv[1]["score"], reverse=True)[:2]
    ]

    return AnalyzeResponse(
        label=label,
        confidence=confidence,
        risk_score=risk_score,
        features=features,
        top_flags=top_flags,
        model_version=MODEL_VERSION,
    )
