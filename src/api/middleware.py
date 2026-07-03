"""CORS configuration for the TooSmooth API.

The Chrome extension (Day 8) calls this API from the browser, which is a cross-origin
request — without CORS the browser blocks the response. Kept permissive for local
development; tighten ``allow_origins`` to the published extension ID before Chrome Web
Store submission (Day 10).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def add_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # tighten this before Chrome Web Store submission
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
