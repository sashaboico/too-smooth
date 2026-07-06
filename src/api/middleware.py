"""CORS configuration for the TooSmooth API.

The Chrome extension (Day 8) calls this API from the browser, which is a cross-origin
request — without CORS the browser blocks the response.

Chrome only sends an exact ``chrome-extension://<32-char-id>`` origin (no wildcard
matching), and that id is assigned when the item is first created in the Web Store
developer console — it doesn't exist yet pre-submission. Once the listing is created,
replace ``ALLOWED_ORIGINS`` below with that exact origin and redeploy; ``allow_origins``
is kept permissive until then so the extension keeps working end to end.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# TODO(Day 10 follow-up): replace with ["chrome-extension://<published-id>"] once the
# Chrome Web Store listing is created and the permanent extension id is known.
ALLOWED_ORIGINS = ["*"]


def add_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
