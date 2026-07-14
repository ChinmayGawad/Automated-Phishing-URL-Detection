"""Production REST API for phishing URL detection.

FastAPI-based service with:
- /analyze endpoint for URL analysis
- /health endpoint for monitoring
- Request validation and error handling
- CORS support for web frontends
- Structured logging
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

from ..core.config import HybridConfig
from ..core.hybrid import analyze
from ..lexical.model import LexicalModel

logger = logging.getLogger("phishguard")

# Global model instance (loaded once at startup)
_lexical_model: Optional[LexicalModel] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup, cleanup on shutdown."""
    global _lexical_model
    logger.info("Loading lexical model...")
    _lexical_model = LexicalModel()
    _lexical_model._ensure_loaded()
    logger.info("Model loaded successfully.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL detection using hybrid ML pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    run_vision: bool = Field(False, description="Enable visual capture stage (slower)")

    model_config = {"json_schema_extra": {"examples": [
        {"url": "https://www.google.com"},
        {"url": "http://micr0soft-secure-login.com/verify"},
    ]}}


class StageScoreResponse(BaseModel):
    name: str
    probability: float
    used: bool
    detail: str = ""


class AnalyzeResponse(BaseModel):
    url: str
    verdict: str
    risk: float
    fast_path: bool
    stage_scores: list[StageScoreResponse]
    notes: list[str]
    latency_ms: float


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=100)
    run_vision: bool = False


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
    total_latency_ms: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint for monitoring."""
    return HealthResponse(
        status="ok",
        model_loaded=_lexical_model is not None,
        version="1.0.0",
    )


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(req: AnalyzeRequest):
    """Analyze a single URL for phishing risk."""
    if _lexical_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    start = time.monotonic()
    try:
        result = analyze(
            req.url,
            lexical_model=_lexical_model,
            run_vision=req.run_vision,
        )
    except Exception as e:
        logger.error("Analysis failed for %s: %s", req.url, e)
        raise HTTPException(status_code=500, detail=str(e))

    latency_ms = (time.monotonic() - start) * 1000

    return AnalyzeResponse(
        url=result.url,
        verdict=result.verdict,
        risk=result.risk,
        fast_path=result.fast_path,
        stage_scores=[StageScoreResponse(**asdict(s)) for s in result.stage_scores],
        notes=result.notes,
        latency_ms=round(latency_ms, 2),
    )


@app.post("/analyze/batch", response_model=BatchAnalyzeResponse)
async def analyze_batch(req: BatchAnalyzeRequest):
    """Analyze multiple URLs in a single request."""
    if _lexical_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    start = time.monotonic()
    results = []
    for url in req.urls:
        try:
            result = analyze(
                url,
                lexical_model=_lexical_model,
                run_vision=req.run_vision,
            )
            latency_ms = 0  # individual latency not tracked in batch
            results.append(AnalyzeResponse(
                url=result.url,
                verdict=result.verdict,
                risk=result.risk,
                fast_path=result.fast_path,
                stage_scores=[StageScoreResponse(**asdict(s)) for s in result.stage_scores],
                notes=result.notes,
                latency_ms=0,
            ))
        except Exception as e:
            logger.error("Batch analysis failed for %s: %s", url, e)
            results.append(AnalyzeResponse(
                url=url, verdict="Error", risk=0.0, fast_path=False,
                stage_scores=[], notes=[str(e)], latency_ms=0,
            ))

    total_ms = (time.monotonic() - start) * 1000
    return BatchAnalyzeResponse(results=results, total_latency_ms=round(total_ms, 2))


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8000)
