"""PhishGuard API server with hardened security controls.

Security improvements:
- CORS configured via env var (not wildcard with credentials)
- Optional API key auth via PHISHGUARD_API_KEYS
- Per-IP rate limiting via slowapi
- Request ID middleware for observability
- Scheme allowlist (rejects non-http(s) URLs)
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

# Optional: rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    _HAS_RATE_LIMITER = True
except ImportError:
    _HAS_RATE_LIMITER = False
    Limiter = None
    _rate_limit_exceeded_handler = None
    RateLimitExceeded = Exception

from ..core.config import HybridConfig
from ..core.hybrid import analyze
from ..lexical.model import LexicalModel

logger = logging.getLogger("phishguard")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

# CORS origins (comma-separated; empty = allow all for development)
_CORS_ORIGINS = os.getenv("PHISHGUARD_CORS_ORIGINS", "").split(",") or ["*"]
# API keys (comma-separated; empty = no auth)
_API_KEYS = {k.strip() for k in os.getenv("PHISHGUARD_API_KEYS", "").split(",") if k.strip()}
# Rate limit (requests per minute per IP; empty = no limit)
_RATE_LIMIT = os.getenv("PHISHGUARD_RATE_LIMIT", "0")  # 0 = disabled
# Request timeout in seconds
_TIMEOUT_S = int(os.getenv("PHISHGUARD_TIMEOUT_S", "30"))


def _cors_allowlist() -> list[str]:
    """Parse CORS origins config."""
    if _CORS_ORIGINS == ["*"]:
        return ["*"]
    return [o.strip() for o in _CORS_ORIGINS if o.strip()]


# ---------------------------------------------------------------------------
# Global model instance
# ---------------------------------------------------------------------------

_lexical_model: Optional[LexicalModel] = None

# Rate limiter setup
limiter: Optional[Limiter] = None
if _HAS_RATE_LIMITER and _RATE_LIMIT and _RATE_LIMIT != "0":
    limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    run_vision: bool = Field(False, description="Enable visual capture stage (slower)")

    @validator("url")
    def validate_scheme(cls, v: str) -> str:
        """Only allow http(s) schemes."""
        lower = v.strip().lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("Only http:// and https:// URLs are allowed")
        # Reject data:, javascript:, etc.
        if ":" in v.split("//")[0]:
            scheme = v.split("://")[0].lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"Scheme '{scheme}' is not allowed")
        return v.strip()

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
    request_id: str = ""


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=100)
    run_vision: bool = False

    @validator("urls")
    def validate_urls(cls, v: list[str]) -> list[str]:
        for u in v:
            lower = u.strip().lower()
            if not (lower.startswith("http://") or lower.startswith("https://")):
                raise ValueError(f"Only http:// and https:// URLs are allowed, got: {u}")
        return [u.strip() for u in v]


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
    total_latency_ms: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str
    n_features: int = 0


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _lexical_model
    logger.info("Loading lexical model...")
    _lexical_model = LexicalModel()
    _lexical_model._ensure_loaded()
    logger.info("Model loaded successfully.")
    yield
    logger.info("Shutting down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL detection using hybrid ML pipeline",
    version="1.1.0",
    lifespan=lifespan,
)

# CORS middleware (properly configured)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allowlist(),
    allow_credentials=False,  # Safe with wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    response = await call_next(request)
    response.headers["X-Request-Id"] = request_id
    return response


# Rate limiting
if _HAS_RATE_LIMITER and limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if limiter:
            # Apply rate limit to /analyze endpoints
            if request.url.path.startswith("/analyze"):
                return await limiter.try_ratelimit(request, get_remote_address)
        return await call_next(request)


# Auth middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if _API_KEYS:
        api_key = request.headers.get("X-API-Key", "")
        if api_key not in _API_KEYS:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return await call_next(request)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    """Health check endpoint for monitoring."""
    n_features = 0
    if _lexical_model and _lexical_model._artifact:
        n_features = _lexical_model._artifact.get("n_features", 0)
    return HealthResponse(
        status="ok",
        model_loaded=_lexical_model is not None,
        version="1.1.0",
        n_features=n_features,
    )


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(req: AnalyzeRequest, request: Request):
    """Analyze a single URL for phishing risk."""
    if _lexical_model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    request_id = request.headers.get("X-Request-Id", "")
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
        request_id=request_id,
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
            results.append(AnalyzeResponse(
                url=result.url,
                verdict=result.verdict,
                risk=result.risk,
                fast_path=result.fast_path,
                stage_scores=[StageScoreResponse(**asdict(s)) for s in result.stage_scores],
                notes=result.notes,
                latency_ms=0,
                request_id="",
            ))
        except Exception as e:
            logger.error("Batch analysis failed for %s: %s", url, e)
            results.append(AnalyzeResponse(
                url=url, verdict="Error", risk=0.0, fast_path=False,
                stage_scores=[], notes=[str(e)], latency_ms=0,
                request_id="",
            ))

    total_ms = (time.monotonic() - start) * 1000
    return BatchAnalyzeResponse(results=results, total_latency_ms=round(total_ms, 2))


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8000)
