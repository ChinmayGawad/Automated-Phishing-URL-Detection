"""Hybrid decision core: fuse lexical + vision scores into a verdict.

Implements the three-stage routing described in the project architecture:

1. **Whitelist check**: If the domain is a known legitimate site, return
   Safe immediately (most reliable signal).
2. Compute the fast lexical score.
3. If it is extremely confident, short-circuit with a fast-path verdict.
4. Otherwise (ambiguous/suspicious), run the visual engine and fuse the two
   scores with configurable weights into a final risk in [0, 1].
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .config import DEFAULT_CONFIG, HybridConfig

from ..lexical.features import KNOWN_LEGITIMATE_DOMAINS
from ..lexical.model import LexicalModel
from ..vision.capture import capture
from ..vision.model import VisionModel


@dataclass
class StageScore:
    name: str
    probability: float
    used: bool
    detail: str = ""


@dataclass
class AnalysisResult:
    url: str
    verdict: str            # "Safe" | "Suspicious" | "Phishing"
    risk: float             # fused risk in [0, 1]
    stage_scores: list[StageScore] = field(default_factory=list)
    fast_path: bool = False
    screenshot: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def _verdict_from_risk(risk: float, cfg: HybridConfig) -> str:
    if risk <= cfg.safe_threshold:
        return "Safe"
    if risk >= cfg.phishing_threshold:
        return "Phishing"
    return "Suspicious"


def _check_whitelist(url: str) -> bool:
    """Check if the URL's domain is a known legitimate site.

    Checks the full hostname and the registered domain against the whitelist.
    This is the most reliable anti-phishing signal — domain reputation
    outweighs any structural URL feature.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.netloc or "").lower().split(":")[0]
    except Exception:
        return False

    # Direct match
    if host in KNOWN_LEGITIMATE_DOMAINS:
        return True

    # Subdomain match (e.g. docs.google.com -> google.com)
    for wl_domain in KNOWN_LEGITIMATE_DOMAINS:
        if host == wl_domain or host.endswith("." + wl_domain):
            return True

    return False


def analyze(url: str,
            cfg: HybridConfig = DEFAULT_CONFIG,
            lexical_model: Optional[LexicalModel] = None,
            vision_model: Optional[VisionModel] = None,
            run_vision: bool = True) -> AnalysisResult:
    """Run the full hybrid pipeline on a single URL."""

    # Stage 0: Whitelist fast-path (most reliable signal)
    if _check_whitelist(url):
        return AnalysisResult(
            url=url, verdict="Safe", risk=0.0, fast_path=True,
            notes=["Domain is in known legitimate whitelist -> Safe."])

    lex_model = lexical_model or LexicalModel()
    vis_model = vision_model or VisionModel()

    lex_prob = lex_model.predict_proba(url)
    scores: list[StageScore] = [
        StageScore("Lexical", lex_prob, True,
                   "RandomForest over URL string features")
    ]

    # Fast-path: lexical confidence is extreme -> no network capture needed.
    if lex_prob <= cfg.fast_path_safe:
        return AnalysisResult(
            url=url, verdict="Safe", risk=lex_prob,
            stage_scores=scores, fast_path=True,
            notes=["Lexical score confident -> Safe fast-path (no capture)."])
    if lex_prob >= cfg.fast_path_malicious:
        return AnalysisResult(
            url=url, verdict="Phishing", risk=lex_prob,
            stage_scores=scores, fast_path=True,
            notes=["Lexical score confident -> Phishing fast-path (no capture)."])

    # Ambiguous: only invoke the visual stage if enabled and triggered.
    vis_used = False
    vis_prob = 0.5
    screenshot = None
    notes: list[str] = []
    if run_vision and cfg.vision_trigger_lo <= lex_prob <= cfg.vision_trigger_hi:
        shot_path = capture(url, f"data/screenshots/_live/{_safe_name(url)}.png")
        if shot_path.ok:
            vis_prob, vis_used = vis_model.predict_proba(shot_path.image_path)
            screenshot = str(shot_path.image_path)
            if not vis_used:
                notes.append("Vision model unavailable -> neutral vision score.")
        else:
            notes.append(f"Capture failed: {shot_path.error}")
        scores.append(StageScore("Vision", vis_prob, vis_used,
                                 "CNN over headless screenshot"))
    else:
        scores.append(StageScore("Vision", vis_prob, False,
                                 "skipped (lexical outside trigger band)"))

    # Fuse. Normalize weights to sum to 1.
    w_sum = cfg.w_lexical + cfg.w_vision
    if w_sum <= 0:
        w_sum = 1.0
    risk = (cfg.w_lexical * lex_prob + cfg.w_vision * vis_prob) / w_sum

    verdict = _verdict_from_risk(risk, cfg)
    notes.append(f"Fused risk={risk:.3f} with w_lex={cfg.w_lexical}, "
                 f"w_vis={cfg.w_vision} -> {verdict}.")
    return AnalysisResult(url=url, verdict=verdict, risk=risk,
                          stage_scores=scores, fast_path=False,
                          screenshot=screenshot, notes=notes)


def _safe_name(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "_", url)[:80]
