"""Hybrid decision core: fuse lexical + vision scores into a verdict.

Implements the three-stage routing described in the project architecture:

1. **Whitelist check**: If the domain is a known legitimate site, return
   Safe immediately (most reliable signal).
2. **Rule-based check**: Catch obvious phishing patterns (typosquatting, etc.)
3. Compute the fast lexical score.
4. If it is extremely confident, short-circuit with a fast-path verdict.
5. Otherwise (ambiguous/suspicious), run the visual engine and fuse the two
   scores with configurable weights into a final risk in [0, 1].
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .config import DEFAULT_CONFIG, HybridConfig

from ..lexical.features import (
    KNOWN_BRANDS, KNOWN_LEGITIMATE_DOMAINS, PHISH_COMBINATION_WORDS,
    SHORTENER_DOMAINS, _levenshtein, _is_ip, _entropy,
)
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


def _rule_based_check(url: str) -> tuple[float, str]:
    """Rule-based phishing detection for patterns ML might miss.

    Returns (score, reason) where score is 0-1 (higher = more suspicious).
    Catches: typosquatting, hyphenated brand impersonation, suspicious prefixes.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.netloc or "").lower().split(":")[0]
        path = (parsed.path or "").lower()
    except Exception:
        return 0.3, "Malformed URL"

    domain = host.split(".")[-2] if host.count(".") >= 2 else host.split(".")[0]
    suspicion = 0.0
    reasons = []

    # Rule 1: Brand near-match (Levenshtein 1-2)
    for brand in KNOWN_BRANDS:
        dist = _levenshtein(domain, brand)
        if 1 <= dist <= 2 and len(domain) >= 3:
            suspicion += 0.6
            reasons.append(f"Domain '{domain}' is {dist} edit(s) from brand '{brand}'")
            break

    # Rule 2: Hyphenated brand impersonation
    if "-" in domain:
        parts = domain.split("-")
        if len(parts) == 2:
            for part in parts:
                for brand in KNOWN_BRANDS:
                    if part == brand or _levenshtein(part, brand) <= 1:
                        other = parts[1] if parts[0] in (brand,) else parts[0]
                        if any(w in other or _levenshtein(other, w) <= 1
                               for w in PHISH_COMBINATION_WORDS[:15]):
                            suspicion += 0.7
                            reasons.append(f"Hyphenated brand impersonation: '{domain}'")
                            break
                if suspicion > 0.5:
                    break

    # Rule 3: Suspicious prefix/suffix with brand
    for word in PHISH_COMBINATION_WORDS[:12]:
        if domain.startswith(word + "-") or domain.startswith(word + "."):
            rest = domain[len(word) + 1:]
            for brand in KNOWN_BRANDS:
                if brand in rest or _levenshtein(rest, brand) <= 1:
                    suspicion += 0.6
                    reasons.append(f"Suspicious prefix '{word}' with brand in '{domain}'")
                    break
        if domain.endswith("-" + word) or domain.endswith("." + word):
            rest = domain[:-(len(word) + 1)]
            for brand in KNOWN_BRANDS:
                if brand in rest or _levenshtein(rest, brand) <= 1:
                    suspicion += 0.6
                    reasons.append(f"Suspicious suffix '-{word}' with brand in '{domain}'")
                    break

    # Rule 4: IP address as host
    if _is_ip(host):
        suspicion += 0.5
        reasons.append("IP address used as hostname")

    return min(1.0, suspicion), "; ".join(reasons) or "No rule triggered"


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

    # Stage 0.5: Rule-based check (catches patterns ML might miss)
    rule_score, rule_reason = _rule_based_check(url)
    if rule_score >= 0.5:
        return AnalysisResult(
            url=url, verdict="Phishing", risk=rule_score, fast_path=True,
            notes=[f"Rule-based detection: {rule_reason}"])

    lex_model = lexical_model or LexicalModel()
    vis_model = vision_model or VisionModel()

    lex_prob = lex_model.predict_proba(url)
    scores: list[StageScore] = [
        StageScore("Lexical", lex_prob, True,
                   "RandomForest over URL string features")
    ]

    # Combine ML probability with rule-based score
    combined_risk = max(lex_prob, rule_score * 0.8)

    # Fast-path: lexical confidence is extreme -> no network capture needed.
    if combined_risk <= cfg.fast_path_safe:
        return AnalysisResult(
            url=url, verdict="Safe", risk=combined_risk,
            stage_scores=scores, fast_path=True,
            notes=["Combined score confident -> Safe fast-path (no capture)."])
    if combined_risk >= cfg.fast_path_malicious:
        return AnalysisResult(
            url=url, verdict="Phishing", risk=combined_risk,
            stage_scores=scores, fast_path=True,
            notes=["Combined score confident -> Phishing fast-path (no capture)."])

    # Ambiguous: only invoke the visual stage if enabled and triggered.
    vis_used = False
    vis_prob = 0.5
    screenshot = None
    notes: list[str] = []
    if run_vision and cfg.vision_trigger_lo <= combined_risk <= cfg.vision_trigger_hi:
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
    risk = (cfg.w_lexical * combined_risk + cfg.w_vision * vis_prob) / w_sum

    verdict = _verdict_from_risk(risk, cfg)
    notes.append(f"ML prob={lex_prob:.3f}, rule score={rule_score:.2f}, "
                 f"fused risk={risk:.3f} -> {verdict}.")
    return AnalysisResult(url=url, verdict=verdict, risk=risk,
                          stage_scores=scores, fast_path=False,
                          screenshot=screenshot, notes=notes)


def _safe_name(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "_", url)[:80]
