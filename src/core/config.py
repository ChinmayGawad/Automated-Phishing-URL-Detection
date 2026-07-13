"""Configuration for the hybrid decision core.

All thresholds and weights are centralized here so the Streamlit simulator can
expose them as live sliders. See ``src/core/hybrid.py`` for how they are used.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class HybridConfig:
    # Weight of the lexical score vs the vision score in the fused risk.
    w_lexical: float = 0.5
    w_vision: float = 0.5

    # Lexical fast-path: if confidence is extreme, skip vision entirely.
    fast_path_safe: float = 0.15       # lexical prob <= this -> Safe shortcut
    fast_path_malicious: float = 0.85  # lexical prob >= this -> Phishing shortcut

    # Routing: only run the (expensive) vision stage when lexical is ambiguous.
    vision_trigger_lo: float = 0.15
    vision_trigger_hi: float = 0.85

    # Verdict thresholds on the fused risk score in [0, 1].
    safe_threshold: float = 0.33
    phishing_threshold: float = 0.66

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_CONFIG = HybridConfig()
