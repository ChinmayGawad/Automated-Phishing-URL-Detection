"""Unit tests for the lexical feature engine and hybrid routing."""

from __future__ import annotations

import pytest

from src.lexical.features import extract_features, FEATURE_NAMES
from src.core.config import HybridConfig
from src.core.hybrid import analyze
from src.lexical.model import LexicalModel
from src.vision.model import VisionModel


def test_onnx_export_size_gate():
    """ONNX extension model must be under 5 MB to ship in the Chrome extension."""
    from pathlib import Path
    onnx_path = Path(__file__).resolve().parents[1] / "extension" / "models" / "lexical.onnx"
    if not onnx_path.exists():
        pytest.skip("ONNX model not present")
    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    assert size_mb < 5.0, f"ONNX model too large: {size_mb:.1f} MB"


def test_feature_vector_length_and_order():
    f = extract_features("http://micr0soft-secure-login.com/verify")
    vec = f.vector()
    assert len(vec) == len(FEATURE_NAMES)
    assert all(name in f.values for name in FEATURE_NAMES)


def test_ip_host_detected():
    f = extract_features("http://192.168.1.1/login")
    assert f.values["has_ip_host"] == 1.0


def test_suspicious_keyword_count():
    f = extract_features("http://paypa1.com/account/verify")
    assert f.values["suspicious_keyword_count"] >= 2


def test_hybrid_safe_fast_path():
    # Legit-looking URL should be below the safe fast-path threshold.
    cfg = HybridConfig()
    res = analyze("https://www.google.com", cfg=cfg, run_vision=False)
    assert res.fast_path is True
    assert res.verdict == "Safe"


def test_hybrid_phishing_fast_path():
    cfg = HybridConfig()
    res = analyze("http://192.168.1.1/login", cfg=cfg, run_vision=False)
    # IP-host + no https should push lexical prob high -> Phishing fast-path.
    assert res.verdict in ("Phishing", "Suspicious")


def test_vision_unavailable_graceful():
    vis = VisionModel(model_path="models/does_not_exist.pt")
    assert vis.available is False
    prob, used = vis.predict_proba("data/screenshots/_live/x.png")
    assert used is False and prob == 0.5
