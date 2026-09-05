"""Tests for the PhishGuard FastAPI server."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.server import app, lifespan


@pytest.fixture(scope="module")
def client():
    """Create a test client with the model loaded."""
    with TestClient(app) as c:
        yield c


def test_health(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    assert "version" in data
    assert data["n_features"] > 0


def test_analyze_validates_scheme(client: TestClient):
    """Non-http schemes should be rejected."""
    resp = client.post("/analyze", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422
    resp = client.post("/analyze", json={"url": "data:text/html,<script>"})
    assert resp.status_code == 422


def test_analyze_response_has_request_id(client: TestClient):
    resp = client.post("/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 200
    # Request ID is returned as a response header
    assert "X-Request-Id" in resp.headers
    assert resp.headers["X-Request-Id"] != ""


def test_batch_request_id_present(client: TestClient):
    resp = client.post("/analyze/batch", json={
        "urls": ["https://www.google.com"]
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 1
    assert "request_id" in data["results"][0]
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    assert "version" in data


def test_analyze_safe_url(client: TestClient):
    resp = client.post("/analyze", json={"url": "https://www.google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Safe"
    assert data["risk"] == 0.0
    assert data["fast_path"] is True
    assert data["latency_ms"] >= 0


def test_analyze_phishing_url(client: TestClient):
    resp = client.post("/analyze", json={
        "url": "http://micr0soft-secure-login.com/verify"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("Phishing", "Suspicious")
    assert data["risk"] > 0.0


def test_analyze_empty_url_rejected(client: TestClient):
    resp = client.post("/analyze", json={"url": ""})
    assert resp.status_code == 422


def test_analyze_missing_url_rejected(client: TestClient):
    resp = client.post("/analyze", json={})
    assert resp.status_code == 422


def test_batch_analyze(client: TestClient):
    resp = client.post("/analyze/batch", json={
        "urls": [
            "https://www.google.com",
            "http://micr0soft-secure-login.com/verify",
            "https://github.com/login",
        ]
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 3
    assert data["total_latency_ms"] >= 0
    verdicts = [r["verdict"] for r in data["results"]]
    assert "Safe" in verdicts


def test_batch_empty_list_rejected(client: TestClient):
    resp = client.post("/analyze/batch", json={"urls": []})
    assert resp.status_code == 422


def test_batch_too_many_urls_rejected(client: TestClient):
    resp = client.post("/analyze/batch", json={
        "urls": ["https://example.com"] * 101
    })
    assert resp.status_code == 422


def test_analyze_response_structure(client: TestClient):
    resp = client.post("/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    required_fields = {"url", "verdict", "risk", "fast_path",
                       "stage_scores", "notes", "latency_ms"}
    assert required_fields.issubset(data.keys())
    assert data["verdict"] in ("Safe", "Suspicious", "Phishing")
    assert 0.0 <= data["risk"] <= 1.0
