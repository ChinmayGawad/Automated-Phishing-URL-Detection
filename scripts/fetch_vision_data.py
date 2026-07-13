"""Fetch/capture a genuine labeled screenshot dataset for the vision CNN.

Legitimate screenshots are captured from **Tranco top sites** (reputable,
safe-to-visit). Phishing screenshots come from **PhishTank** URLs, but visiting
live phishing pages executes attacker-controlled content in a browser and is
genuinely dangerous — so phishing capture is **opt-in** via the
``PHISH_CAPTURE=1`` environment variable and MUST run inside an isolated,
network-restricted sandbox. When it is disabled (default), a synthetic phishing
set is generated so the CNN still trains on two balanced classes.

Usage:
    python scripts/fetch_vision_data.py            # legit (real) + phish (synthetic)
    PHISH_CAPTURE=1 python scripts/fetch_vision_data.py   # also capture real phish (SANDBOX ONLY)
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SHOT_DIR = ROOT / "data" / "screenshots"

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"
UA = {"User-Agent": "Mozilla/5.0 (phishing-research; educational)"}

LEGIT_LIMIT = 60        # real, safe captures
PHISH_CAPTURE_LIMIT = 60  # only used when PHISH_CAPTURE=1


def _tranco_domains(limit: int) -> list[str]:
    try:
        r = requests.get(TRANCO_URL, headers=UA, timeout=30)
        r.raise_for_status()
        content = r.content
        if content[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                content = z.read(z.namelist()[0])
        text = content.decode("utf-8", errors="ignore")
        domains = []
        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) >= 2 and parts[1].strip():
                domains.append(parts[1].strip())
            if len(domains) >= limit:
                break
        return domains
    except Exception as exc:  # pragma: no cover - network
        print(f"[warn] Tranco download failed: {exc}")
        return []


def _phishtank_urls(limit: int) -> list[str]:
    try:
        r = requests.get(PHISHTANK_URL, headers=UA, timeout=30)
        r.raise_for_status()
        import csv
        urls = []
        for row in csv.DictReader(io.StringIO(r.text)):
            u = (row.get("url") or "").strip()
            if u:
                urls.append(u)
            if len(urls) >= limit:
                break
        return urls
    except Exception as exc:  # pragma: no cover - network
        print(f"[warn] PhishTank download failed: {exc}")
        return []


def fetch() -> Path:
    from src.vision.capture import capture_batch

    # --- Legitimate class (real, safe captures) ---
    legit_dir = SHOT_DIR / "legit"
    legit_dir.mkdir(parents=True, exist_ok=True)
    domains = _tranco_domains(LEGIT_LIMIT)
    if domains:
        print(f"[info] capturing {len(domains)} legit screenshots...")
        capture_batch([f"https://{d}" for d in domains], legit_dir, label="legit")
    else:
        print("[warn] no legit domains; skipping legit capture.")

    # --- Phishing class ---
    phish_dir = SHOT_DIR / "phish"
    phish_dir.mkdir(parents=True, exist_ok=True)
    if os.environ.get("PHISH_CAPTURE") == "1":
        print("[!!] PHISH_CAPTURE=1: visiting LIVE phishing URLs. "
              "Ensure this runs in an isolated sandbox only.")
        urls = _phishtank_urls(PHISH_CAPTURE_LIMIT)
        if urls:
            capture_batch(urls, phish_dir, label="phish")
    else:
        print("[info] phishing capture disabled (safe default). "
              "Generating synthetic phishing screenshots.")
        from src.vision.dataset import _make_synthetic_class
        _make_synthetic_class(phish_dir, (170, 60, 50), 60, seed=7)

    n_legit = len(list((SHOT_DIR / "legit").glob("*.png")))
    n_phish = len(list((SHOT_DIR / "phish").glob("*.png")))
    print(f"[done] dataset: {n_legit} legit, {n_phish} phish -> {SHOT_DIR}")
    return SHOT_DIR


if __name__ == "__main__":
    fetch()
