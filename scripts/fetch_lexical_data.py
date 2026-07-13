"""Fetch a genuine labeled lexical URL dataset from multiple sources.

Combines four real public sources:

* **PhishTank** (https://phishtank.org) — verified phishing URLs -> label 1.
* **OpenPhish** (https://openphish.com) — curated phishing feed -> label 1.
* **URLhaus** (https://urlhaus.abuse.ch) — malware/phishing URLs -> label 1.
* **Tranco** (https://tranco-list.eu) — reputable top sites -> label 0.

Network access is required. If all downloads fail, a built-in fallback sample
is used so training always has something to run on.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from pathlib import Path

import requests

OUT_PATH = Path(__file__).resolve().parents[1] / "data" / "raw" / "lexical_urls.csv"

UA = {"User-Agent": "Mozilla/5.0 (phishing-research; educational)"}

# Per-source caps.
PHISH_LIMIT = 20000
LEGIT_LIMIT = 20000
OPENPHISH_LIMIT = 10000
URLHAUS_LIMIT = 10000

_FALLBACK = [
    ("http://google.com", 0), ("https://www.amazon.com/", 0),
    ("https://github.com/login", 0), ("https://bankofamerica.com/secure", 0),
    ("https://netflix.com/your-account", 0), ("https://microsoft.com/en-us/account", 0),
    ("http://192.168.1.1/login", 1), ("http://micr0soft-secure-login.com/verify", 1),
    ("http://paypa1.com/account/confirm", 1), ("http://secure-bank-update.tk/reset", 1),
    ("http://bit.ly/3xlogin-verify", 1), ("http://apple-id-verify.info/signin", 1),
    ("http://wellsf4rgo.com/online/login", 1), ("http://faceb00k-support.com/help", 1),
]


def _fetch_phishtank() -> list[tuple[str, int]]:
    url = "https://data.phishtank.com/data/online-valid.csv"
    try:
        r = requests.get(url, headers=UA, timeout=60)
        r.raise_for_status()
        text = r.text
    except Exception as exc:
        print(f"[warn] PhishTank download failed: {exc}")
        return []
    rows: list[tuple[str, int]] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        u = (row.get("url") or "").strip()
        if u:
            rows.append((u, 1))
        if len(rows) >= PHISH_LIMIT:
            break
    print(f"[ok] PhishTank: {len(rows)} phishing URLs")
    return rows


def _fetch_openphish() -> list[tuple[str, int]]:
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, headers=UA, timeout=30)
        r.raise_for_status()
        text = r.text
    except Exception as exc:
        print(f"[warn] OpenPhish download failed: {exc}")
        return []
    rows: list[tuple[str, int]] = []
    for line in text.splitlines():
        u = line.strip()
        if u and u.startswith("http"):
            rows.append((u, 1))
        if len(rows) >= OPENPHISH_LIMIT:
            break
    print(f"[ok] OpenPhish: {len(rows)} phishing URLs")
    return rows


def _fetch_urlhaus() -> list[tuple[str, int]]:
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        r = requests.get(url, headers=UA, timeout=60)
        r.raise_for_status()
        text = r.text
    except Exception as exc:
        print(f"[warn] URLhaus download failed: {exc}")
        return []
    rows: list[tuple[str, int]] = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(",", 3)
        if len(parts) < 5:
            continue
        # CSV columns: id, dateadded, url, threat, status
        u = parts[2].strip().strip('"')
        status = parts[4].strip().strip('"')
        if u and status == "online":
            rows.append((u, 1))
        if len(rows) >= URLHAUS_LIMIT:
            break
    print(f"[ok] URLhaus: {len(rows)} phishing/malware URLs")
    return rows


def _fetch_tranco() -> list[tuple[str, int]]:
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        r = requests.get(url, headers=UA, timeout=60)
        r.raise_for_status()
        content = r.content
        if content[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                content = z.read(z.namelist()[0])
        text = content.decode("utf-8", errors="ignore")
    except Exception as exc:
        print(f"[warn] Tranco download failed: {exc}")
        return []
    rows: list[tuple[str, int]] = []
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) < 2:
            continue
        domain = parts[1].strip()
        if domain:
            rows.append((f"https://{domain}", 0))
        if len(rows) >= LEGIT_LIMIT:
            break
    print(f"[ok] Tranco: {len(rows)} legitimate URLs")
    return rows


def fetch() -> Path:
    phish = _fetch_phishtank()
    openphish = _fetch_openphish()
    urlhaus = _fetch_urlhaus()
    legit = _fetch_tranco()

    all_phish = phish + openphish + urlhaus

    if not all_phish and not legit:
        print("[warn] No network data; writing offline fallback sample.")
        rows = _FALLBACK
    else:
        rows = all_phish + legit

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"[done] Wrote {len(rows)} rows ({len(all_phish)} phish, {len(legit)} legit) -> {OUT_PATH}")
    return OUT_PATH


if __name__ == "__main__":
    fetch()
