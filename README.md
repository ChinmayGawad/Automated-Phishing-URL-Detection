# Automated Phishing URL Detection

A hybrid, multi-stage pipeline that detects phishing URLs in real time by
combining a fast **lexical** classifier with a deep **visual** (CNN)
impersonation engine, fused by a configurable **hybrid decision core**.

## Architecture

```
[ User Inputs/Visits URL ]
          │
          ▼
┌────────────────────────────────────────┐
│     Stage 1: Lexical Feature Engine    │ ──(If highly certain safe/malicious)──> [Fast-Path Return]
└────────────────────────────────────────┘
          │ (If ambiguous or suspicious)
          ▼
┌────────────────────────────────────────┐
│    Stage 2: Visual Simulation Engine   │ (Headless Browser / Screenshot Capture)
└────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────┐
│    Stage 3: Hybrid Scoring Inference   │ (Weights: Lexical Score + Vision Score)
└────────────────────────────────────────┘
          │
          ▼
[ Final Verdict: Safe / Suspicious / Phishing ]
```

* **Stage 1 — Lexical Engine** (`src/lexical`): parses the URL with no network
  request and extracts 20+ numerical features (length metrics, delimiter
  counts, IP-as-host, subdomain count, suspicious keywords). A trained
  `RandomForestClassifier` produces a fast phishing probability.
* **Stage 2 — Visual Engine** (`src/vision`): if the lexical score is
  ambiguous, a headless Chromium (Playwright) captures a viewport screenshot in
  an isolated context, which a CNN classifies as phishing/legitimate.
* **Stage 3 — Hybrid Core** (`src/core`): weighted ensemble of the two scores
  against configurable thresholds, with a fast-path shortcut when lexical
  confidence is extreme.

## Project Layout

```
data/        raw datasets, captured screenshots, brand reference images
src/lexical  URL feature extraction, RF training, inference
src/vision   Playwright capture, screenshot dataset, CNN training, inference
src/core     hybrid decision core + config (weights, thresholds)
src/utils    shared helpers
app/         Streamlit interactive engine simulator
models/      saved model artifacts (lexical_rf.joblib, cnn_phish.pt)
scripts/     data acquisition (with offline fallback samples)
tests/       unit tests
```

## Setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium   # for the visual capture stage
```

## Data & Training

The models are trained on genuine public datasets:

* **Lexical** — `scripts/fetch_lexical_data.py` combines **PhishTank**
  (verified phishing URLs → label 1) with **Tranco** top sites
  (reputable URLs → label 0) into `data/raw/lexical_urls.csv`.
* **Vision** — `scripts/fetch_vision_data.py` captures real screenshots of
  Tranco top sites for the *legitimate* class. The *phishing* class is captured
  from PhishTank URLs **only when `PHISH_CAPTURE=1`**, because visiting live
  phishing pages executes attacker-controlled content and must run inside an
  isolated sandbox. Without that flag, a synthetic phishing set is generated so
  training still runs.

```bash
python scripts/fetch_lexical_data.py
python scripts/fetch_vision_data.py            # legit (real) + phish (synthetic)
# PHISH_CAPTURE=1 python scripts/fetch_vision_data.py   # also real phish (sandbox only)
```

Train the models:

```bash
python -m src.lexical.train
python -m src.vision.train
```

If `torch`/`playwright` are unavailable, the vision stage falls back to a
heuristic so the rest of the pipeline still runs.

## Run the Simulator

```bash
streamlit run app/simulator.py
```

Paste a URL, inspect per-stage scores, the risk matrix, and drag the weight
sliders to see how the final verdict changes in real time.

## Programmatic Use

```python
from src.core.hybrid import analyze
result = analyze("http://micr0soft-secure-login.com/verify")
print(result.verdict, result.risk, result.stage_scores)
```

## Notes on Safety

The visual capture stage visits untrusted URLs. Always run it inside an
isolated, network-restricted sandbox or container (see README note in
`src/vision/capture.py`). Do not visit URLs on a production host.
