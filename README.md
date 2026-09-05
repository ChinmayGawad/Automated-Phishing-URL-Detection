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
  request and extracts ~90 numerical features (length metrics, delimiter
  counts, IP-as-host, subdomain count, suspicious keywords, brand impersonation
  detection, free-hosting patterns). A trained `HistGradientBoostingClassifier`
  produces a fast phishing probability with ~0.997 AUC.
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
pip install -e ".[dev]"     # development tools: pytest, ruff, mypy
```

## 🧩 Chrome Extension Quick Start

The project includes **PhishGuard**, a real-time browser extension powered by on-device machine learning:

1. **Download the project**: Click **Code → Download ZIP** (or `git clone https://github.com/ChinmayGawad/Automated-Phishing-URL-Detection.git`).
2. **Open Extensions page**: Open Chrome and navigate to `chrome://extensions/`.
3. **Load Extension**: Enable **Developer mode** (top-right toggle), click **Load unpacked**, and select the **`extension/`** folder.

📖 *For a detailed step-by-step guide with screenshots and edge browser instructions, see [EXTENSION_INSTALLATION.md](EXTENSION_INSTALLATION.md).*


## API Security

The API supports authentication and rate limiting via environment variables:

```bash
# Require API key for all requests
PHISHGUARD_API_KEYS=key1,key2 uvicorn src.api.server:app --port 8000

# Rate limit: 100 requests per minute per IP
PHISHGUARD_RATE_LIMIT="100/minute" uvicorn src.api.server:app --port 8000

# Restrict CORS origins
PHISHGUARD_CORS_ORIGINS=http://localhost:8501,https://example.com uvicorn ...
```

For production safety notes, see [SECURITY.md](SECURITY.md).

## Pre-trained Models & Download

The project includes pre-trained model checkpoints ready for instant inference:

| Model File | Stage | Description | Size | Tracking |
|------------|-------|-------------|------|----------|
| `models/lexical_rf.joblib` | Stage 1 (Lexical) | HistGradientBoosting lexical classifier | ~2.2 MB | Standard Git |
| `models/cnn_phish.pt` | Stage 2 (Visual) | PyTorch ResNet18 visual page classifier | ~44 MB | Git LFS |
| `models/cnn_phish_metadata.json` | Stage 2 | Training metrics and provenance | ~1 KB | Standard Git |
| `extension/models/lexical.onnx` | Extension | Compact ONNX model (50 trees) | ~4.6 MB | Standard Git |

### Downloading via Git LFS

Large model files (like `cnn_phish.pt`) are tracked using **Git LFS**. To fetch model weights after cloning:

```bash
# Install Git LFS (once per machine)
git lfs install

# Fetch and pull model weights
git lfs pull
```

### Direct Download / GitHub Releases

If downloading without Git LFS or using the models standalone, download the weights from GitHub Releases:
- **Lexical Random Forest**: `models/lexical_rf.joblib`
- **Visual CNN PyTorch Checkpoint**: `models/cnn_phish.pt`
- **Browser Extension ONNX Model**: `extension/models/lexical.onnx` (export via `python build/export_model.py`)

Place downloaded model files directly inside the `models/` folder.


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

## Safety & Security

**The visual capture stage visits untrusted URLs.** Always run it inside an
isolated, network-restricted sandbox or container. See [SECURITY.md](SECURITY.md)
for detailed safety guidelines.

Key principles:
- Use `PHISH_CAPTURE=1` only in sandboxed environments
- Never expose capture endpoints to the internet
- Rate limit and authenticate API requests in production
- Monitor for unusual traffic patterns
