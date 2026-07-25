# PhishGuard Chrome Extension

Real-time phishing URL detection powered by machine learning, running entirely in your browser.

## Features

- **Local-only detection** — No data sent to any server. All analysis runs in your browser.
- **Toolbar icon** — Click to analyze the current page URL
- **Real-time browsing** — Automatically checks URLs as you navigate
- **Manual URL input** — Paste any URL to analyze
- **Configurable response** — Block navigation, show alerts, or both

## Installation

### Quick Start (Pre-built Model Included)

The ONNX model (`extension/models/lexical.onnx`) is **pre-packaged in the repository**.

1. Download or clone this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in top-right).
4. Click **Load unpacked** and select the `extension/` directory.
5. The **PhishGuard** icon will appear in your toolbar!

### Retraining & Exporting Model (Optional)

If you modify the training code or features and want to re-export the ONNX model:

```bash
pip install skl2onnx onnx onnxruntime
python build/export_model.py
```


## How It Works

PhishGuard uses a 77-feature lexical analysis engine to detect phishing URLs:

1. **Whitelist check** — Known legitimate domains (300+) are immediately marked Safe
2. **Feature extraction** — 77 numerical features are computed from the URL string (no network requests)
3. **ML inference** — A HistGradientBoosting classifier predicts phishing probability
4. **Fast-path** — High-confidence results skip further analysis for instant verdicts

## Settings

Click the extension icon → Settings to configure:

- **Enable/Disable** — Master switch
- **Real-time checking** — Auto-analyze URLs on navigation
- **Detection mode** — Block, alert, or both
- **Badge indicator** — Show colored badge on icon
- **Thresholds** — Adjust ML model sensitivity (advanced)

## Permissions

- `storage` — Save settings
- `tabs` — Access current tab URL
- `webNavigation` — Detect URL navigation
- `notifications` — Show phishing alerts
- `activeTab` — Analyze current page

## Architecture

```
extension/
├── manifest.json          # Manifest V3 config
├── lib/
│   ├── features.js        # 77-feature extraction (JS port)
│   ├── model.js           # ONNX model inference
│   ├── whitelist.js       # Known legitimate domains
│   ├── analyzer.js        # Pipeline orchestrator
│   └── config.js          # Settings management
├── popup/                 # Extension popup UI
├── background/            # Service worker
├── content/               # Warning banner injector
├── options/               # Settings page
├── models/                # ONNX model files
└── icons/                 # Extension icons
```

## Model

The ML model is a scikit-learn HistGradientBoostingClassifier exported to ONNX format (via a RandomForest proxy for ONNX compatibility):

- **Classifier**: HistGradientBoostingClassifier (400 iterations)
- **ONNX proxy**: RandomForestClassifier (400 trees) for browser inference
- **Features**: 77 lexical URL features
- **Input**: URL string → feature vector [77 floats]
- **Output**: Phishing probability [0, 1]

To retrain and export:
```bash
python -m src.lexical.train
python build/export_model.py
```

## License

Part of the Automated Phishing URL Detection project.
