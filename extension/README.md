# PhishGuard Chrome Extension

Real-time phishing URL detection powered by machine learning, running entirely in your browser.

## Features

- **Local-only detection** — No data sent to any server. All analysis runs in your browser.
- **Toolbar icon** — Click to analyze the current page URL
- **Real-time browsing** — Automatically checks URLs as you navigate
- **Manual URL input** — Paste any URL to analyze
- **Configurable response** — Block navigation, show alerts, or both

## Installation

### From Source (Developer Mode)

**Note:** The ONNX model file (`lexical.onnx`, ~177MB) is not included in the repository. You must generate it before loading the extension.

1. Build the ONNX model:
   ```bash
   pip install skl2onnx onnx onnxruntime
   python build/export_model.py
   ```

2. Download ONNX Runtime Web for the popup (required for full ML inference):
   ```bash
   # Download onnxruntime-web from npm or CDN
   npm pack onnxruntime-web
   tar -xzf onnxruntime-web-*.tgz
   cp package/dist/ort.min.js extension/lib/
   ```

3. Generate extension icons (requires Pillow):
   ```bash
   python build/generate_icons.py
   ```

4. Open Chrome and navigate to `chrome://extensions/`

5. Enable "Developer mode" (toggle in top-right)

6. Click "Load unpacked" and select the `extension/` directory

7. The PhishGuard icon appears in your toolbar

**Note:** The background service worker uses a built-in fallback predictor for real-time URL checking. The full ONNX model is used when analyzing URLs via the popup (toolbar icon click or manual input).

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
