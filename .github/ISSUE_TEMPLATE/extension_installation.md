---
name: EXTENSION_INSTALLATION
about: Installation
title: ''
labels: ''
assignees: ''

---

# 🧩 How to Download & Install the PhishGuard Chrome Extension

This guide provides step-by-step instructions for downloading, installing, and running the **PhishGuard Chrome Extension** on your browser (Google Chrome, Microsoft Edge, Brave, or Opera).

---

## 📥 Step 1: Download the Extension

You can obtain the extension files in one of two ways:

### Method A: Download ZIP (Easiest)
1. Go to the GitHub repository: [Automated-Phishing-URL-Detection](https://github.com/ChinmayGawad/Automated-Phishing-URL-Detection)
2. Click the green **`<> Code`** button near the top right.
3. Select **`Download ZIP`**.
4. Extract the downloaded ZIP file to a folder on your computer.

### Method B: Clone via Git
```bash
git clone https://github.com/ChinmayGawad/Automated-Phishing-URL-Detection.git
cd Automated-Phishing-URL-Detection
git lfs pull
```

---

## ⚙️ Step 2: Verify Pre-trained Model

The repository already includes the pre-packaged ONNX machine learning model for browser inference:
- Path: `extension/models/lexical.onnx` (~170 KB)

*No build or compilation steps are required—it is ready to run right after downloading!*

---

## 🔌 Step 3: Install in Your Browser

The extension runs on any Chromium-based browser (Chrome, Edge, Brave, Opera, Vivaldi).

### For Google Chrome & Brave:
1. Open your browser and navigate to `chrome://extensions/`.
2. Turn ON **Developer mode** using the toggle in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Browse to the downloaded/extracted project folder and select the **`extension`** directory.
5. The **PhishGuard** extension icon will now appear in your browser toolbar!

### For Microsoft Edge:
1. Navigate to `edge://extensions/`.
2. Enable **Developer mode** in the left sidebar.
3. Click **Load unpacked** and select the **`extension`** directory.

---

## 🛡️ Step 4: How to Use PhishGuard

1. **Automatic Navigation Protection**: As you browse, PhishGuard checks URLs in real time. If a site is identified as phishing, a warning alert or block screen is displayed.
2. **Toolbar Popup**: Click the PhishGuard icon in your extension bar to:
   - Inspect the safety score of your current active tab.
   - Manually paste and analyze any suspicious link.
3. **Settings**: Right-click the icon $\rightarrow$ *Options* (or click Settings inside the popup) to adjust detection modes (Block, Alert, or Both) and sensitivity thresholds.

---

## 🔍 Troubleshooting

- **Extension error on load?** Ensure you selected the **`extension/`** folder itself (the folder containing `manifest.json`), not the root project folder.
- **Model missing?** Verify `extension/models/lexical.onnx` exists. If missing, generate it by running `python build/export_model.py` in the root folder.
