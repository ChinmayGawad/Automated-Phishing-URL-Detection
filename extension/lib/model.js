/**
 * ONNX model inference wrapper for the lexical phishing classifier.
 * Uses onnxruntime-web to run the sklearn stacking ensemble in-browser.
 *
 * This script expects onnxruntime to be loaded globally (via <script> tag
 * or bundled). The ONNX Runtime WebAssembly files should be placed in
 * the extension's directory.
 */

let _session = null;
let _loading = false;
let _loadPromise = null;

// Get reference to onnxruntime (loaded globally or via import)
function getORT() {
  if (typeof ort !== "undefined") return ort;
  if (typeof OnnxRuntime !== "undefined") return OnnxRuntime;
  return null;
}

async function loadModel() {
  if (_session) return _session;
  if (_loadPromise) return _loadPromise;

  _loading = true;
  _loadPromise = (async () => {
    try {
      const ort = getORT();
      if (!ort) {
        console.error("PhishGuard: onnxruntime-web not loaded. Add <script> tag for onnxruntime-web.");
        return null;
      }

      // Configure wasm path for Chrome extension
      if (typeof chrome !== "undefined" && chrome.runtime) {
        ort.env.wasm.wasmPaths = chrome.runtime.getURL("lib/");
      }

      const modelPath = chrome.runtime.getURL("models/lexical.onnx");
      const response = await fetch(modelPath);
      if (!response.ok) {
        console.error("PhishGuard: Failed to fetch model:", response.status);
        return null;
      }

      const modelBuffer = await response.arrayBuffer();
      _session = await ort.InferenceSession.create(modelBuffer);
      console.log("PhishGuard: Model loaded successfully");
      return _session;
    } catch (err) {
      console.error("PhishGuard: Model load error:", err);
      _session = null;
      return null;
    } finally {
      _loading = false;
    }
  })();

  return _loadPromise;
}

async function predictProba(vector) {
  const session = await loadModel();
  if (!session) {
    // Fallback: use simple rule-based scoring if model unavailable
    return fallbackPredict(vector);
  }

  try {
    const ort = getORT();
    const inputTensor = new Float32Array(vector);
    const inputShape = [1, vector.length];

    const feeds = {};
    const inputName = session.inputNames[0];

    if (ort && ort.Tensor) {
      feeds[inputName] = new ort.Tensor("float32", inputTensor, inputShape);
    } else {
      // Fallback for environments without ort.Tensor
      return fallbackPredict(vector);
    }

    const results = await session.run(feeds);
    // The ONNX model outputs two tensors: 'label' (int64) and 'probabilities'
    // (float32 [p_class0, p_class1]). Use the probabilities tensor.
    const probName = session.outputNames.includes("probabilities")
      ? "probabilities"
      : session.outputNames[session.outputNames.length - 1];
    const output = results[probName];

    // probabilities = [prob_class_0, prob_class_1]; we want class 1 (phishing).
    if (output.data.length >= 2) {
      return output.data[1]; // phishing probability
    }
    return output.data[0];
  } catch (err) {
    console.error("PhishGuard: Inference error:", err);
    return fallbackPredict(vector);
  }
}

/**
 * Simple fallback predictor when ONNX model is unavailable.
 * Uses a weighted combination of key features to estimate risk.
 */
function fallbackPredict(vector) {
  if (!vector || vector.length < 77) return 0.5;

  let risk = 0.5; // neutral baseline

  // Key phishing indicators (feature indices from FEATURE_NAMES, 77-feature order)
  const urlLength = vector[0];           // url_length
  const hasIP = vector[13];              // has_ip_host
  const hasHTTPS = vector[14];           // has_https
  const suspKeyword = vector[16];        // suspicious_keyword_count
  const suspTLD = vector[17];            // has_suspicious_tld
  const brandInDomain = vector[23];      // brand_in_domain
  const brandMatch = vector[24];         // brand_domain_match
  const tldTrust = vector[31];           // tld_trust_score
  const isFreeHosting = vector[32];      // is_free_hosting
  const isKnownLegit = vector[56];       // is_known_legitimate

  // Known legitimate = very safe
  if (isKnownLegit > 0) return 0.05;

  // IP-based host = very suspicious
  if (hasIP > 0) risk += 0.3;

  // No HTTPS = slightly suspicious
  if (hasHTTPS === 0) risk += 0.05;

  // Suspicious keywords
  risk += Math.min(suspKeyword * 0.05, 0.2);

  // Suspicious TLD
  if (suspTLD > 0) risk += 0.15;

  // Brand impersonation
  if (brandMatch > 0) risk += 0.25;
  else if (brandInDomain > 0) risk += 0.1;

  // TLD trust
  if (tldTrust < 0.5) risk += 0.1;

  // Free hosting
  if (isFreeHosting > 0) risk += 0.1;

  // Long URLs are more suspicious
  if (urlLength > 75) risk += 0.05;
  if (urlLength > 150) risk += 0.1;

  return Math.max(0, Math.min(1, risk));
}

function isModelLoading() {
  return _loading;
}

function isModelLoaded() {
  return _session !== null;
}
