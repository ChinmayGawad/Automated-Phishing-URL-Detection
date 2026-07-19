/**
 * PhishGuard popup logic — handles UI interactions and URL analysis.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const currentUrlEl = document.getElementById("current-url");
  const analyzeCurrentBtn = document.getElementById("analyze-current");
  const analyzeBtn = document.getElementById("analyze-btn");
  const urlInput = document.getElementById("url-input");
  const settingsLink = document.getElementById("settings-link");
  const statusBadge = document.getElementById("status-badge");

  // Initialize whitelist
  initFeatures(KNOWN_LEGITIMATE_DOMAINS);

  // Load config
  const config = await getConfig();
  if (!config.enabled) {
    statusBadge.textContent = "OFF";
    statusBadge.className = "badge badge-off";
    analyzeCurrentBtn.disabled = true;
    analyzeBtn.disabled = true;
    return;
  }

  // Helper: skip browser internal URLs
  function isInternalUrl(url) {
    return /^(chrome|chrome-extension|about|edge|moz-extension|safari-extension):\/\//i.test(url);
  }

  // Get current tab URL
  let currentTabUrl = null;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabUrl = tab.url;
      currentUrlEl.textContent = currentTabUrl;
      analyzeCurrentBtn.disabled = false;
      // Auto-analyze the current URL immediately
      if (isInternalUrl(currentTabUrl)) {
        displayResult("current", { url: currentTabUrl, verdict: "Safe", risk: 0, fastPath: true, latencyMs: 0, notes: ["Browser internal page"] });
      } else {
        analyzeCurrentBtn.disabled = true;
        analyzeCurrentBtn.textContent = "Analyzing...";
        try {
          const result = await analyzeUrl(currentTabUrl, { thresholds: config.thresholds });
          displayResult("current", result);
        } catch (err) {
          console.error("Auto-analysis error:", err);
        } finally {
          analyzeCurrentBtn.disabled = false;
          analyzeCurrentBtn.textContent = "Analyze Current Page";
        }
      }
    } else {
      currentUrlEl.textContent = "No URL available";
    }
  } catch (err) {
    currentUrlEl.textContent = "Unable to get current URL";
  }

  // Analyze current page (manual re-analysis)
  analyzeCurrentBtn.addEventListener("click", async () => {
    if (!currentTabUrl) return;
    if (isInternalUrl(currentTabUrl)) {
      displayResult("current", { url: currentTabUrl, verdict: "Safe", risk: 0, fastPath: true, latencyMs: 0, notes: ["Browser internal page"] });
      return;
    }
    analyzeCurrentBtn.disabled = true;
    analyzeCurrentBtn.textContent = "Analyzing...";
    try {
      const result = await analyzeUrl(currentTabUrl, { thresholds: config.thresholds });
      displayResult("current", result);
    } catch (err) {
      console.error("Analysis error:", err);
    } finally {
      analyzeCurrentBtn.disabled = false;
      analyzeCurrentBtn.textContent = "Analyze Current Page";
    }
  });

  // Analyze manual URL
  analyzeBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) return;
    if (isInternalUrl(url)) {
      displayResult("manual", { url, verdict: "Safe", risk: 0, fastPath: true, latencyMs: 0, notes: ["Browser internal page"] });
      return;
    }
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";
    try {
      const result = await analyzeUrl(url, { thresholds: config.thresholds });
      displayResult("manual", result);
    } catch (err) {
      console.error("Analysis error:", err);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Analyze";
    }
  });

  // Enter key to analyze
  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      analyzeBtn.click();
    }
  });

  // Settings link
  settingsLink.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});

function displayResult(prefix, result) {
  const container = document.getElementById(`${prefix}-result`);
  const verdictEl = document.getElementById(`${prefix}-verdict`);
  const riskFillEl = document.getElementById(`${prefix}-risk-fill`);
  const riskTextEl = document.getElementById(`${prefix}-risk-text`);

  container.classList.remove("hidden");

  // Verdict
  const verdictClass = {
    "Safe": "verdict-safe",
    "Suspicious": "verdict-suspicious",
    "Phishing": "verdict-phishing",
  }[result.verdict] || "verdict-safe";

  const verdictIcon = {
    "Safe": "\u2713",
    "Suspicious": "!",
    "Phishing": "\u2717",
  }[result.verdict] || "?";

  verdictEl.className = `verdict ${verdictClass}`;
  verdictEl.innerHTML = `<span class="verdict-icon">${verdictIcon}</span> ${result.verdict}`;

  // Risk bar
  const riskPercent = Math.round(result.risk * 100);
  riskFillEl.style.width = `${riskPercent}%`;

  const riskColor = result.risk <= 0.33
    ? "#66bb6a"
    : result.risk >= 0.66
      ? "#ef5350"
      : "#ffa726";
  riskFillEl.style.background = riskColor;

  riskTextEl.textContent = `Risk: ${riskPercent}% | ${result.fastPath ? "Fast-path" : "Full analysis"} | ${Math.round(result.latencyMs)}ms`;
}
