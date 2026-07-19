/**
 * PhishGuard background service worker — handles real-time URL checking,
 * message routing, and badge management.
 */

// Import library files
importScripts(
  "../lib/whitelist.js",
  "../lib/features.js",
  "../lib/model.js",
  "../lib/analyzer.js",
  "../lib/config.js"
);

// Initialize whitelist
initFeatures(KNOWN_LEGITIMATE_DOMAINS);

// Track analyzed URLs to avoid re-analyzing
const analyzedUrls = new Map();

// Badge colors
const BADGE_COLORS = {
  Safe: "#43a047",
  Suspicious: "#fb8c00",
  Phishing: "#e53935",
};

// ===== Message handling from popup and content scripts =====

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_URL") {
    handleAnalyzeUrl(message.url)
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ error: err.message }));
    return true; // Keep message channel open for async response
  }

  if (message.type === "GET_CONFIG") {
    getConfig().then(config => sendResponse(config));
    return true;
  }

  if (message.type === "UPDATE_CONFIG") {
    updateConfig(message.config).then(config => sendResponse(config));
    return true;
  }
});

// ===== Real-time URL checking =====

chrome.webNavigation.onCompleted.addListener(
  async (details) => {
    // Only check main frame navigations
    if (details.frameId !== 0) return;

    const config = await getConfig();
    if (!config.enabled || !config.realTimeCheck) return;

    const url = details.url;
    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

    try {
      const result = await handleAnalyzeUrl(url);
      await applyVerdict(details.tabId, result, config);
    } catch (err) {
      console.error("PhishGuard: Real-time check failed:", err);
    }
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// ===== Core analysis handler =====

async function handleAnalyzeUrl(url) {
  // Check cache first (avoid re-analyzing the same URL within 5 minutes)
  const cached = analyzedUrls.get(url);
  if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) {
    return cached.result;
  }

  const config = await getConfig();
  const result = await analyzeUrl(url, { thresholds: config.thresholds });

  // Cache the result
  analyzedUrls.set(url, { result, timestamp: Date.now() });

  // Clean up old cache entries (keep max 100)
  if (analyzedUrls.size > 100) {
    const oldest = analyzedUrls.keys().next().value;
    analyzedUrls.delete(oldest);
  }

  return result;
}

// ===== Apply verdict to tab =====

async function applyVerdict(tabId, result, config) {
  if (!config.showBadge) return;

  // Update badge
  const color = BADGE_COLORS[result.verdict] || BADGE_COLORS.Safe;
  const text = result.verdict === "Safe" ? "" : result.verdict[0];

  try {
    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setBadgeText({ text, tabId });
  } catch (err) {
    // Badge API might not be available in all contexts
  }

  // Handle phishing/suspicious verdicts
  if (result.verdict === "Phishing" || result.verdict === "Suspicious") {
    const shouldBlock = config.blockMode === "block" || config.blockMode === "both";
    const shouldAlert = config.blockMode === "alert" || config.blockMode === "both";

    if (shouldBlock) {
      // Redirect to warning page
      const warningUrl = chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(result.url)}&reasons=${encodeURIComponent(JSON.stringify(result.notes))}`
      );
      try {
        await chrome.tabs.update(tabId, { url: warningUrl });
      } catch (err) {
        console.error("PhishGuard: Failed to redirect to warning page:", err);
      }
    }

    if (shouldAlert) {
      // Show notification
      try {
        await chrome.notifications.create(`phishguard-${tabId}`, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon128.png"),
          title: `PhishGuard: ${result.verdict}`,
          message: `Potentially ${result.verdict.toLowerCase()} URL detected: ${result.url}`,
          priority: 2,
        });
      } catch (err) {
        console.error("PhishGuard: Failed to show notification:", err);
      }
    }
  }
}

// ===== Context menu =====

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-analyze",
    title: "Analyze URL with PhishGuard",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "phishguard-analyze" && info.linkUrl) {
    try {
      const result = await handleAnalyzeUrl(info.linkUrl);
      const config = await getConfig();

      // Show result as notification
      const iconUrl = result.verdict === "Safe"
        ? "icons/icon48.png"
        : "icons/icon128.png";

      await chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL(iconUrl),
        title: `PhishGuard: ${result.verdict}`,
        message: `${info.linkUrl}\nRisk: ${Math.round(result.risk * 100)}%`,
        priority: 1,
      });
    } catch (err) {
      console.error("PhishGuard: Context menu analysis failed:", err);
    }
  }
});

// ===== Notification click handling =====

if (chrome.notifications && chrome.notifications.onClicked) {
  chrome.notifications.onClicked.addListener((notificationId) => {
    if (notificationId.startsWith("phishguard-")) {
      const tabId = parseInt(notificationId.split("-")[1]);
      if (!isNaN(tabId)) {
        chrome.tabs.update(tabId, { active: true });
      }
    }
  });
}

console.log("PhishGuard: Service worker loaded");
