/**
 * PhishGuard content script — injects warning banners for non-blocking alerts.
 * Runs in the context of web pages.
 */

(function () {
  "use strict";

  let bannerEl = null;

  // Listen for messages from the background service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SHOW_WARNING_BANNER") {
      showBanner(message.result);
      sendResponse({ success: true });
    }

    if (message.type === "DISMISS_BANNER") {
      dismissBanner();
      sendResponse({ success: true });
    }
  });

  function showBanner(result) {
    // Don't show duplicate banners
    if (bannerEl) return;

    const verdict = result.verdict || "Suspicious";
    const risk = result.risk || 0;
    const notes = result.notes || [];

    // Create banner element
    bannerEl = document.createElement("div");
    bannerEl.id = "phishguard-banner";

    const isPhishing = verdict === "Phishing";
    const bgColor = isPhishing ? "#b71c1c" : "#e65100";
    const borderColor = isPhishing ? "#ef5350" : "#ffa726";

    bannerEl.innerHTML = `
      <style>
        #phishguard-banner {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 2147483647;
          background: ${bgColor};
          color: white;
          padding: 12px 16px;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          font-size: 14px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          box-shadow: 0 2px 8px rgba(0,0,0,0.3);
          border-bottom: 2px solid ${borderColor};
        }
        #phishguard-banner .left {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        #phishguard-banner .icon {
          font-size: 20px;
        }
        #phishguard-banner .text {
          display: flex;
          flex-direction: column;
        }
        #phishguard-banner .title {
          font-weight: 600;
        }
        #phishguard-banner .subtitle {
          font-size: 12px;
          opacity: 0.9;
        }
        #phishguard-banner .dismiss {
          background: transparent;
          border: 1px solid rgba(255,255,255,0.3);
          color: white;
          padding: 6px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
        }
        #phishguard-banner .dismiss:hover {
          background: rgba(255,255,255,0.1);
        }
      </style>
      <div class="left">
        <span class="icon">\u26A0</span>
        <div class="text">
          <span class="title">PhishGuard: ${verdict}</span>
          <span class="subtitle">This page may be a phishing site. Risk: ${Math.round(risk * 100)}%</span>
        </div>
      </div>
      <button class="dismiss" id="phishguard-dismiss">Dismiss</button>
    `;

    document.body.prepend(bannerEl);

    // Add dismiss handler
    document.getElementById("phishguard-dismiss").addEventListener("click", dismissBanner);

    // Auto-dismiss after 10 seconds
    setTimeout(dismissBanner, 10000);
  }

  function dismissBanner() {
    if (bannerEl) {
      bannerEl.remove();
      bannerEl = null;
    }
  }
})();
