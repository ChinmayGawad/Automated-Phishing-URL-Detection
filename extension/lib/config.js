/**
 * Configuration management for PhishGuard extension.
 * Uses chrome.storage.sync for persistence.
 */

const DEFAULT_CONFIG = {
  enabled: true,
  realTimeCheck: true,
  blockMode: "both", // "block" | "alert" | "both"
  showBadge: true,
  thresholds: {
    fastPathSafe: 0.15,
    fastPathMalicious: 0.85,
    safeThreshold: 0.33,
    phishingThreshold: 0.66,
  },
};

async function getConfig() {
  return new Promise((resolve) => {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.sync.get("phishguard_config", (result) => {
        resolve({ ...DEFAULT_CONFIG, ...result.phishguard_config });
      });
    } else {
      resolve({ ...DEFAULT_CONFIG });
    }
  });
}

async function setConfig(config) {
  return new Promise((resolve) => {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.sync.set({ phishguard_config: config }, resolve);
    } else {
      resolve();
    }
  });
}

async function updateConfig(partial) {
  const current = await getConfig();
  const updated = { ...current, ...partial };
  if (partial.thresholds) {
    updated.thresholds = { ...current.thresholds, ...partial.thresholds };
  }
  await setConfig(updated);
  return updated;
}

// ES module exports
if (typeof module !== "undefined") {
  module.exports = { DEFAULT_CONFIG, getConfig, setConfig, updateConfig };
}
