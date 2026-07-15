/**
 * PhishGuard options page logic — handles settings UI and persistence.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const enabled = document.getElementById("enabled");
  const realTimeCheck = document.getElementById("realTimeCheck");
  const showBadge = document.getElementById("showBadge");
  const blockMode = document.getElementById("blockMode");
  const safeThreshold = document.getElementById("safeThreshold");
  const safeThresholdValue = document.getElementById("safeThresholdValue");
  const phishingThreshold = document.getElementById("phishingThreshold");
  const phishingThresholdValue = document.getElementById("phishingThresholdValue");
  const saveBtn = document.getElementById("save");
  const resetBtn = document.getElementById("reset");
  const saveStatus = document.getElementById("save-status");

  // Load current config
  const config = await getConfig();

  // Set UI values
  enabled.checked = config.enabled;
  realTimeCheck.checked = config.realTimeCheck;
  showBadge.checked = config.showBadge;
  blockMode.value = config.blockMode;
  safeThreshold.value = config.thresholds.safeThreshold;
  safeThresholdValue.textContent = config.thresholds.safeThreshold.toFixed(2);
  phishingThreshold.value = config.thresholds.phishingThreshold;
  phishingThresholdValue.textContent = config.thresholds.phishingThreshold.toFixed(2);

  // Update displayed values on slider change
  safeThreshold.addEventListener("input", () => {
    safeThresholdValue.textContent = parseFloat(safeThreshold.value).toFixed(2);
  });

  phishingThreshold.addEventListener("input", () => {
    phishingThresholdValue.textContent = parseFloat(phishingThreshold.value).toFixed(2);
  });

  // Save settings
  saveBtn.addEventListener("click", async () => {
    const newConfig = {
      enabled: enabled.checked,
      realTimeCheck: realTimeCheck.checked,
      showBadge: showBadge.checked,
      blockMode: blockMode.value,
      thresholds: {
        fastPathSafe: 0.15,
        fastPathMalicious: 0.85,
        safeThreshold: parseFloat(safeThreshold.value),
        phishingThreshold: parseFloat(phishingThreshold.value),
      },
    };

    await setConfig(newConfig);

    // Notify service worker of config change
    try {
      chrome.runtime.sendMessage({ type: "UPDATE_CONFIG", config: newConfig });
    } catch {
      // Service worker might not be ready
    }

    // Show save confirmation
    saveStatus.textContent = "Settings saved!";
    saveStatus.classList.add("visible");
    setTimeout(() => {
      saveStatus.classList.remove("visible");
    }, 2000);
  });

  // Reset to defaults
  resetBtn.addEventListener("click", async () => {
    if (confirm("Reset all settings to defaults?")) {
      await setConfig(DEFAULT_CONFIG);

      // Update UI
      enabled.checked = DEFAULT_CONFIG.enabled;
      realTimeCheck.checked = DEFAULT_CONFIG.realTimeCheck;
      showBadge.checked = DEFAULT_CONFIG.showBadge;
      blockMode.value = DEFAULT_CONFIG.blockMode;
      safeThreshold.value = DEFAULT_CONFIG.thresholds.safeThreshold;
      safeThresholdValue.textContent = DEFAULT_CONFIG.thresholds.safeThreshold.toFixed(2);
      phishingThreshold.value = DEFAULT_CONFIG.thresholds.phishingThreshold;
      phishingThresholdValue.textContent = DEFAULT_CONFIG.thresholds.phishingThreshold.toFixed(2);

      saveStatus.textContent = "Settings reset to defaults!";
      saveStatus.classList.add("visible");
      setTimeout(() => {
        saveStatus.classList.remove("visible");
      }, 2000);
    }
  });
});
