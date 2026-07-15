/**
 * Phishing URL analyzer — orchestrates the hybrid pipeline with both
 * rule-based and ML-based detection for maximum coverage.
 */

const DEFAULT_THRESHOLDS = {
  fastPathSafe: 0.15,
  fastPathMalicious: 0.85,
  safeThreshold: 0.33,
  phishingThreshold: 0.66,
};

// Known brand names for rule-based detection
const KNOWN_BRANDS = [
  "google", "facebook", "amazon", "apple", "microsoft", "netflix",
  "paypal", "ebay", "instagram", "twitter", "linkedin", "youtube",
  "github", "reddit", "whatsapp", "snapchat", "tiktok", "discord",
  "spotify", "uber", "airbnb", "dropbox", "adobe", "zoom", "slack",
  "stripe", "shopify", "walmart", "target", "bestbuy", "costco",
  "bankofamerica", "wellsfargo", "chase", "citi", "roblox", "steam", "epic",
];

// Common phishing combination words
const PHISH_WORDS = [
  "secure", "login", "verify", "auth", "account", "bank", "update",
  "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
  "center", "hub", "official", "team", "support", "service",
];

/**
 * Levenshtein distance between two strings
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const temp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = temp;
    }
  }
  return dp[n];
}

/**
 * Rule-based phishing detection — catches patterns the ML model might miss.
 * Returns { score, reason } where score is 0-1 (higher = more suspicious).
 */
function ruleBasedCheck(url) {
  let parsed;
  try {
    parsed = new URL(url.includes("://") ? url : "http://" + url);
  } catch {
    return { score: 0.3, reason: "Malformed URL" };
  }

  const host = (parsed.hostname || "").toLowerCase().split(":")[0];
  const domain = host.split(".").slice(-2, -1)[0] || host.split(".")[0];
  const path = (parsed.pathname || "").toLowerCase();

  let suspicionScore = 0;
  const reasons = [];

  // Rule 1: Brand near-match (Levenshtein distance 1-2)
  for (const brand of KNOWN_BRANDS) {
    const dist = levenshtein(domain, brand);
    if (dist >= 1 && dist <= 2 && domain.length >= 3) {
      suspicionScore += 0.6;
      reasons.push(`Domain '${domain}' is ${dist} edit(s) away from brand '${brand}'`);
      break;
    }
  }

  // Rule 2: Hyphenated brand impersonation
  if (domain.includes("-")) {
    const parts = domain.split("-");
    if (parts.length === 2) {
      for (const part of parts) {
        for (const brand of KNOWN_BRANDS) {
          if (part === brand || levenshtein(part, brand) <= 1) {
            const otherPart = parts[0] === brand ? parts[1] : parts[0];
            if (PHISH_WORDS.some(w => otherPart.includes(w) || levenshtein(otherPart, w) <= 1)) {
              suspicionScore += 0.7;
              reasons.push(`Hyphenated brand impersonation: '${domain}'`);
              break;
            }
          }
        }
        if (suspicionScore > 0.5) break;
      }
    }
  }

  // Rule 3: Suspicious prefix/suffix with brand
  for (const word of PHISH_WORDS) {
    if (domain.startsWith(word + "-") || domain.startsWith(word + ".")) {
      const rest = domain.slice(word.length + 1);
      for (const brand of KNOWN_BRANDS) {
        if (rest.includes(brand) || levenshtein(rest, brand) <= 1) {
          suspicionScore += 0.6;
          reasons.push(`Suspicious prefix '${word}' with brand in '${domain}'`);
          break;
        }
      }
    }
    if (domain.endsWith("-" + word) || domain.endsWith("." + word)) {
      const rest = domain.slice(0, -(word.length + 1));
      for (const brand of KNOWN_BRANDS) {
        if (rest.includes(brand) || levenshtein(rest, brand) <= 1) {
          suspicionScore += 0.6;
          reasons.push(`Suspicious suffix '-${word}' with brand in '${domain}'`);
          break;
        }
      }
    }
  }

  // Rule 4: Short unknown domain with brand-like patterns
  if (domain.length < 12 && !host.includes("google.com") && !host.includes("github.com")) {
    for (const brand of KNOWN_BRANDS) {
      if (domain.includes(brand) || levenshtein(domain, brand) <= 2) {
        suspicionScore += 0.4;
        reasons.push(`Short domain '${domain}' contains brand pattern`);
        break;
      }
    }
  }

  // Rule 5: IP address as host
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    suspicionScore += 0.5;
    reasons.push("IP address used as hostname");
  }

  // Rule 6: Free hosting with brand in path
  const freeHosts = ["github.io", "gitbook.io", "appspot.com", "netlify.app",
    "vercel.app", "pages.dev", "herokuapp.com", "weebly.com"];
  if (freeHosts.some(fh => host.endsWith(fh))) {
    for (const brand of KNOWN_BRANDS) {
      if (domain.includes(brand) || path.includes(brand)) {
        suspicionScore += 0.5;
        reasons.push(`Free hosting '${host}' with brand reference`);
        break;
      }
    }
  }

  // Rule 7: Data URI
  if (url.startsWith("data:")) {
    suspicionScore += 0.8;
    reasons.push("Data URI detected (potential XSS)");
  }

  return {
    score: Math.min(1, suspicionScore),
    reason: reasons.join("; ") || "No rule triggered",
  };
}

async function analyzeUrl(url, options = {}) {
  const startTime = performance.now();
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds };

  // Stage 0: Whitelist fast-path (most reliable signal)
  if (checkWhitelist(url)) {
    return {
      url,
      verdict: "Safe",
      risk: 0.0,
      fastPath: true,
      latencyMs: performance.now() - startTime,
      notes: ["Domain is in known legitimate whitelist -> Safe."],
    };
  }

  // Stage 0.5: Rule-based check (catches patterns ML might miss)
  const ruleResult = ruleBasedCheck(url);
  if (ruleResult.score >= 0.5) {
    return {
      url,
      verdict: "Phishing",
      risk: ruleResult.score,
      fastPath: true,
      latencyMs: performance.now() - startTime,
      notes: [`Rule-based detection: ${ruleResult.reason}`],
    };
  }

  // Stage 1: Lexical feature extraction
  const features = extractFeatures(url);

  // Stage 2: Model inference
  const mlProb = await predictProba(features.vector);

  // Combine ML probability with rule-based score
  const combinedRisk = Math.max(mlProb, ruleResult.score * 0.8);

  // Fast-path: high confidence -> no further analysis needed
  if (combinedRisk <= thresholds.fastPathSafe) {
    return {
      url,
      verdict: "Safe",
      risk: combinedRisk,
      fastPath: true,
      latencyMs: performance.now() - startTime,
      notes: ["Combined score confident -> Safe fast-path."],
    };
  }

  if (combinedRisk >= thresholds.fastPathMalicious) {
    return {
      url,
      verdict: "Phishing",
      risk: combinedRisk,
      fastPath: true,
      latencyMs: performance.now() - startTime,
      notes: ["Combined score confident -> Phishing fast-path."],
    };
  }

  // Apply thresholds
  let verdict;
  if (combinedRisk <= thresholds.safeThreshold) {
    verdict = "Safe";
  } else if (combinedRisk >= thresholds.phishingThreshold) {
    verdict = "Phishing";
  } else {
    verdict = "Suspicious";
  }

  const notes = [`ML probability: ${mlProb.toFixed(3)}`];
  if (ruleResult.score > 0) {
    notes.push(`Rule score: ${ruleResult.score.toFixed(2)} - ${ruleResult.reason}`);
  }
  notes.push(`Combined risk: ${combinedRisk.toFixed(3)} -> ${verdict}`);

  return {
    url,
    verdict,
    risk: combinedRisk,
    fastPath: false,
    latencyMs: performance.now() - startTime,
    notes,
  };
}
