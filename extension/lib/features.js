/**
 * Lexical URL feature extraction — JavaScript port of src/lexical/features.py
 * Extracts 57 numerical features from a URL string with zero network requests.
 */

const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "verify", "verification", "account", "password",
  "secure", "bank", "update", "confirm", "wallet", "paypal", "apple",
  "microsoft", "google", "amazon", "ebay", "netflix", "crypto", "reset",
  "otp", "2fa", "authenticate",
];

const KNOWN_BRANDS = [
  "google", "facebook", "amazon", "apple", "microsoft", "netflix",
  "paypal", "ebay", "instagram", "twitter", "linkedin", "youtube",
  "github", "stackoverflow", "reddit", "wikipedia", "whatsapp",
  "snapchat", "tiktok", "discord", "spotify", "uber", "airbnb",
  "dropbox", "adobe", "zoom", "slack", "stripe", "shopify",
  "walmart", "target", "bestbuy", "costco", "homedepot",
  "bankofamerica", "wellsfargo", "chase", "citi", "usaa",
  "hsbc", "barclays", "lloyds", "natwest", "santander",
  "irs", "usps", "fedex", "ups", "dhl",
  "roblox", "steam", "epic",
];

const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
  "buff.ly", "adf.ly", "shorturl.at", "cutt.ly",
]);

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "ru", "cn", "top", "xyz", "country",
  "buzz", "icu", "cam", "rest", "surf", "mom",
  "shop", "click", "sbs", "cfd", "digital", "help",
  "live", "life", "fun", "site", "store", "rent",
]);

const TRUSTED_TLDS = new Set([
  "com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "de",
  "fr", "jp", "au", "ca", "nl", "se", "no", "fi", "dk", "at",
  "ch", "be", "it", "es", "pt", "pl", "cz", "ro", "hu", "bg",
  "hr", "sk", "si", "lt", "lv", "ee", "ie", "nz", "za", "br",
  "mx", "ar", "cl", "pe", "in", "sg", "hk", "tw", "kr",
  "me", "tv", "cc", "ws", "to", "ai",
]);

const FREE_HOSTING = new Set([
  "github.io", "gitbook.io", "appspot.com", "firebaseapp.com",
  "netlify.app", "vercel.app", "pages.dev", "workers.dev",
  "herokuapp.com", "glitch.me", "repl.co", "codesandbox.io",
  "weebly.com", "wixsite.com", "wordpress.com", "blogspot.com",
  "webs.com", "yolasite.com", "ucraft.com", "strikingly.com",
  "carrd.co", "linktr.ee", "beacons.ai", "bio.link",
]);

const FEATURE_NAMES = [
  "url_length", "hostname_length", "path_length",
  "num_dots", "num_hyphens", "num_underscores", "num_slashes",
  "num_question", "num_equal", "num_at", "num_percent", "num_digits",
  "num_subdomains", "has_ip_host", "has_https", "has_port",
  "suspicious_keyword_count", "has_suspicious_tld", "domain_entropy",
  "url_shortener",
  // v2
  "digit_ratio", "hex_encoded_count", "max_consecutive_special",
  "brand_in_domain", "brand_domain_match", "has_port_number",
  "has_single_char_subdomain", "path_depth", "query_length",
  "has_encoded_chars", "domain_digit_count", "hostname_hyphen_count",
  // v3
  "tld_trust_score", "is_free_hosting", "domain_has_digit_insert",
  "registered_domain_length",
  // v4
  "vowel_ratio", "char_repetition_ratio", "has_admin_path",
  "has_suspicious_path", "brand_in_path", "randomness_score",
  "host_to_url_ratio", "path_to_url_ratio", "num_query_params",
  "has_fragment", "max_domain_word_length", "num_domain_words",
  "tld_length", "path_has_numbers", "has_double_slash_path",
  "path_entropy", "domain_vowel_consonant_ratio", "num_special_in_path",
  "has_long_query",
  // v5
  "is_known_legitimate", "domain_name_in_whitelist",
  // v6 (advanced typosquatting & impersonation)
  "brand_near_match", "brand_hyphenated_domain",
  "suspicious_prefix_suffix", "has_non_ascii_chars", "short_unknown_domain",
];

// Common phishing prefixes/suffixes
const SUSPICIOUS_PREFIXES = [
  "secure", "login", "verify", "auth", "account", "bank", "update",
  "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
];

const SUSPICIOUS_SUFFIXES = [
  "secure", "login", "verify", "auth", "account", "bank",
  "center", "hub", "portal", "service", "support", "team",
];

const PHISH_COMBINATION_WORDS = [
  "secure", "login", "verify", "auth", "account", "bank", "update",
  "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
  "center", "hub", "official", "team", "support", "service",
  "online", "access", "identity", "session", "token",
];

// KNOWN_LEGITIMATE_DOMAINS is provided by whitelist.js (loaded first)

function initFeatures(domains) {
  // KNOWN_LEGITIMATE_DOMAINS is already initialized from whitelist.js
  // This hook exists for callers that may want to override in the future.
}

function _entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const n = s.length;
  let h = 0;
  for (const c of Object.values(freq)) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function _isIP(host) {
  if (!host) return false;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function _levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const temp = dp[j];
      dp[j] = Math.min(
        dp[j] + 1,
        dp[j - 1] + 1,
        prev + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      prev = temp;
    }
  }
  return dp[n];
}

function _maxConsecutiveSpecial(s) {
  let mx = 0, cur = 0;
  for (const ch of s) {
    if (!/[a-zA-Z0-9]/.test(ch)) {
      cur++;
      mx = Math.max(mx, cur);
    } else {
      cur = 0;
    }
  }
  return mx;
}

function extractFeatures(url) {
  const raw = url.trim();
  const hasProto = raw.includes("://");
  let parsed;
  try {
    parsed = new URL(hasProto ? raw : "http://" + raw);
  } catch {
    // Fallback for malformed URLs
    parsed = { protocol: "http:", hostname: "", pathname: "", search: "", hash: "" };
  }

  const host = (parsed.hostname || "").toLowerCase();
  const hostNoPort = host.split(":")[0];
  const path = parsed.pathname || "";
  const query = (parsed.search || "").replace(/^\?/, "");

  const lower = raw.toLowerCase();
  let keywordCount = 0;
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lower.includes(kw)) keywordCount++;
  }

  // Subdomain count
  let subdomains = 0;
  if (hostNoPort) {
    const parts = hostNoPort.split(".");
    if (parts.length > 2 || (parts.length === 2 && _isIP(hostNoPort))) {
      subdomains = Math.max(0, parts.length - 2);
    }
  }

  // TLD
  let tld = "";
  if (hostNoPort && hostNoPort.includes(".") && !_isIP(hostNoPort)) {
    tld = hostNoPort.split(".").pop();
  }

  const domainForEntropy = hostNoPort.includes(".")
    ? hostNoPort.split(".").slice(-2, -1)[0] || hostNoPort.split(".")[0]
    : hostNoPort;
  const domainBase = domainForEntropy.toLowerCase();

  // v1 - Structural
  const urlLength = raw.length;
  const hostnameLength = hostNoPort.length;
  const pathLength = path.length;
  const numDots = (raw.match(/\./g) || []).length;
  const numHyphens = (raw.match(/-/g) || []).length;
  const numUnderscores = (raw.match(/_/g) || []).length;
  const numSlashes = (raw.match(/\//g) || []).length;
  const numQuestion = (raw.match(/\?/g) || []).length;
  const numEqual = (raw.match(/=/g) || []).length;
  const numAt = (raw.match(/@/g) || []).length;
  const numPercent = (raw.match(/%/g) || []).length;
  let numDigits = 0;
  for (const ch of raw) {
    if (/\d/.test(ch)) numDigits++;
  }

  const hasIPHost = _isIP(hostNoPort) ? 1 : 0;
  const hasHTTPS = parsed.protocol === "https:" ? 1 : 0;
  const hasPort = host.includes(":") ? 1 : 0;
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  const domainEntropy = _entropy(domainForEntropy);
  const urlShortener = SHORTENER_DOMAINS.has(hostNoPort) ? 1 : 0;

  // v2 - Advanced
  const digitRatio = numDigits / Math.max(urlLength, 1);
  const hexEncoded = (raw.match(/%[0-9a-fA-F]{2}/g) || []).length;
  const maxConsecutiveSpecial = _maxConsecutiveSpecial(raw);

  let brandInDomain = 0;
  let brandDomainMatch = 0;
  for (const brand of KNOWN_BRANDS) {
    if (domainBase.includes(brand)) {
      brandInDomain = 1;
      if (domainBase === brand || _levenshtein(domainBase, brand) <= 1) {
        brandDomainMatch = 1;
        break;
      }
    }
  }

  let hasPortNumber = 0;
  if (host.includes(":")) {
    const portPart = host.split(":").pop();
    if (/^\d+$/.test(portPart) && portPart !== "80" && portPart !== "443") {
      hasPortNumber = 1;
    }
  }

  let hasSingleCharSubdomain = 0;
  const parts = hostNoPort.split(".");
  if (parts.length > 2) {
    for (let i = 0; i < parts.length - 2; i++) {
      if (parts[i].length === 1) {
        hasSingleCharSubdomain = 1;
        break;
      }
    }
  }

  const pathDepth = path.split("/").filter(s => s.length > 0).length;
  const queryLength = query.length;
  const hasEncodedChars = (raw.includes("%") || raw.toLowerCase().includes("&amp;")) ? 1 : 0;
  let domainDigitCount = 0;
  for (const c of domainBase) {
    if (/\d/.test(c)) domainDigitCount++;
  }
  const hostnameHyphenCount = (hostNoPort.match(/-/g) || []).length;

  // v3 - Trust
  let tldTrustScore = 0;
  if (tld) {
    if (TRUSTED_TLDS.has(tld)) tldTrustScore = 1;
    else if (SUSPICIOUS_TLDS.has(tld)) tldTrustScore = 0;
    else tldTrustScore = 0.5;
  }

  let isFreeHosting = 0;
  for (const fh of FREE_HOSTING) {
    if (hostNoPort === fh || hostNoPort.endsWith("." + fh)) {
      isFreeHosting = 1;
      break;
    }
  }

  let domainHasDigitInsert = 0;
  if (/\d/.test(domainBase)) {
    const noDigits = domainBase.replace(/\d/g, "");
    for (const brand of KNOWN_BRANDS) {
      if (noDigits.length >= 3 && _levenshtein(noDigits, brand) <= 2) {
        domainHasDigitInsert = 1;
        break;
      }
    }
  }

  const registeredDomainLength = (domainForEntropy + (tld ? "." + tld : "")).length;

  // v4 - Behavioral
  let vowels = 0;
  for (const c of domainBase) {
    if ("aeiou".includes(c)) vowels++;
  }
  const vowelRatio = vowels / Math.max(domainBase.length, 1);

  const uniqueChars = new Set(domainBase).size;
  const charRepetitionRatio = 1 - (uniqueChars / Math.max(domainBase.length, 1));

  const adminPaths = ["/wp-admin", "/wp-login", "/cgi-bin", "/admin",
    "/phpmyadmin", "/cpanel", "/webmail", "/phpinfo"];
  const hasAdminPath = adminPaths.some(p => path.toLowerCase().includes(p)) ? 1 : 0;

  const suspPaths = ["/login", "/signin", "/verify", "/secure", "/account",
    "/update", "/confirm", "/reset", "/auth", "/session"];
  const hasSuspiciousPath = suspPaths.some(p => path.toLowerCase().includes(p)) ? 1 : 0;

  let brandInPath = 0;
  if (brandInDomain === 1) {
    for (const brand of KNOWN_BRANDS) {
      if (path.toLowerCase().includes(brand)) {
        brandInPath = 1;
        break;
      }
    }
  }

  const allChars = domainBase + path.replace(/\//g, "");
  const randomnessScore = allChars.length > 0
    ? new Set(allChars).size / allChars.length
    : 0;

  const hostToURLRatio = hostNoPort.length / Math.max(urlLength, 1);
  const pathToURLRatio = path.length / Math.max(urlLength, 1);
  const numQueryParams = query ? query.split("&").length : 0;
  const hasFragment = raw.includes("#") ? 1 : 0;

  const domainWords = domainBase.split(/[^a-zA-Z]/).filter(w => w.length >= 2);
  const maxDomainWordLength = domainWords.length > 0
    ? Math.max(...domainWords.map(w => w.length))
    : 0;
  const numDomainWords = domainWords.length;
  const tldLength = tld.length;

  let pathHasNumbers = 0;
  for (const c of path) {
    if (/\d/.test(c)) pathHasNumbers++;
  }

  const hasDoubleSlashPath = path.includes("//") ? 1 : 0;
  const pathEntropy = _entropy(path.replace(/\//g, ""));

  const consonants = domainBase.length - vowels;
  const domainVowelConsonantRatio = vowels / Math.max(consonants, 1);

  let numSpecialInPath = 0;
  for (const c of path) {
    if (!/[a-zA-Z0-9]/.test(c) && c !== "/" && c !== ".") numSpecialInPath++;
  }

  const hasLongQuery = query.length > 100 ? 1 : 0;

  // v5 - Whitelist
  let isKnownLegitimate = 0;
  if (KNOWN_LEGITIMATE_DOMAINS.has(hostNoPort)) {
    isKnownLegitimate = 1;
  } else if (hostNoPort.includes(".") && !_isIP(hostNoPort)) {
    const regCheck = domainForEntropy + (tld ? "." + tld : "");
    if (KNOWN_LEGITIMATE_DOMAINS.has(regCheck)) {
      isKnownLegitimate = 1;
    }
  }

  let domainNameInWhitelist = 0;
  if (isKnownLegitimate === 0) {
    for (const wlDomain of KNOWN_LEGITIMATE_DOMAINS) {
      if (hostNoPort === wlDomain || hostNoPort.endsWith("." + wlDomain)) {
        domainNameInWhitelist = 1;
        break;
      }
    }
  }

  // v6: Advanced typosquatting & impersonation features

  // Brand near-match: Levenshtein distance 1-2 from a known brand
  let brandNearMatch = 0;
  for (const brand of KNOWN_BRANDS) {
    const dist = _levenshtein(domainBase, brand);
    if (dist >= 1 && dist <= 2 && domainBase.length >= 3) {
      brandNearMatch = 1;
      break;
    }
  }

  // Brand hyphenated domain: brand + common word with hyphens
  let brandHyphenatedDomain = 0;
  if (domainBase.includes("-")) {
    const parts = domainBase.split("-");
    if (parts.length === 2) {
      for (const part of parts) {
        for (const brand of KNOWN_BRANDS) {
          if (part === brand || _levenshtein(part, brand) <= 1) {
            const otherPart = parts[0] === brand ? parts[1] : parts[0];
            if (PHISH_COMBINATION_WORDS.some(w => otherPart.includes(w) || _levenshtein(otherPart, w) <= 1)) {
              brandHyphenatedDomain = 1;
              break;
            }
          }
        }
        if (brandHyphenatedDomain === 1) break;
      }
    }
  }

  // Suspicious prefix/suffix with brand
  let suspiciousPrefixSuffix = 0;
  for (const word of SUSPICIOUS_PREFIXES) {
    if (domainBase.startsWith(word + "-") || domainBase.startsWith(word + ".")) {
      const rest = domainBase.slice(word.length + 1);
      for (const brand of KNOWN_BRANDS) {
        if (rest.includes(brand) || _levenshtein(rest, brand) <= 1) {
          suspiciousPrefixSuffix = 1;
          break;
        }
      }
    }
    if (suspiciousPrefixSuffix === 1) break;
  }
  if (suspiciousPrefixSuffix === 0) {
    for (const word of SUSPICIOUS_SUFFIXES) {
      if (domainBase.endsWith("-" + word) || domainBase.endsWith("." + word)) {
        const rest = domainBase.slice(0, -(word.length + 1));
        for (const brand of KNOWN_BRANDS) {
          if (rest.includes(brand) || _levenshtein(rest, brand) <= 1) {
            suspiciousPrefixSuffix = 1;
            break;
          }
        }
      }
      if (suspiciousPrefixSuffix === 1) break;
    }
  }

  // Non-ASCII characters in domain (homograph attacks)
  const hasNonAscii = /[^\x00-\x7F]/.test(domainBase) ? 1 : 0;

  // Short unknown domain
  let shortUnknownDomain = 0;
  if (domainBase.length < 12 && !SHORTENER_DOMAINS.has(hostNoPort) &&
      isKnownLegitimate === 0 && !_isIP(hostNoPort)) {
    if (vowelRatio < 0.3 || _entropy(domainForEntropy) > 3.0) {
      shortUnknownDomain = 1;
    }
  }

  const values = {
    url_length: urlLength,
    hostname_length: hostnameLength,
    path_length: pathLength,
    num_dots: numDots,
    num_hyphens: numHyphens,
    num_underscores: numUnderscores,
    num_slashes: numSlashes,
    num_question: numQuestion,
    num_equal: numEqual,
    num_at: numAt,
    num_percent: numPercent,
    num_digits: numDigits,
    num_subdomains: subdomains,
    has_ip_host: hasIPHost,
    has_https: hasHTTPS,
    has_port: hasPort,
    suspicious_keyword_count: keywordCount,
    has_suspicious_tld: hasSuspiciousTLD,
    domain_entropy: domainEntropy,
    url_shortener: urlShortener,
    digit_ratio: digitRatio,
    hex_encoded_count: hexEncoded,
    max_consecutive_special: maxConsecutiveSpecial,
    brand_in_domain: brandInDomain,
    brand_domain_match: brandDomainMatch,
    has_port_number: hasPortNumber,
    has_single_char_subdomain: hasSingleCharSubdomain,
    path_depth: pathDepth,
    query_length: queryLength,
    has_encoded_chars: hasEncodedChars,
    domain_digit_count: domainDigitCount,
    hostname_hyphen_count: hostnameHyphenCount,
    tld_trust_score: tldTrustScore,
    is_free_hosting: isFreeHosting,
    domain_has_digit_insert: domainHasDigitInsert,
    registered_domain_length: registeredDomainLength,
    vowel_ratio: vowelRatio,
    char_repetition_ratio: charRepetitionRatio,
    has_admin_path: hasAdminPath,
    has_suspicious_path: hasSuspiciousPath,
    brand_in_path: brandInPath,
    randomness_score: randomnessScore,
    host_to_url_ratio: hostToURLRatio,
    path_to_url_ratio: pathToURLRatio,
    num_query_params: numQueryParams,
    has_fragment: hasFragment,
    max_domain_word_length: maxDomainWordLength,
    num_domain_words: numDomainWords,
    tld_length: tldLength,
    path_has_numbers: pathHasNumbers,
    has_double_slash_path: hasDoubleSlashPath,
    path_entropy: pathEntropy,
    domain_vowel_consonant_ratio: domainVowelConsonantRatio,
    num_special_in_path: numSpecialInPath,
    has_long_query: hasLongQuery,
    is_known_legitimate: isKnownLegitimate,
    domain_name_in_whitelist: domainNameInWhitelist,
    // v6
    brand_near_match: brandNearMatch,
    brand_hyphenated_domain: brandHyphenatedDomain,
    suspicious_prefix_suffix: suspiciousPrefixSuffix,
    has_non_ascii_chars: hasNonAscii,
    short_unknown_domain: shortUnknownDomain,
  };

  const vector = FEATURE_NAMES.map(name => values[name]);

  return { url: raw, values, vector };
}

// ES module exports
if (typeof module !== "undefined") {
  module.exports = { extractFeatures, FEATURE_NAMES, SUSPICIOUS_KEYWORDS, KNOWN_BRANDS };
}
