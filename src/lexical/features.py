"""Lexical URL feature extraction.

Extracts numerical features from a URL string without performing any network
request. All features are deterministic and cheap to compute, which is what
makes Stage 1 suitable as a low-latency fast-path classifier.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

logger = logging.getLogger("phishguard.features")

# Keywords frequently abused by phishing pages to create a sense of urgency or
# impersonate a brand's account flow.
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "verification", "account", "password",
    "secure", "bank", "update", "confirm", "wallet", "paypal", "apple",
    "microsoft", "google", "amazon", "ebay", "netflix", "crypto", "reset",
    "otp", "2fa", "authenticate",
)

# Import shared constants from the centralized module.
from ..utils.constants import KNOWN_BRANDS, SUSPICIOUS_TLDS, TRUSTED_TLDS
from ..utils.constants import FREE_HOSTING, SHORTENER_DOMAINS, PHISH_WORDS

# Feature names, in a stable order. Used by both training and inference.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question",
    "num_equal",
    "num_at",
    "num_percent",
    "num_digits",
    "num_subdomains",
    "has_ip_host",
    "has_https",
    "has_port",
    "suspicious_keyword_count",
    "has_suspicious_tld",
    "domain_entropy",
    "url_shortener",
    # --- new features (v2) ---
    "digit_ratio",
    "hex_encoded_count",
    "max_consecutive_special",
    "brand_in_domain",
    "brand_domain_match",
    "has_port_number",
    "has_single_char_subdomain",
    "path_depth",
    "query_length",
    "has_encoded_chars",
    "domain_digit_count",
    "hostname_hyphen_count",
    # --- v3 features ---
    "tld_trust_score",
    "is_free_hosting",
    "domain_has_digit_insert",
    "registered_domain_length",
    # --- v4 features ---
    "vowel_ratio",
    "char_repetition_ratio",
    "has_admin_path",
    "has_suspicious_path",
    "brand_in_path",
    "randomness_score",
    "host_to_url_ratio",
    "path_to_url_ratio",
    "num_query_params",
    "has_fragment",
    "max_domain_word_length",
    "num_domain_words",
    "tld_length",
    "path_has_numbers",
    "has_double_slash_path",
    "path_entropy",
    "domain_vowel_consonant_ratio",
    "num_special_in_path",
    "has_long_query",
    # --- v5 features ---
    "is_known_legitimate",
    "domain_name_in_whitelist",
    # --- v6 features (advanced typosquatting & impersonation) ---
    "brand_near_match",
    "brand_hyphenated_domain",
    "suspicious_prefix_suffix",
    "has_non_ascii_chars",
    "short_unknown_domain",
    # --- v7 features (advanced patterns & interactions) ---
    "domain_consonant_cluster_ratio",
    "url_encoding_density",
    "domain_starts_with_digit",
    "domain_ends_with_digit",
    "path_has_file_extension",
    "has_suspicious_file_ext",
    "domain_has_repeated_chars",
    "domain_avg_word_length",
    "path_to_domain_ratio",
    "has_double_scheme",
    "brand_min_levenshtein",
    "domain_digit_ratio",
    "path_segment_count",
    "query_has_encoded",
    "has_suspicious_port",
]

# Common phishing prefixes/suffixes used to impersonate brands
SUSPICIOUS_PREFIXES = (
    "secure", "login", "verify", "auth", "account", "bank", "update",
    "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
    "my", "app", "admin", "panel", "console", "dashboard",
)

SUSPICIOUS_SUFFIXES = (
    "secure", "login", "verify", "auth", "account", "bank", "update",
    "confirm", "wallet", "crypto", "pay", "center", "hub", "portal",
    "service", "support", "help", "team", "staff", "official",
)

# Words commonly combined with brand names in phishing domains
PHISH_COMBINATION_WORDS = (
    "secure", "login", "verify", "auth", "account", "bank", "update",
    "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
    "center", "hub", "official", "team", "support", "service",
    "online", "access", "identity", "session", "token",
)

# Known legitimate domains (major internet sites).
# This is how real-world phishing detectors work — domain reputation is
# the single most reliable signal. A domain in this list is almost
# certainly NOT a phishing site, regardless of URL structure.
KNOWN_LEGITIMATE_DOMAINS = frozenset({
    # Search / Tech giants
    "google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
    "google.ca", "google.com.au", "google.co.in", "google.com.br",
    "google.it", "google.es", "google.nl", "google.pl", "google.ru",
    "google.cn", "google.com.hk", "google.com.sg", "google.co.kr",
    "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
    # Social media
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com",
    "snapchat.com", "tiktok.com", "whatsapp.com", "telegram.org",
    "telegram.me", "telegram.dog", "discord.com", "discord.gg",
    "quora.com", "medium.com", "substack.com", "threads.net",
    "mastodon.social", "bsky.app",
    # Video / Music
    "youtube.com", "youtu.be", "twitch.tv", "vimeo.com",
    "soundcloud.com", "spotify.com", "open.spotify.com",
    "deezer.com", "pandora.com", "music.apple.com",
    # Developer / Code
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "stackoverflow.com", "stackexchange.com", "dev.to",
    "npmjs.com", "pypi.org", "crates.io", "rubygems.org",
    "nuget.org", "packagist.org", "maven.org", "crates.io",
    "docker.com", "docker.io", "hub.docker.com",
    "vercel.com", "netlify.com", "heroku.com", "firebase.google.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "digitalocean.com", "linode.com", "vultr.com",
    "railway.app", "fly.io", "render.com", "replit.com",
    "codesandbox.io", "stackblitz.com", "glitch.com",
    "gitbook.io", "readthedocs.io",
    # Cloud / Enterprise
    "aws.amazon.com", "console.aws.amazon.com",
    "cloud.google.com", "console.cloud.google.com",
    "azure.microsoft.com", "portal.azure.com",
    "salesforce.com", "hubspot.com", "zoho.com",
    "slack.com", "app.slack.com", "teams.microsoft.com",
    "zoom.us", "webex.com", "gotomeeting.com",
    "jira.atlassian.com", "confluence.atlassian.com",
    "trello.com", "asana.com", "monday.com", "clickup.com",
    "notion.so", "figma.com", "canva.com", "miro.com",
    "airtable.com", "linear.app", "height.app",
    "freshdesk.com", "zendesk.com", "intercom.com", "drift.com",
    "mailchimp.com", "sendgrid.com", "twilio.com",
    "stripe.com", "square.com", "paypal.com",
    "todoist.com", "clockify.me", "harvestapp.com",
    # News / Media
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
    "washingtonpost.com", "theguardian.com", "reuters.com",
    "apnews.com", "bloomberg.com", "wsj.com", "ft.com",
    "economist.com", "aljazeera.com", "dw.com", "france24.com",
    "techcrunch.com", "arstechnica.com", "theverge.com",
    "wired.com", "engadget.com", "mashable.com",
    "pcmag.com", "tomsguide.com", "howtogeek.com",
    "huffpost.com", "usatoday.com", "nbcnews.com", "cbsnews.com",
    "foxnews.com", "latimes.com", "sfgate.com",
    # Shopping / E-commerce
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazon.ca", "amazon.com.au", "amazon.in", "amazon.com.br",
    "ebay.com", "etsy.com", "walmart.com", "target.com",
    "bestbuy.com", "costco.com", "homedepot.com", "lowes.com",
    "ikea.com", "wayfair.com", "zappos.com", "newegg.com",
    "aliexpress.com", "wish.com", "mercari.com",
    "shopify.com", "bigcommerce.com", "squarespace.com", "wix.com",
    # Finance / Banking
    "bankofamerica.com", "wellsfargo.com", "chase.com",
    "citi.com", "capitalone.com", "discover.com",
    "americanexpress.com", "usaa.com",
    "paypal.com", "venmo.com", "zellepay.com",
    "fidelity.com", "vanguard.com", "schwab.com",
    "etrade.com", "tdameritrade.com", "robinhood.com",
    "coinbase.com", "kraken.com", "binance.com",
    "hsbc.com", "barclays.com", "lloydsbank.com",
    "natwest.com", "santander.com", "halifax.co.uk",
    # Travel / Hospitality
    "booking.com", "airbnb.com", "tripadvisor.com",
    "expedia.com", "kayak.com", "hotels.com",
    "vrbo.com", "hilton.com", "marriott.com",
    "ihg.com", "hyatt.com", "sheraton.com",
    "uber.com", "lyft.com", "grab.com",
    # Education
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org",
    "codecademy.com", "freecodecamp.org", "leetcode.com",
    "hackerrank.com", "codewars.com", "geeksforgeeks.org",
    "w3schools.com", "tutorialspoint.com", "programiz.com",
    "duolingo.com", "brilliant.org",
    # Docs / Reference
    "developer.mozilla.org", "docs.python.org",
    "react.dev", "vuejs.org", "angular.io", "svelte.dev",
    "nextjs.org", "nuxt.com", "astro.build",
    "pytorch.org", "tensorflow.org", "huggingface.co",
    "typescriptlang.org", "rust-lang.org", "golang.org",
    "dart.dev", "kotlinlang.org", "swift.org",
    # Health
    "mayoclinic.org", "webmd.com", "healthline.com",
    "medicalnewstoday.com", "clevelandclinic.org",
    "hopkinsmedicine.org", "massgeneral.org",
    "cedars-sinai.org", "mountsinai.org",
    # Government (.gov)
    "usa.gov", "irs.gov", "ssa.gov", "usps.com",
    "nasa.gov", "cdc.gov", "nih.gov", "fda.gov",
    "epa.gov", "energy.gov", "ed.gov", "dol.gov",
    "hhs.gov", "state.gov", "justice.gov", "defense.gov",
    "va.gov", "usda.gov", "commerce.gov", "hud.gov",
    "fbi.gov", "cia.gov", "fcc.gov", "faa.gov",
    # Entertainment / Gaming
    "netflix.com", "disneyplus.com", "hulu.com",
    "hbo.com", "paramountplus.com", "peacocktv.com",
    "crunchyroll.com", "apple.com", "icloud.com",
    "microsoft.com", "windows.com", "office.com",
    "xbox.com", "playstation.com", "nintendo.com",
    "steampowered.com", "epicgames.com", "roblox.com",
    "ea.com", "ubisoft.com", "blizzard.com",
    # Other major sites
    "wikipedia.org", "wikimedia.org",
    "archive.org", "imdb.com", "rottentomatoes.com",
    "goodreads.com", "etsy.com", "craigslist.org",
    "yelp.com", "tripadvisor.com", "opentable.com",
    "dropbox.com", "box.com", "onedrive.live.com",
    "obsidian.md", "logseq.com", "ankiweb.net",
    "jetbrains.com", "visualstudio.com", "sublimetext.com",
    "namecheap.com", "godaddy.com", "hover.com",
    "1password.com", "lastpass.com", "bitwarden.com",
    # Developer frameworks / tooling sites (short single-word brand domains)
    "solidjs.com", "remix.run", "svelte.dev", "astro.build",
    "vuejs.org", "react.dev", "angular.io", "nextjs.org", "nuxt.com",
    "deno.com", "bun.sh", "pnpm.io", "npmjs.com", "yarnpkg.com",
    "rollupjs.org", "vitejs.dev", "webpack.js.org", "tailwindcss.com",
    "prisma.io", "supabase.com", "planetscale.com", "neon.tech",
    "turso.tech", "dgraph.io", "arangodb.com", "redis.io", "memcached.org",
    "rabbitmq.com", "kafka.apache.org", "elastic.co", "datadog.com",
    "grafana.com", "prometheus.io", "newrelic.com", "sentry.io",
    # Universities / education
    "mit.edu", "ocw.mit.edu", "stanford.edu", "harvard.edu",
    "berkeley.edu", "cmu.edu", "caltech.edu", "princeton.edu",
    "yale.edu", "cornell.edu", "columbia.edu", "upenn.edu",
    "umich.edu", "uw.edu", "ucla.edu", "utexas.edu", "gatech.edu",
    # Personal / project GitHub Pages (legit developer portfolios)
    "chinmaygawad.github.io",
})


@dataclass
class LexicalFeatures:
    url: str
    values: dict[str, float]

    def vector(self) -> list[float]:
        return [float(self.values[name]) for name in FEATURE_NAMES]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _is_ip(host: str) -> bool:
    if not host:
        return False
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1,
                        prev + (0 if a[i - 1] == b[j - 1] else 1))
            prev = temp
    return dp[n]


def _max_consecutive_special(s: str) -> int:
    mx = cur = 0
    for ch in s:
        if not ch.isalnum():
            cur += 1
            mx = max(mx, cur)
        else:
            cur = 0
    return mx


@lru_cache(maxsize=4096)
def _extract_features_cached(raw: str) -> LexicalFeatures:
    """Cached worker. Keyed on the stripped URL so repeated URLs (e.g. in the
    simulator or a request stream) don't pay the feature cost twice."""
    return _extract_features_impl(raw)


def extract_features(url: str) -> LexicalFeatures:
    """Return lexical features for a single URL (cached)."""
    return _extract_features_cached(url.strip())


def _extract_features_impl(raw: str) -> LexicalFeatures:
    """Return lexical features for a single (already stripped) URL."""
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.netloc or "").lower()
    host_no_port = host.split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""

    lower = raw.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower)

    subdomains = 0
    if host_no_port:
        parts = host_no_port.split(".")
        if len(parts) > 2 or (len(parts) == 2 and _is_ip(host_no_port)):
            subdomains = max(0, len(parts) - 2)

    tld = ""
    if host_no_port and "." in host_no_port and not _is_ip(host_no_port):
        tld = host_no_port.rsplit(".", 1)[-1]

    domain_for_entropy = host_no_port.rsplit(".", 1)[0] if "." in host_no_port else host_no_port

    # --- v2 features ---
    # digit ratio in full URL
    digit_count = sum(ch.isdigit() for ch in raw)
    digit_ratio = digit_count / max(len(raw), 1)

    # hex-encoded characters (%XX)
    hex_encoded = len(re.findall(r"%[0-9a-fA-F]{2}", raw))

    # brand name in domain (typosquatting detector)
    domain_base = domain_for_entropy.lower()

    # --- single pass over brands: compute every brand-derived signal at once
    # to avoid repeated O(brands) Levenshtein scans (a major perf hotspot). ---
    brand_in = 0.0
    brand_match = 0.0       # exact brand or edit distance <= 1
    brand_near = 0.0        # edit distance in [1, 2]
    brand_min_lev = 10.0    # minimum edit distance to any known brand (capped)
    if domain_base:
        db_len = len(domain_base)
        for brand in KNOWN_BRANDS:
            # Quick substring / exact-match shortcut (cheap, no DP).
            if brand in domain_base:
                brand_in = 1.0
                if domain_base == brand:
                    brand_match = 1.0
                elif db_len - len(brand) in (-1, 0, 1) and \
                        _levenshtein(domain_base, brand) <= 1:
                    brand_match = 1.0
            # Length pre-filter: Levenshtein >= |len diff|, so a brand whose
            # length differs by >2 can never be a near-match and cannot beat
            # the current best minimum (capped at 10). Skip the DP for it.
            diff = abs(db_len - len(brand))
            if diff > 2 and diff >= brand_min_lev:
                continue
            d = _levenshtein(domain_base, brand)
            if d < brand_min_lev:
                brand_min_lev = d
            if brand_match == 0.0 and 1 <= d <= 2 and db_len >= 3:
                brand_near = 1.0

    # has explicit non-standard port (e.g. :8080)
    has_port_num = 0.0
    if ":" in host:
        port_part = host.split(":")[-1]
        if port_part.isdigit() and port_part not in ("80", "443"):
            has_port_num = 1.0

    # single-character subdomain (often used in phishing: a.evil.com)
    single_char_sub = 0.0
    parts = host_no_port.split(".")
    if len(parts) > 2:
        for p in parts[:-2]:
            if len(p) == 1:
                single_char_sub = 1.0
                break

    # path depth (number of / segments)
    path_depth = len([s for s in path.split("/") if s])

    # query string length
    query_len = len(query)

    # encoded chars (not just hex — also &amp; etc.)
    has_encoded = float("%" in raw or "&amp;" in raw.lower())

    # digits inside the domain name itself
    domain_digits = sum(c.isdigit() for c in domain_base)

    # hyphens in hostname (phishing uses hyphens to break up brand names)
    hostname_hyphens = host_no_port.count("-")

    # TLD trust score: 1.0 for common legit TLDs, 0.0 for suspicious ones
    tld_trust = 0.0
    if tld:
        if tld in TRUSTED_TLDS:
            tld_trust = 1.0
        elif tld in SUSPICIOUS_TLDS:
            tld_trust = 0.0
        else:
            tld_trust = 0.5  # unknown TLD gets neutral score

    # Free hosting platform detection
    is_free_host = 0.0
    for fh in FREE_HOSTING:
        if host_no_port == fh or host_no_port.endswith("." + fh):
            is_free_host = 1.0
            break

    # Digit inserted into a word (paypa1, amaz0n, faceb00k)
    # Checks if digits replace common letters in the domain
    digit_insert = 0.0
    _digit_letters = {"0": "o", "1": "i", "1": "l", "3": "e", "4": "a",
                      "5": "s", "7": "t", "8": "b", "9": "g"}
    if any(c.isdigit() for c in domain_base):
        # Check if removing digits yields a word closer to a known brand
        no_digits = re.sub(r"\d", "", domain_base)
        for brand in KNOWN_BRANDS:
            if len(no_digits) >= 3 and _levenshtein(no_digits, brand) <= 2:
                digit_insert = 1.0
                break

    # Registered domain length (domain + TLD, without subdomains)
    reg_domain = domain_for_entropy + ("." + tld if tld else "")
    reg_len = float(len(reg_domain))

    # --- v4 features ---

    # Vowel ratio in domain (phishing domains often have fewer vowels)
    vowels = sum(1 for c in domain_base if c in "aeiou")
    vowel_ratio = vowels / max(len(domain_base), 1)

    # Character repetition ratio (phishing domains repeat chars more)
    unique_chars = len(set(domain_base))
    char_repeat = 1.0 - (unique_chars / max(len(domain_base), 1))

    # Admin/compromise-related paths
    admin_paths = ("/wp-admin", "/wp-login", "/cgi-bin", "/admin",
                   "/phpmyadmin", "/cpanel", "/webmail", "/phpinfo")
    has_admin = float(any(p in path.lower() for p in admin_paths))

    # Suspicious path patterns (credential harvesting)
    susp_paths = ("/login", "/signin", "/verify", "/secure", "/account",
                  "/update", "/confirm", "/reset", "/auth", "/session")
    has_susp_path = float(any(p in path.lower() for p in susp_paths))

    # Brand appears in BOTH domain AND path (common in phishing pages)
    brand_in_path_flag = 0.0
    if brand_in == 1.0:
        for brand in KNOWN_BRANDS:
            if brand in path.lower():
                brand_in_path_flag = 1.0
                break

    # Randomness score: unique chars / total chars (phishing has higher randomness)
    all_chars = domain_base + path.replace("/", "")
    randomness = len(set(all_chars)) / max(len(all_chars), 1) if all_chars else 0.0

    # Host-to-URL ratio (legit sites tend to have shorter hosts relative to URL)
    host_url_ratio = len(host_no_port) / max(len(raw), 1)

    # Path-to-URL ratio
    path_url_ratio = len(path) / max(len(raw), 1)

    # Number of query parameters
    num_params = float(len(query.split("&"))) if query else 0.0

    # Has URL fragment (#)
    has_frag = float("#" in raw)

    # Longest word-like segment in domain
    domain_words = re.split(r"[^a-zA-Z]", domain_base)
    domain_words = [w for w in domain_words if len(w) >= 2]
    max_word_len = float(max((len(w) for w in domain_words), default=0))

    # Number of word-like segments in domain
    num_words = float(len(domain_words))

    # TLD length
    tld_len = float(len(tld))

    # Path contains numbers (phishing paths often have numeric IDs)
    path_nums = float(sum(c.isdigit() for c in path))

    # Double slash in path (unusual, sometimes used to obscure)
    has_double_slash = float("//" in path)

    # Path entropy (random-looking paths are suspicious)
    path_ent = _entropy(path.replace("/", ""))

    # Vowel-consonant ratio in domain
    consonants = len(domain_base) - vowels
    vc_ratio = vowels / max(consonants, 1)

    # Special characters in path
    path_special = float(sum(1 for c in path if not c.isalnum() and c not in "/."))

    # Long query string (phishing often has long encoded queries)
    has_long_query = float(len(query) > 100)

    # --- v5 features ---

    # Known legitimate domain lookup (the most reliable anti-phishing signal)
    # Checks both the full hostname and the registered domain
    is_known_legit = 0.0
    if host_no_port in KNOWN_LEGITIMATE_DOMAINS:
        is_known_legit = 1.0
    elif "." in host_no_port and not _is_ip(host_no_port):
        # Check registered domain (domain.tld) without subdomains
        reg_check = domain_for_entropy + ("." + tld if tld else "")
        if reg_check in KNOWN_LEGITIMATE_DOMAINS:
            is_known_legit = 1.0

    # Domain name substring match in whitelist (catches subdomains like
    # app.bankofamerica.com, mail.google.com, etc.)
    domain_name_in_wl = 0.0
    if is_known_legit == 0.0:
        # Extract the registrable domain and check if it appears in any
        # whitelist entry as a substring
        for wl_domain in KNOWN_LEGITIMATE_DOMAINS:
            if host_no_port == wl_domain or host_no_port.endswith("." + wl_domain):
                domain_name_in_wl = 1.0
                break

    # --- v6 features (advanced typosquatting & impersonation) ---

    # Brand near-match: computed in the unified brand pass above (brand_near).

    # Brand hyphenated domain: brand + common word with hyphens
    # Catches: accounts-google.com, secure-paypal.com, google-accounts.com
    brand_hyphen = 0.0
    if "-" in domain_base:
        parts = domain_base.split("-")
        if len(parts) == 2:
            for part in parts:
                for brand in KNOWN_BRANDS:
                    if (part == brand or _levenshtein(part, brand) <= 1) and \
                       any(w in parts[0] if parts[0] != brand else parts[1]
                           for w in PHISH_COMBINATION_WORDS):
                        brand_hyphen = 1.0
                        break
                if brand_hyphen == 1.0:
                    break

    # Suspicious prefix/suffix: domain starts/ends with phishing words
    # Catches: secure-paypal.com, paypal-login.com, verify-account.com
    susp_prefix_suffix = 0.0
    for prefix in SUSPICIOUS_PREFIXES:
        if domain_base.startswith(prefix + "-") or domain_base.startswith(prefix + "."):
            # Check if the rest contains a brand name
            rest = domain_base[len(prefix)+1:]
            for brand in KNOWN_BRANDS:
                if brand in rest or _levenshtein(rest, brand) <= 1:
                    susp_prefix_suffix = 1.0
                    break
        if susp_prefix_suffix == 1.0:
            break
    if susp_prefix_suffix == 0.0:
        for suffix in SUSPICIOUS_SUFFIXES:
            if domain_base.endswith("-" + suffix) or domain_base.endswith("." + suffix):
                rest = domain_base[:-(len(suffix)+1)]
                for brand in KNOWN_BRANDS:
                    if brand in rest or _levenshtein(rest, brand) <= 1:
                        susp_prefix_suffix = 1.0
                        break
                if susp_prefix_suffix == 1.0:
                    break

    # Non-ASCII characters in domain (homograph attacks)
    # Catches: аpple.com (Cyrillic 'a'), gооgle.com (Cyrillic 'o')
    has_non_ascii = 0.0
    try:
        domain_base.encode('ascii')
    except UnicodeEncodeError:
        has_non_ascii = 1.0

    # Short unknown domain: short (<12 chars) domain that's not a known
    # shortener or legitimate site — often suspicious
    short_unknown = 0.0
    if len(domain_base) < 12 and not host_no_port in SHORTENER_DOMAINS and \
       is_known_legit == 0.0 and not _is_ip(host_no_port):
        # Additional check: low vowel ratio or high entropy suggests random name
        if vowel_ratio < 0.3 or _entropy(domain_for_entropy) > 3.0:
            short_unknown = 1.0

    # --- v7 features (advanced patterns & interactions) ---

    # Consonant cluster ratio: phishing domains often have unusual consonant patterns
    consonants_only = [c for c in domain_base if c.isalpha() and c not in "aeiou"]
    max_cluster = 0
    cur_cluster = 0
    for c in domain_base:
        if c.isalpha() and c not in "aeiou":
            cur_cluster += 1
            max_cluster = max(max_cluster, cur_cluster)
        else:
            cur_cluster = 0
    consonant_cluster_ratio = max_cluster / max(len(domain_base), 1)

    # URL encoding density: percentage of encoded characters (%XX)
    encoding_density = hex_encoded / max(len(raw), 1)

    # Domain starts with digit (often suspicious)
    domain_starts_digit = float(domain_base[0].isdigit()) if domain_base else 0.0

    # Domain ends with digit (often suspicious)
    domain_ends_digit = float(domain_base[-1].isdigit()) if domain_base else 0.0

    # Path has file extension (phishing often uses .php, .html, .exe)
    path_has_ext = float(bool(re.search(r"\.[a-zA-Z]{2,5}$", path)))

    # Suspicious file extensions in path
    suspicious_exts = (".php", ".exe", ".bat", ".cmd", ".scr", ".pif",
                       ".com", ".hta", ".vbs", ".js", ".wsf")
    has_susp_ext = float(any(path.lower().endswith(ext) for ext in suspicious_exts))

    # Domain has repeated characters (gooooogle, faceboook)
    domain_has_repeated = float(len(domain_base) != len(set(domain_base)))

    # Average word length in domain
    domain_avg_word_len = max_word_len  # reuse existing computation

    # Path to domain ratio (phishing often has long paths)
    path_domain_ratio = len(path) / max(len(domain_for_entropy), 1)

    # Has double scheme (httphttp:// — malformed/phishing)
    has_double_scheme = float("httphttp" in raw.lower() or "httpshttps" in raw.lower())

    # Minimum Levenshtein distance to any known brand (from unified brand pass)
    brand_min_lev = float(brand_min_lev)  # already capped at 10 in the pass

    # Domain digit ratio (separate from URL digit ratio)
    domain_digit_ratio_val = domain_digits / max(len(domain_base), 1)

    # Path segment count
    path_segments = len([s for s in path.split("/") if s])

    # Query has encoded characters
    query_has_enc = float("%" in query)

    # Suspicious port (non-standard)
    susp_port = 0.0
    if ":" in host:
        port_part = host.split(":")[-1]
        if port_part.isdigit() and int(port_part) not in (80, 443, 8080, 8443):
            susp_port = 1.0

    values = {
        "url_length": len(raw),
        "hostname_length": len(host_no_port),
        "path_length": len(path),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_underscores": raw.count("_"),
        "num_slashes": raw.count("/"),
        "num_question": raw.count("?"),
        "num_equal": raw.count("="),
        "num_at": raw.count("@"),
        "num_percent": raw.count("%"),
        "num_digits": digit_count,
        "num_subdomains": subdomains,
        "has_ip_host": float(_is_ip(host_no_port)),
        "has_https": float(parsed.scheme == "https"),
        "has_port": float(":" in host),
        "suspicious_keyword_count": keyword_count,
        "has_suspicious_tld": float(tld in SUSPICIOUS_TLDS),
        "domain_entropy": _entropy(domain_for_entropy),
        "url_shortener": float(host_no_port in SHORTENER_DOMAINS),
        # v2
        "digit_ratio": digit_ratio,
        "hex_encoded_count": float(hex_encoded),
        "max_consecutive_special": float(_max_consecutive_special(raw)),
        "brand_in_domain": brand_in,
        "brand_domain_match": brand_match,
        "has_port_number": has_port_num,
        "has_single_char_subdomain": single_char_sub,
        "path_depth": float(path_depth),
        "query_length": float(query_len),
        "has_encoded_chars": has_encoded,
        "domain_digit_count": float(domain_digits),
        "hostname_hyphen_count": float(hostname_hyphens),
        # v3
        "tld_trust_score": tld_trust,
        "is_free_hosting": is_free_host,
        "domain_has_digit_insert": digit_insert,
        "registered_domain_length": reg_len,
        # v4
        "vowel_ratio": vowel_ratio,
        "char_repetition_ratio": char_repeat,
        "has_admin_path": has_admin,
        "has_suspicious_path": has_susp_path,
        "brand_in_path": brand_in_path_flag,
        "randomness_score": randomness,
        "host_to_url_ratio": host_url_ratio,
        "path_to_url_ratio": path_url_ratio,
        "num_query_params": num_params,
        "has_fragment": has_frag,
        "max_domain_word_length": max_word_len,
        "num_domain_words": num_words,
        "tld_length": tld_len,
        "path_has_numbers": path_nums,
        "has_double_slash_path": has_double_slash,
        "path_entropy": path_ent,
        "domain_vowel_consonant_ratio": vc_ratio,
        "num_special_in_path": path_special,
        "has_long_query": has_long_query,
        # v5
        "is_known_legitimate": is_known_legit,
        "domain_name_in_whitelist": domain_name_in_wl,
        # v6
        "brand_near_match": brand_near,
        "brand_hyphenated_domain": brand_hyphen,
        "suspicious_prefix_suffix": susp_prefix_suffix,
        "has_non_ascii_chars": has_non_ascii,
        "short_unknown_domain": short_unknown,
        # v7
        "domain_consonant_cluster_ratio": consonant_cluster_ratio,
        "url_encoding_density": encoding_density,
        "domain_starts_with_digit": domain_starts_digit,
        "domain_ends_with_digit": domain_ends_digit,
        "path_has_file_extension": path_has_ext,
        "has_suspicious_file_ext": has_susp_ext,
        "domain_has_repeated_chars": domain_has_repeated,
        "domain_avg_word_length": domain_avg_word_len,
        "path_to_domain_ratio": path_domain_ratio,
        "has_double_scheme": has_double_scheme,
        "brand_min_levenshtein": brand_min_lev,
        "domain_digit_ratio": domain_digit_ratio_val,
        "path_segment_count": float(path_segments),
        "query_has_encoded": query_has_enc,
        "has_suspicious_port": susp_port,
    }
    return LexicalFeatures(url=raw, values=values)


def extract_batch(urls: list[str]) -> list[list[float]]:
    return [extract_features(u).vector() for u in urls]
