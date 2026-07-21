"""Shared constants for phishing URL detection.

Centralizes brand lists, TLD classifications, and phishing keywords used
across training scripts, feature extraction, and the hybrid pipeline.
"""

from __future__ import annotations


KNOWN_BRANDS: tuple[str, ...] = (
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
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "ru", "cn", "top", "xyz", "country",
    "buzz", "icu", "cam", "rest", "surf", "mom",
    "shop", "click", "sbs", "cfd", "digital", "help",
    "live", "life", "fun", "site", "store", "rent",
})

TRUSTED_TLDS: frozenset[str] = frozenset({
    "com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "de",
    "fr", "jp", "au", "ca", "nl", "se", "no", "fi", "dk", "at",
    "ch", "be", "it", "es", "pt", "pl", "cz", "ro", "hu", "bg",
    "hr", "sk", "si", "lt", "lv", "ee", "ie", "nz", "za", "br",
    "mx", "ar", "cl", "pe", "co", "in", "sg", "hk", "tw", "kr",
    "me", "tv", "cc", "ws", "to", "ai",
})

PHISH_WORDS: tuple[str, ...] = (
    "secure", "login", "verify", "auth", "account", "bank", "update",
    "confirm", "wallet", "crypto", "pay", "mail", "web", "portal",
    "center", "hub", "official", "team", "support", "service",
    "online", "access", "identity", "session", "token",
)

FREE_HOSTING: frozenset[str] = frozenset({
    "github.io", "gitbook.io", "appspot.com", "firebaseapp.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "herokuapp.com", "glitch.me", "repl.co", "codesandbox.io",
    "weebly.com", "wixsite.com", "wordpress.com", "blogspot.com",
    "webs.com", "yolasite.com", "ucraft.com", "strikingly.com",
    "carrd.co", "linktr.ee", "beacons.ai", "bio.link",
})

SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorturl.at", "cutt.ly",
})
