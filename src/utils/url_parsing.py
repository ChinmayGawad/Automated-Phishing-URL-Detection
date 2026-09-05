"""Public URL-parsing helpers for the phishing-detection pipeline.

These replace the internal ``_is_ip`` / ``_entropy`` / ``rsplit`` logic in
``src.lexical.features`` and ``src.core.hybrid`` so that:
- IPv6 hosts are handled (the old dotted-quad regex rejected them).
- Multi-part TLDs (``co.uk``, ``com.au``, ``github.io``) are detected
  correctly for suspicious-TLD and whitelist subdomain matching.
- Punycode (IDN) domains are decoded before brand/Levenshtein checks.

All helpers are deterministic and require no network I/O.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("phishguard.url_parsing")

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
    _extractor = tldextract.TLDExtract(cache_dir=None)
except ImportError:
    _TLDEXTRACT_AVAILABLE = False
    _extractor = None

# Local suffix list for common multi-part TLDs when tldextract is absent.
_FALLBACK_SUFFIXES = (
    "co.uk", "ac.uk", "sch.uk", "gov.uk", "nhs.uk",
    "com.au", "edu.au", "gov.au",
    "com.br", "com.cn", "com.mx", "com.ar",
    "co.jp", "or.jp", "ac.jp",
    "com.tw", "net.tw",
    "co.in", "in",
    "com.sg", "org.sg",
    "com.hk", "org.hk",
    "github.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com",
    "firebaseapp.com", "appspot.com", "blogspot.com", "wordpress.com",
)


def is_ip(host: str) -> bool:
    """Return True if ``host`` is an IPv4 or IPv6 address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Return the registrable domain (e.g. ``google.com``) from a hostname.

    Handles subdomains, multi-part TLDs, and IPv4/IPv6.
    """
    if not host or is_ip(host):
        return host
    # Strip port if present
    if ":" in host:
        host = host.split(":", 1)[0]
    if _TLDEXTRACT_AVAILABLE and _extractor:
        try:
            extracted = _extractor(host)
            reg = extracted.registered_domain or ""
            if reg:
                return reg
        except Exception:  # pragma: no cover - tldextract internals
            pass
    # Fallback: strip one label at a time looking for a known suffix
    parts = host.split(".")
    for n in range(2, len(parts) + 1):
        candidate = ".".join(parts[-n:])
        if candidate in _FALLBACK_SUFFIXES:
            return candidate
        if candidate.count(".") <= 1:
            # Simple TLD (com, org, net, ...), return the last two parts
            return candidate
    return host


def tld_of(host: str) -> str:
    """Return the TLD string (e.g. ``uk`` from ``google.co.uk``)."""
    if not host or is_ip(host):
        return ""
    if ":" in host:
        host = host.split(":", 1)[0]
    if _TLDEXTRACT_AVAILABLE and _extractor:
        try:
            extracted = _extractor(host)
            return extracted.suffix or ""
        except Exception:
            pass
    # Fallback: last dot-separated segment
    return host.rsplit(".", 1)[-1]


def normalize_idn(host: str) -> str:
    """Decode a punycode hostname (``xn--...``) to its Unicode form when
    possible, so brand-matching operates on the visual domain.

    Returns the original host unchanged when decoding fails or is unnecessary.
    """
    if not host or "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
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
