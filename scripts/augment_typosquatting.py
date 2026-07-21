"""
Augment training data with typosquatting and brand impersonation samples.

This script generates realistic phishing URL variations to improve
detection of advanced phishing patterns like:
- Short typosquatting (gooogle.com, amazn.com)
- Hyphenated brand impersonation (accounts-google.com)
- Suspicious prefix/suffix patterns (secure-paypal.com)
"""

from __future__ import annotations

import random
import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "raw" / "lexical_urls.csv"

sys.path.insert(0, str(ROOT))
from src.utils.constants import KNOWN_BRANDS, SUSPICIOUS_TLDS, TRUSTED_TLDS, PHISH_WORDS, FREE_HOSTING


def _char_variants(brand: str) -> list[str]:
    """Generate character-level typos of a brand name."""
    variants = []
    # Missing character
    for i in range(len(brand)):
        variants.append(brand[:i] + brand[i+1:])
    # Double character
    for i in range(len(brand)):
        variants.append(brand[:i] + brand[i] + brand[i:])
    # Adjacent swap
    for i in range(len(brand) - 1):
        variants.append(brand[:i] + brand[i+1] + brand[i] + brand[i+2:])
    # Similar char substitutions
    subs = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "l": "1"}
    for i, c in enumerate(brand):
        if c in subs:
            variants.append(brand[:i] + subs[c] + brand[i+1:])
    return list(set(variants))


def _hyphenated_variants(brand: str) -> list[str]:
    """Generate hyphenated brand + word combinations."""
    variants = []
    for word in PHISH_WORDS[:15]:
        variants.append(f"{word}-{brand}")
        variants.append(f"{brand}-{word}")
    return variants


def _prefix_suffix_variants(brand: str) -> list[str]:
    """Generate prefix/suffix + brand combinations."""
    variants = []
    prefixes = ["secure", "login", "verify", "auth", "account", "bank",
                "update", "confirm", "wallet", "crypto", "my", "app"]
    suffixes = ["secure", "login", "verify", "auth", "account", "bank",
                "center", "hub", "portal", "service", "support", "team"]
    for p in prefixes:
        variants.append(f"{p}{brand}")
        variants.append(f"{p}-{brand}")
    for s in suffixes:
        variants.append(f"{brand}{s}")
        variants.append(f"{brand}-{s}")
    return variants


def _subdomain_variants(brand: str) -> list[str]:
    """Generate subdomain-based impersonation."""
    variants = []
    prefixes = ["secure", "login", "verify", "auth", "account", "bank",
                "update", "mail", "web", "portal", "my", "app"]
    for p in prefixes:
        variants.append(f"{p}.{brand}")
        variants.append(f"{p}-{brand}")
    return variants


def generate_phishing_samples(n_per_brand: int = 50) -> list[tuple[str, int]]:
    """Generate phishing URL samples for each brand."""
    samples = []

    for brand in KNOWN_BRANDS:
        # Character variants
        for variant in _char_variants(brand)[:n_per_brand]:
            tld = random.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{variant}.{tld}", 1))

        # Hyphenated variants
        for variant in _hyphenated_variants(brand)[:n_per_brand]:
            tld = random.choice(TRUSTED_TLDS)
            samples.append((f"https://{variant}.{tld}", 1))

        # Prefix/suffix variants
        for variant in _prefix_suffix_variants(brand)[:n_per_brand]:
            tld = random.choice(TRUSTED_TLDS)
            samples.append((f"https://{variant}.{tld}", 1))

        # Subdomain variants
        for variant in _subdomain_variants(brand)[:n_per_brand]:
            tld = random.choice(TRUSTED_TLDS)
            samples.append((f"https://{variant}.com", 1))

        # Free hosting variants
        for host in random.sample(FREE_HOSTING, min(3, len(FREE_HOSTING))):
            samples.append((f"https://{brand}-secure.{host}/login", 1))

    return samples


def main():
    print("Loading existing dataset...")
    df = pd.read_csv(OUTPUT)
    existing_urls = set(df["url"].tolist())
    print(f"  Existing samples: {len(df)}")

    print("Generating typosquatting samples...")
    new_samples = generate_phishing_samples(n_per_brand=30)

    # Filter out duplicates
    new_samples = [(url, label) for url, label in new_samples
                   if url not in existing_urls]

    print(f"  New unique samples: {len(new_samples)}")

    # Add to dataframe
    new_df = pd.DataFrame(new_samples, columns=["url", "label"])
    df = pd.concat([df, new_df], ignore_index=True)
    df = df.drop_duplicates(subset=["url"], keep="first")

    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:")
    print(f"    Legitimate: {(df.label == 0).sum()}")
    print(f"    Phishing: {(df.label == 1).sum()}")

    # Save
    df.to_csv(OUTPUT, index=False)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
