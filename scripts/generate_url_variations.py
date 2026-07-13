"""Generate realistic URL variations from bare Tranco domains.

The Tranco dataset only provides bare domains (e.g. https://google.com),
but real websites have paths, query strings, and subdomains. This script
takes the bare Tranco domains and generates realistic URL variations so
the model learns that legitimate sites also have complex URL structures.
"""

import random
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data" / "raw" / "lexical_urls.csv"

# Common path patterns for legitimate sites
PATH_PATTERNS = [
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/account",
    "/settings",
    "/profile",
    "/dashboard",
    "/home",
    "/about",
    "/contact",
    "/help",
    "/support",
    "/faq",
    "/docs",
    "/documentation",
    "/api",
    "/search",
    "/explore",
    "/trending",
    "/popular",
    "/new",
    "/latest",
    "/recent",
    "/top",
    "/best",
    "/categories",
    "/tags",
    "/projects",
    "/products",
    "/services",
    "/pricing",
    "/plans",
    "/features",
    "/blog",
    "/news",
    "/articles",
    "/posts",
    "/forum",
    "/community",
    "/events",
    "/careers",
    "/jobs",
    "/team",
    "/company",
    "/about-us",
    "/privacy",
    "/terms",
    "/security",
    "/status",
    "/download",
    "/install",
    "/demo",
    "/trial",
    "/free",
    "/premium",
    "/pro",
    "/enterprise",
]

# Subdomain patterns
SUBDOMAIN_PATTERNS = [
    "www",
    "app",
    "api",
    "docs",
    "blog",
    "support",
    "help",
    "admin",
    "mail",
    "cdn",
    "static",
    "media",
    "assets",
    "img",
    "images",
    "files",
    "download",
    "stage",
    "staging",
    "dev",
    "test",
    "beta",
    "alpha",
    "preview",
    "demo",
    "sandbox",
    "playground",
    "learn",
    "academy",
    "courses",
    "training",
    "community",
    "forum",
    "status",
    "monitor",
    "analytics",
    "dashboard",
    "portal",
    "hub",
    "center",
    "store",
    "shop",
    "market",
    "payments",
    "billing",
    "checkout",
    "cart",
    "orders",
    "account",
    "profile",
    "settings",
    "preferences",
]


def generate_variations(domain: str, n: int = 3, seed: int = 42) -> list[str]:
    """Generate n realistic URL variations for a domain."""
    rng = random.Random(seed + hash(domain) % 100000)
    urls = []

    # Bare domain (always include)
    urls.append(f"https://{domain}")

    # With path
    for _ in range(n):
        path = rng.choice(PATH_PATTERNS)
        urls.append(f"https://{domain}{path}")

    # With subdomain
    sub = rng.choice(SUBDOMAIN_PATTERNS)
    urls.append(f"https://{sub}.{domain}")

    # With subdomain + path
    path = rng.choice(PATH_PATTERNS)
    urls.append(f"https://{sub}.{domain}{path}")

    return urls


def main():
    df = pd.read_csv(CSV).dropna(subset=["url", "label"])

    # Get Tranco bare domains (legit, no path)
    legit_domains = set()
    for _, row in df[df.label == 0].iterrows():
        url = row["url"]
        if url.startswith("https://") and url.count("/") <= 2:
            domain = url.replace("https://", "").rstrip("/")
            if "." in domain and len(domain) < 50:
                legit_domains.add(domain)

    print(f"Found {len(legit_domains)} Tranco domains")

    # Generate variations
    new_urls = []
    for domain in list(legit_domains)[:5000]:  # Limit to 5000 domains
        variations = generate_variations(domain, n=2)
        for v in variations:
            new_urls.append({"url": v, "label": 0})

    # Add to dataset
    new_df = pd.DataFrame(new_urls)
    df = pd.concat([df, new_df], ignore_index=True)
    df = df.drop_duplicates(subset="url")
    df.to_csv(CSV, index=False)
    print(f"Added {len(new_urls)} URL variations")
    print(f"Total: {len(df)} rows ({(df.label==1).sum()} phish, {(df.label==0).sum()} legit)")


if __name__ == "__main__":
    main()
