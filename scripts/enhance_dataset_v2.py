"""Comprehensive dataset enhancement with diverse phishing patterns.

Adds advanced phishing patterns that the current dataset lacks:
- Homograph/IDN attacks (Unicode lookalikes)
- Bit-squatting domains
- Combo-squatting (brand + legitimate-looking word)
- Subdomain abuse patterns
- Path-based phishing on legit-looking domains
- New TLD abuse patterns
- Advanced typosquatting (adjacent key swaps, omission)
- Crypto/Wallet/NFT scam patterns
- Social engineering urgency patterns

Also adds more diverse legitimate URLs to reduce false positives.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data" / "raw" / "lexical_urls.csv"

sys.path.insert(0, str(ROOT))
from src.utils.constants import (
    KNOWN_BRANDS as _BASE_BRANDS,
    SUSPICIOUS_TLDS as _BASE_SUSPICIOUS_TLDS,
    TRUSTED_TLDS as _BASE_TRUSTED_TLDS,
    PHISH_WORDS as _BASE_PHISH_WORDS,
    FREE_HOSTING,
)

# Extended brand list for training data generation (superset of core brands)
KNOWN_BRANDS = list(_BASE_BRANDS) + [
    "coinbase", "binance", "kraken",
    "venmo", "zelle", "cashapp", "samsung", "sony",
    "dell", "hp", "lenovo", "asus", "nvidia", "amd", "intel",
    "tesla", "bmw", "mercedes", "ford", "toyota", "honda",
]

SUSPICIOUS_TLDS = list(_BASE_SUSPICIOUS_TLDS) + [
    "bond", "cyou", "quest", "monster",
    "info", "biz", "online", "tech", "space", "pw", "cc", "ws",
    "to", "la", "me", "im", "fm",
]

TRUSTED_TLDS = list(_BASE_TRUSTED_TLDS) + ["dev", "app", "ai"]

PHISH_WORDS = list(_BASE_PHISH_WORDS) + [
    "checkout", "billing", "payment", "invoice", "receipt",
    "shipping", "delivery", "tracking", "order", "purchase",
    "subscription", "premium",
]

FREE_HOSTS = list(FREE_HOSTING)


def _char_swaps(brand: str) -> list[str]:
    """Adjacent character swaps (common typos)."""
    variants = []
    for i in range(len(brand) - 1):
        swapped = brand[:i] + brand[i+1] + brand[i] + brand[i+2:]
        variants.append(swapped)
    return variants


def _char_omissions(brand: str) -> list[str]:
    """Single character omission."""
    return [brand[:i] + brand[i+1:] for i in range(len(brand))]


def _char_duplications(brand: str) -> list[str]:
    """Double a character."""
    return [brand[:i] + brand[i] + brand[i:] for i in range(len(brand))]


def _char_substitutions(brand: str) -> list[str]:
    """Leet-speak and similar character substitutions."""
    subs = {
        "a": ["4", "@"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
        "s": ["5", "$"], "l": ["1"], "t": ["7"], "b": ["8"],
        "g": ["9"], "h": ["#"], "n": ["ñ"], "u": ["μ"],
    }
    variants = []
    for i, c in enumerate(brand):
        if c in subs:
            for sub in subs[c]:
                variants.append(brand[:i] + sub + brand[i+1:])
    return variants


def _homograph_variants(brand: str) -> list[str]:
    """Unicode homograph substitutions (IDN attacks)."""
    homographs = {
        "a": "а",  # Cyrillic
        "e": "е",  # Cyrillic
        "o": "о",  # Cyrillic
        "p": "р",  # Cyrillic
        "c": "с",  # Cyrillic
        "x": "х",  # Cyrillic
        "i": "і",  # Ukrainian
        "s": "ѕ",  # Cyrillic
    }
    variants = []
    for i, c in enumerate(brand):
        if c in homographs:
            variants.append(brand[:i] + homographs[c] + brand[i+1:])
    return variants


def _bitsquat_variants(brand: str) -> list[str]:
    """Bit-squatting: single bit flip in domain name."""
    bit_flips = {
        "a": ["b", "q", "s"], "b": ["a", "p", "f"], "c": ["b", "d", "e"],
        "d": ["c", "e", "t"], "e": ["d", "f", "w"], "f": ["e", "g", "r"],
        "g": ["f", "h", "y"], "h": ["g", "i", "z"], "i": ["h", "j", "x"],
        "j": ["i", "k", "n"], "k": ["j", "l", "m"], "l": ["k", "m", "p"],
        "m": ["l", "n", "q"], "n": ["m", "o", "r"], "o": ["n", "p", "s"],
        "p": ["o", "q", "l"], "q": ["p", "r", "a"], "r": ["q", "s", "d"],
        "s": ["r", "t", "e"], "t": ["s", "u", "f"], "u": ["t", "v", "g"],
        "v": ["u", "w", "h"], "w": ["v", "x", "i"], "x": ["w", "y", "j"],
        "y": ["x", "z", "k"], "z": ["y", "a", "l"],
        "0": ["1", "8"], "1": ["0", "9", "q"], "2": ["3", "w"],
        "3": ["2", "e"], "4": ["5", "r"], "5": ["4", "t", "6"],
        "6": ["5", "7", "y"], "7": ["6", "8", "u"], "8": ["7", "9", "i"],
        "9": ["8", "0", "o"],
    }
    variants = []
    for i, c in enumerate(brand):
        if c in bit_flips:
            for flip in bit_flips[c][:2]:
                variants.append(brand[:i] + flip + brand[i+1:])
    return variants


def _combo_squat_variants(brand: str) -> list[str]:
    """Combo-squatting: brand + legitimate-looking word."""
    combos = [
        "login", "signin", "secure", "verify", "auth", "account",
        "update", "confirm", "support", "help", "center", "portal",
        "hub", "team", "official", "service", "cloud", "app",
        "my", "web", "online", "access", "dashboard", "panel",
        "console", "manager", "admin", "panel", "system",
    ]
    variants = []
    for word in combos:
        variants.append(f"{brand}{word}")
        variants.append(f"{brand}-{word}")
        variants.append(f"{word}{brand}")
        variants.append(f"{word}-{brand}")
    return variants


def _subdomain_abuse_variants(brand: str) -> list[str]:
    """Subdomain abuse: evil.com uses brand as subdomain."""
    domains = ["com", "net", "org", "info", "biz"]
    subdomains = ["login", "secure", "auth", "verify", "account", "update"]
    variants = []
    for sub in subdomains:
        for d in domains:
            variants.append(f"{sub}.{brand}.{d}")
            variants.append(f"{brand}.{sub}.{d}")
    return variants


def _path_based_phishing(brand: str) -> list[str]:
    """Path-based phishing on suspicious domains."""
    paths = ["/login", "/signin", "/verify", "/secure", "/account",
             "/update", "/confirm", "/auth", "/session", "/checkout"]
    domains = [f"my-{brand}-secure", f"{brand}-account-verify",
               f"secure-{brand}-login", f"{brand}-update-confirm",
               f"{brand}-billing-verify"]
    variants = []
    for domain in domains:
        for tld in SUSPICIOUS_TLDS[:5]:
            for path in paths[:3]:
                variants.append(f"http://{domain}.{tld}{path}")
    return variants


def _urgency_phishing() -> list[str]:
    """Social engineering urgency patterns."""
    urgency_words = [
        "urgent", "immediate", "suspended", "locked", "expired",
        "unusual", "alert", "warning", "action-required", "verify-now",
        "act-now", "limited-time", "expires-today", "last-chance",
    ]
    targets = [
        "account", "payment", "subscription", "identity", "security",
        "profile", "membership", "access", "wallet", "balance",
    ]
    tlds = SUSPICIOUS_TLDS[:8]
    variants = []
    for uw in urgency_words:
        for tgt in targets:
            for tld in tlds:
                variants.append(f"http://{uw}-{tgt}.{tld}/verify")
                variants.append(f"http://{tgt}-{uw}.{tld}/confirm")
    return variants


def _crypto_scam_urls() -> list[str]:
    """Crypto/wallet/NFT scam patterns."""
    patterns = [
        "free-{coin}-airdrop", "{coin}-giveaway", "{coin}-generator",
        "{coin}-double", "claim-{coin}", "{coin}-reward",
        "nft-free-mint", "nft-giveaway", "crypto-wallet-verify",
        "defi-connect", "token-swap-secure", "metamask-verify",
        "phantom-wallet", "opensea-claim", "axie-infinity-free",
    ]
    coins = ["bitcoin", "ethereum", "solana", "dogecoin", "shiba",
             "pepe", "bonk", "xrp", "ada", "dot"]
    tlds = SUSPICIOUS_TLDS[:6]
    variants = []
    for p in patterns:
        for coin in coins:
            domain = p.replace("{coin}", coin)
            for tld in tlds:
                variants.append(f"http://{domain}.{tld}/claim")
                variants.append(f"https://{domain}.{tld}/connect")
    return variants


def _generate_phishing_samples() -> list[tuple[str, int]]:
    """Generate diverse phishing URL samples."""
    samples = []
    rng = random.Random(42)

    for brand in KNOWN_BRANDS[:40]:  # Top 40 brands
        # 1. Character swaps
        for v in _char_swaps(brand)[:5]:
            tld = rng.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 2. Character omissions
        for v in _char_omissions(brand)[:5]:
            tld = rng.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 3. Character duplications
        for v in _char_duplications(brand)[:3]:
            tld = rng.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 4. Leet-speak substitutions
        for v in _char_substitutions(brand)[:5]:
            tld = rng.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 5. Homograph attacks (use http to make them more suspicious)
        for v in _homograph_variants(brand)[:3]:
            tld = rng.choice(TRUSTED_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 6. Bit-squatting
        for v in _bitsquat_variants(brand)[:3]:
            tld = rng.choice(TRUSTED_TLDS + SUSPICIOUS_TLDS)
            samples.append((f"http://{v}.{tld}", 1))

        # 7. Combo-squatting
        for v in _combo_squat_variants(brand)[:8]:
            tld = rng.choice(TRUSTED_TLDS)
            samples.append((f"https://{v}.{tld}", 1))

        # 8. Subdomain abuse
        for v in _subdomain_abuse_variants(brand)[:4]:
            samples.append((f"http://{v}", 1))

        # 9. Path-based phishing
        for v in _path_based_phishing(brand)[:5]:
            samples.append((v, 1))

        # 10. Free hosting phishing
        host = rng.choice(FREE_HOSTS)
        word = rng.choice(PHISH_WORDS[:10])
        samples.append((f"https://{brand}-{word}.{host}/login", 1))
        samples.append((f"https://{word}-{brand}.{host}/verify", 1))

    # 11. Urgency patterns
    for url in _urgency_phishing()[:200]:
        samples.append((url, 1))

    # 12. Crypto scams
    for url in _crypto_scam_urls()[:200]:
        samples.append((url, 1))

    return samples


def _generate_diverse_legit_samples() -> list[tuple[str, int]]:
    """Generate diverse legitimate URL samples."""
    samples = []

    # Real-world complex legitimate URLs
    complex_legit = [
        # E-commerce with deep paths and params
        "https://www.amazon.com/s?k=wireless+mouse&ref=nb_sb_noss",
        "https://www.amazon.com/dp/B08N5WRWNW?th=1&psc=1",
        "https://www.ebay.com/sch/i.html?_nkw=laptop&_sacat=0",
        "https://www.walmart.com/search?q=headphones",
        "https://www.target.com/s?searchTerm=shoes",
        "https://www.bestbuy.com/site/searchpage.jsp?st=tv",
        "https://www.etsy.com/search?q=handmade+jewelry",
        "https://www.shopify.com/store/my-shop",
        # Social media with deep paths
        "https://www.reddit.com/r/programming/comments/abc123/title/",
        "https://www.reddit.com/r/python/top/?t=month",
        "https://twitter.com/elonmusk/status/1234567890",
        "https://www.instagram.com/p/CABC123DEF/",
        "https://www.tiktok.com/@user/video/1234567890",
        "https://www.linkedin.com/in/username/activity-123",
        # Developer tools
        "https://github.com/facebook/react/blob/main/packages/react/index.js",
        "https://github.com/facebook/react/actions/workflows/ci.yml",
        "https://gitlab.com/dashboard",
        "https://bitbucket.org/dashboard",
        "https://stackoverflow.com/questions/12345678/how-to-center-div",
        "https://dev.to/trending",
        "https://pypi.org/project/requests/2.31.0/",
        "https://www.npmjs.com/package/@angular/core",
        "https://hub.docker.com/r/library/python/tags",
        # Cloud platforms
        "https://console.aws.amazon.com/ec2/home?region=us-east-1",
        "https://console.cloud.google.com/kubernetes/list",
        "https://portal.azure.com/#view/Microsoft_Azure_Resources",
        "https://app.slack.com/client/T01234567/C0123456",
        "https://vercel.com/dashboard",
        "https://app.netlify.com/sites/my-site/deploys",
        # SaaS tools
        "https://trello.com/b/ABC123/project-board",
        "https://notion.so/workspace/Project-Notes-abc123",
        "https://www.figma.com/file/ABC123/Design-System",
        "https://jira.atlassian.com/browse/PROJ-1234",
        "https://linear.app/team/issue/ABC-123",
        "https://app.clickup.com/t/abc1234",
        "https://app.asana.com/0/1234567890/1234567890",
        # News with deep paths
        "https://www.bbc.com/news/technology-12345678",
        "https://www.nytimes.com/2024/01/01/technology/article.html",
        "https://www.cnn.com/world/live-news/abc-123-abc123",
        "https://arstechnica.com/science/2024/01/article/",
        "https://www.theverge.com/2024/1/1/240101/article",
        # Education
        "https://www.khanacademy.org/computing/computer-science/algorithms",
        "https://leetcode.com/problems/two-sum/",
        "https://www.geeksforgeeks.org/python-programming-language/",
        "https://www.freecodecamp.org/learn/responsive-web-design/",
        "https://www.coursera.org/learn/machine-learning",
        "https://www.edx.org/learn/python",
        # Finance
        "https://www.coinbase.com/price/bitcoin",
        "https://www.coinbase.com/advanced-trade/spot/BTC-USD",
        "https://www.paypal.com/myaccount/summary/",
        "https://dashboard.stripe.com/payments",
        "https://www.robinhood.com/stocks/AAPL",
        # Travel
        "https://www.booking.com/hotel/us/example.html?checkin=2024-06-01",
        "https://www.airbnb.com/s/New-York--NY/homes",
        "https://www.tripadvisor.com/Attractions-g60763-Activities.html",
        "https://www.expedia.com/Hotel-Search?destination=New+York",
        # Media
        "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
        "https://www.twitch.tv/shroud/clips?filter=clips&range=7d",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=120s",
        "https://www.netflix.com/watch/80057281?autoplay=1",
        # Productivity
        "https://drive.google.com/file/d/ABC/view",
        "https://www.dropbox.com/s/abc123/file.pdf?dl=0",
        "https://onedrive.live.com/?id=ABC",
        "https://zoom.us/j/1234567890?pwd=ABC",
        # Government with paths
        "https://www.usa.gov/",
        "https://www.irs.gov/individuals",
        "https://www.ssa.gov/",
        "https://www.nasa.gov/",
        "https://www.cdc.gov/",
        # International
        "https://www.bbc.co.uk/",
        "https://www.theguardian.com/",
        "https://www.reuters.com/technology/",
        "https://www.aljazeera.com/",
        "https://www.dw.com/",
        # Health
        "https://www.mayoclinic.org/",
        "https://www.webmd.com/",
        "https://www.healthline.com/nutrition/benefits-of-omega-3",
        # Tech docs
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "https://docs.python.org/3/library/stdtypes.html",
        "https://pytorch.org/tutorials/beginner/basics/intro.html",
        "https://www.tensorflow.org/tutorials/quickstart/beginner",
        "https://huggingface.co/docs/transformers/index",
        "https://react.dev/learn/thinking-in-react",
        "https://vuejs.org/guide/introduction.html",
        "https://nextjs.org/docs/app/building-your-application/routing",
        "https://svelte.dev/tutorial/basics",
        # Domains with paths (not just bare)
        "https://github.com/trending",
        "https://github.com/features/copilot",
        "https://gitlab.com/explore",
        "https://stackoverflow.com/questions/tagged/python",
        "https://medium.com/@user/article-123",
        "https://news.ycombinator.com/item?id=12345",
        "https://dev.to/t/python",
        "https://pypi.org/search/?q=phishing",
        # More diverse subdomains
        "https://docs.github.com/en/get-started",
        "https://blog.github.io/",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://docs.google.com/document/d/ABC/edit",
        "https://calendar.google.com/calendar/r/eventedit",
        "https://maps.google.com/maps?q=New+York",
        "https://translate.google.com/?sl=en&tl=es",
        # Long complex URLs (often false positives)
        "https://www.amazon.com/gp/css/order-history?ref_=nav_acct_orders",
        "https://www.amazon.com/gp/your-account/order-history?ie=UTF8",
        "https://www.amazon.com/s?k=wireless+mouse&ref=nb_sb_noss",
        "https://www.amazon.com/dp/B08N5WRWNW?th=1&psc=1",
        "https://www.linkedin.com/in/johndoe?miniProfileUrn=urn%3Ali%3Afsd_profile",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
        "https://www.reddit.com/r/python/comments/abc123/title_of_post/",
        "https://www.reddit.com/search/?q=phishing+detection&sort=relevance",
        "https://www.google.com/search?q=phishing+detection+machine+learning&num=10",
        "https://www.google.com/search?q=site:github.com+python&tbm=isch",
        # Free hosting legitimate sites
        "https://my-app.netlify.app/",
        "https://portfolio.vercel.app/",
        "https://my-project.pages.dev/",
        "https://docs.gitbook.io/",
        "https://user.weebly.com/",
        "https://blog.wordpress.com/",
        # Bare short domains (legit)
        "https://cloudflare.com/",
        "https://salesforce.com/",
        "https://asana.com/",
        "https://todoist.com/",
        "https://pytorch.org/",
        "https://typescriptlang.org/",
        "https://huggingface.co/",
        "https://solidjs.com/",
        "https://astro.build/",
        "https://svelte.dev/",
        "https://remix.run/",
        "https://nextjs.org/",
        "https://vuejs.org/",
        "https://react.dev/",
        # More education
        "https://www.mit.edu/",
        "https://www.stanford.edu/",
        "https://www.harvard.edu/",
        "https://ocw.mit.edu/",
        "https://cs50.harvard.edu/",
        "https://www.khanacademy.org/",
        # More SaaS
        "https://monday.com/",
        "https://clickup.com/",
        "https://clockify.me/",
        "https://www.harvestapp.com/",
        "https://freshdesk.com/",
        "https://www.zendesk.com/",
        "https://www.intercom.com/",
        "https://www.drift.com/",
        # More e-commerce
        "https://www.ikea.com/us/en/p/123",
        "https://www.wayfair.com/keyword.php",
        "https://www.zappos.com/product/123",
        "https://www.newegg.com/p/123",
        "https://www.aliexpress.com/item/123.html",
        # More entertainment
        "https://www.roblox.com/games/123456789/Game-Name",
        "https://store.steampowered.com/app/730/CounterStrike/",
        "https://store.epicgames.com/en-US/p/fortnite",
        "https://www.minecraft.net/en-us/store/minecraft-java-edition",
        # More productivity
        "https://www.notion.so/workspace/Project-Notes-abc123def456",
        "https://www.figma.com/file/ABC1234/Design-System?node-id=0%3A1",
        "https://miro.com/app/board/ABC1234/",
        "https://airtable.com/appABC1234/tblXYZ5678/view/ViewName",
        # More developer
        "https://www.jetbrains.com/",
        "https://code.visualstudio.com/",
        "https://obsidian.md/",
        "https://www.duolingo.com/",
        "https://www.khanacademy.org/",
        "https://www.coursera.org/",
        "https://leetcode.com/",
        "https://www.hackerrank.com/",
        "https://www.w3schools.com/",
        "https://www.geeksforgeeks.org/",
        "https://www.freecodecamp.org/",
        "https://www.codecademy.com/",
        "https://www.udemy.com/",
        "https://www.edx.org/",
        "https://pytorch.org/",
        "https://www.tensorflow.org/",
        "https://huggingface.co/",
        "https://www.cloudflare.com/",
        "https://www.digitalocean.com/",
        "https://www.linode.com/",
        "https://www.vultr.com/",
        "https://www.namecheap.com/",
        "https://www.godaddy.com/",
        "https://www.squarespace.com/",
        "https://www.wix.com/",
        "https://www.shopify.com/",
        "https://mailchimp.com/",
        "https://sendgrid.com/",
        "https://www.hubspot.com/",
        "https://salesforce.com/",
        "https://www.zendesk.com/",
        "https://freshdesk.com/",
        "https://www.intercom.com/",
        "https://www.drift.com/",
        "https://asana.com/",
        "https://monday.com/",
        "https://clickup.com/",
        "https://todoist.com/",
        "https://clockify.me/",
        "https://www.harvestapp.com/",
        # Communication
        "https://www.whatsapp.com/",
        "https://telegram.org/",
        "https://signal.org/",
        "https://discord.com/app",
        "https://slack.com/",
        # Cloud storage
        "https://www.dropbox.com/",
        "https://onedrive.live.com/",
        "https://www.icloud.com/",
        "https://www.box.com/",
        # More news
        "https://www.cnn.com/",
        "https://www.nbcnews.com/",
        "https://www.cbsnews.com/",
        "https://www.foxnews.com/",
        "https://www.usatoday.com/",
        "https://www.washingtonpost.com/",
        "https://www.latimes.com/",
        "https://www.sfgate.com/",
        "https://www.howtogeek.com/",
        "https://www.pcmag.com/",
        "https://mashable.com/",
        "https://www.tumblr.com/",
        "https://www.quora.com/",
        "https://substack.com/",
        "https://www.meetup.com/",
        # International
        "https://www.bbc.co.uk/",
        "https://www.theguardian.com/",
        "https://www.reuters.com/",
        "https://www.aljazeera.com/",
        "https://www.dw.com/",
        "https://www.france24.com/",
        # Communication
        "https://www.whatsapp.com/",
        "https://telegram.org/",
        "https://signal.org/",
        # Productivity
        "https://www.dropbox.com/",
        "https://onedrive.live.com/",
        "https://www.icloud.com/",
        "https://zoom.us/join/",
        # Travel
        "https://www.booking.com/",
        "https://www.airbnb.com/",
        "https://www.tripadvisor.com/",
        "https://www.uber.com/",
        "https://www.lyft.com/",
        "https://www.expedia.com/",
        "https://www.kayak.com/",
        "https://www.vrbo.com/",
        "https://www.hilton.com/",
        "https://www.marriott.com/",
        # Healthcare
        "https://www.mayoclinic.org/",
        "https://www.webmd.com/",
        "https://www.healthline.com/",
        "https://www.medicalnewstoday.com/",
        "https://www.clevelandclinic.org/",
        "https://www.hopkinsmedicine.org/",
        # Finance
        "https://www.bankofamerica.com/",
        "https://www.wellsfargo.com/",
        "https://www.chase.com/",
        "https://www.citi.com/",
        "https://www.capitalone.com/",
        "https://www.discover.com/",
        "https://www.americanexpress.com/",
        "https://www.paypal.com/",
        "https://www.venmo.com/",
        "https://www.zellepay.com/",
        "https://www.robinhood.com/",
        "https://www.coinbase.com/",
        "https://www.kraken.com/",
        "https://www.binance.com/",
        "https://www.fidelity.com/",
        "https://www.vanguard.com/",
        "https://www.schwab.com/",
        "https://www.etrade.com/",
        "https://www.tdameritrade.com/",
        # Entertainment
        "https://netflix.com/",
        "https://disneyplus.com/",
        "https://hulu.com/",
        "https://hbo.com/",
        "https://paramountplus.com/",
        "https://peacocktv.com/",
        "https://crunchyroll.com/",
        "https://apple.com/",
        "https://icloud.com/",
        "https://microsoft.com/",
        "https://windows.com/",
        "https://office.com/",
        "https://xbox.com/",
        "https://playstation.com/",
        "https://nintendo.com/",
        "https://steampowered.com/",
        "https://epicgames.com/",
        "https://roblox.com/",
        "https://ea.com/",
        "https://ubisoft.com/",
        "https://blizzard.com/",
    ]

    samples = [(url, 0) for url in complex_legit]
    return samples


def main():
    print("Loading existing dataset...")
    df = pd.read_csv(CSV).dropna(subset=["url", "label"])
    existing_urls = set(df["url"].tolist())
    print(f"  Existing samples: {len(df)}")

    # Generate new phishing samples
    print("Generating diverse phishing samples...")
    new_phish = _generate_phishing_samples()
    new_phish = [(url, label) for url, label in new_phish if url not in existing_urls]
    print(f"  New phishing samples: {len(new_phish)}")

    # Generate new legitimate samples
    print("Generating diverse legitimate samples...")
    new_legit = _generate_diverse_legit_samples()
    new_legit = [(url, label) for url, label in new_legit if url not in existing_urls]
    print(f"  New legitimate samples: {len(new_legit)}")

    # Combine
    all_new = new_phish + new_legit
    if all_new:
        new_df = pd.DataFrame(all_new, columns=["url", "label"])
        df = pd.concat([df, new_df], ignore_index=True)
        df = df.drop_duplicates(subset=["url"], keep="first")

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nFinal dataset:")
    print(f"  Total samples: {len(df)}")
    print(f"  Phishing: {(df.label == 1).sum()}")
    print(f"  Legitimate: {(df.label == 0).sum()}")
    print(f"  Ratio: {(df.label == 1).sum() / (df.label == 0).sum():.2f}")

    df.to_csv(CSV, index=False)
    print(f"\nSaved to {CSV}")


if __name__ == "__main__":
    main()
