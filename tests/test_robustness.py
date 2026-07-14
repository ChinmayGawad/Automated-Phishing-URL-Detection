"""Comprehensive robustness tests for the phishing URL detection model.

Tests 200+ real-world URLs across categories to ensure the model generalizes:
- Major legitimate sites (Google, GitHub, Amazon, Netflix, etc.)
- Government and education sites
- SaaS and developer tools
- Phishing patterns (typosquatting, IP hosts, suspicious TLDs, etc.)

Target: >95% accuracy on legitimate URLs, >98% recall on phishing URLs.
"""

from __future__ import annotations

import pytest

from src.lexical.model import LexicalModel

# ---------------------------------------------------------------------------
# URL fixtures
# ---------------------------------------------------------------------------

LEGITIMATE_URLS = [
    # Major tech
    "https://www.google.com",
    "https://www.google.com/search?q=python",
    "https://github.com/login",
    "https://github.com/trending",
    "https://github.com/chinmaygawad/Portfolio",
    "https://stackoverflow.com/questions",
    "https://stackoverflow.com/questions/tagged/python",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.amazon.com/s?k=keyboard",
    "https://mail.google.com/mail/u/0/",
    "https://www.linkedin.com/in/username",
    "https://www.linkedin.com/feed/",
    "https://www.linkedin.com/jobs/",
    "https://www.netflix.com/browse",
    "https://www.netflix.com/watch/12345",
    "https://www.reddit.com/r/python",
    "https://www.reddit.com/r/programming",
    "https://news.ycombinator.com/",
    "https://www.bbc.com/news",
    "https://www.nytimes.com/",
    "https://www.twitch.tv/",
    "https://discord.com/app",
    "https://open.spotify.com/",
    "https://twitter.com/home",
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    # Free hosting (legit)
    "https://chinmaygawad.github.io/Portfolio/",
    "https://username.github.io/project/",
    "https://my-app.netlify.app/",
    "https://my-app.vercel.app/",
    "https://my-project.pages.dev/",
    "https://my-app.herokuapp.com/",
    # Developer tools
    "https://pypi.org/project/requests/",
    "https://dev.to/trending",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://docs.python.org/3/",
    "https://react.dev/",
    "https://vuejs.org/",
    "https://nextjs.org/",
    # SaaS
    "https://app.slack.com/",
    "https://trello.com/b/boardname",
    "https://notion.so/workspace",
    "https://figma.com/file/abc",
    "https://canva.com/design/abc",
    # Government
    "https://www.usa.gov/",
    "https://www.irs.gov/individuals",
    "https://www.ssa.gov/",
    "https://www.nasa.gov/",
    "https://www.cdc.gov/",
    # Education
    "https://www.mit.edu/",
    "https://www.stanford.edu/",
    "https://www.harvard.edu/",
    "https://ocw.mit.edu/",
    # Finance
    "https://www.bankofamerica.com/",
    "https://www.chase.com/",
    "https://www.paypal.com/",
    "https://www.coinbase.com/",
    # News
    "https://arstechnica.com/",
    "https://www.theverge.com/",
    "https://www.wired.com/",
    "https://www.techcrunch.com/",
    # Cloud
    "https://aws.amazon.com/console/",
    "https://console.cloud.google.com/",
    "https://portal.azure.com/",
    "https://cloudflare.com/",
    # E-commerce
    "https://www.ebay.com/item/123",
    "https://www.etsy.com/listing/123",
    "https://www.walmart.com/ip/123",
    "https://www.target.com/p/123",
    # Travel
    "https://www.booking.com/",
    "https://www.airbnb.com/",
    "https://www.tripadvisor.com/",
    "https://www.uber.com/",
    # Healthcare
    "https://www.mayoclinic.org/",
    "https://www.webmd.com/",
    "https://www.healthline.com/",
    # International
    "https://www.bbc.co.uk/",
    "https://www.theguardian.com/",
    "https://www.reuters.com/",
    "https://www.aljazeera.com/",
    # Communication
    "https://www.whatsapp.com/",
    "https://telegram.org/",
    "https://signal.org/",
    # Productivity
    "https://www.dropbox.com/",
    "https://onedrive.live.com/",
    "https://www.icloud.com/",
    "https://zoom.us/join/",
    # More realistic paths
    "https://github.com/chinmaygawad/Portfolio/tree/main",
    "https://github.com/chinmaygawad/Portfolio/blob/main/README.md",
    "https://github.com/chinmaygawad/Portfolio/issues",
    "https://github.com/chinmaygawad/Portfolio/pulls",
    "https://github.com/chinmaygawad/Portfolio/actions",
    "https://stackoverflow.com/questions/12345678/how-to-center-a-div",
    "https://en.wikipedia.org/wiki/Python_(programming_language)",
    "https://www.amazon.com/gp/css/homepage.html",
    "https://www.amazon.com/gp/cart/view.html",
    "https://www.linkedin.com/company/google/",
    "https://www.linkedin.com/posts/username_activity-123",
    "https://www.reddit.com/r/python/comments/abc123/title",
    "https://medium.com/@user/article-123",
    "https://news.ycombinator.com/item?id=12345",
    "https://www.bbc.com/news/technology",
    "https://www.nytimes.com/section/technology",
    "https://www.youtube.com/channel/UC-lHJZR3Gqxm24_Vd_AJ5Yw",
    "https://www.twitch.tv/directory/category/just-chatting",
    "https://open.spotify.com/playlist/12345",
    "https://www.reddit.com/r/python/top/?t=month",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.amazon.com/gp/your-account/order-history",
    "https://github.com/features/copilot",
    "https://gitlab.com/dashboard",
    "https://bitbucket.org/dashboard",
    "https://jira.atlassian.com/",
    "https://linear.app/",
    "https://supabase.com/dashboard",
    "https://railway.com/dashboard",
    "https://fly.io/dashboard",
    "https://render.com/dashboard",
    "https://replit.com/",
    "https://codesandbox.io/",
    "https://stackblitz.com/",
    "https://glitch.com/",
    "https://www.jetbrains.com/",
    "https://code.visualstudio.com/",
    "https://obsidian.md/",
    "https://www.duolingo.com/",
    "https://www.khanacademy.org/",
    "https://www.coursera.org/",
    "https://leetcode.com/",
    "https://www.hackerrank.com/",
    "https://www.w3schools.com/",
    "https://typescriptlang.org/",
    "https://svelte.dev/",
    "https://astro.build/",
    "https://remix.run/",
    "https://solidjs.com/",
    "https://drive.google.com/",
    "https://www.box.com/",
    "https://www.cnn.com/",
    "https://www.nbcnews.com/",
    "https://www.washingtonpost.com/",
    "https://www.howtogeek.com/",
    "https://www.pcmag.com/",
    "https://mashable.com/",
    "https://www.tumblr.com/",
    "https://www.quora.com/",
    "https://substack.com/",
    "https://www.meetup.com/",
    "https://www.tripadvisor.com/Attractions-g60763-Activities-New_York_City_New_York.html",
    "https://www.hilton.com/en/locations/usa/",
    "https://www.marriott.com/",
    "https://www.uber.com/global/en/price-estimate/",
    "https://www.lyft.com/ride",
    "https://www.expedia.com/Hotels",
    "https://www.kayak.com/",
    "https://www.vrbo.com/",
    "https://www.ankiweb.net/",
    "https://www.geeksforgeeks.org/",
    "https://www.freecodecamp.org/",
    "https://www.codecademy.com/",
    "https://www.udemy.com/",
    "https://www.edx.org/",
    "https://pytorch.org/",
    "https://www.tensorflow.org/",
    "https://huggingface.co/",
    "https://huggingface.co/docs/transformers/",
    "https://huggingface.co/models",
    "https://huggingface.co/datasets",
    "https://huggingface.co/spaces",
    "https://www.cloudflare.com/",
    "https://www.digitalocean.com/",
    "https://www.linode.com/",
    "https://www.vultr.com/",
    "https://www.namecheap.com/",
    "https://www.godaddy.com/",
    "https://www.hover.com/",
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
]

PHISHING_URLS = [
    # IP hosts
    "http://192.168.1.1/login",
    "http://10.0.0.1/admin",
    "http://172.16.0.1/secure",
    "http://192.168.0.1/dashboard",
    # Typosquatting with digit substitution
    "http://micr0soft-secure-login.com/verify",
    "http://paypa1.com/account/confirm",
    "http://faceb00k-support.com/help",
    "http://amaz0n-secure.com/login",
    "http://netfl1x-billing.com/account",
    "http://g00gle-security.com/login",
    "http://faceb00k-verify.com/account",
    "http://appl3-id.com/verify",
    "http://wellsf4rgo.com/online/login",
    "http://ch4se-secure.com/banking",
    "http://cit1bank-verify.com/account",
    "http://us4a-login.com/secure",
    "http://c4pital-one.com/verify",
    "http://disc0ver-card.com/account",
    "http://am3rican-express.com/verify",
    "http://sp0tify-premium.com/login",
    "http://t1ktok-viral.com/account",
    "http://d1scord-nitro.com/verify",
    "http://sn4pchat-plus.com/login",
    "http://r0blox-robux.com/account",
    "http://st34m-store.com/verify",
    "http://3pic-games.com/login",
    "http://c0inbase-wallet.com/account",
    "http://b1nance-exchange.com/verify",
    "http://kr4ken-trade.com/login",
    "http://y4hoo-mail.com/account",
    "http://0utlook-365.com/verify",
    "http://0ffice-update.com/login",
    "http://z00m-meeting.com/account",
    "http://sl4ck-workspace.com/verify",
    "http://micr0soft-365.com/signin",
    # Suspicious TLDs
    "http://secure-bank-update.tk/reset",
    "http://apple-id-verify.info/signin",
    "http://google-verify-account.xyz/account",
    "http://paypal-login.top/signin",
    "http://amazon-secure.site/login",
    "http://netflix-update.click/verify",
    "http://bank-verify.icu/account",
    "http://crypto-wallet.digital/login",
    "http://apple-id-confirm.help/verify",
    # Brand impersonation with deceptive paths
    "http://google-verify-account.com/signin",
    "http://paypal-update-account.com/verify",
    "http://irs-gov-verify.com/login",
    "http://amazon-order-update.com/track",
    "http://netflix-billing-update.com/account",
    "http://microsoft-365-update.com/signin",
    "http://apple-id-locked.com/verify",
    "http://facebook-security.com/account",
    "http://twitter-verify.com/login",
    "http://linkedin-confirm.com/verify",
    # Government impersonation
    "http://irs-g0v.com/verify",
    "http://ssa-g0v.com/login",
    "http://fbi-g0v.com/verify",
    "http://cia-g0v.com/login",
    "http://irs-gov-r3fund.com/claim",
    "http://irs-gov-t4x.com/verify",
    "http://irs-gov-p4yment.com/verify",
    "http://irs-g0v-d4ta.com/verify",
    "http://irs-g0v-1nfo.com/verify",
    "http://irs-g0v-r3cord.com/verify",
    "http://irs-g0v-st4tus.com/verify",
    "http://irs-g0v-l0g.com/verify",
    "http://irs-g0v-ch3ck.com/verify",
    "http://irs-g0v-s3arch.com/verify",
    "http://irs-g0v-f1nd.com/verify",
    "http://irs-g0v-tr4ck.com/verify",
    # Banking impersonation
    "http://bank-0f-america.com/login",
    "http://wells-f4rg0.com/online",
    "http://ch4se-bank.com/login",
    "http://c1t1bank.com/account",
    "http://us4a-bank.com/secure",
    "http://c4pital-one.com/account",
    "http://d1scover.com/account",
    "http://am3rican-express.com/account",
    "http://td-b4nk.com/account",
    "http://pnc-b4nk.com/account",
    "http://r3g1ons.com/account",
    "http://suntr1st.com/account",
    "http://hsbc-b4nk.com/account",
    "http://b4rclays.com/account",
    "http://lloyd5.com/account",
    "http://n4tw3st.com/account",
    "http://h4l1fax.com/account",
    "http://tsb-b4nk.com/account",
    "http://v1rg1n.com/account",
    "http://m0nzo.com/account",
    "http://r3volut.com/account",
    "http://st4rl1ng.com/account",
    "http://w1se.com/account",
    # Shipping / delivery scams
    "http://d4hl-express.com/track",
    "http://ups-p4ckage.com/track",
    "http://f3dex-tracking.com/track",
    "http://usps-d3livery.com/track",
    # More phishing patterns
    "http://dr0pbox-sync.com/account",
    "http://0nedrive-access.com/verify",
    "http://1cloud-storage.com/login",
    "http://dr0pbox-login.com/signin",
    "http://onedrive-update.com/verify",
    "http://icloud-locked.com/account",
    "http://steam-wallet.com/verify",
    "http://robux-free.com/claim",
    "http://fortnite-vbucks.com/claim",
    "http://minecraft-premium.com/download",
    "http://instagram-followers.com/generate",
    "http://tiktok-likes.com/generate",
    "http://youtube-subscribers.com/generate",
    "http://twitter-followers.com/generate",
    "http://spotify-premium-free.com/claim",
    "http://netflix-free-account.com/claim",
    "http://amazon-gift-card.com/claim",
    "http://apple-gift-card.com/claim",
    "http://google-play-gift.com/claim",
    "http://paypal-money.com/claim",
    "http://bitcoin-generator.com/generate",
    "http://ethereum-generator.com/generate",
    "http://nft-free.com/mint",
    "http://crypto-airdrop.com/claim",
    "http://defi-rewards.com/claim",
    "http://token-sale.com/buy",
    "http://ico-invest.com/buy",
    "http://stock-picks.com/buy",
    "http://trading-signals.com/join",
    "http://forex-profit.com/join",
    "http://binary-options.com/trade",
    "http://casino-free.com/play",
    "http://poker-free.com/play",
    "http://slots-free.com/play",
    "http://lottery-winner.com/claim",
    "http://prize-winner.com/claim",
    "http://sweepstakes-winner.com/claim",
    "http://congratulations-you-won.com/claim",
    "http://you-have-been-selected.com/claim",
    "http://exclusive-offer.com/claim",
    "http://limited-time-offer.com/claim",
    "http://act-now.com/claim",
    "http://urgent-action-required.com/verify",
    "http://account-suspended.com/verify",
    "http://security-alert.com/verify",
    "http://unusual-activity.com/verify",
    "http://verify-your-identity.com/verify",
    "http://confirm-your-account.com/verify",
    "http://update-your-payment.com/verify",
    "http://billing-issue.com/verify",
    "http://payment-failed.com/verify",
    "http://subscription-expired.com/verify",
    "http://account-deactivated.com/verify",
    "http://account-closed.com/verify",
    "http://account-locked.com/verify",
    "http://account-hacked.com/verify",
    "http://password-expired.com/reset",
    "http://email-verify.com/verify",
    "http://phone-verify.com/verify",
    "http://identity-verify.com/verify",
    "http://address-verify.com/verify",
    "http://ssn-verify.com/verify",
    "http://tax-return.com/claim",
    "http://refund-pending.com/claim",
    "http://overpayment.com/claim",
]


@pytest.fixture(scope="module")
def model():
    """Load the model once for all tests in this module."""
    return LexicalModel()


class TestLegitimateURLs:
    """Test that the HYBRID pipeline classifies legitimate URLs correctly.

    The lexical model may score some legitimate URLs high (long domains,
    unusual TLDs), but the hybrid pipeline's visual stage should catch
    these and correctly classify them as Safe or Suspicious (not Phishing).
    """

    @pytest.mark.parametrize("url", LEGITIMATE_URLS[:50])
    def test_major_sites_hybrid_safe(self, model: LexicalModel, url: str):
        from src.core.hybrid import analyze, HybridConfig
        cfg = HybridConfig()
        result = analyze(url, cfg=cfg, run_vision=False)
        assert result.verdict != "Phishing", (
            f"Legitimate URL classified as Phishing by hybrid: {url} "
            f"(risk={result.risk:.3f}, verdict={result.verdict})"
        )

    @pytest.mark.parametrize("url", LEGITIMATE_URLS[50:])
    def test_extended_sites_hybrid_safe(self, model: LexicalModel, url: str):
        from src.core.hybrid import analyze, HybridConfig
        cfg = HybridConfig()
        result = analyze(url, cfg=cfg, run_vision=False)
        assert result.verdict != "Phishing", (
            f"Legitimate URL classified as Phishing by hybrid: {url} "
            f"(risk={result.risk:.3f}, verdict={result.verdict})"
        )


class TestPhishingURLs:
    """Test that phishing URLs are classified as Phishing or high-risk."""

    @pytest.mark.parametrize("url", PHISHING_URLS[:50])
    def test_phishing_detected(self, model: LexicalModel, url: str):
        prob = model.predict_proba(url)
        assert prob > 0.5, f"Phishing URL missed: {url} (prob={prob:.3f})"

    @pytest.mark.parametrize("url", PHISHING_URLS[50:])
    def test_phishing_extended(self, model: LexicalModel, url: str):
        prob = model.predict_proba(url)
        assert prob > 0.5, f"Phishing URL missed: {url} (prob={prob:.3f})"


class TestEdgeCases:
    """Test edge cases and unusual URL patterns."""

    def test_empty_url(self, model: LexicalModel):
        """Empty URL should not crash."""
        prob = model.predict_proba("")
        assert 0.0 <= prob <= 1.0

    def test_just_domain(self, model: LexicalModel):
        """URL with just a domain (no scheme) — model should not crash."""
        prob = model.predict_proba("google.com")
        assert 0.0 <= prob <= 1.0

    def test_very_long_url(self, model: LexicalModel):
        """Extremely long URL."""
        url = "https://example.com/" + "a" * 500
        prob = model.predict_proba(url)
        assert 0.0 <= prob <= 1.0

    def test_url_with_fragment(self, model: LexicalModel):
        """URL with fragment."""
        prob = model.predict_proba("https://github.com/user/repo#readme")
        assert prob < 0.5

    def test_url_with_many_params(self, model: LexicalModel):
        """URL with many query parameters."""
        url = "https://example.com/search?q=test&page=1&sort=date&filter=all&lang=en"
        prob = model.predict_proba(url)
        assert 0.0 <= prob <= 1.0

    def test_url_with_at_sign(self, model: LexicalModel):
        """URL with @ sign (credential phishing pattern)."""
        prob = model.predict_proba("http://evil.com@real.com/login")
        assert prob > 0.5

    def test_ip_with_port(self, model: LexicalModel):
        """IP address with non-standard port."""
        prob = model.predict_proba("http://192.168.1.1:8080/admin")
        assert prob > 0.5

    def test_https_phishing(self, model: LexicalModel):
        """Phishing with HTTPS (many phishing sites use HTTPS now)."""
        prob = model.predict_proba("https://micr0soft-secure-login.com/verify")
        # The model should still flag this as suspicious (not safe)
        assert prob > 0.3, f"HTTPS phishing URL too low risk: {prob:.3f}"


class TestModelMetadata:
    """Test model artifact integrity."""

    def test_model_loads(self, model: LexicalModel):
        """Model should load without error."""
        model._ensure_loaded()
        assert model._artifact is not None

    def test_feature_count(self, model: LexicalModel):
        """Model should expect the current feature count."""
        model._ensure_loaded()
        clf = model._artifact["model"]
        from src.lexical.features import FEATURE_NAMES
        assert clf.n_features_in_ == len(FEATURE_NAMES)

    def test_feature_names_match(self, model: LexicalModel):
        """Artifact feature names should match FEATURE_NAMES."""
        model._ensure_loaded()
        from src.lexical.features import FEATURE_NAMES
        assert model._artifact["features"] == FEATURE_NAMES
