"""Add complex legitimate URLs to the training dataset.

These are real-world URL patterns from major sites that have deep paths,
query parameters, encoded characters, and other complex structures.
Without these, the model learns 'complex URL = phishing'.
"""

import random
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data" / "raw" / "lexical_urls.csv"

# Real-world complex legitimate URLs from major sites
COMPLEX_LEGIT_URLS = [
    # Amazon — deep paths, query params, encoded chars
    "https://www.amazon.com/gp/css/order-history?ref_=nav_acct_orders",
    "https://www.amazon.com/gp/your-account/order-history?ie=UTF8",
    "https://www.amazon.com/gp/registry/search.html?type=2&field-keywords=",
    "https://www.amazon.com/s?k=wireless+mouse&ref=nb_sb_noss",
    "https://www.amazon.com/dp/B08N5WRWNW?th=1&psc=1",
    "https://www.amazon.com/gp/cart/view.html?ref_=nav_cart",
    "https://www.amazon.com/gp/your-account/address-book",
    "https://www.amazon.com/gp/your-account/payment-methods",
    "https://www.amazon.com/hz/wishlist/ls?query=",
    "https://www.amazon.com/gp/help/customer/display.html?nodeId=201819200",
    # Google Docs — long paths with encoded IDs
    "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit",
    "https://docs.google.com/spreadsheets/d/1AbCdEfGhIjKlMnOpQrStUvWxYz1234567890/edit",
    "https://docs.google.com/presentation/d/1ABCDEFgHIJKLMNOpQRSTUVWXYZ/edit",
    "https://drive.google.com/file/d/1ABCDEFgHIJKLMNOpQRSTUVWXYZ/view",
    "https://drive.google.com/drive/folders/1ABCDEFgHIJKLMNOpQRSTUVWXYZ",
    "https://calendar.google.com/calendar/r/eventedit?text=Meeting",
    "https://maps.google.com/maps?q=New+York&t=k&z=12",
    "https://translate.google.com/?sl=en&tl=es&op=translate",
    "https://scholar.google.com/scholar?q=machine+learning&hl=en",
    # LinkedIn — encoded query params
    "https://www.linkedin.com/in/johndoe?miniProfileUrn=urn%3Ali%3Afsd_profile%3AACoAAAA",
    "https://www.linkedin.com/jobs/search/?keywords=python&location=remote",
    "https://www.linkedin.com/company/google/jobs/",
    "https://www.linkedin.com/messaging/?filter=unread",
    "https://www.linkedin.com/feed/update/urn:li:activity:1234567890",
    "https://www.linkedin.com/notifications/?filter=mentions",
    "https://www.linkedin.com/search/results/people/?keywords=data+scientist",
    # YouTube — complex query params
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=120s",
    "https://www.youtube.com/watch?v=9bZkp7q19f0&list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
    "https://www.youtube.com/results?search_query=python+tutorial",
    "https://www.youtube.com/channel/UC-lHJZR3Gqxm24_Vd_AJ5Yw/videos",
    "https://www.youtube.com/@username/shorts",
    "https://www.youtube.com/playlist?list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
    "https://www.youtube.com/feed/subscriptions",
    "https://www.youtube.com/gaming",
    # Twitch — filters, ranges
    "https://www.twitch.tv/shroud/clips?filter=clips&range=7d",
    "https://www.twitch.tv/directory/category/just-chatting?sort=VIEWER_COUNT",
    "https://www.twitch.tv/directory/all?sort=VIEWER_COUNT",
    "https://www.twitch.tv/videos/1234567890",
    "https://www.twitch.tv/events/1234567",
    "https://www.twitch.tv/settings/profile",
    # Netflix — watch IDs, categories
    "https://www.netflix.com/watch/80057281?autoplay=1",
    "https://www.netflix.com/browse/genre/343",
    "https://www.netflix.com/search?q=test",
    "https://www.netflix.com/title/80057281",
    "https://www.netflix.com/my-list",
    "https://www.netflix.com/account/planform",
    # Spotify — URIs, playlists
    "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
    "https://open.spotify.com/album/1DFixLWuPkv3KT3TnV35m3",
    "https://open.spotify.com/artist/06HL4z0CvFAxyc27GXpf02",
    "https://open.spotify.com/show/2MAi0BvDc6OOh2G2U8rHxs",
    "https://open.spotify.com/episode/7makk4lTQi5VhRCPZIz0JZ",
    "https://open.spotify.com/search/python%20playlist",
    "https://open.spotify.com/collection/tracks",
    # Reddit — deep paths, query params
    "https://www.reddit.com/r/programming/comments/abc123/title_of_post/",
    "https://www.reddit.com/r/python/top/?t=month",
    "https://www.reddit.com/r/AskReddit/controversial/?t=year",
    "https://www.reddit.com/user/username/saved/",
    "https://www.reddit.com/message/inbox/",
    "https://www.reddit.com/settings/",
    "https://www.reddit.com/search/?q=phishing+detection&sort=relevance",
    "https://www.reddit.com/r/all/",
    # Hulu — series IDs
    "https://www.hulu.com/series/the-handmaids-tale-1234567",
    "https://www.hulu.com/series/pretty-little-liars-1234567/episodes",
    "https://www.hulu.com/guides/94ac5bfd-0bb8-4b1e-9864-abc123def456",
    # Disney+ — deep paths
    "https://www.disneyplus.com/series/the-mandalorian/3jLIGMDYINqD",
    "https://www.disneyplus.com/video/4e9d5f4b-e1e3-4bf3-ae1c-2c6d8f9e0a1b",
    "https://www.disneyplus.com/search?q=star+wars",
    # GitHub — tree, blob, actions
    "https://github.com/facebook/react/blob/main/packages/react/index.js",
    "https://github.com/facebook/react/tree/main/packages",
    "https://github.com/facebook/react/actions/workflows/ci.yml",
    "https://github.com/facebook/react/releases/tag/v18.2.0",
    "https://github.com/facebook/react/pull/12345",
    "https://github.com/facebook/react/issues/12345",
    "https://github.com/facebook/react/compare/v18.1.0...v18.2.0",
    "https://github.com/facebook/react/network/members",
    "https://github.com/facebook/react/graphs/contributors",
    # Stack Overflow — question IDs, tags
    "https://stackoverflow.com/questions/12345678/how-to-center-a-div",
    "https://stackoverflow.com/questions/tagged/python?tab=votes",
    "https://stackoverflow.com/questions/12345678/how-to-center-a-div?answertab=scoredesc",
    "https://stackoverflow.com/search?q=python+list+comprehension",
    "https://stackoverflow.com/users/12345678/username",
    # Twitter/X — status IDs
    "https://twitter.com/elonmusk/status/1234567890123456789",
    "https://twitter.com/search?q=python&src=typed_query",
    "https://twitter.com/explore",
    "https://twitter.com/notifications",
    "https://twitter.com/settings/account",
    # Discord — deep paths
    "https://discord.com/channels/1234567890/9876543210/1111111111",
    "https://discord.com/invite/abc123",
    "https://discord.com/settings/account",
    "https://discord.com/nitro",
    # Dropbox — shared links
    "https://www.dropbox.com/s/abc123def456/file.pdf?dl=0",
    "https://www.dropbox.com/sh/abc123def456/AAA",
    "https://www.dropbox.com/home/Projects/my-project",
    # Notion — deep paths
    "https://www.notion.so/workspace/Project-Notes-abc123def456",
    "https://www.notion.so/My-Database-abc123def456?v=abc123",
    "https://www.notion.so/team/Engineering-abc123def456",
    # Figma — file IDs
    "https://www.figma.com/file/ABC123/Design-System",
    "https://www.figma.com/proto/ABC123/Prototype",
    "https://www.figma.com/board/ABC123/Whiteboard",
    # Jira — issue keys
    "https://jira.atlassian.com/browse/PROJ-1234",
    "https://jira.atlassian.com/projects/PROJ/boards/123",
    "https://jira.atlassian.com/jira/software/projects/PROJ/versions/12345",
    # Slack — deep paths
    "https://app.slack.com/client/T01234567/C0123456",
    "https://app.slack.com/create?email=user%40example.com",
    "https://app.slack.com/A01234567/B0123456",
    # Trello — board IDs
    "https://trello.com/b/ABC123/project-board",
    "https://trello.com/c/ABC123/card-title",
    "https://trello.com/u/username/boards",
    # Zoom — meeting IDs
    "https://zoom.us/j/1234567890?pwd=ABC123DEF456",
    "https://zoom.us/s/abc123def456",
    "https://zoom.us/wc/1234567890/abc123",
    # Google Search — encoded queries
    "https://www.google.com/search?q=phishing+detection+machine+learning&num=10",
    "https://www.google.com/search?q=site:github.com+python&tbm=isch",
    "https://www.google.com/search?q=weather+today&tbs=qdr:w",
    "https://www.google.com/search?q=define:phishing",
    # Google Maps — coordinates
    "https://www.google.com/maps/@37.7749,-122.4194,15z",
    "https://www.google.com/maps/place/New+York,+NY",
    "https://www.google.com/maps/dir/Paris/London",
    # Google Calendar — event editing
    "https://calendar.google.com/calendar/r/eventedit?text=Meeting&dates=20240101T100000Z/20240101T110000Z",
    # Wikipedia — deep paths
    "https://en.wikipedia.org/wiki/Phishing#Techniques",
    "https://en.wikipedia.org/w/index.php?title=Phishing&action=history",
    "https://en.wikipedia.org/wiki/Special:Search?search=machine+learning",
    "https://en.wikipedia.org/wiki/Python_(programming_language)#Libraries",
    # MDN — deep paths
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map",
    "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch",
    "https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Asynchronous",
    # PyPI — complex paths
    "https://pypi.org/project/requests/2.31.0/#history",
    "https://pypi.org/simple/requests/",
    "https://pypi.org/search/?q=phishing",
    # npm — scoped packages
    "https://www.npmjs.com/package/@angular/core",
    "https://www.npmjs.com/package/@types/node?activeTab=versions",
    "https://www.npmjs.com/search?q=phishing",
    # Docker Hub — tags
    "https://hub.docker.com/r/library/python/tags",
    "https://hub.docker.com/_/nginx?tab=tags",
    "https://hub.docker.com/u/username",
    # HuggingFace — model cards
    "https://huggingface.co/bert-base-uncased",
    "https://huggingface.co/datasets/squad",
    "https://huggingface.co/spaces/username/my-project",
    "https://huggingface.co/gpt2/tree/main",
    "https://huggingface.co/api/models/bert-base-uncased",
    # Cloudflare — dashboard
    "https://dash.cloudflare.com/abc123def456/example.com",
    "https://developers.cloudflare.com/workers/",
    "https://blog.cloudflare.com/tag/security/",
    # Vercel — deployments
    "https://vercel.com/username/project/deployments",
    "https://vercel.com/username/project/settings/environment-variables",
    "https://vercel.com/username/project/domains",
    # Netlify — sites
    "https://app.netlify.com/sites/my-site/deploys",
    "https://app.netlify.com/sites/my-site/settings/deploys",
    "https://app.netlify.com/teams/username/sites",
    # AWS Console — deep paths
    "https://console.aws.amazon.com/ec2/home?region=us-east-1#Instances:",
    "https://console.aws.amazon.com/s3/home?region=us-east-1#bucket-policy",
    "https://console.aws.amazon.com/lambda/home#/functions",
    "https://us-east-1.console.aws.amazon.com/cloudwatch/home",
    # Azure — portal paths
    "https://portal.azure.com/#view/Microsoft_Azure_Resources",
    "https://portal.azure.com/#blade/Microsoft_Azure_Resources",
    "https://learn.microsoft.com/en-us/azure/active-directory/",
    # GCP Console
    "https://console.cloud.google.com/kubernetes/list/overview",
    "https://console.cloud.google.com/functions/list",
    "https://console.cloud.google.com/logs/query",
    # Medium — article IDs
    "https://medium.com/@user/article-title-abc123def456",
    "https://medium.com/towards-data-science/phishing-detection-abc123",
    "https://medium.com/@user/list/my-list-abc123",
    # Dev.to — article slugs
    "https://dev.to/user/article-title-abc123",
    "https://dev.to/t/python",
    "https://dev.to/top/week",
    # Hacker News — item IDs
    "https://news.ycombinator.com/item?id=12345678",
    "https://news.ycombinator.com/newest",
    "https://news.ycombinator.com/ask",
    "https://news.ycombinator.com/show",
    # BBC — sections
    "https://www.bbc.com/news/technology-12345678",
    "https://www.bbc.com/sport/football/scores-fixtures",
    "https://www.bbc.co.uk/iplayer/episodes/live",
    # NYT — sections, encoded
    "https://www.nytimes.com/2024/01/01/technology/article.html",
    "https://www.nytimes.com/crosswords/game/mini",
    "https://www.nytimes.com/section/technology?redirectUri=abc",
    # CNN — sections
    "https://www.cnn.com/world/live-news/abc-123-abc123",
    "https://edition.cnn.com/video",
    # Reuters — deep paths
    "https://www.reuters.com/technology/",
    "https://www.reuters.com/business/finance/",
    # CoinGecko — coin pages
    "https://www.coingecko.com/en/coins/bitcoin",
    "https://www.coingecko.com/en/coins/ethereum/chart",
    "https://www.coingecko.com/en/exchanges/binance",
    # TradingView — charts
    "https://www.tradingview.com/chart/ABC123/",
    "https://www.tradingview.com/symbols/BTCUSD/",
    "https://www.tradingview.com/symbols/BTCUSD/technicals/",
    # Booking.com — complex paths
    "https://www.booking.com/hotel/us/example.html?checkin=2024-06-01",
    "https://www.booking.com/searchresults.html?ss=New+York",
    "https://www.booking.com/mybookings.html",
    # Airbnb — search params
    "https://www.airbnb.com/s/New-York--NY/homes",
    "https://www.airbnb.com/rooms/12345678",
    "https://www.airbnb.com/users/show/12345678",
    # TripAdvisor — deep paths
    "https://www.tripadvisor.com/Attractions-g60763-Activities-New_York_City_New_York.html",
    "https://www.tripadvisor.com/Hotel_Review-g60763-d1234567-Reviews-Example.html",
    "https://www.tripadvisor.com/Restaurant_Review-g60763-d1234567-Reviews.html",
    # Expedia — search params
    "https://www.expedia.com/Hotel-Search?destination=New+York",
    "https://www.expedia.com/Flights-search?trip=roundtrip",
    "https://www.expedia.com/Cars-search?locn=JFK",
    # Khan Academy — paths
    "https://www.khanacademy.org/computing/computer-science/algorithms",
    "https://www.khanacademy.org/math/algebra/x2f8bb11595b61c86:foundation-algebra",
    "https://www.khanacademy.org/science/biology",
    # LeetCode — problem IDs
    "https://leetcode.com/problems/two-sum/",
    "https://leetcode.com/problems/add-two-numbers/description/",
    "https://leetcode.com/tag/array/",
    "https://leetcode.com/studyplan/top-interview-150/",
    # GeeksforGeeks — article paths
    "https://www.geeksforgeeks.org/python-programming-language/",
    "https://www.geeksforgeeks.org/maximize-sum-of-consecutive-differences-in-a-circular-array/",
    "https://www.geeksforgeeks.org/searching-algorithms/",
    # W3Schools — paths
    "https://www.w3schools.com/python/default.asp",
    "https://www.w3schools.com/jsref/event_onclick.asp",
    "https://www.w3schools.com/cssref/pr_class_display.php",
    # MDN — paths
    "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input",
    "https://developer.mozilla.org/en-US/docs/Web/CSS/@media",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    # PyTorch — paths
    "https://pytorch.org/tutorials/beginner/basics/intro.html",
    "https://pytorch.org/docs/stable/nn.html",
    "https://pytorch.org/hub/",
    # TensorFlow — paths
    "https://www.tensorflow.org/tutorials/quickstart/beginner",
    "https://www.tensorflow.org/api_docs/python/tf/keras",
    "https://www.tensorflow.org/tfx/guide",
    # React — paths
    "https://react.dev/learn/thinking-in-react",
    "https://react.dev/reference/react/useState",
    "https://react.dev/learn/managing-state",
    # Vue — paths
    "https://vuejs.org/guide/introduction.html",
    "https://vuejs.org/api/sfc-script-setup.html",
    "https://vuejs.org/examples/#game",
    # Next.js — paths
    "https://nextjs.org/docs/app/building-your-application/routing",
    "https://nextjs.org/docs/app/api-reference",
    "https://nextjs.org/learn",
    # Svelte — paths
    "https://svelte.dev/tutorial/basics",
    "https://svelte.dev/docs/svelte/overview",
    # Tailwind — paths
    "https://tailwindcss.com/docs/utility-first",
    "https://tailwindcss.com/docs/customizing-colors",
    # GitHub Pages — complex paths
    "https://username.github.io/my-project/docs/getting-started",
    "https://user.github.io/project-name/api-reference",
    # Notion — deep paths
    "https://www.notion.so/workspace/Project-Management-abc123def456?v=xyz789",
    "https://www.notion.so/team/Engineering/Meeting-Notes-abc123",
    # Linear — issue IDs
    "https://linear.app/team/issue/ABC-123/title-of-issue",
    "https://linear.app/team/teams/engineering",
    # ClickUp — task IDs
    "https://app.clickup.com/t/abc1234",
    "https://app.clickup.com/2345678/v/l/abc1234",
    # Asana — task IDs
    "https://app.asana.com/0/1234567890/1234567890/f",
    "https://app.asana.com/0/home/1234567890",
    # Monday.com — board IDs
    "https://app.monday.com/workspaces/123456/boards/123456",
    # Todoist — project IDs
    "https://app.todoist.com/app/project/abc1234",
    # Clockify — workspace
    "https://app.clockify.me/tracker",
    "https://app.clockify.me/reports",
    # Freshdesk — ticket IDs
    "https://support.example.com/a/tickets/12345",
    "https://support.example.com/support/home",
    # Zendesk — ticket IDs
    "https://example.zendesk.com/hc/en-us/articles/12345",
    "https://example.zendesk.com/agent/tickets/12345",
    # HubSpot — CRM paths
    "https://app.hubspot.com/contacts/1234567/dashboard",
    "https://app.hubspot.com/crm-dashboard/1234567",
    # Salesforce — paths
    "https://login.salesforce.com/",
    "https://na1.salesforce.com/001000000000001",
    # Mailchimp — campaign IDs
    "https://us1.campaign-archive.com/home/?u=abc123&id=def456",
    # SendGrid — dashboard
    "https://app.sendgrid.com/statistics",
    # Twilio — console
    "https://console.twilio.com/us1/develop/sms",
    # Stripe — dashboard
    "https://dashboard.stripe.com/payments",
    "https://dashboard.stripe.com/test/customers",
    # PayPal — deep paths
    "https://www.paypal.com/myaccount/summary/",
    "https://www.paypal.com/activity",
    "https://www.paypal.com/us/webapps/mpp/account-limitations",
    # Bank of America — deep paths
    "https://www.bankofamerica.com/deposits/checking/accounts/",
    "https://www.bankofamerica.com/credit-cards/",
    "https://www.bankofamerica.com/mortgage/mortgage-rates/",
    # Chase — deep paths
    "https://www.chase.com/personal/checking",
    "https://www.chase.com/business/banking",
    "https://www.chase.com/content/dam/chase-ux/documents/personal/checking/compare-checking-accounts.pdf",
    # Wells Fargo — deep paths
    "https://www.wellsfargo.com/checking/",
    "https://www.wellsfargo.com/savings-accounts/",
    # Coinbase — deep paths
    "https://www.coinbase.com/price/bitcoin",
    "https://www.coinbase.com/learn",
    "https://www.coinbase.com/advanced-trade/spot/BTC-USD",
    # TradingView — complex
    "https://www.tradingview.com/symbols/NASDAQ-AAPL/technicals/",
    "https://www.tradingview.com/symbols/BTCUSD/forecast/",
    # IMDb — deep paths
    "https://www.imdb.com/title/tt0111161/",
    "https://www.imdb.com/title/tt0111161/fullcredits",
    "https://www.imdb.com/chart/top/",
    "https://www.imdb.com/search/title/?genres=action",
    # Goodreads — book IDs
    "https://www.goodreads.com/book/show/12345-the-book",
    "https://www.goodreads.com/reviews/widget_iframe/12345",
    # Steam — app IDs
    "https://store.steampowered.com/app/730/CounterStrike/",
    "https://store.steampowered.com/app/730/CounterStrike/?snr=1_7_7_230_7",
    "https://steamcommunity.com/profiles/76561198000000000",
    "https://store.steampowered.com/search/?term=phishing",
    # Epic Games — paths
    "https://store.epicgames.com/en-US/p/fortnite",
    "https://www.epicgames.com/store/en-US/browse?q=search",
    # Roblox — game IDs
    "https://www.roblox.com/games/123456789/Game-Name",
    "https://www.roblox.com/users/123456789/profile",
    # Minecraft — paths
    "https://www.minecraft.net/en-us/store/minecraft-java-edition",
    "https://www.minecraft.net/en-us/realms",
    # Canva — design IDs
    "https://www.canva.com/design/ABC123/view",
    "https://www.canva.com/templates/?query=presentation",
    # Figma — file IDs
    "https://www.figma.com/file/ABC1234/Design-System?node-id=0%3A1",
    "https://www.figma.com/proto/ABC1234/Prototype?scaling=min-zoom",
    # Miro — board IDs
    "https://miro.com/app/board/ABC1234/",
    "https://miro.com/app/live-docs/ABC1234/",
    # Airtable — base IDs
    "https://airtable.com/appABC1234/tblXYZ5678/viweABC123",
    # Google Analytics — paths
    "https://analytics.google.com/analytics/web/#/abc1234",
    # Google Search Console — paths
    "https://search.google.com/search-console/performance/abc1234",
    # Mailchimp — paths
    "https://us1.campaign-archive.com/home/?u=abc123&id=def456",
    "https://login.mailchimp.com/",
    # Zapier — paths
    "https://zapier.com/app/zaps",
    "https://zapier.com/app/editor/12345678",
    # IFTTT — paths
    "https://ifttt.com/my_applets",
    # Grammarly — paths
    "https://www.grammarly.com/edu/assignments",
    # Notion — pages
    "https://www.notion.so/username/page-title-abc123def456",
    "https://www.notion.so/workspace/Team-Space-abc123def456",
    # Coda — docs
    "https://coda.io/d/ABC1234/Document-Title_dabc1234",
    # Airtable — views
    "https://airtable.com/appABC1234/tblXYZ5678/view/VIewName",
    # Toggl — tracking
    "https://track.toggl.com/9876543/dashboard",
    "https://toggl.com/reports/summary",
    # Calendly — booking
    "https://calendly.com/username/30min",
    "https://calendly.com/username/event-types",
    # Loom — video IDs
    "https://www.loom.com/share/abc123def456ghi789",
    # Vidyard — video IDs
    "https://video.vidyard.com/watch/abc123def456",
    # Typeform — form IDs
    "https://form.typeform.com/to/abc123def456",
    # SurveyMonkey — survey IDs
    "https://www.surveymonkey.com/r/ABC1234",
    # Google Forms — form IDs
    "https://docs.google.com/forms/d/e/1FAIpQLSeF2/viewform",
    "https://docs.google.com/forms/d/1ABC1234/viewform",
]


def main():
    df = pd.read_csv(CSV).dropna(subset=["url", "label"])

    before = len(df[df.label == 0])
    new_rows = [{"url": u, "label": 0} for u in COMPLEX_LEGIT_URLS]
    new_df = pd.DataFrame(new_rows)
    df = pd.concat([df, new_df], ignore_index=True)
    df = df.drop_duplicates(subset="url")

    after = len(df[df.label == 0])
    print(f"Added {after - before} complex legitimate URLs")
    print(f"Total: {len(df)} ({(df.label==1).sum()} phish, {(df.label==0).sum()} legit)")
    df.to_csv(CSV, index=False)


if __name__ == "__main__":
    main()
