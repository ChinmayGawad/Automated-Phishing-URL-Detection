/**
 * Known legitimate domains whitelist — port of KNOWN_LEGITIMATE_DOMAINS from features.py
 * Used for fast-path: known legit domains are immediately marked Safe.
 */

// KNOWN_LEGITIMATE_DOMAINS — GENERATED from src/lexical/features.py
// (run: python scripts/gen_extension_constants.py). Do not edit by hand.
const KNOWN_LEGITIMATE_DOMAINS = new Set([
  "google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
  "google.ca", "google.com.au", "google.co.in", "google.com.br",
  "google.it", "google.es", "google.nl", "google.pl", "google.ru",
  "google.cn", "google.com.hk", "google.com.sg", "google.co.kr",
  "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
  "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
  "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com",
  "snapchat.com", "tiktok.com", "whatsapp.com", "telegram.org",
  "telegram.me", "telegram.dog", "discord.com", "discord.gg",
  "quora.com", "medium.com", "substack.com", "threads.net",
  "mastodon.social", "bsky.app",
  "youtube.com", "youtu.be", "twitch.tv", "vimeo.com",
  "soundcloud.com", "spotify.com", "open.spotify.com",
  "deezer.com", "pandora.com", "music.apple.com",
  "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
  "stackoverflow.com", "stackexchange.com", "dev.to",
  "npmjs.com", "pypi.org", "crates.io", "rubygems.org",
  "nuget.org", "packagist.org", "maven.org",
  "docker.com", "docker.io", "hub.docker.com",
  "vercel.com", "netlify.com", "heroku.com", "firebase.google.com",
  "cloudflare.com", "fastly.com", "akamai.com",
  "digitalocean.com", "linode.com", "vultr.com",
  "railway.app", "fly.io", "render.com", "replit.com",
  "codesandbox.io", "stackblitz.com", "glitch.com",
  "gitbook.io", "readthedocs.io",
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
  "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
  "washingtonpost.com", "theguardian.com", "reuters.com",
  "apnews.com", "bloomberg.com", "wsj.com", "ft.com",
  "economist.com", "aljazeera.com", "dw.com", "france24.com",
  "techcrunch.com", "arstechnica.com", "theverge.com",
  "wired.com", "engadget.com", "mashable.com",
  "pcmag.com", "tomsguide.com", "howtogeek.com",
  "huffpost.com", "usatoday.com", "nbcnews.com", "cbsnews.com",
  "foxnews.com", "latimes.com", "sfgate.com",
  "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
  "amazon.ca", "amazon.com.au", "amazon.in", "amazon.com.br",
  "ebay.com", "etsy.com", "walmart.com", "target.com",
  "bestbuy.com", "costco.com", "homedepot.com", "lowes.com",
  "ikea.com", "wayfair.com", "zappos.com", "newegg.com",
  "aliexpress.com", "wish.com", "mercari.com",
  "shopify.com", "bigcommerce.com", "squarespace.com", "wix.com",
  "bankofamerica.com", "wellsfargo.com", "chase.com",
  "citi.com", "capitalone.com", "discover.com",
  "americanexpress.com", "usaa.com",
  "venmo.com", "zellepay.com",
  "fidelity.com", "vanguard.com", "schwab.com",
  "etrade.com", "tdameritrade.com", "robinhood.com",
  "coinbase.com", "kraken.com", "binance.com",
  "hsbc.com", "barclays.com", "lloydsbank.com",
  "natwest.com", "santander.com", "halifax.co.uk",
  "booking.com", "airbnb.com", "tripadvisor.com",
  "expedia.com", "kayak.com", "hotels.com",
  "vrbo.com", "hilton.com", "marriott.com",
  "ihg.com", "hyatt.com", "sheraton.com",
  "uber.com", "lyft.com", "grab.com",
  "coursera.org", "edx.org", "udemy.com", "khanacademy.org",
  "codecademy.com", "freecodecamp.org", "leetcode.com",
  "hackerrank.com", "codewars.com", "geeksforgeeks.org",
  "w3schools.com", "tutorialspoint.com", "programiz.com",
  "duolingo.com", "brilliant.org",
  "developer.mozilla.org", "docs.python.org",
  "react.dev", "vuejs.org", "angular.io", "svelte.dev",
  "nextjs.org", "nuxt.com", "astro.build",
  "pytorch.org", "tensorflow.org", "huggingface.co",
  "typescriptlang.org", "rust-lang.org", "golang.org",
  "dart.dev", "kotlinlang.org", "swift.org",
  "mayoclinic.org", "webmd.com", "healthline.com",
  "medicalnewstoday.com", "clevelandclinic.org",
  "hopkinsmedicine.org", "massgeneral.org",
  "cedars-sinai.org", "mountsinai.org",
  "usa.gov", "irs.gov", "ssa.gov", "usps.com",
  "nasa.gov", "cdc.gov", "nih.gov", "fda.gov",
  "epa.gov", "energy.gov", "ed.gov", "dol.gov",
  "hhs.gov", "state.gov", "justice.gov", "defense.gov",
  "va.gov", "usda.gov", "commerce.gov", "hud.gov",
  "fbi.gov", "cia.gov", "fcc.gov", "faa.gov",
  "netflix.com", "disneyplus.com", "hulu.com",
  "hbo.com", "paramountplus.com", "peacocktv.com",
  "crunchyroll.com", "apple.com", "icloud.com",
  "microsoft.com", "windows.com", "office.com",
  "xbox.com", "playstation.com", "nintendo.com",
  "steampowered.com", "epicgames.com", "roblox.com",
  "ea.com", "ubisoft.com", "blizzard.com",
  "wikipedia.org", "wikimedia.org",
  "archive.org", "imdb.com", "rottentomatoes.com",
  "goodreads.com", "craigslist.org",
  "yelp.com", "opentable.com",
  "dropbox.com", "box.com", "onedrive.live.com",
  "obsidian.md", "logseq.com", "ankiweb.net",
  "jetbrains.com", "visualstudio.com", "sublimetext.com",
  "namecheap.com", "godaddy.com", "hover.com",
  "1password.com", "lastpass.com", "bitwarden.com",
  "solidjs.com", "remix.run", "svelte.dev", "astro.build",
  "vuejs.org", "react.dev", "angular.io", "nextjs.org", "nuxt.com",
  "deno.com", "bun.sh", "pnpm.io", "npmjs.com", "yarnpkg.com",
  "rollupjs.org", "vitejs.dev", "webpack.js.org", "tailwindcss.com",
  "prisma.io", "supabase.com", "planetscale.com", "neon.tech",
  "turso.tech", "dgraph.io", "arangodb.com", "redis.io", "memcached.org",
  "rabbitmq.com", "kafka.apache.org", "elastic.co", "datadog.com",
  "grafana.com", "prometheus.io", "newrelic.com", "sentry.io",
  "mit.edu", "ocw.mit.edu", "stanford.edu", "harvard.edu",
  "berkeley.edu", "cmu.edu", "caltech.edu", "princeton.edu",
  "yale.edu", "cornell.edu", "columbia.edu", "upenn.edu",
  "umich.edu", "uw.edu", "ucla.edu", "utexas.edu", "gatech.edu",
  "chinmaygawad.github.io",
]);

function checkWhitelist(url) {
  let parsed;
  try {
    parsed = new URL(url.includes("://") ? url : "http://" + url);
  } catch {
    return false;
  }

  const host = (parsed.hostname || "").toLowerCase().split(":")[0];

  // Direct match
  if (KNOWN_LEGITIMATE_DOMAINS.has(host)) return true;

  // Subdomain match
  for (const wlDomain of KNOWN_LEGITIMATE_DOMAINS) {
    if (host === wlDomain || host.endsWith("." + wlDomain)) return true;
  }

  return false;
}

// ES module exports
if (typeof module !== "undefined") {
  module.exports = { KNOWN_LEGITIMATE_DOMAINS, checkWhitelist };
}
