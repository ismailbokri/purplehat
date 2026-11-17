"""Reference cybersecurity news sources (RSS/Atom feeds).

~20 trusted sources covering CVEs, vulnerabilities, threats, incidents, and
security research. Feeds are parsed with the stdlib XML parser (no extra deps).
"""

# (name, feed_url)
NEWS_FEEDS = [
    ("The Hacker News",          "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer",         "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security",        "https://krebsonsecurity.com/feed/"),
    ("Dark Reading",             "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",             "https://www.securityweek.com/feed/"),
    ("Threatpost",               "https://threatpost.com/feed/"),
    ("Schneier on Security",     "https://www.schneier.com/feed/atom/"),
    ("Google Project Zero",      "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Google Online Security",   "https://security.googleblog.com/feeds/posts/default"),
    ("Microsoft MSRC",           "https://msrc.microsoft.com/blog/feed"),
    ("Cisco Talos",              "https://blog.talosintelligence.com/rss/"),
    ("Rapid7 Blog",              "https://www.rapid7.com/blog/rss/"),
    ("Tenable Blog",             "https://www.tenable.com/blog/feed"),
    ("Qualys ThreatPROTECT",     "https://blog.qualys.com/feed"),
    ("Naked Security (Sophos)",  "https://nakedsecurity.sophos.com/feed/"),
    ("Troy Hunt",                "https://www.troyhunt.com/rss/"),
    ("PortSwigger Research",     "https://portswigger.net/research/rss"),
    ("SANS ISC",                 "https://isc.sans.edu/rssfeed_full.xml"),
    ("CISA Advisories",          "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("NVD Recent CVEs",          "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"),
]

# Max articles pulled per feed per run (keeps a run bounded).
MAX_ARTICLES_PER_FEED = 8

# Weekly cadence: only refresh if the last update is older than this.
UPDATE_INTERVAL_DAYS = 7
