# News / Threat Intelligence module

A curated cybersecurity news feed, refreshed weekly from ~20 trusted sources.
The UI presents it as a professional intelligence feed — with **no** AI traces,
relevance percentages, or confidence scores.

## Sources

Defined in `news/config.py` (`NEWS_FEEDS`): ~20 RSS/Atom feeds covering CVEs and
vulnerabilities, threats and incidents, attack techniques, security of
languages/frameworks/libraries, patches/releases, and research (e.g. The Hacker
News, BleepingComputer, Krebs, Dark Reading, Project Zero, MSRC, Talos,
PortSwigger Research, SANS ISC, CISA advisories, NVD recent CVEs, …).

## Pipeline (`news/fetcher.py`)

1. **Fetch** — each feed is pulled with `requests` and parsed with the stdlib
   XML parser (`xml.etree`) — no extra dependency. Both RSS and Atom are handled;
   HTML in summaries is stripped. Up to `MAX_ARTICLES_PER_FEED` items per feed.
2. **Dedupe** — by article URL and by a `content_hash` (title+link), checked
   against `news_articles` before any LLM work.
3. **Curate** — each new item goes to the **News Curator Agent**
   (`agents/news_curator_agent.py`), which decides whether it is genuinely
   cybersecurity-relevant and, if so, returns a professional title, a concise
   summary, and a list of affected technologies. Irrelevant items are rejected.
4. **Store** — validated items are inserted into `news_articles`.

## Weekly scheduling

- `news/config.py:UPDATE_INTERVAL_DAYS = 7`.
- On backend startup (`server/main.py` → `_maybe_refresh_news`), a background
  daemon thread checks `app_meta.last_news_update`. If it is older than 7 days
  (or never set), the update runs **in the background** — startup never blocks on
  network/LLM calls. Otherwise it is skipped.
- `last_news_update` is written after each run.

## API

- `GET /api/news?limit=N` — list curated articles (authenticated users).
  Returns only `{title, summary, source, url, affected_technologies, published_at}`.
- `POST /api/news/refresh` — **admin only**, manual background trigger (ignores
  the 7-day gate).

## UI

`frontend/src/pages/News.jsx` renders a card grid (title → source link, summary,
affected-technology tags, relative time). The brand nav links to it, and the
landing page shows a 4-item teaser. The interface deliberately never shows that
articles were processed by an agent, nor any relevance/confidence score.

## Operational notes

- Individual feed failures are logged and skipped — one bad feed never aborts the
  run.
- If the curator LLM is unavailable, items are simply not stored (no partial/raw
  articles leak into the feed).
