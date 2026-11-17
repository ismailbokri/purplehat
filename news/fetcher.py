"""News fetch + curate pipeline.

Pulls recent items from the configured RSS/Atom feeds (parsed with the stdlib
XML parser — no extra dependency), sends each to the curator agent, and stores
validated, de-duplicated articles. Runs weekly, triggered from startup only if
the last successful update is older than UPDATE_INTERVAL_DAYS.
"""

import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from db.connection import get_conn
from news.config import MAX_ARTICLES_PER_FEED, NEWS_FEEDS, UPDATE_INTERVAL_DAYS

logger = logging.getLogger(__name__)

_LAST_UPDATE_KEY = "last_news_update"
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _strip_html(text: str) -> str:
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", text or "")).strip()


def _local(tag: str) -> str:
    """Strip XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1].lower()


def _parse_feed(xml_bytes: bytes) -> List[Dict[str, str]]:
    """Parse an RSS or Atom document into [{title, link, summary}]."""
    items: List[Dict[str, str]] = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return items

    # RSS: channel/item ; Atom: feed/entry. Handle both by local tag names.
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        title = link = summary = ""
        for child in el:
            name = _local(child.tag)
            if name == "title" and child.text:
                title = child.text.strip()
            elif name == "link":
                # RSS: text; Atom: href attribute
                href = child.get("href")
                if href:
                    link = href
                elif child.text:
                    link = child.text.strip()
            elif name in ("description", "summary", "content") and not summary:
                summary = _strip_html(child.text or "")
        if title and link:
            items.append({"title": title, "link": link, "summary": summary})
        if len(items) >= MAX_ARTICLES_PER_FEED:
            break
    return items


def _content_hash(title: str, link: str) -> str:
    return hashlib.sha256(f"{title}|{link}".encode("utf-8", "ignore")).hexdigest()


def _already_stored(cur, url: str, content_hash: str) -> bool:
    cur.execute(
        "SELECT 1 FROM news_articles WHERE url = %s OR content_hash = %s LIMIT 1",
        (url, content_hash),
    )
    return cur.fetchone() is not None


def get_last_update() -> Optional[datetime]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM app_meta WHERE key = %s", (_LAST_UPDATE_KEY,))
            row = cur.fetchone()
    if not row or not row[0]:
        return None
    try:
        return datetime.fromisoformat(row[0])
    except Exception:
        return None


def _set_last_update(ts: datetime) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_meta (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                """,
                (_LAST_UPDATE_KEY, ts.isoformat()),
            )


def is_update_due() -> bool:
    last = get_last_update()
    if last is None:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last > timedelta(days=UPDATE_INTERVAL_DAYS)


def run_news_update(*, force: bool = False) -> Dict[str, Any]:
    """Fetch → curate → store. Returns a small summary dict."""
    if not force and not is_update_due():
        logger.info("[news] update not due — skipping")
        return {"status": "skipped", "stored": 0}

    from agents.news_curator_agent import curate_article

    stored = 0
    processed = 0
    for source, feed_url in NEWS_FEEDS:
        try:
            resp = requests.get(feed_url, timeout=20, headers={"User-Agent": "pentest-ai-news/1.0"})
            resp.raise_for_status()
            items = _parse_feed(resp.content)
        except Exception as exc:
            logger.warning("[news] feed failed %s: %s", source, exc)
            continue

        for item in items:
            processed += 1
            url = item["link"]
            chash = _content_hash(item["title"], url)
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        if _already_stored(cur, url, chash):
                            continue
            except Exception as exc:
                logger.warning("[news] dedupe check failed: %s", exc)
                continue

            curated = curate_article(
                raw_title=item["title"], raw_body=item["summary"], source=source,
            )
            if not curated:
                continue  # irrelevant or curator unavailable

            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO news_articles
                                (url, content_hash, title, summary, source,
                                 affected_technologies, published_at)
                            VALUES (%s, %s, %s, %s, %s, %s, now())
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                url, chash, curated["title"], curated["summary"],
                                source, curated["affected_technologies"],
                            ),
                        )
                        if cur.rowcount:
                            stored += 1
            except Exception as exc:
                logger.warning("[news] insert failed: %s", exc)

    _set_last_update(datetime.now(timezone.utc))
    logger.info("[news] update complete — processed %d, stored %d", processed, stored)
    return {"status": "complete", "processed": processed, "stored": stored}
