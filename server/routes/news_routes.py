"""Cybersecurity news intelligence routes.

GET /api/news            — list curated articles (public to authenticated users).
POST /api/news/refresh   — admin-only manual trigger of the fetch/curate job.

The response exposes only curated content — no AI traces, no confidence scores.
"""

import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from psycopg2.extras import DictCursor

from auth.dependencies import CurrentUser, get_current_user
from db.connection import get_conn

router = APIRouter(prefix="/api/news", tags=["news"])


@router.get("")
def list_news(
    limit: int = 50,
    user: CurrentUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(
                """
                SELECT title, summary, source, url, affected_technologies, published_at
                  FROM news_articles
                 ORDER BY published_at DESC NULLS LAST, id DESC
                 LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [
        {
            "title": r["title"],
            "summary": r["summary"],
            "source": r["source"],
            "url": r["url"],
            "affected_technologies": list(r["affected_technologies"] or []),
            "published_at": r["published_at"],
        }
        for r in rows
    ]


@router.post("/refresh")
def refresh_news(user: CurrentUser = Depends(get_current_user)) -> Dict[str, str]:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    def _job():
        try:
            from news.fetcher import run_news_update
            run_news_update(force=True)
        except Exception:
            pass

    threading.Thread(target=_job, daemon=True).start()
    return {"status": "started"}
