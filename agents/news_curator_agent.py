"""News Curator Agent.

Given a raw fetched article (title + summary/body + source), it decides whether
the item is genuinely cybersecurity-relevant and, if so, produces a professional
title, a concise summary, and a list of affected technologies. Irrelevant items
are rejected.

The UI never exposes this agent's operation — only the curated result is shown.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SYSTEM = """You are a cybersecurity news editor. You receive a raw article (title + excerpt + source) and decide whether it is genuinely about cybersecurity — vulnerabilities, CVEs, threats, incidents, attack techniques, security of languages/frameworks/libraries, security patches/releases, or security research.

If it IS relevant, produce:
- a professional, concise title (no clickbait),
- a clear 2-4 sentence summary,
- a list of affected technologies/products (empty if none).

If it is NOT genuinely cybersecurity-related, reject it.

Respond in STRICT JSON only:
{"relevant": true|false, "title": "...", "summary": "...", "affected_technologies": ["..."]}
"""


def _coerce(raw: str) -> Optional[Dict[str, Any]]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        obj = json.loads(text)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    return obj


def curate_article(*, raw_title: str, raw_body: str, source: str) -> Optional[Dict[str, Any]]:
    """Return a curated dict, or None if irrelevant / the LLM is unavailable.

    Curated dict: {title, summary, affected_technologies: [str]}.
    """
    try:
        from functions import call_llm_text
    except Exception as exc:
        logger.warning("news curator: LLM helper unavailable: %s", exc)
        return None

    user = (
        f"Source: {source}\n"
        f"Title: {raw_title}\n"
        f"Excerpt: {(raw_body or '')[:2000]}"
    )
    try:
        raw = call_llm_text([
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": user},
        ])
    except Exception as exc:
        logger.warning("news curator LLM call failed: %s", exc)
        return None

    obj = _coerce(raw)
    if not obj or not obj.get("relevant"):
        return None

    title = str(obj.get("title") or raw_title).strip()
    summary = str(obj.get("summary") or "").strip()
    techs: List[str] = []
    for t in obj.get("affected_technologies") or []:
        s = str(t).strip()
        if s:
            techs.append(s)
    if not title:
        return None
    return {"title": title, "summary": summary, "affected_technologies": techs}
