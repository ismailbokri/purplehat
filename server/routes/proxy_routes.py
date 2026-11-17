"""In-app browser reverse proxy.

The BrowserExplorer embeds the target in an <iframe>. Many real apps (Juice Shop,
for one) send `X-Frame-Options: SAMEORIGIN` or a frame-blocking CSP, which makes
the browser refuse to render them inside our page. This route fetches the target
server-side and re-serves it from our own origin with those framing restrictions
stripped, so the iframe can display it.

To keep an SPA usable inside the frame, HTML responses are rewritten so that
absolute-path URLs (`/main.js`, `/rest/...`) and the document <base> route back
through this proxy instead of hitting the app's own origin.

Scope: a local, tester-driven pentest tool pointed at authorized targets. The
proxy is session-scoped and requires the session owner's token. It is not a
general open proxy — it only forwards to http/https URLs the tester navigates to.
"""

import json
import re
from typing import Any, Dict
from urllib.parse import quote, urljoin, urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from auth.dependencies import CurrentUser, _load_user
from auth.security import decode_token
from server.sessions_runtime import PENTEST_SESSIONS

router = APIRouter(prefix="/api/sessions", tags=["proxy"])


def _user_from_request(request: Request) -> CurrentUser:
    """Resolve the user from the Authorization header OR a `_jwt`/`token` query
    param. An <iframe src> cannot send headers, so the embedded browser passes
    the JWT in the query string — this route authenticates it the same way.
    """
    token = ""
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if not token:
        token = (request.query_params.get("_jwt")
                 or request.query_params.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Malformed token")
    user = _load_user(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user

# Response headers we must NOT pass through: framing/security headers that would
# re-block the iframe, and hop-by-hop / encoding headers httpx already resolved.
_STRIP_RESP_HEADERS = {
    "x-frame-options",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "content-encoding",      # httpx decodes the body; the header would mislead the client
    "content-length",        # recomputed by Starlette from the (possibly rewritten) body
    "transfer-encoding",
    "connection",
    "keep-alive",
    "strict-transport-security",
}

# Request headers we should not forward verbatim from the browser to the target.
_STRIP_REQ_HEADERS = {
    "host", "connection", "keep-alive", "content-length",
    "accept-encoding",       # let httpx negotiate; we strip content-encoding anyway
    "authorization",         # our JWT is for US, not the target
    "cookie",                # browser cookies are for our origin, not the target
    "referer", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "upgrade-insecure-requests",
}


def _session_or_404(session_id: str, user: CurrentUser) -> Dict[str, Any]:
    sess = PENTEST_SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this session")
    return sess


def _proxy_prefix(session_id: str, token: str) -> str:
    base = f"/api/sessions/{quote(session_id)}/proxy?"
    if token:
        base += f"_jwt={quote(token, safe='')}&"
    return base + "url="


def _wrap(session_id: str, token: str, absolute_url: str) -> str:
    """Return a proxied URL for an absolute target URL."""
    return _proxy_prefix(session_id, token) + quote(absolute_url, safe="")


def _self_origin(request: Request) -> str:
    """Origin the browser uses to reach THIS backend (e.g. http://localhost:8000)."""
    host = (request.headers.get("x-forwarded-host")
            or request.headers.get("host") or request.url.netloc)
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{scheme}://{host}"


def _rewrite_html(body: bytes, base_url: str, session_id: str, token: str, charset: str,
                  self_origin: str = "") -> bytes:
    """Rewrite an HTML document so sub-resources load back through the proxy.

    - Absolute-path refs (src="/x", href="/x") → proxied absolute URL.
    - A <base href> is injected so relative refs resolve against the target,
      then themselves get proxied by the browser's next request (which we also
      wrap because the resolved URL is absolute-path on our origin).

    The proxy links MUST be absolute (`self_origin` + /api/...): a root-relative
    `/api/sessions/...` would be resolved against the injected <base> and hit
    the target (http://localhost:8084/api/... → 404), so CSS/images never load.
    """
    try:
        html = body.decode(charset, errors="replace")
    except LookupError:
        html = body.decode("utf-8", errors="replace")

    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))
    prefix = self_origin + _proxy_prefix(session_id, token)

    # 1) Rewrite root-relative attribute URLs: src="/..", href="/..", action="/.."
    #    (not "//host" protocol-relative, handled separately).
    def repl_rootrel(m: "re.Match[str]") -> str:
        attr, quote_ch, path = m.group(1), m.group(2), m.group(3)
        absolute = origin + "/" + path
        return f'{attr}={quote_ch}{prefix}{quote(absolute, safe="")}{quote_ch}'

    html = re.sub(
        r'\b(src|href|action)\s*=\s*(["\'])/(?!/)([^"\']*)\2',
        repl_rootrel, html, flags=re.IGNORECASE,
    )

    # 2) Rewrite protocol-relative and absolute http(s) URLs in the same attrs.
    def repl_absolute(m: "re.Match[str]") -> str:
        attr, quote_ch, url = m.group(1), m.group(2), m.group(3)
        if url.startswith(prefix):
            return m.group(0)  # already proxied by step 1
        if url.startswith("//"):
            url = urlparse(base_url).scheme + ":" + url
        return f'{attr}={quote_ch}{prefix}{quote(url, safe="")}{quote_ch}'

    html = re.sub(
        r'\b(src|href|action)\s*=\s*(["\'])((?:https?:)?//[^"\']+)\2',
        repl_absolute, html, flags=re.IGNORECASE,
    )

    # 3) Inject a <base> so any remaining relative refs resolve against the
    #    target origin, plus the navigation reporter. Place both after <head>.
    base_tag = f'<base href="{origin}/">' + _nav_reporter_script(base_url)
    if re.search(r"<head[^>]*>", html, flags=re.IGNORECASE):
        html = re.sub(r"(<head[^>]*>)", lambda m: m.group(1) + base_tag, html,
                      count=1, flags=re.IGNORECASE)
    else:
        html = base_tag + html

    return html.encode(charset, errors="replace") if _safe_charset(charset) else html.encode("utf-8", errors="replace")


_NAV_MSG_TYPE = "pentest-proxy-nav"


def _nav_reporter_script(page_url: str) -> str:
    """Script that tells the parent BrowserExplorer which REAL target URL is shown.

    The iframe's own location is the proxy URL on another origin, which the
    parent page cannot read. So each proxied page posts its target URL on load,
    and again on SPA route changes (hash routes, pushState/replaceState, which
    resolve against the injected <base>, i.e. the target origin).
    """
    page = json.dumps(page_url.split("#", 1)[0]).replace("</", "<\\/")
    msg_type = json.dumps(_NAV_MSG_TYPE)
    return (
        "<script>(function(){"
        f"var PAGE={page},T={msg_type};"
        "function send(u){try{parent.postMessage({type:T,url:u},'*');}catch(e){}}"
        "function cur(){return PAGE+(location.hash||'');}"
        "send(cur());"
        "addEventListener('hashchange',function(){send(cur());});"
        "['pushState','replaceState'].forEach(function(k){var o=history[k];"
        "if(!o)return;history[k]=function(s,t,u){var r=o.apply(this,arguments);"
        "if(u!=null){try{send(new URL(u,document.baseURI).href);}catch(e){}}return r;};});"
        "})();</script>"
    )


def _safe_charset(charset: str) -> bool:
    try:
        "".encode(charset)
        return True
    except LookupError:
        return False


@router.api_route("/{session_id}/proxy", methods=["GET", "POST"])
async def proxy(
    session_id: str,
    url: str,
    request: Request,
) -> Response:
    user = _user_from_request(request)
    _session_or_404(session_id, user)

    # The token that got us here is reused to keep sub-resource requests (assets,
    # XHR, redirects) authenticated as the browser follows the rewritten links.
    token = (request.query_params.get("_jwt")
             or request.query_params.get("token") or "")
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()

    target = url.strip()
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Only absolute http(s) URLs can be proxied.")

    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _STRIP_REQ_HEADERS
    }

    body = await request.body() if request.method == "POST" else None

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=20.0, verify=False) as client:
            upstream = await client.request(
                request.method, target, headers=fwd_headers, content=body,
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Proxy fetch failed: {exc}")

    content_type = upstream.headers.get("content-type", "")
    out_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _STRIP_RESP_HEADERS
    }

    # Keep redirects inside the proxy: rewrite Location to a proxied URL.
    if "location" in {k.lower() for k in upstream.headers}:
        loc = upstream.headers.get("location", "")
        if loc:
            absolute = urljoin(target, loc)
            out_headers["location"] = _wrap(session_id, token, absolute)

    payload = upstream.content
    if "text/html" in content_type.lower():
        charset = "utf-8"
        m = re.search(r"charset=([\w-]+)", content_type, flags=re.IGNORECASE)
        if m:
            charset = m.group(1)
        payload = _rewrite_html(payload, target, session_id, token, charset,
                                self_origin=_self_origin(request))

    return Response(
        content=payload,
        status_code=upstream.status_code,
        headers=out_headers,
        media_type=content_type or None,
    )
