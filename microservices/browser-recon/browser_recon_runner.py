#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# ─── Configuration ────────────────────────────────────────────────────────────

TARGET_URL   = os.environ.get("TARGET_URL", "").strip()
RUN_ID       = os.environ.get("RUN_ID", f"slime_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
API_KEY_pfe = os.environ.get("API_KEY_pfe", "").strip()
MAX_ITER     = int(os.environ.get("MAX_ITERATIONS", "8"))
OUTPUT_DIR   = pathlib.Path(os.environ.get("OUTPUT_DIR", "/app/runs/slime"))
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
BROWSER_AGENT_MODE = os.environ.get("BROWSER_AGENT_MODE", "recon").strip().lower() or "recon"
LOGIN_USERNAME = os.environ.get("LOGIN_USERNAME", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
try:
    AUTH_COOKIES: dict = json.loads(os.environ.get("AUTH_COOKIES_JSON", "{}"))
    if not isinstance(AUTH_COOKIES, dict):
        AUTH_COOKIES = {}
except Exception:
    AUTH_COOKIES = {}
try:
    BROWSER_TASK_PROMPTS = json.loads(os.environ.get("BROWSER_TASK_PROMPTS_JSON", "[]"))
    if not isinstance(BROWSER_TASK_PROMPTS, list):
        BROWSER_TASK_PROMPTS = []
except Exception:
    BROWSER_TASK_PROMPTS = []

# When True: auth is out of scope — cookies/credentials are pre-injected, recon skips all auth logic
AUTH_OUT_OF_SCOPE = os.environ.get("AUTH_OUT_OF_SCOPE", "false").lower() == "true"

# ─── Groq client ──────────────────────────────────────────────────────────────

_groq = None
if BROWSER_AGENT_MODE != "auth_only":
    try:
        from groq import Groq
    except ImportError:
        print("[RUNNER] groq package not installed", file=sys.stderr)
        sys.exit(1)
    if not API_KEY_pfe:
        print("[RUNNER] API_KEY_pfe env var is required", file=sys.stderr)
        sys.exit(1)
    _groq = Groq(api_key=API_KEY_pfe)


# ─── Strict JSON schema enforcement (mirrors functions.py call_llm_prep) ─────

def _groq_response_format(schema_dict: Dict[str, Any]) -> Dict[str, Any]:
    inner = schema_dict.get("schema") or schema_dict.get("input_schema")
    if not inner:
        raise ValueError(f"Schema for '{schema_dict.get('name')}' missing 'schema' key")
    return {
        "type": "json_schema",
        "json_schema": {
            "name":   schema_dict["name"],
            "strict": True,
            "schema": inner,
        },
    }


def _is_schema_error(error_str: str) -> bool:
    s = error_str.lower()
    return "400" in s or "json_validate_failed" in s or "invalid_request_error" in s


def _call_groq(
    prompt: str,
    system: str,
    response_format: Optional[Dict[str, Any]] = None,
    temperature: float = 0.1,
) -> str:
    kwargs: Dict[str, Any] = {
        "model":       GROQ_MODEL,
        "messages":    [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "temperature": temperature,
    }
    if response_format:
        kwargs["response_format"] = response_format

    last_exc = None
    for attempt in range(1, 3):
        try:
            resp = _groq.chat.completions.create(**kwargs)
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:
            last_exc = exc
            err = str(exc)
            if response_format and _is_schema_error(err):
                # Schema rejected by provider — drop format and retry with plain prompt
                print(f"[GROQ] Strict schema rejected (attempt {attempt}) — retrying without response_format", file=sys.stderr)
                kwargs.pop("response_format", None)
                response_format = None
                continue
            print(f"[GROQ] {exc}", file=sys.stderr)
            return "{}"

    print(f"[GROQ] All attempts failed: {last_exc}", file=sys.stderr)
    return "{}"



# ─── Prompt definitions ───────────────────────────────────────────────────────

# ── Default recon subprompt ───────────────────────────────────────────────────
# Reproduces the current generic recon behaviour exactly.
# Used when no router-generated subprompt is available (first pipeline pass).
if AUTH_OUT_OF_SCOPE:
    DEFAULT_RECON_SUBPROMPT = (
        "RECON OBJECTIVE: Maximum attack surface discovery — you are already authenticated.\n"
        "Focus exclusively on endpoint exploration and attack surface mapping.\n"
        "Priority order: POST forms, admin/management panels, authenticated-only routes, "
        "upload forms, API-triggering buttons, navigation links.\n"
        "CRITICAL: NEVER attempt authentication. If you land on a login page, "
        "navigate IMMEDIATELY to the first entry in unvisited_routes.\n"
        "Do NOT repeat any action already recorded in recent_tested.\n"
        "Record every discovered route and form schema in your decision trace."
    )
else:
    DEFAULT_RECON_SUBPROMPT = (
        "RECON OBJECTIVE: Maximum attack surface discovery.\n"
        "Explore all accessible routes, forms, and authenticated areas.\n"
        "Priority order: POST forms, admin/management panels, authenticated-only routes, "
        "upload forms, API-triggering buttons, navigation links.\n"
        f"Authentication: attempt login with username={LOGIN_USERNAME}, password={LOGIN_PASSWORD} "
        "when a login form is present.\n"
        "Do NOT repeat any action already recorded in recent_tested.\n"
        "Record every discovered route and form schema in your decision trace."
    )

_DEFAULT_REASON_SYSTEM = (
    "You are a strategic web security reconnaissance agent. "
    "Your mission is maximum attack surface discovery. "
    "Follow the decision rules exactly and in order. "
    "Return only valid JSON. No markdown fences, no prose."
)

_DEFAULT_REASON_TEMPLATE = """\
You are a strategic web security reconnaissance agent. Maximize attack surface discovery.

## SESSION CONTEXT
Current URL: {current_url}
Current path: {current_path}
Scope host: {scope_host}
Iteration: {iteration}/{max_iterations}
Authenticated: {is_authenticated}

## EXPLORATION MEMORY
Session-wide recent actions (ALL pages, newest first): {session_recent_actions}
Discovered routes: {discovered_routes}
Visited URLs (do NOT navigate back to any of these via static links): {visited_urls}
Path visit counts (path → times): {path_visit_counts}
Recent interactions on THIS page (last 12): {recent_tested}
Failed interactions (never repeat): {recent_failures}
Unvisited routes ready for exploration: {unvisited_routes}

## CURRENT PAGE
{aria_snapshot}

## DECISION RULES — apply in order, stop at first match

RULE 1 — PAGE EXHAUSTION (check first, highest priority):
Count outcomes in recent_tested that end with "→ already_tested", "→ erroneous", or "→ impossible".
If 3 or more such outcomes exist for the current URL:
  → Return a navigation action to the FIRST entry in unvisited_routes.
  → If unvisited_routes is empty, navigate to a known unexplored path from discovered_routes.
  → Do NOT attempt any other interaction on the current page.

RULE 2 — PATH REPETITION:
If path_visit_counts shows the current path has been visited 2 or more times AND Authenticated=true:
  → Navigate to the first unvisited route.
  → Do NOT stay on this path.
If Authenticated=false and a login form is present: ignore path repetition and apply RULE 5 first.

RULE 3 — NO-REPEAT POLICY (mandatory):
NEVER return an action that exactly matches any entry in recent_tested.
If every visible action is already in recent_tested:
  → Navigate to the first unvisited route from unvisited_routes.

RULE 4 — URL NAVIGATION RESTRICTION:
NEVER click a link whose target is already in visited_urls.
NEVER click links whose accessible name is a full URL with query parameters (injection artifacts).

RULE 5 — AUTHENTICATION DETECTION AND STRATEGY (highest priority when unauthenticated):
Check the "Authenticated" flag above first.
If Authenticated=false and a login form is visible in the aria snapshot:
  → You MUST submit credentials NOW using the EXACT multi-step actions array below.
  → NEVER return a single click on the submit button without the preceding fill steps.
  → Use the exact field names from the aria snapshot (e.g. "Username", "Password", "Login").
  → REQUIRED actions array structure for login:
    [
      {{"target_role": "textbox", "target_name": "<username field name>", "action": "fill", "fill_value": "{login_username}"}},
      {{"target_role": "textbox", "target_name": "<password field name>", "action": "fill", "fill_value": "{login_password}"}},
      {{"target_role": "button",  "target_name": "<submit button name>",  "action": "click", "fill_value": null}}
    ]
  → If session_recent_actions already shows a failed login attempt with {login_username}/{login_password},
    stop retrying and navigate to the next unvisited route.
If Authenticated=true: look for "Logout", "Log Out", or "Sign Out" in the page.

RULE 6 — EXPLORATION PRIORITY ORDER (when no rule above triggers):
Select from these in order of preference:
  1. POST forms not yet tested: login, register, search, data submission (gravity 8-10)
  2. Navigation to authenticated-only routes (dashboard, admin, profile) (gravity 7-9)
  3. Admin or management panels (gravity 8-10)
  4. Upload forms or file input fields (gravity 7-9)
  5. API-triggering buttons: delete, update, publish, save (gravity 6-8)
  6. Navigation links to entries in unvisited_routes (gravity 4-6)
  7. Static informational links (gravity 1-3) — only if nothing else available

RULE 7 — FORM COMPLETION:
For all form interactions: include ALL fill steps before the submit action.
Use exact element names from the aria snapshot. For unlabeled textboxes, use target_name="".
Gravity rubric: 8-10 for auth/admin/upload forms; 4-7 for navigation; 1-3 for static.

Return exactly one JSON object.

{{
    "page_context": "auth state (logged_in/not_logged_in) + key page observation",
    "decision_trace": [
        "rule applied: RULE N — reason",
        "exhaustion check: N already_tested/erroneous/impossible outcomes on this URL",
        "selected action justification"
    ],
    "identified_attack_surface": [
        "concise testable surface hypothesis"
    ],
    "actions": [
        {{"target_role": "button|link|menuitem|textbox|combobox", "target_name": "exact name", "action": "click|fill|select", "fill_value": null}}
    ],
    "target_role": "button|link|menuitem|textbox|combobox",
    "target_name": "exact name from snapshot",
    "action": "click|fill|select",
    "fill_value": null,
    "gravity_score": 5,
    "reasoning": "which rule triggered + why this maximizes attack surface discovery",
    "expected_observable": "specific measurable effect"
}}\
"""

_DEFAULT_EVAL_SYSTEM = (
    "You are a security yield evaluation judge. "
    "Return only valid JSON. No markdown fences, no prose."
)

_DEFAULT_EVAL_TEMPLATE = """\
You are the Yield and Vulnerability Evaluation Judge.
Evaluate the latest action outcome and return strict JSON only.

Action taken: {action_taken}
URL transition: {url_transition}
Network requests generated: {network_requests}
Browser errors: {errors}
Already known routes: {known_routes}

Page content after action (text extracted from body, max 1500 chars):
{page_content_after}

Yield rubric (choose exactly one):
- impossible: action did not execute (not visible, intercept, timeout, invalid locator)
- erroneous: action executed but produced no meaningful backend signal
- tested_low_priority: action succeeded but only known superficial behavior
- tested_high_value: action produced backend-relevant novelty (new route, state transition, write method, new form surface)

Vulnerability signals to detect in page content above:
- sql_injection: multiple rows of user/email data, DB version string (e.g. "5.x-MariaDB"), "root@localhost", UNION result sets
- command_injection: OS file content ("root:x:0:0:", "/bin/bash"), command output ("uid=", "groups=", kernel version)
- xss_reflected: injected script/tag payload appearing unescaped in page content
- auth_bypass: dashboard/profile/logout UI appearing after weak credential submission
- information_disclosure: stack traces, internal file paths, PHP/Apache version, DB connection strings

Set vulnerability_found=true and populate vulnerability_signals if ANY of the above are present in page content.

Return:
{{
  "yield_classification": "impossible|erroneous|tested_low_priority|tested_high_value",
  "yield_rationale": "short factual rationale",
  "novel_routes_discovered": ["/new/route"],
  "vulnerability_signals": [
    {{
      "finding_type": "string",
      "severity": "low|medium|high|critical",
      "evidence_snippet": "short quote",
      "detection_regex": "regex"
    }}
  ],
  "vulnerability_found": false
}}\
"""

_RULE5_OUT_OF_SCOPE = (
    "RULE 5 — AUTHENTICATION IS OUT OF SCOPE:\n"
    "You are pre-authenticated. NEVER fill credentials, submit login forms, or interact with auth pages.\n"
    "If the current page is a login or authentication page: navigate IMMEDIATELY to the first\n"
    "entry in unvisited_routes. Do NOT stay on or interact with any login/register page."
)

_SYSTEM_REASON = _DEFAULT_REASON_SYSTEM
if AUTH_OUT_OF_SCOPE:
    _rule5_start = _DEFAULT_REASON_TEMPLATE.index("RULE 5 —")
    _rule5_end   = _DEFAULT_REASON_TEMPLATE.index("RULE 6 —")
    _REASON_TEMPLATE = (
        _DEFAULT_REASON_TEMPLATE[:_rule5_start]
        + _RULE5_OUT_OF_SCOPE + "\n\n"
        + _DEFAULT_REASON_TEMPLATE[_rule5_end:]
    )
else:
    _REASON_TEMPLATE = _DEFAULT_REASON_TEMPLATE
_SYSTEM_EVAL           = _DEFAULT_EVAL_SYSTEM
_EVAL_TEMPLATE         = _DEFAULT_EVAL_TEMPLATE
_REASON_RESPONSE_FORMAT: Optional[Dict[str, Any]] = None
_EVAL_RESPONSE_FORMAT:   Optional[Dict[str, Any]] = None


# ─── Prompt builders ──────────────────────────────────────────────────────────

def _build_reason_prompt(
    *,
    current_url: str,
    aria_snapshot: str,
    scope_host: str,
    discovered_routes: List[str],
    recent_tested: List[str],
    recent_failures: List[Dict[str, Any]],
    visited_urls: List[str],
    path_visit_counts: Dict[str, int],
    unvisited_routes: List[str],
    iteration: int,
    max_iterations: int,
    is_authenticated: bool = False,
    session_recent_actions: List[str] = None,
) -> str:
    current_path = urlparse(current_url).path or "/"
    base_prompt = _REASON_TEMPLATE.format(
        current_url            = current_url,
        current_path           = current_path,
        scope_host             = scope_host,
        iteration              = iteration,
        max_iterations         = max_iterations,
        is_authenticated       = is_authenticated,
        session_recent_actions = json.dumps((session_recent_actions or [])[:10], ensure_ascii=True),
        discovered_routes      = json.dumps(discovered_routes[-25:], ensure_ascii=True),
        visited_urls           = json.dumps(visited_urls[-20:], ensure_ascii=True),
        path_visit_counts      = json.dumps(path_visit_counts, ensure_ascii=True),
        unvisited_routes       = json.dumps(unvisited_routes[:10], ensure_ascii=True),
        recent_tested          = json.dumps(recent_tested, ensure_ascii=True),
        recent_failures        = json.dumps(recent_failures, ensure_ascii=True),
        aria_snapshot          = aria_snapshot[:3500],
        login_username         = LOGIN_USERNAME,
        login_password         = LOGIN_PASSWORD,
    )

    if BROWSER_AGENT_MODE == "task_execution" and BROWSER_TASK_PROMPTS:
        # task_execution mode: inject task block as a HEADER (same pattern as recon mode)
        # so the LLM reads the objective BEFORE the decision rules, not after.
        # Authentication is explicitly flagged as a prerequisite so the LLM does not
        # misinterpret "test BAC on /login.php" as "bypass auth on /login.php".
        task_block = "\n".join(f"  - {str(task).strip()}" for task in BROWSER_TASK_PROMPTS if str(task).strip())
        header = (
            "## STRATEGIC TASK DIRECTIVES\n"
            f"{task_block}\n\n"
            "EXECUTION ORDER:\n"
            "  1. Authenticate first (RULE 5 — fill username + password, then click submit).\n"
            "  2. Navigate to the target endpoints listed in the directives above.\n"
            "  3. Interact with all relevant forms and parameters to test the objective.\n"
            "  4. Record findings in your decision trace.\n"
            "IMPORTANT: Do NOT attempt task objectives on the login page. "
            "Authenticate FIRST, then execute the directives.\n"
        )
        base_prompt = (
            header
            + "\n## DETAILED SESSION CONTEXT AND DECISION RULES\n"
            + base_prompt
        )
    elif BROWSER_AGENT_MODE == "recon" and BROWSER_TASK_PROMPTS:
        # recon mode: inject router-generated subprompt as a strategic header.
        # Falls back to DEFAULT_RECON_SUBPROMPT when BROWSER_TASK_PROMPTS is empty.
        subprompt = str(BROWSER_TASK_PROMPTS[0]).strip() or DEFAULT_RECON_SUBPROMPT
        base_prompt = (
            f"## STRATEGIC RECON DIRECTIVE\n{subprompt}\n\n"
            f"## DETAILED SESSION CONTEXT AND DECISION RULES\n{base_prompt}"
        )
    else:
        # First-pass fallback: no subprompt from the router yet — use the default.
        base_prompt = (
            f"## STRATEGIC RECON DIRECTIVE\n{DEFAULT_RECON_SUBPROMPT}\n\n"
            f"## DETAILED SESSION CONTEXT AND DECISION RULES\n{base_prompt}"
        )

    return base_prompt


def _build_eval_prompt(
    *,
    action_taken: Dict[str, Any],
    url_before: str,
    url_after: str,
    url_changed: bool,
    network_requests: List[Dict[str, Any]],
    errors: List[str],
    known_routes: List[str],
    page_content_after: str = "",
) -> str:
    return _EVAL_TEMPLATE.format(
        action_taken       = json.dumps(action_taken, ensure_ascii=True),
        url_transition     = json.dumps({"before": url_before, "after": url_after, "changed": url_changed}, ensure_ascii=True),
        network_requests   = json.dumps(network_requests[:10], ensure_ascii=True),
        errors             = json.dumps(errors[:6], ensure_ascii=True),
        known_routes       = json.dumps(known_routes[:20], ensure_ascii=True),
        page_content_after = page_content_after[:1500],
    )


# ─── Pipeline logger ──────────────────────────────────────────────────────────

class PipelineLogger:
    def __init__(self, run_dir: pathlib.Path) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        self.path = run_dir / "pipeline.jsonl"

    def log(self, event: str, payload: Dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "run_id": RUN_ID,
            "event": event,
            "payload": payload,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")


# ─── Per-target SQLite memory ─────────────────────────────────────────────────

class ExplorationMemory:
    """Lightweight SQLite store — avoids retesting identical (url, role, name, action) tuples."""

    def __init__(self, db_path: pathlib.Path) -> None:
        self._db = str(db_path)
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS interactions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    url         TEXT NOT NULL,
                    target_role TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    outcome     TEXT NOT NULL DEFAULT 'unknown',
                    created_at  TEXT NOT NULL
                )
            """)
            conn.commit()

    def was_tested(self, url: str, role: str, name: str, action: str) -> bool:
        with sqlite3.connect(self._db) as conn:
            row = conn.execute(
                "SELECT 1 FROM interactions WHERE url=? AND target_role=? AND target_name=? AND action=? LIMIT 1",
                (url, role.lower(), name, action.lower()),
            ).fetchone()
        return row is not None

    def record(self, url: str, role: str, name: str, action: str, outcome: str) -> None:
        with sqlite3.connect(self._db) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO interactions (url,target_role,target_name,action,outcome,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (url, role.lower(), name, action.lower(), outcome,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            conn.commit()

    def recent_failures(self, url: str, limit: int = 12) -> List[Dict[str, Any]]:
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT target_role,target_name,action,outcome FROM interactions "
                "WHERE url=? AND outcome IN ('impossible','erroneous') ORDER BY id DESC LIMIT ?",
                (url, limit),
            ).fetchall()
        return [{"target_role": r, "target_name": n, "action": a, "outcome": o} for r, n, a, o in rows]

    def recent_tested(self, url: str, limit: int = 12) -> List[str]:
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT target_role,target_name,action,outcome FROM interactions "
                "WHERE url=? ORDER BY id DESC LIMIT ?",
                (url, limit),
            ).fetchall()
        return [f"{a} {r} '{n}' → {o}" for r, n, a, o in rows]

    def recent_session_actions(self, limit: int = 20) -> List[str]:
        """Return the last N actions across ALL URLs in this session (session-level history)."""
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT url,target_role,target_name,action,outcome FROM interactions "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [f"{a} {r} '{n}' on {url} → {o}" for url, r, n, a, o in rows]


# ─── Network helpers ──────────────────────────────────────────────────────────

_STATIC_SUFFIXES = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
)


def _is_static(route: str) -> bool:
    r = route.lower().split("?")[0]
    return r.endswith(_STATIC_SUFFIXES) or "/static/" in r or "/assets/" in r


def _normalize_route(url: str) -> str:
    try:
        path = urlparse(url).path or "/"
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        return path
    except Exception:
        return "/"


def _parse_post_data(raw: str) -> Dict[str, str]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {k: str(v) for k, v in list(parsed.items())[:16]}
    except Exception:
        pass
    try:
        pairs = parse_qs(raw, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in list(pairs.items())[:16]}
    except Exception:
        return {}


# ─── Live frame emission (host UI replay channel) ──────────────────────────────
# Each frame is a single JSON line on stderr, prefixed with `[FRAME]`. The host
# wrapper (tools/browser_explore_tool.py:_stream_container) parses these lines
# and forwards them to the frontend WebSocket as `browser_frame` events.

def _capture_screenshot_b64(page) -> str:
    """Return a base64 JPEG (1024×640 viewport clip) or '' on failure.

    Clipping rather than full-page screenshot keeps the payload ~30–60 KB
    per frame at quality 55, well within WS budget for live streaming.
    """
    try:
        raw = page.screenshot(
            type="jpeg",
            quality=55,
            full_page=False,
            clip={"x": 0, "y": 0, "width": 1024, "height": 640},
        )
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        # If clip exceeds the rendered area (small viewport / mobile-like layouts)
        # fall back to a plain viewport screenshot.
        try:
            raw = page.screenshot(type="jpeg", quality=50, full_page=False)
            return base64.b64encode(raw).decode("ascii")
        except Exception:
            return ""


def _emit_frame(
    page,
    *,
    iteration: int,
    max_iterations: int,
    action: str,
    target_role: str = "",
    target_name: str = "",
    outcome: str = "",
    url_before: str = "",
    url_after: str = "",
    network_count: int = 0,
    error_count: int = 0,
    note: str = "",
) -> None:
    """Emit a single replay frame for the host UI. Non-fatal on any error."""
    try:
        screenshot_b64 = _capture_screenshot_b64(page) if page is not None else ""
        payload = {
            "ts":             datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "iter":           iteration,
            "max_iter":       max_iterations,
            "action":         action,
            "target_role":    target_role,
            "target_name":    target_name[:80],
            "outcome":        outcome,
            "url_before":     url_before[:240],
            "url_after":      url_after[:240],
            "url_changed":    bool(url_before and url_after and url_before != url_after),
            "network_count":  int(network_count),
            "error_count":    int(error_count),
            "note":           note[:160],
            "screenshot_b64": screenshot_b64,
        }
        # Single line, no embedded newlines (base64 has none either).
        sys.stderr.write("[FRAME]" + json.dumps(payload, ensure_ascii=True) + "\n")
        sys.stderr.flush()
    except Exception as exc:
        # Never let frame emission interrupt the recon loop.
        print(f"[RUNNER] frame emission failed: {exc}", file=sys.stderr)


# ─── Error label helpers ───────────────────────────────────────────────────────

def _error_label(error_text: str) -> str:
    t = error_text.lower()
    if "timeout" in t and "click" in t:
        return "timeout_click"
    if "timeout" in t and "fill" in t:
        return "timeout_fill"
    if "timeout" in t:
        return "timeout_action"
    if "not visible" in t or "not_visible" in t:
        return "not_visible"
    if "strict mode" in t or "selector_ambiguous" in t:
        return "selector_ambiguous"
    if "target closed" in t:
        return "target_closed"
    return "action_error"


# ─── Runtime route discovery (robots.txt, sitemap.xml, SPA JS introspection) ──

def _bootstrap_route_discovery(ctx, target_url: str, scope_host: str) -> List[str]:
    """Pull candidate routes from runtime sources only — no hardcoded path lists.

    Sources, in order:
      1. /robots.txt — extract Allow/Disallow paths.
      2. /sitemap.xml — extract <loc> URLs (same host only).
      3. Any link/<a href> already rendered in the loaded page is handled separately
         by the LLM iteration loop.

    Returns a deduplicated list of paths (each starts with '/').
    """
    routes: List[str] = []
    seen: set = set()

    def _add(path_or_url: str) -> None:
        if not path_or_url:
            return
        s = path_or_url.strip()
        if s.startswith(("http://", "https://")):
            try:
                pu = urlparse(s)
                if pu.netloc and pu.netloc != scope_host:
                    return
                s = pu.path or "/"
            except Exception:
                return
        if not s.startswith("/"):
            s = "/" + s
        if s not in seen:
            seen.add(s)
            routes.append(s)

    base = f"{urlparse(target_url).scheme}://{scope_host}"
    try:
        req = ctx.request
    except Exception:
        return routes

    try:
        r = req.get(f"{base}/robots.txt", timeout=5_000)
        if r.ok:
            for line in r.text().splitlines():
                m = re.match(r'^\s*(?:Allow|Disallow)\s*:\s*(.+?)\s*$', line, re.IGNORECASE)
                if m:
                    val = m.group(1)
                    if val and val != "*":
                        _add(val)
    except Exception as exc:
        print(f"[RUNNER] robots.txt fetch failed: {exc}", file=sys.stderr)

    try:
        r = req.get(f"{base}/sitemap.xml", timeout=5_000)
        if r.ok:
            for m in re.finditer(r"<loc>\s*(.+?)\s*</loc>", r.text(), re.IGNORECASE):
                _add(m.group(1))
    except Exception as exc:
        print(f"[RUNNER] sitemap.xml fetch failed: {exc}", file=sys.stderr)

    return routes


_SPA_ROUTE_PATTERNS = [
    re.compile(r"""path\s*:\s*['"]([^'"]{1,80})['"]"""),
    re.compile(r"""['"](#/[A-Za-z0-9_\-/]{1,80})['"]"""),
    re.compile(r"""['"]/?([A-Za-z0-9_\-]{2,40}/[A-Za-z0-9_\-/]{0,80})['"]"""),
]


def _extract_spa_routes_from_page(page, scope_host: str) -> List[str]:
    """Inspect loaded JS bundles for SPA route definitions. Returns deduplicated paths."""
    routes: List[str] = []
    seen: set = set()

    def _add(raw: str) -> None:
        s = (raw or "").strip()
        if not s:
            return
        if s.startswith("#"):
            s = s[1:]
        if not s.startswith("/"):
            s = "/" + s
        if any(ch in s for ch in (" ", "<", ">", "{", "}", "?", "=")):
            return
        if len(s) > 80:
            return
        if s not in seen:
            seen.add(s)
            routes.append(s)

    try:
        scripts = page.evaluate(
            "() => Array.from(document.scripts).map(s => s.src).filter(Boolean)"
        ) or []
    except Exception:
        scripts = []

    js_sources: List[str] = []
    try:
        inline_text = page.evaluate(
            "() => Array.from(document.scripts).filter(s => !s.src).map(s => s.textContent).join('\\n')"
        ) or ""
        if inline_text:
            js_sources.append(inline_text[:200_000])
    except Exception:
        pass

    try:
        req = page.context.request
    except Exception:
        req = None

    if req:
        for src in scripts[:8]:
            try:
                pu = urlparse(src)
                if pu.netloc and pu.netloc != scope_host:
                    continue
                r = req.get(src, timeout=5_000)
                if r.ok:
                    body = r.text()
                    if body:
                        js_sources.append(body[:400_000])
            except Exception:
                continue

    blob = "\n".join(js_sources)
    if not blob:
        return routes

    for pat in _SPA_ROUTE_PATTERNS[:2]:
        for m in pat.finditer(blob):
            _add(m.group(1))

    return routes[:60]


def _is_json_response(page) -> bool:
    """Return True if the current page was served with a JSON content type."""
    try:
        ct = page.evaluate("() => document.contentType || ''")
        return isinstance(ct, str) and "json" in ct.lower()
    except Exception:
        return False


# ─── Main exploration loop ────────────────────────────────────────────────────

def run_exploration() -> None:
    if not TARGET_URL:
        print("[RUNNER] TARGET_URL env var is required", file=sys.stderr)
        sys.exit(1)

    run_dir = OUTPUT_DIR / RUN_ID
    logger  = PipelineLogger(run_dir)
    memory  = ExplorationMemory(run_dir / "memory.db")

    scope_host      = urlparse(TARGET_URL).netloc or TARGET_URL
    target_scheme   = urlparse(TARGET_URL).scheme or "http"
    discovered_routes: List[str] = []

    logger.log("run_started", {
        "target_url":     TARGET_URL,
        "scope_host":     scope_host,
        "max_iterations": MAX_ITER,
        "headless":       True,
    })

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[RUNNER] playwright not installed", file=sys.stderr)
        sys.exit(1)

    print(f"[RUNNER] Starting exploration → {TARGET_URL}", file=sys.stderr)
    print(f"[RUNNER] Mode={BROWSER_AGENT_MODE} | Routed tasks={len(BROWSER_TASK_PROMPTS)}", file=sys.stderr)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            ctx  = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()

            # Inject pre-obtained auth cookies before first navigation
            if AUTH_COOKIES:
                from urllib.parse import urlparse as _urlparse
                _domain = _urlparse(TARGET_URL).hostname or ""
                ctx.add_cookies([
                    {"name": k, "value": v, "domain": _domain, "path": "/"}
                    for k, v in AUTH_COOKIES.items()
                ])
                print(f"[RUNNER] Injected {len(AUTH_COOKIES)} pre-auth cookie(s): {', '.join(AUTH_COOKIES)}", file=sys.stderr)

            # Initial navigation
            # Use "commit" so we succeed as soon as HTTP response headers arrive —
            # this avoids timing out when the app JS-redirects to an external Auth0
            # domain before domcontentloaded fires.
            _nav_ok = False
            for _wait_until in ("commit", "domcontentloaded"):
                try:
                    page.goto(TARGET_URL, wait_until=_wait_until, timeout=30_000)
                    print(f"[RUNNER] Loaded ({_wait_until}): {page.url}", file=sys.stderr)
                    _nav_ok = True
                    break
                except Exception as exc:
                    logger.log("navigate_error", {"error": str(exc)[:300], "url": TARGET_URL, "wait_until": _wait_until})
                    print(f"[RUNNER] Navigate error ({_wait_until}): {exc}", file=sys.stderr)
            if not _nav_ok:
                print("[RUNNER] All navigation attempts failed — aborting", file=sys.stderr)
                return

            # Give the SPA (React/Next.js) time to hydrate after the commit navigation.
            # If domcontentloaded already fired the call returns immediately; if a
            # subsequent auth redirect is in flight we cap the wait so we don't hang.
            try:
                page.wait_for_load_state("domcontentloaded", timeout=8_000)
            except Exception:
                pass

            # Bootstrap route discovery — robots.txt, sitemap.xml, and SPA JS introspection.
            # All sources are runtime — no hardcoded path lists.
            try:
                bootstrap_routes = _bootstrap_route_discovery(ctx, TARGET_URL, scope_host)
                if bootstrap_routes:
                    print(
                        f"[RUNNER] Bootstrap discovery: {len(bootstrap_routes)} route(s) "
                        f"from robots.txt/sitemap.xml",
                        file=sys.stderr,
                    )
                    logger.log("bootstrap_discovery", {"source": "robots_sitemap", "routes": bootstrap_routes[:50]})
                    for r in bootstrap_routes:
                        if r not in discovered_routes and not _is_static(r):
                            discovered_routes.append(r)
            except Exception as exc:
                print(f"[RUNNER] Bootstrap discovery failed: {exc}", file=sys.stderr)

            try:
                spa_routes = _extract_spa_routes_from_page(page, scope_host)
                if spa_routes:
                    print(
                        f"[RUNNER] SPA route extraction: {len(spa_routes)} candidate route(s) from JS bundles",
                        file=sys.stderr,
                    )
                    logger.log("bootstrap_discovery", {"source": "spa_js", "routes": spa_routes[:50]})
                    for r in spa_routes:
                        if r not in discovered_routes and not _is_static(r):
                            discovered_routes.append(r)
            except Exception as exc:
                print(f"[RUNNER] SPA route extraction failed: {exc}", file=sys.stderr)

            visited_urls: List[str] = []
            path_visit_counts: Dict[str, int] = {}   # normalized path → visit count
            consecutive_same_path: int = 0
            last_normalized_path: str = ""
            already_tested_per_url: Dict[str, int] = {}  # url → consecutive exhausted-outcome count

            # Auth is handled outside this container (by browser_explore_agent.py preflight).
            # If AUTH_COOKIES were injected above, we start as pre-authenticated immediately.
            is_authenticated: bool = bool(AUTH_COOKIES)

            if AUTH_COOKIES:
                print(f"[RUNNER] {len(AUTH_COOKIES)} session cookie(s) injected — starting as authenticated", file=sys.stderr)

            # Initial frame — shows the loaded landing page before any action.
            _emit_frame(
                page,
                iteration=0,
                max_iterations=MAX_ITER,
                action="initial",
                outcome="loaded",
                url_after=page.url,
                note=f"Bootstrap: {len(discovered_routes)} route(s) discovered",
            )

            for iteration in range(1, MAX_ITER + 1):
                current_url = page.url
                if current_url not in visited_urls:
                    visited_urls.append(current_url)

                # Track normalized path visits (strip query params)
                normalized_path = urlparse(current_url).path or "/"
                path_visit_counts[normalized_path] = path_visit_counts.get(normalized_path, 0) + 1

                if normalized_path == last_normalized_path:
                    consecutive_same_path += 1
                else:
                    consecutive_same_path = 0
                    last_normalized_path = normalized_path

                print(f"[RUNNER] Iter {iteration}/{MAX_ITER} | {current_url}", file=sys.stderr)

                # JSON-page pivot: when the current response is JSON there is no DOM
                # to click — capture it as an API surface and immediately pivot to
                # the next unvisited route rather than wasting iterations on the LLM.
                if _is_json_response(page):
                    try:
                        body = page.evaluate("() => document.body ? document.body.innerText : ''") or ""
                    except Exception:
                        body = ""
                    logger.log("json_response", {
                        "iteration":  iteration,
                        "url":        current_url,
                        "body_size":  len(body),
                        "body_head":  body[:1000],
                    })
                    print(f"[RUNNER] JSON response detected at {current_url} — captured ({len(body)} bytes) and pivoting", file=sys.stderr)
                    visited_path_set = {urlparse(u).path for u in visited_urls}
                    unvisited = [
                        r for r in discovered_routes
                        if r not in visited_path_set and not _is_static(r)
                    ]
                    if unvisited:
                        nav_url = f"{target_scheme}://{scope_host}{unvisited[0]}"
                        try:
                            page.goto(nav_url, wait_until="domcontentloaded", timeout=15_000)
                            consecutive_same_path = 0
                            print(f"[RUNNER] Pivoted to {nav_url}", file=sys.stderr)
                        except Exception as exc:
                            print(f"[RUNNER] JSON pivot navigate failed: {exc}", file=sys.stderr)
                    else:
                        print(f"[RUNNER] No unvisited routes to pivot to — staying", file=sys.stderr)
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action="json_pivot",
                        outcome="navigated",
                        url_before=current_url,
                        url_after=page.url,
                        note="JSON response — pivoted to next route",
                    )
                    continue

                # Hard guard: if the same path keeps appearing, force navigation away.
                if consecutive_same_path >= 2:
                    visited_path_set = {urlparse(u).path for u in visited_urls}
                    unvisited = [
                        r for r in discovered_routes
                        if r not in visited_path_set and not _is_static(r)
                    ]
                    nav_url = (f"{target_scheme}://{scope_host}{unvisited[0]}"
                               if unvisited else TARGET_URL)
                    nav_path = urlparse(nav_url).path or "/"
                    if nav_path == normalized_path:
                        consecutive_same_path = 0
                        print(
                            f"[RUNNER] FORCE NAVIGATE — no new routes yet, resetting counter",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"[RUNNER] FORCE NAVIGATE — path '{normalized_path}' repeated "
                            f"{consecutive_same_path + 1}x → {nav_url}",
                            file=sys.stderr,
                        )
                        try:
                            page.goto(nav_url, wait_until="domcontentloaded", timeout=15_000)
                            after_path = urlparse(page.url).path or "/"
                            if after_path == normalized_path:
                                print(
                                    f"[RUNNER] Force navigate redirect loop detected (→ {page.url}) — staying",
                                    file=sys.stderr,
                                )
                            consecutive_same_path = 0
                        except Exception as exc:
                            print(f"[RUNNER] Force navigate failed: {exc}", file=sys.stderr)
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action="force_navigate",
                        outcome="navigated",
                        url_before=current_url,
                        url_after=page.url,
                        note=f"Path '{normalized_path}' repeated — forced pivot",
                    )
                    continue

                # Per-URL exhaustion guard: too many already_tested/erroneous outcomes → force navigate
                if already_tested_per_url.get(current_url, 0) >= 2:
                    visited_path_set = {urlparse(u).path for u in visited_urls}
                    unvisited = [
                        r for r in discovered_routes
                        if r not in visited_path_set and not _is_static(r)
                    ]
                    nav_url = (f"{target_scheme}://{scope_host}{unvisited[0]}"
                               if unvisited else TARGET_URL)
                    print(
                        f"[RUNNER] EXHAUSTION NAVIGATE — URL '{current_url}' exhausted "
                        f"({already_tested_per_url[current_url]} dead outcomes) → {nav_url}",
                        file=sys.stderr,
                    )
                    already_tested_per_url[current_url] = 0
                    try:
                        page.goto(nav_url, wait_until="domcontentloaded", timeout=15_000)
                        consecutive_same_path = 0
                    except Exception as exc:
                        print(f"[RUNNER] Exhaustion navigate failed: {exc}", file=sys.stderr)
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action="exhaustion_navigate",
                        outcome="navigated",
                        url_before=current_url,
                        url_after=page.url,
                        note="URL exhausted — forced pivot",
                    )
                    continue

                # Wait for the SPA to finish rendering before snapshotting
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5_000)
                except Exception:
                    pass

                # Capture accessibility tree
                try:
                    aria_snapshot = page.aria_snapshot()
                except Exception:
                    try:
                        snapshot_obj = page.accessibility.snapshot()
                        aria_snapshot = json.dumps(snapshot_obj, ensure_ascii=True)[:4000] if snapshot_obj else ""
                    except Exception:
                        aria_snapshot = ""

                if not aria_snapshot:
                    aria_snapshot = f"Page title: {page.title()}"

                # Compute unvisited routes for the prompt
                visited_path_set = {urlparse(u).path for u in visited_urls}
                unvisited_routes = [
                    r for r in discovered_routes
                    if r not in visited_path_set and not _is_static(r)
                ][:12]

                # LLM decision
                reason_prompt = _build_reason_prompt(
                    current_url=current_url,
                    aria_snapshot=aria_snapshot[:3500],
                    scope_host=scope_host,
                    discovered_routes=discovered_routes[-20:],
                    recent_tested=memory.recent_tested(current_url),
                    recent_failures=memory.recent_failures(current_url),
                    visited_urls=visited_urls,
                    path_visit_counts=path_visit_counts,
                    unvisited_routes=unvisited_routes,
                    iteration=iteration,
                    max_iterations=MAX_ITER,
                    is_authenticated=is_authenticated,
                    session_recent_actions=memory.recent_session_actions(10),
                )
                raw_decision = _call_groq(reason_prompt, system=_SYSTEM_REASON, response_format=_REASON_RESPONSE_FORMAT, temperature=0.1)
                try:
                    decision = json.loads(raw_decision)
                except Exception:
                    decision = {}

                if not decision:
                    print(f"[RUNNER] Empty LLM decision at iter {iteration}", file=sys.stderr)
                    continue

                # Normalise decision fields
                gravity     = max(1, min(10, int(decision.get("gravity_score", 3) or 3)))
                target_role = str(decision.get("target_role", "")).strip()
                target_name = str(decision.get("target_name", "")).strip()
                action      = str(decision.get("action", "")).strip().lower()
                fill_value  = decision.get("fill_value")
                action_plan = decision.get("actions", [])
                if not isinstance(action_plan, list) or not action_plan:
                    action_plan = [{
                        "target_role": target_role,
                        "target_name": target_name,
                        "action":      action,
                        "fill_value":  fill_value,
                    }]
                attack_surfaces = [
                    str(s)[:200] for s in decision.get("identified_attack_surface", [])
                    if str(s).strip()
                ][:8]

                logger.log("reason_done", {
                    "iteration": iteration,
                    "decision": {
                        "target_role":             target_role,
                        "target_name":             target_name,
                        "action":                  action,
                        "fill_value":              fill_value,
                        "action_plan":             action_plan[:6],
                        "gravity_score":           gravity,
                        "page_context":            str(decision.get("page_context", ""))[:200],
                        "decision_trace":          [str(t)[:200] for t in decision.get("decision_trace", [])[:3]],
                        "identified_attack_surface": attack_surfaces,
                        "reasoning":               str(decision.get("reasoning", ""))[:300],
                    },
                })

                if not target_role or not target_name or action not in {"click", "fill", "select"}:
                    print(f"[RUNNER] Invalid decision fields — skipping", file=sys.stderr)
                    continue

                # Multi-step form submissions (login attempts, search forms, etc.) must not
                # be blocked by was_tested — the LLM may retry with different fill values
                # (e.g. admin/admin fallback after admin/password fails).
                is_multistep_submission = len(action_plan) > 1 and action == "click"
                if not is_multistep_submission and memory.was_tested(current_url, target_role, target_name, action):
                    print(f"[RUNNER] Already tested: {action} {target_role} '{target_name}' — emitting skip", file=sys.stderr)
                    logger.log("act_done", {
                        "iteration":             iteration,
                        "url_before":            current_url,
                        "url_after":             current_url,
                        "url_changed":           False,
                        "network_request_count": 0,
                        "network_requests":      [],
                        "error_count":           0,
                        "error_labels":          ["already_tested"],
                        "vulnerability_found":   False,
                        "yield_classification":  "erroneous",
                        "discovered_route_signatures": [],
                    })
                    memory.record(current_url, target_role, target_name, action, "already_tested")
                    already_tested_per_url[current_url] = already_tested_per_url.get(current_url, 0) + 1
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action=action,
                        target_role=target_role,
                        target_name=target_name,
                        outcome="already_tested",
                        url_before=current_url,
                        url_after=current_url,
                        note="skipped — interaction already recorded",
                    )
                    continue

                # ── Execute action plan via Playwright ────────────────────────
                url_before          = page.url
                network_requests:   List[Dict[str, Any]] = []
                errors:             List[str]             = []

                def _on_request(req):
                    route = _normalize_route(req.url)
                    if _is_static(route):
                        return
                    post_raw = ""
                    try:
                        post_raw = req.post_data or ""
                    except Exception:
                        pass
                    post_keys = list(_parse_post_data(post_raw).keys())
                    network_requests.append({
                        "method":          req.method.upper(),
                        "url":             req.url[:200],
                        "route":           route,
                        "query_keys":      list(parse_qs(urlparse(req.url).query).keys())[:8],
                        "post_keys":       post_keys[:12],
                        "has_post_data":   bool(post_raw),
                        "post_data_sample": post_raw[:400],
                    })

                page.on("request", _on_request)

                try:
                    completed    = 0
                    last_step    = {}
                    fill_counter: Dict[str, int] = {}

                    for step in action_plan[:6]:
                        s_role  = str(step.get("target_role", "")).strip()
                        s_name  = str(step.get("target_name", "")).strip()
                        s_act   = str(step.get("action",      "")).strip().lower()
                        s_fill  = step.get("fill_value")

                        if not s_role or s_act not in {"click", "fill", "select"}:
                            continue
                        # click/select require a name; fill uses positional fallback for empty names
                        if not s_name and s_act != "fill":
                            continue

                        try:
                            if s_act == "fill" and not s_name:
                                # Positional fallback: nth unlabeled textbox (0-indexed per role)
                                nth = fill_counter.get(s_role, 0)
                                fill_counter[s_role] = nth + 1
                                loc = page.get_by_role(s_role).nth(nth)
                            else:
                                loc = page.get_by_role(s_role, name=s_name).first
                            if s_act == "fill":
                                loc.fill(str(s_fill or ""), timeout=6_000)
                            elif s_act == "select":
                                loc.select_option(str(s_fill or ""), timeout=6_000)
                            else:
                                loc.click(timeout=6_000)
                            try:
                                page.wait_for_load_state("domcontentloaded", timeout=5_000)
                            except Exception:
                                pass
                            completed += 1
                            last_step  = step
                        except Exception as exc:
                            errors.append(str(exc)[:200])
                            break

                    url_after   = page.url
                    url_changed = url_before != url_after

                    # Update authentication state from post-action aria snapshot
                    if not is_authenticated and url_changed:
                        try:
                            post_snap = page.aria_snapshot()
                            if any(t in post_snap.lower() for t in ["logout", "log out", "sign out"]):
                                is_authenticated = True
                                print("[RUNNER] ✓ Authenticated — post-login surface now accessible", file=sys.stderr)
                        except Exception:
                            pass

                    # Capture page body text for vulnerability signal detection
                    try:
                        page_content_after = page.inner_text("body", timeout=3_000)[:1500]
                    except Exception:
                        page_content_after = ""

                    # ── Evaluate yield ────────────────────────────────────────
                    outcome          = "tested_low_priority"
                    vulnerability_found = False
                    novel_routes:    List[str] = []

                    if errors and completed == 0:
                        outcome = "impossible"
                    elif network_requests or url_changed:
                        eval_prompt = _build_eval_prompt(
                            action_taken={
                                "actions":               action_plan[:3],
                                "completed_action_count": completed,
                                "last_action":           last_step,
                            },
                            url_before=url_before,
                            url_after=url_after,
                            url_changed=url_changed,
                            network_requests=network_requests[:10],
                            errors=errors[:5],
                            known_routes=discovered_routes,
                            page_content_after=page_content_after,
                        )
                        eval_raw = _call_groq(eval_prompt, system=_SYSTEM_EVAL, response_format=_EVAL_RESPONSE_FORMAT, temperature=0.05)
                        try:
                            eval_result = json.loads(eval_raw)
                        except Exception:
                            eval_result = {}

                        outcome = eval_result.get("yield_classification", "tested_low_priority") or "tested_low_priority"
                        vulnerability_found = bool(eval_result.get("vulnerability_found", False))
                        novel_routes = [
                            r for r in eval_result.get("novel_routes_discovered", [])
                            if isinstance(r, str)
                        ]

                    # Update discovered routes
                    for req in network_requests:
                        r = req.get("route", "")
                        if r and not _is_static(r) and r not in discovered_routes:
                            discovered_routes.append(r)
                    for r in novel_routes:
                        if r not in discovered_routes:
                            discovered_routes.append(r)

                    error_labels = list({_error_label(e) for e in errors[:4]})

                    logger.log("act_done", {
                        "iteration":              iteration,
                        "url_before":             url_before,
                        "url_after":              url_after,
                        "url_changed":            url_changed,
                        "network_request_count":  len(network_requests),
                        "network_requests":        network_requests[:20],
                        "error_count":            len(errors),
                        "error_labels":           error_labels,
                        "vulnerability_found":    vulnerability_found,
                        "yield_classification":   outcome,
                        "discovered_route_signatures": [
                            f"{r.get('method','?')} {r.get('route','?')}"
                            for r in network_requests[:10]
                        ],
                    })

                    memory.record(current_url, target_role, target_name, action, outcome)
                    print(
                        f"[RUNNER] {action} '{target_name}' → {outcome} "
                        f"| net={len(network_requests)} err={len(errors)}",
                        file=sys.stderr,
                    )
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action=action,
                        target_role=target_role,
                        target_name=target_name,
                        outcome=outcome,
                        url_before=url_before,
                        url_after=url_after,
                        network_count=len(network_requests),
                        error_count=len(errors),
                        note=("vulnerability signal" if vulnerability_found else ""),
                    )

                except Exception as exc:
                    errors.append(str(exc)[:300])
                    logger.log("act_error", {"iteration": iteration, "error": str(exc)[:300]})
                    memory.record(current_url, target_role, target_name, action, "erroneous")
                    print(f"[RUNNER] Action error at iter {iteration}: {exc}", file=sys.stderr)
                    _emit_frame(
                        page,
                        iteration=iteration,
                        max_iterations=MAX_ITER,
                        action=action,
                        target_role=target_role,
                        target_name=target_name,
                        outcome="erroneous",
                        url_before=current_url,
                        url_after=page.url,
                        error_count=len(errors),
                        note=str(exc)[:140],
                    )
                finally:
                    page.remove_listener("request", _on_request)

        finally:
            browser.close()

    logger.log("run_finished", {
        "total_iterations":       MAX_ITER,
        "discovered_routes_count": len(discovered_routes),
        "discovered_routes":       discovered_routes[:50],
    })
    print(f"[RUNNER] Done — {len(discovered_routes)} routes | log: {run_dir / 'pipeline.jsonl'}", file=sys.stderr)

def run_auth_preflight() -> None:
    """
    AUTH_ONLY mode — log in via direct HTTP (no browser), extract session cookies,
    write to auth_cookies.json, exit.

    Uses urllib (built-in) instead of Playwright: no browser timing races, no
    Chromium startup, full control over the POST body.  The CookieJar is shared
    across GET (session init + CSRF harvest) and POST (login submission), which
    mirrors exactly what a real browser does.
    """
    import urllib.request
    import urllib.parse
    import http.cookiejar

    if not TARGET_URL:
        print("[AUTH] TARGET_URL env var is required", file=sys.stderr)
        sys.exit(1)
    if not LOGIN_USERNAME or not LOGIN_PASSWORD:
        print("[AUTH] LOGIN_USERNAME and LOGIN_PASSWORD required", file=sys.stderr)
        sys.exit(1)

    run_dir = OUTPUT_DIR / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    cookies_file = run_dir / "auth_cookies.json"

    print(f"[AUTH] Pre-authenticating → {TARGET_URL}", file=sys.stderr)
    print(f"[AUTH] User: {LOGIN_USERNAME}", file=sys.stderr)

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
    )
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0"),
        ("Accept", "text/html,application/xhtml+xml,*/*;q=0.9"),
        ("Accept-Language", "en-US,en;q=0.9"),
    ]

    auth_success = False
    final_url    = TARGET_URL
    cookies_dict: dict = {}

    try:
        # ── Step 1: GET login page ────────────────────────────────────────────
        # Picks up the session cookie and lets us harvest any CSRF token in the HTML.
        resp         = opener.open(TARGET_URL, timeout=15)
        html_content = resp.read().decode("utf-8", errors="replace")
        login_url    = resp.geturl()   # final URL after any server redirect
        print(f"[AUTH] Loaded: {login_url}", file=sys.stderr)

        # ── Step 2: harvest hidden form fields (CSRF tokens, etc.) ───────────
        hidden_fields: dict = {}
        for m in re.finditer(
            r"<input[^>]+>",
            html_content,
            re.IGNORECASE,
        ):
            tag = m.group(0)
            type_m = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if type_m and type_m.group(1).lower() not in ("hidden",):
                continue
            name_m  = re.search(r'name=["\']([^"\']+)["\']',  tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                hidden_fields[name_m.group(1)] = value_m.group(1) if value_m else ""

        # ── Step 3: POST login ────────────────────────────────────────────────
        # Seed with all hidden fields so CSRF tokens are always included,
        # then overlay credentials and the submit-button marker.
        form_fields: dict = dict(hidden_fields)
        form_fields["username"] = LOGIN_USERNAME
        form_fields["password"] = LOGIN_PASSWORD
        form_fields["Login"]    = "Login"   # DVWA gates on isset($_POST['Login'])

        print(f"[AUTH] POST fields: {list(form_fields.keys())}", file=sys.stderr)

        parsed = urlparse(login_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        req = urllib.request.Request(
            login_url,
            data=urllib.parse.urlencode(form_fields).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer":      login_url,
                "Origin":       origin,
            },
        )
        resp2      = opener.open(req, timeout=15)
        body2      = resp2.read().decode("utf-8", errors="replace")
        final_url  = resp2.geturl()
        final_path = (urlparse(final_url).path or "").lower()
        body_lower = body2.lower()

        auth_success = (
            "login" not in final_path
            or "logout"   in body_lower
            or "log out"  in body_lower
            or "sign out" in body_lower
        )
        cookies_dict = {c.name: c.value for c in jar}

    except Exception as exc:
        print(f"[AUTH] HTTP login error: {exc}", file=sys.stderr)

    print(f"[AUTH] Result: {'SUCCESS' if auth_success else 'FAILED'} → {final_url}", file=sys.stderr)
    print(f"[AUTH] Cookies: {', '.join(cookies_dict.keys()) or '(none)'}", file=sys.stderr)

    with cookies_file.open("w", encoding="utf-8") as fh:
        json.dump({"cookies": cookies_dict, "auth_success": auth_success, "final_url": final_url}, fh)
    print(f"[AUTH] Written → {cookies_file}", file=sys.stderr)


if __name__ == "__main__":
    if BROWSER_AGENT_MODE == "auth_only":
        run_auth_preflight()
    else:
        run_exploration()