"""In-memory runtime for the modular /sessions workflow.

One pentest "session" groups many module runs (Découverte, Pré-auth, Post-auth…)
executed against the same target with shared state (discovered endpoints,
auth cookies, custom endpoints, accumulated findings).

The session lives in `PENTEST_SESSIONS` keyed by a UUID. Module runs are
serialized per session (a `threading.Lock` enforces "one run at a time"); each
run gets its own row in `pentest_runs` (tagged with `module_key` and linked to
the session via `pentest_session_id`) so findings keep their existing 1:N
relationship with runs and the legacy /vtest schema is untouched.
"""

import asyncio
import json
import threading
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from db.connection import get_conn


# ── In-memory session store ──────────────────────────────────────────────────

# session_id (UUID str) → dict:
#   id                 : int          # pentest_sessions.id
#   user_id            : int
#   target             : str
#   host_port          : str | None
#   host_base_url      : str | None
#   custom_endpoints   : list[str]
#   auth_payload       : dict         # {username, password, raw_cookies, bearer_token}
#   state              : dict         # cumulative AgentState
#   queue              : asyncio.Queue
#   events             : list[dict]
#   lock               : threading.Lock
#   active_module      : str | None
#   module_runs        : dict[module_key, dict]
#   report_status      : "idle"|"running"|"complete"|"error"
#   last_report_pdf_path: str | None
#   last_report_text_path: str | None
PENTEST_SESSIONS: Dict[str, Dict[str, Any]] = {}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_host_info(target: str):
    """Split a tester-entered target into (host_port, host_base_url).

    `host_base_url` is the EXTERNAL / browser-plane URL: the one Chrome, the
    "Open in tab" link, and the host-side backend proxy must use. When the
    tester enters a Docker compose service name (e.g. http://juice-shop:8082),
    the hostname is rewritten to localhost here so the browser can resolve it —
    the published host port is kept as-is. The raw `target` string is left
    untouched elsewhere so the engine plane can still derive the internal
    service URL (juice-shop:3000). See tools/docker_target_map.py for why the
    two planes must never be collapsed into one value.
    """
    if not target:
        return None, None
    parse_input = target if "://" in target else f"http://{target}"
    parsed = urlparse(parse_input)
    host = parsed.hostname or target
    host_port = str(parsed.port) if parsed.port else None
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    # Rewrite a known compose service name → localhost for the browser plane.
    # Unknown hostnames (a real authorized external target) pass through.
    if host_port:
        from tools.docker_target_map import resolve_external_url
        origin = resolve_external_url(host, int(host_port), scheme)
    else:
        origin = f"{scheme}://{host}"
    # Preserve any path the tester provided (e.g. WebGoat serves its app under
    # /WebGoat — without the path the browser lands on a 404). Query/fragment
    # are kept too so a deep link survives. A bare "/" adds nothing, so drop it.
    path = parsed.path or ""
    if path == "/":
        path = ""
    suffix = path
    if parsed.query:
        suffix += f"?{parsed.query}"
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    host_base_url = origin + suffix
    return host_port, host_base_url


def _parse_raw_cookies(raw: str) -> dict:
    result = {}
    for part in (raw or "").strip().split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _empty_agent_state(target: str, host_port: Optional[str], host_base_url: Optional[str]) -> dict:
    """Return a fresh AgentState scaffold (mirrors _make_initial_state in main.py)."""
    return {
        "target": target,
        "host_port": host_port,
        "host_base_url": host_base_url,
        "internal_port": None,
        "internal_base_url": None,
        "scan_history": [],
        "open_ports": [],
        "services": [],
        "web_technologies": [],
        "technology_scan_url": None,
        "technology_profiles": [],
        "technology_stack": {
            "frontend_frameworks": [], "backend_frameworks": [], "cms": [],
            "javascript_libraries": [], "web_servers": [],
            "authentication_technologies": [], "cdn": [], "waf": [],
            "analytics": [], "databases": [],
        },
        "directories": [],
        "auth_headers": {},
        "auth_cookies": {},
        "auth_base_url": None,
        "session_cookie": None,
        "session_token": None,
        "bearer_token": None,
        "jwt_token": None,
        "api_token": None,
        "username": None,
        "password": None,
        "auth_out_of_scope": False,
        "auth_status": None,
        "auth_attempts": [],
        "auth_log": [],
        "os": None,
        "last_output": "",
        "phase": "Scanning",
        "last_agent": None,
        "vulnerability_focus": [],
        "vulnerabilities_total": 0,
        "vulnerabilities_parsed": 0,
        "processed_vulnerability_types": [],
        "current_exploit_index": 0,
        "current_exploit_type": None,
        "retrieval_complete": False,
        "retrieval_top_k": 3,
        "retrieval_query": [],
        "retrieved_exploits": [],
        "retrieved_exploits_batch": [],
        "review_use_llm": True,
        "reviewed_exploits": [],
        "usable_review_artifacts": [],
        "prepared_exploits": [],
        "execution_results": [],
        "exploitation_status": None,
        "patch_strategy": None,
        "patch_route_reason": None,
        "patch_strategy_override": None,
        "patch_regeneration_count": 0,
        "parsed_exploit_reports": [],
        "report_sections": {},
        "final_report_text_path": None,
        "final_report_pdf_path": None,
        "browser_recon_run_dir": None,
        "browser_recon_run_id": None,
        "browser_recon_complete": False,
        "browser_agent_mode": "recon",
        "browser_task_prompts": [],
        "hit_targets": [],
        "login_endpoints": [],
        "discovered_endpoints": [],
        "endpoint_schemas": {},
        "browser_attack_surfaces": [],
        "prober_plan": [],
        "prober_plan_version": 0,
        "planner_subplans": [],
        "planner_output_markdown": "",
        "checklist_all_tests": [],
        "checklist_all_done": False,
        "checklist_current_test": {},
        "selected_categories": [],
        "probe_cache": {},
        "probe_confirmed_skip_exploit": False,
        "router_decisions": [],
        "router_script_tasks": [],
        "router_browser_tasks": [],
        "router_summary": "",
        "router_version": 0,
        "browser_task_execution_run_dir": None,
        "browser_task_execution_tasks": [],
        "browser_task_execution_report": {},
        "script_task_selection_count": 0,
        "script_execution_enabled": True,
        "browser_recon_subprompt": "",
        "ip_addresses": [],
        "security_findings": [],
        "checklist_tests": [],
        "checklist_current_index": 0,
        "checklist_completed_ids": [],
        "checklist_results": [],
        "scope": {},
    }


def apply_auth_to_state(state: dict, auth_payload: dict) -> None:
    """Inject username/password/cookies/bearer from auth_payload into state."""
    username = (auth_payload.get("username") or "").strip() or None
    password = (auth_payload.get("password") or "").strip() or None
    raw_cookies = (auth_payload.get("raw_cookies") or "").strip()
    bearer = (auth_payload.get("bearer_token") or "").strip()

    cookies_dict = _parse_raw_cookies(raw_cookies) if raw_cookies else {}
    cookie_string = (
        "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
        if cookies_dict else None
    )

    state["username"] = username
    state["password"] = password
    state["auth_cookies"] = cookies_dict
    state["session_cookie"] = cookie_string
    state["bearer_token"] = bearer or None
    state["jwt_token"] = bearer or None
    state["auth_headers"] = (
        {"Authorization": f"Bearer {bearer}"} if bearer else {}
    )
    pre_auth = bool(cookies_dict) or bool(bearer)
    state["auth_out_of_scope"] = pre_auth or bool(username and password)
    state["auth_status"] = "success" if pre_auth else state.get("auth_status")


def apply_scope_to_state(state: dict, scope: Optional[dict]) -> None:
    """Store the normalized scope on the agent state so agent prompts can
    render it via tools.scope_tool.render_scope_prompt."""
    from tools.scope_tool import normalize_scope
    state["scope"] = normalize_scope(scope or {})


def apply_custom_endpoints_to_state(state: dict, custom_endpoints: List[str]) -> None:
    """Merge user-added endpoints into state["discovered_endpoints"] (deduped)."""
    if not custom_endpoints:
        return
    existing = list(state.get("discovered_endpoints") or [])
    seen = {str(e) for e in existing}
    for ep in custom_endpoints:
        s = str(ep).strip()
        if s and s not in seen:
            existing.append(s)
            seen.add(s)
    state["discovered_endpoints"] = existing








# ── DB helpers ───────────────────────────────────────────────────────────────

def db_create_session(*, user_id: int, target: str, host_port: Optional[str], host_base_url: Optional[str], custom_endpoints: List[str], scope: Optional[dict] = None) -> int:
    from tools.scope_tool import normalize_scope
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pentest_sessions
                    (user_id, target, host_port, host_base_url, custom_endpoints, scope)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
                RETURNING id
                """,
                (user_id, target, host_port, host_base_url,
                 json.dumps(custom_endpoints or [], ensure_ascii=False),
                 json.dumps(normalize_scope(scope or {}), ensure_ascii=False)),
            )
            return int(cur.fetchone()[0])


def db_update_session_snapshot(session_db_id: int, *, custom_endpoints: Optional[List[str]] = None, auth_payload: Optional[dict] = None, state_snapshot: Optional[dict] = None, last_report_pdf_path: Optional[str] = None, last_report_text_path: Optional[str] = None, scope: Optional[dict] = None) -> None:
    fields: List[str] = []
    values: List[Any] = []
    if custom_endpoints is not None:
        fields.append("custom_endpoints = %s::jsonb")
        values.append(json.dumps(custom_endpoints, ensure_ascii=False))
    if scope is not None:
        from tools.scope_tool import normalize_scope
        fields.append("scope = %s::jsonb")
        values.append(json.dumps(normalize_scope(scope), ensure_ascii=False))
    if auth_payload is not None:
        # Never persist plaintext passwords in DB — keep only flags/tokens.
        redacted = {
            "has_username": bool(auth_payload.get("username")),
            "has_password": bool(auth_payload.get("password")),
            "raw_cookies":  bool(auth_payload.get("raw_cookies")),
            "bearer_token": bool(auth_payload.get("bearer_token")),
        }
        fields.append("auth_payload = %s::jsonb")
        values.append(json.dumps(redacted, ensure_ascii=False))
    if state_snapshot is not None:
        fields.append("state_snapshot = %s::jsonb")
        values.append(json.dumps(_serializable_state(state_snapshot), ensure_ascii=False))
    if last_report_pdf_path is not None:
        fields.append("last_report_pdf_path = %s")
        values.append(last_report_pdf_path)
    if last_report_text_path is not None:
        fields.append("last_report_text_path = %s")
        values.append(last_report_text_path)
    if not fields:
        return
    fields.append("updated_at = now()")
    values.append(session_db_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE pentest_sessions SET {', '.join(fields)} WHERE id = %s",
                values,
            )


def db_get_or_create_manual_run(
    *, user_id: int, pentest_session_id: int, session_id: str, target: str,
) -> int:
    """Return the id of this session's single 'manual' run, creating it if needed.

    In the tester-driven model there is no automatic module execution, so
    findings recorded by hand, by the chat agent, or saved from an Exploit
    Generation result have no run to attach to. We keep one durable
    module_key='manual' pentest_runs row per session for them. This reuses the
    existing findings schema (findings.run_id → pentest_runs) and the existing
    db_list_session_findings aggregation with no schema change.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM pentest_runs
                 WHERE pentest_session_id = %s AND module_key = 'manual'
                 ORDER BY id LIMIT 1
                """,
                (pentest_session_id,),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
            cur.execute(
                """
                INSERT INTO pentest_runs
                    (user_id, session_id, target, status,
                     selected_categories, skip_scan,
                     pentest_session_id, module_key, selected_test_ids)
                VALUES (%s, %s, %s, 'complete', %s::jsonb, false,
                        %s, 'manual', %s::jsonb)
                RETURNING id
                """,
                (
                    user_id, f"{session_id}#manual", target,
                    json.dumps([], ensure_ascii=False),
                    pentest_session_id,
                    json.dumps([], ensure_ascii=False),
                ),
            )
            return int(cur.fetchone()[0])


def db_record_session_finding(
    *, user_id: int, pentest_session_id: int, session_id: str, target: str,
    title: str, severity: str = "", phase: str = "", endpoint: str = "",
    evidence: str = "", description: str = "", source: str = "manual",
    test_status: str = "found", checklist_test_id: str = "",
) -> Optional[int]:
    """Record a tester-confirmed result against the session's manual run.

    `source` is one of 'manual' | 'chat' | 'exploit_gen' | 'sandbox' and is folded
    into checklist_category for provenance. `test_status` is one of
    'found' | 'not_found' | 'not_conclusive' — a Finding Agent verdict the tester
    confirmed, so Not-Vulnerable / Inconclusive outcomes are recorded too, not only
    vulnerabilities. `checklist_test_id` links the record to a reference test so the
    Tests/Findings section can show the verdict under that row. Returns the new
    finding id or None on failure.
    """
    from db.findings_repo import insert_finding

    status = test_status if test_status in ("found", "not_found", "not_conclusive") else "found"

    run_id = db_get_or_create_manual_run(
        user_id=user_id, pentest_session_id=pentest_session_id,
        session_id=session_id, target=target,
    )
    finding_text = title.strip()
    if description.strip():
        finding_text = f"{finding_text}\n\n{description.strip()}"
    return insert_finding(
        run_id=run_id,
        user_id=user_id,
        finding={
            "phase": phase or "",
            "test_status": status,
            "finding": finding_text,
            "severity": severity or "",
            "command": endpoint or "",
            "checklist_test_id": checklist_test_id or "",
            "checklist_category": f"manual:{source}",
            "proof_of_concept": {"output_snippet": evidence or ""},
        },
    )


def db_list_session_run_ids(session_db_id: int) -> List[int]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM pentest_runs WHERE pentest_session_id = %s ORDER BY id",
                (session_db_id,),
            )
            return [int(r[0]) for r in cur.fetchall()]


def db_list_session_findings(session_db_id: int, *, module_key: Optional[str] = None, test_status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Aggregate all findings from all module runs of this session."""
    conditions = ["r.pentest_session_id = %s"]
    params: List[Any] = [session_db_id]
    if module_key:
        conditions.append("r.module_key = %s")
        params.append(module_key)
    if test_status:
        conditions.append("f.test_status = %s")
        params.append(test_status)

    sql = f"""
        SELECT f.id, f.run_id, f.finding_id, f.finding_timestamp, f.phase,
               f.test_status, f.finding, f.owasp_id, f.owasp_category,
               f.checklist_test_id, f.checklist_category, f.test_description,
               f.vuln_attendue, f.severity, f.cvss, f.cvss_vector, f.cve,
               f.command, f.output_snippet, f.exploit_refs, f.cvss_records,
               f.created_at, r.module_key
          FROM findings f
          JOIN pentest_runs r ON r.id = f.run_id
         WHERE {' AND '.join(conditions)}
         ORDER BY
             CASE f.test_status WHEN 'found' THEN 0 WHEN 'not_conclusive' THEN 1 ELSE 2 END,
             CASE f.severity
                WHEN 'Critical' THEN 0
                WHEN 'High' THEN 1
                WHEN 'Medium' THEN 2
                WHEN 'Low' THEN 3
                WHEN 'Informational' THEN 4
                ELSE 5
             END,
             f.created_at DESC
    """
    from psycopg2.extras import DictCursor
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


def db_findings_for_report(session_db_id: int) -> List[Dict[str, Any]]:
    """Load every finding of this session from Postgres, shaped for the report agent.

    The DB is the single source of truth for findings in the tester-driven flow:
    sandbox verdicts, chat proposals, exploit-gen saves and the manual form all
    go through `db_record_session_finding`, which writes ONLY to Postgres. The
    legacy per-target JSONL (reports/findings/*.jsonl) was written solely by the
    deleted auto-run graph, so reading it yields an empty report.

    Rows are converted to the dict shape `report_node` expects (nested
    `proof_of_concept`, plain list `cve`, float `cvss`, JSON-safe timestamps).
    Manual records carry a provenance tag (`manual:<source>`) in
    checklist_category, so the real checklist category / description / expected
    vulnerability are looked up from `checklist_tests` via checklist_test_id.
    """
    rows = db_list_session_findings(session_db_id)

    test_ids = sorted({str(r.get("checklist_test_id") or "") for r in rows} - {""})
    meta: Dict[str, Dict[str, str]] = {}
    if test_ids:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT test_id, category, tests, vulnerabilite_attendue
                      FROM checklist_tests
                     WHERE test_id = ANY(%s)
                    """,
                    (test_ids,),
                )
                for tid, cat, desc, vuln in cur.fetchall():
                    meta[str(tid)] = {
                        "category": cat or "",
                        "tests": desc or "",
                        "vuln": vuln or "",
                    }

    out: List[Dict[str, Any]] = []
    for r in rows:
        tid = str(r.get("checklist_test_id") or "")
        m = meta.get(tid, {})
        raw_cat = str(r.get("checklist_category") or "")
        provenance = raw_cat if raw_cat.startswith("manual:") else ""
        category = (
            m.get("category")
            or ("" if provenance else raw_cat)
            or str(r.get("owasp_category") or "")
        )
        cvss = r.get("cvss")
        ts = r.get("finding_timestamp") or r.get("created_at")
        out.append({
            "db_id":              r.get("id"),
            "finding_id":         str(r.get("finding_id") or r.get("id") or ""),
            "timestamp":          ts.isoformat() if hasattr(ts, "isoformat") else (ts or ""),
            "module_key":         r.get("module_key") or "",
            "source":             provenance.split(":", 1)[1] if provenance else "",
            "phase":              r.get("phase") or "",
            "test_status":        r.get("test_status") or "not_conclusive",
            "finding":            r.get("finding") or "",
            "owasp_id":           r.get("owasp_id") or "",
            "owasp_category":     r.get("owasp_category") or "",
            "checklist_test_id":  tid,
            "checklist_category": category,
            "test_description":   r.get("test_description") or m.get("tests", ""),
            "vuln_attendue":      r.get("vuln_attendue") or m.get("vuln", ""),
            "severity":           r.get("severity") or "",
            "cvss":               float(cvss) if cvss is not None else None,
            "cvss_vector":        r.get("cvss_vector") or "",
            "cve":                list(r.get("cve") or []),
            "command":            r.get("command") or "",
            "proof_of_concept": {
                "command":        r.get("command") or "",
                "output_snippet": r.get("output_snippet") or "",
            },
            "exploit_refs":       list(r.get("exploit_refs") or []),
            "cvss_records":       r.get("cvss_records") or [],
        })
    return out


def db_get_session(session_db_id: int) -> Optional[Dict[str, Any]]:
    from psycopg2.extras import DictCursor
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(
                """
                SELECT id, user_id, target, host_port, host_base_url,
                       custom_endpoints, auth_payload, state_snapshot, status,
                       last_report_pdf_path, last_report_text_path,
                       scope, created_at, updated_at
                  FROM pentest_sessions
                 WHERE id = %s
                """,
                (session_db_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def db_add_chat_message(*, pentest_session_id: int, phase: str, role: str, content: str, suggestions: Optional[list] = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO chat_messages
                    (pentest_session_id, phase, role, content, suggestions)
                VALUES (%s, %s, %s, %s, %s::jsonb)
                """,
                (pentest_session_id, phase, role, content,
                 json.dumps(suggestions or [], ensure_ascii=False)),
            )


def db_list_chat_messages(pentest_session_id: int, phase: str) -> List[Dict[str, Any]]:
    from psycopg2.extras import DictCursor
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(
                """
                SELECT role, content, suggestions, created_at
                  FROM chat_messages
                 WHERE pentest_session_id = %s AND phase = %s
                 ORDER BY created_at ASC, id ASC
                """,
                (pentest_session_id, phase),
            )
            return [dict(r) for r in cur.fetchall()]


def db_clear_chat_messages(pentest_session_id: int, phase: str) -> int:
    """Delete all chat messages for one session+phase.

    Returns the number of rows removed. This is the storage side of the
    AI Assistant "Clear" action: it wipes the conversation context the
    agent is given on each turn, so the next message starts fresh.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM chat_messages
                 WHERE pentest_session_id = %s AND phase = %s
                """,
                (pentest_session_id, phase),
            )
            return cur.rowcount


def db_delete_session(session_db_id: int) -> bool:
    """Delete a pentest session row and its module-run children via cascade.

    Returns True if a row was deleted, False if none matched.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM pentest_sessions WHERE id = %s",
                (session_db_id,),
            )
            return cur.rowcount > 0


def db_list_user_sessions(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    from psycopg2.extras import DictCursor
    with get_conn() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(
                """
                SELECT id, target, host_port, status,
                       created_at, updated_at, last_report_pdf_path
                  FROM pentest_sessions
                 WHERE user_id = %s
                 ORDER BY created_at DESC
                 LIMIT %s
                """,
                (user_id, int(limit)),
            )
            return [dict(r) for r in cur.fetchall()]


def _serializable_state(state: dict) -> dict:
    """Strip the AgentState down to JSON-serializable fields for DB snapshot."""
    out: Dict[str, Any] = {}
    for k, v in state.items():
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            # Skip non-serializable values silently.
            continue
    return out


# ── Module run thread ────────────────────────────────────────────────────────

def emit_to_session(session: dict, event: dict, loop: asyncio.AbstractEventLoop) -> None:
    """Append to event buffer + push to the live queue (thread-safe)."""
    session["events"].append(event)
    if len(session["events"]) > 2000:
        # Drop oldest to bound memory.
        del session["events"][:1000]
    asyncio.run_coroutine_threadsafe(session["queue"].put(event), loop)




# ── Report-generation thread ─────────────────────────────────────────────────

def run_report_thread(*, session_id: str, loop: asyncio.AbstractEventLoop):
    from agents.report_agent import generate_report_for_session

    session = PENTEST_SESSIONS.get(session_id)
    if session is None:
        return

    def emit(event_type: str, data: dict):
        emit_to_session(
            session,
            {"type": event_type, "timestamp": _now(), "data": data},
            loop,
        )

    session["report_status"] = "running"
    emit("report_progress", {"stage": "start"})

    try:
        # Findings live in Postgres (every tester save path writes there). Load
        # this session's findings explicitly instead of letting the report agent
        # fall back to the legacy per-target JSONL, which is never written now.
        findings = db_findings_for_report(session["id"])
        emit("report_progress", {
            "stage": "findings_loaded",
            "total": len(findings),
            "confirmed": sum(1 for f in findings if f.get("test_status") == "found"),
        })

        def _cb(stage: str, detail: dict):
            emit("report_progress", {"stage": stage, **detail})

        state_in = dict(session.get("state") or {})
        state_in.setdefault("target", session["target"])
        result = generate_report_for_session(
            state_in, findings=findings, progress_cb=_cb,
        )
        pdf_path = result.get("final_report_pdf_path")
        text_path = result.get("final_report_text_path")
        session["last_report_pdf_path"] = pdf_path
        session["last_report_text_path"] = text_path
        session["report_status"] = "complete"
        db_update_session_snapshot(
            session["id"],
            last_report_pdf_path=pdf_path,
            last_report_text_path=text_path,
        )
        emit("report_complete", {
            "status": "complete",
            "pdf_path": pdf_path,
            "text_path": text_path,
        })
    except Exception as exc:
        session["report_status"] = "error"
        emit("report_complete", {
            "status": "error",
            "error": str(exc),
            "detail": traceback.format_exc(),
        })
