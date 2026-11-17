"""HTTP + WebSocket routes for the modular /sessions workflow.

The user creates a pentest session once (POST /sessions) and then drives the
pentest by running individual modules (Découverte, Pré-auth, Post-auth…),
each scoped to a user-selected subset of checklist tests. A single WebSocket
streams events for all module runs in the session, plus on-demand report
progress.
"""

import asyncio
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from auth.dependencies import CurrentUser, get_current_user
from graphs import MODULE_CATEGORY, MODULE_KEYS
from tools.scope_tool import normalize_scope
from server.sessions_runtime import (
    PENTEST_SESSIONS,
    _empty_agent_state,
    _parse_host_info,
    apply_auth_to_state,
    apply_custom_endpoints_to_state,
    apply_scope_to_state,
    db_record_session_finding,
    db_create_session,
    db_delete_session,
    db_get_session,
    db_list_session_findings,
    db_list_user_sessions,
    db_update_session_snapshot,
    emit_to_session,
    run_report_thread,
)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


# ─── Models ──────────────────────────────────────────────────────────────────

class SessionCreateIn(BaseModel):
    target: str = Field(min_length=1)
    port: Optional[int] = None
    custom_endpoints: List[str] = Field(default_factory=list)
    scope: Dict[str, Any] = Field(default_factory=dict)


class ScopePatch(BaseModel):
    in_scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None
    authorized_domains: Optional[List[str]] = None
    restrictions: Optional[str] = None
    auth_requirements: Optional[str] = None
    notes: Optional[str] = None


class SessionOut(BaseModel):
    session_id: str
    id: int
    target: str
    host_port: Optional[str] = None
    host_base_url: Optional[str] = None
    custom_endpoints: List[str] = Field(default_factory=list)
    scope: Dict[str, Any] = Field(default_factory=dict)
    auth_payload: Dict[str, Any] = Field(default_factory=dict)  # redacted (bool flags only)
    status: str = "active"
    active_module: Optional[str] = None
    module_runs: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    report_status: str = "idle"
    last_report_pdf_path: Optional[str] = None
    discovered_endpoints: List[str] = Field(default_factory=list)
    findings_count: int = 0
    created_at: Optional[datetime] = None


class SessionListItem(BaseModel):
    session_id: str
    id: int
    target: str
    status: str
    created_at: Optional[datetime] = None
    last_report_pdf_path: Optional[str] = None


class EndpointPatch(BaseModel):
    add: List[str] = Field(default_factory=list)
    remove: List[str] = Field(default_factory=list)


class AuthPatch(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    raw_cookies: Optional[str] = None
    bearer_token: Optional[str] = None


class FindingIn(BaseModel):
    """A tester-confirmed result recorded manually, from chat, exploit gen, or a
    sandbox Finding Agent verdict.

    `test_status` lets the sandbox record Not-Vulnerable / Inconclusive outcomes —
    not only confirmed vulnerabilities — and `checklist_test_id` links the record
    to a reference test so the Tests/Findings section reflects the verdict.
    """
    # A short display title. The Finding Agent can now emit long "why it is / is
    # not vulnerable" reasoning; that belongs in `description`, but to make sure a
    # verbose title never 422s the whole save, we accept a generous length and
    # trim to a clean 200-char title in the validator below rather than rejecting.
    title: str = Field(min_length=1, max_length=4000)
    severity: str = ""
    phase: str = ""
    endpoint: str = ""
    evidence: str = ""
    description: str = ""
    source: str = "manual"  # manual | chat | exploit_gen | sandbox
    test_status: str = "found"  # found | not_found | not_conclusive
    checklist_test_id: str = ""

    @field_validator("title")
    @classmethod
    def _trim_title(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("title must not be empty")
        if len(v) > 200:
            v = v[:199].rstrip() + "…"
        return v


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _session_or_404(session_id: str, user: CurrentUser) -> Dict[str, Any]:
    s = PENTEST_SESSIONS.get(session_id)
    if s is None:
        # Try restoring from DB by scanning for the user's sessions.
        # Lightweight: lookups are rare and the table is small per-user.
        for row in db_list_user_sessions(user.id, limit=500):
            sid_key = _session_id_for_row(row["id"])
            if sid_key == session_id:
                # Found a DB row but no in-memory entry → reconstruct minimally.
                s = _reconstruct_session_from_db(session_id, row["id"], user.id)
                break
        if s is None:
            raise HTTPException(status_code=404, detail="Session not found")
    if s["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this session")
    return s


def _session_id_for_row(db_id: int) -> str:
    """Sessions are keyed in memory by their public UUID; the DB stores the
    numeric PK. We map them via the in-memory record only — for lookups by DB
    id, callers can iterate `PENTEST_SESSIONS` to find a matching `id`.
    """
    for sid, sess in PENTEST_SESSIONS.items():
        if sess.get("id") == db_id:
            return sid
    return ""


def _reconstruct_session_from_db(session_id: str, db_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Restore an in-memory entry from a persisted DB row (after a server restart)."""
    row = db_get_session(db_id)
    if row is None or row.get("user_id") != user_id:
        return None
    snapshot = row.get("state_snapshot") or {}
    custom_endpoints = list(row.get("custom_endpoints") or [])
    auth_payload = dict(row.get("auth_payload") or {})
    scope = normalize_scope(row.get("scope") or {})
    target = row["target"]
    state = _empty_agent_state(target, row.get("host_port"), row.get("host_base_url"))
    if isinstance(snapshot, dict):
        state.update(snapshot)
    apply_scope_to_state(state, scope)
    sess = {
        "id": db_id,
        "user_id": user_id,
        "target": target,
        "host_port": row.get("host_port"),
        "host_base_url": row.get("host_base_url"),
        "custom_endpoints": custom_endpoints,
        "scope": scope,
        "auth_payload": auth_payload,  # NB: only flags stored in DB; secrets lost on restart
        "state": state,
        "queue": asyncio.Queue(maxsize=4000),
        "events": [],
        "lock": threading.Lock(),
        "active_module": None,
        "module_runs": {},
        "report_status": "idle",
        "last_report_pdf_path": row.get("last_report_pdf_path"),
        "last_report_text_path": row.get("last_report_text_path"),
        "created_at": row.get("created_at"),
    }
    PENTEST_SESSIONS[session_id] = sess
    return sess


def _session_to_out(session_id: str, sess: Dict[str, Any]) -> SessionOut:
    return SessionOut(
        session_id=session_id,
        id=sess["id"],
        target=sess["target"],
        host_port=sess.get("host_port"),
        host_base_url=sess.get("host_base_url"),
        custom_endpoints=list(sess.get("custom_endpoints") or []),
        scope=normalize_scope(sess.get("scope") or {}),
        auth_payload={
            "has_username": bool((sess.get("auth_payload") or {}).get("username")),
            "has_password": bool((sess.get("auth_payload") or {}).get("password")),
            "raw_cookies":  bool((sess.get("auth_payload") or {}).get("raw_cookies")),
            "bearer_token": bool((sess.get("auth_payload") or {}).get("bearer_token")),
        },
        status="active",
        active_module=sess.get("active_module"),
        module_runs=dict(sess.get("module_runs") or {}),
        report_status=str(sess.get("report_status") or "idle"),
        last_report_pdf_path=sess.get("last_report_pdf_path"),
        discovered_endpoints=list((sess.get("state") or {}).get("discovered_endpoints") or []),
        findings_count=len(db_list_session_findings(sess["id"])),
        created_at=sess.get("created_at"),
    )


def _check_module_key(module_key: str) -> None:
    if module_key not in MODULE_KEYS:
        raise HTTPException(status_code=400, detail=f"Unknown module_key: {module_key}")


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("", response_model=List[SessionListItem])
def list_sessions(user: CurrentUser = Depends(get_current_user)) -> List[SessionListItem]:
    rows = db_list_user_sessions(user.id)
    items: List[SessionListItem] = []
    for r in rows:
        # Find the matching in-memory session_id, or mint one if it's a fresh restore.
        sid = _session_id_for_row(r["id"])
        if not sid:
            sid = str(uuid.uuid4())
            _reconstruct_session_from_db(sid, r["id"], user.id)
        items.append(SessionListItem(
            session_id=sid, id=r["id"], target=r["target"],
            status=str(r.get("status") or "active"),
            created_at=r.get("created_at"),
            last_report_pdf_path=r.get("last_report_pdf_path"),
        ))
    return items


@router.post("", response_model=SessionOut, status_code=status.HTTP_201_CREATED)
def create_session(
    payload: SessionCreateIn,
    user: CurrentUser = Depends(get_current_user),
) -> SessionOut:
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    if payload.port and "://" not in target and ":" not in target:
        target = f"{target}:{int(payload.port)}"
    host_port, host_base_url = _parse_host_info(target)
    scope = normalize_scope(payload.scope or {})

    db_id = db_create_session(
        user_id=user.id, target=target,
        host_port=host_port, host_base_url=host_base_url,
        custom_endpoints=list(payload.custom_endpoints or []),
        scope=scope,
    )

    sid = str(uuid.uuid4())
    state = _empty_agent_state(target, host_port, host_base_url)
    apply_custom_endpoints_to_state(state, list(payload.custom_endpoints or []))
    apply_scope_to_state(state, scope)
    sess = {
        "id": db_id,
        "user_id": user.id,
        "target": target,
        "host_port": host_port,
        "host_base_url": host_base_url,
        "custom_endpoints": list(payload.custom_endpoints or []),
        "scope": scope,
        "auth_payload": {},
        "state": state,
        "queue": asyncio.Queue(maxsize=4000),
        "events": [],
        "lock": threading.Lock(),
        "active_module": None,
        "module_runs": {},
        "report_status": "idle",
        "last_report_pdf_path": None,
        "last_report_text_path": None,
        "created_at": datetime.utcnow(),
    }
    PENTEST_SESSIONS[sid] = sess
    return _session_to_out(sid, sess)


@router.get("/{session_id}", response_model=SessionOut)
def get_session(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> SessionOut:
    sess = _session_or_404(session_id, user)
    return _session_to_out(session_id, sess)


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    """Delete a pentest session and all its module runs/findings (DB cascade).

    Refuses if a module run is in flight (409). The user must own the session
    (admins can delete anyone's).
    """
    sess = _session_or_404(session_id, user)
    if sess.get("active_module"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete: module {sess['active_module']!r} is still running. "
                   "Stop it first.",
        )
    if sess.get("report_status") == "running":
        raise HTTPException(
            status_code=409,
            detail="Cannot delete: a report is currently being generated.",
        )

    db_delete_session(sess["id"])

    # Drain the WebSocket queue so any open client unblocks and closes cleanly.
    try:
        q = sess.get("queue")
        if q is not None:
            q.put_nowait(None)
    except Exception:
        pass

    PENTEST_SESSIONS.pop(session_id, None)
    return None


@router.patch("/{session_id}/endpoints", response_model=SessionOut)
def patch_endpoints(
    session_id: str,
    payload: EndpointPatch,
    user: CurrentUser = Depends(get_current_user),
) -> SessionOut:
    sess = _session_or_404(session_id, user)
    current = list(sess.get("custom_endpoints") or [])
    seen = {e for e in current}
    for ep in payload.add or []:
        s = (ep or "").strip()
        if s and s not in seen:
            current.append(s)
            seen.add(s)
    if payload.remove:
        remove_set = {(e or "").strip() for e in payload.remove}
        current = [e for e in current if e not in remove_set]
    sess["custom_endpoints"] = current
    apply_custom_endpoints_to_state(sess["state"], current)
    db_update_session_snapshot(sess["id"], custom_endpoints=current, state_snapshot=sess["state"])
    return _session_to_out(session_id, sess)


@router.patch("/{session_id}/auth", response_model=SessionOut)
def patch_auth(
    session_id: str,
    payload: AuthPatch,
    user: CurrentUser = Depends(get_current_user),
) -> SessionOut:
    sess = _session_or_404(session_id, user)
    auth_payload = dict(sess.get("auth_payload") or {})
    for field in ("username", "password", "raw_cookies", "bearer_token"):
        v = getattr(payload, field, None)
        if v is not None:
            auth_payload[field] = v
    sess["auth_payload"] = auth_payload
    apply_auth_to_state(sess["state"], auth_payload)
    db_update_session_snapshot(sess["id"], auth_payload=auth_payload, state_snapshot=sess["state"])
    return _session_to_out(session_id, sess)


@router.get("/{session_id}/scope")
def get_scope(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    sess = _session_or_404(session_id, user)
    return normalize_scope(sess.get("scope") or {})


@router.patch("/{session_id}/scope", response_model=SessionOut)
def patch_scope(
    session_id: str,
    payload: ScopePatch,
    user: CurrentUser = Depends(get_current_user),
) -> SessionOut:
    sess = _session_or_404(session_id, user)
    scope = normalize_scope(sess.get("scope") or {})
    # Apply only the fields the caller sent (partial update).
    for field in ("in_scope", "out_of_scope", "authorized_domains",
                  "restrictions", "auth_requirements", "notes"):
        v = getattr(payload, field, None)
        if v is not None:
            scope[field] = v
    scope = normalize_scope(scope)
    sess["scope"] = scope
    apply_scope_to_state(sess["state"], scope)
    db_update_session_snapshot(sess["id"], scope=scope, state_snapshot=sess["state"])
    return _session_to_out(session_id, sess)


@router.get("/{session_id}/findings")
def list_findings(
    session_id: str,
    module_key: Optional[str] = None,
    test_status: Optional[str] = None,
    user: CurrentUser = Depends(get_current_user),
):
    sess = _session_or_404(session_id, user)
    # 'manual' is a valid run bucket (the single per-session run that holds every
    # tester-recorded finding — manual form, chat, exploit-gen, sandbox verdicts),
    # not a conversation phase, so it is accepted here even though _check_module_key
    # (used for phase-scoped routes) does not list it.
    if module_key is not None and module_key != "manual":
        _check_module_key(module_key)
    rows = db_list_session_findings(sess["id"], module_key=module_key, test_status=test_status)
    return rows


@router.post("/{session_id}/findings", status_code=status.HTTP_201_CREATED)
def create_finding(
    session_id: str,
    payload: FindingIn,
    user: CurrentUser = Depends(get_current_user),
):
    """Record one tester-confirmed finding against the session's manual run.

    Used by the 'Add finding' form, by saving an Exploit Generation result, and
    by the chat agent's finding proposal once the tester confirms it. There is
    no automatic module execution in the tester-driven model, so this is the
    path by which findings enter the system.
    """
    sess = _session_or_404(session_id, user)
    fid = db_record_session_finding(
        user_id=user.id,
        pentest_session_id=sess["id"],
        session_id=session_id,
        target=sess["target"],
        title=payload.title,
        severity=payload.severity,
        phase=payload.phase,
        endpoint=payload.endpoint,
        evidence=payload.evidence,
        description=payload.description,
        source=payload.source if payload.source in ("manual", "chat", "exploit_gen", "sandbox") else "manual",
        test_status=payload.test_status,
        checklist_test_id=payload.checklist_test_id,
    )
    if fid is None:
        raise HTTPException(status_code=500, detail="Failed to record finding")
    return {"id": fid, "status": "recorded"}


@router.post("/{session_id}/report")
async def create_report(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    sess = _session_or_404(session_id, user)
    if sess.get("report_status") == "running":
        raise HTTPException(status_code=409, detail="A report is already being generated for this session")
    loop = asyncio.get_running_loop()
    thread = threading.Thread(
        target=run_report_thread,
        kwargs={"session_id": session_id, "loop": loop},
        daemon=True,
    )
    thread.start()
    return {"status": "started"}


@router.get("/{session_id}/report.pdf")
def download_report(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
):
    sess = _session_or_404(session_id, user)
    pdf_path = sess.get("last_report_pdf_path")
    if not pdf_path:
        raise HTTPException(status_code=404, detail="No report generated yet")
    import os as _os
    if not _os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Report PDF file is missing on disk")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=_os.path.basename(pdf_path),
    )


# ─── WebSocket: scoped to a session, multiplexes all module/report events ────

@router.websocket("/{session_id}/ws")
async def session_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    sess = PENTEST_SESSIONS.get(session_id)
    if sess is None:
        await websocket.send_json({"type": "error", "data": {"message": "Session not found"}})
        await websocket.close()
        return

    queue: asyncio.Queue = sess["queue"]

    # Replay buffered events (covers refresh / late-connect race).
    for event in list(sess["events"]):
        try:
            await websocket.send_json(event)
        except Exception:
            return

    async def _ping_loop():
        while True:
            await asyncio.sleep(25)
            try:
                await websocket.send_json({"type": "ping"})
            except Exception:
                break

    ping_task = asyncio.create_task(_ping_loop())
    try:
        while True:
            event = await queue.get()
            if event is None:
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        ping_task.cancel()
        try:
            await websocket.close()
        except Exception:
            pass
