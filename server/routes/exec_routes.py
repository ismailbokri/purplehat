"""Execution & Inspection sandbox routes (Interface B).

The penetration tester runs authorized commands/scripts inside the pre-baked
`pentest-container`. Output streams over the session WebSocket as `sandbox_*`
events; generated files can be listed and read back. No AI agent calls these —
execution is strictly tester-triggered.
"""

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser, get_current_user
from server.sessions_runtime import PENTEST_SESSIONS, emit_to_session
from tools.finding_reporter_tool import classify_output
from tools.sandbox_tool import (
    SandboxError, ensure_workspace, list_files, read_file, run_command,
)

router = APIRouter(prefix="/api/sessions", tags=["sandbox"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecIn(BaseModel):
    command: str = Field(min_length=1)
    # Optional checklist context from the active reference test — sharpens the
    # Finding Agent's verdict (Not Vulnerable vs. Inconclusive). All optional;
    # analysis always runs and always produces a verdict without them.
    phase: str = ""
    test_description: str = ""
    vuln_attendue: str = ""
    resultat_attendu: str = ""


def _session_or_404(session_id: str, user: CurrentUser) -> Dict[str, Any]:
    sess = PENTEST_SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this session")
    return sess


def _run_exec_thread(
    session: dict,
    command: str,
    ctx: Dict[str, str],
    loop: asyncio.AbstractEventLoop,
) -> None:
    session_id = next((k for k, v in PENTEST_SESSIONS.items() if v is session), None)
    if session_id is None:
        return

    def emit(event_type: str, data: dict):
        emit_to_session(
            session,
            {"type": event_type, "timestamp": _now(), "data": data},
            loop,
        )

    # Two planes: the tester (and the browser) use localhost:8084, but this
    # command runs in pentest-container on pentest-net, where localhost is the
    # container itself. Translate to the service address (web:5000) and show
    # both so the rewrite is never silent.
    from tools.docker_target_map import to_internal_command
    typed = command
    command = to_internal_command(
        typed, default_url=str(session.get("host_base_url") or session.get("target") or ""),
    )
    start = {"command": command}
    if command != typed:
        start["typed"] = typed
    emit("sandbox_start", start)
    output = ""
    try:
        result = run_command(
            session_id, command,
            on_line=lambda line: emit("sandbox_output", {"line": line}),
        )
        output = str(result.get("output") or "")
        emit("sandbox_complete", {
            "command": command,
            "exit_code": result.get("exit_code"),
            "timed_out": result.get("timed_out", False),
        })
    except SandboxError as exc:
        emit("sandbox_error", {"command": command, "message": str(exc)})
        _emit_analysis(emit, command, output, ctx, session)  # still give a verdict
        session.pop("sandbox_running", None)
        return
    except Exception as exc:  # defensive — never kill the thread silently
        emit("sandbox_error", {"command": command, "message": f"unexpected: {exc}"})
        _emit_analysis(emit, command, output, ctx, session)
        session.pop("sandbox_running", None)
        return

    # Finding Agent: analyze the output of EVERY execution and always emit an
    # explicit verdict — never blank (see classify_output). Runs in this worker
    # thread (not the event loop) because call_llm is blocking.
    _emit_analysis(emit, command, output, ctx, session)
    session.pop("sandbox_running", None)


def _emit_analysis(emit, command: str, output: str, ctx: Dict[str, str], session: dict) -> None:
    """Classify the command output and emit `sandbox_analysis`.

    Guarantees a verdict is always emitted, even if classification itself raises
    — in that case we report an explicit 'Inconclusive' rather than nothing.
    """
    try:
        verdict = classify_output(
            command=command,
            output=output,
            target=str(session.get("target") or ""),
            phase=ctx.get("phase") or "Sandbox",
            test_description=ctx.get("test_description", ""),
            vuln_attendue=ctx.get("vuln_attendue", ""),
            resultat_attendu=ctx.get("resultat_attendu", ""),
        )
    except Exception as exc:
        verdict = {
            "status":  "not_conclusive",
            "label":   "Inconclusive",
            "summary": f"Analysis could not complete ({exc.__class__.__name__}); "
                       "verdict is inconclusive.",
            "finding": None,
        }
    emit("sandbox_analysis", {"command": command, **verdict})


@router.post("/{session_id}/exec")
async def exec_command(
    session_id: str,
    payload: ExecIn,
    user: CurrentUser = Depends(get_current_user),
):
    sess = _session_or_404(session_id, user)
    if sess.get("sandbox_running"):
        raise HTTPException(status_code=409, detail="A sandbox command is already running")

    try:
        ensure_workspace(session_id)
    except SandboxError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    sess["sandbox_running"] = True
    loop = asyncio.get_running_loop()
    ctx = {
        "phase":            payload.phase.strip(),
        "test_description": payload.test_description.strip(),
        "vuln_attendue":    payload.vuln_attendue.strip(),
        "resultat_attendu": payload.resultat_attendu.strip(),
    }
    threading.Thread(
        target=_run_exec_thread,
        kwargs={"session": sess, "command": payload.command.strip(), "ctx": ctx, "loop": loop},
        daemon=True,
    ).start()
    return {"status": "started"}


@router.get("/{session_id}/files")
def session_files(
    session_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    _session_or_404(session_id, user)
    try:
        return list_files(session_id)
    except SandboxError:
        return []


@router.get("/{session_id}/files/content")
def session_file_content(
    session_id: str,
    name: str,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, str]:
    _session_or_404(session_id, user)
    try:
        return {"name": name, "content": read_file(session_id, name)}
    except SandboxError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
