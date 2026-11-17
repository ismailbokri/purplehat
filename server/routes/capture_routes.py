"""Browser capture route (Interface, Section 6).

The tester browses the target and clicks Capture. This endpoint grabs the DOM
outline + screenshot of the given URL, stores a summary in session state so the
phase Conversation Agent has the browser context, and runs one chat turn so the
agent responds with analysis/recommendations based on the captured page.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser, get_current_user
from agents.conversation_agent import PHASE_KEYS, converse
from server.sessions_runtime import (
    PENTEST_SESSIONS, db_add_chat_message, db_list_chat_messages,
)

router = APIRouter(prefix="/api/sessions", tags=["capture"])


class CaptureIn(BaseModel):
    url: str = Field(min_length=1)
    phase: str = "discovery"
    notes: str = ""


def _session_or_404(session_id: str, user: CurrentUser) -> Dict[str, Any]:
    sess = PENTEST_SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this session")
    return sess


@router.post("/{session_id}/capture")
def capture(
    session_id: str,
    payload: CaptureIn,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    sess = _session_or_404(session_id, user)
    phase = payload.phase if payload.phase in PHASE_KEYS else "discovery"

    from tools.capture_tool import capture_page, summarize_capture_for_agent, CaptureError
    from tools.docker_target_map import to_internal_url

    state = sess.get("state") or {}
    cookie = state.get("session_cookie") or ""
    # The frontend sends the browser-plane URL (localhost:8082/...). capture_page
    # runs inside the browser-recon container on pentest-net, which cannot reach
    # localhost — translate to the Docker-plane URL (juice-shop:3000/...) first.
    fetch_url = to_internal_url(payload.url.strip())
    try:
        cap = capture_page(fetch_url, cookie)
    except CaptureError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    summary = summarize_capture_for_agent(cap, payload.notes)
    # Store the latest capture so subsequent chat turns keep the context.
    state["last_capture_summary"] = summary
    sess["state"] = state

    # Seed a chat turn so the agent analyzes the capture.
    history = [
        {"role": r["role"], "content": r["content"]}
        for r in db_list_chat_messages(sess["id"], phase)
    ]
    user_msg = (
        "I captured the current page in the browser. Analyze it and tell me what to "
        "test next, staying in scope.\n\n" + summary
    )
    db_add_chat_message(pentest_session_id=sess["id"], phase=phase, role="user", content=user_msg)

    result = converse(phase=phase, state=state, history=history, user_message=user_msg)
    db_add_chat_message(
        pentest_session_id=sess["id"], phase=phase, role="assistant",
        content=result.get("reply", ""), suggestions=result.get("suggestions") or [],
    )

    return {
        "capture": {
            # Echo the browser-plane URL the tester navigated to, not the
            # internal juice-shop:3000 URL the container actually fetched.
            "url": payload.url.strip(),
            "title": cap.get("title"),
            "screenshot_b64": cap.get("screenshot_b64"),
            "dom_summary": cap.get("dom_summary"),
        },
        "assistant": result,
        "phase": phase,
    }
