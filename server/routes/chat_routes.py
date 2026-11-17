"""Per-phase AI Assistant chat (Interface A).

The tester chats with the Conversation Agent specialized for a phase. The agent
answers, proposes sandbox commands, and may suggest routing to the Browser
Explorer or Exploit Generation agent. It never executes anything.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser, get_current_user
from agents.conversation_agent import PHASE_KEYS, converse
from server.sessions_runtime import (
    PENTEST_SESSIONS, db_add_chat_message, db_clear_chat_messages,
    db_list_chat_messages, db_list_session_findings,
)

router = APIRouter(prefix="/api/sessions", tags=["chat"])


class ChatIn(BaseModel):
    message: str = Field(min_length=1)


def _session_or_404(session_id: str, user: CurrentUser) -> Dict[str, Any]:
    sess = PENTEST_SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this session")
    return sess


def _check_phase(phase: str) -> None:
    if phase not in PHASE_KEYS:
        raise HTTPException(status_code=400, detail=f"Unknown phase: {phase}")


@router.get("/{session_id}/phases/{phase}/chat")
def get_chat(
    session_id: str,
    phase: str,
    user: CurrentUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    _check_phase(phase)
    sess = _session_or_404(session_id, user)
    rows = db_list_chat_messages(sess["id"], phase)
    return [
        {
            "role": r["role"],
            "content": r["content"],
            "suggestions": r.get("suggestions") or [],
            "created_at": r.get("created_at"),
        }
        for r in rows
    ]


@router.delete("/{session_id}/phases/{phase}/chat")
def clear_chat(
    session_id: str,
    phase: str,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Clear the AI Assistant context for a phase.

    Wipes the stored conversation so the agent's memory (the history it
    receives each turn) starts fresh. Only the owner (or an admin) may do it.
    """
    _check_phase(phase)
    sess = _session_or_404(session_id, user)
    removed = db_clear_chat_messages(sess["id"], phase)
    return {"cleared": True, "removed": removed}


@router.post("/{session_id}/phases/{phase}/chat")
def post_chat(
    session_id: str,
    phase: str,
    payload: ChatIn,
    user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    _check_phase(phase)
    sess = _session_or_404(session_id, user)

    message = payload.message.strip()

    history = [
        {"role": r["role"], "content": r["content"]}
        for r in db_list_chat_messages(sess["id"], phase)
    ]

    # Persist the user's turn first.
    db_add_chat_message(
        pentest_session_id=sess["id"], phase=phase, role="user", content=message,
    )

    # Enrich the agent's view of state with the findings recorded so far. This is
    # what lets the Reporting agent discuss findings and the other phases avoid
    # re-proposing something already recorded.
    state = dict(sess.get("state") or {})
    try:
        state["recorded_findings"] = db_list_session_findings(sess["id"])
    except Exception:
        state.setdefault("recorded_findings", [])

    result = converse(
        phase=phase,
        state=state,
        history=history,
        user_message=message,
    )

    db_add_chat_message(
        pentest_session_id=sess["id"], phase=phase, role="assistant",
        content=result.get("reply", ""), suggestions=result.get("suggestions") or [],
    )

    return result
