"""Read endpoints for pentest runs and findings.

  GET /runs/me                  — list this user's runs (most recent first)
  GET /runs/me/latest           — single most recent run
  GET /runs/me/latest/findings  — findings of the most recent run (or [] if none)
  GET /runs/{run_id}            — single run (must belong to caller, unless admin)
  GET /runs/{run_id}/findings   — findings of that run (same authorization)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser, get_current_user
from db.findings_repo import (
    get_latest_run_for_user,
    get_run,
    list_findings_for_run,
    list_runs_for_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/runs", tags=["runs"])


# ── Models ────────────────────────────────────────────────────────────────────

class RunOut(BaseModel):
    id:                  int
    session_id:          str
    target:              str
    status:              str
    started_at:          Optional[datetime] = None
    completed_at:        Optional[datetime] = None
    selected_categories: List[str] = Field(default_factory=list)
    skip_scan:           bool = False
    error_message:       Optional[str] = None
    report_text_path:    Optional[str] = None
    report_pdf_path:     Optional[str] = None


class FindingOut(BaseModel):
    id:                  int
    run_id:              int
    finding_id:          Optional[str] = None
    finding_timestamp:   Optional[datetime] = None
    phase:               str = ""
    test_status:         str
    finding:             str = ""
    owasp_id:            str = ""
    owasp_category:      str = ""
    checklist_test_id:   str = ""
    checklist_category:  str = ""
    test_description:    str = ""
    vuln_attendue:       str = ""
    severity:            str = ""
    cvss:                Optional[float] = None
    cvss_vector:         str = ""
    cve:                 List[str] = Field(default_factory=list)
    command:             str = ""
    output_snippet:      str = ""
    exploit_refs:        List[str] = Field(default_factory=list)
    cvss_records:        List[Dict[str, Any]] = Field(default_factory=list)
    created_at:          Optional[datetime] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_to_out(row: Dict[str, Any]) -> RunOut:
    sel = row.get("selected_categories") or []
    if isinstance(sel, str):
        try:
            import json as _json
            sel = _json.loads(sel)
        except Exception:
            sel = []
    return RunOut(
        id=row["id"],
        session_id=row["session_id"],
        target=row["target"],
        status=row["status"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        selected_categories=list(sel or []),
        skip_scan=bool(row.get("skip_scan") or False),
        error_message=row.get("error_message"),
        report_text_path=row.get("report_text_path"),
        report_pdf_path=row.get("report_pdf_path"),
    )


def _finding_to_out(row: Dict[str, Any]) -> FindingOut:
    cvss = row.get("cvss")
    return FindingOut(
        id=row["id"],
        run_id=row["run_id"],
        finding_id=row.get("finding_id"),
        finding_timestamp=row.get("finding_timestamp"),
        phase=row.get("phase") or "",
        test_status=row.get("test_status") or "not_conclusive",
        finding=row.get("finding") or "",
        owasp_id=row.get("owasp_id") or "",
        owasp_category=row.get("owasp_category") or "",
        checklist_test_id=row.get("checklist_test_id") or "",
        checklist_category=row.get("checklist_category") or "",
        test_description=row.get("test_description") or "",
        vuln_attendue=row.get("vuln_attendue") or "",
        severity=row.get("severity") or "",
        cvss=float(cvss) if cvss is not None else None,
        cvss_vector=row.get("cvss_vector") or "",
        cve=list(row.get("cve") or []),
        command=row.get("command") or "",
        output_snippet=row.get("output_snippet") or "",
        exploit_refs=list(row.get("exploit_refs") or []),
        cvss_records=list(row.get("cvss_records") or []),
        created_at=row.get("created_at"),
    )


def _authorize_run(run_id: int, user: CurrentUser) -> Dict[str, Any]:
    """Fetch the run and raise 403/404 if the caller can't access it."""
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this run")
    return run


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/me", response_model=List[RunOut])
def my_runs(user: CurrentUser = Depends(get_current_user)) -> List[RunOut]:
    rows = list_runs_for_user(user.id)
    return [_run_to_out(r) for r in rows]


@router.get("/me/latest", response_model=Optional[RunOut])
def my_latest_run(user: CurrentUser = Depends(get_current_user)) -> Optional[RunOut]:
    row = get_latest_run_for_user(user.id)
    return _run_to_out(row) if row else None


@router.get("/me/latest/findings", response_model=List[FindingOut])
def my_latest_findings(user: CurrentUser = Depends(get_current_user)) -> List[FindingOut]:
    latest = get_latest_run_for_user(user.id)
    if latest is None:
        return []
    rows = list_findings_for_run(int(latest["id"]))
    return [_finding_to_out(r) for r in rows]


@router.get("/{run_id}", response_model=RunOut)
def get_run_detail(
    run_id: int, user: CurrentUser = Depends(get_current_user),
) -> RunOut:
    return _run_to_out(_authorize_run(run_id, user))


@router.get("/{run_id}/findings", response_model=List[FindingOut])
def get_run_findings(
    run_id: int, user: CurrentUser = Depends(get_current_user),
) -> List[FindingOut]:
    _authorize_run(run_id, user)
    rows = list_findings_for_run(run_id)
    return [_finding_to_out(r) for r in rows]
