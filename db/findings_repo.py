"""DB persistence for findings.

Writes are append-only and tied to a (run_id, user_id) pair propagated from
the pipeline thread via tools/run_context.py.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from db.connection import get_conn, get_dict_cursor

logger = logging.getLogger(__name__)


def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except Exception:
        return None


def insert_finding(*, run_id: int, user_id: int, finding: Dict[str, Any]) -> Optional[int]:
    """Insert one finding record. Never raises; logs and returns None on failure."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO findings
                        (run_id, user_id, finding_id, finding_timestamp, phase,
                         test_status, finding, owasp_id, owasp_category,
                         checklist_test_id, checklist_category, test_description,
                         vuln_attendue, severity, cvss, cvss_vector, cve,
                         command, output_snippet, exploit_refs, cvss_records)
                    VALUES (%s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s::jsonb)
                    RETURNING id
                    """,
                    (
                        run_id, user_id,
                        str(finding.get("finding_id") or "") or None,
                        _parse_ts(finding.get("timestamp")),
                        str(finding.get("phase") or ""),
                        str(finding.get("test_status") or "not_conclusive"),
                        str(finding.get("finding") or ""),
                        str(finding.get("owasp_id") or ""),
                        str(finding.get("owasp_category") or ""),
                        str(finding.get("checklist_test_id") or ""),
                        str(finding.get("checklist_category") or ""),
                        str(finding.get("test_description") or ""),
                        str(finding.get("vuln_attendue") or ""),
                        str(finding.get("severity") or ""),
                        finding.get("cvss"),
                        str(finding.get("cvss_vector") or ""),
                        list(finding.get("cve") or []),
                        str((finding.get("proof_of_concept") or {}).get("command")
                            or finding.get("command") or ""),
                        str((finding.get("proof_of_concept") or {}).get("output_snippet") or ""),
                        list(finding.get("exploit_refs") or []),
                        json.dumps(finding.get("cvss_records") or [], ensure_ascii=False),
                    ),
                )
                return int(cur.fetchone()[0])
    except Exception as exc:
        logger.warning("[findings_repo] insert failed for run_id=%s: %s", run_id, exc)
        return None


def list_findings_for_run(run_id: int) -> List[Dict[str, Any]]:
    with get_dict_cursor() as cur:
        cur.execute(
            """
            SELECT id, run_id, finding_id,
                   finding_timestamp, phase, test_status, finding,
                   owasp_id, owasp_category, checklist_test_id, checklist_category,
                   test_description, vuln_attendue, severity, cvss, cvss_vector,
                   cve, command, output_snippet, exploit_refs, cvss_records, created_at
              FROM findings
             WHERE run_id = %s
             ORDER BY
                 -- 'found' first, then by severity (Critical>High>Medium>Low>Informational), then by time
                 CASE test_status WHEN 'found' THEN 0 WHEN 'not_conclusive' THEN 1 ELSE 2 END,
                 CASE severity
                    WHEN 'Critical'      THEN 0
                    WHEN 'High'          THEN 1
                    WHEN 'Medium'        THEN 2
                    WHEN 'Low'           THEN 3
                    WHEN 'Informational' THEN 4
                    ELSE 5
                 END,
                 created_at DESC
            """,
            (run_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_run(run_id: int) -> Optional[Dict[str, Any]]:
    with get_dict_cursor() as cur:
        cur.execute(
            """
            SELECT id, user_id, session_id, target, status, selected_categories,
                   skip_scan, started_at, completed_at, error_message,
                   report_text_path, report_pdf_path
              FROM pentest_runs
             WHERE id = %s
            """,
            (run_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_latest_run_for_user(user_id: int) -> Optional[Dict[str, Any]]:
    with get_dict_cursor() as cur:
        cur.execute(
            """
            SELECT id, user_id, session_id, target, status, selected_categories,
                   skip_scan, started_at, completed_at, error_message,
                   report_text_path, report_pdf_path
              FROM pentest_runs
             WHERE user_id = %s
             ORDER BY started_at DESC
             LIMIT 1
            """,
            (user_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def list_runs_for_user(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    with get_dict_cursor() as cur:
        cur.execute(
            """
            SELECT id, session_id, target, status, started_at, completed_at,
                   selected_categories, skip_scan, error_message
              FROM pentest_runs
             WHERE user_id = %s
             ORDER BY started_at DESC
             LIMIT %s
            """,
            (user_id, int(limit)),
        )
        return [dict(r) for r in cur.fetchall()]
