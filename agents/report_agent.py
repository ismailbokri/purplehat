
import json
import logging
import os
import pathlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from config import AgentState
from functions import call_llm_prep
from tools.prompt_registry_tool import load_prompt_from_registry, render_template
from tools.generate_report_tool import (
    generate_pdf_report,
    write_text_report,
)
from tools.finding_reporter_tool import read_findings, write_findings_json

load_dotenv()

logger = logging.getLogger(__name__)


# ── Prompt loaders (file-based registry) ──────────────────────────────────────

# Path to the branded template PDF used as a visual background for the
# generated report (cover, repeating inner-page background, back cover).
# Falls back to the standalone layout when the file is missing.
_TEMPLATE_PDF_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "palnner" / "template.pdf"
)

_VULN_PROMPT_NAME    = os.getenv("REPORT_VULN_PROMPT_NAME",    "pentest_report_vuln_detail")
_VULN_PROMPT_VERSION = os.getenv("REPORT_VULN_PROMPT_VERSION", "1")
_SUMMARY_PROMPT_NAME    = os.getenv("REPORT_SUMMARY_PROMPT_NAME",    "pentest_report_exec_summary")
_SUMMARY_PROMPT_VERSION = os.getenv("REPORT_SUMMARY_PROMPT_VERSION", "1")

_VULN_PROMPT_PAYLOAD    = load_prompt_from_registry(_VULN_PROMPT_NAME, _VULN_PROMPT_VERSION)
_SUMMARY_PROMPT_PAYLOAD = load_prompt_from_registry(_SUMMARY_PROMPT_NAME, _SUMMARY_PROMPT_VERSION)

_VULN_TEMPLATE  = _VULN_PROMPT_PAYLOAD.get("template", "")
_VULN_SYSTEM    = _VULN_PROMPT_PAYLOAD["tags"].get("system_prompt", "")
_VULN_SCHEMA    = json.loads(_VULN_PROMPT_PAYLOAD["tags"]["json_schema"])
_SUMMARY_TEMPLATE = _SUMMARY_PROMPT_PAYLOAD.get("template", "")
_SUMMARY_SYSTEM = _SUMMARY_PROMPT_PAYLOAD["tags"].get("system_prompt", "")
_SUMMARY_SCHEMA = json.loads(_SUMMARY_PROMPT_PAYLOAD["tags"]["json_schema"])


# ── Heuristics ────────────────────────────────────────────────────────────────

_BLACKBOX_CATS = {"Découverte", "Pré-authentification", "Reconnaissance"}

# Priority matrix:  (severity, complexity) → implementation priority
_PRIORITY_MATRIX = {
    ("Critical", "Simple"):  "Immediate",
    ("Critical", "Medium"):  "Immediate",
    ("Critical", "Complex"): "Short Term",
    ("High",     "Simple"):  "Immediate",
    ("High",     "Medium"):  "Short Term",
    ("High",     "Complex"): "Short Term",
    ("Medium",   "Simple"):  "Short Term",
    ("Medium",   "Medium"):  "Mid Term",
    ("Medium",   "Complex"): "Mid Term",
    ("Low",      "Simple"):  "Short Term",
    ("Low",      "Medium"):  "Mid Term",
    ("Low",      "Complex"): "Long Term",
}

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _deduplicate_findings(findings: List[dict]) -> List[dict]:
    """Remove duplicate findings, keeping the first (most severe) representative.

    Two findings are duplicates when:
    - They share at least one CVE ID (primary check), OR
    - Their normalized finding text is identical after stripping version numbers
      (fallback for CVE-less findings).

    Assumes findings are already sorted by severity so the best representative
    of each duplicate group is encountered first.
    """
    seen_cves: set = set()
    seen_norm: set = set()
    unique: List[dict] = []
    for f in findings:
        cves = set(f.get("cve") or [])
        if cves and cves & seen_cves:
            logger.info(
                "[dedup] dropping duplicate finding (shared CVE): %s",
                (f.get("finding") or "")[:80],
            )
            continue
        # Normalize: lowercase, strip version numbers and punctuation for a stable key.
        norm = re.sub(r"[\d\.\-]+", " ", (f.get("finding") or "").lower())
        norm = re.sub(r"\s+", " ", norm).strip()[:100]
        if norm and norm in seen_norm:
            logger.info(
                "[dedup] dropping duplicate finding (similar text): %s",
                (f.get("finding") or "")[:80],
            )
            continue
        seen_cves |= cves
        if norm:
            seen_norm.add(norm)
        unique.append(f)
    return unique


def _priority_for(severity: str, complexity: str) -> str:
    sev = severity if severity in {"Critical", "High", "Medium", "Low"} else "Low"
    cmp = complexity if complexity in {"Simple", "Medium", "Complex"} else "Medium"
    return _PRIORITY_MATRIX.get((sev, cmp), "Mid Term")


_BLACKBOX_PHASES = {"discovery", "preauth", "pre-auth", "reconnaissance", "recon"}


def _classify_box(finding: dict) -> str:
    cat = str(finding.get("checklist_category") or "").strip()
    if cat in _BLACKBOX_CATS or cat.lower() in _BLACKBOX_PHASES:
        return "Blackbox"
    phase = str(finding.get("phase") or "").strip().lower()
    return "Blackbox" if phase in _BLACKBOX_PHASES else "Greybox"


def _performed_tests(state: AgentState, all_findings: List[dict]) -> Dict[str, Any]:
    """Categories / test count for the 'Performed tests' section.

    The legacy auto-run filled `prober_plan`; in the tester-driven flow it is
    empty, so derive the overview from the recorded verdicts (all statuses —
    a Not-Vulnerable result is still a performed test).
    """
    plan = state.get("prober_plan") or []
    if plan:
        return {
            "categories_tested": sorted({
                str(p.get("checklist_category") or "").strip()
                for p in plan if p.get("checklist_category")
            }),
            "total_tests": len(plan),
        }
    categories = sorted({
        str(f.get("checklist_category") or "").strip()
        for f in all_findings
        if f.get("checklist_category")
        and not str(f.get("checklist_category")).startswith("manual:")
    })
    test_keys = {
        str(f.get("checklist_test_id") or "") or f"rec:{f.get('finding_id') or id(f)}"
        for f in all_findings
    }
    return {"categories_tested": categories, "total_tests": len(test_keys)}


def _severity_distribution(findings: List[dict]) -> Dict[str, int]:
    dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = str(f.get("severity") or "Informational").strip()
        if sev not in dist:
            sev = "Informational"
        dist[sev] += 1
    return dist


def _overall_rating(dist: Dict[str, int]) -> str:
    """
    Map the severity distribution to an overall security rating.
      Low           — Critical vulnerabilities present.
      Below Average — 2+ High or many Medium findings.
      Average       — 1 High or several Medium findings.
      Normal        — Only Low/Medium findings present.
      Good          — No confirmed findings.
    """
    if dist.get("Critical", 0) >= 1:
        return "Low"
    if dist.get("High", 0) >= 2 or dist.get("Medium", 0) >= 5:
        return "Below Average"
    if dist.get("High", 0) >= 1 or dist.get("Medium", 0) >= 3:
        return "Average"
    if dist.get("Medium", 0) >= 1 or dist.get("Low", 0) >= 1:
        return "Normal"
    return "Good"


def _affected_target(finding: dict, default_target: str) -> str:
    """Prefer a concrete URL or endpoint from the finding's PoC command."""
    pc = finding.get("proof_of_concept") or {}
    cmd = str(pc.get("command") or finding.get("command") or "")
    url = re.search(r"https?://\S+", cmd)
    if url:
        return url.group(0).rstrip(".,);")
    endpoint = finding.get("endpoint")
    if endpoint:
        return f"{default_target} {endpoint}"
    return default_target or "unknown"


# ── LLM helpers ───────────────────────────────────────────────────────────────

def _gen_vuln_detail(finding: dict, target: str, idx: int) -> dict:
    poc = finding.get("proof_of_concept") or {}
    user_msg = render_template(_VULN_TEMPLATE, {
        "target": target,
        "category": str(
            finding.get("checklist_category")
            or finding.get("owasp_category")
            or "Web Application"
        ),
        "finding_id": str(finding.get("finding_id") or "?"),
        "severity": str(finding.get("severity") or "Informational"),
        "cvss": str(finding.get("cvss") if finding.get("cvss") is not None else "N/A"),
        "cvss_vector": str(finding.get("cvss_vector") or ""),
        "cves": ", ".join(finding.get("cve") or []) or "None",
        "original": str(finding.get("finding") or finding.get("test_description") or ""),
        "evidence": str(poc.get("output_snippet") or "(no evidence captured)")[:1500],
    })
    try:
        return call_llm_prep(
            [
                {"role": "system", "content": _VULN_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            _VULN_SCHEMA,
        )
    except Exception as exc:
        logger.warning("[report_node] vuln-detail LLM failed for #%d: %s", idx, exc)
        return {
            "title": (finding.get("finding") or "Finding")[:80],
            "description": finding.get("finding") or "",
            "recommendation_steps": ["Review and remediate the identified issue."],
            "type": "Technical",
            "complexity": "Medium",
        }


def _gen_exec_summary(
    target: str,
    state: AgentState,
    dist: Dict[str, int],
    total: int,
    rating: str,
) -> dict:
    user_msg = render_template(_SUMMARY_TEMPLATE, {
        "target": target,
        "web_tech": ", ".join(state.get("web_technologies", []) or []) or "N/A",
        "services": ", ".join(state.get("services", []) or []) or "N/A",
        "ports": ", ".join(str(p) for p in (state.get("open_ports", []) or [])) or "N/A",
        "total": total,
        "critical": dist.get("Critical", 0),
        "high": dist.get("High", 0),
        "medium": dist.get("Medium", 0),
        "low": dist.get("Low", 0),
        "rating": rating,
    })
    try:
        return call_llm_prep(
            [
                {"role": "system", "content": _SUMMARY_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            _SUMMARY_SCHEMA,
        )
    except Exception as exc:
        logger.warning("[report_node] exec-summary LLM failed: %s", exc)
        return {
            "project_context":
                f"This document presents the results of the web-application "
                f"penetration test conducted against {target}.",
            "audit_objectives":
                "Identify exploitable vulnerabilities, evaluate their criticality, "
                "and provide actionable remediation guidance.",
            "rating_justification":
                f"The overall security rating is {rating} based on the distribution "
                f"of confirmed findings ({total} total).",
            "document_structure":
                "The document is structured into a Preface, a Summary, an overview "
                "of performed tests, detailed vulnerability findings, and appendices.",
        }


# ── Main node ─────────────────────────────────────────────────────────────────

def report_node(state: AgentState, findings: Optional[List[dict]] = None) -> dict:
    """Build the text + PDF report.

    ``findings`` — the records to report on. The session flow passes the
    session's findings loaded from Postgres (the source of truth for every
    tester save path). When omitted, falls back to the legacy per-target JSONL.
    """
    print("[report_node] Generating penetration test report...")

    target = state.get("target", "unknown")

    # 1) Load findings and refresh the consolidated findings.json snapshot.
    if findings is not None:
        all_findings = list(findings)
        print(f"[report_node] using {len(all_findings)} finding(s) supplied by caller (DB)")
    else:
        all_findings = read_findings(target)
        print(f"[report_node] using {len(all_findings)} finding(s) from legacy JSONL")
    try:
        findings_json_path = write_findings_json(target, records=all_findings)
        print(f"[report_node] findings.json → {findings_json_path}")
    except Exception as exc:
        logger.warning("[report_node] write_findings_json failed: %s", exc)
        findings_json_path = None

    # 2) Keep only confirmed findings; sort by severity then deduplicate.
    confirmed = [f for f in all_findings if f.get("test_status") == "found"]
    confirmed.sort(key=lambda f: _SEVERITY_ORDER.get(
        str(f.get("severity") or "Informational"), 9
    ))
    before_dedup = len(confirmed)
    confirmed = _deduplicate_findings(confirmed)

    print(f"[report_node] {len(all_findings)} record(s) total — "
          f"{before_dedup} confirmed, {len(confirmed)} after dedup.")

    # 3) Severity distribution + overall rating.
    dist = _severity_distribution(confirmed)
    rating = _overall_rating(dist)
    print(f"[report_node] distribution={dist}  rating={rating}")

    # 4) Generate per-vulnerability detail blocks via the vuln-detail LLM prompt.
    vulnerabilities: List[Dict[str, Any]] = []
    for idx, finding in enumerate(confirmed, start=1):
        vuln_id = f"V_{idx:03d}"
        print(f"  [{vuln_id}] severity={finding.get('severity')} "
              f"category={finding.get('checklist_category')}")
        detail = _gen_vuln_detail(finding, target, idx)
        complexity = str(detail.get("complexity") or "Medium")
        severity = str(finding.get("severity") or "Informational")
        priority = _priority_for(severity, complexity)
        vulnerabilities.append({
            "vuln_id":               vuln_id,
            "title":                 str(detail.get("title") or "Finding"),
            "box_category":          _classify_box(finding),
            "severity":              severity,
            "status":                "Unsolved",
            "cvss_score":            finding.get("cvss") if finding.get("cvss") is not None else "N/A",
            "cvss_vector":           str(finding.get("cvss_vector") or ""),
            "affected_target":       _affected_target(finding, target),
            "description":           str(detail.get("description") or ""),
            "recommendation_steps":  list(detail.get("recommendation_steps") or []),
            "type":                  str(detail.get("type") or "Technical"),
            "complexity":            complexity,
            "priority":              priority,
            "evidence":              str((finding.get("proof_of_concept") or {}).get("output_snippet") or ""),
            "cve":                   list(finding.get("cve") or []),
            "checklist_test_id":     str(finding.get("checklist_test_id") or ""),
            "checklist_category":    str(finding.get("checklist_category") or ""),
            "owasp_id":              str(finding.get("owasp_id") or ""),
        })

    # 5) Generate executive summary via the exec-summary LLM prompt.
    summary = _gen_exec_summary(target, state, dist, len(confirmed), rating)

    # 6) Assemble the report payload.
    report_data = {
        "target":      target,
        "report_date": datetime.now().strftime("%B %d, %Y"),
        "scope":       [target],
        "preface": {
            "project_context":     summary.get("project_context", ""),
            "audit_objectives":    summary.get("audit_objectives", ""),
            "document_structure":  summary.get("document_structure", ""),
            "notes": [
                "All passwords identified during these tests are masked in screenshots "
                "and replaced by the character string \"******\" in the text.",
                "All recommendations issued must be tested in a staging environment "
                "before being implemented in production.",
            ],
        },
        "system_info": {
            "os":               state.get("os") or "N/A",
            "open_ports":       state.get("open_ports") or [],
            "services":         state.get("services") or [],
            "web_technologies": state.get("web_technologies") or [],
            "directories":      state.get("directories") or [],
            "auth_status":      state.get("auth_status") or "N/A",
        },
        "summary": {
            "rating":               rating,
            "rating_justification": summary.get("rating_justification", ""),
            "distribution":         dist,
            "total_findings":       len(confirmed),
        },
        "performed_tests": _performed_tests(state, all_findings),
        "vulnerabilities":  vulnerabilities,
    }

    # 7) Render text + PDF.
    print("[report_node] Writing text report...")
    text_path = write_text_report(report_data)
    print(f"[report_node] Text  → {text_path}")

    print("[report_node] Generating PDF...")
    template_arg = str(_TEMPLATE_PDF_PATH) if _TEMPLATE_PDF_PATH.exists() else None
    if template_arg:
        print(f"[report_node] Using template background → {template_arg}")
    pdf_path = generate_pdf_report(report_data, template_pdf_path=template_arg)
    print(f"[report_node] PDF   → {pdf_path}")

    return {
        "report_data":           report_data,
        "report_sections":        {},  # kept for backward-compat with downstream readers
        "final_report_text_path": text_path,
        "final_report_pdf_path":  pdf_path,
        "findings_json_path":     str(findings_json_path) if findings_json_path else None,
    }


# ── On-demand report (modular UI: "Create Report" button) ───────────────────

def generate_report_for_session(
    session_state: dict,
    *,
    findings: Optional[List[dict]] = None,
    progress_cb=None,
) -> dict:
    """Render a PDF report from the cumulative session state at any time.

    The modular UI lets users click "Create Report" before the workflow is
    complete. Findings are read from disk (the same JSONL the legacy pipeline
    writes incrementally), so the report reflects exactly what the user has
    collected so far across module runs in the session.

    `progress_cb` (optional) is called as `progress_cb(stage, detail)` to emit
    WebSocket updates while the LLM detail prompt runs for each finding.
    """
    state_in: AgentState = dict(session_state) if session_state else {}
    if progress_cb is not None:
        progress_cb("start", {"target": state_in.get("target")})
    try:
        result = report_node(state_in, findings=findings)
    finally:
        if progress_cb is not None:
            progress_cb("complete", {})
    return result
