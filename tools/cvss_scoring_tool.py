"""
cvss_scoring_tool.py

Deterministic CVSS extractor.
Parses security_findings (nmap vulners lines) to build a structured
CVE/CVSS table that is stored in state and passed to the report generator.
"""

import re
from typing import Any, Dict, List

_LINE_RE = re.compile(
    r"(CVE-\d{4}-\d+"
    r"|PACKETSTORM:[A-Z0-9]+"
    r"|EDB-ID:\d+"
    r"|HTTPD:[A-F0-9]+"
    r"|CNVD-\d{4}-\d+"
    r"|[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}"
    r")\s+(\d+(?:\.\d+)?)\s+(https?://\S+)"
)


def _severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def build_cvss_scoring(security_findings: List[str]) -> List[Dict[str, Any]]:
    """
    Parse nmap vulners-format lines into structured CVSS records.
    Returns a list sorted by CVSS score descending, deduplicated by ID.
    """
    records: List[Dict[str, Any]] = []
    seen: set = set()

    for line in security_findings:
        m = _LINE_RE.search(line)
        if not m:
            continue
        vuln_id = m.group(1)
        if vuln_id in seen:
            continue
        seen.add(vuln_id)
        score = float(m.group(2))
        url   = m.group(3).rstrip()
        records.append({
            "id":         vuln_id,
            "cvss":       score,
            "severity":   _severity(score),
            "url":        url,
            "is_exploit": "*EXPLOIT*" in line,
            "is_cve":     vuln_id.startswith("CVE-"),
        })

    records.sort(key=lambda r: r["cvss"], reverse=True)
    return records


def format_cvss_table(records: List[Dict[str, Any]]) -> str:
    """Render a plain-text CVSS table for inclusion in the report."""
    if not records:
        return "(no CVE/CVSS data extracted)"

    cves     = [r for r in records if r["is_cve"]]
    exploits = [r for r in records if r["is_exploit"]]
    misc     = [r for r in records if not r["is_cve"]]

    lines = [
        f"Total vulnerabilities : {len(records)}",
        f"CVEs                  : {len(cves)}",
        f"Non-CVE findings      : {len(misc)}",
        f"Exploit references    : {len(exploits)}",
        f"Highest CVSS score    : {records[0]['cvss']} ({records[0]['severity']})",
        "",
        f"{'ID':<32} {'CVSS':>5}  {'Severity':<12}  {'Exploit?':>8}  CVSS Vector / Description",
        "-" * 110,
    ]
    for r in records[:40]:
        exploit_flag = "YES" if r["is_exploit"] else "-"
        vector = r.get("cvss_vector", "")
        desc   = r.get("description", "")
        detail = vector if vector else (desc[:50] if desc else "")
        detail_col = f"  {detail}" if detail else ""
        lines.append(
            f"{r['id']:<32} {r['cvss']:>5.1f}  {r['severity']:<12}  {exploit_flag:>8}{detail_col}"
        )
    if len(records) > 40:
        lines.append(f"... and {len(records) - 40} more entries")

    return "\n".join(lines)
