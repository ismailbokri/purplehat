import logging
import os
import re
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.colors import HexColor, white
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False

logger = logging.getLogger(__name__)

REPORT_DIR = Path(__file__).parent.parent / "reports"


def ensure_report_dir() -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return REPORT_DIR


def _safe_name(target: str) -> str:
    return re.sub(r'[^\w\-]', '_', target)[:40].strip('_') or "target"


# Characters outside Latin-1 that Helvetica cannot render — map to safe equivalents.
_UNICODE_MAP = {
    '—': '--',   '–': '-',    '‒': '-',
    '‑': '-',    '‐': '-',    '­': '',     # hyphens / dashes / soft-hyphen
    '‘': "'",    '’': "'",    '‚': "'",    # single curly quotes
    '“': '"',    '”': '"',    '„': '"',    # double curly quotes
    '…': '...',  '•': '-',    '●': '-',    # ellipsis, bullets
    ' ': ' ',    ' ': ' ',    ' ': ' ',    # non-breaking / narrow spaces
    '→': '->',   '←': '<-',   '⇒': '=>',   # arrows
    '×': 'x',    '÷': '/',                      # math operators
    '′': "'",    '″': '"',                      # prime symbols
    '«': '"',    '»': '"',                      # guillemets
    '‹': "'",    '›': "'",                      # single guillemets
    '†': '+',    '‡': '+',                      # daggers
    '·': '.',    '‧': '.',                      # middle dots
}


def _clean(text: str) -> str:
    """Replace non-Latin-1 Unicode chars so Helvetica renders them correctly."""
    for char, repl in _UNICODE_MAP.items():
        text = text.replace(char, repl)
    # Silently drop any remaining characters outside Latin-1
    return text.encode('latin-1', errors='replace').decode('latin-1')


def _esc(text: str) -> str:
    text = _clean(str(text))
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ══════════════════════════════════════════════════════════════════════════════
# Structured report (Web Application Penetration Test Report layout)
# ══════════════════════════════════════════════════════════════════════════════

# Severity → display colour used in cards and tables.
_SEVERITY_COLOR = {
    "Critical":      HexColor("#7B1A1A") if _REPORTLAB else None,
    "High":          HexColor("#C0392B") if _REPORTLAB else None,
    "Medium":        HexColor("#E67E22") if _REPORTLAB else None,
    "Low":           HexColor("#27AE60") if _REPORTLAB else None,
    "Informational": HexColor("#7F8C8D") if _REPORTLAB else None,
}

# Report accent colours
_REPORT_DARK = HexColor("#1B2A4A") if _REPORTLAB else None
_REPORT_MID  = HexColor("#2E5090") if _REPORTLAB else None
_REPORT_ACC  = HexColor("#E84040") if _REPORTLAB else None


def _report_styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "TLCoverTitle", parent=base["Heading1"], fontSize=24, leading=30,
            textColor=white, alignment=TA_CENTER, fontName="Helvetica-Bold",
        ),
        "cover_sub": ParagraphStyle(
            "TLCoverSub", parent=base["Normal"], fontSize=12, leading=16,
            textColor=HexColor("#CCCCCC"), alignment=TA_CENTER,
        ),
        "h1": ParagraphStyle(
            "TLH1", parent=base["Heading1"], fontSize=16, leading=20,
            textColor=white, fontName="Helvetica-Bold", spaceAfter=0,
        ),
        "h2": ParagraphStyle(
            "TLH2", parent=base["Heading2"], fontSize=13, leading=17,
            textColor=_REPORT_DARK, fontName="Helvetica-Bold",
            spaceBefore=12, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "TLH3", parent=base["Heading3"], fontSize=11, leading=15,
            textColor=_REPORT_MID, fontName="Helvetica-Bold",
            spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "TLBody", parent=base["Normal"], fontSize=9.5, leading=14,
            textColor=HexColor("#222222"), alignment=TA_JUSTIFY, spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "TLBullet", parent=base["Normal"], fontSize=9.5, leading=14,
            textColor=HexColor("#222222"), leftIndent=14, bulletIndent=4, spaceAfter=2,
        ),
        "field_label": ParagraphStyle(
            "TLFieldLabel", parent=base["Normal"], fontSize=9.5, leading=13,
            textColor=_REPORT_DARK, fontName="Helvetica-Bold",
        ),
        "field_value": ParagraphStyle(
            "TLFieldValue", parent=base["Normal"], fontSize=9.5, leading=13,
            textColor=HexColor("#222222"),
        ),
        "evidence": ParagraphStyle(
            "TLEvidence", parent=base["Normal"], fontSize=8.5, leading=11,
            textColor=HexColor("#222222"), fontName="Courier",
            backColor=HexColor("#F5F5F5"), leftIndent=6, rightIndent=6,
            spaceBefore=4, spaceAfter=4,
        ),
        "caption": ParagraphStyle(
            "TLCaption", parent=base["Normal"], fontSize=8.5, leading=11,
            textColor=HexColor("#666666"), alignment=TA_CENTER,
            spaceBefore=2, spaceAfter=8, fontName="Helvetica-Oblique",
        ),
    }


def _section_banner(title: str, styles: dict):
    """Coloured banner used to introduce numbered sections."""
    tbl = Table([[Paragraph(_esc(title), styles["h1"])]], colWidths=[17 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _REPORT_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
    ]))
    return tbl


def _kv_table(rows: list, col_widths=(4.5 * cm, 12.5 * cm)) -> Table:
    """Two-column key/value table used by Classification / Change History / Scope."""
    tbl = Table(rows, colWidths=list(col_widths))
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (0, -1), HexColor("#E8EEF7")),
        ("TEXTCOLOR",      (0, 0), (0, -1), _REPORT_DARK),
        ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _distribution_table(dist: dict) -> Table:
    """Severity distribution as a small table."""
    header = ["Critical", "High", "Medium", "Low", "Informational"]
    values = [str(dist.get(k, 0)) for k in header]
    tbl = Table([header, values], colWidths=[3.4 * cm] * 5)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9.5),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",       (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    for col_idx, sev in enumerate(header):
        colour = _SEVERITY_COLOR.get(sev, HexColor("#888888"))
        style_cmds.append(("TEXTCOLOR", (col_idx, 1), (col_idx, 1), colour))
        style_cmds.append(("FONTNAME",  (col_idx, 1), (col_idx, 1), "Helvetica-Bold"))
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


def _vuln_summary_table(vulnerabilities: list) -> Table:
    """
    Detailed summary table — one row per vulnerability with the columns the
    report layout uses on Table 7 (Vulnerabilities Summary).

    Column widths sum to exactly 17 cm (A4 content width with 2 cm margins).
    Cells use Paragraph objects so text wraps instead of overflowing.
    """
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    _hdr_s = ParagraphStyle(
        "VSTHdr", fontSize=8, leading=10,
        textColor=white, fontName="Helvetica-Bold", alignment=TA_LEFT,
    )
    _cell_s = ParagraphStyle(
        "VSTCell", fontSize=7.5, leading=10,
        textColor=HexColor("#222222"), alignment=TA_LEFT,
    )
    _risk_s = ParagraphStyle(
        "VSTRisk", fontSize=7.5, leading=10,
        textColor=white, fontName="Helvetica-Bold", alignment=TA_CENTER,
    )

    def _p(text, style):
        return Paragraph(_esc(str(text)), style)

    header = [
        _p("Ref.",            _hdr_s),
        _p("Affected Target", _hdr_s),
        _p("Vulnerability",   _hdr_s),
        _p("Risk",            _hdr_s),
        _p("Type",            _hdr_s),
        _p("Recommendation",  _hdr_s),
        _p("Complexity",      _hdr_s),
        _p("Priority",        _hdr_s),
    ]
    rows = [header]
    for v in vulnerabilities:
        rec_first = (v.get("recommendation_steps") or [""])[0]
        rec_first = (rec_first[:160] + "...") if len(rec_first) > 160 else rec_first
        rows.append([
            _p(v.get("vuln_id", "?"),                       _cell_s),
            _p((v.get("affected_target") or "")[:50],       _cell_s),
            _p((v.get("title") or "")[:70],                 _cell_s),
            _p(v.get("severity", "?"),                      _risk_s),
            _p(v.get("type", "?"),                          _cell_s),
            _p(rec_first or "(see detail page)",            _cell_s),
            _p(v.get("complexity", "?"),                    _cell_s),
            _p(v.get("priority", "?"),                      _cell_s),
        ])

    # Widths must sum to 17.0 cm (A4 with 2 cm left+right margins).
    col_widths = [1.0*cm, 2.7*cm, 3.6*cm, 1.5*cm, 1.8*cm, 4.0*cm, 1.2*cm, 1.2*cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",          (3, 0), (3, -1),  "CENTER"),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.3, HexColor("#CCCCCC")),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
    ]
    # Per-row severity background on the Risk column (text color is in _risk_s).
    for r_idx, v in enumerate(vulnerabilities, start=1):
        colour = _SEVERITY_COLOR.get(v.get("severity"), HexColor("#888888"))
        style_cmds.append(("BACKGROUND", (3, r_idx), (3, r_idx), colour))

    tbl.setStyle(TableStyle(style_cmds))
    return tbl


def _vuln_detail_block(v: dict, styles: dict, story: list) -> None:
    """
    Render one vulnerability detail block in the report format:

        V_xxx — TITLE                            ← Heading3
        ┌─────────────┬─────────────┬───────────┐
        │ Risk        │ Status      │ CVSS      │
        │ {severity}  │ {status}    │ {score}   │
        └─────────────┴─────────────┴───────────┘
        Affected target: {target}
        Description:     {description}
        Recommendation:  {numbered steps}
        Type: {type}    Complexity: {complexity}    Priority: {priority}
        CVSS Vector:     {vector}
        Proof of Concept (Evidence): {evidence block}

    Note: the "Risk scenario" field is intentionally omitted per stakeholder request.
    """
    title = f"{v.get('vuln_id', '?')} — {(v.get('title') or 'Finding').upper()}"
    story.append(Paragraph(_esc(title), styles["h3"]))

    severity = v.get("severity", "?")
    sev_color = _SEVERITY_COLOR.get(severity, HexColor("#888888"))
    cvss = v.get("cvss_score", "N/A")

    rh = Table(
        [
            ["Risk", "Status", "CVSS Score"],
            [str(severity), str(v.get("status", "Unsolved")), str(cvss)],
        ],
        colWidths=[5.7 * cm, 5.7 * cm, 5.6 * cm],
    )
    rh.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("BACKGROUND",     (0, 1), (0, 1),   sev_color),
        ("TEXTCOLOR",      (0, 1), (0, 1),   white),
        ("FONTNAME",       (0, 1), (-1, 1),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    story.append(rh)
    story.append(Spacer(1, 0.25 * cm))

    # Affected target
    story.append(Paragraph(
        f"<b>Affected target:</b> {_esc(v.get('affected_target', '-'))}",
        styles["body"],
    ))
    # Description
    story.append(Paragraph("<b>Description:</b>", styles["body"]))
    story.append(Paragraph(_esc(v.get("description", "")), styles["body"]))

    # Recommendation
    story.append(Paragraph("<b>Recommendation:</b>", styles["body"]))
    story.append(Paragraph("It is recommended to:", styles["body"]))
    for i, step in enumerate(v.get("recommendation_steps", []) or [], start=1):
        story.append(Paragraph(f"{i}. {_esc(step)}", styles["bullet"]))

    # Type / Complexity / Priority — single-row layout
    tcp = Table(
        [[
            Paragraph(f"<b>Type:</b> {_esc(v.get('type', '-'))}", styles["field_value"]),
            Paragraph(f"<b>Complexity:</b> {_esc(v.get('complexity', '-'))}", styles["field_value"]),
            Paragraph(f"<b>Priority:</b> {_esc(v.get('priority', '-'))}", styles["field_value"]),
        ]],
        colWidths=[5.7 * cm, 5.7 * cm, 5.6 * cm],
    )
    tcp.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#F0F4FA")),
        ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#CCCCCC")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(Spacer(1, 0.15 * cm))
    story.append(tcp)

    # CVSS vector
    vector = v.get("cvss_vector", "")
    if vector:
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph(f"<b>CVSS Vector:</b> {_esc(vector)}", styles["body"]))

    # CVE references
    cves = v.get("cve") or []
    if cves:
        story.append(Paragraph(f"<b>CVE:</b> {_esc(', '.join(cves))}", styles["body"]))

    # Proof of Concept
    evidence = v.get("evidence", "") or "(no evidence captured)"
    story.append(Paragraph("<b>Proof of Concept (Evidence):</b>", styles["body"]))
    # Truncate evidence display to 1500 chars to keep layout clean
    if len(evidence) > 1500:
        evidence = evidence[:1500] + "\n... (truncated)"
    for line in evidence.splitlines() or [evidence]:
        story.append(Paragraph(_esc(line) or "&nbsp;", styles["evidence"]))


def write_text_report(report_data: dict) -> str:
    """
    Write the same payload as `generate_pdf_report` to a plain-text file.
    Kept for downstream tools that only consume text.
    """
    ensure_report_dir()
    target = report_data.get("target", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"pentest_report_{_safe_name(target)}_{ts}.txt"

    sep_eq = "=" * 80
    sep_dash = "-" * 80
    lines: list = []

    # Cover
    lines += [
        sep_eq,
        "WEB APPLICATION PENETRATION TEST REPORT",
        f"Target : {target}",
        f"Date   : {report_data.get('report_date', '')}",
        "Classification : CONFIDENTIAL — TLP: RED",
        sep_eq,
        "",
    ]

    # Section 1 — Preface
    pref = report_data.get("preface") or {}
    lines += [
        "1. PREFACE",
        sep_dash,
        "1.1 Project Context",
        pref.get("project_context", ""),
        "",
        "1.2 Audit Objectives",
        pref.get("audit_objectives", ""),
        "",
        "1.3 Scope of Testing",
        *[f"  - {s}" for s in report_data.get("scope", [])],
        "",
        "1.4 Document Structure",
        pref.get("document_structure", ""),
        "",
        "1.5 Notes",
        *[f"  - {n}" for n in pref.get("notes", [])],
        "",
    ]

    # Section 2 — Summary
    summ = report_data.get("summary") or {}
    dist = summ.get("distribution") or {}
    lines += [
        "2. SUMMARY",
        sep_dash,
        "2.1 General Summary",
        f"Overall security level: {summ.get('rating', '?')}",
        summ.get("rating_justification", ""),
        "",
        "Distribution of vulnerabilities by criticality:",
        f"  Critical: {dist.get('Critical', 0)}  "
        f"High: {dist.get('High', 0)}  "
        f"Medium: {dist.get('Medium', 0)}  "
        f"Low: {dist.get('Low', 0)}  "
        f"Informational: {dist.get('Informational', 0)}",
        "",
        "2.2 Detailed Summary",
    ]
    if report_data.get("vulnerabilities"):
        lines.append(f"{'Ref.':<7}{'Severity':<15}{'Type':<16}{'Complexity':<12}{'Priority':<14}Title")
        lines.append(sep_dash)
        for v in report_data["vulnerabilities"]:
            lines.append(
                f"{v.get('vuln_id', '?'):<7}{v.get('severity', '?'):<15}"
                f"{v.get('type', '?'):<16}{v.get('complexity', '?'):<12}"
                f"{v.get('priority', '?'):<14}{(v.get('title') or '')[:60]}"
            )
    else:
        lines.append("(no confirmed vulnerabilities)")
    lines.append("")

    # Section 3 — Performed tests & conditions
    sysinfo = report_data.get("system_info") or {}
    perf = report_data.get("performed_tests") or {}
    lines += [
        "3. PERFORMED TESTS AND FINDINGS",
        sep_dash,
        "3.1 Overview of Performed Tests",
        f"  Categories tested : {', '.join(perf.get('categories_tested') or []) or 'N/A'}",
        f"  Total tests dispatched : {perf.get('total_tests', 0)}",
        "",
        "3.2 Testing Conditions",
        f"  Target          : {target}",
        f"  OS              : {sysinfo.get('os', 'N/A')}",
        f"  Open ports      : {', '.join(str(p) for p in sysinfo.get('open_ports', []) or []) or 'N/A'}",
        f"  Services        : {', '.join(sysinfo.get('services', []) or []) or 'N/A'}",
        f"  Web technologies: {', '.join(sysinfo.get('web_technologies', []) or []) or 'N/A'}",
        f"  Auth status     : {sysinfo.get('auth_status', 'N/A')}",
        "",
    ]

    # Section 4 — Vulnerability details
    lines += ["4. DETAILS OF THE TESTS PERFORMED", sep_dash]
    blackbox = [v for v in report_data.get("vulnerabilities", []) if v.get("box_category") == "Blackbox"]
    greybox  = [v for v in report_data.get("vulnerabilities", []) if v.get("box_category") == "Greybox"]
    for group_label, group in [("4.1 Web Application Pentest: Blackbox Vulnerabilities", blackbox),
                                ("4.2 Web Application Pentest: Greybox Vulnerabilities",  greybox)]:
        if not group:
            continue
        lines += ["", group_label, ""]
        for v in group:
            lines += [
                f"{v.get('vuln_id', '?')} — {(v.get('title') or '').upper()}",
                sep_dash,
                f"  Risk            : {v.get('severity', '-')}",
                f"  Status          : {v.get('status', '-')}",
                f"  CVSS Score      : {v.get('cvss_score', '-')}",
                f"  Affected target : {v.get('affected_target', '-')}",
                "",
                "  Description:",
                f"    {v.get('description', '')}",
                "",
                "  Recommendation — It is recommended to:",
            ]
            for i, step in enumerate(v.get("recommendation_steps") or [], start=1):
                lines.append(f"    {i}. {step}")
            lines += [
                "",
                f"  Type        : {v.get('type', '-')}",
                f"  Complexity  : {v.get('complexity', '-')}",
                f"  Priority    : {v.get('priority', '-')}",
                f"  CVSS Vector : {v.get('cvss_vector', '-')}",
            ]
            if v.get("cve"):
                lines.append(f"  CVE         : {', '.join(v.get('cve'))}")
            lines += ["", "  Proof of Concept (Evidence):"]
            for ln in (v.get("evidence") or "(no evidence)").splitlines():
                lines.append(f"      {ln}")
            lines += ["", sep_dash, ""]

    # Appendix — Vulnerability classification reference
    lines += [
        "APPENDIX A — Vulnerability classification reference",
        sep_dash,
        "  CVSS Score range  Level",
        "  0.1 - 3.9         Low",
        "  4.0 - 6.9         Medium",
        "  7.0 - 8.9         High",
        "  9.0 - 10.0        Critical",
        "",
        "  Vulnerability types:",
        "    - Technical     : flaw in code or protocol implementation",
        "    - Configuration : insecure setting on equipment / service",
        "    - Organizational: process or governance gap",
        "",
        "  Implementation complexity:",
        "    - Simple : configuration tweak",
        "    - Medium : code change or reconfiguration",
        "    - Complex: architecture change",
        "",
        "  Implementation priority:",
        "    - Immediate : within 1 month",
        "    - Short Term: 1 to 3 months",
        "    - Mid Term  : 3 to 6 months",
        "    - Long Term : > 6 months",
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def _build_report_story(
    report_data: dict,
    styles: dict,
    include_cover: bool = True,
    include_doc_info: bool = True,
) -> list:
    """
    Build the full report story (list of reportlab flowables) used by both the
    standalone PDF generator and the template-overlay generator. Flags allow
    callers to skip the cover (when a template PDF supplies one) or the document
    info tables.
    """
    target = report_data.get("target", "unknown")
    story: list = []

    # ── Cover page ────────────────────────────────────────────────────────────
    if include_cover:
        story.append(Spacer(1, 3 * cm))
        cover = Table(
            [[Paragraph("WEB APPLICATION PENETRATION TEST REPORT", styles["cover_title"])]],
            colWidths=[17 * cm],
        )
        cover.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _REPORT_DARK),
            ("TOPPADDING",    (0, 0), (-1, -1), 26),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 26),
        ]))
        story.append(cover)
        story.append(HRFlowable(width="100%", thickness=4, color=_REPORT_ACC))
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(f"<b>Target System :</b> {_esc(target)}", styles["cover_sub"]))
        story.append(Paragraph(
            f"<b>Report Date :</b> {_esc(report_data.get('report_date', ''))}",
            styles["cover_sub"],
        ))
        story.append(Paragraph("<b>Classification :</b> CONFIDENTIAL", styles["cover_sub"]))
        story.append(Paragraph("<b>TLP :</b> RED", styles["cover_sub"]))
        story.append(PageBreak())

    # ── Information / Classification table ────────────────────────────────────
    if include_doc_info:
        story.append(Paragraph("Information / Classification", styles["h2"]))
        story.append(_kv_table([
            ["Title",           "Web Application Penetration Test Report"],
            ["Reference",       f"WAPT-{_safe_name(target).upper()}-{datetime.now().strftime('%Y%m%d')}"],
            ["Classification",  "Confidential Document"],
            ["Document Owner",  "Automated Pentest Pipeline"],
            ["Generated",       report_data.get("report_date", "")],
        ]))
        story.append(Paragraph("Table 1: Document Classification", styles["caption"]))

        story.append(Paragraph("Change History", styles["h2"]))
        story.append(_kv_table(
            [
                ["Version", "1.0"],
                ["Date",    report_data.get("report_date", "")],
                ["Author",  "Automated Pentest Pipeline"],
                ["Changes", "Initial automated generation"],
            ],
        ))
        story.append(Paragraph("Table 2: Change History", styles["caption"]))
        story.append(PageBreak())

    # ── Section 1 — Preface ───────────────────────────────────────────────────
    pref = report_data.get("preface") or {}
    story.append(_section_banner("1. Preface", styles))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("1.1 Project Context", styles["h2"]))
    story.append(Paragraph(_esc(pref.get("project_context", "")), styles["body"]))

    story.append(Paragraph("1.2 Audit Objectives", styles["h2"]))
    story.append(Paragraph(_esc(pref.get("audit_objectives", "")), styles["body"]))

    story.append(Paragraph("1.3 Scope of Testing", styles["h2"]))
    story.append(Paragraph(
        "The following targets were covered under the security audit:",
        styles["body"],
    ))
    scope_rows = [["Scope"]] + [[s] for s in (report_data.get("scope") or [target])]
    scope_tbl = Table(scope_rows, colWidths=[17 * cm])
    scope_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 10),
    ]))
    story.append(scope_tbl)
    story.append(Paragraph("Table 3: Scope", styles["caption"]))

    story.append(Paragraph("1.4 Document Structure", styles["h2"]))
    story.append(Paragraph(_esc(pref.get("document_structure", "")), styles["body"]))

    story.append(Paragraph("1.5 Notes", styles["h2"]))
    for note in pref.get("notes", []) or []:
        story.append(Paragraph(f"• {_esc(note)}", styles["bullet"]))
    story.append(PageBreak())

    # ── Section 2 — Summary ──────────────────────────────────────────────────
    summ = report_data.get("summary") or {}
    dist = summ.get("distribution") or {}
    story.append(_section_banner("2. Summary", styles))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("2.1 General Summary", styles["h2"]))
    story.append(Paragraph(
        f"The audit raised an overall level of security qualified as "
        f"<b>{_esc(summ.get('rating', '?'))}</b>.",
        styles["body"],
    ))
    story.append(Paragraph(_esc(summ.get("rating_justification", "")), styles["body"]))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "The table below shows the distribution of vulnerabilities by level of "
        "criticality:",
        styles["body"],
    ))
    story.append(_distribution_table(dist))
    story.append(Paragraph(
        "Figure 1: Distribution of vulnerabilities by criticality",
        styles["caption"],
    ))

    story.append(Paragraph("2.2 Detailed Summary", styles["h2"]))
    if report_data.get("vulnerabilities"):
        story.append(Paragraph(
            "The following table shows all the vulnerabilities detected during "
            "this audit, as well as the recommendations suggested.",
            styles["body"],
        ))
        story.append(_vuln_summary_table(report_data["vulnerabilities"]))
        story.append(Paragraph("Table 7: Vulnerabilities Summary", styles["caption"]))
    else:
        story.append(Paragraph(
            "No confirmed vulnerabilities were identified during this audit.",
            styles["body"],
        ))
    story.append(PageBreak())

    # ── Section 3 — Performed tests + Testing conditions ──────────────────────
    sysinfo = report_data.get("system_info") or {}
    perf = report_data.get("performed_tests") or {}
    story.append(_section_banner("3. Performed Tests and Findings", styles))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("3.1 Overview of Performed Tests", styles["h2"]))
    cats = perf.get("categories_tested") or []
    overview_rows = [["Test Group", "Coverage"]]
    if cats:
        for c in cats:
            overview_rows.append([c, "Automated checks + LLM analysis"])
    else:
        overview_rows.append(["(no categories recorded)", "-"])
    ov_tbl = Table(overview_rows, colWidths=[8.5 * cm, 8.5 * cm])
    ov_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
    ]))
    story.append(ov_tbl)
    story.append(Paragraph("Table 8: Summary of tests performed", styles["caption"]))

    story.append(Paragraph("3.2 Testing Conditions", styles["h2"]))
    cond_rows = [
        ["Field", "Value"],
        ["Target",            target],
        ["OS",                sysinfo.get("os", "N/A")],
        ["Open ports",        ", ".join(str(p) for p in (sysinfo.get("open_ports") or [])) or "N/A"],
        ["Services",          ", ".join(sysinfo.get("services") or []) or "N/A"],
        ["Web technologies",  ", ".join(sysinfo.get("web_technologies") or []) or "N/A"],
        ["Authentication",    sysinfo.get("auth_status") or "N/A"],
        ["Service",           "Web Application Penetration Test"],
    ]
    cond_tbl = Table(cond_rows, colWidths=[4.5 * cm, 12.5 * cm])
    cond_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
    ]))
    story.append(cond_tbl)
    story.append(Paragraph("Table 9: Test conditions", styles["caption"]))
    story.append(PageBreak())

    # ── Section 4 — Vulnerability details ────────────────────────────────────
    story.append(_section_banner("4. Details of the Tests Performed", styles))
    story.append(Spacer(1, 0.3 * cm))

    vulns = report_data.get("vulnerabilities") or []
    blackbox = [v for v in vulns if v.get("box_category") == "Blackbox"]
    greybox  = [v for v in vulns if v.get("box_category") == "Greybox"]

    if blackbox:
        story.append(Paragraph("4.1 Web Application Pentest: Blackbox Vulnerabilities", styles["h2"]))
        for v in blackbox:
            _vuln_detail_block(v, styles, story)
            story.append(Spacer(1, 0.4 * cm))
        story.append(PageBreak())

    if greybox:
        story.append(Paragraph("4.2 Web Application Pentest: Greybox Vulnerabilities", styles["h2"]))
        for v in greybox:
            _vuln_detail_block(v, styles, story)
            story.append(Spacer(1, 0.4 * cm))
        story.append(PageBreak())

    if not vulns:
        story.append(Paragraph(
            "No confirmed vulnerabilities were identified — the section above lists "
            "all tests performed and confirms the absence of exploitable findings "
            "across the tested surface.",
            styles["body"],
        ))
        story.append(PageBreak())

    # ── Appendix — Vulnerability classification reference ─────────────────────
    story.append(_section_banner("Appendices", styles))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Appendix A — Vulnerability Classification & Risk Analysis", styles["h2"]))

    story.append(Paragraph("CVSS Score → Criticality Level", styles["h3"]))
    cvss_rows = [
        ["CVSS Score range", "Level"],
        ["0.1 – 3.9",        "Low"],
        ["4.0 – 6.9",        "Medium"],
        ["7.0 – 8.9",        "High"],
        ["9.0 – 10.0",       "Critical"],
    ]
    cvss_tbl = Table(cvss_rows, colWidths=[6.0 * cm, 11.0 * cm])
    cvss_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    story.append(cvss_tbl)
    story.append(Paragraph("Table 10: Level distribution", styles["caption"]))

    story.append(Paragraph("Vulnerability Types", styles["h3"]))
    type_rows = [
        ["Type",          "Description"],
        ["Organizational", "Vulnerability linked to organisational choices for the audited system"],
        ["Technical",      "Vulnerability linked to technical/technological choices in the audited system"],
        ["Configuration",  "Vulnerability linked to an unsuitable configuration"],
    ]
    type_tbl = Table(type_rows, colWidths=[4.5 * cm, 12.5 * cm])
    type_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    story.append(type_tbl)
    story.append(Paragraph("Table 11: Vulnerability types", styles["caption"]))

    story.append(Paragraph("Complexity & Priority", styles["h3"]))
    prio_rows = [
        ["Priority",    "Description"],
        ["Immediate",   "Fix must be carried out within a period of less than one month"],
        ["Short Term",  "Fix must be carried out within a period of 1 to 3 months"],
        ["Mid Term",    "Fix must be carried out within a period of 3 to 6 months"],
        ["Long Term",   "Fix must be carried out within a period of > 6 months"],
    ]
    prio_tbl = Table(prio_rows, colWidths=[4.5 * cm, 12.5 * cm])
    prio_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  _REPORT_DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F5F7FA"), HexColor("#FFFFFF")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, HexColor("#BBBBBB")),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    story.append(prio_tbl)
    story.append(Paragraph("Table 14: Priority level", styles["caption"]))

    return story


# ── Cover overlay + template merge helpers ────────────────────────────────────

def _build_cover_overlay_bytes(report_data: dict) -> bytes:
    """
    Render a single-page PDF (in-memory) containing only the dynamic text that
    overlays template.pdf's cover (page 1): Target + Report Date.

    Coordinates are conservative — placed in the lower-middle area of A4 to
    avoid clashing with a typical template cover logo/title block at the top.
    Tune the y-coordinates after the first render if the text overlaps the
    cover design.
    """
    from io import BytesIO
    from reportlab.pdfgen.canvas import Canvas

    buf = BytesIO()
    c = Canvas(buf, pagesize=A4)
    page_w, page_h = A4

    target = report_data.get("target", "unknown")
    date = report_data.get("report_date", "")

    # Position roughly in the lower-middle band of the page.
    target_y = page_h * 0.42
    date_y   = page_h * 0.37

    c.setFillColor(_REPORT_DARK)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(page_w / 2, target_y, _clean(f"Target: {target}"))

    c.setFillColor(HexColor("#555555"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(page_w / 2, date_y, _clean(f"Report Date: {date}"))

    c.showPage()
    c.save()
    return buf.getvalue()


def _merge_pdf_with_template(
    content_bytes: bytes,
    overlay_bytes: bytes,
    template_path: str,
    output_path: str,
) -> None:
    """
    Stitch the generated content over the background template:
      page 1     : template.pages[0] + cover overlay (Target + Date)
      page 2..N+1: template.pages[1] (repeated) + content page i
      page N+2   : template.pages[2] (back cover, no overlay)
    """
    from io import BytesIO
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()

    # ── 1) Cover ──────────────────────────────────────────────────────────────
    tpl_cover_reader = PdfReader(template_path)
    cover_bg = tpl_cover_reader.pages[0]
    if overlay_bytes:
        overlay = PdfReader(BytesIO(overlay_bytes))
        if overlay.pages:
            cover_bg.merge_page(overlay.pages[0])
    writer.add_page(cover_bg)

    # ── 2) Inner content pages ────────────────────────────────────────────────
    content = PdfReader(BytesIO(content_bytes))
    n_template_pages = len(PdfReader(template_path).pages)
    inner_idx = 1 if n_template_pages >= 2 else 0

    for cp in content.pages:
        # Re-read template per iteration so each inner page gets a fresh copy
        # of the background (mutating the same PageObject across iterations
        # would stack every content page on top of one another).
        tpl_inner_reader = PdfReader(template_path)
        bg = tpl_inner_reader.pages[inner_idx]
        bg.merge_page(cp)
        writer.add_page(bg)

    # ── 3) Back cover ─────────────────────────────────────────────────────────
    if n_template_pages >= 3:
        tpl_back_reader = PdfReader(template_path)
        writer.add_page(tpl_back_reader.pages[2])

    with open(output_path, "wb") as fh:
        writer.write(fh)


def _generate_with_template_bg(report_data: dict, template_path: str) -> str:
    """
    Render the report content (without our standalone cover or page chrome)
    in-memory, then overlay it on top of template.pdf pages via pypdf.
    """
    from io import BytesIO

    ensure_report_dir()
    target = report_data.get("target", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_path = REPORT_DIR / f"pentest_report_{_safe_name(target)}_{ts}.pdf"

    # 1) Cover overlay (Target + Date only)
    overlay_bytes = _build_cover_overlay_bytes(report_data)

    # 2) Content (sections 1-4 + appendix) — no cover, no page chrome
    styles = _report_styles()
    story = _build_report_story(
        report_data, styles,
        include_cover=False,
        include_doc_info=True,   # Classification + Change History on inner pages
    )

    content_buf = BytesIO()
    doc = SimpleDocTemplate(
        content_buf, pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=3.5 * cm, bottomMargin=2.5 * cm,
    )
    doc.build(story)  # no page chrome — template supplies its own header/footer
    content_bytes = content_buf.getvalue()

    # 3) Merge with template
    _merge_pdf_with_template(content_bytes, overlay_bytes, template_path, str(final_path))
    return str(final_path)


# ── Public entry point ───────────────────────────────────────────────────────

def generate_pdf_report(report_data: dict, template_pdf_path: str = None) -> str:
    """
    Render `report_data` (built by report_node) into a PDF that follows the standard
    Web Application Pentest Report template.

    When `template_pdf_path` points to a 3-page branded background PDF, that PDF is
    used as the visual layer: page 1 = cover (with Target + Date overlay),
    page 2 = repeated background on every inner content page, page 3 = back
    cover appended at the end. Without a template, falls back to the
    standalone ReportLab layout. Returns the absolute path of the written PDF.
    """
    if not _REPORTLAB:
        return write_text_report(report_data)

    # Template-overlay path
    if template_pdf_path and os.path.exists(template_pdf_path):
        try:
            return _generate_with_template_bg(report_data, template_pdf_path)
        except Exception as exc:
            logger.warning(
                "[generate_pdf_report] template overlay failed (%s) — "
                "falling back to standalone layout", exc,
            )

    # Standalone path (no template available)
    ensure_report_dir()
    target = report_data.get("target", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = REPORT_DIR / f"pentest_report_{_safe_name(target)}_{ts}.pdf"

    styles = _report_styles()
    story = _build_report_story(
        report_data, styles,
        include_cover=True,
        include_doc_info=True,
    )

    doc = SimpleDocTemplate(
        str(pdf_path), pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2.5 * cm, bottomMargin=2.5 * cm,
    )
    doc.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return str(pdf_path)


def _page_chrome(canvas, doc):
    DARK = HexColor("#1B2A4A")
    ACC  = HexColor("#E84040")
    canvas.saveState()
    # Header
    canvas.setFillColor(DARK)
    canvas.rect(0, A4[1] - 1.4 * cm, A4[0], 1.4 * cm, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(2 * cm, A4[1] - 0.9 * cm, "PENETRATION TESTING REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 0.9 * cm, "CONFIDENTIAL")
    # Footer
    canvas.setFillColor(DARK)
    canvas.rect(0, 0, A4[0], 1.1 * cm, fill=1, stroke=0)
    canvas.setFillColor(ACC)
    canvas.rect(0, 1.1 * cm, A4[0], 0.12 * cm, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(2 * cm, 0.38 * cm, f"Generated: {datetime.now().strftime('%Y-%m-%d')}")
    canvas.drawCentredString(
        A4[0] / 2, 0.38 * cm, "CONFIDENTIAL — FOR AUTHORIZED USE ONLY",
    )
    canvas.drawRightString(A4[0] - 2 * cm, 0.38 * cm, f"Page {doc.page}")
    canvas.restoreState()
