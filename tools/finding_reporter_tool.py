import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from dotenv import load_dotenv

from functions import call_llm
from tools.cvss_scoring_tool import build_cvss_scoring
from tools.run_context import get_run_context

load_dotenv()
logger = logging.getLogger(__name__)

FINDINGS_DIR = Path(__file__).parent.parent / "reports" / "findings"

# ── Prompt ────────────────────────────────────────────────────────────────────

_SYSTEM = """\
You are a senior penetration tester reviewing the output of a security tool.
Your task: analyze the tool output against the tested issue, classify the
outcome, and ALWAYS explain your reasoning so a reader can see exactly why the
target is or is not vulnerable.

DECISION — set "test_status" to exactly one of:
  "found"          — the tool ran successfully AND the output contains concrete,
                     verifiable evidence of a vulnerability, misconfiguration, or CVE.
  "not_found"      — the tool ran successfully AND the output contains concrete
                     evidence the target is secure on this point (payload rejected,
                     no reflection/error leak, patched version, "not vulnerable"
                     message, access denied, input properly handled).
  "not_conclusive" — the output cannot support either verdict: command not found,
                     STATUS: ERROR, timeout, empty output, network unreachable,
                     tool/config error, or genuinely ambiguous results.

TEST INTENT — read the "Expected vulnerability" / test description FIRST and decide
which kind of test this is. The two kinds have DIFFERENT triggers for "found":

  (a) DISCLOSURE / EXPOSURE / MISCONFIGURATION tests — the vulnerability IS the fact
      that something is revealed or misconfigured. Triggers include: a version or
      software banner is printed; a server/framework/language is named (Server,
      X-Powered-By, Werkzeug/…, PHP/…, Python/…, Apache/…); a sensitive path responds
      (/robots.txt, /.env, /.git/config, /config.*, /backup/*.sql); a security header
      is ABSENT (X-Frame-Options, CSP, HSTS); a cookie lacks HttpOnly/Secure. For
      these tests the verdict is "found" the MOMENT the output SHOWS the exposure —
      you do NOT need a known CVE, an error, or a working exploit. Severity is usually
      Informational or Low; that is still "found", not "not_conclusive".
      "not_conclusive" here is ONLY for an execution failure (empty/errored output) —
      NEVER for "I see the version but don't know a CVE for it".

  (b) EXPLOITATION tests — the vulnerability requires the vector to actually work
      (SQL error returned, payload reflected, auth bypassed, RCE output, file read).
      Here a clean/rejected/patched response is a genuine "not_found".

  Do NOT apply the (b) standard to an (a) test. "No version known to be vulnerable"
  is NEVER a reason to downgrade a disclosure test — CVE correlation is a SEPARATE
  test. Keep the two questions apart: (a) is a banner/version/path/header exposed?
  → THIS test, trigger = any disclosure; (b) is it a known-vulnerable version?
  → a different test, not your job here.

CONTRADICTORY / DECEPTIVE EVIDENCE is itself a finding. If banners disagree — e.g.
nmap reports "Apache" but the same response carries "Werkzeug" + "Python" and
"X-Powered-By: PHP" — a single server cannot truthfully be all three. Report it as a
banner/fingerprint inconsistency (misconfiguration or deliberate deception),
set "found" with Informational/Low severity, quote ALL conflicting lines in
"evidence", and do NOT silently adopt one banner as the truth.

CROSS-TEST CONSISTENCY (MANDATORY — apply BEFORE choosing the verdict) — the
"Known facts from earlier tests" block lists what SIBLING tests already proved
(open ports, detected services/versions). It is GROUND TRUTH. You must reconcile
this command's output against it first:

  STEP 1 — If this output is a NEGATIVE result (ports "closed", "nothing listening",
    "no services", "not reachable", empty), check the Known facts for ANY open port
    or running service. If the facts list even one open port/service, then this
    negative CONTRADICTS established ground truth — the host is NOT clean; this scan
    simply used a narrower port set or missed the service.
      → You MUST NOT return "not_found" in this situation.
      → Return "not_conclusive"; in "reasoning" state that the host has known-open
        service(s) (name them from the facts) and this negative is a scan-COVERAGE
        gap, not evidence of security.
    This holds EVEN IF the specific ports in THIS command (e.g. 22/23/80/443) all
    came back closed — a different port (e.g. 5000) being open in the facts is still
    a contradiction, because a reachable service exists that this scan did not cover.

  STEP 2 — Known facts may also STRENGTHEN a "found" verdict (a disclosed version in
    the facts corroborates a banner in this output). Use them; cite them in
    "reasoning".

  Only after STEP 1 finds NO contradiction may you consider "not_found".

EVIDENCE-FIRST REASONING — required for EVERY verdict, including not_found:
  - "evidence": copy the EXACT line(s) from the RAW OUTPUT that drive your verdict
    (e.g. an HTTP status, a SQL error string, a version banner, a rejection
    message, a reflected/unreflected payload). Verbatim, not paraphrased. If the
    output is truly empty or errored, say so literally (e.g. "STATUS: ERROR").
  - "reasoning": 1-3 sentences tying that evidence to the tested issue. State WHY
    it proves the verdict:
      * for "found": why the evidence confirms the vulnerability is exploitable;
      * for "not_found": why the evidence shows the vector does NOT work here
        (what a vulnerable target would have shown instead, and that it is absent);
      * for "not_conclusive": what is missing or why the output can't decide.
    Reference the "Expected vulnerability"/"Expected result" context when present.
    Never leave "reasoning" empty and never use a generic boilerplate sentence.

RULES:
1. Only set "found" for CONFIRMED or STRONGLY INDICATED findings — not theoretical.
   Base every verdict strictly on what is IN the output, never on assumptions.
2. When test_status is "found":
   - Include ALL CVE identifiers in "cve"; set "cvss" to the highest score.
   - Choose "owasp_id" from A01-A10 (OWASP Top 10 2021).
   - "proof_of_concept.output_snippet" MUST be a verbatim excerpt proving the finding.
   - "severity" must be one of: Critical, High, Medium, Low, Informational.
   - "cvss_vector": produce a CVSS v3.1 vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
     Base it on the finding characteristics (network-exposed = AV:N, no auth = PR:N, etc.).
     If a CVE is present and you know its published vector, use it. Otherwise derive it from the evidence.
     Leave empty string "" only if there is genuinely no way to assess any metric.
3. When test_status is "not_found" or "not_conclusive", leave the FINDING fields
   (finding, cve, cvss, severity, owasp_id, proof_of_concept) empty / null — do NOT
   invent content — but you MUST still fill "evidence" and "reasoning".
4. "finding" (the summary line) is for "found" only. For the why-it-is / why-it-is-not
   explanation, use "reasoning" — that field is filled for all three verdicts.
5. Output STRICT JSON only — no markdown, no prose.\
"""

_USER_TEMPLATE = """\
PHASE   : {phase}
COMMAND : {command}
TARGET  : {target}

════ Checklist test context ════
Test description     : {test_description}
Expected vulnerability: {vuln_attendue}
Expected result      : {resultat_attendu}

════ Known facts from earlier tests (ground truth — reconcile against these) ════
{shared_facts_block}
════ Pre-parsed findings (extracted from output) ════
{security_findings_block}
════ RAW OUTPUT (may be truncated) ════
{output}

Analyze the RAW OUTPUT against the tested issue. Decide the verdict, then quote
the exact output line(s) in "evidence" and explain in "reasoning" WHY the target
is vulnerable (for found) or WHY it is NOT vulnerable / inconclusive (for the
others). Produce the structured record as strict JSON.\
"""

_SCHEMA = {
    "name": "pentest_finding",
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "test_status": {
                "type": "string",
                "enum": ["found", "not_found", "not_conclusive"],
            },
            "evidence":       {"type": "string"},
            "reasoning":      {"type": "string"},
            "finding":        {"type": "string"},
            "owasp_id": {
                "type": "string",
                "enum": ["A01","A02","A03","A04","A05",
                         "A06","A07","A08","A09","A10",""],
            },
            "owasp_category": {"type": "string"},
            "cve":            {"type": "array", "items": {"type": "string"}},
            "cvss":           {"type": ["number", "null"]},
            "severity": {
                "type": "string",
                "enum": ["Critical","High","Medium","Low","Informational",""],
            },
            "proof_of_concept": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "command":        {"type": "string"},
                    "output_snippet": {"type": "string"},
                },
                "required": ["command", "output_snippet"],
            },
            "exploit_refs": {"type": "array", "items": {"type": "string"}},
            "cvss_vector":  {"type": "string"},
        },
        "required": [
            "test_status", "evidence", "reasoning", "finding", "owasp_id",
            "owasp_category", "cve", "cvss", "severity", "proof_of_concept",
            "exploit_refs", "cvss_vector",
        ],
    },
}

# ── Shared-facts rendering ────────────────────────────────────────────────────

def _render_shared_facts(shared_facts: Optional[dict]) -> str:
    """Render the cross-test facts block for the Finding Agent prompt.

    ``shared_facts`` carries what sibling tests already established (open ports,
    services/versions, OS, technologies). Surfacing it lets the agent reconcile a
    single command's output against the run as a whole — e.g. not trust an
    "all ports closed" result when another test already found port 5000 open.
    Returns a ``(none known yet)`` line when there is nothing to show so the
    template never renders an empty section.
    """
    if not shared_facts:
        return "(none known yet)\n"

    lines: List[str] = []

    def _add(label: str, values: Any) -> None:
        if not values:
            return
        if isinstance(values, (list, tuple, set)):
            items = [str(v).strip() for v in values if str(v).strip()]
            if not items:
                return
            lines.append(f"  - {label}: {', '.join(items[:40])}")
        else:
            text = str(values).strip()
            if text:
                lines.append(f"  - {label}: {text}")

    _add("Open ports", shared_facts.get("open_ports"))
    _add("Services (port:name:version)", shared_facts.get("services"))
    _add("OS", shared_facts.get("os"))
    _add("Detected technologies", shared_facts.get("technologies"))

    return ("\n".join(lines) + "\n") if lines else "(none known yet)\n"


# ── JSONL helpers ─────────────────────────────────────────────────────────────

def _findings_file(target: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(target or "unknown"))
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    return FINDINGS_DIR / f"findings_{safe}.jsonl"


def _findings_json_file(target: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(target or "unknown"))
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    return FINDINGS_DIR / f"findings_{safe}.json"


def write_finding(finding: dict, target: str) -> None:
    path = _findings_file(target)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(finding, ensure_ascii=False) + "\n")
    # Refresh the consolidated findings.json snapshot on every append so the file
    # exists and reflects current state even if the pipeline is interrupted
    # (e.g. user-initiated skip/stop) before report_node runs.
    try:
        write_findings_json(target)
    except Exception as exc:
        logger.warning("write_finding: failed to refresh findings.json snapshot: %s", exc)

    # Mirror into Postgres so the dashboard can render cards per run.
    # This is best-effort: if the DB is unavailable or no run is active
    # (e.g. tests/CLI runs outside the API), the JSON path above is still authoritative.
    run_id, user_id = get_run_context()
    if run_id is not None and user_id is not None:
        try:
            from db.findings_repo import insert_finding
            insert_finding(run_id=run_id, user_id=user_id, finding=finding)
        except Exception as exc:
            logger.warning("write_finding: DB mirror failed: %s", exc)


def read_findings(target: str) -> List[dict]:
    path = _findings_file(target)
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
    return out


def write_findings_json(target: str, records: Optional[List[dict]] = None) -> Path:
    """
    Write the consolidated findings.json snapshot for ``target``.

    ``records`` — when given (e.g. the session's findings loaded from Postgres),
    they are written as-is; otherwise the per-line JSONL for ``target`` is read.
    Returns the path written.
    """
    if records is None:
        records = read_findings(target)
    summary = {
        "target":            target,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "total_findings":    len(records),
        "found_count":       sum(1 for r in records if r.get("test_status") == "found"),
        "not_found_count":   sum(1 for r in records if r.get("test_status") == "not_found"),
        "inconclusive_count": sum(1 for r in records if r.get("test_status") == "not_conclusive"),
        "findings":          records,
    }
    path = _findings_json_file(target)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    return path


def report_step_findings(
    target: str,
    step: str,
    items: List[dict],
    state_context: Optional[dict] = None,
) -> Optional[Path]:
    """
    Per-step finding extractor — runs after browser_explore, execute, and payload.

    For each item ({"command", "output"}), call analyze_and_report to LLM-classify
    the output and append a finding record. Always refresh findings.json afterwards
    so the snapshot file exists even when no items produced confirmed findings.

    Returns the findings.json path, or None if target is empty.
    """
    target = (target or "").strip()
    if not target:
        return None

    test = (state_context or {}).get("checklist_current_test") or {}
    test_id = str(test.get("ID") or "")
    test_cat = str(test.get("Catégorie") or "")
    test_desc = str(test.get("Tests") or "")
    vuln_attendue = str(test.get("Vulnérabilité attendue") or "")
    resultat_attendu = str(test.get("Résultat attendu") or "")

    for item in items or []:
        cmd = str(item.get("command") or "").strip()
        out = str(item.get("output") or "").strip()
        if not cmd and not out:
            continue
        try:
            analyze_and_report(
                command=cmd or f"{step}:item",
                output=out,
                target=target,
                phase=step,
                test_description=test_desc,
                vuln_attendue=vuln_attendue,
                resultat_attendu=resultat_attendu,
                checklist_test_id=test_id,
                checklist_category=test_cat,
            )
        except Exception as exc:
            logger.warning("report_step_findings: %s item failed: %s", step, exc)

    # Always ensure findings.json exists — even if no items contributed findings,
    # an empty consolidated snapshot is written so downstream readers never hit
    # a missing-file error.
    try:
        return write_findings_json(target)
    except Exception as exc:
        logger.warning("report_step_findings: failed to write findings.json: %s", exc)
        return None


# ── Classification (no persistence) ───────────────────────────────────────────

# Human-facing labels for the three outcome states. Kept here so the API, the
# CLI prints, and the report all speak with one voice and the UI never has to
# guess a verdict string.
STATUS_LABELS = {
    "found":          "Vulnerability Detected",
    "not_found":      "Not Vulnerable",
    "not_conclusive": "Inconclusive",
}


def classify_output(
    command: str,
    output: str,
    target: str = "",
    phase: str = "Scanning",
    test_description: str = "",
    vuln_attendue: str = "",
    resultat_attendu: str = "",
    security_findings: Optional[List[str]] = None,
    shared_facts: Optional[dict] = None,
) -> dict:
    """Classify one command's output WITHOUT persisting anything.

    This is the Finding Agent's core assessment. It ALWAYS returns a dict with a
    defined ``status`` — never blank — so every execution yields an explicit
    verdict even when the output is empty or the LLM call fails:

      {
        "status":    "found" | "not_found" | "not_conclusive",
        "label":     "Vulnerability Detected" | "Not Vulnerable" | "Inconclusive",
        "summary":   short human-readable line (always set),
        "evidence":  verbatim output line(s) the verdict rests on (always set),
        "reasoning": why the target is / is not vulnerable (always set),
        "finding":   full LLM record (only when status == "found", else None),
      }

    Callers that want to persist a confirmed finding pass the returned
    ``finding`` record to :func:`build_finding_record` / ``write_finding``.
    """
    short_cmd = command.split()[0] if command else "?"

    def _verdict(
        status: str,
        summary: str,
        finding: Optional[dict] = None,
        *,
        evidence: str = "",
        reasoning: str = "",
    ) -> dict:
        return {
            "status":    status,
            "label":     STATUS_LABELS.get(status, STATUS_LABELS["not_conclusive"]),
            "summary":   summary,
            "evidence":  evidence,
            "reasoning": reasoning or summary,
            "finding":   finding,
        }

    if not output or not output.strip():
        # No output at all — we cannot assess the target. Never leave this blank.
        return _verdict(
            "not_conclusive",
            "No output was produced, so the test is inconclusive — nothing to assess.",
            evidence="(no output captured)",
            reasoning="The command returned no output, so there is no evidence to "
                      "decide whether the target is vulnerable.",
        )

    # Keep first 2500 chars + last 500 chars so we catch both the header and CVE tail
    output_for_llm = output.strip()
    if len(output_for_llm) > 3000:
        output_for_llm = output_for_llm[:2500] + "\n...\n" + output_for_llm[-500:]

    findings_block = ""
    if security_findings:
        lines = "\n".join(f"  - {f}" for f in security_findings[:30])
        findings_block = f"Parsed findings ({len(security_findings)} total):\n{lines}\n\n"

    user_msg = _USER_TEMPLATE.format(
        phase=phase,
        command=command,
        target=target or "(not specified)",
        output=output_for_llm,
        test_description=test_description or "(not specified)",
        vuln_attendue=vuln_attendue or "(not specified)",
        resultat_attendu=resultat_attendu or "(not specified)",
        shared_facts_block=_render_shared_facts(shared_facts),
        security_findings_block=findings_block or "(none pre-parsed)\n",
    )

    try:
        result = call_llm(
            [
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            _SCHEMA,
        )
    except Exception as exc:
        # The agent must always render a verdict. If the LLM is unreachable we
        # fall back to "Inconclusive" rather than returning nothing.
        print(f"[FINDING] ERROR (LLM failed) — {short_cmd}: {exc}")
        logger.warning("finding_reporter: LLM call failed: %s", exc)
        return _verdict(
            "not_conclusive",
            f"The analysis model could not be reached ({exc.__class__.__name__}); "
            "verdict is inconclusive. Re-run to retry.",
            evidence="(analysis model unavailable)",
            reasoning=f"The output could not be analyzed because the model call "
                      f"failed ({exc.__class__.__name__}); no verdict can be drawn.",
        )

    status = result.get("test_status") or "not_conclusive"
    if status not in STATUS_LABELS:
        status = "not_conclusive"

    evidence  = str(result.get("evidence") or "").strip()
    reasoning = str(result.get("reasoning") or "").strip()

    if status == "not_found":
        return _verdict(
            "not_found",
            reasoning
            or "The output provides sufficient evidence that the target is not "
               "vulnerable to the tested issue.",
            evidence=evidence,
            reasoning=reasoning,
        )
    if status == "not_conclusive":
        return _verdict(
            "not_conclusive",
            reasoning
            or "The output is insufficient to determine whether a vulnerability "
               "exists (execution error, empty, or ambiguous result).",
            evidence=evidence,
            reasoning=reasoning,
        )

    # status == "found": build the full structured finding record.
    finding = build_finding_record(
        result, command=command, output_for_llm=output_for_llm,
        phase=phase, security_findings=security_findings,
        test_description=test_description, vuln_attendue=vuln_attendue,
    )
    return _verdict(
        "found",
        finding.get("finding") or "A potential vulnerability was identified.",
        finding,
        evidence=finding.get("evidence") or evidence,
        reasoning=finding.get("reasoning") or reasoning,
    )


def build_finding_record(
    result: dict,
    *,
    command: str,
    output_for_llm: str,
    phase: str = "Scanning",
    security_findings: Optional[List[str]] = None,
    test_description: str = "",
    vuln_attendue: str = "",
    checklist_test_id: str = "",
    checklist_category: str = "",
) -> dict:
    """Assemble the persisted finding dict from a 'found' LLM result.

    Extracted from :func:`analyze_and_report` so the classify-only path and the
    legacy analyze-and-write path produce identical records (severity/CVSS
    normalization, synthetic CVSS for CVE-less findings, etc.).
    """
    finding_id   = str(uuid.uuid4())[:8]
    cvss_records = build_cvss_scoring(security_findings or [])

    # Normalize severity to match the CVSS score when they conflict
    cvss_score_raw = result.get("cvss")
    if cvss_score_raw is not None:
        score = float(cvss_score_raw)
        result["severity"] = (
            "Critical"      if score >= 9.0 else
            "High"          if score >= 7.0 else
            "Medium"        if score >= 4.0 else
            "Low"           if score > 0.0  else
            "Informational"
        )

    # For findings with no CVEs, synthesize a record from the LLM's severity
    # assessment so they still appear in CVSS tables and report sections.
    cve_list = result.get("cve") or []
    if not cve_list:
        severity   = result.get("severity") or "Informational"
        cvss_score = result.get("cvss")
        if cvss_score is None:
            cvss_score = {"Critical": 9.5, "High": 8.0, "Medium": 5.0, "Low": 2.0}.get(severity, 0.0)
        owasp_id     = result.get("owasp_id") or "MISC"
        synthetic_id = f"{owasp_id}-{finding_id}"
        if not any(r["id"] == synthetic_id for r in cvss_records):
            cvss_records.append({
                "id":          synthetic_id,
                "cvss":        cvss_score,
                "severity":    severity,
                "url":         "",
                "is_exploit":  False,
                "is_cve":      False,
                "description": result.get("finding", "")[:100],
                "cvss_vector": result.get("cvss_vector", ""),
            })
            cvss_records.sort(key=lambda r: r["cvss"], reverse=True)

    return {
        "finding_id":         finding_id,
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "phase":              phase,
        "test_status":        "found",
        "finding":            result.get("finding", ""),
        "evidence":           str(result.get("evidence") or ""),
        "reasoning":          str(result.get("reasoning") or ""),
        "owasp_id":           result.get("owasp_id", ""),
        "owasp_category":     result.get("owasp_category", ""),
        "checklist_test_id":  checklist_test_id,
        "checklist_category": checklist_category or result.get("owasp_category", ""),
        "test_description":   test_description,
        "vuln_attendue":      vuln_attendue,
        "cve":                result.get("cve") or [],
        "cvss":               result.get("cvss"),
        "severity":           result.get("severity", "Informational"),
        "proof_of_concept": {
            "command":        command,
            "output_snippet": (result.get("proof_of_concept") or {}).get(
                "output_snippet", output_for_llm[:400]
            ),
        },
        "exploit_refs":  result.get("exploit_refs") or [],
        "cvss_vector":   result.get("cvss_vector", ""),
        "cvss_records":  cvss_records,
    }


# ── Main public function ──────────────────────────────────────────────────────

def analyze_and_report(
    command: str,
    output: str,
    target: str,
    phase: str = "Scanning",
    test_description: str = "",
    vuln_attendue: str = "",
    resultat_attendu: str = "",
    security_findings: Optional[List[str]] = None,
    checklist_test_id: str = "",
    checklist_category: str = "",
    shared_facts: Optional[dict] = None,
) -> tuple[Optional[str], Optional[dict]]:
    """
    Ask the LLM to classify one tool's output and write a finding if confirmed.

    Returns ``(status, record)``:
      - ``status`` is ``"found" | "not_found" | "not_conclusive" | None`` (None on
        empty output or LLM failure)
      - ``record`` is the finding dict for status == "found"; for a persisted
        not_found / not_conclusive row it is the stub record (which carries the
        "evidence" / "reasoning" explanation); otherwise None.
    """
    short_cmd = command.split()[0] if command else "?"

    if not output or not output.strip():
        print(f"[FINDING] SKIP (empty output) — {short_cmd}")
        return (None, None)

    # Keep first 2500 chars + last 500 chars so we catch both the header and CVE tail
    output_for_llm = output.strip()
    if len(output_for_llm) > 3000:
        output_for_llm = output_for_llm[:2500] + "\n...\n" + output_for_llm[-500:]

    findings_block = ""
    if security_findings:
        lines = "\n".join(f"  - {f}" for f in security_findings[:30])
        findings_block = f"Parsed findings ({len(security_findings)} total):\n{lines}\n\n"

    user_msg = _USER_TEMPLATE.format(
        phase=phase,
        command=command,
        target=target,
        output=output_for_llm,
        test_description=test_description or "(not specified)",
        vuln_attendue=vuln_attendue or "(not specified)",
        resultat_attendu=resultat_attendu or "(not specified)",
        shared_facts_block=_render_shared_facts(shared_facts),
        security_findings_block=findings_block or "(none pre-parsed)\n",
    )

    try:
        result = call_llm(
            [
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            _SCHEMA,
        )
    except Exception as exc:
        print(f"[FINDING] ERROR (LLM failed) — {short_cmd}: {exc}")
        logger.warning("finding_reporter: LLM call failed: %s", exc)
        return (None, None)

    status    = result.get("test_status", "not_conclusive")
    cmd_label = command[:70]
    evidence  = str(result.get("evidence") or "").strip()
    reasoning = str(result.get("reasoning") or "").strip()

    if status in ("not_found", "not_conclusive"):
        label = "NOT FOUND     " if status == "not_found" else "NOT CONCLUSIVE"
        print(f"[FINDING] {label} — {short_cmd}: {cmd_label}")
        if reasoning:
            print(f"          why: {reasoning[:140]}")
        record = {
            "finding_id":         str(uuid.uuid4())[:8],
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "phase":              phase,
            "test_status":        status,
            "command":            command,
            "finding":            "",
            "evidence":           evidence,
            "reasoning":          reasoning,
            "checklist_test_id":  checklist_test_id,
            "checklist_category": checklist_category,
            "test_description":   test_description,
            "vuln_attendue":      vuln_attendue,
        }
        # Steps outside the checklist loop (browser_explore / execute / payload)
        # have no test_id / test_description, so they get no titled UI row — skip
        # persisting a titleless stub, but still RETURN the record so the caller
        # can read the "why it is not vulnerable / inconclusive" explanation.
        if checklist_test_id or test_description:
            write_finding(record, target)
        return (status, record)

    # status == "found"
    finding = build_finding_record(
        result, command=command, output_for_llm=output_for_llm,
        phase=phase, security_findings=security_findings,
        test_description=test_description, vuln_attendue=vuln_attendue,
        checklist_test_id=checklist_test_id, checklist_category=checklist_category,
    )

    write_finding(finding, target)

    sev   = finding["severity"]
    oid   = finding["owasp_id"]
    cves  = finding["cve"]
    cvss  = f" CVSS {finding['cvss']}" if finding["cvss"] else ""
    cve_s = f" | CVE: {', '.join(cves[:3])}" if cves else ""
    why   = str(finding.get("reasoning") or "").strip()
    print(
        f"[FINDING] FOUND          [{oid}] {sev:13s}{cvss}{cve_s}\n"
        f"          {finding['finding'][:90]}"
        + (f"\n          why: {why[:140]}" if why else "")
    )

    return ("found", finding)
