from functions import *
from config import *
import re
import json
from dotenv import load_dotenv
import os
from tools.prompt_registry_tool import load_prompt_from_registry
from tools.finding_reporter_tool import analyze_and_report
from tools.cvss_scoring_tool import build_cvss_scoring

load_dotenv()

_prompt_payload = load_prompt_from_registry("pentest_parse_node", "1")
_system_prompt  = _prompt_payload["tags"]["system_prompt"]
_json_schema    = json.loads(_prompt_payload["tags"]["json_schema"])


ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def normalize_os_label(raw_os: str) -> str:
    cleaned = ANSI_ESCAPE_RE.sub("", raw_os).strip()
    lowered = cleaned.lower()

    families = [
        ("linux", "Linux"),
        ("windows", "Windows"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("netbsd", "NetBSD"),
        ("solaris", "Solaris"),
        ("mac os", "macOS"),
        ("darwin", "macOS"),
        ("routeros", "RouterOS"),
        ("openwrt", "OpenWrt"),
    ]

    for needle, label in families:
        if needle in lowered:
            return label

    first_guess = cleaned.split(",")[0].strip()
    return first_guess if first_guess else cleaned


def _extract_ipv4_addresses(text: str) -> List[str]:
    addresses = []
    seen = set()

    for match in IPV4_RE.findall(text):
        octets = match.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            if match not in seen:
                seen.add(match)
                addresses.append(match)

    return addresses


def _store_ip_addresses(state: AgentState, text: str) -> None:
    if "ip_addresses" not in state:
        state["ip_addresses"] = []

    alias_values = state.get("ip_adresse", [])
    for address in alias_values:
        if address not in state["ip_addresses"]:
            state["ip_addresses"].append(address)

    for address in _extract_ipv4_addresses(text):
        if address not in state["ip_addresses"]:
            state["ip_addresses"].append(address)

    state["ip_adresse"] = list(state["ip_addresses"])


def _build_technology_stack(state: AgentState) -> Dict[str, List[str]]:
    stack = {
        "frontend_frameworks": [],
        "backend_frameworks": [],
        "cms": [],
        "javascript_libraries": [],
        "web_servers": [],
        "authentication_technologies": [],
        "cdn": [],
        "waf": [],
        "analytics": [],
        "databases": [],
    }
    seen = {key: set() for key in stack}

    def _add(bucket: str, name: str) -> None:
        label = str(name or "").strip()
        if not label or label in seen[bucket]:
            return
        seen[bucket].add(label)
        stack[bucket].append(label)

    for profile in (state.get("technology_profiles") or []):
        if not isinstance(profile, dict):
            continue
        tech_name = str(profile.get("name") or "").strip()
        if not tech_name:
            continue
        for category in (profile.get("categories") or []):
            low = str(category or "").strip().lower()
            if not low:
                continue
            if "javascript framework" in low or "ui framework" in low or "frontend" in low:
                _add("frontend_frameworks", tech_name)
            if "web framework" in low or "backend" in low:
                _add("backend_frameworks", tech_name)
            if "cms" in low:
                _add("cms", tech_name)
            if "javascript library" in low:
                _add("javascript_libraries", tech_name)
            if "web server" in low or low == "servers":
                _add("web_servers", tech_name)
            if "authentication" in low or "security" in low:
                _add("authentication_technologies", tech_name)
            if "cdn" in low:
                _add("cdn", tech_name)
            if "waf" in low or "firewall" in low:
                _add("waf", tech_name)
            if "analytics" in low or "tag manager" in low:
                _add("analytics", tech_name)
            if "database" in low:
                _add("databases", tech_name)

    return stack


def _refresh_technology_context(state: AgentState) -> None:
    if "web_technologies" not in state:
        state["web_technologies"] = []
    deduped: List[str] = []
    seen = set()
    for item in state.get("web_technologies", []):
        label = str(item or "").strip()
        if not label:
            continue
        key = label.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(label)
    state["web_technologies"] = deduped
    state["technology_stack"] = _build_technology_stack(state)


def _extract_nmap_script_findings(state: AgentState, output_text: str) -> None:
    state.setdefault("security_findings", [])
    for line in output_text.split("\n"):
        cleaned = ANSI_ESCAPE_RE.sub("", line).strip()
        if not cleaned.startswith("|"):
            continue
        finding = re.sub(r"^\|_?\s*", "", cleaned).strip()
        if len(finding) > 4 and finding not in state["security_findings"]:
            state["security_findings"].append(finding)


def _parse_curl_file_probes(state: AgentState, output_text: str) -> None:
    from urllib.parse import urlparse as _up
    state.setdefault("directories", [])
    state.setdefault("security_findings", [])

    for line in output_text.split("\n"):
        cleaned = ANSI_ESCAPE_RE.sub("", line).strip()
        m = re.match(r"^(\d{3})\s+(https?://\S+)", cleaned)
        if not m:
            continue
        code = int(m.group(1))
        url  = m.group(2)
        path = _up(url).path or "/"

        if code in (200, 301, 302):
            entry = f"[{code}] {path}"
            if entry not in state["directories"]:
                state["directories"].append(entry)
            note = f"File exists ({code}): {path}"
            if note not in state["security_findings"]:
                state["security_findings"].append(note)
        elif code == 403:
            entry = f"[403] {path}"
            if entry not in state["directories"]:
                state["directories"].append(entry)


def parse_node(state: AgentState):

    last_cmd    = state["scan_history"][-1] if state["scan_history"] else ""
    output_text = state.get("last_output", "")
    target      = state.get("target", "")
    phase       = state.get("phase", "Scanning")

    # Whois output contains IANA network ranges — skip generic IP extraction.
    if not last_cmd.startswith("whois"):
        _store_ip_addresses(state, output_text)
    _refresh_technology_context(state)

    # ── Tool-specific output parsers ──────────────────────────────────────────
    # nmap: extract NSE script findings, then fall through to the LLM branch
    # so open_ports/services/os are also extracted from the same output.
    if last_cmd.startswith("nmap"):
        prev_count = len(state.get("security_findings", []))
        _extract_nmap_script_findings(state, output_text)
        new_findings = state["security_findings"][prev_count:]
        if new_findings:
            print(f" PARSED NMAP FINDINGS (+{len(new_findings)} new):", new_findings)
        elif state.get("security_findings"):
            print(f" PARSED NMAP FINDINGS: {len(state['security_findings'])} cumulative")
        # Rebuild CVSS table from all accumulated security_findings
        state["cvss_findings"] = build_cvss_scoring(state.get("security_findings", []))
        if state["cvss_findings"]:
            print(f" CVSS RECORDS: {len(state['cvss_findings'])} entries, top score {state['cvss_findings'][0]['cvss']}")
        # Fall through to LLM below (intentional — no elif/return here)

    if "whatweb" in last_cmd:
        state.setdefault("web_technologies", [])
        state.setdefault("directories", [])
        for line in output_text.split("\n"):
            cleaned_line = ANSI_ESCAPE_RE.sub("", line).strip()
            if cleaned_line and "[" in cleaned_line and "]" in cleaned_line:
                if cleaned_line not in state["web_technologies"]:
                    state["web_technologies"].append(cleaned_line)
                for redirect in re.findall(r"RedirectLocation\[([^\]]+)\]", cleaned_line):
                    redirect = redirect.strip()
                    if redirect:
                        normalized = redirect if redirect.startswith("/") else f"/{redirect}"
                        if normalized not in state["directories"]:
                            state["directories"].append(normalized)
        print("\n PARSED WHATWEB:", state["web_technologies"])
        print(" PARSED IPS:", state.get("ip_addresses", []))
        _refresh_technology_context(state)

    elif "dirsearch" in last_cmd:
        state.setdefault("directories", [])
        for line in output_text.split("\n"):
            cleaned = line.strip()
            if any(code in cleaned for code in [" 200 ", " 301 ", " 302 ", " 403 "]):
                if cleaned and cleaned not in state["directories"]:
                    state["directories"].append(cleaned)
        print("\n PARSED DIRSEARCH:", state["directories"])
        print(" PARSED IPS:", state.get("ip_addresses", []))
        _refresh_technology_context(state)

    elif last_cmd.startswith("gobuster") and any(
        m in last_cmd for m in (" dir ", " fuzz ", " dir\t", "-m dir")
    ):
        state.setdefault("directories", [])
        for line in output_text.split("\n"):
            cleaned = ANSI_ESCAPE_RE.sub("", line).strip()
            if cleaned.startswith("/") or "Status:" in cleaned:
                if cleaned not in state["directories"]:
                    state["directories"].append(cleaned)
        print("\n PARSED GOBUSTER DIR:", state["directories"])
        _refresh_technology_context(state)

    elif (last_cmd.startswith("gobuster") and "vhost" in last_cmd) or \
            any(last_cmd.startswith(t) for t in ("sublist3r", "amass", "waybackurls")):
        state.setdefault("discovered_endpoints", [])
        for line in output_text.split("\n"):
            cleaned = ANSI_ESCAPE_RE.sub("", line).strip()
            if not cleaned or cleaned.startswith("#") or "=" * 5 in cleaned:
                continue
            if "Found:" in cleaned:
                host = cleaned.split("Found:")[-1].split("(")[0].strip()
                if host and host not in state["discovered_endpoints"]:
                    state["discovered_endpoints"].append(host)
            elif re.match(r"^[a-zA-Z0-9][\w.\-]+\.[a-zA-Z]{2,}", cleaned):
                host = cleaned.split()[0]
                if host not in state["discovered_endpoints"]:
                    state["discovered_endpoints"].append(host)
            elif cleaned.startswith("http"):
                if cleaned not in state["discovered_endpoints"]:
                    state["discovered_endpoints"].append(cleaned)
        print("\n PARSED HOSTS/URLS:", state["discovered_endpoints"])
        _refresh_technology_context(state)

    elif last_cmd.startswith("whois"):
        print(" PARSED WHOIS: (no structured extraction)")
        _refresh_technology_context(state)

    elif last_cmd.startswith("curl"):
        _parse_curl_file_probes(state, output_text)
        if state.get("directories") or state.get("security_findings"):
            print(" PARSED CURL PATHS:", state.get("directories", []))
        _refresh_technology_context(state)

    elif last_cmd.startswith("dirb"):
        state.setdefault("directories", [])
        for line in output_text.split("\n"):
            cleaned = ANSI_ESCAPE_RE.sub("", line).strip()
            if cleaned.startswith("+"):
                path_part = cleaned.lstrip("+ ").split("(")[0].strip()
                if path_part and path_part not in state["directories"]:
                    state["directories"].append(path_part)
        print("\n PARSED DIRB:", state["directories"])
        _refresh_technology_context(state)

    else:
        # LLM fallback — also runs for nmap (falls through from the nmap block above)
        messages = [
            {"role": "system", "content": _system_prompt},
            {"role": "user",   "content": output_text},
        ]
        result = call_llm(messages, _json_schema)

        state["open_ports"] = list(set(state["open_ports"] + result["open_ports"]))
        for svc in result["services"]:
            formatted = f"{svc['port']}:{svc['name']}:{svc['version']}"
            if formatted not in state["services"]:
                state["services"].append(formatted)
        if result["os"]:
            state["os"] = normalize_os_label(result["os"])

        _refresh_technology_context(state)
        print("\n PARSED:", {**result, "ip_addresses": state.get("ip_addresses", [])})

    # ── Single finding reporter call — runs after every command ───────────────
    # Pull checklist context for the command that just ran (if available)
    checklist_results = state.get("checklist_results") or []
    last_cl = checklist_results[-1] if checklist_results else {}

    # Cross-test ground truth: what sibling tests already established. Passing this
    # lets the Finding Agent reconcile a single command's output against the whole
    # run — e.g. not trust an "all ports closed" result when another test found
    # port 5000 open, and corroborate a disclosed version banner against services.
    shared_facts = {
        "open_ports":   state.get("open_ports") or [],
        "services":     state.get("services") or [],
        "os":           state.get("os") or "",
        "technologies": state.get("web_technologies") or [],
    }

    status, finding = analyze_and_report(
        last_cmd,
        output_text,
        target,
        phase=phase,
        test_description=last_cl.get("test_description") or "",
        vuln_attendue=last_cl.get("vuln_attendue") or "",
        resultat_attendu=last_cl.get("resultat_attendu") or "",
        security_findings=state.get("security_findings") or [],
        checklist_test_id=str(last_cl.get("test_id") or ""),
        checklist_category=str(last_cl.get("category") or ""),
        shared_facts=shared_facts,
    )

    # Annotate the latest checklist_results entry so the server can emit a
    # structured per-test event (found / not_found / not_conclusive) to the UI.
    if last_cl and checklist_results:
        rec = finding or {}
        last_cl["test_status"]    = status or "not_conclusive"
        last_cl["finding_summary"] = rec.get("finding", "") if status == "found" else ""
        last_cl["severity"]        = rec.get("severity", "") if status == "found" else ""
        # Why-it-is / why-it-is-not reasoning + supporting evidence, surfaced for
        # EVERY verdict so the UI can explain the outcome — not just "found".
        # analyze_and_report now returns the record for not_found / not_conclusive
        # too, so no second LLM call is needed.
        last_cl["reasoning"] = rec.get("reasoning", "")
        last_cl["evidence"]  = rec.get("evidence", "")

    return state
