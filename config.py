import logging
from typing import TypedDict, List, Optional
from typing import Any, Dict
from dotenv import load_dotenv

MODEL = "openai/gpt-oss-120b"

ALLOWED_COMMANDS = [
    "nmap", "whatweb", "dirsearch", "ls", "whoami",
    "traceroute", "whois", "host", "dig", "nslookup",
    "telnet", "curl", "ping",
    "sublist3r", "amass", "waybackurls",
    "gobuster", "dirb",
    "bfac", "git-dumper",
]
IMAGE_NAME = "pentest-tools"

# Keep third-party HTTP client logs quiet in CLI output.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)
logging.getLogger("groq").setLevel(logging.WARNING)

PENTEST_PHASES = [
    "Scanning",
    "Browser Recon",
    "Vulnerability Discovery",
    "Reporting",
]

PHASE_ALLOWED_COMMANDS = {
    "Scanning": [
        "nmap",
        "whatweb",
        "dirsearch",
        "dirb",
        "traceroute",
        "whois",
        "host",
        "dig",
        "telnet",
        "curl",
        "ping",
        "sublist3r",
        "amass",
        "waybackurls",
        "gobuster",
        "bfac",
        "git-dumper",
    ],
    "Vulnerability Analysis": [
    ],
    "Reporting": [
    ],
}



class AgentState(TypedDict):
    target: str
    # Host-side port given by the user — for display/reporting only
    host_port: Optional[str]
    host_base_url: Optional[str]
    # Internal container port discovered by nmap — used by all Docker tools
    internal_port: Optional[str]
    internal_base_url: Optional[str]
    scan_history: List[str]
    open_ports: List[str]
    ip_addresses: List[str]
    services: List[str]
    web_technologies: List[str]
    technology_scan_url: Optional[str]
    technology_profiles: List[Dict[str, Any]]
    technology_stack: Dict[str, List[str]]
    directories: List[str]
    auth_headers: Dict[str, str]
    auth_cookies: Dict[str, str]
    auth_base_url: Optional[str]
    session_cookie: Optional[str]
    session_token: Optional[str]
    bearer_token: Optional[str]
    jwt_token: Optional[str]
    api_token: Optional[str]
    username: Optional[str]
    password: Optional[str]
    auth_status: Optional[str]
    auth_attempts: List[dict]
    auth_log: List[str]
    os: Optional[str]
    last_output: str
    phase: str
    decision: Optional[str]
    last_agent: Optional[str]
    vulnerability_focus: List[str]
    vulnerabilities_total: int
    vulnerabilities_parsed: int
    processed_vulnerability_types: List[str]
    current_exploit_index: int
    current_exploit_type: Optional[str]
    retrieval_complete: bool
    retrieval_top_k: int
    retrieval_query: List[str]
    retrieved_exploits: List[dict]
    retrieved_exploits_batch: List[dict]
    review_use_llm: bool
    reviewed_exploits: List[dict]
    usable_review_artifacts: List[dict]
    prepared_exploits: List[dict]
    execution_results: List[dict]
    exploitation_status: Optional[str]
    patch_strategy: Optional[str]
    patch_route_reason: Optional[str]
    patch_strategy_override: Optional[str]
    patch_regeneration_count: int
    # Reporting phase
    parsed_exploit_reports: List[dict]
    report_sections: Dict[str, str]
    final_report_text_path: Optional[str]
    final_report_pdf_path: Optional[str]
    # Browser Recon phase
    browser_recon_run_dir: Optional[str]
    browser_recon_run_id: Optional[str]
    browser_recon_complete: bool
    browser_agent_mode: str
    browser_task_prompts: List[str]
    hit_targets: List[dict]
    login_endpoints: List[dict]
    discovered_endpoints: List[str]
    endpoint_schemas: Dict[str, dict]
    browser_attack_surfaces: List[str]
    # Prober
    prober_plan: List[dict]
    prober_plan_version: int
    planner_subplans: List[str]
    planner_output_markdown: str
    # Router
    router_decisions: List[dict]
    router_script_tasks: List[str]
    router_browser_tasks: List[str]
    router_summary: str
    router_version: int
    browser_task_execution_run_dir: Optional[str]
    browser_task_execution_tasks: List[str]
    browser_task_execution_report: Dict[str, Any]
    script_task_selection_count: int
    script_execution_enabled: bool
    # Router → Recon subprompt (generated per OWASP cycle, consumed by browser_explore_node)
    browser_recon_subprompt: str
    # Security findings extracted from nmap scripts, headers, curl probes
    security_findings: List[str]
    # Découverte checklist tracking (seeded from the checklist JSON into checklist_tests)
    checklist_tests: List[Dict[str, Any]]
    checklist_current_index: int
    checklist_completed_ids: List[str]
    checklist_results: List[Dict[str, Any]]
    # Checklist-driven probing (post-Découverte phases)
    checklist_all_tests: List[Dict[str, Any]]
    checklist_all_done: bool
    checklist_current_test: Dict[str, Any]
    # User-selected post-Découverte categories. Empty list → run all.
    selected_categories: List[str]
    # Structured CVE/CVSS records parsed from nmap vulners output
    cvss_findings: List[Dict[str, Any]]
    # Probe deduplication cache — key = f"{probe_type}::{normalized_endpoint}::{cookie_fingerprint}"
    probe_cache: Dict[str, List[Dict[str, Any]]]
    # Set by prober when probes confirm Critical/High vuln → skip exploit chain
    probe_confirmed_skip_exploit: bool




