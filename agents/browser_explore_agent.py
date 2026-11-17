import logging
import pathlib
from typing import Any, Dict, List

from config import AgentState
from tools.browser_explore_tool import _origin, build_target_url, run_browser_explore
from tools.docker_target_map import to_external_url
from tools.finding_reporter_tool import report_step_findings

logger = logging.getLogger(__name__)


def _summarize_browser_run(run_dir: str, max_chars: int = 3000) -> str:
    """Return a truncated tail of pipeline.jsonl so the LLM classifier has context."""
    if not run_dir:
        return ""
    pipeline_file = pathlib.Path(run_dir) / "pipeline.jsonl"
    if not pipeline_file.exists():
        return ""
    try:
        text = pipeline_file.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("BROWSER EXPLORE: failed to read pipeline.jsonl: %s", exc)
        return ""
    return text[-max_chars:] if len(text) > max_chars else text


def _detect_spa_framework(state: AgentState) -> str:
    """Return a lowercase framework name if detected in technology_stack, else ''."""
    stack = state.get("technology_stack") or {}
    frontend = [str(x).lower() for x in (stack.get("frontend_frameworks") or [])]
    js_libs = [str(x).lower() for x in (stack.get("javascript_libraries") or [])]
    flat = " ".join(frontend + js_libs)
    for fw in ("angular", "react", "vue", "svelte", "ember"):
        if fw in flat or (fw == "react" and "next" in flat) or (fw == "vue" and "nuxt" in flat):
            return fw
    return ""


def _generate_discovery_subprompt(state: AgentState) -> str:
    """First-pass exploration hints sourced from state — no hardcoded route lists.

    Pulls candidate routes only from already-discovered state (dirsearch/wappalyzer/etc.)
    and instructs the runner to use protocol-standard discovery (robots.txt, sitemap.xml,
    JS-bundle introspection) when state is empty.
    """
    framework = _detect_spa_framework(state)
    stack = state.get("technology_stack") or {}
    username = state.get("username") or ""
    password = state.get("password") or ""

    discovered = list(state.get("discovered_endpoints") or [])
    directories = list(state.get("directories") or [])
    login_eps = list(state.get("login_endpoints") or [])

    state_routes: List[str] = []
    seen = set()
    for src in (discovered, directories):
        for r in src:
            key = str(r).strip()
            if key and key not in seen:
                seen.add(key)
                state_routes.append(key)

    lines: List[str] = [
        "RECON OBJECTIVE — first-pass discovery",
        "Goal: enumerate routes, login forms, API surface, and admin/configuration paths.",
        "",
        "Authentication context:",
    ]
    if login_eps:
        for ep in login_eps[:3]:
            route = ep.get("route", "(unknown)") if isinstance(ep, dict) else str(ep)
            lines.append(f"  - Known login endpoint: {route}")
        if username and password:
            lines.append(f"  - Credentials: {username} / {password}")
    elif username and password:
        lines.append(f"  - Attempt login with {username}/{password} if a login form is present.")
    else:
        lines.append("  - No credentials provided; do not attempt login forms.")

    lines.append("")

    if state_routes:
        lines.append(f"Routes already known from prior scanning ({len(state_routes)} total) — prioritise these:")
        for r in state_routes[:20]:
            lines.append(f"  - {r}")
    else:
        lines.append("No routes have been pre-discovered. Use protocol-standard discovery:")
        lines.append("  - Fetch /robots.txt and /sitemap.xml; extract any disclosed paths.")
        lines.append("  - Crawl links from the root page; follow same-origin <a href> values.")
        if framework:
            lines.append(
                f"  - SPA framework detected ({framework}): inspect the main JS bundle for route "
                "definitions (look for `path:` entries in router configs, hash-route patterns "
                "`#/...`, or lazy-load chunk names) and treat those as candidate routes."
            )

    if stack:
        stack_flat = ", ".join(
            f"{k}={v}" for k, v in stack.items()
            if v and (isinstance(v, str) or (isinstance(v, list) and v))
        )[:200]
        if stack_flat:
            lines += ["", f"Detected stack: {stack_flat}"]

    lines += [
        "",
        "Execution strategy:",
        "  1. Visit the root and record initial routes/forms.",
        "  2. If the response is JSON (Content-Type application/json), treat it as an API surface; "
        "do not attempt DOM clicks — extract any keys/paths and pivot.",
        "  3. Visit each known route above; record any new sub-routes discovered.",
        "  4. Fill in login forms with the provided credentials when encountered.",
        "  5. Do NOT repeat the same action twice — pivot when a path is exhausted.",
        "  6. Record all discovered routes and form schemas in your decision trace.",
    ]
    return "\n".join(lines)


def browser_explore_node(state: AgentState) -> AgentState:
    target     = state.get("target", "")
    open_ports = state.get("open_ports", []) or []
    browser_mode = str(state.get("browser_agent_mode") or "recon")
    browser_tasks = list(state.get("browser_task_prompts") or [])

    # First-pass: no router-generated subprompt yet. Generate a discovery-mode subprompt
    # so the recon container gets stack-aware hints sourced from state (no hardcoded paths).
    recon_subprompt = str(state.get("browser_recon_subprompt") or "").strip()
    if not recon_subprompt and browser_mode == "recon":
        try:
            recon_subprompt = _generate_discovery_subprompt(state)
            state["browser_recon_subprompt"] = recon_subprompt
            logger.info("BROWSER EXPLORE: discovery subprompt generated (%d chars)", len(recon_subprompt))
        except Exception as exc:
            logger.warning("BROWSER EXPLORE: discovery subprompt generation failed: %s", exc)
            recon_subprompt = ""

    if recon_subprompt and browser_mode == "recon":
        browser_tasks = [recon_subprompt]

    # ── 1. Build target URL ────────────────────────────────────────────────────
    # Two planes, never collapsed (see tools/docker_target_map.py):
    #   target_url  = Docker plane: what the browser-recon container navigates to
    #                 on pentest-net (http://web:5000). localhost there would be
    #                 the container itself, so this one MUST stay internal.
    #   display_url = browser plane: what the tester sees in logs, live frames
    #                 and findings (http://localhost:8084).
    # Prefer the nmap-discovered internal URL (container port on pentest-net).
    # Fall back to build_target_url only if nmap hasn't run yet.
    target_url = state.get("internal_base_url") or build_target_url(target, open_ports)

    if not target_url:
        print("[BROWSER EXPLORE] Could not build target URL — skipping recon")
        state["browser_recon_run_dir"] = None
        state["browser_recon_run_id"]  = None
        return state

    display_url = to_external_url(target_url)
    if display_url == target_url and state.get("host_base_url"):
        # Compose doesn't know this target: fall back to the tester-facing URL.
        display_url = str(state["host_base_url"])
    internal_origin = _origin(target_url)
    external_origin = _origin(display_url)

    print(f"\n[BROWSER EXPLORE] URL resolved: {display_url}")
    if recon_subprompt and browser_mode == "recon":
        print(f"[BROWSER EXPLORE] Recon subprompt active ({len(recon_subprompt)} chars) — guided exploration")

    username    = str(state.get("username") or "")
    password    = str(state.get("password") or "")
    auth_cookies = dict(state.get("auth_cookies") or {})
    auth_out_of_scope = bool(state.get("auth_out_of_scope"))

    # ── 2. Run Docker exploration ──────────────────────────────────────────────
    # Auth cookies are injected into session state (apply_auth_to_state) and, when
    # credentials are supplied, resolved via run_auth_preflight before recon.
    run_dir = run_browser_explore(
        target_url        = target_url,
        target            = target,
        max_iterations    = 20,
        mode              = browser_mode,
        task_prompts      = browser_tasks,
        username          = username,
        password          = password,
        auth_cookies      = auth_cookies or None,
        auth_out_of_scope = auth_out_of_scope,
        display_url       = display_url,
    )

    if run_dir:
        run_id = pathlib.Path(run_dir).name
        state["browser_recon_run_dir"] = run_dir
        state["browser_recon_run_id"]  = run_id
        logger.info("BROWSER EXPLORE: run_dir=%s", run_dir)
    else:
        print("[BROWSER EXPLORE] Container returned no output — recon skipped")
        state["browser_recon_run_dir"] = None
        state["browser_recon_run_id"]  = None

    # Per-step reporting: classify the browser run's output and refresh findings.json.
    # Always runs (even when run_dir is None) so findings.json is created on first pass.
    try:
        items: List[Dict[str, str]] = []
        run_summary = _summarize_browser_run(run_dir) if run_dir else ""
        if internal_origin and external_origin and internal_origin != external_origin:
            # Findings are read by the tester: report the browser-plane URL.
            run_summary = run_summary.replace(internal_origin, external_origin)
        if run_summary:
            items.append({
                "command": f"browser_explore[{browser_mode}] → {display_url}",
                "output": run_summary,
            })
        report_path = report_step_findings(
            target=target,
            step=f"browser_explore:{browser_mode}",
            items=items,
            state_context=state,
        )
        if report_path:
            print(f"[BROWSER EXPLORE] findings.json refreshed → {report_path}")
    except Exception as exc:
        logger.warning("BROWSER EXPLORE: per-step report failed: %s", exc)

    return state
