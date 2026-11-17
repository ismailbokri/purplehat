"""
Browser Investigate Agent — LangGraph node.

Reads pipeline.jsonl produced by browser_explore_agent and extracts
structured recon findings (hit targets, login endpoints, schemas)
into AgentState. Attack surface analysis is the prober's responsibility.
"""
import logging

from config import AgentState
from tools.browser_investigate_tool import run_investigation

logger = logging.getLogger(__name__)


def browser_investigate_node(state: AgentState) -> AgentState:
    run_dir = state.get("browser_recon_run_dir")

    # ── Guard: no run dir means explore was skipped ────────────────────────────
    if not run_dir:
        print("[INVESTIGATE] No browser recon run_dir — skipping investigation")
        state["browser_recon_complete"]  = True
        state["hit_targets"]             = []
        state["login_endpoints"]         = []
        state["discovered_endpoints"]    = []
        state["endpoint_schemas"]        = {}
        state["browser_attack_surfaces"] = []
        return state

    # ── Run investigation ──────────────────────────────────────────────────────
    try:
        report = run_investigation(run_dir)
    except Exception as exc:
        logger.error("INVESTIGATE failed: %s", exc, exc_info=True)
        print(f"[INVESTIGATE] ERROR: {exc} — continuing without browser recon data")
        report = {
            "hit_targets":          [],
            "login_endpoints":      [],
            "discovered_endpoints": [],
            "endpoint_schemas":     {},
            "summary":              "",
        }

    # ── Populate state ─────────────────────────────────────────────────────────
    # recon mode (first pass): overwrite — state has no prior browser findings.
    # task_execution mode (router-triggered): merge — preserve the initial recon
    # findings and enrich them with the targeted browser pass results.
    browser_mode = str(state.get("browser_agent_mode") or "recon")

    if browser_mode == "task_execution":
        # Merge hit_targets (deduplicate by page_url)
        existing_urls = {h.get("page_url") for h in (state.get("hit_targets") or [])}
        merged_hits = list(state.get("hit_targets") or [])
        for h in (report.get("hit_targets") or []):
            if h.get("page_url") not in existing_urls:
                merged_hits.append(h)
                existing_urls.add(h.get("page_url"))
        state["hit_targets"] = merged_hits

        # Merge login_endpoints (deduplicate by route)
        existing_routes = {ep.get("route") for ep in (state.get("login_endpoints") or [])}
        merged_logins = list(state.get("login_endpoints") or [])
        for ep in (report.get("login_endpoints") or []):
            if ep.get("route") not in existing_routes:
                merged_logins.append(ep)
                existing_routes.add(ep.get("route"))
        state["login_endpoints"] = merged_logins

        # Merge discovered_endpoints (deduplicate, preserve order)
        existing_eps = set(state.get("discovered_endpoints") or [])
        merged_eps = list(state.get("discovered_endpoints") or [])
        for ep in (report.get("discovered_endpoints") or []):
            if ep not in existing_eps:
                merged_eps.append(ep)
                existing_eps.add(ep)
        state["discovered_endpoints"] = merged_eps

        # Merge endpoint_schemas (new schemas augment existing ones)
        merged_schemas = dict(state.get("endpoint_schemas") or {})
        for k, v in (report.get("endpoint_schemas") or {}).items():
            if k not in merged_schemas:
                merged_schemas[k] = v
        state["endpoint_schemas"] = merged_schemas

        print(
            f"[INVESTIGATE] Merged task_execution findings — "
            f"+{len(report.get('hit_targets', []))} hits, "
            f"+{len(report.get('discovered_endpoints', []))} endpoints"
        )
    else:
        # First recon pass — full overwrite
        state["hit_targets"]          = report.get("hit_targets",          [])
        state["login_endpoints"]      = report.get("login_endpoints",      [])
        state["discovered_endpoints"] = report.get("discovered_endpoints", [])
        state["endpoint_schemas"]     = report.get("endpoint_schemas",     {})

    state["browser_recon_complete"] = True

    hit_count   = len(state["hit_targets"])
    login_count = len(state["login_endpoints"])
    ep_count    = len(state["discovered_endpoints"])

    print(
        f"\n[INVESTIGATE] Complete | "
        f"hits={hit_count} login_eps={login_count} endpoints={ep_count}"
    )

    if state["login_endpoints"]:
        print("[INVESTIGATE] Login endpoints found:")
        for ep in state["login_endpoints"][:5]:
            print(f"  {ep.get('route','')} | fields: {list((ep.get('schema') or {}).keys())}")

    logger.info(
        "INVESTIGATE: hits=%d login_eps=%d endpoints=%d",
        hit_count, login_count, ep_count,
    )

    return state
