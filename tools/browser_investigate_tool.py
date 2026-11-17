"""
Browser Investigate Tool
Analyses pipeline.jsonl produced by the browser-recon container.

Core extraction is fully deterministic (no LLM required).
One optional Groq call generates the human-readable summary field.
"""
import json
import pathlib
import re
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs


# ─── JSONL helpers ────────────────────────────────────────────────────────────

def _parse_line(raw: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


# ─── Schema inference (from investigator_agent.py) ───────────────────────────

def _infer_scalar_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if value is None:
        return "null"
    text = str(value).strip()
    if not text:
        return "string"
    low = text.lower()
    if low in {"true", "false"}:
        return "boolean"
    if re.fullmatch(r"[+-]?\d+", text):
        return "integer"
    if re.fullmatch(r"[+-]?\d+\.\d+", text):
        return "number"
    return "string"


def _parse_post_sample(sample: str) -> Optional[Dict[str, Any]]:
    text = str(sample or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    try:
        pairs = parse_qs(text, keep_blank_values=True)
        return {k: (v[0] if len(v) == 1 else v) for k, v in pairs.items()} if pairs else None
    except Exception:
        return None


def _infer_schema(sample: str) -> Dict[str, str]:
    parsed = _parse_post_sample(sample)
    if not isinstance(parsed, dict):
        return {}
    return {k: _infer_scalar_type(v) for k, v in parsed.items() if str(k).strip()}


def _merge_schemas(base: Dict[str, str], incoming: Dict[str, str]) -> Dict[str, str]:
    if not base:
        return dict(incoming)
    merged = dict(base)
    for key, typ in incoming.items():
        existing = merged.get(key)
        merged[key] = typ if not existing or existing == typ else "string"
    return merged


# ─── Step 1 — pipeline overview ───────────────────────────────────────────────

def get_pipeline_overview(pipeline_path: pathlib.Path) -> Dict[str, Any]:
    """Return aggregate statistics and notable events from pipeline.jsonl."""
    if not pipeline_path.exists():
        return {"error": f"pipeline_not_found: {pipeline_path}"}

    total_lines   = 0
    valid_records = 0
    first_ts = last_ts = ""
    event_counts: Counter = Counter()
    interesting:  List[Dict[str, Any]] = []

    with pipeline_path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            total_lines = line_no
            record = _parse_line(raw)
            if not record:
                continue

            valid_records += 1
            event   = str(record.get("event", "")).strip()
            payload = record.get("payload", {})
            if event:
                event_counts[event] += 1

            ts = str(record.get("ts", "")).strip()
            if ts and not first_ts:
                first_ts = ts
            if ts:
                last_ts = ts

            if not isinstance(payload, dict):
                continue

            if event == "act_done":
                net   = _coerce_int(payload.get("network_request_count", 0))
                err   = _coerce_int(payload.get("error_count", 0))
                vuln  = bool(payload.get("vulnerability_found", False))
                chg   = bool(payload.get("url_changed", False))
                if net > 0 or err > 0 or vuln or chg:
                    interesting.append({
                        "line":                   line_no,
                        "event":                  event,
                        "network_request_count":  net,
                        "error_count":            err,
                        "url_changed":            chg,
                        "vulnerability_found":    vuln,
                    })

            if event == "reason_done":
                decision = payload.get("decision", {})
                if isinstance(decision, dict):
                    gravity = _coerce_int(decision.get("gravity_score", 0))
                    if gravity >= 7:
                        interesting.append({
                            "line":        line_no,
                            "event":       event,
                            "gravity_score": gravity,
                            "target_role": str(decision.get("target_role", "")),
                            "target_name": str(decision.get("target_name", "")),
                            "action":      str(decision.get("action", "")),
                        })

    return {
        "pipeline_path":             str(pipeline_path),
        "total_lines":               total_lines,
        "valid_records":             valid_records,
        "first_ts":                  first_ts,
        "last_ts":                   last_ts,
        "event_counts":              dict(event_counts),
        "interesting_events_sample": interesting[:40],
    }


# ─── Step 2 — candidate hit extraction ───────────────────────────────────────

def extract_candidate_hits(pipeline_path: pathlib.Path, max_hits: int = 20) -> List[Dict[str, Any]]:
    """
    Correlate reason_done decisions with act_done outcomes to extract hit targets.
    Fully deterministic — no LLM call.
    """
    if not pipeline_path.exists():
        return []

    limit           = max(1, min(_coerce_int(max_hits, default=20), 50))
    latest_decision: Dict[str, Any] = {}
    candidates:      List[Dict[str, Any]] = []
    seen             = set()

    with pipeline_path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            record = _parse_line(raw)
            if not record:
                continue

            event   = str(record.get("event", "")).strip()
            payload = record.get("payload", {})
            if not isinstance(payload, dict):
                continue

            # ── Capture latest LLM decision ───────────────────────────────
            if event == "reason_done":
                decision = payload.get("decision", {})
                if isinstance(decision, dict):
                    latest_decision = dict(decision)
                    surfaces = decision.get("identified_attack_surface", [])
                    if isinstance(surfaces, list):
                        latest_decision["attack_surfaces"] = surfaces
                continue

            if event != "act_done" or not latest_decision:
                continue

            # ── Correlate with act_done ───────────────────────────────────
            net_count     = _coerce_int(payload.get("network_request_count", 0))
            error_count   = _coerce_int(payload.get("error_count", 0))
            url_changed   = bool(payload.get("url_changed", False))
            vuln_signal   = bool(payload.get("vulnerability_found", False))
            page_url      = str(payload.get("url_before", ""))

            request_rows: List[Dict[str, Any]] = []
            for item in payload.get("network_requests", []):
                if not isinstance(item, dict):
                    continue
                method   = str(item.get("method", "")).strip().upper()
                route    = str(item.get("route",  "")).strip()
                if not method and not route:
                    continue
                q_keys = [str(k).strip() for k in item.get("query_keys", []) if str(k).strip()][:16]
                p_keys = [str(k).strip() for k in item.get("post_keys",  []) if str(k).strip()][:24]
                request_rows.append({
                    "method":          method,
                    "route":           route,
                    "query_keys":      q_keys,
                    "post_keys":       p_keys,
                    "has_post_data":   bool(item.get("has_post_data", False)),
                    "post_data_sample": str(item.get("post_data_sample", ""))[:600],
                })

            if net_count <= 0:
                net_count = len(request_rows)

            # Build route signatures
            route_signatures: List[str] = []
            for req in request_rows:
                sig = f"{req['method']} {req['route']}".strip()
                if sig and sig not in route_signatures:
                    route_signatures.append(sig)

            # Schema inference from POST bodies
            route_schema_map:     Dict[str, Dict[str, str]] = {}
            request_body_samples: List[str] = []
            write_like = False

            for req in request_rows:
                if req["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
                    write_like = True
                sample  = str(req.get("post_data_sample", "")).strip()
                sig     = f"{req['method']} {req['route']}".strip()
                if sample:
                    if sample not in request_body_samples:
                        request_body_samples.append(sample[:220])
                    schema = _infer_schema(sample)
                    if schema and sig:
                        route_schema_map[sig] = _merge_schemas(route_schema_map.get(sig, {}), schema)

            # Scoring
            score = 0
            if net_count > 0:
                score += 2
            if write_like:
                score += 1
            if url_changed:
                score += 1
            if vuln_signal:
                score += 3
            if route_schema_map:
                score += 1
            if error_count > 0 and not vuln_signal:
                score -= 2

            role    = str(latest_decision.get("target_role", "")).strip().lower()
            name    = str(latest_decision.get("target_name", "")).strip()
            action  = str(latest_decision.get("action",      "")).strip().lower()
            gravity = _coerce_int(latest_decision.get("gravity_score", 0))
            attack_surfaces = latest_decision.get("attack_surfaces", [])
            error_labels    = payload.get("error_labels", [])

            is_high_gravity_form = role in {"form", "textbox"} and gravity >= 7

            if score < 2 and not is_high_gravity_form:
                continue
            if not role or not name or action not in {"click", "fill", "select"}:
                continue

            key = (page_url, role, name, action)
            if key in seen:
                continue
            seen.add(key)

            candidates.append({
                "line":                 line_no,
                "page_url":             page_url,
                "target_role":          role,
                "target_name":          name,
                "action":               action,
                "associated_routes":    route_signatures,
                "error_labels":         error_labels if isinstance(error_labels, list) else [],
                "attack_surfaces":      attack_surfaces if isinstance(attack_surfaces, list) else [],
                "vulnerability_signal": vuln_signal,
                "network_pulses":       net_count,
                "network_requests":     request_rows,
                "request_body_schema":  route_schema_map or None,
                "request_body_samples": request_body_samples[:6],
                "gravity_score":        gravity,
                "rationale": (
                    f"score={score}; network={net_count}; "
                    f"url_changed={url_changed}; errors={error_count}; gravity={gravity}"
                ),
            })

            if len(candidates) >= limit:
                break

    candidates.sort(key=lambda x: x.get("gravity_score", 0), reverse=True)
    return candidates


# ─── Step 3 — derive structured findings for AgentState ──────────────────────

def _extract_login_endpoints(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    From hit targets, identify login/auth endpoints (POST routes with password-like fields).
    Returns list of {url, route, schema} dicts.
    """
    login_endpoints = []
    auth_keywords   = {"password", "passwd", "pass", "pwd", "secret", "token", "credential"}

    for cand in candidates:
        schema_map = cand.get("request_body_schema") or {}
        for route_sig, schema in schema_map.items():
            field_names = {k.lower() for k in schema.keys()}
            if field_names & auth_keywords:
                login_endpoints.append({
                    "page_url":   cand.get("page_url", ""),
                    "route":      route_sig,
                    "schema":     schema,
                    "target_role": cand.get("target_role", ""),
                    "target_name": cand.get("target_name", ""),
                })
    return login_endpoints


def _extract_discovered_endpoints(candidates: List[Dict[str, Any]]) -> List[str]:
    seen      = set()
    endpoints = []
    for cand in candidates:
        for route in cand.get("associated_routes", []):
            if route and route not in seen:
                seen.add(route)
                endpoints.append(route)
    return endpoints


def _extract_endpoint_schemas(candidates: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    merged: Dict[str, Dict[str, str]] = {}
    for cand in candidates:
        # POST/PUT schemas from request body samples
        schema_map = cand.get("request_body_schema") or {}
        for route_sig, schema in schema_map.items():
            merged[route_sig] = _merge_schemas(merged.get(route_sig, {}), schema)
        # GET query parameter schemas — inferred from query_keys captured during recon
        for req in cand.get("network_requests", []):
            if req.get("method") == "GET":
                q_keys = [k for k in req.get("query_keys", []) if k]
                if q_keys:
                    route = str(req.get("route", "")).strip()
                    if route:
                        sig = f"GET {route}"
                        get_schema = {k: "string" for k in q_keys}
                        merged[sig] = _merge_schemas(merged.get(sig, {}), get_schema)
    return merged


def _extract_attack_surfaces(candidates: List[Dict[str, Any]]) -> List[str]:
    seen     = set()
    surfaces = []
    for cand in candidates:
        for surface in cand.get("attack_surfaces", []):
            s = str(surface).strip()
            if s and s not in seen:
                seen.add(s)
                surfaces.append(s)
    return surfaces[:20]


# ─── Main entrypoint ──────────────────────────────────────────────────────────

def run_investigation(run_dir: str) -> Dict[str, Any]:
    """
    Full investigation pipeline over a browser-recon run directory.

    Returns a dict ready to be merged into AgentState:
      hit_targets, login_endpoints, discovered_endpoints,
      endpoint_schemas, browser_attack_surfaces
    """
    run_path      = pathlib.Path(run_dir)
    pipeline_path = run_path / "pipeline.jsonl"

    print(f"\n[INVESTIGATE] Analysing {pipeline_path}")

    # ── 1. Overview ────────────────────────────────────────────────────────────
    overview = get_pipeline_overview(pipeline_path)
    event_counts = overview.get("event_counts", {})
    print(
        f"[INVESTIGATE] Events: total={overview.get('total_lines', 0)} | "
        f"act_done={event_counts.get('act_done', 0)} | "
        f"reason_done={event_counts.get('reason_done', 0)}"
    )

    # ── 2. Candidate hits ──────────────────────────────────────────────────────
    candidates = extract_candidate_hits(pipeline_path, max_hits=20)
    print(f"[INVESTIGATE] Hit targets extracted: {len(candidates)}")

    # ── 3. Derive structured findings ─────────────────────────────────────────
    login_endpoints      = _extract_login_endpoints(candidates)
    discovered_endpoints = _extract_discovered_endpoints(candidates)
    endpoint_schemas     = _extract_endpoint_schemas(candidates)

    # ── 4. Summary (one Groq call via host call_llm) ──────────────────────────
    summary = _generate_summary(
        candidates=candidates,
        login_endpoints=login_endpoints,
        discovered_endpoints=discovered_endpoints,
        attack_surfaces=[],
    )

    # ── 5. Persist investigation JSON alongside pipeline.jsonl ────────────────
    report = {
        "run_id":               run_path.name,
        "summary":              summary,
        "hit_targets":          candidates,
        "login_endpoints":      login_endpoints,
        "discovered_endpoints": discovered_endpoints,
        "endpoint_schemas":     endpoint_schemas,
    }

    out_path = run_path / "investigation.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=True)
    print(f"[INVESTIGATE] Saved investigation report → {out_path}")

    return report


# ─── Optional LLM summary ────────────────────────────────────────────────────

_SUMMARY_FALLBACK_PROMPT = """
You are a penetration testing analyst. Based on the browser recon findings below, write a
concise (3-5 sentences) summary of the discovered attack surface for the security team.
Focus on: discovered endpoints, login/auth surfaces, potential vulnerability vectors.

Findings:
- Hit targets count: {hit_count}
- Login endpoints found: {login_count}
- Discovered routes: {routes}
- Attack surface signals: {surfaces}

Respond with a single paragraph. No markdown headers.
"""


def _generate_summary(
    *,
    candidates:          List[Dict[str, Any]],
    login_endpoints:     List[Dict[str, Any]],
    discovered_endpoints: List[str],
    attack_surfaces:     List[str],
) -> str:
    try:
        from functions import call_llm

        try:
            from tools.prompt_registry_tool import load_prompt_from_registry
            payload     = load_prompt_from_registry("browser_investigate_summary", "1")
            tags        = payload.get("tags") or {}
            system_tmpl = tags.get("system_prompt", "You are a security analyst. Summarise these browser recon findings in 3-5 sentences.")
            schema      = json.loads(tags["json_schema"])
        except Exception:
            system_tmpl = "You are a security analyst. Return only valid JSON."
            schema = {
                "name": "browser_investigate_summary",
                "schema": {
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"],
                    "additionalProperties": False,
                },
            }

        user_prompt = _SUMMARY_FALLBACK_PROMPT.format(
            hit_count   = len(candidates),
            login_count = len(login_endpoints),
            routes      = json.dumps(discovered_endpoints[:15]),
            surfaces    = json.dumps(attack_surfaces[:10]),
        ).strip()

        messages = [
            {"role": "system", "content": system_tmpl},
            {"role": "user",   "content": user_prompt},
        ]
        result = call_llm(messages, schema)
        return str(result.get("summary", "")).strip()

    except Exception as exc:
        print(f"[INVESTIGATE] Summary LLM skipped: {exc}")
        route_list = ", ".join(discovered_endpoints[:8]) or "none"
        return (
            f"Browser recon identified {len(candidates)} high-value interaction targets "
            f"and {len(login_endpoints)} potential login endpoint(s). "
            f"Discovered routes: {route_list}. "
            f"Attack surface signals: {', '.join(attack_surfaces[:5]) or 'none'}."
        )
