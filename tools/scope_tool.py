"""Assessment scope — normalization and system-prompt rendering.

A session's scope is a plain dict stored on `pentest_sessions.scope`. It is
turned into a deterministic instruction block by `render_scope_prompt` and
injected into every agent's system prompt so agents stay within the targets
the penetration tester authorized.

NOTE: enforcement is prompt-level (an instruction to the LLM), not a network
firewall. The UI states this limitation to the tester.
"""

from typing import Any, Dict, List

# Canonical scope fields. Anything else in an incoming dict is ignored.
_LIST_FIELDS = ("in_scope", "out_of_scope", "authorized_domains")
_TEXT_FIELDS = ("restrictions", "auth_requirements", "notes")


def normalize_scope(scope: Any) -> Dict[str, Any]:
    """Coerce arbitrary input into the canonical scope shape.

    Lists are de-duplicated and stripped; text fields are trimmed. Unknown keys
    are dropped. Always returns every canonical key so downstream code never
    needs `.get(... , default)`.
    """
    src = scope if isinstance(scope, dict) else {}
    out: Dict[str, Any] = {}

    for field in _LIST_FIELDS:
        raw = src.get(field) or []
        if not isinstance(raw, (list, tuple)):
            raw = [raw]
        seen: set = set()
        items: List[str] = []
        for v in raw:
            s = str(v).strip()
            if s and s not in seen:
                items.append(s)
                seen.add(s)
        out[field] = items

    for field in _TEXT_FIELDS:
        v = src.get(field)
        out[field] = str(v).strip() if v is not None else ""

    return out


def scope_is_empty(scope: Dict[str, Any]) -> bool:
    s = normalize_scope(scope)
    return (
        not s["in_scope"] and not s["out_of_scope"] and not s["authorized_domains"]
        and not s["restrictions"] and not s["auth_requirements"] and not s["notes"]
    )


def render_scope_prompt(scope: Any) -> str:
    """Render the scope into a system-prompt block.

    Returns an empty string when no scope is defined, so callers can safely
    concatenate the result unconditionally.
    """
    s = normalize_scope(scope)
    if scope_is_empty(s):
        return ""

    lines: List[str] = [
        "## ASSESSMENT SCOPE (authorized boundaries — must be respected)",
    ]
    if s["in_scope"]:
        lines.append("In-scope targets (only these may be tested):")
        lines += [f"  - {t}" for t in s["in_scope"]]
    if s["authorized_domains"]:
        lines.append("Authorized domains:")
        lines += [f"  - {d}" for d in s["authorized_domains"]]
    if s["out_of_scope"]:
        lines.append("Out-of-scope (never test or recommend testing these):")
        lines += [f"  - {t}" for t in s["out_of_scope"]]
    if s["restrictions"]:
        lines.append(f"Testing restrictions: {s['restrictions']}")
    if s["auth_requirements"]:
        lines.append(f"Authentication requirements: {s['auth_requirements']}")
    if s["notes"]:
        lines.append(f"Additional instructions: {s['notes']}")

    lines.append(
        "Never suggest, plan, or perform actions against anything outside the "
        "in-scope targets and authorized domains above. If the tester asks about "
        "an out-of-scope resource, explain that it is out of scope and decline."
    )
    return "\n".join(lines)
