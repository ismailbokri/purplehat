"""Module metadata for the tester-driven workflow.

The platform no longer runs autonomous per-module LangGraph subgraphs. The
penetration tester drives each phase manually through the phase Conversation
Agent (chat) and the Execution Sandbox. This module now only exposes the
mapping from a UI module key to its checklist category.
"""

# UI module key → checklist category exposed in the DB.
# Two active phases only. The former "preauth" and "postauth" modules were
# merged into a single "Exploitation" phase (their checklist items were re-tagged
# to the "Exploitation" category in the DB; see db/bootstrap.py). Reporting is a
# dedicated module handled separately (agents/report_agent.py).
MODULE_CATEGORY: dict[str, str] = {
    "discovery":    "Discovery",
    "exploitation": "Exploitation",
}

MODULE_KEYS = tuple(MODULE_CATEGORY.keys())

__all__ = ["MODULE_CATEGORY", "MODULE_KEYS"]
