# Agents

The platform has **5 active agents** (plus one dormant Report agent). Agents
never execute anything; they answer, propose, interpret, or generate artifacts
the tester then uses.

## 1–3. Conversation Agents (one per phase)

File: `agents/conversation_agent.py`. Phases: `discovery`, `preauth`, `postauth`.

Each is a specialist copilot for its phase. It:
- answers questions and explains what to test next,
- proposes shell commands / short scripts (returned as `suggestions`, which the
  UI drops into the Execution Sandbox — never auto-run),
- interprets sandbox output and captured browser context,
- can indicate a `route` to the Browser Explorer or Exploit Generation.

The **Discovery agent** absorbs the responsibilities of the old `plan_node`
(propose recon commands) and `parse_agent` (interpret scan output). Routing
(old `router_agent`) is now simply the agent's `route` field.

Each turn, the backend builds the prompt from the scope block + phase system
prompt + a session-state slice + history + the message. Output is strict JSON:
```json
{"reply": "...", "suggestions": [{"label": "...", "command": "..."}], "route": "none|browser_explorer|exploit_generation"}
```

Module → phase mapping: `discovery→discovery`, `preauth→preauth`,
`postauth / preauth_in_postauth / business_logic → postauth`.

## 4. Browser Explorer

On-demand capture rather than autonomous exploration.
- `microservices/browser-recon/capture_runner.py` — one-shot Playwright load of a
  single URL → screenshot + compact DOM outline (forms, inputs, links, buttons).
- `tools/capture_tool.py` — runs it in the `browser-recon` container and parses
  the result.
- `server/routes/capture_routes.py` — on **Capture**, stores the page summary in
  session state and seeds one chat turn so the phase agent analyzes it.

## 5. Exploit Generation

File: `agents/exploit_generation_agent.py`. Bundles the three surviving exploit
steps into a single tester-invoked call:
1. **RAG retrieval — top 3** (`tools/exploit_retrival_tool.py`,
   `MIN_RETRIEVAL_PER_TYPE = 3`, via `plan_agent.retrieval_node`),
2. **relevance review** (`review_agent`),
3. **code generation** (`llm_generator_agent`).

The generated exploit is written into the session sandbox workspace. The tester
runs it manually in the Execution Sandbox. There is **no** auto-execute,
auto-patch, or auto-log-parse — if a run fails, ask the phase agent for help.

## Dormant: Report Agent

`agents/report_agent.py` still exists but is not wired into the current UI.
Reporting is a later phase; its code (and its de-branding) is intentionally
untouched for now.

## Scope injection

Every agent prompt includes the rendered scope block from
`tools/scope_tool.py:render_scope_prompt(scope)`. Agents are instructed to stay
within the in-scope targets and to decline out-of-scope requests with a reason.
See [sandbox-and-scope.md](sandbox-and-scope.md).

## Removed agents

`prober`, `router`, `auth` (node), `prepare_exploit`, `prepare_artifacts`,
`exploit` (executor), `fallback`, `parse_logs`, `probe_payload_generator` were
removed when the autonomous pipeline was retired. Deterministic login survives
as a utility (`tools/browser_explore_tool.py:run_auth_preflight` +
`apply_auth_to_state`), not an AI agent.
