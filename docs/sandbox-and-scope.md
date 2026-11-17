# Sandbox & Scope

## Execution sandbox (Interface B)

The tester runs authorized commands and generated exploits inside a single,
long-lived Docker container — never on the host.

- **Image:** `pentest-tools`, built once from `microservices/pentester/Dockerfile`.
  It is pre-baked with recon tools (nmap, whatweb, dirsearch, gobuster, amass,
  sublist3r, waybackurls, git-dumper, curl, dig, whois, …) **and** language
  runtimes for generated exploits (python + requests/urllib3/bs4, perl + LWP/JSON,
  ruby + json, bash). No agent builds a Dockerfile — everything needed is in the
  image from the start.
- **Container:** `pentest-container`, running on the `pentest-net` network so it
  reaches targets by name (`http://juice-shop:3000`).
- **Workspace:** each session gets an isolated directory `/workspace/<session_id>`
  inside the container. Generated files land there and are listed/readable from
  the UI.

### How it runs (`tools/sandbox_tool.py`)

- `run_command(session_id, command, on_line=…)` → `docker exec -w <workspace>
  pentest-container bash -lc "cd <workspace> && <command>"`, streaming stdout
  line-by-line to the session WebSocket (`sandbox_output` events).
- `list_files` / `read_file` inspect generated artifacts. Filenames are
  validated (no `..`, no shell metacharacters) before use.
- Only the backend route `POST /api/sessions/{id}/exec` triggers execution, and
  only on an explicit tester action. No agent calls the sandbox.

### Isolation boundaries

- Commands run **inside** the container, not on the host. There is no host
  filesystem mount beyond the per-session workspace.
- Network access is limited to `pentest-net` (where your authorized targets
  live). Do **not** attach untrusted or production networks to it.
- A per-command timeout prevents a runaway process from hanging a session.

> This is isolation suited to a controlled lab against intentionally vulnerable
> targets. It is not a hardened multi-tenant sandbox — run it on a machine you
> control, with only authorized targets on `pentest-net`.

## Scope

Each assessment session carries a **scope** object (`pentest_sessions.scope`):

```json
{
  "in_scope": ["http://juice-shop:3000"],
  "authorized_domains": ["juice-shop"],
  "out_of_scope": ["/admin/billing"],
  "restrictions": "No destructive payloads; rate-limit requests",
  "auth_requirements": "Standard user account",
  "notes": "Focus on the REST API under /rest"
}
```

- Edit it at session creation or via the **Scope** tab
  (`ScopeEditor.jsx` → `PATCH /api/sessions/{id}/scope`).
- `tools/scope_tool.py:render_scope_prompt(scope)` turns it into a system-prompt
  block that is injected into **every** agent call. Agents are instructed to
  only act within in-scope targets and to decline out-of-scope requests with an
  explanation.

### Important limitation

Scope is enforced at the **AI-guidance level** — it shapes what the agents
recommend. It is **not** a network firewall or an allow-list on the sandbox:
the sandbox will run whatever command you type. You remain responsible for only
testing authorized targets. The UI states this next to the scope editor.
