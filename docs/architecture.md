# Architecture

## Overview

PenTest AI is a tester-controlled assessment platform. A single FastAPI backend
orchestrates everything; there is no autonomous agent-to-agent pipeline. The
tester creates an **assessment session**, works through phases, and drives every
action. Agents only answer, propose, and interpret.

```
┌──────────────┐     HTTP / WebSocket      ┌─────────────────────────────┐
│  React SPA   │ ────────────────────────▶ │  FastAPI backend (server/)  │
│ (frontend/)  │ ◀──────────────────────── │                             │
└──────────────┘       events stream        │  routes: sessions, chat,    │
                                            │  exec, exploit, capture,     │
                                            │  news, findings, auth        │
                                            └───────┬──────────┬──────────┘
                                                    │          │
                                      agents/ (LLM) │          │ Docker
                                                    ▼          ▼
                                        Conversation / Exploit  pentest-container
                                        / Browser / News agents (sandbox + targets)
                                                               Postgres (db/)
```

## Backend (`server/`)

- `main.py` — app setup, routers, startup hooks (DB bootstrap + weekly news).
- `routes/`
  - `sessions_routes.py` — create/list/delete sessions; endpoints, auth, scope;
    module "runs" (which now just load the phase's checklist tests — no graph).
  - `chat_routes.py` — per-phase AI Assistant chat.
  - `exec_routes.py` — execution sandbox (run command, list/read files).
  - `exploit_routes.py` — exploit generation (top-3 RAG → review → generate).
  - `capture_routes.py` — on-demand browser capture → feeds the phase chat.
  - `news_routes.py` — curated news list + admin refresh.
  - `findings_routes.py`, `auth_routes.py`, `checklist_routes.py` — unchanged.
- `sessions_runtime.py` — in-memory session store, state hydration, DB helpers,
  the (now non-autonomous) module-run worker, chat persistence.
- `stdout_capture.py` — forwards agent `print()` output to the session WebSocket.

## Agents (`agents/`)

5 active (see [agents.md](agents.md)):

1. **Conversation Agent** (`conversation_agent.py`) — one specialist per phase
   (discovery, preauth, postauth). Scope-aware; returns `{reply, suggestions, route}`.
2. **Browser Explorer** — on-demand capture (`tools/capture_tool.py` +
   `microservices/browser-recon/capture_runner.py`).
3. **Exploit Generation** (`exploit_generation_agent.py`) — bundles the surviving
   `plan_agent.retrieval_node` + `review_agent` + `llm_generator_agent`.
4. **News Curator** (`news_curator_agent.py`) — classifies/curates news items.

`report_agent.py` exists but is dormant (reporting is a later phase).

## Orchestration model

No cross-agent messaging. For each chat turn, the backend assembles the prompt
from: the rendered **scope block** + the phase system prompt + a compact
**session-state slice** (discovered endpoints, auth status, last capture, last
sandbox output) + chat history + the tester's message. The agent returns text
plus optional structured suggestions the UI renders as one-click "insert into
sandbox" actions — the tester still presses Run. Nothing an agent returns is
executed automatically.

## Data model (`db/schema.sql`)

- `users`, `pentest_sessions` (+ `scope` JSONB), `pentest_runs`, `findings`,
  `checklist_tests` — existing.
- `chat_messages` — per-phase chat history.
- `news_articles`, `app_meta` — curated news + `last_news_update`.

## Frontend (`frontend/src/`)

- Pages: `Overview` (landing), `SessionList`, `SessionSetup`, `SessionLayout`
  (+ `ModulesOverview`, `ModuleRunner`, `ScopeView`, `FindingsView`,
  `EndpointsView`), `News`, `Checklist`, `Login`, `Register`.
- Key components: `ChatPanel`, `SandboxPanel`, `ExploitGenPanel`,
  `BrowserExplorer`, `ScopeEditor`, `AuthPanel`.
- Phase colours: `index.css` tokens + `MODULE_PHASE_CLASS` in `api/sessions.js`.

## What was removed

The former autonomous pipeline (`/vtest`, `app.py` global graph, all
`graphs/*` subgraphs) and the agents it chained (`prober`, `router`,
`auth` node, `prepare_exploit`, `prepare_artifacts`, `exploit` executor,
`fallback`, `parse_logs`, `probe_payload_generator`) were deleted. See
[../IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) for the full history.
