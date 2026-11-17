# Implementation Plan — Cybersecurity Assessment & AI-Assistant Platform

> Transform the existing auto-pilot pentest pipeline into a **tester-controlled, AI-assisted** assessment platform. The penetration tester drives every phase; agents recommend and explain but never execute autonomously.

**Status:** planning — not yet implemented. The codebase currently holds the OLD architecture.
**Last updated:** 2026-11-07.

---

## 0. How to read this document

Each phase is self-contained and independently shippable: **the application must run after every phase.** Phases are ordered so no phase breaks a previously completed one. Every phase lists:

1. Objective
2. Files to inspect first
3. Files to modify
4. Files to create
5. Files to remove
6. Technical changes (step by step)
7. Data-model / API changes
8. Dependencies on earlier phases
9. Expected result
10. Validation criteria
11. Risks / notes

Global rules in **§3** apply to every phase and are not repeated.

---

## 1. Current state (verified)

### 1.1 Two parallel backends
| | Legacy `/vtest` | Modular `/api/sessions` |
|---|---|---|
| Entry | `server/main.py` `POST /vtest` | `server/routes/sessions_routes.py` |
| Graph | `app.py` `build_graph()` — all 17 nodes | `graphs/` — 3 subgraphs |
| Behaviour | one call runs the whole scan→exploit→report chain unattended | tester runs one module at a time, but each module **still auto-chains internally** |
| Frontend | `frontend/src/pages/Dashboard.jsx` (1309 lines) | `SessionLayout → ModulesOverview → ModuleRunner` |
| Reachable from UI? | **No** — `App.jsx` has no route; `/dashboard` redirects to `/sessions` | **Yes** — the only live UI |

`Dashboard.jsx` is dead frontend code. `/vtest` is still mounted server-side.

### 1.2 Module subgraphs (`graphs/`)
- `discovery.py` — `plan` + `parse` loop.
- `checklist_loop.py` — `auth → browser_explore → browser_investigate → prober → router → retrieve → review → prepare_exploit → llm_generator → prepare_artifacts → execute → fallback → (loop)`. **Fully autonomous once started** — this is the automation to remove.
- `business_logic.py` — browser-driven variant.
- `MODULE_CATEGORY` (`graphs/__init__.py`): `discovery`, `preauth`, `postauth`, `preauth_in_postauth`, `business_logic`.

### 1.3 Agents (`agents/`) — 16 standalone LLM roles today
`plan_agent.plan_node`, `parse_agent`, `auth_agent`, `browser_explore_agent`, `browser_investigate_agent`, `prober_agent`, `router_agent`, `plan_agent.retrieval_node`, `review_agent`, `prepare_exploit_agent`, `llm_generator_agent`, `prepare_artifacts_agent`, `exploit_agent` (executor), `fallback_agent`, `parse_logs_agent`, `report_agent`. Helper: `probe_payload_generator_agent` (used only by prober).

### 1.4 Infrastructure that already exists and is reused
- **Sandbox image** — `microservices/pentester/Dockerfile`: nmap, whatweb, dirb, dirsearch, gobuster, amass, sublist3r, waybackurls, git-dumper, bfac. Invoked today only by agents via `docker exec pentest-container …` (`agents/plan_agent.py`). No interactive exec exposed to the tester.
- **Browser recon microservice** — `microservices/browser-recon/`: autonomous Playwright; streams screenshots the frontend replays passively (`components/BrowserReplay.jsx`).
- **Exploit runtimes** — `tools/exec_exploit.py` holds per-language fallback Dockerfiles (python/perl/bash/ruby) built per-exploit at run time.
- **Auth / credentials injection** — `components/AuthPanel.jsx` + `PATCH /api/sessions/{id}/auth` (credentials / cookies / bearer). Clean; **keep unchanged.**
- **Auth/JWT** — `auth/security.py` (bcrypt + JWT), `auth/dependencies.py`. Solid; keep.
- **DB** — `db/schema.sql`, `db/connection.py`, `db/bootstrap.py`. Tables: `users`, `checklist_tests`, `pentest_runs`, `pentest_sessions`, `findings`.
- **Checklist** — `checklist_tests` table + `tools/checklist_tool.py`; structured OWASP-style methodology driving per-module test selection.
- **Scraper** — `scrapper/` (HTTP fetch + parse patterns) — reuse for the News fetcher.

### 1.5 Branding / stale files
Legacy third-party branding strings in `config.py` (comment), `tools/checklist_tool.py`, `tools/generate_report_tool.py`, `agents/report_agent.py` (report only — postponed), the original checklist JSON (now `palnner/checklist.json`) (superseded by DB table). `arapport_pfe/` is the author's academic report — **not app code, never touched.**

---

## 2. Target architecture

### 2.1 Agent roster: 16 → **5 active (6 in codebase)**

**Active:**
| # | Agent | Owns / absorbs | How invoked |
|---|---|---|---|
| 1 | Discovery & Reconnaissance Conversation Agent | absorbs `plan_node` + `parse_agent` | chat; routes to Browser Explorer |
| 2 | Pre-authentication Conversation Agent | pre-auth guidance; interprets sandbox output | chat; routes to Exploit Generation |
| 3 | Post-authentication Conversation Agent | post-auth guidance using auth + capture context | chat; routes to Exploit Generation + Browser Explorer |
| 4 | Browser Explorer Agent | on-demand DOM + screenshot capture & analysis (reuses `browser_explore` + `browser_investigate`) | called by a Conversation Agent / Capture button |
| 5 | Exploit Generation Agent | RAG retrieval (**top-3**) + relevance review + code generation (reuses `retrieval_node` + `review_agent` + `llm_generator_agent`) | called by a Conversation Agent |

**Dormant (postponed):** Report Agent (`agents/report_agent.py`) — reactivated in Phase 10 only.

**Deleted (8):** `auth_agent`, `prober_agent`, `router_agent`, `prepare_exploit_agent`, `prepare_artifacts_agent`, `exploit_agent`, `fallback_agent`, `parse_logs_agent`. Also `probe_payload_generator_agent` (orphaned when prober goes — verify before deleting).

**Merged away (2):** `plan_node`, `parse_agent` → folded into the Discovery Conversation Agent.

**Phase mapping:** the brief's 4 phases (Discovery & Recon, Pre-auth, Post-auth, Reporting). 3 Conversation Agents active now; Reporting's 4th added in Phase 10. The code's extra modules (`preauth_in_postauth`, `business_logic`) become **checklist-category groupings inside the Post-authentication phase**, not separate agents.

### 2.2 Keep / change / remove / new
- **Keep as-is:** JWT auth, DB layer, `checklist_tests` + tool, credentials-injection UI, `pentest_sessions` model, sandbox image concept, browser-recon microservice (repurposed), exploit RAG vector store.
- **Change:** module run = conversational + manual, not a graph auto-run; RAG top-3; sandbox pre-baked; scope injected into prompts.
- **Remove:** `/vtest`, `app.py` graph, `Dashboard.jsx`, 8 agents, auto-chaining subgraph edges, legacy third-party branding.
- **New:** scope model, phase colors, execution sandbox API/UI, per-phase chat, browser capture, News module, landing page, docs.

### 2.3 Orchestration model
FastAPI stays the single orchestrator — no agent-to-agent messaging. A Conversation Agent receives: `render_scope_prompt(scope)` + a session-state slice (discovered endpoints, auth status, last capture, last sandbox output) + the tester's message. It returns prose plus optional structured suggestions (`suggested_command`, `suggested_script`, `route: browser_explorer|exploit_generation`). The UI renders suggestions as one-click **"insert into sandbox"** actions — the tester still presses Run. No agent calls `exec`.

---

## 3. Global constraints & conventions (apply to all phases)

1. **No automatic execution.** Nothing runs a command, script, scan, or exploit without an explicit tester click. Agents may *propose*; only the tester (or an explicit, user-triggered capture) acts.
2. **Reporting is frozen until Phase 10.** Do not modify `agents/report_agent.py`, `tools/generate_report_tool.py` report logic, or the PDF template before Phase 10.
3. **Inspect before changing.** Every phase starts by reading the files it touches and grepping for cross-references; report findings before deleting.
4. **No scope-creep edits.** Touch only the files the phase names. Do not refactor working code without a stated reason.
5. **No unnecessary dependencies.** Frontend stays lean (react, react-router-dom, marked). Justify any new package.
6. **Scope respected.** Once Phase 1 lands, every agent prompt carries the scope block; agents must refuse out-of-scope targets with an explanation.
7. **Deployment target:** runs locally as a normal web app (frontend + API reachable in a browser), tested against containerized vulnerable targets (OWASP Juice Shop, DVWA) on the same Docker network. No public cloud deploy required.
8. **`arapport_pfe/` is untouchable.**
9. **Attribution** on commits/PRs per the session's current reminder.
10. **Runnable after every phase** — validated before moving on.

---

## 4. Data-model changes (consolidated)

All via `db/schema.sql` (idempotent `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE … ADD COLUMN IF NOT EXISTS`), applied by `db/bootstrap.py` on startup.

- **Phase 1 — scope:** `ALTER TABLE pentest_sessions ADD COLUMN IF NOT EXISTS scope JSONB NOT NULL DEFAULT '{}'::jsonb;` Shape: `{in_scope: [], out_of_scope: [], authorized_domains: [], restrictions: "", auth_requirements: "", notes: ""}`.
- **Phase 4 — chat history:** `chat_messages(id, pentest_session_id FK, phase TEXT, role TEXT CHECK(role IN ('user','assistant')), content TEXT, suggestions JSONB, created_at)`. Index on `(pentest_session_id, phase, created_at)`.
- **Phase 7 — news:** `news_articles(id, url UNIQUE, title, summary, source, affected_technologies TEXT[], published_at, fetched_at, content_hash UNIQUE)` + `news_meta(key PK, value)` holding `last_news_update`.
- **Phase 0 — cleanup:** remove `pentest_runs.skip_scan` only if confirmed unused by `sessions_runtime.py`. Keep `pentest_runs` and `findings`.

---

## 5. API surface (consolidated)

Existing (keep): `POST/GET/DELETE /api/sessions…`, `PATCH …/endpoints`, `PATCH …/auth`, `POST …/modules/{key}/run`*, `GET …/findings`, `POST …/report`, `GET …/report.pdf`, `…/ws`.
(*`/run` semantics change in Phase 4 from "start graph" to "start/validate a phase chat session".)

New:
- **Phase 1:** `PATCH /api/sessions/{id}/scope`, `GET …/scope`.
- **Phase 3:** `POST /api/sessions/{id}/exec` (stream stdout over `…/ws`), `GET …/files`, `GET …/files/{name}`.
- **Phase 4:** `POST /api/sessions/{id}/phases/{phase}/chat`, `GET …/phases/{phase}/chat` (history).
- **Phase 5:** `POST /api/sessions/{id}/exploits/generate` (invokes Exploit Generation Agent, writes to sandbox workspace).
- **Phase 6:** `POST /api/sessions/{id}/capture` (Playwright DOM+screenshot → phase chat).
- **Phase 7:** `GET /api/news`, `POST /api/news/refresh` (admin, manual trigger).

Removed (Phase 0): `/vtest`, `/ws/{session_id}`, `/status/{session_id}`, `/report/{session_id}`, `/report-pdf/{session_id}`.

---

## 6. Phase dependency map

```
P0 cleanup ──┬─> P1 scope ──┐
             ├─> P2 colors   ├─> P4 conversation agents ─> P5 exploit-gen ─> P6 capture
             └─> P3 sandbox ─┘                                                   │
P0 ──> P7 news ───────────────────────────────> P8 landing <────── P2, P7       │
P0..P8 ──> P9 docs ──> P10 reporting (deferred) <───────────────────────────────┘
```
Critical path: **P0 → P3 → P4 → P5 → P6**. P1, P2, P7 are parallelizable after P0.

---

## 7. Phases

### Phase 0 — Dead-code & brand cleanup
**Objective:** remove orphaned legacy code with zero behaviour change to the live app.
**Inspect:** `server/main.py`, `app.py`, `App.jsx`, `frontend/src/api/{checklist,findings}.js`, `tools/checklist_tool.py`, `tools/generate_report_tool.py`, `config.py`, `sessions_runtime.py` (for `skip_scan`).
**Modify:** `server/main.py` — delete `/vtest`, `_run_pipeline`, `_get_pipeline`, `sessions` dict, `NODE_LABELS`, `_NODE_UI_PHASE`, `_get_ui_phase`, `_next_step_hint`, `_extract_logs`, and `/ws/{session_id}`, `/status/{session_id}`, `/report/{session_id}`, `/report-pdf/{session_id}`, plus `/vtest`-only Pydantic models. Keep `/health`, static mount, DB bootstrap hook, and all `app.include_router(...)`. Remove legacy branding wording from `config.py`, `tools/checklist_tool.py`, `tools/generate_report_tool.py` (text only).
**Create:** none.
**Remove:** `app.py` `build_graph()` + global wiring (keep agent modules still imported by `graphs/`); `frontend/src/pages/Dashboard.jsx`; dead API exports used only by Dashboard; the original checklist JSON (now `palnner/checklist.json`) (after confirming `checklist_tool.py` reads only the DB).
**Technical changes:** pure subtraction. Do not touch `graphs/`, `sessions_runtime.py`, `sessions_routes.py`, `agents/report_agent.py`.
**Data/API:** remove listed routes; optionally drop `pentest_runs.skip_scan` if unused.
**Depends on:** —.
**Expected result:** smaller codebase, identical running behaviour.
**Validation:** `uvicorn server.main:app` boots; `npm run build` passes; `GET /health` → 200; create-session → run module → findings works as before; a case-insensitive grep for the legacy brand name over the 3 app files is empty; `report_agent.py` diff empty; no references remain to `Dashboard`, `build_graph`, `NODE_LABELS`.
**Risks:** a hidden import of `app.build_graph` — grep first.

### Phase 1 — Scope management
**Objective:** per-session scope definition injected into every agent prompt.
**Inspect:** `pentest_sessions` schema, `sessions_runtime.py` (`_empty_agent_state`, snapshot helpers), `sessions_routes.py`.
**Modify:** `db/schema.sql` (+`scope` column), `sessions_runtime.py` (persist/restore scope), `sessions_routes.py` (+routes, include scope in `SessionOut`), `SessionSetup.jsx` / `SessionLayout.jsx` (surface the editor).
**Create:** `tools/scope_tool.py` → `render_scope_prompt(scope: dict) -> str`; `frontend/src/components/ScopeEditor.jsx`; `frontend/src/api/scope.js`.
**Remove:** none.
**Technical changes:** structured scope form → stored JSONB → rendered to a deterministic system-prompt block. Enforcement is prompt-level (not a network firewall) — state this in the UI.
**Data/API:** `scope` column; `PATCH/GET …/scope`.
**Depends on:** P0.
**Expected result:** scope persists and round-trips; present in agent prompts (once agents exist).
**Validation:** save/reload persists; dev-log a sample prompt and confirm the scope block is present; empty scope → empty block, no crash.
**Risks:** none significant.

### Phase 2 — Phase visual identity
**Objective:** color-code phases — Discovery/Recon = blue, Pre-auth = green, Post-auth = red, Reporting = purple.
**Inspect:** `frontend/src/theme/`, `ModulesOverview.jsx`, `SessionLayout.jsx`, tag styles.
**Modify:** theme CSS (phase color custom properties), `ModulesOverview.jsx` (cards), `SessionLayout.jsx` (nav), status tags.
**Create:** `MODULE_COLOR` token map (in theme or `api/sessions.js`).
**Remove:** none.
**Technical changes:** CSS custom properties `--phase-discovery/-preauth/-postauth/-reporting`; apply to nav items, module cards, phase badges. No logic change.
**Depends on:** P0.
**Expected result:** each phase visually distinct and consistent light/dark.
**Validation:** visual review on every session page; contrast acceptable in both themes.
**Risks:** none.

### Phase 3 — Unified sandbox + Execution & Inspection environment (Interface B)
**Objective:** one pre-baked image with all permitted tools + runtimes; tester-driven command/script execution with output inspection.
**Inspect:** `microservices/pentester/Dockerfile`, `microservices/run.ps1`/`stop.ps1`, `tools/exec_exploit.py`, `tools/docker_target_map.py`, `server/sessions_runtime.py` (WS emit), `components/LiveLog.jsx`.
**Modify:** `microservices/pentester/Dockerfile` — add python/perl/ruby/bash runtimes + common exploit libs (requests, urllib3, LWP::UserAgent, JSON, etc.) alongside existing recon tools. `tools/exec_exploit.py` — stop generating per-exploit Dockerfiles; run inside the fixed image.
**Create:** `server/routes/exec_routes.py` (`POST …/exec`, `GET …/files`, `GET …/files/{name}`); `frontend/src/components/SandboxPanel.jsx` (command input, streamed output, generated-file list + viewer); `frontend/src/api/exec.js`.
**Remove:** per-exploit Dockerfile generation path in `exec_exploit.py` (dead after unified image).
**Technical changes:** each session gets a workspace dir mounted into the container run; `exec` runs `docker exec` (or `docker run --rm` with the workspace + target network) and streams stdout/stderr over the existing session WS; no host filesystem mount beyond the workspace; container network limited to the target. Output persisted so the Conversation Agent can read "last sandbox output".
**Data/API:** `POST …/exec`, `GET …/files`.
**Depends on:** P0.
**Expected result:** tester runs `nmap`/`curl`/a script and watches live output; generated files browsable.
**Validation:** against a local Juice Shop container: `nmap`/`curl` stream correctly; file write appears in `GET …/files`; container cannot read host paths outside the workspace; concurrent sessions isolated.
**Risks:** Docker socket availability on the host; document the `docker build` setup step.

### Phase 4 — Conversation Agents (the pivot)
**Objective:** replace automatic workflow with per-phase chat copilots; remove Prober/Router/Auth-as-agent and all auto-chaining.
**Inspect:** all of `graphs/`, `agents/{plan,parse,prober,router,auth,browser_explore,browser_investigate}_agent.py`, `sessions_runtime.py` (`run_module_thread`), `sessions_routes.py` (`/run`), `ModuleRunner.jsx`, `SessionLayout.jsx` reducer, `functions.py` (LLM call helpers), `tools/prompt_registry_tool.py`.
**Modify:** `graphs/discovery.py`, `graphs/checklist_loop.py`, `graphs/business_logic.py` — dismantle auto-chains (or retire the graphs entirely once the chat flow covers them). `sessions_routes.py` / `sessions_runtime.py` — `/run` becomes "open/validate a phase chat session" instead of launching a graph. `ModuleRunner.jsx` — new layout: ChatPanel + SandboxPanel (+ Capture in P6), per-phase. `App.jsx` routing if phase routes change.
**Create:** `agents/conversation_agent.py` — a base `ConversationAgent` + 3 phase specialists (Discovery&Recon, Pre-auth, Post-auth) differing by system prompt, allowed routes, and state slice. `server/routes/chat_routes.py` (`POST/GET …/phases/{phase}/chat`). `frontend/src/components/ChatPanel.jsx`, `frontend/src/api/chat.js`. Prompt definitions (MLflow registry or local) per phase.
**Remove:** `agents/prober_agent.py`, `agents/router_agent.py`, `agents/probe_payload_generator_agent.py` (verify prober-only). Strip the **agent** role from `agents/auth_agent.py`: relocate the deterministic Selenium login / cookie extraction into a plain utility (e.g. `tools/auth_login.py`) called by `PATCH …/auth`; delete the LLM parts. Fold `plan_node` + `parse_agent` logic into the Discovery Conversation Agent, then remove them as graph nodes.
**Technical changes:** chat endpoint builds prompt = scope block + phase system prompt + state slice + history + user message; returns `{reply, suggestions[], route?}`. `suggestions` render as "insert into sandbox"; `route` offers a button to invoke Browser Explorer (P6) or Exploit Generation (P5). Persist turns to `chat_messages`. The automatic graph no longer runs.
**Data/API:** `chat_messages` table; chat routes.
**Depends on:** P1 (scope), P3 (sandbox to route commands into).
**Expected result:** tester chats per phase; guidance is scoped and non-executing; `plan`/`parse`/`prober`/`router`/`auth` agents gone.
**Validation:** ask a Discovery question → scoped answer + a command that lands in the sandbox input (not auto-run); out-of-scope target → agent declines with reason; confirm no graph auto-chain fires; credentials injection still works unchanged.
**Risks:** largest phase — may be split into P4a (Discovery), P4b (Pre-auth), P4c (Post-auth). Keep `findings` writing intact so Phase 10 has data.

### Phase 5 — Exploit Generation Agent (top-3) + remove execution agents
**Objective:** one tester-invoked exploit builder; execution remains the tester's job in the sandbox.
**Inspect:** `agents/plan_agent.retrieval_node`, `agents/review_agent.py`, `agents/llm_generator_agent.py`, `tools/exploit_retrival_tool.py`, `tools/exploit_review_tool.py`, `config.py` (`retrieval_top_k`), `sessions_runtime.py`.
**Modify:** `tools/exploit_retrival_tool.py` — `MIN_RETRIEVAL_PER_TYPE` 20 → **3**. `server/sessions_runtime.py` + any remaining default — `retrieval_top_k` 15 → **3**. Wrap `retrieval_node` + `review_agent` + `llm_generator_agent` into one callable `ExploitGenerationAgent` writing generated code into the session sandbox workspace.
**Create:** `server/routes/exploit_routes.py` (`POST …/exploits/generate`); `frontend/src/components/ExploitGenPanel.jsx` (or a chat action); `frontend/src/api/exploits.js`.
**Remove:** `agents/prepare_exploit_agent.py`, `agents/prepare_artifacts_agent.py`, `agents/exploit_agent.py`, `agents/fallback_agent.py`, `agents/parse_logs_agent.py` (orphaned after P4). Clean their imports from `sessions_runtime.py`.
**Technical changes:** generate = retrieve top-3 → relevance review → adapt/generate one script into `exploit_<id>/` in the workspace. The tester runs it via Phase-3 `exec`. On failure the tester asks the Conversation Agent — no auto-patch, no auto-log-parse.
**Data/API:** `POST …/exploits/generate`.
**Depends on:** P3, P4.
**Expected result:** ≤3 candidates considered; one exploit script written to the sandbox and listed in `GET …/files`.
**Validation:** request an exploit → retrieval returns ≤3; generated file appears and runs manually against DVWA/Juice Shop; removed agents have no remaining references.
**Risks:** top-3 may reduce hit rate — acceptable per requirement; note it in docs.

### Phase 6 — Browser Explorer Agent + Capture (Interface, Section 6)
**Objective:** integrated browser with an explicit **Capture** button feeding the phase Conversation Agent.
**Inspect:** `microservices/browser-recon/browser_recon_runner.py`, `agents/browser_explore_agent.py`, `agents/browser_investigate_agent.py`, `tools/browser_explore_tool.py`, `tools/browser_investigate_tool.py`, `components/BrowserReplay.jsx`.
**Modify:** repurpose `browser_explore`/`browser_investigate` from autonomous clicking to **on-demand** DOM + screenshot capture + analysis. `ModuleRunner.jsx` — add an iframe browser panel + Capture button.
**Create:** `server/routes/capture_routes.py` (`POST …/capture` → Playwright loads the given URL, extracts DOM outline + screenshot, attaches user notes, hands to the phase Conversation Agent); `frontend/src/components/BrowserExplorer.jsx` (iframe + Capture); optional same-origin proxy if the target blocks framing; `frontend/src/api/capture.js`.
**Remove:** autonomous recon-loop invocation (keep the capture primitives).
**Technical changes:** Capture is strictly user-triggered; result `{dom_summary, screenshot_b64, user_notes}` posted into the current phase's chat, which replies with analysis/recommendations. BrowserReplay can be retired or kept for history.
**Data/API:** `POST …/capture`.
**Depends on:** P4 (chat to deliver capture into).
**Expected result:** tester browses the target, clicks Capture, agent responds using DOM content — not just the URL.
**Validation:** capture a DVWA page → agent reply references real DOM elements; cross-origin target handled (proxy or documented limitation).
**Risks:** iframe cross-origin framing — proxy fallback documented.

### Phase 7 — News intelligence module
**Objective:** curated cybersecurity news, weekly auto-refresh, presented with no AI traces.
**Inspect:** `scrapper/` (fetch/parse patterns), `db/bootstrap.py` (startup hook), `functions.py` (LLM helper), `auth/dependencies.py` (admin gate).
**Modify:** `db/schema.sql` (+`news_articles`, `news_meta`), `db/bootstrap.py` / `server/main.py` startup (check `last_news_update`; if > 7 days, run fetch in a background thread — never blocking startup).
**Create:** `news/fetcher.py` (~20 configured feeds), `news/config.py` (feed list), `agents/news_curator_agent.py` (classify relevance, generate professional title + concise summary, extract affected tech/vulns/dates, reject irrelevant, dedupe by `content_hash`/`url`), `server/routes/news_routes.py` (`GET /api/news`, `POST /api/news/refresh` admin), `frontend/src/pages/News.jsx`, `frontend/src/api/news.js`.
**Remove:** none.
**Technical changes:** one curator agent processes each fetched article; only validated rows stored. **UI shows none of:** AI involvement, relevance %, confidence scores, processing traces. Clean card grid.
**Data/API:** `news_articles`, `news_meta`; `GET /api/news`, `POST /api/news/refresh`.
**Depends on:** P0.
**Expected result:** curated, deduped articles on a professional feed page.
**Validation:** manual `POST /api/news/refresh` inserts deduped rows; second run adds no duplicates; UI contains no AI/confidence markers; startup skips fetch when `last_news_update` < 7 days.
**Risks:** feed availability/format drift — fetcher must tolerate per-feed failures.

### Phase 8 — Landing / overview page
**Objective:** professional entry point (active assessments + progress, quick links to News and new assessment).
**Inspect:** `App.jsx`, `SessionList.jsx`, News API.
**Modify:** `App.jsx` (new `/` overview route), nav.
**Create:** `frontend/src/pages/Overview.jsx`.
**Remove:** none (Dashboard already gone in P0).
**Technical changes:** cards for active sessions with phase-colored progress; a News teaser; "New assessment" CTA; consistent typography/spacing.
**Depends on:** P2, P7.
**Expected result:** polished landing reflecting real data.
**Validation:** shows real sessions + latest news; links work; phase colors applied.
**Risks:** none.

### Phase 9 — Documentation
**Objective:** deliver the `README.md` + 5 Markdown docs.
**Create:** `README.md` (overview, setup, running the app, spinning up Juice Shop/DVWA targets, first assessment walkthrough); `docs/architecture.md` (components, agent roster, orchestration); `docs/getting-started.md` (install, env, DB, sandbox `docker build`, run); `docs/agents.md` (the 5 agents, roles, scope injection, routing); `docs/sandbox-and-scope.md` (execution model, isolation, scope semantics + prompt-level limitation); `docs/news-module.md` (feeds, weekly refresh, curation policy).
**Depends on:** reflects final state → after P0–P8.
**Validation:** a new user sets up and runs the app from the README alone, including bringing up a vulnerable target and completing one scoped chat + sandbox cycle.
**Risks:** keep docs in sync if later phases change behaviour.

### Phase 10 — Reporting phase (DEFERRED — build last)
**Objective:** reactivate reporting with a 4th Conversation Agent; de-brand.
**Inspect:** `agents/report_agent.py`, `tools/generate_report_tool.py`, `findings` table, `ReportButton.jsx`, `server/routes/sessions_routes.py` report routes.
**Modify (only now):** remove legacy branding from `report_agent.py` / `generate_report_tool.py` and replace the PDF template; wire the Reporting phase UI (purple).
**Create:** Reporting Conversation Agent; reporting view.
**Remove:** legacy branded template asset.
**Technical changes:** consume accumulated `findings`; Conversation Agent helps structure/explain the report; generation stays on-demand (`POST …/report`).
**Depends on:** P0–P9 (findings accumulated throughout).
**Expected result:** generate a de-branded report from a completed session's findings.
**Validation:** run a full assessment → findings present → generate report → PDF renders without legacy branding.
**Risks:** report template rework scope — keep contained to this phase.

---

## 8. Deliverables summary
- Running tester-controlled platform (Phases 0–8).
- 5 active agents (6 in codebase incl. dormant Report Agent).
- `README.md` + 5 docs (Phase 9).
- Reporting (Phase 10, deferred).

## 9. Risks & limitations
- **Scope enforcement is prompt-level**, not network-level — surfaced in UI and docs.
- **Phase 4 is large** — split per phase-agent if needed.
- **Top-3 RAG** may lower exploit hit rate — intentional.
- **iframe cross-origin** — proxy fallback or documented limitation.
- **Docker required on host** for sandbox + targets — documented.

## 10. Validation strategy
After each phase: boot API, `npm run build`, smoke-test the live `/api/sessions` flow, and run the phase's specific validation. End-to-end target: against local **Juice Shop** and **DVWA** containers on the pentest Docker network, complete create-session → set scope → chat per phase → run commands/exploits in the sandbox → capture a page → accumulate findings, entirely tester-driven.
```
```
