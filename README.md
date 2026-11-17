# PurpleHat — AI-Assisted Web Application Penetration Testing

PurpleHat is a **tester-controlled, AI-assisted** platform for web-application
security assessments. AI agents guide each phase of an engagement: they
explain, propose commands, and analyse output. **The tester runs every step.
Nothing runs automatically.**

> **⚠️ Authorized testing only.** Use this platform only against systems you own
> or have written permission to test, such as the local practice targets
> shipped with this repository (OWASP Juice Shop, DVWA, WebGoat, VulnShop). Keep
> those targets on your own machine or an isolated lab network. Never expose
> them to the internet.

---

## Quick start

**Already have Docker, Python 3.10, Node.js 20 and a Groq API key?** These
commands take you from zero to a running app. They are shown for Windows
PowerShell; the macOS/Linux differences are in [§5](#5-set-up-the-project-step-by-step).
**New to these tools?** Start at [§3 Prerequisites](#3-prerequisites).

```powershell
# 1. Get the code (private repo: Git asks you to sign in to GitHub the first time)
git clone https://github.com/ismailbokri/purplehat.git
cd purplehat

# 2. Configuration: copy the template, then open .env and fill in
#    your Groq key(s) and a JWT_SECRET
Copy-Item .env.example .env

# 3. Docker: network, database, sandbox, capture browser, one practice target
docker network create pentest-net
docker compose -f microservices/infrastructure/docker-compose.yml up -d pgvector
docker compose -f microservices/pentester/docker-compose.yml up -d --build
docker build -t browser-recon:latest microservices/browser-recon
docker compose -f microservices/target/docker-compose.yml up -d juice-shop

# 4. Backend dependencies
py -3.10 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# 5. Frontend: install and build
cd frontend; npm ci; npm run build; cd ..

# 6. Run
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Open **<http://127.0.0.1:8000>**, register an account, and create an assessment
with the target `http://localhost:8082` (Juice Shop). The first sandbox build
(step 3) can take 10–20 minutes.

---

## Table of contents

0. [Quick start](#quick-start)
1. [What the platform does](#1-what-the-platform-does)
2. [How the pieces fit together](#2-how-the-pieces-fit-together)
3. [Prerequisites](#3-prerequisites)
4. [Install the required software](#4-install-the-required-software)
5. [Set up the project (step by step)](#5-set-up-the-project-step-by-step)
6. [Run the application](#6-run-the-application)
7. [Your first assessment](#7-your-first-assessment)
8. [Verify the installation (tests)](#8-verify-the-installation-tests)
9. [Daily use: start, stop, reset](#9-daily-use-start-stop-reset)
10. [Configuration reference](#10-configuration-reference)
11. [Project structure](#11-project-structure)
12. [Troubleshooting](#12-troubleshooting)
13. [Working with GitHub](#13-working-with-github)
14. [Further documentation](#14-further-documentation)

---

## 1. What the platform does

| Feature | Description |
|---|---|
| **Phased workflow** | An engagement has three phases: **Discovery & Reconnaissance**, **Exploitation** (pre- and post-authentication tests together), and **Reporting**. |
| **Per-phase AI assistant** | Each phase has a chat assistant (Conversation Agent). It answers questions, suggests tests, and proposes commands. It never runs them itself. |
| **Execution sandbox** | You run commands (nmap, gobuster, curl, Python/Perl/Ruby/Bash scripts, …) in an isolated Docker container. Output streams live into the UI. |
| **Automatic verdicts** | After each sandbox run, the Finding Agent classifies the output as *Vulnerability Detected*, *Not Vulnerable*, or *Inconclusive*. Nothing is saved until you confirm it. |
| **Browser Explorer + Capture** | Browse the target inside the app. Capture a page's DOM and screenshot (headless Chromium) to give the assistant real page context. |
| **Scope management** | You define in-scope and out-of-scope targets for each assessment. The scope is added to every agent prompt. |
| **Findings & reporting** | Record findings from the sandbox, the chat, or by hand, then generate a **PDF report**. A reporting assistant can answer questions about your findings. |
| **Reference checklist** | A web pentest checklist, seeded into the database on first start, used as testing guidance. |
| **Threat-intel news** | A curated security news feed, refreshed weekly from public RSS sources. |

---

## 2. How the pieces fit together

```
  Your web browser
        │
        ▼
  React frontend ── dev: Vite on http://127.0.0.1:5173 (proxies API calls to :8000)
        │           prod: built files served by the backend on :8000
        │  REST + WebSocket
        ▼
  FastAPI backend (runs on the HOST, port 8000)
        │
        ├── PostgreSQL ........... Docker container "pgvector-db" (host port 6000)
        ├── Groq LLM API ......... over HTTPS (needs an API key + internet)
        └── docker CLI ──┬── docker exec → "pentest-container"   (sandbox, image pentest-tools)
                         └── docker run  → "browser-recon:latest" (one-shot Playwright capture)
                                     │
                    all on the Docker network "pentest-net", together with
                    the practice targets: juice-shop, dvwa-web, webgoat, vulnshop
```

Key points:

- The **backend is not containerized**. It runs on your machine with Python and
  controls Docker through the `docker` command. The `docker` CLI must work for
  the user who starts the backend.
- The sandbox and the capture container reach the targets **by container name**
  on `pentest-net` (for example `http://juice-shop:3000`). Your browser reaches
  the same targets on `localhost` ports (for example `http://localhost:8082`).
  The app translates between the two automatically.

---

## 3. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **OS** | Windows 10/11, macOS 12+, or Linux (Ubuntu 22.04+ / Debian 12) | Developed and verified on Windows 10 Pro. |
| **Git** | any recent | To clone and push the repository. |
| **Docker** | Docker Desktop 4.x **or** Docker Engine 24+ with **Compose v2** (`docker compose …`) | Runs the database, sandbox, capture browser, and targets. |
| **Python** | **3.10** (verified with 3.10.9) or 3.11 | 3.12+ is untested. Some dependencies expect `setuptools`, which 3.12 virtual environments no longer include. |
| **Node.js** | **20 LTS** (verified with 20.19.5), minimum 18 | Comes with npm (verified with 10.8.2). |
| **Groq API key** | free tier works | Create one at <https://console.groq.com/keys>. |
| **Hardware** | ≥ 8 GB RAM (16 GB recommended), ≈ 10 GB free disk | Give Docker at least 4 GB of RAM, or 8 GB if you run all practice targets at once. |
| **Internet** | during setup and use | To pull images and packages, and to reach the Groq API and the news feeds. |

---

## 4. Install the required software

Skip any tool you already have. Check each one with the command in its
"Verify" line.

### 4.1 Git

| OS | Command |
|---|---|
| Windows | `winget install -e --id Git.Git` (or download from <https://git-scm.com/download/win>) |
| macOS | `xcode-select --install` (or `brew install git`) |
| Ubuntu/Debian | `sudo apt update && sudo apt install -y git` |

Verify: `git --version`

### 4.2 Docker

#### Windows 10/11

1. Open **PowerShell as Administrator** and enable WSL 2 (Docker Desktop needs it):
   ```powershell
   wsl --install
   ```
   Reboot when asked.
2. Install Docker Desktop:
   ```powershell
   winget install -e --id Docker.DockerDesktop
   ```
   You can also download the installer from <https://www.docker.com/products/docker-desktop/>.
   Keep **"Use WSL 2 instead of Hyper-V"** checked during installation.
3. Start **Docker Desktop** from the Start menu and wait until it shows
   *Engine running*. Optionally, raise the memory limit in
   *Settings → Resources*.

#### macOS

1. Download Docker Desktop from <https://www.docker.com/products/docker-desktop/>.
   Pick the **Apple Silicon** or **Intel** build to match your Mac. With Homebrew,
   you can run `brew install --cask docker` instead.
2. Open **Docker** from Applications and wait for *Engine running*.
3. **Apple Silicon (M1/M2/M3/M4) only:** the sandbox image downloads x86-64
   binaries (Go, amass). Build it in x86-64 mode by running this in every
   terminal you use for Docker builds (or add it to `~/.zshrc`):
   ```bash
   export DOCKER_DEFAULT_PLATFORM=linux/amd64
   ```

#### Linux (Ubuntu / Debian)

```bash
# Install Docker Engine + Compose v2 with Docker's official script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Let your user run docker without sudo (the backend calls `docker` directly)
sudo usermod -aG docker $USER
newgrp docker          # or log out and back in
```

**Verify (all OSes):**

```bash
docker --version
docker compose version
docker run --rm hello-world
```

The last command must print *"Hello from Docker!"*.

### 4.3 Python 3.10

| OS | Command |
|---|---|
| Windows | `winget install -e --id Python.Python.3.10`. If you use the python.org installer instead, check **"Add python.exe to PATH"**. |
| macOS | `brew install python@3.10` |
| Ubuntu 22.04 | `sudo apt install -y python3.10 python3.10-venv python3.10-dev` |
| Ubuntu 24.04 / Debian 12 | `sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt update && sudo apt install -y python3.10 python3.10-venv python3.10-dev` (deadsnakes is Ubuntu-only; on Debian, use [pyenv](https://github.com/pyenv/pyenv)) |

**Linux and macOS only:** the PostgreSQL driver (`psycopg2`) is compiled from
source there, so you need the build tools:

```bash
# Ubuntu / Debian
sudo apt install -y build-essential libpq-dev
# macOS
brew install libpq && brew link --force libpq
```

Verify: `py -3.10 --version` (Windows) or `python3.10 --version` (macOS/Linux)

### 4.4 Node.js 20 LTS

| OS | Command |
|---|---|
| Windows | `winget install -e --id OpenJS.NodeJS.LTS` |
| macOS | `brew install node@20 && brew link --overwrite node@20` |
| Linux | Install [nvm](https://github.com/nvm-sh/nvm), then `nvm install 20 && nvm use 20` |

Verify: `node --version` (v20.x) and `npm --version`

> **Windows:** close and reopen your terminal after installing anything with
> `winget` so the new `PATH` takes effect.

---

## 5. Set up the project (step by step)

Run every command from the **project root** (the folder that contains this
README) unless a step says otherwise.

### Step 1 — Clone the repository

```bash
git clone https://github.com/ismailbokri/purplehat.git
cd purplehat
```

The repository is **private**. The first time, Git opens a browser window to
sign in to GitHub (or run `gh auth login` beforehand, see [§13.1](#131-one-time-git-setup-on-a-new-machine)).
Your GitHub account needs access to the repository: the owner adds you under
*Settings → Collaborators*.

### Step 2 — Create the `.env` configuration file

Copy the template:

```powershell
# Windows (PowerShell)
Copy-Item .env.example .env
```
```bash
# macOS / Linux
cp .env.example .env
```

Open `.env` in an editor and fill in at least these values:

- `GROQ_API_KEY1` … `GROQ_API_KEY4`: your Groq key(s). **All four must be
  set.** If you have only one key, paste it four times.
- `API_KEY_pfe`: a Groq key (it can be the same one).
- `JWT_SECRET`: a long random string. Generate one with:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(64))"
  ```
- `PFE_DB_*`: keep the defaults. They match the database container started in
  Step 4.

See [§10](#10-configuration-reference) for every variable.

### Step 3 — Create the shared Docker network

All containers (sandbox, capture browser, targets, database) talk to each other
on one network:

```bash
docker network create pentest-net
```

(If it says *"already exists"*, that's fine.)

### Step 4 — Start the PostgreSQL database

```bash
docker compose -f microservices/infrastructure/docker-compose.yml up -d pgvector
```

This starts the container `pgvector-db`, publishes it on host port **6000**,
creates the database `pfe` (user `postgres`, password `0000`), and stores the
data in a Docker volume. **You don't create any tables yourself**: the backend
creates the schema and seeds the checklist the first time it starts.

> That compose file also defines an `mlflow` service. It is legacy and **not
> needed**. Naming `pgvector` in the command starts only the database.

Verify:

```bash
docker exec pgvector-db pg_isready -U postgres
# → /var/run/postgresql:5432 - accepting connections
```

### Step 5 — Build and start the execution sandbox

This builds the `pentest-tools` image (nmap, whatweb, dirsearch, dirb, gobuster,
amass, sublist3r, waybackurls, git-dumper, bfac, curl, plus Python, Perl, Ruby
and Bash runtimes). It then starts the long-running container
`pentest-container` that the app executes commands in.

```bash
docker compose -f microservices/pentester/docker-compose.yml up -d --build
```

The first build downloads Go and several tools and **can take 10–20 minutes**.
Later starts take seconds.

Verify:

```bash
docker exec pentest-container bash -lc "nmap --version | head -1 && whatweb --version"
```

### Step 6 — Build the browser-capture image

The **Capture** and browser-exploration features start a one-shot container
from the image `browser-recon:latest` (Python + Playwright + Chromium). Build it
once:

```bash
docker build -t browser-recon:latest microservices/browser-recon
```

Verify: `docker image inspect browser-recon:latest --format "{{.Id}}"` prints an
image ID.

### Step 7 — Start one or more practice targets

These are deliberately vulnerable apps for practicing safely. Start all three
standard targets:

```bash
docker compose -f microservices/target/docker-compose.yml up -d
```

You can also start only the ones you need, for example
`... up -d juice-shop`. VulnShop, the custom e-commerce target shipped in this
repo, has its own compose file:

```bash
docker compose -f vulnshop/docker-compose.yml up -d --build
```

| Target | Open in browser | Name inside Docker | Default login |
|---|---|---|---|
| OWASP Juice Shop | <http://localhost:8082> | `juice-shop:3000` | register in the app |
| DVWA | <http://localhost:8081> | `dvwa-web:80` | `admin` / `password` — open `/setup.php` first and click **Create / Reset Database** |
| WebGoat | <http://localhost:8083/WebGoat> | `webgoat:8080` | register in the app. The bare `/` returns 404 by design. |
| VulnShop | <http://localhost:8084> | `web:5000` | `admin` / `admin123` (see [vulnshop/README.md](vulnshop/README.md)) |

> VulnShop also publishes its MySQL database on host port **3306** on purpose.
> If you already run MySQL locally, stop it first or leave VulnShop off.

Verify the sandbox can reach a target:

```bash
docker exec pentest-container curl -sI http://juice-shop:3000
# → HTTP/1.1 200 OK
```

> **Windows shortcut:** `microservices/run.ps1` runs Steps 3, 4 (plus the
> legacy MLflow), 5, 6 and 7 in one go. It also builds a legacy `http-probe`
> image that the app no longer uses. Run it from inside `microservices/`:
> `cd microservices; powershell -ExecutionPolicy Bypass -File .\run.ps1; cd ..`

### Step 8 — Install the Python backend dependencies

Create a virtual environment named `venv` in the project root, activate it, and
install the pinned dependencies:

```powershell
# Windows (PowerShell)
py -3.10 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
```bash
# macOS / Linux
python3.10 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Your prompt now starts with `(venv)`. **Activate the venv in every new
terminal** before you run backend commands.

> - Windows error *"running scripts is disabled on this system"*: run
>   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate
>   again.
> - Always use `python -m pip …`, not `pip.exe`. The `.exe` launchers break if
>   the venv folder is moved or renamed.
> - If `psycopg2` fails to build on macOS/Linux and you can't install the build
>   tools from §4.3, use the prebuilt package instead:
>   ```bash
>   python -m pip install psycopg2-binary==2.9.11
>   grep -v '^psycopg2==' requirements.txt > /tmp/req.txt && python -m pip install -r /tmp/req.txt
>   ```

### Step 9 — Install the frontend dependencies

```bash
cd frontend
npm ci          # exact versions from package-lock.json
cd ..
```

(`npm install` also works. `npm ci` gives a reproducible install.)

Setup is complete. Continue with [§6](#6-run-the-application).

---

## 6. Run the application

Before starting, make sure Docker is running and that `pgvector-db` and
`pentest-container` are up (`docker ps`).

### Option A — Development mode (two terminals, hot reload for the UI)

**Terminal 1 — backend** (project root, venv activated):

```bash
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

On the first start you should see the schema being applied and the checklist
seeded. Leave it running. Add `--reload` if you are editing backend code.

**Terminal 2 — frontend:**

```bash
cd frontend
npm run dev
```

Open **<http://127.0.0.1:5173>**. Vite forwards `/api`, `/auth`, `/checklist`,
`/runs` and `/health` (including WebSockets) to the backend on port 8000.

### Option B — Single-port mode (build the UI once, serve it from the backend)

```bash
cd frontend
npm run build          # produces frontend/dist/
cd ..
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Open **<http://127.0.0.1:8000>**. The backend serves the built UI when
`frontend/dist/` exists.

> **Note:** in this mode, refreshing the browser on a deep link such as
> `/sessions/…` returns `{"detail":"Not Found"}`. Go back to `/` and navigate
> from there, or use Option A.

> **Network exposure:** `--host 127.0.0.1` keeps the app reachable only from
> your machine. Use `--host 0.0.0.0` only on a trusted lab network. The app can
> execute commands in the sandbox.

---

## 7. Your first assessment

1. Open the app and click **Register**. Create an account, then log in.
2. Click **New assessment** and enter a target, for example
   `http://localhost:8082` (Juice Shop). You can leave Port empty when it is
   already in the URL. Optionally add extra endpoints.
3. On the **Scope** step, set the in-scope target (for example
   `http://localhost:8082`). Review and launch.
4. Open the **Discovery** module. In the AI assistant pane on the right, ask
   *"What should I scan first?"* Click a suggested command to send it to the
   **Execution Sandbox** tab, then run it. The output streams live, and a
   verdict card appears when the run finishes.
5. Use **Browser Explorer → Capture** on an interesting page to send its DOM
   and screenshot to the assistant.
6. In **Exploitation**, provide credentials if the target needs them, ask for
   test ideas, and run them in the sandbox. Use the save button on a verdict
   card to record it as a finding. You can also add findings by hand.
7. Open **Report** to discuss your findings with the reporting assistant, then
   generate the report and click **Download PDF**. A copy is also written to
   `reports/`.

> When you type a target as `localhost:<port>`, the app automatically uses the
> matching container address inside the sandbox (for example `localhost:8082`
> becomes `juice-shop:3000`). Inside the sandbox, `localhost` would point at the
> sandbox itself.

---

## 8. Verify the installation (tests)

> **There is no automated unit-test suite in this repository yet.** Use the
> smoke checks below to confirm that each part of the stack works. Run them
> from the project root with the venv activated.

| # | What it checks | Command | Expected result |
|---|---|---|---|
| 1 | All backend Python files compile | `python -m compileall -q agents auth db graphs news server tools config.py functions.py` | no output, exit code 0 |
| 2 | Backend imports with your `.env` | `python -c "import server.main; print('backend OK')"` | `backend OK` |
| 3 | Python dependencies are consistent | `python -m pip check` | `No broken requirements found.` |
| 4 | Backend is up (start it first, §6) | Windows: `curl.exe http://127.0.0.1:8000/health` · macOS/Linux: `curl http://127.0.0.1:8000/health` | `{"status":"ok"}` |
| 5 | Database schema was created | `docker exec pgvector-db psql -U postgres -d pfe -c "\dt"` | tables incl. `users`, `checklist_tests`, `pentest_sessions`, `findings`, `chat_messages`, `news_articles` |
| 6 | Checklist was seeded | `docker exec pgvector-db psql -U postgres -d pfe -c "SELECT COUNT(*) FROM checklist_tests;"` | a number > 0 |
| 7 | Sandbox tools work | `docker exec pentest-container bash -lc "nmap --version && whatweb --version"` | version lines |
| 8 | Sandbox reaches a target | `docker exec pentest-container curl -sI http://juice-shop:3000` | `HTTP/1.1 200 OK` |
| 9 | Capture image works | `docker run --rm --entrypoint python browser-recon:latest -c "import playwright; print('playwright OK')"` | `playwright OK` |
| 10 | Frontend builds | `cd frontend && npm run build` | `✓ built in …`, no errors |

**End-to-end check (manual):** do §7 steps 1–4 against Juice Shop. If a sandbox
command produces output and a verdict card, the frontend, backend, database,
Docker sandbox, and LLM are all wired correctly.

---

## 9. Daily use: start, stop, reset

**Start everything** (after the first setup):

```bash
docker compose -f microservices/infrastructure/docker-compose.yml up -d pgvector
docker compose -f microservices/pentester/docker-compose.yml up -d
docker compose -f microservices/target/docker-compose.yml up -d juice-shop   # or any targets you need
# then start the backend and frontend as in §6
```

**Stop** the backend and frontend with `Ctrl+C` in their terminals, then stop
the containers:

```bash
docker compose -f microservices/target/docker-compose.yml stop
docker compose -f vulnshop/docker-compose.yml stop
docker compose -f microservices/pentester/docker-compose.yml stop
docker compose -f microservices/infrastructure/docker-compose.yml stop
```

On Windows, `cd microservices; .\stop.ps1` removes the containers in one go
(data volumes are kept).

**Rebuild the sandbox** after changing `microservices/pentester/Dockerfile`:

```bash
docker compose -f microservices/pentester/docker-compose.yml up -d --build --force-recreate
```

**Reset the database** (⚠️ deletes all users, assessments, and findings):

```bash
docker compose -f microservices/infrastructure/docker-compose.yml down -v
docker compose -f microservices/infrastructure/docker-compose.yml up -d pgvector
# restart the backend — it recreates the schema and re-seeds the checklist
```

**Update to the latest code** on a machine that is already set up:

```bash
git pull
python -m pip install -r requirements.txt     # venv activated
cd frontend && npm ci && cd ..
```

---

## 10. Configuration reference

### Environment variables (`.env` in the project root)

| Variable | Required | Default / example | Purpose |
|---|---|---|---|
| `GROQ_API_KEY1` … `GROQ_API_KEY4` | **yes (all four)** | `gsk_…` | Groq keys used by the AI agents. The app rotates through them on rate limits (HTTP 429). The same key four times is fine. |
| `API_KEY_pfe` | **yes** | `gsk_…` | Groq key for the browser-exploration and parsing helpers. The backend won't start without it. |
| `JWT_SECRET` | strongly recommended | random 64+ chars | Signs login tokens. If unset, an insecure development default is used and a warning is logged. |
| `PFE_DB_HOST` | **yes** | `localhost` | PostgreSQL host |
| `PFE_DB_PORT` | **yes** | `6000` | PostgreSQL port (host side of the container) |
| `PFE_DB_NAME` | **yes** | `pfe` | Database name |
| `PFE_DB_USER` | **yes** | `postgres` | Database user |
| `PFE_DB_PASSWORD` | **yes** | `0000` | Database password |
| `MODEL` | no | `openai/gpt-oss-120b` | Model for the browser-exploration helper. Other agents use `MODEL` in `config.py`. |
| `REPORT_*_PROMPT_NAME/VERSION` | no | see `.env.example` | Override which prompt files in `prompts/` the report generator uses. |

### Ports

| Port | Service | Started by |
|---|---|---|
| 8000 | FastAPI backend (and built UI in single-port mode) | `uvicorn` |
| 5173 | Vite dev server (UI) | `npm run dev` |
| 6000 | PostgreSQL (`pgvector-db`) | infrastructure compose |
| 8081 | DVWA | target compose |
| 8082 | OWASP Juice Shop | target compose |
| 8083 | WebGoat | target compose |
| 8084 | VulnShop | `vulnshop/docker-compose.yml` |
| 3306 | VulnShop MySQL (exposed on purpose) | `vulnshop/docker-compose.yml` |
| 5000 | MLflow (legacy, not needed) | infrastructure compose (only if started) |

### Docker names the code expects (do not rename)

| Kind | Name | Defined in |
|---|---|---|
| Network | `pentest-net` | created manually (Step 3) |
| Sandbox container | `pentest-container` (image `pentest-tools`) | `microservices/pentester/docker-compose.yml`, `tools/sandbox_tool.py` |
| Capture image | `browser-recon:latest` | `microservices/browser-recon/`, `tools/capture_tool.py` |

Allowed recon commands and the default LLM model are set in
[config.py](config.py).

---

## 11. Project structure

```
.
├── server/                 FastAPI app — entry point server/main.py, API routes in server/routes/
├── agents/                 AI agents (phase conversation agent, browser exploration, report, news curator)
├── tools/                  Sandbox, capture, scope, findings, PDF report, Docker URL mapping …
├── auth/                   Password hashing (bcrypt) and JWT handling
├── db/                     PostgreSQL connection, schema.sql, startup bootstrap/seed
├── news/                   RSS/Atom feed list and fetcher for the news module
├── graphs/                 Module/phase key definitions
├── prompts/                Versioned prompt templates (JSON) used by the agents/report
├── palnner/                Pentest checklist (checklist.json, seeded into the DB) + PDF template
├── frontend/               React 18 + Vite single-page app (src/, package.json)
├── microservices/
│   ├── infrastructure/     PostgreSQL (pgvector) [+ legacy MLflow] compose file
│   ├── pentester/          Sandbox image (recon tools + language runtimes)
│   ├── browser-recon/      Playwright/Chromium capture image
│   ├── target/             DVWA, Juice Shop, WebGoat compose file
│   ├── http-probe/         Legacy probe image (no longer used)
│   └── run.ps1 / stop.ps1  Windows helpers to start/stop the Docker stack
├── vulnshop/               Custom intentionally-vulnerable e-commerce target
├── scripts/                One-off maintenance scripts (checklist translation/re-seed)
├── docs/                   Design documentation
├── config.py               Global settings (model, allowed commands, …)
├── functions.py            LLM client (Groq) with key rotation + command helpers
├── requirements.txt        Pinned Python dependencies
├── .env.example            Template for your local .env
└── reports/                (generated, git-ignored) PDF/text reports and findings
```

---

## 12. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `[startup] DB bootstrap FAILED: … connection refused` | PostgreSQL isn't running or `PFE_DB_*` is wrong. Run `docker ps` and check that `pgvector-db` is *Up*. Port 6000 must be free. |
| `ValueError: No API key at index 0` on startup | `GROQ_API_KEY1` is missing from `.env`, or `.env` isn't in the project root. |
| `GroqError: The api_key client option must be set` | `API_KEY_pfe` is missing from `.env`. |
| Agent replies fail after a while with `No API key at index N` | One of `GROQ_API_KEY2..4` is empty. The rotation hit an empty slot, so fill in all four. |
| `sandbox container 'pentest-container' is not running` | Start it: `docker compose -f microservices/pentester/docker-compose.yml up -d`. |
| `network pentest-net declared as external, but could not be found` | Run `docker network create pentest-net` (Step 3). |
| Capture fails: `docker is not available on the host` | The backend can't find the `docker` CLI. Start Docker Desktop, reopen the terminal, check `docker ps`. On Linux, add your user to the `docker` group (§4.2). |
| Capture fails: `Unable to find image 'browser-recon:latest'` | Build it (Step 6). |
| Sandbox commands time out against `localhost:…` | Inside the sandbox, use the Docker name (`http://juice-shop:3000`), or enter the target as `localhost:<port>` in the app and let it translate. |
| `gobuster: command not found` / `waybackurls: command not found` in the sandbox | Known issue: the sandbox runs commands in a login shell, which drops the Go tools folder from `PATH`. Workaround: call them by full path, for example `/root/go/bin/gobuster dir -u http://juice-shop:3000 -w /usr/share/wordlists/dirb/common.txt`. |
| `exec format error` in the sandbox (Apple Silicon) | Rebuild with `DOCKER_DEFAULT_PLATFORM=linux/amd64` set (§4.2 macOS). |
| Juice Shop shows blank in Browser Explorer | The app loads it through its built-in proxy. If a page still won't render, use the **↗ Tab** button to open it in a real browser tab. Capture still works either way. |
| WebGoat shows *unhealthy* in `docker ps` / 404 on `/` | Expected. Use <http://localhost:8083/WebGoat/login>. |
| `bind: address already in use` / port is allocated | Another program uses 8000/5173/6000/808x/3306. Stop it or change the host port in the relevant compose file. |
| `the attribute 'version' is obsolete` warning | Harmless warning from newer Docker Compose. Ignore it. |
| `Activate.ps1 cannot be loaded … running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| `Unable to create process using …\python.exe` | The venv was moved or copied from another machine. Delete `venv/` and redo Step 8. Never copy a venv between machines. |
| `pg_config executable not found` while installing | Install the build tools (§4.3) or use `psycopg2-binary` (Step 8 note). |
| `{"detail":"Not Found"}` after refreshing a page on port 8000 | Expected in single-port mode. Go to `/`, or use development mode (§6). |
| News page is empty | The weekly refresh runs in the background at startup and needs internet access plus a working Groq key. Check the backend log for `[startup] news update …`. |
| `remote: Repository not found` on `git clone` / `git push` of this private repo | Git used a saved GitHub login that can't see the repository. Run `gh auth login`, then `gh auth setup-git`, so Git uses the GitHub CLI login. On Windows you can also delete the `git:https://github.com` entry in *Credential Manager → Windows Credentials* and retry. |
| VulnShop `/.env` or `/.git/config` return an error | Those two bait files are not in Git (Git can't track a `.git` folder, and `.env` files are ignored). The other VulnShop vulnerabilities work. |

---

## 13. Working with GitHub

The code lives in the **private** repository
<https://github.com/ismailbokri/purplehat> (branch `main`).

### 13.1 One-time Git setup on a new machine

```bash
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"
git config --global init.defaultBranch main
```

**Authentication.** GitHub no longer accepts account passwords for `git push`
over HTTPS. Use one of these:

- **Git Credential Manager** (bundled with Git for Windows): the first `git push`
  opens a browser window to sign in. Nothing else to do.
- **GitHub CLI**: install it (`winget install -e --id GitHub.cli` /
  `brew install gh` / [Linux instructions](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)),
  then run `gh auth login` and choose *HTTPS*.
- **SSH key**: `ssh-keygen -t ed25519 -C "you@example.com"`, add the contents of
  `~/.ssh/id_ed25519.pub` under GitHub → *Settings → SSH and GPG keys*, and use
  the `git@github.com:<user>/<repo>.git` remote URL.

### 13.2 Safety checks before every push

```bash
# 1. .env must be ignored — this must print a .gitignore rule, not nothing
git check-ignore -v .env

# 2. Nothing secret staged: review the file list
git status

# 3. No Groq keys in tracked files (should print nothing)
git grep -nI "gsk_[A-Za-z0-9]\{20,\}"
```

GitHub rejects files larger than **100 MB**. Keep datasets, Docker exports,
and generated reports out of the repo (the `.gitignore` already does this for
`reports/`, `*.db`, `venv/`, `node_modules/`, and `frontend/dist/`).

> **If a secret ever gets committed:** revoke and regenerate that key at the
> provider immediately. Deleting the file in a later commit does **not** remove
> it from Git history.

### 13.3 Save and push your changes

```bash
git status                 # see what changed
git add -A                 # stage new, modified and deleted files
git status                 # check again: no .env, no venv/, no reports/
git commit -m "Short description of the change"
git push                   # send your commits to GitHub (branch main)
```

To get changes made on another machine, run `git pull`, then reinstall the
dependencies as described in [§9](#9-daily-use-start-stop-reset)
(*Update to the latest code*).

**Bigger change?** Work on a branch and merge it through a pull request:

```bash
git switch -c my-feature           # create and switch to a new branch
# … edit files, then git add -A and git commit as above …
git push -u origin my-feature
gh pr create --fill                # open a pull request into main on GitHub
```

### 13.4 Give someone access

The repository is private. On GitHub, open **purplehat → Settings →
Collaborators → Add people** and invite the person's GitHub account. They then
follow the [Quick start](#quick-start) or [§5](#5-set-up-the-project-step-by-step).
Remember that `.env` is never pushed: each machine needs its own copy, created
from `.env.example`.

### 13.5 Publishing to a brand-new repository (for reference)

This is how the repository was created. Use the same steps to publish a copy
elsewhere:

```bash
git add -A
git commit -m "Initial commit"
gh repo create <new-name> --private --source . --remote origin
git push -u origin main
```

Without the GitHub CLI: create an **empty** repository on
<https://github.com/new>. Don't add a README, .gitignore or license there,
because it would make the first push conflict. Then run
`git remote add origin https://github.com/<user>/<new-name>.git` and
`git push -u origin main`.

---

## 14. Further documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, data flow, orchestration model |
| [docs/agents.md](docs/agents.md) | The AI agents, their roles, scope injection, routing |
| [docs/sandbox-and-scope.md](docs/sandbox-and-scope.md) | Execution model, isolation, scope semantics |
| [docs/news-module.md](docs/news-module.md) | Feeds, weekly refresh, curation policy |
| [docs/getting-started.md](docs/getting-started.md) | Earlier setup notes |
| [vulnshop/README.md](vulnshop/README.md) | VulnShop vulnerability catalogue by phase |

> Some files in `docs/` predate the latest refactor. Exploit generation has
> since been removed, and the pre- and post-authentication phases were merged
> into **Exploitation**. **For installation and running, this README is the
> reference.**

**Safety & scope:** the scope is enforced at the AI-guidance level (an
instruction added to every agent prompt). It is **not** a network firewall.
You remain responsible for testing only authorized targets.
