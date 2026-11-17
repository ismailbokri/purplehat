# Getting started

## Prerequisites

- **Docker** (running) — for the sandbox and vulnerable targets.
- **Python 3.11** with the project virtualenv.
- **Node 18+** and npm — for the frontend.
- **PostgreSQL** reachable from the backend.

## 1. Environment variables

Create a `.env` in the project root:

```ini
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/pentestai
# (or the discrete PG* vars your db/connection.py expects)

# Auth
JWT_SECRET=<a long random string>

# LLM provider keys (as used by functions.py / config.py)
API_KEY_pfe=<groq/openai-compatible key>
GROQ_API_KEY1=<groq key>                      # rotated pool used by all agents
MODEL=openai/gpt-oss-120b                    # or your configured model
```

> The exact variable names are read in `config.py`, `functions.py`, and
> `auth/security.py`. Check those files if a key is missing at runtime.

## 2. Python dependencies

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
```

> Always invoke pip as `venv\Scripts\python.exe -m pip …` (not `venv\Scripts\pip.exe`).
> If the venv folder is ever moved or renamed, the `.exe` launchers in `Scripts\`
> keep the old absolute path baked in and fail with "Unable to create process …";
> `python -m pip` sidesteps that entirely.

> **Known issue:** some pinned versions in a pre-existing environment can clash
> (`langchain_huggingface` expecting a `ModelProfile` symbol that the installed
> `langchain_core` doesn't export). If the backend fails to import on boot, pin
> compatible `langchain`/`langchain-core`/`langchain-huggingface` versions
> together and reinstall.

## 3. Database

The backend applies `db/schema.sql` automatically on startup (idempotent) and
seeds the checklist on first run. Just ensure the database exists and
`DATABASE_URL` points to it.

## 4. Sandbox image, network, and container

```powershell
# shared network for the sandbox + targets
docker network create pentest-net

# build the pre-baked sandbox (recon tools + python/perl/ruby/bash runtimes)
docker build -t pentest-tools microservices/pentester

# run the long-lived sandbox container the app execs into
docker run -d --name pentest-container --network pentest-net pentest-tools tail -f /dev/null

# build the browser-capture image (used by the Capture button)
docker build -t browser-recon:latest microservices/browser-recon
```

## 5. A vulnerable target (example)

```powershell
docker run -d --name juice-shop --network pentest-net bkimminich/juice-shop
# or DVWA:
docker run -d --name dvwa --network pentest-net vulnerables/web-dvwa
```

Because the target shares `pentest-net`, the sandbox reaches it by container
name, e.g. `http://juice-shop:3000` or `http://dvwa:80`.

## 6. Run the app

```powershell
# backend
venv\Scripts\uvicorn server.main:app --host 0.0.0.0 --port 8000

# frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Open the Vite URL, register a user, and log in.

## 7. Your first assessment

1. **New assessment** → enter target `http://juice-shop:3000`.
2. Set the **Scope** (in-scope: `http://juice-shop:3000`), save.
3. Open the **Discovery & Reconnaissance** module.
4. In the **AI Assistant**, ask "what should I scan first?" — click a suggested
   command to drop it into the **Execution sandbox**, then Run.
5. Use **Browser explorer → Capture** on an interesting page to get analysis.
6. In **Post-authentication**, provide credentials, then ask for test cases and
   use **Exploit generation** for a confirmed finding.

Nothing runs on its own — every command and exploit is launched by you.
