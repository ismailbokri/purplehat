#!/usr/bin/env python3
# =============================================================================
#  VulnShop  -  Intentionally Vulnerable E-Commerce Target
# =============================================================================
#  FOR AUTHORIZED SECURITY TESTING AND EDUCATION ONLY.
#  This application is DELIBERATELY insecure. Run it ONLY inside an isolated
#  lab (the provided Docker network). NEVER expose it to the public Internet.
#
#  Vulnerability map (phase -> where to find it):
#
#  [1] DISCOVERY
#      - Verbose / misleading Server + X-Powered-By headers        (after_request)
#      - Missing security headers, insecure cookies                (after_request)
#      - robots.txt leaking private paths                          /robots.txt
#      - Exposed secrets                                           /.env /config.py
#      - Exposed source-control metadata                           /.git/config /.git/HEAD
#      - Exposed database backup                                   /backup/<file>
#      - Fake Apache status / phpinfo (fingerprint confusion)      /server-status /phpinfo
#      - Directory listing of uploads                              /uploads/
#      - Debug endpoint leaking environment                        /debug
#      - Werkzeug interactive debugger (debug=True)                any 500 error
#      - Open MySQL port (see docker-compose)                      tcp/3306
#
#  [2] PRE-AUTHENTICATION EXPLOITATION
#      - SQL injection (auth bypass)                               POST /login
#      - SQL injection (UNION, data extraction)                    /search  /product/<id>
#      - Reflected XSS                                             /search  /api/echo
#      - Server-Side Template Injection (Jinja2)                   /hello
#      - OS command injection                                     /admin/ping  (reachable)
#      - Path traversal / LFI                                      /download?file=
#      - Open redirect                                             /redirect?url=
#      - Server-Side Request Forgery (SSRF)                        /admin/fetch?url=
#      - XML External Entity (XXE)                                 POST /api/import
#      - IDOR / excessive data exposure                            /api/user/<id>
#      - User enumeration + no rate limiting                       /login  /register
#
#  [3] POST-AUTHENTICATION EXPLOITATION
#      - Stored XSS (product reviews, profile bio)                 /product/<id>/review
#      - IDOR (read other users' orders)                          /order/<id>
#      - Mass assignment -> privilege escalation                   /register  /profile/update
#      - Broken access control (admin panel)                      /admin (+ X-Admin header)
#      - Session forgery (weak, exposed SECRET_KEY)               cookie "session"
#      - Insecure deserialization (pickle cookie)                  cookie "prefs"
#      - Unrestricted file upload                                  /profile/avatar
#      - Business-logic flaw (negative quantities)                 /cart/update
#      - CSRF (no anti-CSRF tokens anywhere)                       every POST
# =============================================================================

import os
import time
import base64
import pickle
import hashlib
import subprocess

import pymysql
import requests
from lxml import etree
from flask import (
    Flask, request, session, redirect, url_for, make_response,
    render_template, render_template_string, send_file, send_from_directory,
    jsonify, g, Response, abort,
)

# ---------------------------------------------------------------------------
# Configuration (deliberately weak + exposed)
# ---------------------------------------------------------------------------
import config  # noqa: E402  (this module is also served at /config.py on purpose)

app = Flask(__name__)
# VULN: hard-coded, predictable secret key, also leaked via /.env and /config.py.
# Knowing this lets an attacker forge Flask session cookies (privilege escalation).
app.secret_key = config.SECRET_KEY

DB_HOST = os.environ.get("DB_HOST", "db")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "root")
DB_NAME = os.environ.get("DB_NAME", "vulnshop")

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Open a new MySQL connection (DictCursor). Retries while the DB boots."""
    last_err = None
    for _ in range(30):
        try:
            return pymysql.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor, autocommit=True,
                charset="utf8mb4",
            )
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2)
    raise last_err


def query(sql, fetch=True):
    """Run raw SQL. Intentionally does NOT use parameterized queries."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            if fetch:
                return cur.fetchall()
            return cur.lastrowid
    finally:
        conn.close()


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Request hooks
# ---------------------------------------------------------------------------
@app.before_request
def load_prefs():
    """VULN: insecure deserialization. The 'prefs' cookie is base64(pickle)
    and is loaded with pickle.loads on every request -> remote code execution
    for anyone who can craft the cookie."""
    g.prefs = {}
    raw = request.cookies.get("prefs")
    if raw:
        try:
            g.prefs = pickle.loads(base64.b64decode(raw))  # <-- RCE sink
        except Exception:  # noqa: BLE001
            g.prefs = {}


@app.after_request
def insecure_headers(resp):
    # VULN: information disclosure + misleading fingerprint for WhatWeb/Wappalyzer.
    resp.headers["Server"] = "Apache/2.4.29 (Ubuntu) Werkzeug/2.0.3 Python/3.9.18"
    resp.headers["X-Powered-By"] = "PHP/5.6.40"
    resp.headers["X-Debug-Token"] = "vulnshop-dev"
    # VULN: all the usual protective headers are intentionally absent
    # (no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    #  Strict-Transport-Security, Referrer-Policy...). Clickjacking, MIME
    #  sniffing and framing are all possible.
    return resp


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    rows = query("SELECT * FROM users WHERE id = %s" % int(uid))
    return rows[0] if rows else None


def is_admin():
    # VULN: broken access control. Admin is granted by a session flag OR by
    # simply sending the header 'X-Admin: true' (a forgotten "debug backdoor").
    if request.headers.get("X-Admin", "").lower() == "true":
        return True
    return bool(session.get("is_admin"))


@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    return {
        "user": current_user(),
        "cart_count": sum(cart.values()) if cart else 0,
        "categories": ["Audio", "Wearables", "Computing", "Home", "Accessories"],
    }


# ===========================================================================
#  [1] DISCOVERY-PHASE ARTIFACTS
# ===========================================================================
@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup\n"
        "Disallow: /config.py\n"
        "Disallow: /.env\n"
        "Disallow: /.git\n"
        "Disallow: /api\n"
        "Disallow: /debug\n"
        "Disallow: /uploads\n"
        "Disallow: /server-status\n"
        "Sitemap: /sitemap.xml\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    urls = ["/", "/search", "/login", "/register", "/cart", "/admin", "/api/products"]
    items = "".join("<url><loc>%s</loc></url>" % u for u in urls)
    xml = '<?xml version="1.0"?><urlset>%s</urlset>' % items
    return Response(xml, mimetype="application/xml")


@app.route("/.env")
def dotenv():
    # VULN: environment file with live-looking secrets served as text.
    return send_file(os.path.join(os.path.dirname(__file__), ".env"),
                     mimetype="text/plain")


@app.route("/config.py")
def config_py():
    # VULN: application source with the secret key and DB creds.
    return send_file(os.path.join(os.path.dirname(__file__), "config.py"),
                     mimetype="text/plain")


@app.route("/.git/config")
def git_config():
    return send_file(os.path.join(os.path.dirname(__file__), ".git", "config"),
                     mimetype="text/plain")


@app.route("/.git/HEAD")
def git_head():
    return send_file(os.path.join(os.path.dirname(__file__), ".git", "HEAD"),
                     mimetype="text/plain")


@app.route("/backup/<path:filename>")
def backup(filename):
    # VULN: exposed, directory-traversable backup folder with a full DB dump.
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), "backup"), filename)


@app.route("/server-status")
def server_status():
    # VULN: fake Apache mod_status page (fingerprint confusion + info leak).
    html = """<html><head><title>Apache Status</title></head><body>
    <h1>Apache Server Status for vulnshop.local</h1>
    <dl><dt>Server Version: Apache/2.4.29 (Ubuntu)</dt>
    <dt>Server Built: 2018-09-11</dt>
    <dt>Current Time: %s</dt>
    <dt>Restart Time: boot</dt></dl>
    <pre>
    CPU Usage: u2.31 s0.44 cu0 cs0
    1 request currently being processed, 9 idle workers
    Srv  PID   Acc    M  CPU   SS  Req Conn  Client        VHost      Request
    0-0  1337  0/4/4  _  0.00  12  0   0.0   10.0.0.5      vulnshop   GET /admin HTTP/1.1
    0-1  1338  0/2/2  W  0.01  1   0   0.0   10.0.0.9      vulnshop   GET /api/users HTTP/1.1
    </pre></body></html>""" % time.ctime()
    return html


@app.route("/phpinfo")
@app.route("/phpinfo.php")
def phpinfo():
    # VULN: a bogus phpinfo() to mislead scanners into thinking this is PHP.
    html = """<html><body style="font-family:sans-serif">
    <h1 style="background:#9999cc;color:#fff;padding:6px">PHP Version 5.6.40</h1>
    <table border=1 cellpadding=4><tr><td>System</td><td>Linux vulnshop 5.4.0</td></tr>
    <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    <tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
    <tr><td>MYSQL_CONNECT</td><td>vulnshop:vulnshop123@db:3306</td></tr>
    <tr><td>display_errors</td><td>On</td></tr>
    <tr><td>allow_url_fopen</td><td>On</td></tr>
    </table></body></html>"""
    return html


@app.route("/debug")
def debug():
    # VULN: dumps the full process environment, headers and cookies.
    return jsonify({
        "env": dict(os.environ),
        "headers": dict(request.headers),
        "cookies": request.cookies,
        "secret_key": app.secret_key,
    })


@app.route("/uploads/")
def uploads_index():
    # VULN: directory listing of uploaded files.
    files = os.listdir(UPLOAD_DIR)
    links = "".join('<li><a href="/uploads/%s">%s</a></li>' % (f, f) for f in files)
    return "<h1>Index of /uploads</h1><ul>%s</ul>" % links


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # VULN: serves uploaded files with no content-type restriction -> an
    # uploaded .html/.svg executes as stored XSS when opened.
    return send_from_directory(UPLOAD_DIR, filename)


# ===========================================================================
#  STOREFRONT
# ===========================================================================
@app.route("/")
def index():
    products = query("SELECT * FROM products ORDER BY id LIMIT 12")
    featured = products[0] if products else None
    return render_template("index.html", products=products, featured=featured,
                           title="VulnShop")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    error = None
    if q:
        # VULN: SQL injection (string concatenation) + UNION extraction.
        # Try:  ' UNION SELECT id,username,0,password FROM users -- -
        sql = ("SELECT id, name, price, description FROM products "
               "WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'")
        try:
            results = query(sql)
        except Exception as e:  # noqa: BLE001
            error = str(e)  # VULN: raw SQL error leaked to the user
    # VULN: reflected XSS -> {{ q|safe }} in the template echoes input unescaped.
    return render_template("search.html", q=q, results=results, error=error,
                           title="Search")


@app.route("/product/<pid>")
def product(pid):
    # VULN: numeric SQL injection in the id. Try:
    #   /product/0 UNION SELECT id,username,password,email,1,1,'x' FROM users-- -
    sql = "SELECT * FROM products WHERE id = %s" % pid
    try:
        rows = query(sql)
    except Exception as e:  # noqa: BLE001
        return "SQL error: %s" % e, 500  # info disclosure
    if not rows:
        abort(404)
    item = rows[0]
    reviews = query("SELECT * FROM reviews WHERE product_id = %s ORDER BY id DESC"
                    % int(item["id"]) if str(item["id"]).isdigit() else 0)
    return render_template("product.html", item=item, reviews=reviews,
                           title=item.get("name", "Product"))


@app.route("/media/product/<int:pid>.svg")
def product_image(pid):
    # Self-contained placeholder art (no external network needed).
    palette = ["#6d28d9", "#2563eb", "#0891b2", "#059669", "#d97706", "#db2777"]
    c1 = palette[pid % len(palette)]
    c2 = palette[(pid + 2) % len(palette)]
    rows = query("SELECT name FROM products WHERE id = %d" % pid)
    label = (rows[0]["name"] if rows else "Product")[:18]
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="600" height="440">
      <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/>
      </linearGradient></defs>
      <rect width="600" height="440" fill="url(#g)"/>
      <circle cx="480" cy="90" r="120" fill="#ffffff" opacity="0.08"/>
      <circle cx="120" cy="380" r="150" fill="#000000" opacity="0.08"/>
      <text x="40" y="400" font-family="Arial" font-size="26" fill="#ffffff"
            opacity="0.95">{label}</text></svg>"""
    return Response(svg, mimetype="image/svg+xml")


# ---- Server-Side Template Injection -----------------------------------------
@app.route("/hello")
def hello():
    # VULN: SSTI. The input is concatenated into a template string, so Jinja2
    # evaluates it. Try:  /hello?name={{7*7}}   or   /hello?name={{config}}
    name = request.args.get("name", "guest")
    tmpl = "<h2 style='font-family:sans-serif'>Hello, " + name + "!</h2>"
    return render_template_string(tmpl)


# ===========================================================================
#  CART & CHECKOUT
# ===========================================================================
@app.route("/cart")
def cart():
    cart = session.get("cart", {})
    items, total = [], 0.0
    for pid, qty in cart.items():
        rows = query("SELECT * FROM products WHERE id = %d" % int(pid))
        if rows:
            p = rows[0]
            line = float(p["price"]) * qty
            total += line
            items.append({"product": p, "qty": qty, "line": line})
    return render_template("cart.html", items=items, total=total, title="Cart")


@app.route("/cart/add", methods=["POST"])
def cart_add():
    # VULN: no CSRF token on any state-changing request.
    pid = str(request.form.get("product_id", ""))
    cart = session.get("cart", {})
    cart[pid] = cart.get(pid, 0) + 1
    session["cart"] = cart
    return redirect(request.referrer or url_for("index"))


@app.route("/cart/update", methods=["POST"])
def cart_update():
    # VULN: business-logic flaw. Quantity is not validated, so a NEGATIVE
    # quantity produces a negative line total and can zero out / credit an order.
    pid = str(request.form.get("product_id", ""))
    qty = int(request.form.get("qty", 1))  # negatives allowed on purpose
    cart = session.get("cart", {})
    cart[pid] = qty
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["POST"])
def checkout():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    cart = session.get("cart", {})
    total = 0.0
    for pid, qty in cart.items():
        rows = query("SELECT price FROM products WHERE id = %d" % int(pid))
        if rows:
            total += float(rows[0]["price"]) * qty
    # VULN: total can be negative (see cart/update); stored as-is.
    oid = query(
        "INSERT INTO orders (user_id, total, status) VALUES (%d, %f, 'paid')"
        % (int(user["id"]), total), fetch=False)
    session["cart"] = {}
    return redirect(url_for("order_detail", oid=oid))


# ===========================================================================
#  AUTHENTICATION
# ===========================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN: SQL injection auth bypass. Try username:  admin' -- -
        #       or:  ' OR 1=1 LIMIT 1 -- -
        sql = ("SELECT * FROM users WHERE username = '%s' AND password = '%s'"
               % (username, password))
        try:
            rows = query(sql)
        except Exception as e:  # noqa: BLE001
            return render_template("login.html", error="SQL error: %s" % e,
                                   title="Login")
        if rows:
            u = rows[0]
            session["user_id"] = u["id"]
            session["is_admin"] = bool(u["is_admin"])  # trusts DB flag
            return redirect(url_for("index"))
        # VULN: user enumeration (distinct message when the user DOES exist),
        #       and no rate limiting / lockout -> brute force friendly.
        exists = query("SELECT id FROM users WHERE username = '%s'"
                       % username.replace("'", "''"))
        error = ("Wrong password for that account." if exists
                 else "No such username.")
    return render_template("login.html", error=error, title="Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        # VULN: mass assignment. The form field 'is_admin' is trusted, so a
        # user can register straight to an administrator account:
        #   curl -d 'username=evil&password=x&email=e@e&is_admin=1' .../register
        is_admin_flag = 1 if request.form.get("is_admin") else 0
        exists = query("SELECT id FROM users WHERE username = '%s'"
                       % username.replace("'", "''"))
        if exists:
            # VULN: account enumeration on registration.
            error = "That username is already taken."
        else:
            # VULN: plaintext password storage + SQL built by concatenation.
            query("INSERT INTO users (username, password, email, is_admin) "
                  "VALUES ('%s','%s','%s',%d)"
                  % (username, password, email, is_admin_flag), fetch=False)
            rows = query("SELECT * FROM users WHERE username = '%s'"
                         % username.replace("'", "''"))
            session["user_id"] = rows[0]["id"]
            session["is_admin"] = bool(rows[0]["is_admin"])
            return redirect(url_for("index"))
    return render_template("register.html", error=error, title="Register")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ===========================================================================
#  PROFILE
# ===========================================================================
@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    orders = query("SELECT * FROM orders WHERE user_id = %d ORDER BY id DESC"
                   % int(user["id"]))
    return render_template("profile.html", user=user, orders=orders,
                           title="My account")


@app.route("/profile/update", methods=["POST"])
def profile_update():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    bio = request.form.get("bio", "")
    # VULN: mass assignment again -> self-promotion to admin via 'is_admin'.
    admin_set = ", is_admin = 1" if request.form.get("is_admin") else ""
    # VULN: stored XSS (bio rendered with |safe) + SQL injection via bio.
    query("UPDATE users SET bio = '%s'%s WHERE id = %d"
          % (bio, admin_set, int(user["id"])), fetch=False)
    return redirect(url_for("profile"))


@app.route("/profile/avatar", methods=["POST"])
def avatar():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.files.get("avatar")
    if f and f.filename:
        # VULN: unrestricted file upload. No extension/size/content check, and
        # the original filename is trusted (path traversal possible). Files are
        # served from /uploads/ with their uploaded content-type -> an uploaded
        # .html or .svg containing <script> becomes stored XSS.
        dest = os.path.join(UPLOAD_DIR, f.filename)
        f.save(dest)
        query("UPDATE users SET avatar = '%s' WHERE id = %d"
              % (f.filename.replace("'", "''"), int(user["id"])), fetch=False)
    return redirect(url_for("profile"))


@app.route("/user/<int:uid>")
def public_profile(uid):
    rows = query("SELECT * FROM users WHERE id = %d" % uid)
    if not rows:
        abort(404)
    # VULN: stored XSS via bio (rendered |safe) on a public, unauthenticated page.
    return render_template("public_profile.html", profile=rows[0],
                           title=rows[0]["username"])


# ===========================================================================
#  ORDERS  (IDOR)
# ===========================================================================
@app.route("/order/<int:oid>")
def order_detail(oid):
    # VULN: IDOR. No ownership check -> any logged-in user can read any order
    # just by changing the id (/order/1001, /order/1002 ...).
    rows = query("SELECT * FROM orders WHERE id = %d" % oid)
    if not rows:
        abort(404)
    order = rows[0]
    owner = query("SELECT username, email, credit_card FROM users WHERE id = %d"
                  % int(order["user_id"]))
    return render_template("order.html", order=order,
                           owner=owner[0] if owner else {}, title="Order #%d" % oid)


@app.route("/orders")
def orders():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = query("SELECT * FROM orders WHERE user_id = %d ORDER BY id DESC"
                 % int(user["id"]))
    return render_template("orders.html", orders=rows, title="Orders")


# ===========================================================================
#  REVIEWS  (stored XSS)
# ===========================================================================
@app.route("/product/<int:pid>/review", methods=["POST"])
def add_review(pid):
    user = current_user()
    author = user["username"] if user else "anonymous"
    body = request.form.get("body", "")
    # VULN: stored XSS. The body is saved raw and rendered with |safe.
    #       Also SQL injection via the body.
    query("INSERT INTO reviews (product_id, author, body) VALUES (%d, '%s', '%s')"
          % (pid, author.replace("'", "''"), body), fetch=False)
    return redirect(url_for("product", pid=pid))


# ===========================================================================
#  REST-ish API  (IDOR, info disclosure, reflected XSS, XXE)
# ===========================================================================
@app.route("/api/products")
def api_products():
    return jsonify(query("SELECT * FROM products"))


@app.route("/api/user/<int:uid>")
def api_user(uid):
    # VULN: IDOR + excessive data exposure. Returns password, credit card and
    # api_key for ANY user id with no authentication.
    rows = query("SELECT * FROM users WHERE id = %d" % uid)
    if not rows:
        return jsonify({"error": "not found"}), 404
    return jsonify(rows[0])


@app.route("/api/echo")
def api_echo():
    # VULN: reflected XSS with an HTML content type.
    msg = request.args.get("msg", "")
    return Response("<div>%s</div>" % msg, mimetype="text/html")


@app.route("/api/import", methods=["POST"])
def api_import():
    # VULN: XXE. External entities are resolved, so a DOCTYPE with a SYSTEM
    # entity can read local files. Example body:
    #   <?xml version="1.0"?>
    #   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
    #   <order><note>&x;</note></order>
    data = request.get_data()
    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False,
                                 load_dtd=True)
        root = etree.fromstring(data, parser)
        return Response(etree.tostring(root), mimetype="application/xml")
    except Exception as e:  # noqa: BLE001
        return "XML error: %s" % e, 400


# ===========================================================================
#  UTILITIES  (path traversal, open redirect)
# ===========================================================================
@app.route("/download")
def download():
    # VULN: path traversal / LFI. Try:  /download?file=../../etc/passwd
    #       or:  /download?file=../config.py
    name = request.args.get("file", "")
    base = os.path.dirname(__file__)
    try:
        with open(os.path.join(base, name), "rb") as fh:
            return Response(fh.read(), mimetype="application/octet-stream")
    except Exception as e:  # noqa: BLE001
        return "Error: %s" % e, 404


@app.route("/redirect")
def open_redirect():
    # VULN: open redirect. Try:  /redirect?url=https://evil.example.com
    return redirect(request.args.get("url", "/"))


# ===========================================================================
#  [3] ADMIN  (broken access control, command injection, SSRF)
# ===========================================================================
@app.route("/admin")
def admin():
    # VULN: weak gate -> session flag OR 'X-Admin: true' header. The DB is also
    # reachable through session forgery (known SECRET_KEY) / SQLi login.
    if not is_admin():
        return render_template("admin_denied.html", title="Admin"), 403
    users = query("SELECT * FROM users")
    products = query("SELECT * FROM products")
    orders = query("SELECT * FROM orders ORDER BY id DESC")
    return render_template("admin.html", users=users, products=products,
                           orders=orders, title="Admin")


@app.route("/admin/ping", methods=["GET", "POST"])
def admin_ping():
    # VULN: OS command injection. 'host' is passed to a shell unsanitized.
    #   host=127.0.0.1; cat /etc/passwd
    #   host=127.0.0.1 && id
    host = request.values.get("host", "")
    output = ""
    if host:
        try:
            output = subprocess.check_output(
                "ping -c 1 " + host, shell=True,
                stderr=subprocess.STDOUT, timeout=10).decode(errors="replace")
        except subprocess.CalledProcessError as e:
            output = e.output.decode(errors="replace")
        except Exception as e:  # noqa: BLE001
            output = str(e)
    return render_template("tools.html", host=host, output=output,
                           title="Network tools")


@app.route("/admin/fetch")
def admin_fetch():
    # VULN: SSRF. Fetches any URL the server can reach (cloud metadata,
    # internal services, file://). Try:  /admin/fetch?url=http://db:3306
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=", 400
    try:
        r = requests.get(url, timeout=8)
        return Response(r.content, mimetype=r.headers.get("Content-Type", "text/plain"))
    except Exception as e:  # noqa: BLE001
        return "Fetch error: %s" % e, 502


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # VULN: debug=True exposes the Werkzeug interactive debugger (RCE console on
    # any unhandled 500) and verbose tracebacks. Binds to all interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
