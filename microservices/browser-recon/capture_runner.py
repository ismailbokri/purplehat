"""One-shot, on-demand page capture (Interface, Section 6).

Unlike browser_recon_runner.py (which autonomously explores), this script loads
a SINGLE url, captures a screenshot + a compact DOM outline, and prints one JSON
document to stdout. It is invoked explicitly when the tester clicks "Capture" —
never autonomously.

Usage:
  python capture_runner.py <url> [cookie_string]

Output (stdout, single line):
  {"url": ..., "title": ..., "screenshot_b64": ..., "dom_summary": {...}}
"""

import base64
import json
import sys


def _dom_summary(page) -> dict:
    """Extract a compact, security-relevant outline of the page DOM."""
    js = r"""
    () => {
      const txt = (el) => (el.getAttribute('name') || el.getAttribute('id') ||
                           el.getAttribute('placeholder') || el.getAttribute('aria-label') || '').slice(0, 60);
      const forms = [...document.querySelectorAll('form')].slice(0, 20).map(f => ({
        action: f.getAttribute('action') || '',
        method: (f.getAttribute('method') || 'get').toLowerCase(),
        inputs: [...f.querySelectorAll('input,select,textarea')].slice(0, 30).map(i => ({
          name: txt(i), type: i.getAttribute('type') || i.tagName.toLowerCase(),
        })),
      }));
      const links = [...document.querySelectorAll('a[href]')].slice(0, 60)
        .map(a => a.getAttribute('href')).filter(Boolean);
      const inputs = [...document.querySelectorAll('input,select,textarea')].slice(0, 40)
        .map(i => ({ name: txt(i), type: i.getAttribute('type') || i.tagName.toLowerCase() }));
      const buttons = [...document.querySelectorAll('button,[role=button],input[type=submit]')]
        .slice(0, 30).map(b => (b.innerText || b.value || txt(b)).trim().slice(0, 40)).filter(Boolean);
      return { forms, links: [...new Set(links)], inputs, buttons };
    }
    """
    try:
        return page.evaluate(js) or {}
    except Exception:
        return {}


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: capture_runner.py <url> [cookie]"}))
        return 2
    url = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        print(json.dumps({"error": f"playwright unavailable: {exc}"}))
        return 3

    out = {"url": url, "title": "", "screenshot_b64": "", "dom_summary": {}}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            if cookie:
                # Attach cookies for the target host so the capture is authenticated.
                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                    cookies = []
                    for part in cookie.split(";"):
                        if "=" in part:
                            k, v = part.strip().split("=", 1)
                            cookies.append({"name": k.strip(), "value": v.strip(), "domain": host, "path": "/"})
                    if cookies:
                        context.add_cookies(cookies)
                except Exception:
                    pass
            page = context.new_page()
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            out["title"] = page.title() or ""
            out["dom_summary"] = _dom_summary(page)
            shot = page.screenshot(type="jpeg", quality=55, full_page=False)
            out["screenshot_b64"] = base64.b64encode(shot).decode("ascii")
            browser.close()
    except Exception as exc:
        out["error"] = str(exc)

    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
