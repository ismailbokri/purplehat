"""On-demand browser capture (Interface, Section 6).

Runs capture_runner.py once inside the browser-recon container (which has
Playwright) against a single URL, returning the parsed DOM outline + screenshot.
Strictly tester-triggered via the Capture button — never autonomous.
"""

import json
import pathlib
import subprocess
from typing import Any, Dict, Optional

_IMAGE_NAME = "browser-recon:latest"
_NETWORK_NAME = "pentest-net"
_RECON_DIR = pathlib.Path(__file__).resolve().parent.parent / "microservices" / "browser-recon"
_CAPTURE_SCRIPT = _RECON_DIR / "capture_runner.py"


class CaptureError(RuntimeError):
    pass


def capture_page(url: str, cookie: str = "", *, timeout: int = 90) -> Dict[str, Any]:
    """Capture a single page. Returns {url, title, screenshot_b64, dom_summary}.

    Raises CaptureError when the container cannot run or returns no parsable JSON.
    """
    if not url:
        raise CaptureError("url is required")

    # Mount the capture script into the image and override the recon entrypoint.
    cmd = [
        "docker", "run", "--rm",
        "--network", _NETWORK_NAME,
        "-v", f"{_CAPTURE_SCRIPT.resolve()}:/app/capture_runner.py:ro",
        "--entrypoint", "python",
        _IMAGE_NAME,
        "/app/capture_runner.py", url,
    ]
    if cookie:
        cmd.append(cookie)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CaptureError(f"capture timed out after {timeout}s")
    except FileNotFoundError:
        raise CaptureError("docker is not available on the host")

    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise CaptureError(
            f"capture produced no output (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:300]}"
        )

    # The script prints a single JSON line; take the last non-empty line to be safe.
    last = [ln for ln in stdout.splitlines() if ln.strip()][-1]
    try:
        data = json.loads(last)
    except Exception:
        raise CaptureError(f"capture returned non-JSON output: {stdout[:300]}")

    if data.get("error") and not data.get("screenshot_b64"):
        raise CaptureError(str(data["error"]))
    return data


def summarize_capture_for_agent(capture: Dict[str, Any], user_notes: str = "") -> str:
    """Render a capture into a compact text block to feed the Conversation Agent."""
    dom = capture.get("dom_summary") or {}
    lines = [
        f"Captured page: {capture.get('url', '')}",
        f"Title: {capture.get('title', '')}",
    ]
    forms = dom.get("forms") or []
    if forms:
        lines.append(f"Forms ({len(forms)}):")
        for f in forms[:10]:
            inputs = ", ".join(
                f"{i.get('name') or '?'}:{i.get('type')}" for i in (f.get("inputs") or [])[:12]
            )
            lines.append(f"  - {f.get('method', 'get').upper()} {f.get('action', '')} [{inputs}]")
    links = dom.get("links") or []
    if links:
        lines.append("Links: " + ", ".join(str(l) for l in links[:25]))
    inputs = dom.get("inputs") or []
    if inputs:
        lines.append("Inputs: " + ", ".join(f"{i.get('name') or '?'}:{i.get('type')}" for i in inputs[:20]))
    buttons = dom.get("buttons") or []
    if buttons:
        lines.append("Buttons: " + ", ".join(str(b) for b in buttons[:20]))
    if user_notes:
        lines.append(f"\nTester's note / what to investigate: {user_notes}")
    return "\n".join(lines)
