"""
Browser Explore Tool
Constructs target URL from scan state and runs the browser-recon Docker container.
"""
import json
import os
import pathlib
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

_IMAGE_NAME    = "browser-recon:latest"
_NETWORK_NAME  = "pentest-net"
_RUNS_DIR      = pathlib.Path(__file__).resolve().parent.parent / "runs" / "slime"
_AUTH_RUNS_DIR = pathlib.Path(__file__).resolve().parent.parent / "runs" / "auth"

# Preferred web ports in priority order
_WEB_PORT_PRIORITY = ["80", "8080", "8081", "8000", "3000", "443", "8443", "5000"]


def run_auth_preflight(
    target_url: str,
    target: str,
    username: str,
    password: str,
) -> Optional[dict]:
    """
    Run the browser-recon container in auth_only mode to log in and extract session cookies.
    Returns a cookie dict on success, or None if auth failed / no cookies extracted.
    """
    safe_target = re.sub(r"[^a-zA-Z0-9_-]", "_", target) if target else "target"
    run_id = (
        f"auth_{safe_target}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
        f"{uuid.uuid4().hex[:6]}"
    )

    _AUTH_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    auth_runs_abs = str(_AUTH_RUNS_DIR.resolve())

    print(f"\n[AUTH] Pre-authentication → {target_url}")
    print(f"[AUTH] Run ID : {run_id}")

    dockerfile_dir = pathlib.Path(__file__).resolve().parent.parent / "microservices" / "browser-recon"
    _ensure_image(dockerfile_dir)

    cmd = [
        "docker", "run", "--rm",
        "--network", _NETWORK_NAME,
        "-e", f"TARGET_URL={target_url}",
        "-e", f"RUN_ID={run_id}",
        "-e", "API_KEY_pfe=auth_only_placeholder",  # no LLM in auth_only mode
        "-e", "BROWSER_AGENT_MODE=auth_only",
        "-e", f"LOGIN_USERNAME={username}",
        "-e", f"LOGIN_PASSWORD={password}",
        "-e", "OUTPUT_DIR=/app/runs/auth",
        "-e", "PYTHONUNBUFFERED=1",
        "-v", f"{auth_runs_abs}:/app/runs/auth",
        _IMAGE_NAME,
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        timed_out = _stream_container(process, timeout_seconds=60)
        if timed_out:
            print("[AUTH] ERROR: auth container timed out")
            return None

        cookies_file = _AUTH_RUNS_DIR / run_id / "auth_cookies.json"
        if not cookies_file.exists():
            print(f"[AUTH] ERROR: no cookies file produced at {cookies_file}")
            return None

        with cookies_file.open(encoding="utf-8") as fh:
            data = json.load(fh)

        auth_success = data.get("auth_success", False)
        cookies = data.get("cookies", {})

        if not auth_success:
            print(f"[AUTH] Login failed — credentials rejected, unauthenticated cookies discarded")
            return None

        if cookies:
            print(f"[AUTH] Session cookies ready: {', '.join(cookies.keys())}")
            return cookies

        print("[AUTH] No session cookies extracted")
        return None

    except Exception as exc:
        print(f"[AUTH] ERROR: {exc}")
        return None


def build_target_url(target: str, open_ports: list) -> Optional[str]:

    if not target:
        return None

    from urllib.parse import urlparse

    parse_input = target if "://" in target else f"http://{target}"
    parsed = urlparse(parse_input)
    host = parsed.hostname or ""
    if not host:
        return None

    user_port = str(parsed.port) if parsed.port else None
    user_scheme = parsed.scheme if parsed.scheme in ("http", "https") else None

    # Only consult nmap results when the user did not specify a port
    if user_port is None:
        for preferred in _WEB_PORT_PRIORITY:
            for raw in open_ports:
                port_str = str(raw).split("/")[0].strip()
                if port_str == preferred:
                    scheme = "https" if port_str in {"443", "8443"} else "http"
                    return f"{scheme}://{host}:{port_str}"

    fallback_port = user_port or "80"
    fallback_scheme = user_scheme or "http"
    return f"{fallback_scheme}://{host}:{fallback_port}"


def run_browser_explore(
    target_url: str,
    target: str,
    max_iterations: int = 8,
    mode: str = "recon",
    task_prompts: Optional[list[str]] = None,
    username: str = "",
    password: str = "",
    auth_cookies: Optional[dict] = None,
    auth_out_of_scope: bool = False,
    display_url: Optional[str] = None,
) -> Optional[str]:
    """
    Build the browser-recon image (if needed) and run a one-shot exploration container.

    `target_url` is the Docker-plane URL the container navigates to (e.g.
    http://web:5000). `display_url` is the browser-plane URL shown to the tester
    (e.g. http://localhost:8084); logs and live frames are rewritten to it.

    Returns the absolute path to the run directory containing pipeline.jsonl,
    or None if the container failed / pipeline.jsonl was not produced.
    """
    groq_key = (
        os.getenv("API_KEY_pfe")
    )
    if not groq_key:
        print("[BROWSER EXPLORE] ERROR: No API_KEY_pfe found in environment")
        return None

    groq_model = os.getenv("MODEL", "openai/gpt-oss-120b")

    # Unique run identifier includes target name for human readability
    safe_target = re.sub(r"[^a-zA-Z0-9_-]", "_", target) if target else "target"
    run_id      = (
        f"slime_{safe_target}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
        f"{uuid.uuid4().hex[:6]}"
    )

    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    runs_dir_abs = str(_RUNS_DIR.resolve())

    display_url = display_url or target_url
    print(f"\n[BROWSER EXPLORE] Target : {display_url}")
    if display_url != target_url:
        print(f"[BROWSER EXPLORE] Via    : {target_url} (pentest-net)")
    print(f"[BROWSER EXPLORE] Run ID : {run_id}")
    print(f"[BROWSER EXPLORE] Output : {runs_dir_abs}")

    # ── Step 1: build image if not present ────────────────────────────────────
    dockerfile_dir = pathlib.Path(__file__).resolve().parent.parent / "microservices" / "browser-recon"
    _ensure_image(dockerfile_dir)

    # ── Step 2: docker run (one-shot, attached, waits for exit) ───────────────
    cmd = [
        "docker", "run", "--rm",
        "--network", _NETWORK_NAME,
        "-e", f"TARGET_URL={target_url}",
        "-e", f"RUN_ID={run_id}",
        "-e", f"API_KEY_pfe={groq_key}",
        "-e", f"GROQ_MODEL={groq_model}",
        "-e", f"MAX_ITERATIONS={max_iterations}",
        "-e", f"BROWSER_AGENT_MODE={mode}",
        "-e", f"LOGIN_USERNAME={username}",
        "-e", f"LOGIN_PASSWORD={password}",
        "-e", f"AUTH_OUT_OF_SCOPE={'true' if auth_out_of_scope else 'false'}",
        "-e", "OUTPUT_DIR=/app/runs/slime",
        "-e", "PYTHONUNBUFFERED=1",
        "-v", f"{runs_dir_abs}:/app/runs/slime",
        _IMAGE_NAME,
    ]
    if task_prompts:
        cmd[cmd.index(_IMAGE_NAME):cmd.index(_IMAGE_NAME)] = [
            "-e", f"BROWSER_TASK_PROMPTS_JSON={json.dumps(task_prompts)}",
        ]
    if auth_cookies:
        cmd[cmd.index(_IMAGE_NAME):cmd.index(_IMAGE_NAME)] = [
            "-e", f"AUTH_COOKIES_JSON={json.dumps(auth_cookies)}",
        ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr → stdout for unified streaming
            text=True,
            bufsize=1,
        )

        timed_out = _stream_container(
            process,
            timeout_seconds=600,
            url_rewrite=(_origin(target_url), _origin(display_url)),
        )

        if timed_out:
            print("[BROWSER EXPLORE] ERROR: container timed out after 10 minutes")
            return None

        run_dir       = _RUNS_DIR / run_id
        pipeline_file = run_dir / "pipeline.jsonl"

        if pipeline_file.exists():
            event_count = sum(1 for _ in pipeline_file.open(encoding="utf-8"))
            print(f"[BROWSER EXPLORE] Complete — {event_count} events logged")
            return str(run_dir)

        print(f"[BROWSER EXPLORE] WARN: pipeline.jsonl not found at {pipeline_file}")
        return str(run_dir) if run_dir.exists() else None

    except Exception as exc:
        print(f"[BROWSER EXPLORE] ERROR: {exc}")
        return None


def _origin(url: str) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(url or "")
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def _stream_container(
    process: subprocess.Popen,
    timeout_seconds: int,
    url_rewrite: Optional[tuple[str, str]] = None,
) -> bool:
    """
    Read process stdout (stderr merged in) line by line in real-time.
    Kills the process if timeout_seconds elapses.
    Returns True if the timeout fired, False if the process exited normally.

    `url_rewrite` = (internal_origin, external_origin): the container only knows
    the Docker-plane URL, so every printed line and frame URL is rewritten to the
    browser-plane origin before it reaches the tester. Files on disk are left
    untouched: downstream tool containers still need the internal URL.

    Lines starting with `[FRAME]` are detached from the printed log stream and
    forwarded to the per-thread `frame_callback` (set by server/main.py during a
    /vtest run). The frame payload is a single-line JSON document carrying a
    base64 JPEG screenshot — used by the frontend BrowserReplay component.
    """
    # Local import to avoid a hard import cycle (server.stdout_capture imports
    # nothing from tools, but tools running outside the FastAPI server context
    # should still work — e.g. CLI invocation).
    try:
        from server.stdout_capture import _thread_local  # type: ignore
    except Exception:
        _thread_local = None  # type: ignore

    internal_origin, external_origin = url_rewrite or ("", "")

    def _to_display(text: str) -> str:
        if internal_origin and external_origin and internal_origin != external_origin:
            return text.replace(internal_origin, external_origin)
        return text

    timed_out = threading.Event()

    def _kill():
        timed_out.set()
        try:
            process.kill()
        except OSError:
            pass

    timer = threading.Timer(timeout_seconds, _kill)
    timer.start()

    frames_received = 0
    frames_forwarded = 0
    frames_dropped_no_callback = 0
    frames_dropped_parse_error = 0
    frames_dropped_callback_error = 0
    try:
        for line in process.stdout:
            stripped = line.rstrip("\n").strip()
            if not stripped:
                continue
            if stripped.startswith("[FRAME]"):
                # Detach frame payloads from the printed log — they would flood
                # the terminal with base64 noise otherwise.
                frames_received += 1
                cb = getattr(_thread_local, "frame_callback", None) if _thread_local else None
                if cb is None:
                    frames_dropped_no_callback += 1
                    if frames_dropped_no_callback == 1:
                        # Print once per run so a misconfigured pipeline is visible
                        # in the host log without flooding it.
                        print("[BROWSER EXPLORE] WARN: frame received but no frame_callback registered "
                              "(events will not reach the UI)")
                    continue
                try:
                    payload = json.loads(stripped[len("[FRAME]"):])
                except Exception as exc:
                    frames_dropped_parse_error += 1
                    if frames_dropped_parse_error <= 2:
                        print(f"[BROWSER EXPLORE] WARN: malformed FRAME payload ({exc}); "
                              f"len={len(stripped)} head={stripped[:60]!r}")
                    continue
                for key in ("url_before", "url_after", "note"):
                    if isinstance(payload.get(key), str):
                        payload[key] = _to_display(payload[key])
                try:
                    cb(payload)
                    frames_forwarded += 1
                    if frames_forwarded == 1 or frames_forwarded % 10 == 0:
                        # Periodic visibility: confirms the chain is alive.
                        iter_no = payload.get("iter", "?")
                        action  = str(payload.get("action") or "?")
                        outcome = str(payload.get("outcome") or "?")
                        b64_len = len(str(payload.get("screenshot_b64") or ""))
                        print(f"[BROWSER EXPLORE] frame #{frames_forwarded} forwarded "
                              f"(iter={iter_no} action={action} outcome={outcome} b64={b64_len}B)")
                except Exception as exc:
                    frames_dropped_callback_error += 1
                    if frames_dropped_callback_error <= 2:
                        print(f"[BROWSER EXPLORE] WARN: frame_callback raised {type(exc).__name__}: {exc}")
                continue
            print(f"  {_to_display(stripped)}")
        process.wait()
    finally:
        timer.cancel()
        if frames_received:
            print(
                f"[BROWSER EXPLORE] frames stream: received={frames_received} "
                f"forwarded={frames_forwarded} "
                f"dropped(no_cb={frames_dropped_no_callback},"
                f" parse_err={frames_dropped_parse_error},"
                f" cb_err={frames_dropped_callback_error})"
            )

    return timed_out.is_set()


def _ensure_image(dockerfile_dir: pathlib.Path) -> None:
    """Build browser-recon image if it is not already present."""
    check = subprocess.run(
        ["docker", "image", "inspect", _IMAGE_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode == 0:
        return  # image already exists

    print(f"[BROWSER EXPLORE] Building {_IMAGE_NAME} from {dockerfile_dir} …")
    result = subprocess.run(
        ["docker", "build", "-t", _IMAGE_NAME, str(dockerfile_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[BROWSER EXPLORE] Build failed:\n{result.stderr[-800:]}")
    else:
        print(f"[BROWSER EXPLORE] Image {_IMAGE_NAME} built successfully")


# ── re import needed for safe_target slug ─────────────────────────────────────
import re  # noqa: E402 — intentional late import to avoid circular at module level
