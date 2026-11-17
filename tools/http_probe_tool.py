"""
HTTP Probe Tool — runs the http-probe Docker container for a single probe task.
Called by the prober node inline during the Browser Recon phase.
Probe run artifacts are stored under runs/prober/probes/.
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

_IMAGE_NAME   = "http-probe:latest"
_NETWORK_NAME = "pentest-net"
_RUNS_DIR     = pathlib.Path(__file__).resolve().parent.parent / "runs" / "prober" / "probes"

_WEB_PORT_PRIORITY = ["80", "8080", "8081", "8000", "3000", "443", "8443", "5000"]


def build_target_url(target: str, open_ports: list) -> str:
    """
    Construct an HTTP/S URL from a hostname/URL and a list of open ports.
    User-specified ports (e.g. "10.4.1.197:3000") are preserved; nmap ports
    are only applied when no port was given in the target.
    """
    if not target:
        return ""

    from urllib.parse import urlparse

    parse_input = target if "://" in target else f"http://{target}"
    parsed = urlparse(parse_input)
    host = parsed.hostname or ""
    if not host:
        return ""

    user_port = str(parsed.port) if parsed.port else None
    user_scheme = parsed.scheme if parsed.scheme in ("http", "https") else None

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


def run_http_probe(
    probe_type: str,
    target_url: str,
    target: str,
    target_endpoints: Optional[list] = None,
    target_fields: Optional[list] = None,
    session_cookie: Optional[str] = None,
    extra_payloads: Optional[list] = None,
) -> list:
    """
    Run the http-probe Docker container for a single probe task.

    Returns a list of probe result records (dicts) from results.jsonl,
    or an empty list on failure.

    Args:
        target_url:       Base URL reachable from pentest-net .
        target:           Hostname slug used for run naming.
        target_endpoints: List of endpoint paths to probe.
        target_fields:    List of form field names to test.
        session_cookie:   Optional cookie string (name=value) for authenticated requests.
        extra_payloads:   LLM-supplied stack-aware payloads. Passed to the container
                          as EXTRA_PAYLOADS={<probe_type>: [...]} and merged with
                          the runner's hardcoded defaults at runtime.
    """
    safe_target = re.sub(r"[^a-zA-Z0-9_-]", "_", target) if target else "target"
    run_id = (
        f"probe_{probe_type}_{safe_target}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_"
        f"{uuid.uuid4().hex[:6]}"
    )

    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = _RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    runs_dir_abs = str(_RUNS_DIR.resolve())

    print(f"\n[HTTP PROBE] Type     : {probe_type}")
    print(f"[HTTP PROBE] Target   : {target_url}")
    print(f"[HTTP PROBE] Run ID   : {run_id}")
    print(f"[HTTP PROBE] Output   : {runs_dir_abs}")

    dockerfile_dir = pathlib.Path(__file__).resolve().parent.parent / "microservices" / "http-probe"
    _ensure_image(dockerfile_dir)

    endpoints_json = json.dumps(target_endpoints or [])
    fields_json    = json.dumps(target_fields or [])
    extra_payloads_json = json.dumps({probe_type: list(extra_payloads)}) if extra_payloads else ""

    cmd = [
        "docker", "run", "--rm",
        "--network", _NETWORK_NAME,
        "-e", f"PROBE_TYPE={probe_type}",
        "-e", f"BASE_URL={target_url}",
        "-e", f"TARGET_ENDPOINTS={endpoints_json}",
        "-e", f"TARGET_FIELDS={fields_json}",
        "-e", f"SESSION_COOKIE={session_cookie or ''}",
        "-e", f"EXTRA_PAYLOADS={extra_payloads_json}",
        "-e", f"OUTPUT_DIR=/app/runs/{run_id}",
        "-e", f"RUN_ID={run_id}",
        "-e", "PYTHONUNBUFFERED=1",
        "-v", f"{runs_dir_abs}:/app/runs",
        _IMAGE_NAME,
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr → stdout for unified streaming
            text=True,
            bufsize=1,
        )

        timed_out = _stream_container(process, timeout_seconds=300)

        if timed_out:
            print("[HTTP PROBE] ERROR: container timed out after 5 minutes")
            return []

        results_file = run_dir / "results.jsonl"
        if not results_file.exists():
            print(f"[HTTP PROBE] WARN: results.jsonl not found at {results_file}")
            return []

        records = []
        with open(results_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        print(f"[HTTP PROBE] Complete — {len(records)} records")
        return records

    except Exception as exc:
        print(f"[HTTP PROBE] ERROR: {exc}")
        return []


def _stream_container(process: subprocess.Popen, timeout_seconds: int) -> bool:
    """
    Read process stdout (stderr merged in) line by line in real-time.
    Kills the process if timeout_seconds elapses.
    Returns True if the timeout fired, False if the process exited normally.
    """
    timed_out = threading.Event()

    def _kill():
        timed_out.set()
        try:
            process.kill()
        except OSError:
            pass

    timer = threading.Timer(timeout_seconds, _kill)
    timer.start()
    try:
        for line in process.stdout:
            stripped = line.rstrip("\n").strip()
            if stripped:
                print(f"  {stripped}")
        process.wait()
    finally:
        timer.cancel()

    return timed_out.is_set()


def _ensure_image(dockerfile_dir: pathlib.Path) -> None:
    check = subprocess.run(
        ["docker", "image", "inspect", _IMAGE_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode == 0:
        return

    print(f"[HTTP PROBE] Building {_IMAGE_NAME} from {dockerfile_dir} …")
    result = subprocess.run(
        ["docker", "build", "-t", _IMAGE_NAME, str(dockerfile_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[HTTP PROBE] Build failed:\n{result.stderr[-800:]}")
    else:
        print(f"[HTTP PROBE] Image {_IMAGE_NAME} built successfully")
