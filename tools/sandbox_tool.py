"""Controlled execution sandbox.

Runs tester-authorized commands and scripts inside the long-running
`pentest-container` (image `pentest-tools`, network `pentest-net`), which is
pre-baked with all permitted recon tools and language runtimes.

Design constraints (see IMPLEMENTATION_PLAN.md §3, §7 Phase 3):
  - Execution is ALWAYS tester-triggered. No agent calls this module.
  - Each session gets an isolated workspace dir under /workspace/<session_id>
    inside the container, so generated files and outputs stay per-session.
  - Only the shared container filesystem is reachable — no host mount beyond
    the container, network limited to pentest-net (the target lives there).
  - Output is streamed line-by-line through an optional callback so the
    frontend sees it live over the session WebSocket.
"""

import re
import shlex
import subprocess
from typing import Callable, Dict, List, Optional

_CONTAINER = "pentest-container"
_WORKSPACE_ROOT = "/workspace"

# Per-command wall-clock ceiling (s). Keeps a runaway command from hanging a run.
_DEFAULT_TIMEOUT = 300

# session_id must be a safe path segment (UUIDs from the session store already are).
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._#-]+$")
# generated-file names the tester may read back must not escape the workspace.
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._/-]+$")


class SandboxError(RuntimeError):
    pass


def _workspace_dir(session_id: str) -> str:
    if not _SAFE_SEGMENT.match(session_id or ""):
        raise SandboxError("invalid session id")
    return f"{_WORKSPACE_ROOT}/{session_id}"


def _container_running() -> bool:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", _CONTAINER],
            capture_output=True, text=True, timeout=15,
        )
        return out.returncode == 0 and out.stdout.strip() == "true"
    except Exception:
        return False


def ensure_workspace(session_id: str) -> str:
    """Create the per-session workspace dir inside the container. Returns its path."""
    if not _container_running():
        raise SandboxError(
            f"sandbox container {_CONTAINER!r} is not running — start it with "
            "microservices/run.ps1 (docker)"
        )
    wd = _workspace_dir(session_id)
    r = subprocess.run(
        ["docker", "exec", _CONTAINER, "mkdir", "-p", wd],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise SandboxError(f"could not create workspace: {r.stderr.strip()}")
    return wd


def run_command(
    session_id: str,
    command: str,
    *,
    on_line: Optional[Callable[[str], None]] = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> Dict[str, object]:
    """Run `command` in the session workspace inside the container.

    Streams each output line to `on_line` if given, and also returns the full
    captured output. The command runs under `bash -lc` with the workspace as CWD.
    """
    wd = ensure_workspace(session_id)
    # `cd <workspace> && <command>` under bash so pipes/redirections work.
    full = f"cd {shlex.quote(wd)} && {command}"
    argv = ["docker", "exec", "-w", wd, _CONTAINER, "bash", "-lc", full]

    lines: List[str] = []
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception as exc:
        raise SandboxError(f"failed to launch command: {exc}")

    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            lines.append(line)
            if on_line is not None:
                try:
                    on_line(line)
                except Exception:
                    pass
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        lines.append(f"[sandbox] command timed out after {timeout}s — killed")
        if on_line:
            on_line(lines[-1])
        return {"exit_code": -1, "output": "\n".join(lines), "timed_out": True}

    return {
        "exit_code": proc.returncode,
        "output": "\n".join(lines),
        "timed_out": False,
    }


def list_files(session_id: str) -> List[Dict[str, object]]:
    """List files in the session workspace (name + size), recursively."""
    wd = _workspace_dir(session_id)
    r = subprocess.run(
        ["docker", "exec", _CONTAINER, "bash", "-lc",
         f"cd {shlex.quote(wd)} 2>/dev/null && find . -type f -printf '%s\\t%p\\n' 2>/dev/null || true"],
        capture_output=True, text=True, timeout=30,
    )
    files: List[Dict[str, object]] = []
    for line in (r.stdout or "").splitlines():
        if "\t" not in line:
            continue
        size, path = line.split("\t", 1)
        name = path[2:] if path.startswith("./") else path
        try:
            files.append({"name": name, "size": int(size)})
        except ValueError:
            continue
    return files


def read_file(session_id: str, filename: str, *, max_bytes: int = 200_000) -> str:
    """Read a generated file from the session workspace (capped)."""
    if not _SAFE_FILENAME.match(filename or "") or ".." in filename:
        raise SandboxError("invalid filename")
    wd = _workspace_dir(session_id)
    r = subprocess.run(
        ["docker", "exec", _CONTAINER, "bash", "-lc",
         f"head -c {int(max_bytes)} {shlex.quote(wd + '/' + filename)}"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise SandboxError(f"could not read {filename!r}: {r.stderr.strip()}")
    return r.stdout
