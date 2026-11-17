"""Thread-local stdout interceptor for pipeline runners.

Captures `print()` output from agents/tools running in a background thread and
forwards filtered, classified lines to that thread's log callback (typically a
WebSocket emitter). The modular sessions runner attaches a callback via
`_thread_local.log_callback`.

Module-level state:
  - `_thread_local`           — `threading.local()`. Set `log_callback` and `_buf`.
  - `_ThreadLocalStdout`      — wraps sys.stdout and forwards classified lines.
  - `_classify_stdout(line)`  — whitelist classifier; returns level or None.

`sys.stdout` is replaced exactly once, in `server/main.py` at module load.
"""

import threading

_thread_local = threading.local()
_MAX_STDOUT_LINE = 400  # skip raw LLM output / large JSON dumps


def _classify_stdout(text: str) -> str | None:
    """Whitelist-only classifier. Returns log level or None to drop."""
    u = text.upper()
    if "TRACEBACK" in u or "EXCEPTION:" in u or u.startswith("FATAL"):
        return "error"
    if text.startswith("[AUTH]"):
        if "SUCCESS" in u:
            return "success"
        if "FAIL" in u or "ERROR" in u:
            return "warning"
        return None
    if text.startswith("[FINGERPRINT]"):
        return "info"
    return None


class _ThreadLocalStdout:
    """Wraps the real stdout; forwards each line to the per-thread callback."""

    def __init__(self, real: object):
        self._real = real

    def write(self, text: str):
        self._real.write(text)
        cb = getattr(_thread_local, "log_callback", None)
        if cb is None:
            return
        buf = getattr(_thread_local, "_buf", "") + text
        lines = buf.split("\n")
        _thread_local._buf = lines[-1]
        for line in lines[:-1]:
            stripped = line.strip()
            if not stripped or len(stripped) > _MAX_STDOUT_LINE:
                continue
            level = _classify_stdout(stripped)
            if level is not None:
                cb(stripped, level)

    def flush(self):
        self._real.flush()
        cb = getattr(_thread_local, "log_callback", None)
        if cb:
            buf = getattr(_thread_local, "_buf", "").strip()
            if buf and len(buf) <= _MAX_STDOUT_LINE:
                level = _classify_stdout(buf)
                if level is not None:
                    cb(buf, level)
            _thread_local._buf = ""

    def __getattr__(self, name: str):
        return getattr(self._real, name)
