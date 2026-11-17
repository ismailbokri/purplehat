import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Allow imports from project root (config.py, agents/, tools/, graphs/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.bootstrap import run_bootstrap
from server.routes.auth_routes import router as auth_router
from server.routes.capture_routes import router as capture_router
from server.routes.chat_routes import router as chat_router
from server.routes.checklist_routes import router as checklist_router
from server.routes.exec_routes import router as exec_router
from server.routes.findings_routes import router as findings_router
from server.routes.news_routes import router as news_router
from server.routes.proxy_routes import router as proxy_router
from server.routes.sessions_routes import router as sessions_router

# ─── Thread-local stdout interceptor ─────────────────────────────────────────
# Captures print() output from agents and forwards it to the active session's
# WebSocket. Used by the modular /api/sessions runners — see
# [server/stdout_capture.py](server/stdout_capture.py) and
# [server/sessions_runtime.py](server/sessions_runtime.py).

from server.stdout_capture import _ThreadLocalStdout

sys.stdout = _ThreadLocalStdout(sys.stdout)

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="PenTest AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _bootstrap_db() -> None:
    """Create tables and seed checklist (idempotent — safe on every restart)."""
    try:
        run_bootstrap()
    except Exception as exc:
        # Surface a clear error on startup if Postgres is unreachable.
        print(f"[startup] DB bootstrap FAILED: {exc}")
        raise


@app.on_event("startup")
def _maybe_refresh_news() -> None:
    """Trigger the weekly news update in the background if it's been >7 days.

    Runs in a daemon thread so startup never blocks on network/LLM calls.
    """
    import threading

    def _job():
        try:
            from news.fetcher import is_update_due, run_news_update
            if is_update_due():
                print("[startup] news update due — running in background")
                run_news_update()
            else:
                print("[startup] news update not due — skipping")
        except Exception as exc:
            print(f"[startup] news update skipped: {exc}")

    threading.Thread(target=_job, daemon=True).start()


app.include_router(auth_router)
app.include_router(checklist_router)
app.include_router(findings_router)
app.include_router(sessions_router)
app.include_router(exec_router)
app.include_router(chat_router)
app.include_router(capture_router)
app.include_router(news_router)
app.include_router(proxy_router)


@app.get("/health")
async def health():
    return {"status": "ok"}


# ─── Serve built frontend (production) ───────────────────────────────────────

_DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
if os.path.isdir(_DIST):
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="static")
