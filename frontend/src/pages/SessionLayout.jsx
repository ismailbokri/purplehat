import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { Link, NavLink, Outlet, useNavigate, useParams } from 'react-router-dom';
import { deleteSession, getSession, openSessionSocket } from '../api/sessions.js';
import ThemeToggle from '../components/ThemeToggle.jsx';

/**
 * Reducer for incremental session state derived from the WebSocket stream.
 * Events arrive tagged with module_key + module_run_id; we route them into
 * per-module slots so each ModuleRunner sees only its own logs/findings.
 */
function reducer(state, action) {
  switch (action.type) {
    case 'reset':
      return { logs: [], modules: {}, report: { status: 'idle' }, sandbox: { running: false, lines: [], lastExit: null, analysis: null } };
    case 'ws_event': {
      const ev = action.event;
      if (!ev || !ev.type) return state;
      if (ev.type === 'ping') return state;

      // Sandbox events are session-scoped (no module_key).
      if (ev.type === 'sandbox_start') {
        // Clear any prior verdict when a new command begins; analysis arrives
        // after sandbox_complete.
        // When the backend rewrote a browser-plane address (localhost:8084) to
        // the pentest-net one (web:5000), show what was typed and what ran.
        const typed = ev.data?.typed;
        const lines = typed
          ? [`$ ${typed}`, `# localhost → pentest-net, running: ${ev.data?.command || ''}`]
          : [`$ ${ev.data?.command || ''}`];
        return { ...state, sandbox: { running: true, lines, lastExit: null, analysis: null } };
      }
      if (ev.type === 'sandbox_output') {
        const sb = state.sandbox || { running: true, lines: [], lastExit: null };
        return { ...state, sandbox: { ...sb, lines: [...sb.lines, ev.data?.line ?? ''].slice(-1000) } };
      }
      if (ev.type === 'sandbox_complete') {
        const sb = state.sandbox || { lines: [] };
        return { ...state, sandbox: { ...sb, running: false, lastExit: ev.data?.exit_code } };
      }
      if (ev.type === 'sandbox_error') {
        const sb = state.sandbox || { lines: [] };
        return { ...state, sandbox: { ...sb, running: false, lines: [...sb.lines, `[error] ${ev.data?.message || ''}`] } };
      }
      // Finding Agent verdict — always arrives after a run, never blank.
      if (ev.type === 'sandbox_analysis') {
        const sb = state.sandbox || { lines: [] };
        return { ...state, sandbox: { ...sb, analysis: ev.data || null } };
      }

      // Report-progress events are session-scoped (no module_key).
      if (ev.type === 'report_progress') {
        return {
          ...state,
          report: { ...state.report, status: 'running', stage: ev.data?.stage },
        };
      }
      if (ev.type === 'report_complete') {
        return {
          ...state,
          report: {
            status: ev.data?.status === 'error' ? 'error' : 'complete',
            pdfPath: ev.data?.pdf_path,
            error: ev.data?.error,
          },
        };
      }

      // Remaining events: untagged system logs, and (rarely) module-scoped
      // log/error lines. The autonomous run flow that used to emit stage /
      // checklist / browser-frame events was removed — the tester now drives
      // each phase manually — so only log/error are handled here.
      const moduleKey = ev.module_key;
      if (ev.type === 'log' || ev.type === 'error') {
        const entry = ev.type === 'error'
          ? { ts: ev.timestamp, level: 'error', message: ev.data?.message || 'Error' }
          : { ts: ev.timestamp, ...ev.data };
        if (!moduleKey) {
          return { ...state, logs: [...state.logs, { ...entry, moduleKey: null }].slice(-500) };
        }
        const cur = state.modules[moduleKey] || { logs: [] };
        return {
          ...state,
          modules: {
            ...state.modules,
            [moduleKey]: { ...cur, logs: [...(cur.logs || []), entry].slice(-500) },
          },
        };
      }
      return state;
    }
    default:
      return state;
  }
}

export default function SessionLayout() {
  const { sid } = useParams();
  const navigate = useNavigate();
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [events, dispatch] = useReducer(reducer, { logs: [], modules: {}, report: { status: 'idle' }, sandbox: { running: false, lines: [], lastExit: null } });
  const wsRef = useRef(null);

  // Initial load + WebSocket connection.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getSession(sid)
      .then((s) => { if (!cancelled) setSession(s); })
      .catch((e) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });

    dispatch({ type: 'reset' });
    const ws = openSessionSocket(sid, (ev) => dispatch({ type: 'ws_event', event: ev }));
    wsRef.current = ws;
    return () => {
      cancelled = true;
      try { ws.close(); } catch { /* noop */ }
    };
  }, [sid]);

  const refresh = useCallback(async () => {
    try {
      const s = await getSession(sid);
      setSession(s);
    } catch (e) {
      setError(e.message);
    }
  }, [sid]);

  const remove = useCallback(async () => {
    const target = session?.target || 'this session';
    const ok = window.confirm(
      `Delete the session "${target}" and all its runs/findings?\n\nThis action is irreversible.`,
    );
    if (!ok) return;
    try {
      await deleteSession(sid);
      try { wsRef.current?.close(); } catch { /* noop */ }
      navigate('/sessions');
    } catch (e) {
      setError(e.message);
    }
  }, [sid, session, navigate]);

  const ctx = useMemo(() => ({
    sid, session, events, dispatch, refresh,
  }), [sid, session, events, refresh]);

  if (loading) return <div className="page"><p className="muted">Loading…</p></div>;
  if (error) return (
    <div className="page">
      <p className="error">{error}</p>
      <button className="btn" onClick={() => navigate('/sessions')}>← Back</button>
    </div>
  );
  if (!session) return null;

  return (
    <div className="session-layout">
      <div className="session-top">
        <header className="session-header">
          <div className="session-header-left">
            <Link to="/sessions" className="back-link">← Sessions</Link>
            <h1 className="session-title glitch" data-text={session.target}>{session.target}</h1>
            <span className="tag tag-active">{session.status}</span>
          </div>
          <nav className="session-nav">
            <NavLink to="." end>Modules</NavLink>
            <NavLink to="scope">Scope</NavLink>
            <NavLink to="findings">Findings</NavLink>
            <NavLink to="endpoints">Endpoints</NavLink>
            <NavLink to="report">Report</NavLink>
          </nav>
          <div className="session-header-right">
            <button
              type="button"
              className="btn btn-danger"
              onClick={remove}
              title="Delete session"
            >
              Delete
            </button>
            <ThemeToggle />
          </div>
        </header>
      </div>

      <main className="session-main">
        <Outlet context={ctx} />
      </main>
    </div>
  );
}
