import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { deleteSession, listSessions } from '../api/sessions.js';
import TopNav from '../components/TopNav.jsx';

export default function SessionList() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    listSessions()
      .then((rows) => setSessions(Array.isArray(rows) ? rows : []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleDelete(s) {
    const ok = window.confirm(
      `Delete the session "${s.target}" and all its runs/findings?\n\nThis action is irreversible.`,
    );
    if (!ok) return;
    setError(null);
    setDeletingId(s.session_id);
    try {
      await deleteSession(s.session_id);
      setSessions((cur) => cur.filter((x) => x.session_id !== s.session_id));
    } catch (e) {
      setError(e.message);
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <>
    <TopNav />
    <div className="page">
      <header className="page-header">
        <h1 className="glitch" data-text="Pentest sessions">Pentest sessions</h1>
        <Link to="/sessions/new" className="btn btn-primary">+ New session</Link>
      </header>

      {loading && <p className="muted">Loading…</p>}
      {error && <p className="error">{error}</p>}

      {!loading && !error && sessions.length === 0 && (
        <div className="empty">
          <p>No sessions yet.</p>
          <Link to="/sessions/new" className="btn btn-primary">Create the first session</Link>
        </div>
      )}

      {sessions.length > 0 && (
        <table className="table table-sessions">
          <thead>
            <tr><th>Target</th><th>Status</th><th>Created</th><th>Report</th><th></th></tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.session_id}>
                <td><Link to={`/sessions/${s.session_id}`}>{s.target}</Link></td>
                <td><span className={`tag tag-${s.status}`}>{s.status}</span></td>
                <td className="muted">{s.created_at ? new Date(s.created_at).toLocaleString() : '—'}</td>
                <td>{s.last_report_pdf_path ? <span className="tag tag-found">PDF available</span> : <span className="muted">—</span>}</td>
                <td className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
                  <Link to={`/sessions/${s.session_id}`} className="btn">Open</Link>
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() => handleDelete(s)}
                    disabled={deletingId === s.session_id}
                    title="Delete session"
                  >
                    {deletingId === s.session_id ? '…' : 'Delete'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
    </>
  );
}
