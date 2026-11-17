import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { patchEndpoints } from '../api/sessions.js';
import { parseEndpoints } from '../utils/endpoints.js';

export default function EndpointsView() {
  const { sid, session, refresh } = useOutletContext();
  const [input, setInput] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const endpoints = session?.custom_endpoints || [];
  const discovered = session?.discovered_endpoints || [];

  async function add() {
    const parsed = parseEndpoints(input);
    if (parsed.length === 0) return;
    setSubmitting(true);
    setError(null);
    try {
      await patchEndpoints(sid, { add: parsed });
      setInput('');
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function remove(e) {
    setSubmitting(true);
    setError(null);
    try {
      await patchEndpoints(sid, { remove: [e] });
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="endpoints-view">
      <section className="card">
        <h3>Custom endpoints</h3>
        <p className="muted small">
          Added manually and included in all modules. You can paste
          several endpoints at once — separated by space, comma or
          new line. <kbd>Ctrl+Enter</kbd> to add.
        </p>
        <div className="row">
          <textarea
            rows={3}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                add();
              }
            }}
            placeholder=""
          />
          <button className="btn btn-primary" onClick={add} disabled={submitting || !input.trim()}>
            Add
          </button>
        </div>
        {error && <p className="error">{error}</p>}
        {endpoints.length === 0 ? (
          <p className="muted">No custom endpoints yet.</p>
        ) : (
          <ul className="chip-list">
            {endpoints.map((e) => (
              <li key={e} className="chip">
                <span>{e}</span>
                <button type="button" aria-label="Remove" onClick={() => remove(e)}>×</button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h3>Discovered endpoints ({discovered.length})</h3>
        {discovered.length === 0 ? (
          <p className="muted">No endpoints discovered yet. Run the Discovery module to populate them.</p>
        ) : (
          <ul className="endpoint-list">
            {discovered.map((e, i) => <li key={`${e}-${i}`}>{e}</li>)}
          </ul>
        )}
      </section>
    </div>
  );
}
