import { useState } from 'react';
import { patchAuth } from '../api/sessions.js';

export default function AuthPanel({ sid, session }) {
  const [tab, setTab] = useState('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rawCookies, setRawCookies] = useState('');
  const [bearerToken, setBearerToken] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const hasAuth = session?.auth_payload && (
    session.auth_payload.has_username ||
    session.auth_payload.raw_cookies ||
    session.auth_payload.bearer_token
  );

  async function submit() {
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const body =
        tab === 'credentials' ? { username, password } :
        tab === 'cookies'     ? { raw_cookies: rawCookies } :
                                { bearer_token: bearerToken };
      await patchAuth(sid, body);
      setMessage('Authentication saved.');
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-panel">
      <div className="tabs">
        <button className={tab === 'credentials' ? 'tab active' : 'tab'} onClick={() => setTab('credentials')}>Credentials</button>
        <button className={tab === 'cookies' ? 'tab active' : 'tab'} onClick={() => setTab('cookies')}>Cookies / session</button>
        <button className={tab === 'bearer' ? 'tab active' : 'tab'} onClick={() => setTab('bearer')}>Bearer token</button>
      </div>

      {hasAuth && (
        <p className="muted small">
          Authentication already configured for this session.
          {' '}The form below will overwrite it.
        </p>
      )}

      {tab === 'credentials' && (
        <div className="form">
          <label>
            <span>Username</span>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </label>
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </label>
        </div>
      )}

      {tab === 'cookies' && (
        <div className="form">
          <label>
            <span>Cookie string</span>
            <textarea
              rows={3}
              value={rawCookies}
              onChange={(e) => setRawCookies(e.target.value)}
              placeholder="PHPSESSID=abc123; security=low"
            />
          </label>
        </div>
      )}

      {tab === 'bearer' && (
        <div className="form">
          <label>
            <span>Bearer token (JWT, API key…)</span>
            <input type="text" value={bearerToken} onChange={(e) => setBearerToken(e.target.value)} placeholder="eyJhbGc…" />
          </label>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {message && <p className="success">{message}</p>}

      <div className="actions">
        <button className="btn btn-primary" onClick={submit} disabled={submitting}>
          {submitting ? 'Saving…' : 'Save'}
        </button>
      </div>
    </div>
  );
}
