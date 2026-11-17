import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import ThemeToggle from '../components/ThemeToggle.jsx';

/* Public landing page: what PurpleHat is, what each section does, and an
 * inline login card. Reachable at "/" without authentication. */

const FEATURES = [
  {
    icon: '🎯',
    title: 'Assessments',
    desc: 'Spin up a target in a guided multi-step session, then run the full ' +
          'reconnaissance → pre-auth → post-auth workflow from one place.',
  },
  {
    icon: '🧠',
    title: 'AI-assisted workflow',
    desc: 'An agent pipeline plans, explores and probes the target, surfacing ' +
          'findings live as the engagement progresses.',
  },
  {
    icon: '📰',
    title: 'Threat Intelligence',
    desc: 'A curated feed of vulnerabilities, incidents and research so your ' +
          'testing tracks what is current in the wild.',
  },
  {
    icon: '✅',
    title: 'Checklist',
    desc: 'A structured, editable methodology checklist to keep every ' +
          'assessment thorough and repeatable.',
  },
];

export default function Home() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState(null);
  const [busy, setBusy]         = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email.trim(), password);
      navigate('/overview', { replace: true });
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="landing">
      <header className="landing-topbar">
        <span className="landing-logo glitch" data-text="PurpleHat">PurpleHat</span>
        <div className="row">
          <ThemeToggle />
          {!user && <Link to="/register" className="btn btn-sm">Create account</Link>}
        </div>
      </header>

      <main className="landing-split">
        {/* ── Left: who/what ──────────────────────────────────────────────── */}
        <section className="landing-intro">
          <span className="landing-eyebrow">AI-assisted penetration testing</span>
          <h1 className="landing-title">
            Run thorough security assessments,<br />guided end to end.
          </h1>
          <p className="landing-lead">
            PurpleHat is a tester-controlled platform that walks a target through
            reconnaissance, pre-authentication and post-authentication testing —
            with an AI agent pipeline doing the heavy lifting while you stay in
            command of the scope.
          </p>

          <div className="landing-features">
            {FEATURES.map((f) => (
              <div key={f.title} className="feature-card">
                <span className="feature-icon" aria-hidden="true">{f.icon}</span>
                <div>
                  <h3 className="feature-title">{f.title}</h3>
                  <p className="feature-desc">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Right: login (or shortcut when already signed in) ───────────── */}
        <aside className="landing-auth">
          <div className="auth-card landing-auth-card">
            <div className="auth-brand">PurpleHat</div>
            {user ? (
              <>
                <h2 className="auth-heading">Welcome back</h2>
                <p className="auth-subhead">You are signed in as {user.email}</p>
                <div className="landing-cta">
                  <Link to="/overview" className="auth-submit landing-enter">Enter workspace</Link>
                  <Link to="/sessions/new" className="btn">+ New assessment</Link>
                </div>
              </>
            ) : (
              <>
                <h2 className="auth-heading">Log in</h2>
                <p className="auth-subhead">Access your security analysis workspace</p>
                <form onSubmit={onSubmit} className="auth-form">
                  <label className="auth-field">
                    <span className="auth-field-label">Email address</span>
                    <input
                      className="auth-input"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      autoComplete="username"
                      disabled={busy}
                    />
                  </label>
                  <label className="auth-field">
                    <span className="auth-field-label">Password</span>
                    <input
                      className="auth-input"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                      disabled={busy}
                    />
                  </label>
                  {error && <div className="auth-error">{error}</div>}
                  <button type="submit" className="auth-submit" disabled={busy}>
                    {busy ? 'Logging in…' : 'Log in'}
                  </button>
                </form>
                <div className="auth-switch">
                  Don’t have an account yet?{' '}
                  <Link to="/register" className="auth-link">Create an account</Link>
                </div>
              </>
            )}
          </div>
        </aside>
      </main>

      <footer className="landing-footer">
        <span className="muted small">PurpleHat · AI-assisted penetration testing platform</span>
      </footer>
    </div>
  );
}
