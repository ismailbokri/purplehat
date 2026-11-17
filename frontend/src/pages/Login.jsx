import { useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export default function Login() {
  const { user, login } = useAuth();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState(null);
  const [busy, setBusy]         = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = location.state?.from?.pathname || '/overview';

  if (user) return <Navigate to={redirectTo} replace />;

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email.trim(), password);
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">PurpleHat</div>
        <h1 className="auth-heading">Log in</h1>
        <p className="auth-subhead">Access your security analysis workspace</p>

        <form onSubmit={onSubmit} className="auth-form">
          <label className="auth-field">
            <span className="auth-field-label">Email address</span>
            <input
              className="auth-input"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoFocus
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
              onChange={e => setPassword(e.target.value)}
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
          Don’t have an account yet? <Link to="/register" className="auth-link">Create an account</Link>
        </div>
      </div>
    </div>
  );
}
