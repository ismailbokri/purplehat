import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export default function Register() {
  const { user, register } = useAuth();
  const [email, setEmail]             = useState('');
  const [password, setPassword]       = useState('');
  const [confirmPassword, setConfirm] = useState('');
  const [fullName, setFullName]       = useState('');
  const [phone, setPhone]             = useState('');
  const [location, setLocation]       = useState('');
  const [organization, setOrg]        = useState('');
  const [error, setError]             = useState(null);
  const [busy, setBusy]               = useState(false);

  const navigate = useNavigate();

  if (user) return <Navigate to="/overview" replace />;

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (password.length < 6) {
      setError('The password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('The passwords do not match.');
      return;
    }

    setBusy(true);
    try {
      // Profile fields are collected here and sent to the API. The backend
      // currently stores email + password; unknown fields are ignored safely.
      await register(email.trim(), password, {
        full_name: fullName.trim(),
        phone: phone.trim(),
        location: location.trim(),
        organization: organization.trim(),
      });
      navigate('/overview', { replace: true });
    } catch (err) {
      setError(err.message || 'Registration failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card auth-card-wide">
        <div className="auth-brand">PurpleHat</div>
        <h1 className="auth-heading">Create an account</h1>
        <p className="auth-subhead">The first account created gets the administrator role</p>

        <form onSubmit={onSubmit} className="auth-form">
          {/* ── Account credentials ─────────────────────────────────────── */}
          <fieldset className="auth-section">
            <legend className="auth-section-title">Account</legend>

            <label className="auth-field">
              <span className="auth-field-label">Email address</span>
              <input
                className="auth-input"
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
                autoComplete="email"
                disabled={busy}
              />
            </label>

            <div className="auth-grid-2">
              <label className="auth-field">
                <span className="auth-field-label">Password (6 characters min.)</span>
                <input
                  className="auth-input"
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  minLength={6}
                  autoComplete="new-password"
                  disabled={busy}
                />
              </label>
              <label className="auth-field">
                <span className="auth-field-label">Confirm password</span>
                <input
                  className="auth-input"
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirm(e.target.value)}
                  required
                  autoComplete="new-password"
                  disabled={busy}
                />
              </label>
            </div>
          </fieldset>

          {/* ── Profile details ─────────────────────────────────────────── */}
          <fieldset className="auth-section">
            <legend className="auth-section-title">Profile <span className="wizard-optional">optional</span></legend>

            <label className="auth-field">
              <span className="auth-field-label">Full name</span>
              <input
                className="auth-input"
                type="text"
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                autoComplete="name"
                disabled={busy}
              />
            </label>

            <div className="auth-grid-2">
              <label className="auth-field">
                <span className="auth-field-label">Phone number</span>
                <input
                  className="auth-input"
                  type="tel"
                  value={phone}
                  onChange={e => setPhone(e.target.value)}
                  autoComplete="tel"
                  placeholder="+1 555 000 0000"
                  disabled={busy}
                />
              </label>
              <label className="auth-field">
                <span className="auth-field-label">Location</span>
                <input
                  className="auth-input"
                  type="text"
                  value={location}
                  onChange={e => setLocation(e.target.value)}
                  autoComplete="address-level2"
                  placeholder="City, Country"
                  disabled={busy}
                />
              </label>
            </div>

            <label className="auth-field">
              <span className="auth-field-label">Organization</span>
              <input
                className="auth-input"
                type="text"
                value={organization}
                onChange={e => setOrg(e.target.value)}
                autoComplete="organization"
                disabled={busy}
              />
            </label>
          </fieldset>

          {error && <div className="auth-error">{error}</div>}

          <button type="submit" className="auth-submit" disabled={busy}>
            {busy ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <div className="auth-switch">
          Already have an account? <Link to="/login" className="auth-link">Log in</Link>
        </div>
      </div>
    </div>
  );
}
