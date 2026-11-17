import { useEffect, useState } from 'react';
import { getScope, patchScope } from '../api/sessions.js';

const EMPTY = {
  in_scope: [], out_of_scope: [], authorized_domains: [],
  restrictions: '', auth_requirements: '', notes: '',
};

const LIST_FIELDS = [
  { key: 'in_scope',           label: 'In-scope targets / URLs',  placeholder: 'http://localhost:3000' },
  { key: 'authorized_domains', label: 'Authorized domains',       placeholder: 'example.test' },
  { key: 'out_of_scope',       label: 'Out-of-scope resources',   placeholder: '/admin/billing' },
];

const TEXT_FIELDS = [
  { key: 'restrictions',      label: 'Testing restrictions',      placeholder: 'No destructive payloads; rate-limit requests' },
  { key: 'auth_requirements', label: 'Authentication requirements', placeholder: 'Low-security DVWA user' },
  { key: 'notes',             label: 'Additional instructions',   placeholder: 'Focus on the REST API under /api' },
];

function toLines(arr) { return (arr || []).join('\n'); }
function fromLines(text) {
  return (text || '').split('\n').map((s) => s.trim()).filter(Boolean);
}

/**
 * Scope editor. Two modes:
 *  - controlled (pass `value` + `onChange`): used on the create page before a
 *    session exists; the parent owns the scope object.
 *  - standalone (pass `sid`): loads + saves scope against the server.
 */
export default function ScopeEditor({ sid, value, onChange }) {
  const controlled = typeof onChange === 'function';
  const [scope, setScope] = useState(value || EMPTY);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (controlled) { setScope(value || EMPTY); return; }
    if (!sid) return;
    getScope(sid)
      .then((s) => setScope({ ...EMPTY, ...(s || {}) }))
      .catch((e) => setError(e.message));
  }, [sid, controlled, value]);

  function update(key, val) {
    const next = { ...scope, [key]: val };
    setScope(next);
    if (controlled) onChange(next);
  }

  async function save() {
    setSaving(true); setError(null); setMessage(null);
    try {
      await patchScope(sid, scope);
      setMessage('Scope saved.');
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="scope-editor">
      <p className="muted small">
        Define the authorized boundaries of this assessment. These instructions are
        injected into every AI agent so they stay within scope.
        <br />
        <strong>Note:</strong> scope is enforced at the AI-guidance level, not as a
        network firewall — you remain responsible for only testing authorized targets.
      </p>

      {LIST_FIELDS.map(({ key, label, placeholder }) => (
        <label key={key} className="form-field">
          <span>{label} <span className="muted small">(one per line)</span></span>
          <textarea
            rows={2}
            value={toLines(scope[key])}
            placeholder={placeholder}
            onChange={(e) => update(key, fromLines(e.target.value))}
          />
        </label>
      ))}

      {TEXT_FIELDS.map(({ key, label, placeholder }) => (
        <label key={key} className="form-field">
          <span>{label}</span>
          <textarea
            rows={2}
            value={scope[key] || ''}
            placeholder={placeholder}
            onChange={(e) => update(key, e.target.value)}
          />
        </label>
      ))}

      {error && <p className="error">{error}</p>}
      {message && <p className="success">{message}</p>}

      {!controlled && (
        <div className="actions">
          <button className="btn btn-primary" onClick={save} disabled={saving}>
            {saving ? 'Saving…' : 'Save scope'}
          </button>
        </div>
      )}
    </div>
  );
}
