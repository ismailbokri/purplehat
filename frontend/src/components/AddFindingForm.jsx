import { useState } from 'react';
import { createFinding } from '../api/sessions.js';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

/**
 * Compact form to record a finding by hand in the tester-driven model (there is
 * no automatic run that produces findings). On success it calls onRecorded so
 * the parent can refresh the findings list.
 *
 * Props: sid, phase, defaultEndpoint?, onRecorded?
 */
export default function AddFindingForm({ sid, phase, defaultEndpoint = '', onRecorded }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('Medium');
  const [endpoint, setEndpoint] = useState(defaultEndpoint);
  const [evidence, setEvidence] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  function reset() {
    setTitle(''); setSeverity('Medium'); setEndpoint(defaultEndpoint);
    setEvidence(''); setDescription(''); setError(null);
  }

  async function submit(e) {
    e.preventDefault();
    if (!title.trim()) { setError('Title is required.'); return; }
    setSaving(true);
    setError(null);
    try {
      await createFinding(sid, {
        title: title.trim(), severity, phase: phase || '',
        endpoint: endpoint.trim(), evidence: evidence.trim(),
        description: description.trim(), source: 'manual',
      });
      reset();
      setOpen(false);
      onRecorded && onRecorded();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  if (!open) {
    return (
      <button className="btn btn-sm" onClick={() => setOpen(true)}>
        + Add finding
      </button>
    );
  }

  return (
    <form className="add-finding-form" onSubmit={submit}>
      <div className="aff-row">
        <input
          className="aff-input"
          placeholder="Finding title *"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          autoFocus
        />
        <select className="aff-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <input
        className="aff-input"
        placeholder="Affected endpoint / URL"
        value={endpoint}
        onChange={(e) => setEndpoint(e.target.value)}
      />
      <textarea
        className="aff-input"
        rows={2}
        placeholder="Evidence / proof-of-concept"
        value={evidence}
        onChange={(e) => setEvidence(e.target.value)}
      />
      <textarea
        className="aff-input"
        rows={2}
        placeholder="Description / impact"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
      />
      {error && <p className="error small">{error}</p>}
      <div className="aff-actions">
        <button type="submit" className="btn btn-sm btn-primary" disabled={saving}>
          {saving ? 'Saving…' : 'Record finding'}
        </button>
        <button type="button" className="btn btn-sm" onClick={() => { reset(); setOpen(false); }}>
          Cancel
        </button>
      </div>
    </form>
  );
}
