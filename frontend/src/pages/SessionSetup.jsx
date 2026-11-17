import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createSession } from '../api/sessions.js';
import TopNav from '../components/TopNav.jsx';
import ScopeEditor from '../components/ScopeEditor.jsx';
import { parseEndpoints } from '../utils/endpoints.js';

const STEPS = [
  { key: 'target',    label: 'Target',    hint: 'Essential information' },
  { key: 'endpoints', label: 'Endpoints', hint: 'Extra URLs to test' },
  { key: 'scope',     label: 'Scope',     hint: 'Rules of engagement' },
  { key: 'review',    label: 'Review',    hint: 'Confirm & launch' },
];

export default function SessionSetup() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('');
  const [endpointInput, setEndpointInput] = useState('');
  const [endpoints, setEndpoints] = useState([]);
  const [scope, setScope] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const isLast = step === STEPS.length - 1;

  function addEndpoint() {
    const parsed = parseEndpoints(endpointInput);
    if (parsed.length === 0) return;
    setEndpoints((cur) => {
      const seen = new Set(cur);
      const next = [...cur];
      for (const ep of parsed) {
        if (!seen.has(ep)) {
          next.push(ep);
          seen.add(ep);
        }
      }
      return next;
    });
    setEndpointInput('');
  }

  function removeEndpoint(e) {
    setEndpoints((cur) => cur.filter((x) => x !== e));
  }

  function next() {
    // Step 0 (essential info) gates on a non-empty target.
    if (step === 0 && !target.trim()) {
      setError('Target is required to continue.');
      return;
    }
    setError(null);
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  }

  function back() {
    setError(null);
    setStep((s) => Math.max(s - 1, 0));
  }

  async function submit(ev) {
    ev.preventDefault();
    if (!target.trim()) {
      setError('Target required');
      setStep(0);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const res = await createSession({
        target: target.trim(),
        port: port ? parseInt(port, 10) : undefined,
        custom_endpoints: endpoints,
        scope,
      });
      navigate(`/sessions/${res.session_id}`);
    } catch (e) {
      setError(e.message);
      setSubmitting(false);
    }
  }

  const scopeCount = Object.values(scope || {}).filter(
    (v) => (Array.isArray(v) ? v.length : v != null && v !== ''),
  ).length;

  return (
    <>
      <TopNav />
      <div className="page">
        <header className="page-header">
          <h1 className="glitch" data-text="New session">New session</h1>
          <p className="muted">Step {step + 1} of {STEPS.length} — {STEPS[step].hint}</p>
        </header>

        {/* ── Stepper ──────────────────────────────────────────────────────── */}
        <ol className="wizard-steps">
          {STEPS.map((s, i) => {
            const state = i < step ? 'done' : i === step ? 'active' : 'pending';
            return (
              <li key={s.key} className={`wizard-step wizard-step-${state}`}>
                <button
                  type="button"
                  className="wizard-step-marker"
                  onClick={() => { if (i < step) { setError(null); setStep(i); } }}
                  disabled={i > step}
                  aria-current={i === step ? 'step' : undefined}
                >
                  {i < step ? '✓' : i + 1}
                </button>
                <span className="wizard-step-label">{s.label}</span>
              </li>
            );
          })}
        </ol>

        <form className="wizard-card" onSubmit={submit}>
          {/* ── Step 1: Essential information ──────────────────────────────── */}
          {step === 0 && (
            <div className="wizard-panel">
              <h3>Essential information</h3>
              <p className="muted small">Where should the assessment point? This is the only required field.</p>
              <label>
                <span>Target</span>
                {/* Tooltip (2s hover delay) replaces the inline label hint. */}
                <span className="tip tip-block">
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    autoFocus
                    required
                  />
                  <span className="tip-bubble" role="tooltip">hostname, IP, or URL</span>
                </span>
              </label>
              <label>
                <span>
                  Port{' '}
                  {/* The asterisk reveals the "optional…" note on 2s hover. */}
                  <span className="tip tip-up" tabIndex={0}>
                    <span className="tip-star" aria-hidden="true">*</span>
                    <span className="tip-bubble" role="tooltip">optional if already in the target</span>
                  </span>
                </span>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="e.g. 8080"
                  min={1}
                  max={65535}
                />
              </label>
            </div>
          )}

          {/* ── Step 2: Custom endpoints ───────────────────────────────────── */}
          {step === 1 && (
            <div className="wizard-panel">
              <h3>Custom endpoints <span className="wizard-optional">optional</span></h3>
              <p className="muted small">
                URLs or paths to include in the test scope. Paste several at once —
                separated by space, comma or new line. <kbd>Ctrl+Enter</kbd> to add.
              </p>
              <div className="row">
                <textarea
                  rows={3}
                  value={endpointInput}
                  onChange={(e) => setEndpointInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                      e.preventDefault();
                      addEndpoint();
                    }
                  }}
                  placeholder="/api/login&#10;/admin&#10;https://example.com/search?q="
                />
                <button type="button" className="btn" onClick={addEndpoint}>Add</button>
              </div>
              {endpoints.length > 0 && (
                <ul className="chip-list">
                  {endpoints.map((e) => (
                    <li key={e} className="chip">
                      <span>{e}</span>
                      <button type="button" aria-label="Remove" onClick={() => removeEndpoint(e)}>×</button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* ── Step 3: Scope ──────────────────────────────────────────────── */}
          {step === 2 && (
            <div className="wizard-panel">
              <h3>Assessment scope <span className="wizard-optional">optional</span></h3>
              <p className="muted small">Define what is in and out of bounds for this engagement.</p>
              <ScopeEditor value={scope} onChange={setScope} />
            </div>
          )}

          {/* ── Step 4: Review ─────────────────────────────────────────────── */}
          {step === 3 && (
            <div className="wizard-panel">
              <h3>Review &amp; launch</h3>
              <p className="muted small">Confirm the details below, then create the session.</p>
              <dl className="wizard-review">
                <div><dt>Target</dt><dd>{target.trim() || <span className="muted">—</span>}</dd></div>
                <div><dt>Port</dt><dd>{port || <span className="muted">default</span>}</dd></div>
                <div>
                  <dt>Custom endpoints</dt>
                  <dd>{endpoints.length ? `${endpoints.length} added` : <span className="muted">none</span>}</dd>
                </div>
                <div>
                  <dt>Scope rules</dt>
                  <dd>{scopeCount ? `${scopeCount} set` : <span className="muted">defaults</span>}</dd>
                </div>
              </dl>
            </div>
          )}

          {error && <p className="error">{error}</p>}

          {/* ── Navigation ─────────────────────────────────────────────────── */}
          <div className="wizard-actions">
            <button
              type="button"
              className="btn"
              onClick={back}
              disabled={step === 0 || submitting}
            >
              ← Back
            </button>
            {isLast ? (
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? 'Creating…' : 'Create session'}
              </button>
            ) : (
              <button type="button" className="btn btn-primary" onClick={next}>
                Next →
              </button>
            )}
          </div>
        </form>
      </div>
    </>
  );
}
