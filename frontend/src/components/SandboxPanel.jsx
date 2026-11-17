import { useEffect, useRef, useState } from 'react';
import { execCommand, listSandboxFiles, readSandboxFile } from '../api/exec.js';
import { createFinding } from '../api/sessions.js';

/**
 * Execution & Inspection sandbox (Interface B). The tester runs authorized
 * commands inside the pre-baked pentest-container; output streams live over
 * the session WebSocket (sandbox state lives in SessionLayout).
 *
 * After every run the Finding Agent analyzes the output and the panel ALWAYS
 * renders an explicit verdict — Vulnerability Detected / Not Vulnerable /
 * Inconclusive — never a blank result. On a detected vulnerability the tester
 * can save it as a finding (nothing is persisted automatically).
 *
 * Props:
 *   sid            — session id
 *   phase          — current module phase (passed to the analyzer as context)
 *   sandbox        — { running, lines, lastExit, analysis } from the WS reducer
 *   initialCommand — optional string to pre-fill (e.g. an agent suggestion)
 *   activeTestId   — reference test id auto-linked from "Ask AI" (or null); a
 *                    saved verdict is attached to it so the Tests/Findings row updates
 *   onClearTest    — clear the active test link (free-form run)
 *   onFindingSaved — called after a verdict is saved, to refresh lists
 */
export default function SandboxPanel({
  sid, phase, sandbox, initialCommand, activeTestId, onClearTest, onFindingSaved,
}) {
  const [command, setCommand] = useState('');
  const [error, setError] = useState(null);
  const [files, setFiles] = useState([]);
  const [fileView, setFileView] = useState(null);
  const [saveState, setSaveState] = useState('idle'); // idle | saving | saved | error
  const outRef = useRef(null);

  const running = !!sandbox?.running;
  const lines = sandbox?.lines || [];
  const analysis = sandbox?.analysis || null;

  useEffect(() => {
    if (initialCommand) setCommand(initialCommand);
  }, [initialCommand]);

  // Reset the save button whenever a new verdict arrives.
  useEffect(() => { setSaveState('idle'); }, [analysis]);

  // Auto-scroll output to bottom as lines stream in.
  useEffect(() => {
    if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight;
  }, [lines.length]);

  // Refresh the generated-files list when a command finishes.
  useEffect(() => {
    if (!running && sid) refreshFiles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, sid]);

  function refreshFiles() {
    listSandboxFiles(sid).then((f) => setFiles(Array.isArray(f) ? f : [])).catch(() => {});
  }

  async function run() {
    const cmd = command.trim();
    if (!cmd) return;
    setError(null);
    try {
      await execCommand(sid, cmd, { phase: phase || '' });
    } catch (e) {
      setError(e.message);
    }
  }

  async function viewFile(name) {
    try {
      const res = await readSandboxFile(sid, name);
      setFileView({ name, content: res?.content ?? '' });
    } catch (e) {
      setError(e.message);
    }
  }

  // Record the Finding Agent's verdict as a tester-confirmed result. Works for
  // ALL three verdicts: a detected vulnerability is saved as a full finding; a
  // Not-Vulnerable / Inconclusive verdict is saved as a lightweight status
  // record so the linked Tests/Findings row reflects it instead of the
  // "not conclusive yet" placeholder. When a test is linked (activeTestId), the
  // record is attached to it; otherwise it is recorded without a test link.
  async function saveVerdict() {
    if (!analysis?.status) return;
    const f = analysis.finding; // present only for status === 'found'
    setSaveState('saving');
    try {
      // Title must stay short (≤200). For a confirmed finding use its summary
      // line; for Not-Vulnerable / Inconclusive there is no short finding, so use
      // the verdict label — the full "why it is / is not vulnerable" reasoning
      // goes into the description below, never into the title.
      const rawTitle = (f?.finding) || VERDICT[analysis.status]?.label || 'Sandbox verdict';
      const title = rawTitle.length > 200 ? `${rawTitle.slice(0, 197)}…` : rawTitle;
      await createFinding(sid, {
        title,
        severity: f?.severity || '',
        phase: f?.phase || phase || '',
        endpoint: f?.proof_of_concept?.command || analysis.command || '',
        // Evidence: the finding's PoC snippet when present, else the exact output
        // line(s) the Finding Agent based its verdict on.
        evidence: f?.proof_of_concept?.output_snippet || analysis.evidence || '',
        description: [
          // The Finding Agent's explanation of WHY the target is / is not
          // vulnerable — recorded for every verdict, not just confirmed findings.
          analysis.reasoning ? `Analysis: ${analysis.reasoning}` : '',
          f?.owasp_id ? `OWASP: ${f.owasp_id} ${f.owasp_category || ''}`.trim() : '',
          (f?.cve && f.cve.length) ? `CVE: ${f.cve.join(', ')}` : '',
          f?.cvss != null ? `CVSS: ${f.cvss}${f.cvss_vector ? ` (${f.cvss_vector})` : ''}` : '',
        ].filter(Boolean).join('\n'),
        source: 'sandbox',
        test_status: analysis.status,
        checklist_test_id: activeTestId || '',
      });
      setSaveState('saved');
      onFindingSaved?.();
    } catch (e) {
      setError(e.message);
      setSaveState('error');
    }
  }

  return (
    <div className="sandbox-panel">
      <div className="sandbox-input">
        <textarea
          rows={2}
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); }
          }}
          placeholder="Authorized command — e.g.  curl -s http://juice-shop:3000/rest/products   (Ctrl+Enter to run)"
          disabled={running}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          autoComplete="off"
        />
        <button className="btn btn-primary" onClick={run} disabled={running || !command.trim()}>
          {running ? 'Running…' : 'Run'}
        </button>
      </div>
      {error && <p className="error">{error}</p>}

      <div className="terminal">
        <div className="terminal-bar">
          <span className="terminal-dots" aria-hidden="true">
            <i className="tdot tdot-red" />
            <i className="tdot tdot-yellow" />
            <i className="tdot tdot-green" />
          </span>
          <span className="terminal-title">sandbox — pentest-container</span>
          {running && <span className="terminal-status">running…</span>}
        </div>
        <pre className="sandbox-output" ref={outRef}>
          {lines.length === 0
            ? 'No output yet. Run an authorized command above.'
            : lines.join('\n')}
          {!running && sandbox?.lastExit != null && (
            <span className={sandbox.lastExit === 0 ? 'term-exit-ok' : 'term-exit-err'}>
              {`\n\n[exit ${sandbox.lastExit}]`}
            </span>
          )}
        </pre>
      </div>

      <AnalysisCard
        running={running}
        analysis={analysis}
        saveState={saveState}
        onSave={saveVerdict}
        activeTestId={activeTestId}
        onClearTest={onClearTest}
      />

      <div className="sandbox-files">
        <div className="row space-between">
          <span className="muted small">Generated files</span>
          <button className="btn btn-sm" onClick={refreshFiles}>Refresh</button>
        </div>
        {files.length === 0 ? (
          <p className="muted small">None yet.</p>
        ) : (
          <ul className="file-list">
            {files.map((f) => (
              <li key={f.name}>
                <button className="link-btn" onClick={() => viewFile(f.name)}>{f.name}</button>
                <span className="muted small"> ({f.size} B)</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {fileView && (
        <div className="sandbox-fileview">
          <div className="row space-between">
            <strong>{fileView.name}</strong>
            <button className="btn btn-sm" onClick={() => setFileView(null)}>Close</button>
          </div>
          <div className="terminal">
            <div className="terminal-bar">
              <span className="terminal-dots" aria-hidden="true">
                <i className="tdot tdot-red" />
                <i className="tdot tdot-yellow" />
                <i className="tdot tdot-green" />
              </span>
              <span className="terminal-title">{fileView.name}</span>
            </div>
            <pre className="sandbox-output">{fileView.content}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

// Map the three backend statuses to a visual state. The panel always shows one
// of these after a run — the analysis result is never left blank.
const VERDICT = {
  found:          { cls: 'detected',     label: 'Vulnerability Detected' },
  not_found:      { cls: 'not-vuln',     label: 'Not Vulnerable' },
  not_conclusive: { cls: 'inconclusive', label: 'Inconclusive' },
};

// Per-verdict label for the confirm button (reflects what gets recorded).
const SAVE_LABEL = {
  found:          'Record finding',
  not_found:      'Record “Not Vulnerable”',
  not_conclusive: 'Record “Inconclusive”',
};

/** Finding Agent verdict block — rendered after every execution. */
function AnalysisCard({ running, analysis, saveState, onSave, activeTestId, onClearTest }) {
  if (running) {
    return (
      <div className="sandbox-analysis analysis-pending">
        <span className="analysis-title">Finding Agent</span>
        <span className="analysis-summary">Analyzing output…</span>
      </div>
    );
  }
  if (!analysis) return null; // no run yet this session

  const v = VERDICT[analysis.status] || VERDICT.not_conclusive;
  const f = analysis.finding;
  const isFound = analysis.status === 'found';

  return (
    <div className={`sandbox-analysis verdict-${v.cls}`}>
      <div className="row space-between analysis-head">
        <span className="analysis-title">Finding Agent</span>
        <span className={`verdict-badge verdict-${v.cls}`}>{v.label}</span>
      </div>
      <p className="analysis-summary">{analysis.summary}</p>

      {/* Why the target is / is not vulnerable — shown for every verdict when the
          reasoning adds something beyond the summary line already shown above. */}
      {analysis.reasoning && analysis.reasoning !== analysis.summary && (
        <p className="analysis-reasoning muted small">{analysis.reasoning}</p>
      )}
      {/* Evidence the verdict rests on, for Not-Vulnerable / Inconclusive too
          (the 'found' branch below renders the PoC snippet instead). */}
      {!isFound && analysis.evidence && (
        <pre className="analysis-evidence">{analysis.evidence}</pre>
      )}

      {isFound && f && (
        <ul className="analysis-meta">
          {f.severity && (
            <li><span className={`tag tag-sev-${String(f.severity).toLowerCase()}`}>{f.severity}</span></li>
          )}
          {f.cvss != null && <li>CVSS <strong>{f.cvss}</strong></li>}
          {f.owasp_id && <li>{f.owasp_id} {f.owasp_category}</li>}
          {f.cve && f.cve.length > 0 && <li>CVE: {f.cve.slice(0, 3).join(', ')}</li>}
        </ul>
      )}
      {isFound && f?.proof_of_concept?.output_snippet && (
        <pre className="analysis-evidence">{f.proof_of_concept.output_snippet}</pre>
      )}

      {/* Save action for ALL verdicts — this is what syncs Tests/Findings. */}
      <div className="analysis-link">
        {activeTestId ? (
          <span className="muted small">
            Will update <strong>Test #{activeTestId}</strong>.{' '}
            <button type="button" className="link-btn" onClick={onClearTest}>clear</button>
          </span>
        ) : (
          <span className="muted small">
            No test linked — use <strong>✦ Ask AI</strong> on a test first to attach this verdict to its row.
          </span>
        )}
      </div>
      <div className="row space-between analysis-actions">
        <span className="muted small">Nothing is saved until you confirm.</span>
        <button
          className="btn btn-sm btn-primary"
          onClick={onSave}
          disabled={saveState === 'saving' || saveState === 'saved'}
        >
          {saveState === 'saving' ? 'Saving…'
            : saveState === 'saved' ? '✓ Recorded'
            : (SAVE_LABEL[analysis.status] || 'Record verdict')}
        </button>
      </div>
    </div>
  );
}
