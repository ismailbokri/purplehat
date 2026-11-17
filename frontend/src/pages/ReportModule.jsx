import { useCallback, useEffect, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { listFindings, createReport, createFinding, reportPdfUrl } from '../api/sessions.js';
import { getToken } from '../api/client.js';
import FindingsList from '../components/FindingsList.jsx';
import ChatPanel from '../components/ChatPanel.jsx';

/**
 * Reporting module. A dedicated workspace (not just a button): review findings,
 * discuss them with the Reporting assistant, give instructions for the final
 * report, and generate it. The PDF generation core is unchanged — this page
 * drives the existing /report endpoint and adds the discussion agent on top.
 */
export default function ReportModule() {
  const { sid, events } = useOutletContext();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const reportState = events.report || { status: 'idle' };
  const status = reportState.status || 'idle';
  const isRunning = status === 'running';
  const isComplete = status === 'complete';

  const loadFindings = useCallback(() => {
    setLoading(true);
    listFindings(sid)
      .then((rows) => setFindings(Array.isArray(rows) ? rows : []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [sid]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      await createReport(sid);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function download() {
    setError(null);
    try {
      const res = await fetch(reportPdfUrl(sid), {
        headers: { Authorization: `Bearer ${getToken() || ''}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pentest_report_${sid.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message);
    }
  }

  // The reporting assistant can also propose a finding from a PoC the tester shares.
  const recordProposedFinding = useCallback(async (f) => {
    await createFinding(sid, {
      title: f.title, severity: f.severity, phase: 'report',
      endpoint: f.endpoint || '', evidence: f.evidence || '',
      description: f.description || '', source: 'chat',
    });
    loadFindings();
    return true;
  }, [sid, loadFindings]);

  return (
    <div className="module-runner">
      <header className="module-runner-header phase-report">
        <h2>Reporting</h2>
        <span className="phase-badge">Findings review &amp; report</span>
      </header>

      <div className="workspace-split">
        {/* ── LEFT: findings review + report generation ──────────────────── */}
        <section className="workspace-left">
          <div className="workspace-pane">
            <div className="pane-block">
              <div className="sub-card">
                <div className="row space-between">
                  <h4>Report</h4>
                  <div className="row">
                    <button className="btn btn-primary" onClick={generate} disabled={busy || isRunning}>
                      {isRunning ? 'Generating…' : 'Generate report'}
                    </button>
                    {isComplete && (
                      <button className="btn" onClick={download}>Download PDF</button>
                    )}
                  </div>
                </div>
                <p className="muted small">
                  Generation uses every finding recorded in this session. Discuss and refine
                  the findings with the assistant on the right before generating.
                </p>
                {reportState.stage && isRunning && (
                  <p className="muted small">Stage: {reportState.stage}</p>
                )}
                {status === 'error' && (
                  <p className="error small">{reportState.error || 'Report generation failed.'}</p>
                )}
                {error && <p className="error small">{error}</p>}
              </div>

              <div className="sub-card">
                <h4>Findings ({findings.length})</h4>
                {loading && <p className="muted">Loading…</p>}
                {!loading && findings.length === 0 && (
                  <p className="muted small">
                    No findings recorded yet. Record them in the phase modules, or ask the
                    assistant to propose one from a PoC.
                  </p>
                )}
                {findings.length > 0 && <FindingsList findings={findings} />}
              </div>
            </div>
          </div>
        </section>

        {/* ── RIGHT: reporting assistant (fixed) ─────────────────────────── */}
        <aside className="workspace-right">
          <div className="workspace-right-head">
            <h3>Reporting Assistant</h3>
          </div>
          <p className="muted small assistant-sub">
            Ask about the findings, discuss severity and impact, and give instructions for the
            final report. Share a PoC and it can propose a finding to record.
          </p>
          <ChatPanel
            sid={sid}
            phase="report"
            onProposeFinding={recordProposedFinding}
          />
        </aside>
      </div>
    </div>
  );
}
