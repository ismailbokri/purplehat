import { useState } from 'react';
import { categoryLabel } from '../api/sessions.js';

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

export default function FindingsList({ findings, onAskAI }) {
  if (!findings || findings.length === 0) return null;
  const sorted = [...findings].sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity) === -1 ? 9 : SEVERITY_ORDER.indexOf(a.severity);
    const bi = SEVERITY_ORDER.indexOf(b.severity) === -1 ? 9 : SEVERITY_ORDER.indexOf(b.severity);
    return ai - bi;
  });
  return (
    <ul className="findings-list">
      {sorted.map((f) => <FindingCard key={f.id} f={f} onAskAI={onAskAI} />)}
    </ul>
  );
}

function FindingCard({ f, onAskAI }) {
  const [expanded, setExpanded] = useState(false);
  const sev = f.severity || 'Informational';
  return (
    <li className={`finding-card sev-${sev.toLowerCase()}${f.test_status ? ` status-${f.test_status}` : ''}`}>
      <header className="finding-card-header">
        <span className={`tag tag-sev-${sev.toLowerCase()}`}>{sev}</span>
        <span className={`tag tag-${f.test_status}`}>{f.test_status}</span>
        {f.owasp_id && <span className="tag">{f.owasp_id}</span>}
        {f.checklist_test_id && <span className="tag">Test #{f.checklist_test_id}</span>}
        {f.module_key && <span className="tag">{f.module_key}</span>}
      </header>
      <h4 className="finding-title">{f.finding || f.test_description || '(untitled)'}</h4>
      {f.checklist_category && <p className="muted small">{categoryLabel(f.checklist_category)}</p>}
      <div className="finding-card-actions">
        <button className="btn btn-link" onClick={() => setExpanded((v) => !v)}>
          {expanded ? 'Hide details' : 'View details'}
        </button>
        {onAskAI && (
          <button
            type="button"
            className="btn btn-sm ask-ai-btn"
            title="Ask the AI Assistant to produce the command for this finding, adapted to this target"
            onClick={() => onAskAI({ kind: 'finding', item: f })}
          >
            ✦ Ask AI
          </button>
        )}
      </div>
      {expanded && (
        <div className="finding-details">
          {f.cvss != null && <p><strong>CVSS:</strong> {f.cvss}</p>}
          {f.cvss_vector && <p className="muted small">{f.cvss_vector}</p>}
          {f.cve && f.cve.length > 0 && <p><strong>CVE:</strong> {f.cve.join(', ')}</p>}
          {f.command && <pre className="code">{f.command}</pre>}
          {f.output_snippet && <pre className="code">{f.output_snippet}</pre>}
        </div>
      )}
    </li>
  );
}
