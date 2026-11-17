import FindingsList from './FindingsList.jsx';

/**
 * Checklist reference paired with results. In the tester-driven model the
 * checklist is guidance, NOT an executable task list — these items orient the
 * tester on what to look at in this phase. There are no checkboxes and nothing
 * runs. Each test is shown with the finding(s) recorded against it directly
 * underneath; when none exist yet we show a "not conclusive yet" placeholder so
 * every test makes its status explicit.
 *
 * Props:
 *   tests    — [{ id, test_id, tests, vulnerabilite_attendue?, outils?, commande? }]
 *   findings — [{ checklist_test_id, ... }] (optional); matched to a test by
 *              checklist_test_id === test_id.
 */
export default function ReferenceList({ tests, findings = [], onAskAI }) {
  if (!tests || tests.length === 0) {
    return <p className="muted small">No reference items for this phase.</p>;
  }

  // Group findings by the checklist test they belong to.
  const byTest = new Map();
  for (const f of findings) {
    const key = String(f.checklist_test_id || '');
    if (!key) continue;
    if (!byTest.has(key)) byTest.set(key, []);
    byTest.get(key).push(f);
  }

  return (
    <ul className="reference-list">
      {tests.map((t) => {
        const matched = byTest.get(String(t.test_id)) || [];
        return (
          <li key={t.id ?? t.test_id} className="reference-item">
            <div className="ref-main">
              <span className="ref-id">{t.test_id}</span>
              <span className="ref-desc">
                {t.tests || t.description || t.test_description || '—'}
              </span>
              {onAskAI && (
                <button
                  type="button"
                  className="btn btn-sm ask-ai-btn"
                  title="Ask the AI Assistant to produce the command for this test, adapted to this target"
                  onClick={() => onAskAI({ kind: 'test', item: t })}
                >
                  ✦ Ask AI
                </button>
              )}
            </div>
            {(t.vulnerabilite_attendue || t.owasp_category) && (
              <div className="ref-meta muted small">
                {t.owasp_category ? <span className="ref-owasp">{t.owasp_category}</span> : null}
                {t.vulnerabilite_attendue ? (
                  <span className="ref-vuln">{t.vulnerabilite_attendue}</span>
                ) : null}
              </div>
            )}

            <div className="ref-findings">
              {matched.length > 0 ? (
                <FindingsList findings={matched} onAskAI={onAskAI} />
              ) : (
                <p className="ref-no-finding muted small">Not conclusive yet — no finding recorded.</p>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
