import { useEffect, useState } from 'react';
import { Link, useOutletContext } from 'react-router-dom';
import { MODULE_KEYS, MODULE_LABEL, MODULE_CATEGORY, MODULE_PHASE_CLASS } from '../api/sessions.js';
import { apiFetch } from '../api/client.js';

export default function ModulesOverview() {
  const { session, events } = useOutletContext();
  const [testsByCategory, setTestsByCategory] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch('/checklist')
      .then((rows) => {
        const grouped = {};
        for (const t of rows || []) {
          (grouped[t.category] ||= []).push(t);
        }
        setTestsByCategory(grouped);
      })
      .catch(() => { /* leave empty */ })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="modules-overview">
      <p className="page-intro">
        Pick a phase to open its workspace — an AI assistant on the right, and the
        execution environment (browser explorer, sandbox, exploit generation) on the
        left. When you're ready, open <strong>Reporting</strong> to review findings and
        generate the report.
      </p>

      {loading && <p className="muted">Loading modules…</p>}

      <div className="module-grid">
        {MODULE_KEYS.map((key) => {
          const category = MODULE_CATEGORY[key];
          const total = (testsByCategory[category] || []).length;
          const phaseClass = MODULE_PHASE_CLASS[key] || '';
          return (
            <Link key={key} to={`modules/${key}`} className={`module-card phase-colored ${phaseClass}`}>
              <header className="module-card-header">
                <h2>{MODULE_LABEL[key]}</h2>
              </header>
              <div className="module-card-body">
                <p className="muted small">{total} reference item(s)</p>
              </div>
            </Link>
          );
        })}

        {/* Reporting is a dedicated module, not a button. */}
        <Link to="report" className="module-card phase-colored phase-report">
          <header className="module-card-header">
            <h2>Reporting</h2>
          </header>
          <div className="module-card-body">
            <p className="muted small">Review findings &amp; generate the report</p>
          </div>
        </Link>
      </div>
    </div>
  );
}
