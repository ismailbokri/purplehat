import { useEffect, useMemo, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { listFindings, MODULE_KEYS, MODULE_LABEL } from '../api/sessions.js';
import FindingsList from '../components/FindingsList.jsx';

export default function FindingsView() {
  const { sid } = useOutletContext();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [moduleFilter, setModuleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  useEffect(() => {
    setLoading(true);
    listFindings(sid, {
      moduleKey: moduleFilter || undefined,
      testStatus: statusFilter || undefined,
    })
      .then((rows) => setFindings(Array.isArray(rows) ? rows : []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [sid, moduleFilter, statusFilter]);

  const counts = useMemo(() => {
    const c = { found: 0, not_found: 0, not_conclusive: 0 };
    for (const f of findings) {
      if (c[f.test_status] !== undefined) c[f.test_status]++;
    }
    return c;
  }, [findings]);

  return (
    <div className="findings-view">
      <header className="page-header">
        <h2>Findings ({findings.length})</h2>
        <div className="row chip-row">
          <span className="tag tag-found">{counts.found} confirmed</span>
          <span className="tag tag-not_conclusive">{counts.not_conclusive} inconclusive</span>
          <span className="tag tag-not_found">{counts.not_found} not found</span>
        </div>
      </header>

      <div className="filters">
        <label>
          <span>Module</span>
          <select value={moduleFilter} onChange={(e) => setModuleFilter(e.target.value)}>
            <option value="">All</option>
            {MODULE_KEYS.map((k) => (
              <option key={k} value={k}>{MODULE_LABEL[k]}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Status</span>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All</option>
            <option value="found">Confirmed</option>
            <option value="not_conclusive">Inconclusive</option>
            <option value="not_found">Not found</option>
          </select>
        </label>
      </div>

      {loading && <p className="muted">Loading…</p>}
      {error && <p className="error">{error}</p>}
      {!loading && !error && findings.length === 0 && (
        <p className="muted">No findings for this filter.</p>
      )}
      {findings.length > 0 && <FindingsList findings={findings} />}
    </div>
  );
}
