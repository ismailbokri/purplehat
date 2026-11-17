import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { createTest, deleteTest, listTests, updateTest } from '../api/checklist';
import { categoryLabel } from '../api/sessions.js';

const EMPTY_FORM = {
  test_id: '',
  category: '',
  tests: '',
  outils: '',
  commande: '',
  ref_procedure: '',
  commentaires: '',
  resultat_attendu: '',
  vulnerabilite_attendue: '',
  bonne_pratique_attendu: '',
};

export default function Checklist() {
  const { user, logout, isAdmin } = useAuth();

  const [tests, setTests]           = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [editingId, setEditingId]   = useState(null); // null = not editing, 0 = creating, n = editing row n
  const [form, setForm]             = useState(EMPTY_FORM);
  const [busy, setBusy]             = useState(false);
  const [search, setSearch]         = useState('');
  const [filterCategory, setFilter] = useState('');

  const fetchTests = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listTests();
      setTests(data || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTests(); }, [fetchTests]);

  const categories = useMemo(() => {
    const seen = new Set();
    const out = [];
    for (const t of tests) {
      if (!seen.has(t.category)) { seen.add(t.category); out.push(t.category); }
    }
    return out;
  }, [tests]);

  const filtered = useMemo(() => {
    const s = search.trim().toLowerCase();
    return tests.filter(t => {
      if (filterCategory && t.category !== filterCategory) return false;
      if (!s) return true;
      const hay = `${t.test_id} ${t.tests} ${t.outils} ${t.vulnerabilite_attendue}`.toLowerCase();
      return hay.includes(s);
    });
  }, [tests, search, filterCategory]);

  const grouped = useMemo(() => {
    const map = new Map();
    for (const t of filtered) {
      if (!map.has(t.category)) map.set(t.category, []);
      map.get(t.category).push(t);
    }
    return map;
  }, [filtered]);

  const startCreate = () => {
    setEditingId(0);
    setForm({ ...EMPTY_FORM, category: filterCategory || categories[0] || '' });
  };
  const startEdit = (t) => {
    setEditingId(t.id);
    setForm({
      test_id: t.test_id || '',
      category: t.category || '',
      tests: t.tests || '',
      outils: t.outils || '',
      commande: t.commande || '',
      ref_procedure: t.ref_procedure || '',
      commentaires: t.commentaires || '',
      resultat_attendu: t.resultat_attendu || '',
      vulnerabilite_attendue: t.vulnerabilite_attendue || '',
      bonne_pratique_attendu: t.bonne_pratique_attendu || '',
    });
  };
  const cancelEdit = () => { setEditingId(null); setForm(EMPTY_FORM); };

  const submitForm = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (editingId === 0) {
        await createTest(form);
      } else {
        await updateTest(editingId, form);
      }
      cancelEdit();
      await fetchTests();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const removeRow = async (id) => {
    if (!window.confirm('Delete this test? This action is irreversible.')) return;
    setBusy(true);
    try {
      await deleteTest(id);
      await fetchTests();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app">
      <div className="overlay" />
      <div className="shell">
        <header className="header">
          <div className="header-top">
            <nav className="header-nav">
              <Link to="/sessions" className="header-link">Sessions</Link>
              <Link to="/checklist" className="header-link active">Checklist</Link>
            </nav>
            <div className="header-user">
              <span className="header-user-email">
                {user?.email}
                {isAdmin && <span className="header-user-role"> · admin</span>}
              </span>
              <button className="header-logout" onClick={logout}>Log out</button>
            </div>
          </div>
          <div className="logo">
            <span>Checklist</span>
          </div>
          <p className="tagline">Test repository used by the orchestrator</p>
        </header>

        <section className="checklist-toolbar">
          <input
            className="auth-input checklist-search"
            placeholder="Search for a test, a tool…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select
            className="auth-input checklist-filter"
            value={filterCategory}
            onChange={e => setFilter(e.target.value)}
          >
            <option value="">All categories</option>
            {categories.map(c => <option key={c} value={c}>{categoryLabel(c)}</option>)}
          </select>
          {isAdmin && (
            <button className="auth-submit checklist-new-btn" onClick={startCreate} disabled={busy}>
              + New test
            </button>
          )}
        </section>

        {error && <div className="auth-error" style={{ margin: '0 0 1rem 0' }}>{error}</div>}

        {editingId !== null && (
          <ChecklistForm
            form={form}
            setForm={setForm}
            onSubmit={submitForm}
            onCancel={cancelEdit}
            busy={busy}
            creating={editingId === 0}
            knownCategories={categories}
          />
        )}

        {loading ? (
          <div className="checklist-loading">Loading checklist…</div>
        ) : (
          <div className="checklist-groups">
            {[...grouped.entries()].map(([category, rows]) => (
              <div key={category} className="checklist-group">
                <h3 className="checklist-group-title">
                  <span className="checklist-group-bullet">▶</span>
                  {categoryLabel(category)}
                  <span className="checklist-group-count">[{rows.length}]</span>
                </h3>
                <div className="checklist-rows">
                  {rows.map(t => (
                    <div key={t.id} className="checklist-row">
                      <div className="checklist-row-head">
                        <span className="checklist-row-id">#{t.test_id}</span>
                        <span className="checklist-row-title">{t.tests}</span>
                        {isAdmin && (
                          <span className="checklist-row-actions">
                            <button className="checklist-action" onClick={() => startEdit(t)} disabled={busy}>Edit</button>
                            <button className="checklist-action checklist-action-danger" onClick={() => removeRow(t.id)} disabled={busy}>Delete</button>
                          </span>
                        )}
                      </div>
                      <div className="checklist-row-meta">
                        {t.outils && <span><b>Tools:</b> {t.outils}</span>}
                        {t.commande && <span><b>Command:</b> <code>{t.commande}</code></span>}
                        {t.vulnerabilite_attendue && <span><b>Expected vulnerability:</b> {t.vulnerabilite_attendue}</span>}
                        {t.resultat_attendu && <span><b>Expected result:</b> {t.resultat_attendu}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {grouped.size === 0 && (
              <div className="checklist-empty">No test matches the selected filter.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}


function ChecklistForm({ form, setForm, onSubmit, onCancel, busy, creating, knownCategories }) {
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  return (
    <form className="checklist-form" onSubmit={onSubmit}>
      <h3 className="checklist-form-title">
        {creating ? 'New test' : 'Edit test'}
      </h3>
      <div className="checklist-form-grid">
        <label className="auth-field">
          <span className="auth-field-label">Identifier</span>
          <input className="auth-input" value={form.test_id} onChange={e => set('test_id', e.target.value)} required />
        </label>
        <label className="auth-field">
          <span className="auth-field-label">Category</span>
          <input
            className="auth-input"
            value={form.category}
            onChange={e => set('category', e.target.value)}
            list="known-categories"
            required
          />
          <datalist id="known-categories">
            {knownCategories.map(c => <option key={c} value={c} />)}
          </datalist>
        </label>
        <label className="auth-field checklist-field-wide">
          <span className="auth-field-label">Test description</span>
          <textarea className="auth-input" rows={2} value={form.tests} onChange={e => set('tests', e.target.value)} required />
        </label>
        <label className="auth-field">
          <span className="auth-field-label">Tools</span>
          <input className="auth-input" value={form.outils} onChange={e => set('outils', e.target.value)} />
        </label>
        <label className="auth-field">
          <span className="auth-field-label">Command</span>
          <input className="auth-input" value={form.commande} onChange={e => set('commande', e.target.value)} />
        </label>
        <label className="auth-field">
          <span className="auth-field-label">Procedure reference</span>
          <input className="auth-input" value={form.ref_procedure} onChange={e => set('ref_procedure', e.target.value)} />
        </label>
        <label className="auth-field">
          <span className="auth-field-label">Comments</span>
          <input className="auth-input" value={form.commentaires} onChange={e => set('commentaires', e.target.value)} />
        </label>
        <label className="auth-field checklist-field-wide">
          <span className="auth-field-label">Expected result</span>
          <textarea className="auth-input" rows={2} value={form.resultat_attendu} onChange={e => set('resultat_attendu', e.target.value)} />
        </label>
        <label className="auth-field checklist-field-wide">
          <span className="auth-field-label">Expected vulnerability</span>
          <textarea className="auth-input" rows={2} value={form.vulnerabilite_attendue} onChange={e => set('vulnerabilite_attendue', e.target.value)} />
        </label>
        <label className="auth-field checklist-field-wide">
          <span className="auth-field-label">Expected best practice</span>
          <textarea className="auth-input" rows={2} value={form.bonne_pratique_attendu} onChange={e => set('bonne_pratique_attendu', e.target.value)} />
        </label>
      </div>
      <div className="checklist-form-actions">
        <button type="button" className="header-logout" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="submit" className="auth-submit" disabled={busy}>
          {busy ? 'Saving…' : (creating ? 'Create' : 'Save')}
        </button>
      </div>
    </form>
  );
}
