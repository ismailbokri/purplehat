import { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigate, useOutletContext, useParams } from 'react-router-dom';
import {
  MODULE_CATEGORY, MODULE_LABEL, MODULE_PHASE_CLASS,
  MODULE_HAS_BROWSER, MODULE_KEYS, categoryLabel,
  listFindings, createFinding,
} from '../api/sessions.js';
import { apiFetch } from '../api/client.js';
import ReferenceList from '../components/ReferenceList.jsx';
import AuthPanel from '../components/AuthPanel.jsx';
import AddFindingForm from '../components/AddFindingForm.jsx';
import SandboxPanel from '../components/SandboxPanel.jsx';
import ChatPanel from '../components/ChatPanel.jsx';
import BrowserExplorer from '../components/BrowserExplorer.jsx';

// Module key → Conversation-Agent phase. Two active phases only.
const MODULE_TO_PHASE = {
  discovery:    'discovery',
  exploitation: 'exploitation',
};

// Old pre-merge URLs → the merged Exploitation module (keeps bookmarks working).
const LEGACY_MODULE_REDIRECT = {
  preauth:  'exploitation',
  postauth: 'exploitation',
};

export default function ModuleRunner() {
  const { moduleKey } = useParams();
  const { sid, session, events } = useOutletContext();

  const moduleLabel = MODULE_LABEL[moduleKey] || moduleKey;
  const category = MODULE_CATEGORY[moduleKey];
  const phase = MODULE_TO_PHASE[moduleKey] || 'discovery';

  const hasBrowser = !!MODULE_HAS_BROWSER[moduleKey];

  const [tests, setTests] = useState([]);
  const [loadingTests, setLoadingTests] = useState(true);
  const [findings, setFindings] = useState([]);
  const [pendingCommand, setPendingCommand] = useState('');
  const [pendingQuestion, setPendingQuestion] = useState('');
  // The reference test the tester is currently working on, auto-linked from the
  // "Ask AI" flow. The sandbox attaches it to a saved verdict so the result lands
  // under the right Tests/Findings row. Null = free-form run (no test linked).
  const [activeTestId, setActiveTestId] = useState(null);
  const [chatRefresh, setChatRefresh] = useState(0);

  // Which left-pane view is active. Tests+Findings is always available and is
  // the default (Discovery has no browser tab).
  const [leftTab, setLeftTab] = useState('tests');

  // Build the tab set for this module.
  const tabs = useMemo(() => {
    const t = [];
    if (hasBrowser) t.push({ key: 'browser', label: 'Browser Explorer' });
    t.push({ key: 'sandbox', label: 'Execution Sandbox' });
    t.push({ key: 'tests', label: 'Tests & Findings' });
    return t;
  }, [hasBrowser]);

  // Keep the active tab valid when the module (and thus available tabs) changes.
  useEffect(() => {
    if (!tabs.some((t) => t.key === leftTab)) setLeftTab('tests');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey]);

  const loadFindings = useCallback(() => {
    listFindings(sid, { moduleKey: 'manual' })
      .then((rows) => setFindings(Array.isArray(rows) ? rows : []))
      .catch(() => { /* leave empty */ });
  }, [sid]);

  useEffect(() => {
    setLoadingTests(true);
    apiFetch('/checklist')
      .then((rows) => setTests((rows || []).filter((t) => t.category === category)))
      .catch(() => setTests([]))
      .finally(() => setLoadingTests(false));
  }, [category]);

  useEffect(() => { loadFindings(); }, [loadFindings, moduleKey]);

  // Chat suggestion → drop a command into the sandbox and switch to it.
  const useCommand = useCallback((cmd) => {
    setPendingCommand(cmd);
    setLeftTab('sandbox');
  }, []);

  // The real target for this session. host_base_url is the full base URL when
  // known; otherwise fall back to the bare target. We never substitute a
  // placeholder like example.com — the assistant is told the actual target.
  const sessionTarget = session?.host_base_url || session?.target || '';

  // "Ask AI" on a test/finding → build a detailed question tied to THIS target
  // and hand it to the assistant, which replies with the adapted command.
  const askAI = useCallback(({ kind, item }) => {
    const lines = [];
    const target = sessionTarget;

    // Auto-link: remember which reference test this command is for, so a sandbox
    // verdict saved afterward lands under this test's row. Finding → use its
    // related test id if present; otherwise don't change the active link.
    if (kind === 'test') {
      if (item.test_id != null) setActiveTestId(String(item.test_id));
    } else if (item.checklist_test_id) {
      setActiveTestId(String(item.checklist_test_id));
    }

    if (kind === 'test') {
      lines.push(`I want to run checklist test #${item.test_id || '?'} against the target of this session.`);
      lines.push('');
      lines.push('Test details:');
      if (item.tests)                  lines.push(`- Description: ${item.tests}`);
      if (item.category)               lines.push(`- Category: ${categoryLabel(item.category)}`);
      if (item.outils)                 lines.push(`- Tools: ${item.outils}`);
      if (item.commande)               lines.push(`- Reference command (template): ${item.commande}`);
      if (item.vulnerabilite_attendue) lines.push(`- Expected vulnerability: ${item.vulnerabilite_attendue}`);
      if (item.resultat_attendu)       lines.push(`- Expected result: ${item.resultat_attendu}`);
      if (item.ref_procedure)          lines.push(`- Procedure reference: ${item.ref_procedure}`);
    } else {
      lines.push('I want to re-test / dig deeper on a recorded finding against the target of this session.');
      lines.push('');
      lines.push('Finding details:');
      const title = item.finding || item.test_description || item.title;
      if (title)                   lines.push(`- Finding: ${title}`);
      if (item.severity)           lines.push(`- Severity: ${item.severity}`);
      if (item.checklist_test_id)  lines.push(`- Related test: #${item.checklist_test_id}`);
      if (item.checklist_category) lines.push(`- Category: ${categoryLabel(item.checklist_category)}`);
      if (item.endpoint)           lines.push(`- Endpoint: ${item.endpoint}`);
      if (item.command)            lines.push(`- Previous command: ${item.command}`);
      if (item.output_snippet)     lines.push(`- Evidence/output: ${String(item.output_snippet).slice(0, 500)}`);
    }

    lines.push('');
    lines.push(
      target
        ? `Target: ${target}. Give me a single, copy-pasteable command adapted to THIS exact target `
          + `(do not use example.com or any placeholder host). Explain briefly what it checks.`
        : `Give me a single, copy-pasteable command adapted to this session's actual target `
          + `(do not use example.com or any placeholder host). Explain briefly what it checks.`
    );

    setPendingQuestion(lines.join('\n'));
  }, [sessionTarget]);

  // Chat routing suggestion → switch the left tab (if that tab exists here).
  const handleRoute = useCallback((route) => {
    if (route === 'browser_explorer' && hasBrowser) setLeftTab('browser');
  }, [hasBrowser]);

  // Chat agent proposed a finding and the tester confirmed it.
  const recordProposedFinding = useCallback(async (f) => {
    await createFinding(sid, {
      title: f.title, severity: f.severity, phase,
      endpoint: f.endpoint || '', evidence: f.evidence || '',
      description: f.description || '', source: 'chat',
    });
    loadFindings();
    return true;
  }, [sid, phase, loadFindings]);

  // Redirect legacy /modules/preauth|postauth URLs to the merged Exploitation
  // module. Done after all hooks so hook order stays stable.
  const redirectTo = LEGACY_MODULE_REDIRECT[moduleKey];
  if (redirectTo) {
    return <Navigate to={`../modules/${redirectTo}`} replace />;
  }
  // Unknown module key → send back to the module overview.
  if (!MODULE_KEYS.includes(moduleKey)) {
    return <Navigate to=".." replace />;
  }

  return (
    <div className="module-runner">
      <header className={`module-runner-header ${MODULE_PHASE_CLASS[moduleKey] || ''}`}>
        <h2>{moduleLabel}</h2>
        <span className="phase-badge">{categoryLabel(category)}</span>
      </header>

      <div className="workspace-split">
        {/* ── LEFT: execution environment (switchable) ───────────────────── */}
        <section className="workspace-left">
          <div className="workspace-tabs" role="tablist">
            {tabs.map((t) => (
              <button
                key={t.key}
                role="tab"
                aria-selected={leftTab === t.key}
                className={`workspace-tab ${leftTab === t.key ? 'active' : ''}`}
                onClick={() => setLeftTab(t.key)}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="workspace-pane">
            {leftTab === 'browser' && hasBrowser && (
              <div className="pane-block">
                <p className="muted small">
                  Browse the authorized target and click <strong>Capture</strong> to send the
                  page's DOM and a screenshot to the assistant. Capture is manual.
                </p>
                <BrowserExplorer
                  sid={sid}
                  phase={phase}
                  targetUrl={session?.host_base_url || session?.target || ''}
                  onCaptured={() => setChatRefresh((n) => n + 1)}
                />
              </div>
            )}

            {leftTab === 'sandbox' && (
              <div className="pane-block">
                <p className="muted small">
                  Run authorized commands inside the isolated pentest container. Output streams
                  live. Execution is manual — nothing runs without your click.
                </p>
                <SandboxPanel
                  sid={sid}
                  phase={phase}
                  sandbox={events.sandbox}
                  initialCommand={pendingCommand}
                  activeTestId={activeTestId}
                  onClearTest={() => setActiveTestId(null)}
                  onFindingSaved={loadFindings}
                />
              </div>
            )}

            {leftTab === 'tests' && (
              <div className="pane-block">
                {moduleKey === 'exploitation' && (
                  <div className="sub-card">
                    <h4>Authentication</h4>
                    <p className="muted small">
                      Provide cookies or credentials so authenticated testing uses a
                      logged-in session.
                    </p>
                    <AuthPanel sid={sid} session={session} />
                  </div>
                )}

                <div className="sub-card">
                  <div className="row space-between">
                    <h4>Tests &amp; Findings — {moduleLabel}</h4>
                    <AddFindingForm sid={sid} phase={phase} onRecorded={loadFindings} />
                  </div>
                  <p className="muted small">
                    Each checklist test below shows the finding(s) recorded against it. These
                    are reference points, not an executable task list — drive testing yourself
                    via the assistant, the sandbox{hasBrowser ? ', and the browser explorer' : ''}.
                    Tests with no finding yet are marked “not conclusive”.
                  </p>
                  {loadingTests
                    ? <p className="muted">Loading…</p>
                    : <ReferenceList tests={tests} findings={findings} onAskAI={askAI} />}
                </div>

              </div>
            )}
          </div>
        </section>

        {/* ── RIGHT: phase AI assistant (fixed) ──────────────────────────── */}
        <aside className="workspace-right">
          <div className="workspace-right-head">
            <h3>AI Assistant</h3>
            <span className="muted small">{moduleLabel}</span>
          </div>
          <p className="muted small assistant-sub">
            Your phase copilot. It answers questions and proposes commands; it never runs
            anything. Share a PoC and it can propose a finding for you to confirm.
          </p>
          <ChatPanel
            sid={sid}
            phase={phase}
            refreshKey={chatRefresh}
            pendingQuestion={pendingQuestion}
            onQuestionSent={() => setPendingQuestion('')}
            onUseCommand={useCommand}
            onRoute={handleRoute}
            onProposeFinding={recordProposedFinding}
          />
        </aside>
      </div>
    </div>
  );
}
