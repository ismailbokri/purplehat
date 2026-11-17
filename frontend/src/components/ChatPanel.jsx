import { useCallback, useEffect, useRef, useState } from 'react';
import { clearChat, getChatHistory, sendChat } from '../api/chat.js';

const ROUTE_LABEL = {
  browser_explorer: 'Open the Browser Explorer',
};

/**
 * AI Assistant (Interface A) for a phase. Answers questions, proposes commands
 * (which the tester sends to the sandbox — this panel never runs anything), and
 * may suggest routing to another agent.
 *
 * Props:
 *   sid, phase       — session id + phase key (discovery|exploitation|report)
 *   onUseCommand     — (command) => void : hand a suggested command to the sandbox input
 *   onRoute          — (route) => void   : act on a routing suggestion
 *   onProposeFinding — (finding) => Promise : tester confirmed a proposed finding;
 *                      resolve to true to mark it recorded in the transcript
 */
export default function ChatPanel({ sid, phase, onUseCommand, onRoute, onProposeFinding, refreshKey, pendingQuestion, onQuestionSent }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [error, setError] = useState(null);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (!sid || !phase) return;
    getChatHistory(sid, phase)
      .then((rows) => setMessages(Array.isArray(rows) ? rows : []))
      .catch(() => setMessages([]));
  }, [sid, phase, refreshKey]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages.length, sending]);

  async function confirmFinding(idx, finding) {
    if (!onProposeFinding) return;
    try {
      const ok = await onProposeFinding(finding);
      if (ok) {
        setMessages((m) => m.map((msg, i) => (
          i === idx ? { ...msg, proposeFinding: null, findingRecorded: true } : msg
        )));
      }
    } catch (e) {
      setError(e.message);
    }
  }

  function dismissFinding(idx) {
    setMessages((m) => m.map((msg, i) => (
      i === idx ? { ...msg, proposeFinding: null } : msg
    )));
  }

  async function clear() {
    if (clearing || sending) return;
    setError(null);
    setClearing(true);
    try {
      await clearChat(sid, phase);
      // Wipe the panel, then reload from the backend so the agent's memory
      // (the history it is handed each turn) is refreshed to empty.
      setMessages([]);
      const rows = await getChatHistory(sid, phase);
      setMessages(Array.isArray(rows) ? rows : []);
    } catch (e) {
      setError(e.message);
    } finally {
      setClearing(false);
      setConfirmClear(false);
    }
  }

  // Core send path, shared by the input box and the "Ask AI" buttons
  // (which hand a ready-made question straight to the assistant).
  const submit = useCallback(async (text) => {
    const msg = (text || '').trim();
    if (!msg || sending) return;
    setError(null);
    setSending(true);
    setMessages((m) => [...m, { role: 'user', content: msg, suggestions: [] }]);
    try {
      const res = await sendChat(sid, phase, msg);
      setMessages((m) => [...m, {
        role: 'assistant',
        content: res?.reply || '',
        suggestions: res?.suggestions || [],
        route: res?.route || 'none',
        proposeFinding: res?.propose_finding || null,
      }]);
    } catch (e) {
      setError(e.message);
    } finally {
      setSending(false);
    }
  }, [sid, phase, sending]);

  // An "Ask AI" button elsewhere handed us a question — send it once.
  useEffect(() => {
    const q = (pendingQuestion || '').trim();
    if (!q || sending) return;
    submit(q);
    onQuestionSent && onQuestionSent();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingQuestion]);

  async function send() {
    const msg = input.trim();
    if (!msg || sending) return;
    setInput('');
    await submit(msg);
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <span className="chat-title muted small">AI Assistant · {phase}</span>
        {confirmClear ? (
          <span className="chat-clear-confirm">
            <span className="muted small">Clear this conversation?</span>
            <button
              className="btn btn-sm btn-danger"
              onClick={clear}
              disabled={clearing}
            >
              {clearing ? 'Clearing…' : 'Yes, clear'}
            </button>
            <button
              className="btn btn-sm"
              onClick={() => setConfirmClear(false)}
              disabled={clearing}
            >
              Cancel
            </button>
          </span>
        ) : (
          <button
            className="btn btn-sm"
            title="Delete the conversation context and refresh the assistant's memory"
            onClick={() => setConfirmClear(true)}
            disabled={sending || clearing || messages.length === 0}
          >
            🗑 Clear
          </button>
        )}
      </div>
      <div className="chat-messages" ref={scrollRef}>
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg chat-${m.role}`}>
            <div className="chat-bubble">
              <span className="chat-role">{m.role === 'user' ? 'You' : 'Assistant'}</span>
              <div className="chat-content">{m.content}</div>
              {(m.suggestions || []).length > 0 && (
                <div className="chat-suggestions">
                  {m.suggestions.map((s, j) => (
                    <button
                      key={j}
                      className="btn btn-sm"
                      title={s.command}
                      onClick={() => onUseCommand && onUseCommand(s.command)}
                    >
                      ▸ {s.label}
                    </button>
                  ))}
                </div>
              )}
              {m.route && m.route !== 'none' && ROUTE_LABEL[m.route] && (
                <div className="chat-route">
                  <button className="btn btn-sm" onClick={() => onRoute && onRoute(m.route)}>
                    {ROUTE_LABEL[m.route]} →
                  </button>
                </div>
              )}
              {m.proposeFinding && (
                <div className="chat-finding-proposal">
                  <div className="cfp-head">
                    <span className={`sev-dot sev-${(m.proposeFinding.severity || '').toLowerCase()}`} />
                    <strong>Proposed finding</strong>
                    <span className="muted small">{m.proposeFinding.severity}</span>
                  </div>
                  <div className="cfp-title">{m.proposeFinding.title}</div>
                  {m.proposeFinding.endpoint && (
                    <div className="muted small cfp-ep">{m.proposeFinding.endpoint}</div>
                  )}
                  <div className="cfp-actions">
                    <button className="btn btn-sm btn-primary" onClick={() => confirmFinding(i, m.proposeFinding)}>
                      Confirm &amp; record
                    </button>
                    <button className="btn btn-sm" onClick={() => dismissFinding(i)}>
                      Dismiss
                    </button>
                  </div>
                </div>
              )}
              {m.findingRecorded && (
                <div className="chat-finding-recorded muted small">✓ Finding recorded</div>
              )}
            </div>
          </div>
        ))}
        {sending && <p className="muted small">Assistant is thinking…</p>}
      </div>

      {error && <p className="error">{error}</p>}

      <div className="chat-input">
        <textarea
          rows={2}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
          }}
          placeholder=""
          disabled={sending}
        />
        <button className="btn btn-primary" onClick={send} disabled={sending || !input.trim()}>
          Send
        </button>
      </div>
    </div>
  );
}
