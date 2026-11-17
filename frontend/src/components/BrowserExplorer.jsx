import { useEffect, useRef, useState } from 'react';
import { capturePage } from '../api/capture.js';
import { getToken } from '../api/client.js';

/**
 * Integrated browser + explicit Capture. The tester browses the target in an
 * iframe; clicking Capture sends the current URL (+ optional notes) to the
 * backend, which grabs DOM + screenshot and feeds it to the phase Conversation
 * Agent. Capture is user-triggered — nothing happens on navigation.
 *
 * The iframe does NOT point straight at the target: many apps (e.g. Juice Shop)
 * send X-Frame-Options / CSP that forbid embedding. Instead it loads through the
 * session reverse-proxy (/api/sessions/:sid/proxy), which strips those headers
 * and rewrites the page so it renders same-origin. The address bar still shows
 * the real target URL; proxying is transparent.
 *
 * Props: sid, phase, targetUrl, onCaptured(result)
 */

// Wrap an absolute target URL so the iframe loads it through the session proxy.
function proxied(sid, rawUrl) {
  const token = getToken();
  const u = rawUrl.trim();
  if (!u) return '';
  const q = new URLSearchParams();
  if (token) q.set('_jwt', token);
  q.set('url', u);
  return `/api/sessions/${encodeURIComponent(sid)}/proxy?${q.toString()}`;
}

// Normalize what the tester typed into an absolute http(s) URL.
function normalizeUrl(raw) {
  const u = (raw || '').trim();
  if (!u) return '';
  return /^https?:\/\//i.test(u) ? u : `http://${u}`;
}

export default function BrowserExplorer({ sid, phase, targetUrl, onCaptured }) {
  const seed = targetUrl || '';
  const [url, setUrl] = useState(seed);
  const [frameSrc, setFrameSrc] = useState(seed ? proxied(sid, normalizeUrl(seed)) : '');
  const [notes, setNotes] = useState('');
  const [capturing, setCapturing] = useState(false);
  const [error, setError] = useState(null);
  const [preview, setPreview] = useState(null);
  const frameRef = useRef(null);

  // Follow navigation inside the iframe. The proxy injects a script into every
  // page that posts the REAL target URL (the iframe's own location is a proxy
  // URL on another origin, unreadable from here). Keeping the address bar in
  // sync means Capture and ↗ Tab act on the page the tester is actually on.
  useEffect(() => {
    function onMessage(e) {
      if (e.source !== frameRef.current?.contentWindow) return;
      const d = e.data;
      if (d && d.type === 'pentest-proxy-nav' && typeof d.url === 'string'
          && /^https?:\/\//i.test(d.url)) {
        setUrl(d.url);
      }
    }
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);

  function load() {
    const abs = normalizeUrl(url);
    if (!abs) return;
    setUrl(abs);
    setFrameSrc(proxied(sid, abs));
  }

  async function doCapture() {
    const abs = normalizeUrl(url);
    if (!abs) return;
    setCapturing(true);
    setError(null);
    try {
      // Capture hits the real target server-side (no iframe limit), so send the
      // actual URL, not the proxied one.
      const res = await capturePage(sid, { url: abs, phase, notes });
      setPreview(res?.capture || null);
      if (onCaptured) onCaptured(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setCapturing(false);
    }
  }

  return (
    <div className="browser-explorer">
      <div className="be-bar">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); load(); } }}
          placeholder="http://localhost:8082  or  http://localhost:8083/WebGoat/login"
        />
        <button className="btn" onClick={load}>Load</button>
        <button className="btn btn-primary" onClick={doCapture} disabled={capturing || !url.trim()}>
          {capturing ? 'Capturing…' : 'Capture'}
        </button>
        {frameSrc && (
          <a className="btn" href={normalizeUrl(url)} target="_blank" rel="noreferrer" title="Open the real target in a new tab">
            ↗ Tab
          </a>
        )}
      </div>
      <input
        type="text"
        className="be-notes"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="What do you want to investigate on this page? (optional, sent to the assistant)"
      />
      {error && <p className="error">{error}</p>}

      <div className="be-frame-wrap">
        {frameSrc ? (
          <iframe ref={frameRef} title="target" className="be-frame" src={frameSrc} />
        ) : (
          <p className="muted small">Enter a target URL and press Load to browse it here.</p>
        )}
      </div>
      <p className="muted small">
        Pages load through the session proxy so framing restrictions don't block the view.
        If something renders oddly, use <strong>↗ Tab</strong> for the real site or
        <strong> Capture</strong> for a server-side screenshot the assistant can read.
      </p>

      {preview?.screenshot_b64 && (
        <div className="be-preview">
          <span className="muted small">
            Last capture — {preview.title || 'untitled'} · {preview.url}
          </span>
          <img src={`data:image/jpeg;base64,${preview.screenshot_b64}`} alt="capture" />
        </div>
      )}
    </div>
  );
}
