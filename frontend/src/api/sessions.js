// HTTP + WebSocket client for the modular /sessions backend.

import { apiFetch, getToken } from './client.js';

// Two active assessment phases. The former "preauth" and "postauth" modules
// were merged into a single "Exploitation" phase (their checklist items were
// re-tagged to the "Exploitation" category in the DB).
export const MODULE_KEYS = [
  'discovery',
  'exploitation',
];

export const MODULE_LABEL = {
  discovery:    'Discovery',
  exploitation: 'Exploitation',
};

// Each module belongs to one assessment phase, which drives its signature colour
// in the UI (see .phase-* classes in index.css).
export const MODULE_PHASE_CLASS = {
  discovery:    'phase-discovery',
  exploitation: 'phase-exploitation',
};

// These values are the category identifiers stored in the database. The
// checklist was migrated to English (scripts/translate_checklist_db_to_english.py),
// so these now match the English category column used for filtering.
export const MODULE_CATEGORY = {
  discovery:    'Discovery',
  exploitation: 'Exploitation',
};

// Pretty display labels for the category identifiers. Tolerates the old
// pre-merge / French identifiers too, so a not-yet-migrated DB still renders.
const CATEGORY_LABELS = {
  'Discovery':              'Discovery',
  'Exploitation':           'Exploitation',
  // Legacy categories (pre-merge) still render, and all map under Exploitation.
  'Pre-authentication':     'Pre-Authentication',
  'Post-authentication':    'Post-Authentication',
  'Pre-authentication tests to run post-authentication':
                            'Pre-Authentication tests (run post-auth)',
  'Business logic':         'Business Logic',
  // Legacy French identifiers (pre-migration).
  'Découverte':             'Discovery',
  'Pré-authentification':   'Pre-Authentication',
  'Post-authentification':  'Post-Authentication',
};

export function categoryLabel(category) {
  if (!category) return '';
  return CATEGORY_LABELS[category] || category;
}

// Capability flags: which workspace tabs a module exposes.
// Browser Explorer is relevant only after recon, so it appears in the
// Exploitation phase, not in Discovery.
export const MODULE_HAS_BROWSER = {
  discovery:    false,
  exploitation: true,
};

export function listSessions() {
  return apiFetch('/api/sessions');
}

export function createSession({ target, port, custom_endpoints = [], scope = {} }) {
  return apiFetch('/api/sessions', {
    method: 'POST',
    body: { target, port, custom_endpoints, scope },
  });
}

export function getScope(sid) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/scope`);
}

export function patchScope(sid, scope) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/scope`, {
    method: 'PATCH',
    body: scope,
  });
}

export function getSession(sid) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}`);
}

export function deleteSession(sid) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}`, { method: 'DELETE' });
}

export function patchEndpoints(sid, { add = [], remove = [] }) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/endpoints`, {
    method: 'PATCH',
    body: { add, remove },
  });
}

export function patchAuth(sid, payload) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/auth`, {
    method: 'PATCH',
    body: payload,
  });
}

export function listFindings(sid, { moduleKey, testStatus } = {}) {
  const qs = new URLSearchParams();
  if (moduleKey)  qs.set('module_key', moduleKey);
  if (testStatus) qs.set('test_status', testStatus);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/findings${suffix}`);
}

export function createReport(sid) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/report`, { method: 'POST' });
}

// Record one tester-confirmed finding (manual form, saved exploit, or a chat
// agent proposal the tester confirmed). source ∈ {manual, chat, exploit_gen}.
export function createFinding(sid, finding) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/findings`, {
    method: 'POST',
    body: finding,
  });
}

export function reportPdfUrl(sid) {
  const token = getToken();
  // FileResponse downloads must include the token (the SPA can't read the body
  // directly via apiFetch — we hand the URL to <a download> or window.open).
  const t = token ? `?_jwt=${encodeURIComponent(token)}` : '';
  return `/api/sessions/${encodeURIComponent(sid)}/report.pdf${t}`;
}

export function openSessionSocket(sid, onEvent) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/api/sessions/${encodeURIComponent(sid)}/ws`;
  const ws = new WebSocket(url);
  ws.addEventListener('message', (e) => {
    try {
      const ev = JSON.parse(e.data);
      onEvent(ev);
    } catch {
      // ignore malformed payloads
    }
  });
  return ws;
}
