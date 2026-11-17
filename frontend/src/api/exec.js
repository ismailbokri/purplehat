// Execution sandbox client. Command output streams over the session WebSocket
// (sandbox_* events handled in SessionLayout's reducer); these calls only
// trigger execution and inspect generated files.

import { apiFetch } from './client.js';

// `context` is optional checklist context ({ phase, test_description,
// vuln_attendue, resultat_attendu }) that sharpens the Finding Agent's verdict.
// The analysis always runs and always returns a verdict even without it.
export function execCommand(sid, command, context = {}) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/exec`, {
    method: 'POST',
    body: { command, ...context },
  });
}

export function listSandboxFiles(sid) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/files`);
}

export function readSandboxFile(sid, name) {
  const qs = new URLSearchParams({ name }).toString();
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/files/content?${qs}`);
}
