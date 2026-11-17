import { apiFetch } from './client.js';

export function capturePage(sid, { url, phase, notes = '' }) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/capture`, {
    method: 'POST',
    body: { url, phase, notes },
  });
}
