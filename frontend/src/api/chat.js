// Per-phase AI Assistant chat client.

import { apiFetch } from './client.js';

export function getChatHistory(sid, phase) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/phases/${encodeURIComponent(phase)}/chat`);
}

export function sendChat(sid, phase, message) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/phases/${encodeURIComponent(phase)}/chat`, {
    method: 'POST',
    body: { message },
  });
}

// Clear the stored conversation (context/memory) for a phase so the next
// message starts fresh.
export function clearChat(sid, phase) {
  return apiFetch(`/api/sessions/${encodeURIComponent(sid)}/phases/${encodeURIComponent(phase)}/chat`, {
    method: 'DELETE',
  });
}
