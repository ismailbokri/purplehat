import { apiFetch } from './client.js';

export function listNews(limit = 50) {
  return apiFetch(`/api/news?limit=${encodeURIComponent(limit)}`);
}

export function refreshNews() {
  return apiFetch('/api/news/refresh', { method: 'POST' });
}
