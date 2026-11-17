import { apiFetch } from './client';

export const listTests       = () => apiFetch('/checklist');
export const listCategories  = () => apiFetch('/checklist/categories');
export const createTest      = (data) => apiFetch('/checklist', { method: 'POST', body: data });
export const updateTest      = (id, data) => apiFetch(`/checklist/${id}`, { method: 'PUT', body: data });
export const deleteTest      = (id) => apiFetch(`/checklist/${id}`, { method: 'DELETE' });
