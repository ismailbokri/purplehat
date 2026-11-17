// Split a free-form string into a deduplicated list of endpoints.
//
// Accepts any of these separators between endpoints:
//   - whitespace (space, tab, newline)
//   - comma
//   - semicolon
//
// Empties and pure-whitespace tokens are filtered out. Order is preserved
// based on first appearance.
export function parseEndpoints(raw) {
  if (!raw) return [];
  const tokens = String(raw)
    .split(/[\s,;]+/g)
    .map((t) => t.trim())
    .filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const t of tokens) {
    if (!seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}
