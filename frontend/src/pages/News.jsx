import { useEffect, useMemo, useState } from 'react';
import { listNews } from '../api/news.js';
import TopNav from '../components/TopNav.jsx';

function timeAgo(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 3600) return `${Math.max(1, Math.floor(diff / 60))} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return `${Math.floor(diff / 86400)} d ago`;
}

// Categories are derived on the client from each article's text/source, since
// the feed only stores {title, summary, source, url, affected_technologies}.
// Order matters: the first matching rule wins (most specific first).
const CATEGORIES = [
  {
    id: 'vuln',
    label: 'Vulnerabilities',
    match: /\bcve-\d{4}-\d+\b|vulnerab|\brce\b|exploit|zero[- ]day|0[- ]day|privilege escalation|buffer overflow|sql injection|\bxss\b|advisor/i,
  },
  {
    id: 'threat',
    label: 'Threats & Incidents',
    match: /ransomware|malware|breach|attack|threat actor|phishing|botnet|data leak|compromis|apt\b|espionage|\bhack/i,
  },
  {
    id: 'patch',
    label: 'Patches & Releases',
    match: /patch|update released|security update|hotfix|version \d|release\b|fixes? (a|the|multiple)|mitigat/i,
  },
  {
    id: 'research',
    label: 'Research',
    match: /research|analysis|technique|proof[- ]of[- ]concept|\bpoc\b|whitepaper|deep dive|project zero|portswigger/i,
  },
  { id: 'general', label: 'General', match: /.*/ },
];

function categoryOf(article) {
  const hay = [
    article.title || '',
    article.summary || '',
    article.source || '',
    (article.affected_technologies || []).join(' '),
  ].join(' ');
  return (CATEGORIES.find((c) => c.match.test(hay)) || CATEGORIES[CATEGORIES.length - 1]).id;
}

// Patterns that mark text worth emphasising even without an active search.
const KEY_TERMS = /(CVE-\d{4}-\d+|zero[- ]day|0[- ]day|critical|actively exploited|remote code execution|\bRCE\b|unauthenticated)/gi;

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Render text with important fragments wrapped in <strong>. A non-empty search
// query is highlighted as well as the standing key terms.
function Highlighted({ text, query }) {
  if (!text) return null;
  const parts = [KEY_TERMS.source];
  const q = query.trim();
  if (q) parts.push(escapeRegExp(q));
  const splitRe = new RegExp(`(${parts.join('|')})`, 'gi');
  // A separate, non-global regex for the per-segment match test, so stateful
  // lastIndex from a global regex can't cause matches to be skipped.
  const testRe = new RegExp(`^(?:${parts.join('|')})$`, 'i');
  const segments = text.split(splitRe);
  return (
    <>
      {segments.map((seg, i) =>
        seg && testRe.test(seg) ? (
          <strong key={i} className="news-mark">{seg}</strong>
        ) : (
          <span key={i}>{seg}</span>
        )
      )}
    </>
  );
}

export default function News() {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState('');
  const [activeCat, setActiveCat] = useState('all');

  useEffect(() => {
    listNews(60)
      .then((rows) => setArticles(Array.isArray(rows) ? rows : []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Tag each article with its derived category once.
  const tagged = useMemo(
    () => articles.map((a) => ({ ...a, _category: categoryOf(a) })),
    [articles]
  );

  // Counts per category for the filter pills (based on the full set).
  const counts = useMemo(() => {
    const c = { all: tagged.length };
    for (const cat of CATEGORIES) c[cat.id] = 0;
    for (const a of tagged) c[a._category] = (c[a._category] || 0) + 1;
    return c;
  }, [tagged]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return tagged.filter((a) => {
      if (activeCat !== 'all' && a._category !== activeCat) return false;
      if (!q) return true;
      const hay = [
        a.title || '',
        a.summary || '',
        a.source || '',
        (a.affected_technologies || []).join(' '),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [tagged, query, activeCat]);

  const labelOf = (id) => CATEGORIES.find((c) => c.id === id)?.label || id;

  return (
    <>
      <TopNav />
      <div className="page">
        <header className="page-header">
          <h1 className="glitch" data-text="Threat Intelligence">Threat Intelligence</h1>
          <p className="muted">Curated cybersecurity news — vulnerabilities, threats, incidents and research.</p>
        </header>

        {!loading && !error && articles.length > 0 && (
          <div className="news-controls">
            <div className="news-search">
              <input
                type="search"
                className="news-search-input"
                placeholder="Search by title, source, technology…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Search news articles"
              />
              {query && (
                <button
                  type="button"
                  className="news-search-clear"
                  onClick={() => setQuery('')}
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>
            <div className="news-cats" role="tablist" aria-label="Filter by category">
              <button
                type="button"
                className={`news-cat${activeCat === 'all' ? ' is-active' : ''}`}
                aria-pressed={activeCat === 'all'}
                onClick={() => setActiveCat('all')}
              >
                All <span className="news-cat-count">{counts.all}</span>
              </button>
              {CATEGORIES.filter((c) => counts[c.id] > 0).map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={`news-cat${activeCat === c.id ? ' is-active' : ''}`}
                  aria-pressed={activeCat === c.id}
                  onClick={() => setActiveCat(c.id)}
                >
                  {c.label} <span className="news-cat-count">{counts[c.id]}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {loading && <p className="muted">Loading…</p>}
        {error && <p className="error">{error}</p>}
        {!loading && articles.length === 0 && (
          <p className="muted">No news yet. The feed refreshes automatically each week.</p>
        )}
        {!loading && !error && articles.length > 0 && filtered.length === 0 && (
          <p className="muted">
            No articles match your search{activeCat !== 'all' ? ` in ${labelOf(activeCat)}` : ''}.
          </p>
        )}

        <div className="news-grid">
          {filtered.map((a, i) => (
            <article key={i} className="news-card">
              <div className="news-meta">
                <span className="news-source">{a.source}</span>
                <span className={`news-cat-badge cat-${a._category}`}>{labelOf(a._category)}</span>
                {a.published_at && <span className="news-time">{timeAgo(a.published_at)}</span>}
              </div>
              <div className="news-card-body">
                <h2 className="news-title">
                  <a href={a.url} target="_blank" rel="noopener noreferrer">
                    <Highlighted text={a.title} query={query} />
                  </a>
                </h2>
                <p className="news-summary">
                  <Highlighted text={a.summary} query={query} />
                </p>
                {(a.affected_technologies || []).length > 0 && (
                  <div className="news-tech">
                    {a.affected_technologies.slice(0, 6).map((t, j) => (
                      <span key={j} className="news-tech-tag">{t}</span>
                    ))}
                  </div>
                )}
              </div>
            </article>
          ))}
        </div>
      </div>
    </>
  );
}
