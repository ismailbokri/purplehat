import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { listSessions } from '../api/sessions.js';
import { listNews } from '../api/news.js';
import TopNav from '../components/TopNav.jsx';

const PHASES = [
  { key: 'discovery', cls: 'phase-discovery', name: 'Discovery & Reconnaissance',
    desc: 'Map the target: ports, services, technologies, endpoints.' },
  { key: 'exploitation', cls: 'phase-exploitation', name: 'Exploitation',
    desc: 'Test the whole surface — before and after login: headers, access control, injection, business logic.' },
  { key: 'reporting', cls: 'phase-reporting', name: 'Reporting',
    desc: 'Consolidate findings into a report.' },
];

export default function Overview() {
  const [sessions, setSessions] = useState([]);
  const [news, setNews] = useState([]);

  useEffect(() => {
    listSessions().then((r) => setSessions(Array.isArray(r) ? r.slice(0, 5) : [])).catch(() => {});
    listNews(4).then((r) => setNews(Array.isArray(r) ? r : [])).catch(() => {});
  }, []);

  return (
    <>
      <TopNav />
      <div className="page">
        <header className="page-header">
          <h1 className="glitch" data-text="Assessment Platform">Assessment Platform</h1>
          <Link to="/sessions/new" className="btn btn-primary">+ New assessment</Link>
        </header>

        <section className="overview-phases">
          {PHASES.map((p) => (
            <div key={p.key} className={`phase-tile phase-colored ${p.cls}`}>
              <span className="phase-badge">{p.name}</span>
              <p className="muted small">{p.desc}</p>
            </div>
          ))}
        </section>

        <div className="overview-cols">
          <section className="card">
            <div className="row space-between">
              <h3>Active assessments</h3>
              <Link to="/sessions" className="btn btn-sm">View all</Link>
            </div>
            {sessions.length === 0 ? (
              <p className="muted">No assessments yet. <Link to="/sessions/new">Create one</Link>.</p>
            ) : (
              <ul className="overview-list">
                {sessions.map((s) => (
                  <li key={s.session_id}>
                    <Link to={`/sessions/${s.session_id}`}>{s.target}</Link>
                    <span className={`tag tag-${s.status}`}>{s.status}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="row space-between">
              <h3>Threat intelligence</h3>
              <Link to="/news" className="btn btn-sm">All news</Link>
            </div>
            {news.length === 0 ? (
              <p className="muted">No news yet — the feed refreshes weekly.</p>
            ) : (
              <ul className="overview-list">
                {news.map((a, i) => (
                  <li key={i} className="overview-news">
                    <a href={a.url} target="_blank" rel="noopener noreferrer">{a.title}</a>
                    <span className="muted small">{a.source}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </>
  );
}
