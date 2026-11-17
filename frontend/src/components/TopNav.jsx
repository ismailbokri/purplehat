import { Link, NavLink } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import ThemeToggle from './ThemeToggle.jsx';

export default function TopNav() {
  const { user, logout } = useAuth();
  const isAdmin = user?.role === 'admin';
  return (
    <header className="brand-bar">
      <div className="row">
        <Link to="/sessions" className="brand glitch" data-text="PurpleHat">PurpleHat</Link>
        <nav>
          <NavLink to="/sessions">Sessions</NavLink>
          <NavLink to="/news">News</NavLink>
          <NavLink to="/checklist">Checklist</NavLink>
        </nav>
      </div>
      <div className="row">
        {user && (
          <span className="muted small">
            {user.email}
            {isAdmin && <span className="header-user-role"> · admin</span>}
          </span>
        )}
        <ThemeToggle />
        <button className="btn" onClick={logout}>Log out</button>
      </div>
    </header>
  );
}
