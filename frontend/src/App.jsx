import { Navigate, Route, Routes } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Checklist from './pages/Checklist';
import SessionList from './pages/SessionList';
import SessionSetup from './pages/SessionSetup';
import SessionLayout from './pages/SessionLayout';
import ModulesOverview from './pages/ModulesOverview';
import ModuleRunner from './pages/ModuleRunner';
import ReportModule from './pages/ReportModule';
import FindingsView from './pages/FindingsView';
import EndpointsView from './pages/EndpointsView';
import ScopeView from './pages/ScopeView';
import News from './pages/News';
import Overview from './pages/Overview';
import Home from './pages/Home';
import ProtectedRoute from './components/ProtectedRoute';

function Guarded({ children }) {
  return <ProtectedRoute>{children}</ProtectedRoute>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route path="/sessions" element={<Guarded><SessionList /></Guarded>} />
      <Route path="/sessions/new" element={<Guarded><SessionSetup /></Guarded>} />

      <Route path="/sessions/:sid" element={<Guarded><SessionLayout /></Guarded>}>
        <Route index element={<ModulesOverview />} />
        <Route path="modules/:moduleKey" element={<ModuleRunner />} />
        <Route path="report" element={<ReportModule />} />
        <Route path="findings" element={<FindingsView />} />
        <Route path="endpoints" element={<EndpointsView />} />
        <Route path="scope" element={<ScopeView />} />
      </Route>

      <Route path="/checklist" element={<Guarded><Checklist /></Guarded>} />
      <Route path="/news" element={<Guarded><News /></Guarded>} />
      <Route path="/overview" element={<Guarded><Overview /></Guarded>} />

      {/* Public landing page (platform info + inline login). */}
      <Route path="/" element={<Home />} />
      <Route path="/dashboard" element={<Navigate to="/overview" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
