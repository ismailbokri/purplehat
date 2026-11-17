import { useOutletContext } from 'react-router-dom';
import ScopeEditor from '../components/ScopeEditor.jsx';

export default function ScopeView() {
  const { sid } = useOutletContext();
  return (
    <div className="scope-view">
      <section className="card">
        <h3>Assessment scope</h3>
        <ScopeEditor sid={sid} />
      </section>
    </div>
  );
}
