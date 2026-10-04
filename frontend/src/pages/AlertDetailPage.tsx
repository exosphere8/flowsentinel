import { useId, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router';

import { ALERT_STATUSES, api, toApiError, type AlertRow, type AlertStatus } from '../api/client';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { KeyValueList } from '../components/Details';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { ErrorState, Loading } from '../components/States';
import { useCan } from '../lib/auth';
import { formatEndpoint, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

export function AlertDetailPage() {
  const params = useParams();
  const id = idParam(params.id);
  const alertId = idParam(params.alertId);
  if (id === null || alertId === null) return <NotFoundPage />;
  return <AlertDetail id={id} alertId={alertId} />;
}

function evidenceRows(evidence: Record<string, unknown>[]): [string, string][] {
  return evidence
    .map((item) => [item.name, item.value])
    .filter((pair): pair is [string, string] => typeof pair[0] === 'string' && typeof pair[1] === 'string');
}

function Triage({ id, alert, onSaved }: { id: number; alert: AlertRow; onSaved: (alert: AlertRow) => void }) {
  const selectId = useId();
  const [status, setStatus] = useState(alert.status);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const updated = await api.setAlertStatus(id, alert.alert_id, status as AlertStatus);
      onSaved(updated);
      setMessage({ ok: true, text: `Status saved: ${humanize(updated.status)}.` });
    } catch (caught) {
      setMessage({ ok: false, text: toApiError(caught).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} aria-labelledby={`${selectId}-heading`}>
      <h2 id={`${selectId}-heading`}>Triage</h2>
      <p>
        Current status: <StatusBadge status={alert.status} />
        {alert.status_changed_at && <> (changed {formatTime(alert.status_changed_at)})</>}
      </p>
      <div className="filter-row">
        <label htmlFor={selectId}>New status</label>
        <select id={selectId} value={status} onChange={(event) => setStatus(event.target.value)}>
          {ALERT_STATUSES.map((value) => (
            <option key={value} value={value}>
              {humanize(value)}
            </option>
          ))}
        </select>
        <button type="submit" disabled={busy || status === alert.status}>
          {busy ? 'Saving…' : 'Save status'}
        </button>
      </div>
      <div role="status" aria-live="polite">
        {message && <span className={message.ok ? 'ok-text' : 'error-text'}>{message.text}</span>}
      </div>
    </form>
  );
}

function AlertDetail({ id, alertId }: { id: number; alertId: number }) {
  const loaded = useResource(`alert:${id}:${alertId}`, (signal) => api.getAlert(id, alertId, signal));
  const [saved, setSaved] = useState<AlertRow | null>(null);
  const canTriage = useCan('analyst');
  const alert = saved?.alert_id === alertId ? saved : loaded.data;
  useTitle(alert ? `${alert.rule_name} (alert ${alertId})` : `Alert ${alertId}`);
  const crumbs = [
    { label: 'Captures', to: '/captures' },
    { label: `Capture ${id}`, to: `/captures/${id}` },
    { label: 'Alerts', to: `/captures/${id}/alerts` },
    { label: `Alert ${alertId}` },
  ];
  if (loaded.error) {
    return (
      <>
        <PageHeader title={`Alert ${alertId}`} crumbs={crumbs} />
        <ErrorState error={loaded.error} onRetry={loaded.reload} />
      </>
    );
  }
  if (!alert) return <Loading />;

  return (
    <>
      <PageHeader title={alert.rule_name} crumbs={crumbs}>
        <p className="lead">
          <SeverityBadge severity={alert.severity} /> severity, {alert.confidence} confidence ·{' '}
          <code>{alert.rule_id}</code> · alert {alert.alert_id}
        </p>
      </PageHeader>
      <CaptureTabs id={id} />
      <p className="notice">
        <strong>{alert.nature}.</strong>
      </p>
      <div className="columns">
        <section className="card" aria-labelledby="why-heading">
          <h2 id="why-heading">What was observed</h2>
          <p>{alert.explanation}</p>
          <KeyValueList
            items={[
              ['First seen', formatTime(alert.first_seen)],
              ['Last seen', formatTime(alert.last_seen)],
              ['Source', alert.source ?? '–'],
              ['Destination', formatEndpoint(alert.destination, alert.destination_port)],
            ]}
          />
          <h3 id="evidence-heading">Evidence</h3>
          <table aria-labelledby="evidence-heading">
            <thead>
              <tr>
                <th scope="col">Measurement</th>
                <th scope="col">Value</th>
              </tr>
            </thead>
            <tbody>
              {evidenceRows(alert.evidence).map(([name, value]) => (
                <tr key={name}>
                  <th scope="row">{humanize(name)}</th>
                  <td>{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <section className="card" aria-labelledby="doubt-heading">
          <h2 id="doubt-heading">Why it may be wrong</h2>
          <p>{alert.uncertainty}</p>
          <h3>Benign activity that looks the same</h3>
          <ul>
            {alert.likely_false_positives.map((cause) => (
              <li key={cause}>{cause}</li>
            ))}
          </ul>
          {alert.mitre_attack.length > 0 && (
            <>
              <h3>MITRE ATT&amp;CK context</h3>
              <p className="muted">Techniques this pattern can relate to; not a claim that they were used.</p>
              <ul>
                {alert.mitre_attack.map((technique) => (
                  <li key={technique}>{technique}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
      <section aria-labelledby="cited-heading">
        <h2 id="cited-heading">Cited traffic</h2>
        {alert.related_flow_ids.length > 0 && (
          <p>
            Flows:{' '}
            {alert.related_flow_ids.map((flowId, i) => (
              <span key={flowId}>
                {i > 0 && ', '}
                <Link to={`/captures/${id}/flows/${flowId}`}>{flowId}</Link>
              </span>
            ))}
          </p>
        )}
        {alert.related_packet_indexes.length > 0 && (
          <p>
            Packets:{' '}
            {alert.related_packet_indexes.map((index, i) => (
              <span key={index}>
                {i > 0 && ', '}
                <Link to={`/captures/${id}/packets/${index}`}>{index}</Link>
              </span>
            ))}
          </p>
        )}
        <p className="muted">At most 50 flows and 50 packets are cited, starting with the first ones that matched.</p>
      </section>
      {canTriage ? (
        <Triage key={alert.alert_id} id={id} alert={alert} onSaved={setSaved} />
      ) : (
        <section className="card" aria-labelledby="status-heading">
          <h2 id="status-heading">Triage</h2>
          <p>
            Status: <StatusBadge status={alert.status} />. Analysts and admins can change it.
          </p>
        </section>
      )}
    </>
  );
}
