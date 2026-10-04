import { useId, useState, type FormEvent } from 'react';

import { api, toApiError, type FilterTarget, type RetentionSettings } from '../api/client';
import { SeverityBadge } from '../components/Badges';
import { TableScroll } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { ErrorState, HeuristicNotice, Loading } from '../components/States';
import { useResource } from '../lib/useResource';
import { useTitle } from '../lib/useTitle';

function RetentionForm({ settings }: { settings: RetentionSettings }) {
  const ttlId = useId();
  const packetsId = useId();
  const [ttl, setTtl] = useState(String(settings.session_ttl_days));
  const [packets, setPackets] = useState(String(settings.max_packets_stored));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const ttlValue = Number(ttl);
  const packetsValue = Number(packets);
  const ttlError =
    Number.isInteger(ttlValue) && ttlValue >= 1 && ttlValue <= 3650 ? null : 'Enter a whole number from 1 to 3650.';
  const packetsError =
    Number.isInteger(packetsValue) && packetsValue >= 0 && packetsValue <= 1_000_000
      ? null
      : 'Enter a whole number from 0 to 1000000.';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (ttlError || packetsError) return;
    setBusy(true);
    setMessage(null);
    try {
      await api.setRetention({ session_ttl_days: ttlValue, max_packets_stored: packetsValue });
      setMessage({ ok: true, text: 'Saved. The settings apply to new imports.' });
    } catch (caught) {
      setMessage({ ok: false, text: toApiError(caught).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} noValidate>
      <h2>Retention</h2>
      <p className="muted">Changes apply to new imports; existing captures keep their expiry.</p>
      <div className="field">
        <label htmlFor={ttlId}>Keep captures for (days)</label>
        <input
          id={ttlId}
          type="number"
          inputMode="numeric"
          min={1}
          max={3650}
          value={ttl}
          onChange={(event) => setTtl(event.target.value)}
          aria-invalid={ttlError ? true : undefined}
          aria-describedby={ttlError ? `${ttlId}-error` : undefined}
        />
        {ttlError && (
          <span id={`${ttlId}-error`} className="error-text">
            {ttlError}
          </span>
        )}
      </div>
      <div className="field">
        <label htmlFor={packetsId}>Packets stored per capture</label>
        <input
          id={packetsId}
          type="number"
          inputMode="numeric"
          min={0}
          max={1_000_000}
          value={packets}
          onChange={(event) => setPackets(event.target.value)}
          aria-invalid={packetsError ? true : undefined}
          aria-describedby={packetsError ? `${packetsId}-error` : undefined}
        />
        {packetsError && (
          <span id={`${packetsId}-error`} className="error-text">
            {packetsError}
          </span>
        )}
      </div>
      <button type="submit" disabled={busy || Boolean(ttlError || packetsError)}>
        {busy ? 'Saving…' : 'Save retention'}
      </button>
      <div role="status" aria-live="polite">
        {message && <span className={message.ok ? 'ok-text' : 'error-text'}>{message.text}</span>}
      </div>
    </form>
  );
}

function FieldList({ target }: { target: FilterTarget }) {
  const fields = useResource(`fields:${target}`, (signal) => api.filterFields(target, signal));
  if (fields.error) return <ErrorState error={fields.error} onRetry={fields.reload} />;
  if (!fields.data) return <Loading />;
  return (
    <TableScroll label={`${target} filter fields`}>
      <table className="dense">
        <thead>
          <tr>
            <th scope="col">Field</th>
            <th scope="col">Type</th>
            <th scope="col">Operators</th>
            <th scope="col">Meaning</th>
          </tr>
        </thead>
        <tbody>
          {fields.data.map((field) => (
            <tr key={field.name}>
              <th scope="row">
                <code>{field.name}</code>
              </th>
              <td>
                {field.type}
                {field.values ? `: ${field.values.join(', ')}` : ''}
              </td>
              <td>{field.operators.join(' ')}</td>
              <td>{field.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

export function SettingsPage() {
  useTitle('Settings');
  const retention = useResource('retention', (signal) => api.retention(signal));
  const rules = useResource('rules', (signal) => api.rules(signal));

  return (
    <>
      <PageHeader title="Settings" />
      {retention.error ? (
        <ErrorState error={retention.error} onRetry={retention.reload} />
      ) : retention.data ? (
        <RetentionForm settings={retention.data} />
      ) : (
        <Loading />
      )}
      <section aria-labelledby="rules-heading">
        <h2 id="rules-heading">Detection rules</h2>
        <HeuristicNotice />
        <p className="muted">
          Thresholds are set on the server (<code>FLOWSENTINEL_DETECTION_CONFIG</code>).
        </p>
        {rules.error ? (
          <ErrorState error={rules.error} onRetry={rules.reload} />
        ) : !rules.data ? (
          <Loading />
        ) : (
          <TableScroll label="Detection rules">
            <table>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Looks for</th>
                  <th scope="col">Often caused by</th>
                </tr>
              </thead>
              <tbody>
                {rules.data.map((rule) => (
                  <tr key={rule.id}>
                    <th scope="row">
                      {rule.name}
                      <br />
                      <code className="muted">{rule.id}</code>
                    </th>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>{rule.description}</td>
                    <td>{rule.likely_false_positives.join('; ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
      </section>
      <section aria-labelledby="fields-heading">
        <h2 id="fields-heading">Display filter fields</h2>
        <details>
          <summary>Packet fields</summary>
          <FieldList target="packets" />
        </details>
        <details>
          <summary>Flow fields</summary>
          <FieldList target="flows" />
        </details>
      </section>
    </>
  );
}
