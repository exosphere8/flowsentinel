import { Link, useParams } from 'react-router';

import { ALERT_STATUSES, api, SEVERITIES, type AlertStatus, type Severity } from '../api/client';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { TableScroll } from '../components/Details';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { Pagination } from '../components/Pagination';
import { EmptyState, ErrorState, HeuristicNotice, Loading } from '../components/States';
import { formatEndpoint, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam, useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

const PER_PAGE = 50;
const SORTS = [
  ['severity', 'Most severe first'],
  ['time', 'Earliest first'],
  ['id', 'Alert ID'],
] as const;

export function AlertsPage() {
  const id = idParam(useParams().id);
  if (id === null) return <NotFoundPage />;
  return <Alerts id={id} />;
}

function oneOf<T extends string>(value: string, allowed: readonly T[]): T | undefined {
  return (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

function Alerts({ id }: { id: number }) {
  useTitle('Alerts');
  const search = useSearchState();
  const page = search.number('page', 1);
  const sort = search.text('sort', 'severity');
  const severity = oneOf<Severity>(search.text('severity'), SEVERITIES);
  const status = oneOf<AlertStatus>(search.text('status'), ALERT_STATUSES);
  const rule = search.text('rule') || undefined;
  const rules = useResource('rules', (signal) => api.rules(signal));
  const alerts = useResource(
    `alerts:${id}:${page}:${sort}:${severity}:${status}:${rule}`,
    (signal) => api.listAlerts(id, { page, per_page: PER_PAGE, sort, severity, status, rule }, signal),
  );
  const shown = alerts.data ?? alerts.previous;
  const filtered = Boolean(severity || status || rule);

  return (
    <>
      <PageHeader
        title="Alerts"
        crumbs={[
          { label: 'Captures', to: '/captures' },
          { label: `Capture ${id}`, to: `/captures/${id}` },
          { label: 'Alerts' },
        ]}
      />
      <CaptureTabs id={id} />
      <HeuristicNotice />
      <form className="toolbar filters" onSubmit={(event) => event.preventDefault()}>
        <label>
          Severity{' '}
          <select value={severity ?? ''} onChange={(event) => search.update({ severity: event.target.value })}>
            <option value="">Any</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status{' '}
          <select value={status ?? ''} onChange={(event) => search.update({ status: event.target.value })}>
            <option value="">Any</option>
            {ALERT_STATUSES.map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Rule{' '}
          <select value={rule ?? ''} onChange={(event) => search.update({ rule: event.target.value })}>
            <option value="">Any</option>
            {(rules.data ?? []).map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.id})
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort{' '}
          <select value={sort} onChange={(event) => search.update({ sort: event.target.value })}>
            {SORTS.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </form>
      {alerts.error ? (
        <ErrorState error={alerts.error} onRetry={alerts.reload} />
      ) : !shown ? (
        <Loading />
      ) : shown.total === 0 ? (
        <EmptyState title={filtered ? 'No alerts match' : 'No alerts'}>
          {!filtered && (
            <p className="muted">
              No rule matched this capture. That does not mean the traffic is safe: rules only
              recognize a few well-known patterns.
            </p>
          )}
        </EmptyState>
      ) : (
        <div aria-busy={alerts.loading}>
          <TableScroll label="Alerts">
            <table>
              <thead>
                <tr>
                  <th scope="col" className="num">ID</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Indicator</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">First seen</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {shown.items.map((alert) => (
                  <tr key={alert.alert_id}>
                    <th scope="row" className="num">
                      <Link to={`/captures/${id}/alerts/${alert.alert_id}`}>{alert.alert_id}</Link>
                    </th>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <Link to={`/captures/${id}/alerts/${alert.alert_id}`}>{alert.rule_name}</Link>{' '}
                      <code className="muted">{alert.rule_id}</code>
                    </td>
                    <td>{alert.confidence}</td>
                    <td>{alert.source ?? '–'}</td>
                    <td>{formatEndpoint(alert.destination, alert.destination_port)}</td>
                    <td>{formatTime(alert.first_seen)}</td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <Pagination
            label="Alerts"
            page={page}
            perPage={PER_PAGE}
            total={shown.total}
            onPage={(next) => search.update({ page: next })}
          />
        </div>
      )}
    </>
  );
}
