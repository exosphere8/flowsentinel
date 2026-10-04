import { useId } from 'react';

import { api, type AuditOutcome } from '../api/client';
import { TableScroll } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { Pagination, PastEnd } from '../components/Pagination';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatTime } from '../lib/format';
import { useResource } from '../lib/useResource';
import { useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';

const PER_PAGE = 50;

/** The actions the server records, for the filter. */
const ACTIONS = [
  'auth.login',
  'auth.logout',
  'auth.password_change',
  'access.denied',
  'user.bootstrap',
  'user.create',
  'user.update',
  'user.delete',
  'capture.import',
  'capture.delete',
  'alert.status_change',
  'settings.retention_change',
] as const;

const OUTCOMES: readonly AuditOutcome[] = ['success', 'failure', 'denied'];

function details(value: Record<string, unknown>): string {
  return Object.entries(value)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([key, v]) => `${key}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(', ');
}

export function AuditPage() {
  useTitle('Audit log');
  const search = useSearchState();
  const actionId = useId();
  const outcomeId = useId();
  const page = search.number('page', 1);
  const action = search.text('action');
  const outcomeText = search.text('outcome');
  const outcome = OUTCOMES.find((o) => o === outcomeText);
  const events = useResource(`audit:${page}:${action}:${outcome ?? ''}`, (signal) =>
    api.listAudit({ page, per_page: PER_PAGE, action: action || undefined, outcome }, signal),
  );
  const shown = events.data ?? events.previous;

  return (
    <>
      <PageHeader title="Audit log">
        <p className="lead">
          Sign-ins, refused requests and every change, newest first, with the account and client address. Events
          never contain passwords, session tokens or packet data, and are deleted after the audit retention
          period.
        </p>
      </PageHeader>
      <div className="toolbar">
        <label htmlFor={actionId}>
          Action{' '}
          <select id={actionId} value={action} onChange={(event) => search.update({ action: event.target.value })}>
            <option value="">all</option>
            {ACTIONS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label htmlFor={outcomeId}>
          Outcome{' '}
          <select
            id={outcomeId}
            value={outcome ?? ''}
            onChange={(event) => search.update({ outcome: event.target.value })}
          >
            <option value="">all</option>
            {OUTCOMES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
      </div>
      {events.error ? (
        <ErrorState error={events.error} onRetry={events.reload} />
      ) : !shown ? (
        <Loading />
      ) : shown.items.length === 0 && shown.total > 0 ? (
        <PastEnd total={shown.total} perPage={PER_PAGE} onPage={(next) => search.update({ page: next })} />
      ) : shown.total === 0 ? (
        <EmptyState title={action || outcome ? 'No events match' : 'No events yet'} />
      ) : (
        <div aria-busy={events.loading}>
          <TableScroll label="Audit events">
            <table className="dense">
              <thead>
                <tr>
                  <th scope="col">Time (UTC)</th>
                  <th scope="col">Account</th>
                  <th scope="col">Action</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Target</th>
                  <th scope="col">Client</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {shown.items.map((event) => (
                  <tr key={event.id}>
                    <th scope="row">{formatTime(event.at)}</th>
                    <td>{event.actor ?? '–'}</td>
                    <td>
                      <code>{event.action}</code>
                    </td>
                    <td>
                      <span className={`badge outcome-${event.outcome}`}>{event.outcome}</span>
                    </td>
                    <td>{event.target_type ? `${event.target_type} ${event.target_id ?? ''}` : '–'}</td>
                    <td>{event.client_ip ?? '–'}</td>
                    <td className="wrap">{details(event.details) || '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <Pagination
            label="Audit events"
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
