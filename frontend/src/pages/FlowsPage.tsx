import { Link, useParams } from 'react-router';

import { api } from '../api/client';
import { SeverityBadge } from '../components/Badges';
import { TableScroll } from '../components/Details';
import { FilterBar } from '../components/FilterBar';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { Pagination, PastEnd } from '../components/Pagination';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatBytes, formatDuration, formatEndpoint, formatNumber, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam, useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

const PER_PAGE = 50;
const SORTS = [
  ['start', 'Start (flow ID)'],
  ['-bytes', 'Most bytes'],
  ['-packets', 'Most packets'],
  ['-duration', 'Longest'],
] as const;

export function FlowsPage() {
  const id = idParam(useParams().id);
  if (id === null) return <NotFoundPage />;
  return <Flows id={id} />;
}

function Flows({ id }: { id: number }) {
  useTitle('Flows');
  const search = useSearchState();
  const page = search.number('page', 1);
  const sort = search.text('sort', 'start');
  const filter = search.text('filter');
  const flows = useResource(`flows:${id}:${page}:${sort}:${filter}`, (signal) =>
    api.listFlows(id, { page, per_page: PER_PAGE, sort, filter }, signal),
  );
  const shown = flows.data ?? flows.previous;

  return (
    <>
      <PageHeader
        title="Flows"
        crumbs={[
          { label: 'Captures', to: '/captures' },
          { label: `Capture ${id}`, to: `/captures/${id}` },
          { label: 'Flows' },
        ]}
      />
      <CaptureTabs id={id} />
      <FilterBar target="flows" value={filter} onApply={(next) => search.update({ filter: next })} />
      <div className="toolbar">
        <span />
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
      </div>
      {flows.error ? (
        <ErrorState error={flows.error} onRetry={flows.reload} />
      ) : !shown ? (
        <Loading />
      ) : shown.items.length === 0 && shown.total > 0 ? (
        <PastEnd total={shown.total} perPage={PER_PAGE} onPage={(next) => search.update({ page: next })} />
      ) : shown.total === 0 ? (
        <EmptyState title={filter ? 'No flows match' : 'No flows'} />
      ) : (
        <div aria-busy={flows.loading}>
          <TableScroll label="Flows">
            <table className="dense">
              <thead>
                <tr>
                  <th scope="col" className="num">ID</th>
                  <th scope="col">Protocol</th>
                  <th scope="col">Initiator</th>
                  <th scope="col">Responder</th>
                  <th scope="col" className="num">Packets</th>
                  <th scope="col" className="num">Bytes</th>
                  <th scope="col" className="num">Duration</th>
                  <th scope="col">TCP state</th>
                  <th scope="col">Ended</th>
                  <th scope="col">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {shown.items.map((flow) => (
                  <tr key={flow.flow_id}>
                    <th scope="row" className="num">
                      <Link to={`/captures/${id}/flows/${flow.flow_id}`}>{flow.flow_id}</Link>
                    </th>
                    <td>{flow.protocol_name ?? flow.protocol}</td>
                    <td>{formatEndpoint(flow.initiator_ip, flow.initiator_port)}</td>
                    <td>{formatEndpoint(flow.responder_ip, flow.responder_port)}</td>
                    <td className="num">{formatNumber(flow.packets_total)}</td>
                    <td className="num">{formatBytes(flow.bytes_total)}</td>
                    <td className="num">{formatDuration(flow.duration_seconds)}</td>
                    <td>{humanize(flow.tcp_state)}</td>
                    <td>{humanize(flow.end_reason)}</td>
                    <td>
                      {flow.alert_count > 0 ? (
                        <>
                          {flow.alert_count} <SeverityBadge severity={flow.max_alert_severity} />
                        </>
                      ) : (
                        '–'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <Pagination
            label="Flows"
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
