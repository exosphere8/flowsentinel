import { Link, useParams } from 'react-router';

import { api } from '../api/client';
import { TableScroll } from '../components/Details';
import { FilterBar } from '../components/FilterBar';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { Pagination } from '../components/Pagination';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatEndpoint, formatNumber, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam, useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

const PER_PAGE = 100;
const SORTS = [
  ['index', 'Packet number'],
  ['-index', 'Packet number, descending'],
  ['time', 'Time'],
  ['-length', 'Largest first'],
] as const;

export function PacketsPage() {
  const id = idParam(useParams().id);
  if (id === null) return <NotFoundPage />;
  return <Packets id={id} />;
}

function Packets({ id }: { id: number }) {
  useTitle('Packets');
  const search = useSearchState();
  const page = search.number('page', 1);
  const sort = search.text('sort', 'index');
  const filter = search.text('filter');
  const flowId = search.number('flow_id', 0) || undefined;
  const packets = useResource(`packets:${id}:${page}:${sort}:${flowId}:${filter}`, (signal) =>
    api.listPackets(id, { page, per_page: PER_PAGE, sort, filter, flow_id: flowId }, signal),
  );
  const shown = packets.data ?? packets.previous;

  return (
    <>
      <PageHeader
        title="Packets"
        crumbs={[
          { label: 'Captures', to: '/captures' },
          { label: `Capture ${id}`, to: `/captures/${id}` },
          { label: 'Packets' },
        ]}
      />
      <CaptureTabs id={id} />
      <FilterBar target="packets" value={filter} onApply={(next) => search.update({ filter: next })} />
      <div className="toolbar">
        {flowId ? (
          <p>
            Packets of <Link to={`/captures/${id}/flows/${flowId}`}>flow {flowId}</Link>.{' '}
            <button type="button" className="link" onClick={() => search.update({ flow_id: null })}>
              Show all packets
            </button>
          </p>
        ) : (
          <span />
        )}
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
      {packets.error ? (
        <ErrorState error={packets.error} onRetry={packets.reload} />
      ) : !shown ? (
        <Loading />
      ) : shown.total === 0 ? (
        <EmptyState title={filter || flowId ? 'No packets match' : 'No stored packets'}>
          <p className="muted">
            Only the first packets of a capture are stored (see the retention settings); flows and
            summaries always cover the whole capture.
          </p>
        </EmptyState>
      ) : (
        <div aria-busy={packets.loading}>
          <TableScroll label="Packets">
            <table className="dense">
              <thead>
                <tr>
                  <th scope="col" className="num">No.</th>
                  <th scope="col">Time</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Protocol</th>
                  <th scope="col" className="num">Length</th>
                  <th scope="col">Info</th>
                  <th scope="col" className="num">Flow</th>
                </tr>
              </thead>
              <tbody>
                {shown.items.map((packet) => (
                  <tr key={packet.packet_index} className={`decode-${packet.decode_status}`}>
                    <th scope="row" className="num">
                      <Link to={`/captures/${id}/packets/${packet.packet_index}`}>
                        {packet.packet_index}
                      </Link>
                    </th>
                    <td>{formatTime(packet.time)}</td>
                    <td>{formatEndpoint(packet.source, packet.src_port)}</td>
                    <td>{formatEndpoint(packet.destination, packet.dst_port)}</td>
                    <td>{packet.top_protocol ?? humanize(packet.decode_status)}</td>
                    <td className="num">{formatNumber(packet.original_length)}</td>
                    <td className="info">{packet.info}</td>
                    <td className="num">
                      {packet.flow_id ? (
                        <Link to={`/captures/${id}/flows/${packet.flow_id}`}>{packet.flow_id}</Link>
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
            label="Packets"
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
