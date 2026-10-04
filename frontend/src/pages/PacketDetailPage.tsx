import { Link, useParams } from 'react-router';

import { api } from '../api/client';
import { KeyValueList } from '../components/Details';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { ProtocolTree } from '../components/ProtocolTree';
import { ErrorState, Loading } from '../components/States';
import { formatEndpoint, formatNumber, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

export function PacketDetailPage() {
  const params = useParams();
  const id = idParam(params.id);
  const index = idParam(params.index);
  if (id === null || index === null) return <NotFoundPage />;
  return <PacketDetail id={id} index={index} />;
}

function PacketDetail({ id, index }: { id: number; index: number }) {
  useTitle(`Packet ${index}`);
  const packet = useResource(`packet:${id}:${index}`, (signal) => api.getPacket(id, index, signal));
  const crumbs = [
    { label: 'Captures', to: '/captures' },
    { label: `Capture ${id}`, to: `/captures/${id}` },
    { label: 'Packets', to: `/captures/${id}/packets` },
    { label: `Packet ${index}` },
  ];
  if (packet.error) {
    return (
      <>
        <PageHeader title={`Packet ${index}`} crumbs={crumbs} />
        <ErrorState error={packet.error} onRetry={packet.reload} />
      </>
    );
  }
  const data = packet.data;
  if (!data) return <Loading />;
  const warnings = data.warnings
    .map((warning) => [warning.code, warning.detail])
    .filter((pair): pair is [string, string] => typeof pair[0] === 'string');

  return (
    <>
      <PageHeader title={`Packet ${index}`} crumbs={crumbs} />
      <CaptureTabs id={id} />
      <nav aria-label="Neighboring packets" className="toolbar">
        {index > 1 ? <Link to={`/captures/${id}/packets/${index - 1}`}>Previous packet</Link> : <span />}
        <Link to={`/captures/${id}/packets/${index + 1}`}>Next packet</Link>
      </nav>
      <div className="columns">
        <section className="card" aria-labelledby="summary-heading">
          <h2 id="summary-heading">Summary</h2>
          <KeyValueList
            items={[
              ['Time', formatTime(data.time)],
              ['Source', formatEndpoint(data.source, data.src_port)],
              ['Destination', formatEndpoint(data.destination, data.dst_port)],
              ['Protocol', data.top_protocol ?? '–'],
              ['Length on the wire', `${formatNumber(data.original_length)} bytes`],
              ['Captured', `${formatNumber(data.captured_length)} bytes`],
              ['Decode status', humanize(data.decode_status)],
              [
                'Flow',
                data.flow_id ? (
                  <Link key="flow" to={`/captures/${id}/flows/${data.flow_id}`}>
                    Flow {data.flow_id}
                  </Link>
                ) : (
                  'none'
                ),
              ],
              ['Info', data.info],
            ]}
          />
          {warnings.length > 0 && (
            <>
              <h3>Decode warnings</h3>
              <ul>
                {warnings.map(([code, detail], i) => (
                  <li key={i}>
                    <code>{code}</code> {typeof detail === 'string' ? detail : ''}
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
        <section className="card" aria-labelledby="layers-heading">
          <h2 id="layers-heading">Protocol layers</h2>
          <p className="muted">
            Header fields and application metadata only. Payload bytes are never stored or shown,
            only their lengths.
          </p>
          <ProtocolTree layers={data.layers} />
        </section>
      </div>
    </>
  );
}
