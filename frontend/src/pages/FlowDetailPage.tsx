import { Link, useParams } from 'react-router';

import { api } from '../api/client';
import { SeverityBadge } from '../components/Badges';
import { KeyValueList } from '../components/Details';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { ErrorState, HeuristicNotice, Loading } from '../components/States';
import {
  formatBytes,
  formatDuration,
  formatEndpoint,
  formatNumber,
  formatTime,
  humanize,
} from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Obj) : {};
}

function num(value: unknown): number | null {
  return typeof value === 'number' ? value : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function list(values: string[]): string {
  return values.length === 0 ? '–' : values.join(', ');
}

export function FlowDetailPage() {
  const params = useParams();
  const id = idParam(params.id);
  const flowId = idParam(params.flowId);
  if (id === null || flowId === null) return <NotFoundPage />;
  return <FlowDetail id={id} flowId={flowId} />;
}

function FlowDetail({ id, flowId }: { id: number; flowId: number }) {
  useTitle(`Flow ${flowId}`);
  const flow = useResource(`flow:${id}:${flowId}`, (signal) => api.getFlow(id, flowId, signal));
  const crumbs = [
    { label: 'Captures', to: '/captures' },
    { label: `Capture ${id}`, to: `/captures/${id}` },
    { label: 'Flows', to: `/captures/${id}/flows` },
    { label: `Flow ${flowId}` },
  ];
  if (flow.error) {
    return (
      <>
        <PageHeader title={`Flow ${flowId}`} crumbs={crumbs} />
        <ErrorState error={flow.error} onRetry={flow.reload} />
      </>
    );
  }
  const data = flow.data;
  if (!data) return <Loading />;
  const record = data.record;
  const out = obj(record.initiator_to_responder);
  const back = obj(record.responder_to_initiator);
  const tcp = record.tcp ? obj(record.tcp) : null;
  const app = obj(record.application);
  const alertIds = Array.isArray(record.alert_ids)
    ? record.alert_ids.filter((v): v is number => typeof v === 'number')
    : [];

  return (
    <>
      <PageHeader title={`Flow ${flowId}`} crumbs={crumbs}>
        <p className="lead">
          {data.protocol_name ?? `IP protocol ${data.protocol}`}{' '}
          {formatEndpoint(data.initiator_ip, data.initiator_port)} →{' '}
          {formatEndpoint(data.responder_ip, data.responder_port)}
        </p>
      </PageHeader>
      <CaptureTabs id={id} />
      <p>
        <Link to={`/captures/${id}/packets?flow_id=${flowId}`}>Show this flow's packets</Link>
      </p>
      <div className="columns">
        <section className="card" aria-labelledby="flow-heading">
          <h2 id="flow-heading">Flow</h2>
          <KeyValueList
            items={[
              ['Started', formatTime(data.first_seen)],
              ['Duration', formatDuration(data.duration_seconds)],
              ['Packets', formatNumber(data.packets_total)],
              ['Bytes', formatBytes(data.bytes_total)],
              ['Initiator decided by', humanize(typeof record.initiator_basis === 'string' ? record.initiator_basis : null)],
              ['Ended because', humanize(data.end_reason)],
              ['Busier side', humanize(data.dominant_endpoint)],
            ]}
          />
        </section>
        <section className="card" aria-labelledby="directions-heading">
          <h2 id="directions-heading">Directions</h2>
          <table>
            <thead>
              <tr>
                <th scope="col">Direction</th>
                <th scope="col" className="num">Packets</th>
                <th scope="col" className="num">Bytes</th>
                <th scope="col" className="num">Payload bytes</th>
              </tr>
            </thead>
            <tbody>
              {(
                [
                  ['Initiator → responder', out],
                  ['Responder → initiator', back],
                ] as const
              ).map(([label, direction]) => (
                <tr key={label}>
                  <th scope="row">{label}</th>
                  <td className="num">{formatNumber(num(direction.packets))}</td>
                  <td className="num">{formatNumber(num(direction.bytes))}</td>
                  <td className="num">{formatNumber(num(direction.payload_bytes))}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">Payload is counted, never stored.</p>
        </section>
        {tcp && (
          <section className="card" aria-labelledby="tcp-heading">
            <h2 id="tcp-heading">TCP</h2>
            <KeyValueList
              items={[
                ['State (approximate)', humanize(typeof tcp.state === 'string' ? tcp.state : null)],
                ['Initiator flags', list(strings(tcp.flags_initiator))],
                ['Responder flags', list(strings(tcp.flags_responder))],
                ['SYN / FIN / RST packets', `${formatNumber(num(tcp.syn_packets))} / ${formatNumber(num(tcp.fin_packets))} / ${formatNumber(num(tcp.rst_packets))}`],
                ['Duplicate segments', formatNumber(num(tcp.duplicate_segments))],
              ]}
            />
          </section>
        )}
        <section className="card" aria-labelledby="app-heading">
          <h2 id="app-heading">Application metadata</h2>
          <KeyValueList
            items={[
              ['Protocols', list(strings(app.protocols))],
              ['DNS queries', list(strings(app.dns_queries))],
              ['Responder DNS names', list(strings(app.responder_dns_names))],
              ['HTTP hosts', list(strings(app.http_hosts))],
              ['HTTP paths', list(strings(app.http_paths))],
              ['TLS server names', list(strings(app.tls_server_names))],
              ['TLS ALPN', list(strings(app.tls_alpn))],
            ]}
          />
        </section>
      </div>
      <section aria-labelledby="flow-alerts-heading">
        <h2 id="flow-alerts-heading">Alerts citing this flow</h2>
        {alertIds.length === 0 ? (
          <p className="muted">None.</p>
        ) : (
          <>
            <p>
              Highest severity: <SeverityBadge severity={data.max_alert_severity} />
            </p>
            <ul>
              {alertIds.map((alertId) => (
                <li key={alertId}>
                  <Link to={`/captures/${id}/alerts/${alertId}`}>Alert {alertId}</Link>
                </li>
              ))}
            </ul>
            <HeuristicNotice />
          </>
        )}
      </section>
    </>
  );
}
