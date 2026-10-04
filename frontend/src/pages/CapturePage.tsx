import { Link, useParams } from 'react-router';

import { api, SEVERITIES } from '../api/client';
import { BarChart, barsFrom } from '../components/BarChart';
import { KeyValueList } from '../components/Details';
import { CaptureTabs, PageHeader } from '../components/Layout';
import { ErrorState, HeuristicNotice, Loading } from '../components/States';
import { formatBytes, formatNumber, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { idParam } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';
import { NotFoundPage } from './NotFoundPage';

function field(object: unknown, name: string): unknown {
  return typeof object === 'object' && object !== null
    ? (object as Record<string, unknown>)[name]
    : undefined;
}

export function CapturePage() {
  const id = idParam(useParams().id);
  if (id === null) return <NotFoundPage />;
  return <CaptureSummary id={id} />;
}

function CaptureSummary({ id }: { id: number }) {
  const capture = useResource(`capture:${id}`, (signal) => api.getCapture(id, signal));
  useTitle(capture.data?.file_name ?? 'Capture');
  if (capture.error) return <ErrorState error={capture.error} onRetry={capture.reload} />;
  const data = capture.data;
  if (!data) return <Loading />;

  const detection = data.detection_summary;
  const bySeverity = field(detection, 'alerts_by_severity');
  const warnings = data.capture_warnings
    .map((warning) => field(warning, 'code'))
    .filter((code): code is string => typeof code === 'string');

  return (
    <>
      <PageHeader
        title={data.file_name}
        crumbs={[{ label: 'Captures', to: '/captures' }, { label: data.file_name }]}
      />
      <CaptureTabs id={id} />
      <div className="columns">
        <section aria-labelledby="facts-heading" className="card">
          <h2 id="facts-heading">Capture</h2>
          <KeyValueList
            items={[
              ['Size', formatBytes(data.file_size_bytes)],
              ['SHA-256', <code key="sha" className="wrap">{data.sha256}</code>],
              ['Completion', humanize(data.completion_state)],
              ['Format', `PCAP ${data.pcap_version}, ${data.endianness}, ${data.timestamp_resolution}`],
              ['Link type', data.link_type_name ?? String(data.link_type)],
              ['First packet', formatTime(data.first_packet_time)],
              ['Last packet', formatTime(data.last_packet_time)],
              [
                'Packets',
                `${formatNumber(data.packets_processed)} analyzed, ${formatNumber(data.packets_stored)} stored`,
              ],
              ['Flows', `${formatNumber(data.flows_total)} total, ${formatNumber(data.flows_stored)} stored`],
              ['Imported', formatTime(data.created_at)],
              ['Expires', formatTime(data.expires_at)],
            ]}
          />
          {warnings.length > 0 && (
            <>
              <h3>Capture warnings</h3>
              <ul>
                {warnings.map((code) => (
                  <li key={code}>
                    <code>{code}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
        <section aria-labelledby="alerts-heading" className="card">
          <h2 id="alerts-heading">Alerts</h2>
          <p>
            <Link to={`/captures/${id}/alerts`}>{formatNumber(data.alerts_total)} alerts</Link>
          </p>
          <HeuristicNotice />
          <BarChart
            title="Alerts by severity"
            bars={SEVERITIES.map((severity) => ({
              label: severity,
              value: Number(field(bySeverity, severity) ?? 0),
              tone: `severity-${severity}`,
            }))}
          />
        </section>
      </div>
      <div className="charts">
        <BarChart title="Packets by protocol" bars={barsFrom(field(data.decode_summary, 'protocol_counts'))} />
        <BarChart title="Decode status" bars={barsFrom(field(data.decode_summary, 'status_counts'))} />
        <BarChart title="Why flows ended" bars={barsFrom(field(data.flow_summary, 'end_reasons'))} />
        <BarChart title="Alerts by rule" bars={barsFrom(field(detection, 'alerts_by_rule'))} />
      </div>
    </>
  );
}
