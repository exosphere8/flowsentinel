import { Link } from 'react-router';

import { api, SEVERITIES } from '../api/client';
import { BarChart } from '../components/BarChart';
import { TableScroll } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { EmptyState, ErrorState, HeuristicNotice, Loading } from '../components/States';
import { formatBytes, formatNumber, formatTime } from '../lib/format';
import { useResource } from '../lib/useResource';
import { useTitle } from '../lib/useTitle';

export function OverviewPage() {
  useTitle('Overview');
  const overview = useResource('overview', (signal) => api.overview(signal));

  if (overview.error) return <ErrorState error={overview.error} onRetry={overview.reload} />;
  const data = overview.data;
  if (!data) return <Loading />;

  const stats: [string, number][] = [
    ['Captures', data.captures],
    ['Packets analyzed', data.packets_processed],
    ['Flows', data.flows_total],
    ['Alerts', data.alerts_total],
  ];
  return (
    <>
      <PageHeader title="Overview" />
      <ul className="stats" aria-label="Totals">
        {stats.map(([label, value]) => (
          <li key={label} className="stat">
            <span className="stat-value">{formatNumber(value)}</span>
            <span className="stat-label">{label}</span>
          </li>
        ))}
      </ul>
      {data.captures === 0 ? (
        <EmptyState title="No captures yet">
          <p>
            <Link to="/captures">Import a capture</Link> you are authorized to analyze to see its
            packets, flows and alerts.
          </p>
        </EmptyState>
      ) : (
        <>
          <section aria-labelledby="alerts-heading">
            <h2 id="alerts-heading">Alerts</h2>
            <HeuristicNotice />
            <div className="charts">
              <BarChart
                title="Open alerts by severity"
                bars={SEVERITIES.map((severity) => ({
                  label: severity,
                  value: data.open_alerts_by_severity[severity] ?? 0,
                  tone: `severity-${severity}`,
                }))}
              />
              <BarChart
                title="Alerts by status"
                bars={Object.entries(data.alerts_by_status).map(([label, value]) => ({
                  label: label.replace(/_/g, ' '),
                  value,
                }))}
              />
            </div>
          </section>
          <section aria-labelledby="recent-heading">
            <h2 id="recent-heading">Recent captures</h2>
            <TableScroll label="Recent captures">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Capture</th>
                    <th scope="col">Imported</th>
                    <th scope="col" className="num">Size</th>
                    <th scope="col" className="num">Packets</th>
                    <th scope="col" className="num">Flows</th>
                    <th scope="col" className="num">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_captures.map((capture) => (
                    <tr key={capture.id}>
                      <th scope="row">
                        <Link to={`/captures/${capture.id}`}>{capture.file_name}</Link>
                      </th>
                      <td>{formatTime(capture.created_at)}</td>
                      <td className="num">{formatBytes(capture.file_size_bytes)}</td>
                      <td className="num">{formatNumber(capture.packets_processed)}</td>
                      <td className="num">{formatNumber(capture.flows_total)}</td>
                      <td className="num">
                        <Link to={`/captures/${capture.id}/alerts`}>
                          {formatNumber(capture.alerts_total)}
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>
        </>
      )}
    </>
  );
}
