import { useId } from 'react';

import { formatNumber } from '../lib/format';

export interface Bar {
  label: string;
  value: number;
  /** Optional CSS class for the bar, for example a severity color. */
  tone?: string;
}

const ROW = 26;
const LABEL_WIDTH = 140;
const WIDTH = 480;

/**
 * A horizontal bar chart. The SVG is decorative for assistive technology;
 * the same numbers are in a table that screen readers read instead.
 */
export function BarChart({ title, bars }: { title: string; bars: Bar[] }) {
  const id = useId();
  const max = Math.max(1, ...bars.map((bar) => bar.value));
  const height = Math.max(1, bars.length) * ROW;
  return (
    <figure className="chart" aria-labelledby={id}>
      <figcaption id={id}>{title}</figcaption>
      {bars.length === 0 ? (
        <p className="chart-empty">No data</p>
      ) : (
        <>
          <svg
            viewBox={`0 0 ${WIDTH} ${height}`}
            width="100%"
            preserveAspectRatio="xMinYMin meet"
            aria-hidden="true"
            focusable="false"
          >
            {bars.map((bar, i) => {
              const width = Math.max(
                bar.value > 0 ? 2 : 0,
                ((WIDTH - LABEL_WIDTH - 60) * bar.value) / max,
              );
              const y = i * ROW;
              return (
                <g key={bar.label}>
                  <text x={0} y={y + 17} className="chart-label">
                    {bar.label.length > 20 ? `${bar.label.slice(0, 19)}…` : bar.label}
                  </text>
                  <rect
                    x={LABEL_WIDTH}
                    y={y + 4}
                    width={width}
                    height={ROW - 8}
                    rx={3}
                    className={`chart-bar ${bar.tone ?? ''}`}
                  />
                  <text x={LABEL_WIDTH + width + 6} y={y + 17} className="chart-value">
                    {formatNumber(bar.value)}
                  </text>
                </g>
              );
            })}
          </svg>
          <table className="sr-only">
            <caption>{title}</caption>
            <thead>
              <tr>
                <th scope="col">Category</th>
                <th scope="col">Count</th>
              </tr>
            </thead>
            <tbody>
              {bars.map((bar) => (
                <tr key={bar.label}>
                  <th scope="row">{bar.label}</th>
                  <td>{formatNumber(bar.value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </figure>
  );
}

/** Bars from a `{name: count}` object, largest first. */
export function barsFrom(counts: unknown, limit = 12): Bar[] {
  if (typeof counts !== 'object' || counts === null) return [];
  return Object.entries(counts as Record<string, unknown>)
    .filter((entry): entry is [string, number] => typeof entry[1] === 'number')
    .map(([label, value]) => ({ label: label.replace(/_/g, ' '), value }))
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
    .slice(0, limit);
}
