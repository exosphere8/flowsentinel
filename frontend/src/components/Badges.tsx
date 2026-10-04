import { humanize } from '../lib/format';

/** Severity as text and color; the text carries the meaning. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <span className="muted">none</span>;
  return <span className={`badge severity-${severity}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status}`}>{humanize(status)}</span>;
}
