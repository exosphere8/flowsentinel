import type { ReactNode } from 'react';

/** A two-column list of labelled values. */
export function KeyValueList({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([label, value]) => (
        <div key={label} className="kv-row">
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A horizontally scrollable, keyboard-focusable region around a table. */
export function TableScroll({ label, children }: { label: string; children: ReactNode }) {
  return (
    // A focusable region lets keyboard users scroll wide tables.
    <div className="table-scroll" role="region" aria-label={`${label} (table)`} tabIndex={0}>
      {children}
    </div>
  );
}
