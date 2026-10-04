import { humanize } from '../lib/format';

/**
 * Keys that could hold packet contents. The API never sends any; the
 * dashboard refuses to render them anyway, so a future API change cannot
 * put payload on screen by accident.
 */
const WITHHELD = /^(payload|data|raw|bytes|hex|body|content|contents)$/i;
const MAX_DEPTH = 6;
const MAX_ITEMS = 100;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function scalar(value: Json): string | null {
  if (value === null) return '–';
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (typeof value === 'number' || typeof value === 'string') return String(value);
  if (Array.isArray(value) && value.every((v) => v === null || typeof v !== 'object')) {
    return value.length === 0 ? 'none' : value.slice(0, MAX_ITEMS).map(String).join(', ');
  }
  return null;
}

function Fields({ value, depth }: { value: { [key: string]: Json }; depth: number }) {
  const entries = Object.entries(value).filter(([key]) => key !== 'layer' && !WITHHELD.test(key));
  return (
    <dl className="tree-fields">
      {entries.map(([key, child]) => {
        const text = scalar(child);
        return (
          <div key={key} className="tree-field">
            <dt>{humanize(key)}</dt>
            <dd>{text ?? <Nested value={child} depth={depth + 1} />}</dd>
          </div>
        );
      })}
    </dl>
  );
}

function Nested({ value, depth }: { value: Json; depth: number }) {
  if (depth > MAX_DEPTH) return <span className="muted">(nested too deeply to show)</span>;
  if (Array.isArray(value)) {
    return (
      <ol className="tree-list">
        {value.slice(0, MAX_ITEMS).map((item, i) => (
          <li key={i}>{scalar(item) ?? <Nested value={item} depth={depth + 1} />}</li>
        ))}
      </ol>
    );
  }
  if (value !== null && typeof value === 'object') return <Fields value={value} depth={depth} />;
  return <>{scalar(value)}</>;
}

/** The decoded protocol layers of one packet, outermost first. */
export function ProtocolTree({ layers }: { layers: Record<string, unknown>[] }) {
  if (layers.length === 0) return <p className="muted">No layers were decoded.</p>;
  return (
    <ol className="tree" aria-label="Protocol layers">
      {layers.slice(0, MAX_ITEMS).map((layer, i) => {
        const name = typeof layer.layer === 'string' ? layer.layer : `layer ${i + 1}`;
        return (
          <li key={i}>
            <details open>
              <summary>{name.toUpperCase()}</summary>
              <Fields value={layer as { [key: string]: Json }} depth={1} />
            </details>
          </li>
        );
      })}
    </ol>
  );
}
