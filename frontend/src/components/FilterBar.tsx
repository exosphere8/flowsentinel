import { useEffect, useId, useState, type FormEvent } from 'react';

import { api, ApiError, isAbort, toApiError, type FilterTarget } from '../api/client';
import { byteRangeToIndexes } from '../lib/format';

const DEBOUNCE_MS = 300;

interface Check {
  text: string;
  error?: ApiError;
  normalized?: string;
}

const EXAMPLES: Record<FilterTarget, string> = {
  packets: 'tcp.port == 443 and not ip.addr == 10.0.0.0/8',
  flows: 'flow.bytes > 10000 or alert.severity == high',
};

/**
 * A display-filter input. The text is checked by the server as it is typed;
 * a filter is applied only when it is valid (or empty, which clears it).
 */
export function FilterBar({
  target,
  value,
  onApply,
}: {
  target: FilterTarget;
  value: string;
  onApply: (filter: string) => void;
}) {
  const inputId = useId();
  const statusId = useId();
  const [draft, setDraft] = useState(value);
  const [check, setCheck] = useState<Check>({ text: value });
  const [prevValue, setPrevValue] = useState(value);
  if (prevValue !== value) {
    // The applied filter changed elsewhere (for example, browser history).
    setPrevValue(value);
    setDraft(value);
  }

  const text = draft.trim();
  useEffect(() => {
    if (!text) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      api.validateFilter(target, text, controller.signal).then(
        (result) => setCheck({ text, normalized: result.normalized }),
        (error: unknown) => {
          if (!isAbort(error)) setCheck({ text, error: toApiError(error) });
        },
      );
    }, DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [target, text]);

  const checked = text === '' || check.text === text;
  const error = text !== '' && check.text === text ? check.error : undefined;
  const valid = text === '' || (checked && !error);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (valid) onApply(text);
  }

  let marked = null;
  if (error?.position) {
    const [from, to] = byteRangeToIndexes(text, error.position.start, error.position.end);
    marked = (
      <code className="filter-echo" aria-hidden="true">
        {text.slice(0, from)}
        <mark>{text.slice(from, Math.max(to, from + 1)) || ' '}</mark>
        {text.slice(Math.max(to, from + 1))}
      </code>
    );
  }

  return (
    <form className="filter-bar" onSubmit={submit} role="search">
      <label htmlFor={inputId}>Display filter</label>
      <div className="filter-row">
        <input
          id={inputId}
          type="text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={EXAMPLES[target]}
          spellCheck={false}
          autoComplete="off"
          maxLength={1024}
          aria-invalid={error ? true : undefined}
          aria-describedby={statusId}
        />
        <button type="submit" disabled={!valid}>
          Apply
        </button>
        {value && (
          <button type="button" className="secondary" onClick={() => onApply('')}>
            Clear
          </button>
        )}
      </div>
      <div id={statusId} className="filter-status" role="status" aria-live="polite">
        {error ? (
          <span className="error-text">{error.message}</span>
        ) : text && !checked ? (
          <span className="muted">Checking…</span>
        ) : text ? (
          <span className="ok-text">Valid filter: {check.normalized}</span>
        ) : (
          <span className="muted">
            For example <code>{EXAMPLES[target]}</code>. See the field list in Settings.
          </span>
        )}
      </div>
      {marked}
    </form>
  );
}
