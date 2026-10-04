import { useId, useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';

import { api, ApiError, toApiError } from '../api/client';
import { TableScroll } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { Pagination } from '../components/Pagination';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { formatBytes, formatNumber, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { useSearchState } from '../lib/useSearchState';
import { useTitle } from '../lib/useTitle';

const PER_PAGE = 25;
const SORTS = [
  ['newest', 'Newest first'],
  ['oldest', 'Oldest first'],
  ['packets', 'Most packets'],
  ['size', 'Largest'],
] as const;

function ImportForm() {
  const navigate = useNavigate();
  const inputId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const file = input.current?.files?.[0];
    if (!file) {
      setError(new ApiError(0, 'no_file', 'Choose a .pcap file first.'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const capture = await api.importCapture(file);
      navigate(`/captures/${capture.id}`);
    } catch (caught) {
      setError(toApiError(caught));
      setBusy(false);
    }
  }

  return (
    <form className="card import-form" onSubmit={submit} aria-busy={busy}>
      <h2>Import a capture</h2>
      <p className="muted">
        Classic libpcap files (<code>.pcap</code>) only. The file is analyzed for metadata and
        deleted; payloads are never stored. Import only traffic you are authorized to analyze.
      </p>
      <div className="filter-row">
        <label htmlFor={inputId} className="sr-only">
          Capture file
        </label>
        <input id={inputId} ref={input} type="file" accept=".pcap" disabled={busy} />
        <button type="submit" disabled={busy}>
          {busy ? 'Importing…' : 'Import'}
        </button>
      </div>
      <div role="status" aria-live="polite">
        {busy && <span className="muted">Analyzing the capture; large files take a while.</span>}
      </div>
      {error && (
        <p className="error-text" role="alert">
          {error.message}
        </p>
      )}
    </form>
  );
}

function DeleteButton({ id, name, onDeleted }: { id: number; name: string; onDeleted: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function remove() {
    setBusy(true);
    try {
      await api.deleteCapture(id);
      onDeleted();
    } catch (caught) {
      setError(toApiError(caught).message);
      setBusy(false);
    }
  }

  if (!confirming) {
    return (
      <button
        type="button"
        className="secondary"
        aria-label={`Delete ${name}`}
        onClick={() => setConfirming(true)}
      >
        Delete
      </button>
    );
  }
  return (
    <span className="confirm">
      <button
        type="button"
        className="danger"
        aria-label={`Confirm delete ${name}`}
        onClick={remove}
        disabled={busy}
      >
        Confirm delete
      </button>
      <button type="button" className="secondary" onClick={() => setConfirming(false)} disabled={busy}>
        Cancel
      </button>
      {error && (
        <span className="error-text" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}

export function CapturesPage() {
  useTitle('Captures');
  const search = useSearchState();
  const page = search.number('page', 1);
  const sort = search.text('sort', 'newest');
  const captures = useResource(`captures:${page}:${sort}`, (signal) =>
    api.listCaptures({ page, per_page: PER_PAGE, sort }, signal),
  );
  const shown = captures.data ?? captures.previous;

  return (
    <>
      <PageHeader title="Captures" />
      <ImportForm />
      <section aria-labelledby="list-heading">
        <div className="toolbar">
          <h2 id="list-heading">Imported captures</h2>
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
        {captures.error ? (
          <ErrorState error={captures.error} onRetry={captures.reload} />
        ) : !shown ? (
          <Loading />
        ) : shown.total === 0 ? (
          <EmptyState title="No captures yet">
            <p>Import a .pcap file above.</p>
          </EmptyState>
        ) : (
          <div aria-busy={captures.loading}>
            <TableScroll label="Imported captures">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Capture</th>
                    <th scope="col">Imported</th>
                    <th scope="col">Expires</th>
                    <th scope="col">State</th>
                    <th scope="col" className="num">Size</th>
                    <th scope="col" className="num">Packets</th>
                    <th scope="col" className="num">Flows</th>
                    <th scope="col" className="num">Alerts</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.items.map((capture) => (
                    <tr key={capture.id}>
                      <th scope="row">
                        <Link to={`/captures/${capture.id}`}>{capture.file_name}</Link>
                      </th>
                      <td>{formatTime(capture.created_at)}</td>
                      <td>{formatTime(capture.expires_at)}</td>
                      <td>{humanize(capture.completion_state)}</td>
                      <td className="num">{formatBytes(capture.file_size_bytes)}</td>
                      <td className="num">{formatNumber(capture.packets_processed)}</td>
                      <td className="num">{formatNumber(capture.flows_total)}</td>
                      <td className="num">{formatNumber(capture.alerts_total)}</td>
                      <td>
                        <DeleteButton
                          id={capture.id}
                          name={capture.file_name}
                          onDeleted={captures.reload}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
            <Pagination
              label="Captures"
              page={page}
              perPage={PER_PAGE}
              total={shown.total}
              onPage={(next) => search.update({ page: next })}
            />
          </div>
        )}
      </section>
    </>
  );
}
