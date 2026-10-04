import { useEffect, useId, useState, type FormEvent } from 'react';
import { Link } from 'react-router';

import { api, toApiError, type ApiError, type Interface, type LiveStatus } from '../api/client';
import { KeyValueList } from '../components/Details';
import { PageHeader } from '../components/Layout';
import { ErrorState, Loading } from '../components/States';
import { formatBytes, formatNumber, formatTime, humanize } from '../lib/format';
import { useResource } from '../lib/useResource';
import { useTitle } from '../lib/useTitle';

const POLL_MS = 1000;
/** Longest pause between polls after errors. */
const MAX_RETRY_MS = 10_000;
const ACTIVE = new Set(['capturing', 'importing']);

function Unavailable({ error }: { error: ApiError }) {
  const why =
    error.code === 'live_capture_disabled'
      ? 'Live capture is turned off on this server. An operator can enable it with FLOWSENTINEL_LIVE_CAPTURE=true.'
      : error.code === 'live_capture_unavailable'
        ? 'This server was built without live capture (libpcap). Import capture files instead.'
        : error.code === 'capture_permission_denied'
          ? 'The server is not permitted to capture. An operator can grant it the capture capability without running it as root.'
          : null;
  if (!why) return <ErrorState error={error} />;
  return (
    <div className="notice" role="status">
      <p>{why}</p>
      <p>
        See <code>docs/live-capture.md</code> and <code>docs/permissions.md</code> in the repository.
      </p>
    </div>
  );
}

function StartForm({ interfaces, onStarted }: { interfaces: Interface[]; onStarted: (status: LiveStatus) => void }) {
  const ids = { iface: useId(), filter: useId(), seconds: useId(), packets: useId(), promisc: useId(), ok: useId() };
  const [iface, setIface] = useState(interfaces.find((i) => i.up)?.name ?? interfaces[0]?.name ?? '');
  const [filter, setFilter] = useState('');
  const [seconds, setSeconds] = useState('60');
  const [packets, setPackets] = useState('100000');
  const [promiscuous, setPromiscuous] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const whole = (text: string) => (/^\d{1,9}$/.test(text.trim()) ? Number(text.trim()) : null);
  const secondsValue = whole(seconds);
  const packetsValue = whole(packets);
  const limitsOk = secondsValue !== null && secondsValue > 0 && packetsValue !== null && packetsValue > 0;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!limitsOk || !authorized || !iface) return;
    setBusy(true);
    setError(null);
    try {
      onStarted(
        await api.startLive({
          interface: iface,
          filter: filter.trim(),
          promiscuous,
          max_seconds: secondsValue,
          max_packets: packetsValue,
          authorized,
        }),
      );
    } catch (caught) {
      setError(toApiError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} aria-labelledby="start-heading" noValidate>
      <h2 id="start-heading">Start a capture</h2>
      <p className="notice">
        Capture only on networks you own or are explicitly authorized to monitor. Packets are written to a
        private temporary file, imported as metadata when the capture stops, and the file is deleted. Nothing is
        ever sent on the network.
      </p>
      <div className="field">
        <label htmlFor={ids.iface}>Interface</label>
        <select id={ids.iface} value={iface} onChange={(event) => setIface(event.target.value)}>
          {interfaces.map((i) => (
            <option key={i.name} value={i.name}>
              {i.name}
              {i.description ? ` (${i.description})` : ''}
              {i.up ? '' : ' (down)'}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor={ids.filter}>Capture filter (BPF, optional)</label>
        <input
          id={ids.filter}
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="tcp port 443"
          spellCheck={false}
          autoComplete="off"
          maxLength={1024}
        />
      </div>
      <div className="field">
        <label htmlFor={ids.seconds}>Stop after (seconds)</label>
        <input id={ids.seconds} inputMode="numeric" value={seconds} onChange={(event) => setSeconds(event.target.value)} />
      </div>
      <div className="field">
        <label htmlFor={ids.packets}>Stop after (packets)</label>
        <input id={ids.packets} inputMode="numeric" value={packets} onChange={(event) => setPackets(event.target.value)} />
      </div>
      {!limitsOk && <p className="error-text">Enter whole numbers greater than 0.</p>}
      <div className="check">
        <input
          id={ids.promisc}
          type="checkbox"
          checked={promiscuous}
          onChange={(event) => setPromiscuous(event.target.checked)}
          aria-describedby={`${ids.promisc}-help`}
        />
        <label htmlFor={ids.promisc}>Promiscuous mode</label>
        <span id={`${ids.promisc}-help`} className="muted">
          Off by default: only traffic to and from this host is seen.
        </span>
      </div>
      <div className="check">
        <input id={ids.ok} type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
        <label htmlFor={ids.ok}>I own this network or am authorized to capture its traffic</label>
      </div>
      <button type="submit" disabled={busy || !authorized || !limitsOk || !iface}>
        {busy ? 'Starting…' : 'Start capture'}
      </button>
      {error && (
        <p className="error-text" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

function StatusCard({ status, onStop }: { status: LiveStatus; onStop: () => void }) {
  const active = ACTIVE.has(status.state);
  return (
    <section className="card" aria-labelledby="status-heading">
      <h2 id="status-heading">
        {status.state === 'idle' ? 'No capture yet' : `Capture: ${humanize(status.state)}`}
      </h2>
      {status.state !== 'idle' && (
        <KeyValueList
          items={[
            ['Interface', status.interface ?? '–'],
            ['Filter', status.filter || 'none'],
            ['Promiscuous', status.promiscuous ? 'yes' : 'no'],
            ['Started', `${formatTime(status.started_at)} by ${status.started_by ?? '–'}`],
            ['Elapsed', `${formatNumber(status.elapsed_seconds)} s`],
            ['Packets written', formatNumber(status.packets_written)],
            ['Bytes written', formatBytes(status.bytes_written)],
            ['Dropped (writer behind)', formatNumber(status.dropped_backpressure)],
            ['Dropped (system)', formatNumber(status.dropped_by_system)],
            ['Stopped because', humanize(status.stop_reason)],
          ]}
        />
      )}
      <div role="status" aria-live="polite">
        {status.state === 'importing' && <p>Importing the capture as metadata…</p>}
        {status.capture_id != null && (
          <p>
            Stored as <Link to={`/captures/${status.capture_id}`}>capture {status.capture_id}</Link>.
          </p>
        )}
        {status.error && (
          <p className="error-text">
            {status.error.message} <code>{status.error.code}</code>
          </p>
        )}
      </div>
      {status.state === 'capturing' && (
        <button type="button" className="danger" onClick={onStop}>
          Stop capture
        </button>
      )}
      {active && <p className="muted">This page updates every second.</p>}
    </section>
  );
}

export function LivePage() {
  useTitle('Live capture');
  const interfaces = useResource('live-interfaces', (signal) => api.liveInterfaces(signal));
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const active = status ? ACTIVE.has(status.state) : false;

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    let failures = 0;
    const controller = new AbortController();
    async function poll() {
      try {
        const next = await api.liveStatus(controller.signal);
        if (stopped) return;
        failures = 0;
        setStatus(next);
        setError(null);
        if (ACTIVE.has(next.state)) timer = window.setTimeout(poll, POLL_MS);
      } catch (caught) {
        if (stopped || controller.signal.aborted) return;
        setError(toApiError(caught));
        // Keep trying while a capture may be running, backing off.
        if (active) {
          failures += 1;
          timer = window.setTimeout(poll, Math.min(POLL_MS * 2 ** failures, MAX_RETRY_MS));
        }
      }
    }
    void poll();
    return () => {
      stopped = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [active]);

  async function stop() {
    try {
      setStatus(await api.stopLive());
    } catch (caught) {
      setError(toApiError(caught));
    }
  }

  return (
    <>
      <PageHeader title="Live capture">
        <p className="lead">
          Record traffic from one of this server's interfaces within strict limits, then analyze it like an imported
          capture. Admins only; every start and stop is in the audit log.
        </p>
      </PageHeader>
      {interfaces.error ? (
        <Unavailable error={interfaces.error} />
      ) : !interfaces.data ? (
        <Loading />
      ) : interfaces.data.length === 0 ? (
        <p className="notice">No interface is available to capture on (see FLOWSENTINEL_LIVE_INTERFACES).</p>
      ) : !active ? (
        <StartForm interfaces={interfaces.data} onStarted={setStatus} />
      ) : null}
      {error && <ErrorState error={error} />}
      {status && <StatusCard status={status} onStop={() => void stop()} />}
    </>
  );
}
