import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import {
  alert,
  flow,
  flowDetail,
  mockApi,
  packet,
  packetDetail,
  paged,
  session,
  sessionDetail,
} from '../test/api';
import { axeViolations, renderAt } from '../test/render';

const overview = {
  captures: 1,
  packets_processed: 138,
  flows_total: 47,
  alerts_total: 5,
  alerts_by_severity: { high: 2, medium: 2, low: 1 },
  alerts_by_status: { open: 5 },
  open_alerts_by_severity: { high: 2, medium: 2, low: 1 },
  recent_captures: [session],
};

const rules = [
  {
    id: 'FS-BEACON',
    name: 'Regular repeated connections',
    severity: 'medium',
    description: 'One host connected to the same destination at regular intervals.',
    uncertainty: 'Regularity alone is common.',
    likely_false_positives: ['software update and licence checks'],
    mitre_attack: [],
    nature: alert.nature,
  },
];

describe('Overview', () => {
  it('shows totals, alert charts and recent captures, accessibly', async () => {
    mockApi([['GET', /\/overview$/, () => ({ body: overview })]]);
    const { container } = renderAt('/');
    expect(await screen.findByRole('heading', { name: 'Overview', level: 1 })).toBeInTheDocument();
    const totals = screen.getByRole('list', { name: 'Totals' });
    expect(within(totals).getByText('138')).toBeInTheDocument();
    expect(screen.getByText(/heuristic indicators/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'detect-mixed.pcap' })).toHaveAttribute('href', '/captures/7');
    expect(await axeViolations(container)).toEqual([]);
    expect(document.title).toBe('Overview · FlowSentinel');
  });

  it('guides the first import when there is nothing yet', async () => {
    mockApi([['GET', /\/overview$/, () => ({ body: { ...overview, captures: 0, recent_captures: [] } })]]);
    renderAt('/');
    expect(await screen.findByText('No captures yet')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Import a capture' })).toHaveAttribute('href', '/captures');
  });
});

describe('Captures', () => {
  it('lists captures with server-side paging, and deletes after confirmation', async () => {
    let deleted = false;
    const { calls } = mockApi([
      ['GET', /\/captures\?/, () => ({ body: paged(deleted ? [] : [session], 1, 25, deleted ? 0 : 60) })],
      ['DELETE', /\/captures\/7$/, () => { deleted = true; return { status: 204 }; }],
    ]);
    const { container, router } = renderAt('/captures?page=2&sort=size');
    expect(await screen.findByRole('link', { name: 'detect-mixed.pcap' })).toBeInTheDocument();
    expect(calls[0]?.url).toBe('/api/v1/captures?page=2&per_page=25&sort=size');
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(router.state.location.search).toBe('?page=3&sort=size'));

    await userEvent.click(screen.getByRole('button', { name: 'Delete detect-mixed.pcap' }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm delete detect-mixed.pcap' }));
    expect(await screen.findByText('No captures yet')).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(true);
  });

  it('offers the last page when the address points past the end', async () => {
    mockApi([['GET', /\/captures\?/, (call) => ({ body: call.url.includes('page=3') ? paged([], 3, 25, 1) : paged([session], 1, 25, 1) })]]);
    const { router } = renderAt('/captures?page=3');
    expect(await screen.findByText('This page is past the end')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Captures (table)' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Go to the last page' }));
    await waitFor(() => expect(router.state.location.search).toBe('?page=1'));
    expect(await screen.findByRole('link', { name: 'detect-mixed.pcap' })).toBeInTheDocument();
  });

  it('shows errors with a retry', async () => {
    let fail = true;
    mockApi([
      [
        'GET',
        /\/captures\?/,
        () =>
          fail
            ? { status: 503, body: { error: { code: 'database_unavailable', message: 'the database is unavailable' } } }
            : { body: paged([session]) },
      ],
    ]);
    renderAt('/captures');
    expect(await screen.findByRole('alert')).toHaveTextContent('the database is unavailable');
    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('link', { name: 'detect-mixed.pcap' })).toBeInTheDocument();
  });

  it('imports a file and opens the new capture', async () => {
    const { calls } = mockApi([
      ['GET', /\/captures\?/, () => ({ body: paged([]) })],
      ['POST', /\/captures\?file_name=lab\.pcap$/, () => ({ status: 201, body: sessionDetail })],
      ['GET', /\/captures\/7$/, () => ({ body: sessionDetail })],
    ]);
    const { router } = renderAt('/captures');
    const input = await screen.findByLabelText('Capture file');
    await userEvent.upload(input, new File([new Uint8Array([1, 2, 3])], 'lab.pcap'));
    await userEvent.click(screen.getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/captures/7'));
    expect(calls.some((c) => c.method === 'POST')).toBe(true);
    expect(await screen.findByRole('heading', { name: 'detect-mixed.pcap', level: 1 })).toBeInTheDocument();
  });
});

describe('Capture', () => {
  it('summarizes a capture with charts that have table equivalents', async () => {
    mockApi([['GET', /\/captures\/7$/, () => ({ body: sessionDetail })]]);
    const { container } = renderAt('/captures/7');
    expect(await screen.findByRole('heading', { name: 'detect-mixed.pcap', level: 1 })).toBeInTheDocument();
    const protocols = screen.getByRole('figure', { name: 'Packets by protocol' });
    expect(within(protocols).getByRole('table')).toHaveTextContent('tcp');
    expect(screen.getByRole('figure', { name: 'Alerts by rule' })).toBeInTheDocument();
    expect(screen.getAllByText(/heuristic indicators/).length).toBeGreaterThan(0);
    expect(await axeViolations(container)).toEqual([]);
  });

  it('shows a loading state until the capture arrives', async () => {
    let release: () => void = () => {};
    const ready = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockApi([['GET', /\/captures\/7$/, async () => { await ready; return { body: sessionDetail }; }]]);
    renderAt('/captures/7');
    expect(await screen.findByText('Loading…')).toBeInTheDocument();
    release();
    expect(await screen.findByRole('heading', { name: 'detect-mixed.pcap', level: 1 })).toBeInTheDocument();
  });

  it('treats a malformed capture ID as not found without calling the API', async () => {
    const { calls } = mockApi([]);
    renderAt('/captures/abc');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    expect(calls).toEqual([]);
  });
});

describe('Flows', () => {
  it('lists flows with their alerts, filtered and sorted on the server', async () => {
    const { calls } = mockApi([
      ['GET', /\/captures\/7\/flows\?/, () => ({ body: paged([flow], 1, 50, 1) })],
      ['GET', /\/filters\/validate/, () => ({ body: { valid: true, target: 'flows', normalized: 'alert.severity == high', parameters: 1 } })],
    ]);
    const { container, router } = renderAt('/captures/7/flows?filter=alert.severity%20%3D%3D%20high');
    expect(await screen.findByRole('link', { name: '41' })).toHaveAttribute('href', '/captures/7/flows/41');
    expect(calls[0]?.url).toBe('/api/v1/captures/7/flows?page=1&per_page=50&sort=start&filter=alert.severity+%3D%3D+high');
    const table = screen.getByRole('region', { name: 'Flows (table)' });
    expect(within(table).getByText('203.0.113.80:8443')).toBeInTheDocument();
    expect(within(table).getByText('medium')).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.selectOptions(screen.getByLabelText('Sort'), '-bytes');
    await waitFor(() => expect(router.state.location.search).toContain('sort=-bytes'));
    await waitFor(() => expect(calls.some((c) => c.url.includes('sort=-bytes'))).toBe(true));
  });

  it('says when no flow matches a filter', async () => {
    mockApi([
      ['GET', /\/captures\/7\/flows\?/, () => ({ body: paged([], 1, 50, 0) })],
      ['GET', /\/filters\/validate/, () => ({ body: { valid: true, target: 'flows', normalized: 'udp', parameters: 0 } })],
    ]);
    renderAt('/captures/7/flows?filter=udp');
    expect(await screen.findByText('No flows match')).toBeInTheDocument();
  });

  it('shows one flow with both directions, never its payload', async () => {
    mockApi([['GET', /\/captures\/7\/flows\/41$/, () => ({ body: flowDetail })]]);
    const { container } = renderAt('/captures/7/flows/41');
    expect(await screen.findByRole('heading', { name: 'Flow 41', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('rowheader', { name: 'Initiator → responder' })).toBeInTheDocument();
    expect(screen.getByText('www.example.com')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Alert 2' })).toHaveAttribute('href', '/captures/7/alerts/2');
    expect(screen.getByRole('link', { name: "Show this flow's packets" })).toHaveAttribute(
      'href',
      '/captures/7/packets?flow_id=41',
    );
    expect(container.textContent).not.toContain('FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER');
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe('Packets', () => {
  it('reads the filter from the address and lists matching packets', async () => {
    const { calls } = mockApi([
      ['GET', /\/captures\/7\/packets\?/, () => ({ body: paged([packet], 1, 100, 1) })],
      ['GET', /\/filters\/validate/, () => ({ body: { valid: true, target: 'packets', normalized: 'tcp.port == 443', parameters: 1 } })],
    ]);
    const { container } = renderAt('/captures/7/packets?filter=tcp.port%20%3D%3D%20443');
    expect(await screen.findByRole('link', { name: '3' })).toHaveAttribute('href', '/captures/7/packets/3');
    expect(calls[0]?.url).toContain('filter=tcp.port+%3D%3D+443');
    expect(screen.getByLabelText('Display filter')).toHaveValue('tcp.port == 443');
    expect(screen.getByText('192.0.2.10:41000')).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it('shows a packet as a protocol tree without payload', async () => {
    mockApi([
      ['GET', /\/captures\/7\/packets\/3$/, () => ({ body: packetDetail })],
      ['GET', /\/captures\/7$/, () => ({ body: sessionDetail })],
    ]);
    const { container } = renderAt('/captures/7/packets/3');
    expect(await screen.findByRole('heading', { name: 'Packet 3', level: 1 })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Next packet' })).toHaveAttribute('href', '/captures/7/packets/4');
    expect(screen.getByRole('link', { name: 'Previous packet' })).toHaveAttribute('href', '/captures/7/packets/2');
    expect(await axeViolations(container)).toEqual([]);
    expect(screen.getByText('IPV4')).toBeInTheDocument();
    expect(screen.getByText(/Payload bytes are never stored or shown/)).toBeInTheDocument();
  });

  it('offers no next packet after the last stored one', async () => {
    mockApi([
      ['GET', /\/captures\/7\/packets\/3$/, () => ({ body: packetDetail })],
      ['GET', /\/captures\/7$/, () => ({ body: { ...sessionDetail, packets_stored: 3 } })],
    ]);
    renderAt('/captures/7/packets/3');
    expect(await screen.findByRole('heading', { name: 'Packet 3', level: 1 })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('link', { name: 'Previous packet' })).toBeInTheDocument());
    expect(screen.queryByRole('link', { name: 'Next packet' })).not.toBeInTheDocument();
  });

  it('says when a packet does not exist', async () => {
    mockApi([]);
    renderAt('/captures/7/packets/999');
    expect(await screen.findByRole('alert')).toHaveTextContent('no such endpoint');
  });
});

describe('Alerts', () => {
  it('explains an alert and saves a triage decision', async () => {
    const { calls } = mockApi([
      ['GET', /\/captures\/7\/alerts\/2$/, () => ({ body: alert })],
      [
        'PATCH',
        /\/captures\/7\/alerts\/2$/,
        () => ({ body: { ...alert, status: 'false_positive', status_changed_at: '2026-10-04T11:00:00Z' } }),
      ],
    ]);
    const { container } = renderAt('/captures/7/alerts/2');
    expect(await screen.findByRole('heading', { name: 'Regular repeated connections', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/not proof of compromise/)).toBeInTheDocument();
    expect(screen.getByRole('rowheader', { name: 'mean interval seconds' })).toBeInTheDocument();
    expect(screen.getByText('software update and licence checks')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '41' })).toHaveAttribute('href', '/captures/7/flows/41');
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.selectOptions(screen.getByLabelText('New status'), 'false_positive');
    await userEvent.click(screen.getByRole('button', { name: 'Save status' }));
    expect(await screen.findByText('Status saved: false positive.')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ status: 'false_positive' });
  });

  it('filters the alert list by severity through the address', async () => {
    const { calls } = mockApi([
      ['GET', /\/rules$/, () => ({ body: rules })],
      ['GET', /\/captures\/7\/alerts\?/, () => ({ body: paged([alert]) })],
    ]);
    const { container, router } = renderAt('/captures/7/alerts');
    expect(await screen.findByRole('link', { name: 'Regular repeated connections' })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
    await userEvent.selectOptions(screen.getByLabelText('Severity'), 'high');
    await waitFor(() => expect(router.state.location.search).toBe('?severity=high'));
    await waitFor(() => expect(calls.some((c) => c.url.includes('severity=high'))).toBe(true));
  });
});

describe('Settings', () => {
  it('validates retention values before saving them', async () => {
    const { calls } = mockApi([
      ['GET', /\/settings\/retention$/, () => ({ body: { session_ttl_days: 30, max_packets_stored: 100000 } })],
      ['PUT', /\/settings\/retention$/, (call) => ({ body: call.body })],
      ['GET', /\/rules$/, () => ({ body: rules })],
      ['GET', /\/filters\/fields/, () => ({ body: [] })],
    ]);
    const { container } = renderAt('/settings');
    const ttl = await screen.findByLabelText('Keep captures for (days)');
    await userEvent.clear(ttl);
    await userEvent.type(ttl, '0');
    expect(screen.getByText('Enter a whole number from 1 to 3650.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save retention' })).toBeDisabled();
    await userEvent.clear(ttl);
    await userEvent.type(ttl, '7');
    await userEvent.click(screen.getByRole('button', { name: 'Save retention' }));
    expect(await screen.findByText(/Saved/)).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({ session_ttl_days: 7, max_packets_stored: 100000 });
    expect(await screen.findByText('Regular repeated connections')).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it('refuses an empty or non-numeric retention value instead of saving 0', async () => {
    const { calls } = mockApi([
      ['GET', /\/settings\/retention$/, () => ({ body: { session_ttl_days: 30, max_packets_stored: 100000 } })],
      ['GET', /\/rules$/, () => ({ body: rules })],
      ['GET', /\/filters\/fields/, () => ({ body: [] })],
    ]);
    renderAt('/settings');
    const packets = await screen.findByLabelText('Packets stored per capture');
    await userEvent.clear(packets);
    expect(screen.getByText('Enter a whole number from 0 to 1000000.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save retention' })).toBeDisabled();
    await userEvent.type(packets, '0');
    expect(screen.getByRole('button', { name: 'Save retention' })).toBeEnabled();
    const ttl = screen.getByLabelText('Keep captures for (days)');
    await userEvent.clear(ttl);
    expect(screen.getByRole('button', { name: 'Save retention' })).toBeDisabled();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('shows a not-found page for unknown addresses', async () => {
    mockApi([]);
    const { container } = renderAt('/nowhere');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });
});
