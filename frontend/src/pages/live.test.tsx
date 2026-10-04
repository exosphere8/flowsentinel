import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { LiveStatus } from '../api/client';
import { mockApi, sessionAs } from '../test/api';
import { axeViolations, renderAt } from '../test/render';

const idle: LiveStatus = {
  state: 'idle',
  interface: null,
  filter: null,
  promiscuous: false,
  limits: null,
  started_by: null,
  started_at: null,
  elapsed_seconds: 0,
  packets_seen: 0,
  packets_written: 0,
  bytes_written: 0,
  dropped_backpressure: 0,
  dropped_by_system: 0,
  stop_reason: null,
  capture_id: null,
  error: null,
};

const interfaces = [
  { name: 'eth0', description: null, addresses: ['192.0.2.10'], loopback: false, up: true },
  { name: 'lo', description: null, addresses: ['127.0.0.1'], loopback: true, up: true },
];

describe('Live capture', () => {
  it('needs explicit authorization and starts with promiscuous mode off', async () => {
    let state: LiveStatus = idle;
    const { calls } = mockApi([
      ['GET', /\/live\/interfaces$/, () => ({ body: interfaces })],
      ['GET', /\/live\/captures\/current$/, () => ({ body: state })],
      [
        'POST',
        /\/live\/captures$/,
        () => {
          state = { ...idle, state: 'finished', interface: 'eth0', filter: 'tcp port 443', stop_reason: 'time_limit_reached', capture_id: 9, packets_written: 120 };
          return { status: 202, body: { ...idle, state: 'capturing', interface: 'eth0', filter: 'tcp port 443', packets_written: 3 } };
        },
      ],
    ]);
    const { container } = renderAt('/live');
    const start = await screen.findByRole('button', { name: 'Start capture' });
    expect(start).toBeDisabled();
    expect(screen.getByLabelText('Promiscuous mode')).not.toBeChecked();
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.type(screen.getByLabelText('Capture filter (BPF, optional)'), 'tcp port 443');
    await userEvent.click(screen.getByLabelText(/I own this network/));
    await userEvent.click(start);
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      interface: 'eth0',
      filter: 'tcp port 443',
      promiscuous: false,
      max_seconds: 60,
      max_packets: 100000,
      authorized: true,
    });
    expect(calls.find((c) => c.method === 'POST')?.csrf).toBe('c'.repeat(64));
    // Polling picks up the finished capture.
    expect(await screen.findByRole('link', { name: 'capture 9' }, { timeout: 3000 })).toHaveAttribute('href', '/captures/9');
    expect(screen.getByText('time limit reached')).toBeInTheDocument();
  });

  it('explains when live capture is off', async () => {
    mockApi([
      ['GET', /\/live\/interfaces$/, () => ({ status: 503, body: { error: { code: 'live_capture_disabled', message: 'off' } } })],
      ['GET', /\/live\/captures\/current$/, () => ({ body: idle })],
    ]);
    renderAt('/live');
    expect(await screen.findByText(/FLOWSENTINEL_LIVE_CAPTURE=true/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start capture' })).not.toBeInTheDocument();
  });

  it('is for admins only', async () => {
    mockApi([['GET', /\/auth\/session$/, () => ({ body: sessionAs('analyst', 'ana') })]]);
    renderAt('/live');
    expect(await screen.findByRole('heading', { name: 'Not permitted', level: 1 })).toBeInTheDocument();
  });
});
