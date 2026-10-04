import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { safeNext } from '../lib/auth';
import { alert, mockApi, paged, session, sessionAs, sessionDetail } from '../test/api';
import { axeViolations, renderAt } from '../test/render';

const signedOut = ['GET', /\/auth\/session$/, () => ({
  status: 401,
  body: { error: { code: 'unauthenticated', message: 'sign in first' } },
})] as const;

const users = [
  {
    id: 1,
    username: 'admin',
    role: 'admin',
    disabled: false,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    password_changed_at: '2026-10-01T00:00:00Z',
    last_login_at: '2026-10-04T10:00:00Z',
  },
  {
    id: 2,
    username: 'ana',
    role: 'analyst',
    disabled: false,
    created_at: '2026-10-02T00:00:00Z',
    updated_at: '2026-10-02T00:00:00Z',
    password_changed_at: '2026-10-02T00:00:00Z',
    last_login_at: null,
  },
];

describe('Sign-in', () => {
  it('sends signed-out visitors to sign in, then back where they were', async () => {
    let signedIn = false;
    const { calls } = mockApi([
      [
        'GET',
        /\/auth\/session$/,
        () =>
          signedIn
            ? { body: sessionAs('analyst', 'ana') }
            : { status: 401, body: { error: { code: 'unauthenticated', message: 'sign in first' } } },
      ],
      [
        'POST',
        /\/auth\/login$/,
        (call) => {
          const { password } = call.body as { password: string };
          if (password !== 'correct horse battery') {
            return { status: 401, body: { error: { code: 'invalid_credentials', message: 'no' } } };
          }
          signedIn = true;
          return { body: sessionAs('analyst', 'ana') };
        },
      ],
      ['GET', /\/captures\?/, () => ({ body: paged([session]) })],
    ]);
    const { container, router } = renderAt('/captures?page=1');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(router.state.location.search).toBe(`?next=${encodeURIComponent('/captures?page=1')}`);
    expect(await screen.findByRole('heading', { name: 'Sign in to FlowSentinel', level: 1 })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.type(screen.getByLabelText('Username'), 'ana');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong password');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The username or password is wrong');

    await userEvent.clear(screen.getByLabelText('Password'));
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/captures'));
    expect(router.state.location.search).toBe('?page=1');
    expect(await screen.findByRole('link', { name: 'detect-mixed.pcap' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /ana/ })).toHaveAttribute('href', '/account');
    // Sign-in sends no CSRF token: there is no session yet.
    expect(calls.filter((c) => c.method === 'POST').every((c) => c.csrf === null)).toBe(true);
  });

  it('only follows next to paths on this site', () => {
    expect(safeNext('/captures/7?page=2')).toBe('/captures/7?page=2');
    expect(safeNext('/audit?outcome=failure#top')).toBe('/audit?outcome=failure#top');
    for (const bad of [
      null,
      '',
      'https://evil.example',
      '//evil.example',
      '/\\evil.example',
      '/\t/evil.example',
      '/\n/evil.example',
      '/%2F/evil.example'.replace('%2F', '/'),
      'javascript:alert(1)',
    ]) {
      expect(safeNext(bad)).toBe('/');
    }
  });

  it('returns to sign-in when the session ends', async () => {
    let ended = false;
    mockApi([
      ['GET', /\/overview$/, () => (ended
        ? { status: 401, body: { error: { code: 'unauthenticated', message: 'sign in first' } } }
        : { body: { captures: 0, packets_processed: 0, flows_total: 0, alerts_total: 0, alerts_by_severity: {}, alerts_by_status: {}, open_alerts_by_severity: {}, recent_captures: [] } })],
      ['GET', /\/captures\?/, () => ({ status: 401, body: { error: { code: 'unauthenticated', message: 'sign in first' } } })],
    ]);
    const { router } = renderAt('/');
    expect(await screen.findByText('No captures yet')).toBeInTheDocument();
    ended = true;
    await userEvent.click(screen.getByRole('link', { name: 'Captures' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });

  it('signs out', async () => {
    let out = false;
    const { calls } = mockApi([
      ['GET', /\/auth\/session$/, () => (out ? signedOut[2]() : { body: sessionAs('admin') })],
      ['POST', /\/auth\/logout$/, () => {
        out = true;
        return { status: 204 };
      }],
      ['GET', /\/overview$/, () => ({ body: { captures: 0, packets_processed: 0, flows_total: 0, alerts_total: 0, alerts_by_severity: {}, alerts_by_status: {}, open_alerts_by_severity: {}, recent_captures: [] } })],
    ]);
    const { router } = renderAt('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(calls.find((c) => c.method === 'POST')?.csrf).toBe('c'.repeat(64));
  });
});

describe('Roles', () => {
  it('shows viewers what they may read and nothing they may not do', async () => {
    mockApi([
      ['GET', /\/auth\/session$/, () => ({ body: sessionAs('viewer', 'vic') })],
      ['GET', /\/captures\?/, () => ({ body: paged([session]) })],
      ['GET', /\/captures\/7\/alerts\/2$/, () => ({ body: alert })],
      ['GET', /\/settings\/retention$/, () => ({ body: { session_ttl_days: 30, max_packets_stored: 100000 } })],
      ['GET', /\/rules$/, () => ({ body: [] })],
      ['GET', /\/filters\/fields/, () => ({ body: [] })],
    ]);
    const captures = renderAt('/captures');
    expect(await screen.findByRole('link', { name: 'detect-mixed.pcap' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Capture file')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete/ })).not.toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).queryByRole('link', { name: 'Users' })).not.toBeInTheDocument();
    captures.unmount();

    const alertPage = renderAt('/captures/7/alerts/2');
    expect(await screen.findByText(/Analysts and admins can change it/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save status' })).not.toBeInTheDocument();
    alertPage.unmount();

    const settings = renderAt('/settings');
    expect(await screen.findByText('Only admins can change these settings.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save retention' })).not.toBeInTheDocument();
    settings.unmount();

    renderAt('/users');
    expect(await screen.findByRole('heading', { name: 'Not permitted', level: 1 })).toBeInTheDocument();
  });

  it('lets analysts import and triage but not delete', async () => {
    mockApi([
      ['GET', /\/auth\/session$/, () => ({ body: sessionAs('analyst', 'ana') })],
      ['GET', /\/captures\?/, () => ({ body: paged([session]) })],
      ['GET', /\/captures\/7$/, () => ({ body: sessionDetail })],
    ]);
    renderAt('/captures');
    expect(await screen.findByLabelText('Capture file')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete/ })).not.toBeInTheDocument();
  });

  it('sends the CSRF token with changes, not with reads', async () => {
    const { calls } = mockApi([
      ['GET', /\/captures\/7\/alerts\/2$/, () => ({ body: alert })],
      ['PATCH', /\/captures\/7\/alerts\/2$/, () => ({ body: { ...alert, status: 'resolved' } })],
    ]);
    renderAt('/captures/7/alerts/2');
    await userEvent.selectOptions(await screen.findByLabelText('New status'), 'resolved');
    await userEvent.click(screen.getByRole('button', { name: 'Save status' }));
    expect(await screen.findByText('Status saved: resolved.')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PATCH')?.csrf).toBe('c'.repeat(64));
    expect(calls.find((c) => c.method === 'GET')?.csrf).toBeNull();
  });
});

describe('Administration', () => {
  it('lists, creates and changes accounts', async () => {
    const { calls } = mockApi([
      ['GET', /\/users\?/, () => ({ body: paged(users) })],
      ['POST', /\/users$/, (call) => ({ status: 201, body: { ...users[1], id: 3, ...(call.body as object), password: undefined } })],
      ['PATCH', /\/users\/2$/, (call) => ({ body: { ...users[1], ...(call.body as object) } })],
      ['DELETE', /\/users\/2$/, () => ({ status: 204 })],
    ]);
    const { container } = renderAt('/users');
    const table = await screen.findByRole('region', { name: 'Accounts (table)' });
    expect(within(table).getByText('(you)')).toBeInTheDocument();
    // Admins cannot delete themselves from here.
    expect(screen.queryByRole('button', { name: 'Delete admin' })).not.toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);

    await userEvent.type(screen.getByLabelText('Username'), 'vic');
    await userEvent.type(screen.getByLabelText('Initial password'), 'a long initial password');
    await userEvent.selectOptions(screen.getByLabelText('Role'), 'viewer');
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByText('Created vic (viewer).')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      username: 'vic',
      password: 'a long initial password',
      role: 'viewer',
    });

    await userEvent.selectOptions(screen.getByLabelText('Role of ana'), 'admin');
    await userEvent.click(screen.getByRole('button', { name: 'Save role' }));
    await waitFor(() => expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ role: 'admin' }));

    await userEvent.click(screen.getByRole('button', { name: 'Delete ana' }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm delete ana' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true));
    // The password never appears on the page.
    expect(container.textContent).not.toContain('a long initial password');
  });

  it('shows the audit log with filters in the address', async () => {
    const { calls } = mockApi([
      [
        'GET',
        /\/audit\?/,
        () => ({
          body: paged([
            {
              id: 9,
              at: '2026-10-04T10:00:00.000Z',
              actor_id: null,
              actor: 'ana',
              action: 'auth.login',
              outcome: 'failure',
              target_type: null,
              target_id: null,
              client_ip: '192.0.2.10',
              details: { reason: 'wrong_password' },
            },
          ]),
        }),
      ],
    ]);
    const { container, router } = renderAt('/audit');
    expect(await screen.findByText('reason=wrong_password')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
    await userEvent.selectOptions(screen.getByLabelText('Outcome'), 'failure');
    await waitFor(() => expect(router.state.location.search).toBe('?outcome=failure'));
    await waitFor(() => expect(calls.some((c) => c.url.includes('outcome=failure'))).toBe(true));
  });

  it('changes your own password and keeps you signed in', async () => {
    const { calls } = mockApi([
      ['PUT', /\/auth\/password$/, () => ({ body: { ...sessionAs('admin'), csrf_token: 'd'.repeat(64) } })],
      ['GET', /\/overview$/, () => ({ body: { captures: 0, packets_processed: 0, flows_total: 0, alerts_total: 0, alerts_by_severity: {}, alerts_by_status: {}, open_alerts_by_severity: {}, recent_captures: [] } })],
    ]);
    const { container } = renderAt('/account');
    await userEvent.type(await screen.findByLabelText('Current password'), 'the old passphrase');
    await userEvent.type(screen.getByLabelText('New password'), 'a brand new passphrase');
    await userEvent.type(screen.getByLabelText('New password again'), 'a brand new passphrase!');
    expect(screen.getByText('The two new passwords differ.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change password' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('New password again'), '{Backspace}');
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText(/Password changed/)).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({
      current_password: 'the old passphrase',
      new_password: 'a brand new passphrase',
    });
    expect(await axeViolations(container)).toEqual([]);
  });
});
