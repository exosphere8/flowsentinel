// End-to-end smoke test: the built dashboard served by api-server, against a
// real database. Imports the synthetic detection fixture through the UI and
// walks every page. See docs/dashboard.md for how to run it.
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

const FIXTURE = fileURLToPath(new URL('../../fixtures/pcap/detect-mixed.pcap', import.meta.url));
const MARKERS = ['FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER', 'FLOWSENTINEL-SECRET'];
// The server's first admin (FLOWSENTINEL_ADMIN_PASSWORD_FILE); see docs/dashboard.md.
const ADMIN = process.env.E2E_ADMIN_USERNAME ?? 'admin';
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? '';
const VIEWER_PASSWORD = 'viewer passphrase for the smoke test';

async function signIn(page: Page, username: string, password: string) {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login\?next=/);
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Overview');
}

/**
 * Collects console errors (including CSP violations), page errors and server
 * errors. The browser also logs every 4xx response as a console error; those
 * are expected here (an invalid filter is answered with 400), so they are
 * left out.
 */
function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (message) => {
    const text = message.text();
    // 4xx responses are expected: the session check before sign-in (401)
    // and an invalid filter (400).
    if (message.type() === 'error' && !/^Failed to load resource: .* status of 4\d\d/.test(text)) {
      errors.push(text);
    }
  });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('response', (response) => {
    if (response.status() >= 500) errors.push(`${response.status()} ${response.url()}`);
  });
  return errors;
}

async function expectNoPayload(page: Page) {
  const text = (await page.locator('body').innerText()).toUpperCase();
  for (const marker of MARKERS) {
    expect(text).not.toContain(marker);
  }
}

test('import a capture and walk the dashboard', async ({ page }) => {
  expect(ADMIN_PASSWORD, 'set E2E_ADMIN_PASSWORD').not.toBe('');
  const errors = watchErrors(page);

  await signIn(page, ADMIN, ADMIN_PASSWORD);

  // Import through the UI.
  await page.getByRole('link', { name: 'Captures', exact: true }).click();
  await page.getByLabel('Capture file').setInputFiles(FIXTURE);
  await page.getByRole('button', { name: 'Import' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('detect-mixed.pcap');
  await expect(page.getByRole('figure', { name: 'Packets by protocol' })).toBeVisible();
  const captureUrl = page.url();

  // Packets, with a display filter.
  await page.getByRole('link', { name: 'Packets', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Packets (table)' })).toBeVisible();
  await page.getByLabel('Display filter').fill('dns');
  await expect(page.getByText('Valid filter: dns')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page).toHaveURL(/filter=dns/);
  await expect(page.getByText(/of 14$/)).toBeVisible();
  // A DNS packet's protocol tree: it has a payload, which is never shown.
  await page.getByRole('region', { name: 'Packets (table)' }).getByRole('link').first().click();
  await expect(page.getByRole('heading', { name: /^Packet \d+$/ })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Protocol layers' })).toContainText('DNS');
  await expectNoPayload(page);

  // An invalid filter cannot be applied.
  await page.goto(`${captureUrl}/packets`);
  await page.getByLabel('Display filter').fill('tcp.port == ');
  await expect(page.getByLabel('Display filter')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByRole('button', { name: 'Apply' })).toBeDisabled();

  // Flows, filtered by their alerts.
  await page.goto(`${captureUrl}/flows?filter=${encodeURIComponent('alert.severity == high')}`);
  await expect(page.getByRole('region', { name: 'Flows (table)' })).toBeVisible();
  await page.getByRole('region', { name: 'Flows (table)' }).getByRole('link').first().click();
  await expect(page.getByRole('heading', { name: /^Flow \d+$/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Alerts citing this flow' })).toBeVisible();
  await expectNoPayload(page);

  // Alerts: the list, one alert, and triage.
  await page.goto(`${captureUrl}/alerts`);
  await expect(page.getByText(/heuristic indicators/).first()).toBeVisible();
  await expect(page.getByText('1–5 of 5')).toBeVisible();
  await page.getByRole('link', { name: 'Regular repeated connections' }).click();
  await expect(page.getByText(/not proof of compromise/).first()).toBeVisible();
  await page.getByLabel('New status').selectOption('false_positive');
  await page.getByRole('button', { name: 'Save status' }).click();
  await expect(page.getByText('Status saved: false positive.')).toBeVisible();
  await expectNoPayload(page);

  // Settings: retention and the rule catalog.
  await page.getByRole('link', { name: 'Settings' }).click();
  await expect(page.getByLabel('Keep captures for (days)')).toHaveValue(/\d+/);
  await expect(page.getByRole('region', { name: 'Detection rules (table)' }).getByRole('row')).toHaveCount(13);

  // The overview counts the import.
  await page.getByRole('link', { name: 'Overview' }).click();
  await expect(page.getByRole('list', { name: 'Totals' })).toContainText('138');

  // Accounts: create a viewer and check the audit log.
  await page.getByRole('link', { name: 'Users' }).click();
  await page.getByLabel('Username', { exact: true }).fill('smoke-viewer');
  await page.getByLabel('Initial password').fill(VIEWER_PASSWORD);
  await page.getByLabel('Role', { exact: true }).selectOption('viewer');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Created smoke-viewer (viewer).')).toBeVisible();
  await page.getByRole('link', { name: 'Audit log' }).click();
  await expect(page.getByRole('region', { name: 'Audit events (table)' })).toContainText('capture.import');
  await expect(page.getByRole('region', { name: 'Audit events (table)' })).toContainText('user.create');
  await expect(page.locator('body')).not.toContainText(VIEWER_PASSWORD);

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login/);

  expect(errors).toEqual([]);
});

test('a viewer reads but cannot change anything', async ({ page }) => {
  const errors = watchErrors(page);
  await signIn(page, 'smoke-viewer', VIEWER_PASSWORD);
  await page.getByRole('link', { name: 'Captures', exact: true }).click();
  await expect(page.getByRole('link', { name: 'detect-mixed.pcap' }).first()).toBeVisible();
  await expect(page.getByLabel('Capture file')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Delete/ })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Users' })).toHaveCount(0);
  await page.goto('/users');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Not permitted');
  // The API refuses too, whatever the page shows.
  const refused = await page.evaluate(async () => {
    const response = await fetch('/api/v1/users');
    return response.status;
  });
  expect(refused).toBe(403);
  expect(errors.filter((e) => !e.includes('403'))).toEqual([]);
});

test('the server sends a strict content security policy', async ({ request }) => {
  const response = await request.get('/');
  expect(response.ok()).toBe(true);
  const csp = response.headers()['content-security-policy'] ?? '';
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
});
