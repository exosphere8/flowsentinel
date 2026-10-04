// End-to-end smoke test: the built dashboard served by api-server, against a
// real database. Imports the synthetic detection fixture through the UI and
// walks every page. See docs/dashboard.md for how to run it.
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

const FIXTURE = fileURLToPath(new URL('../../fixtures/pcap/detect-mixed.pcap', import.meta.url));
const MARKERS = ['FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER', 'FLOWSENTINEL-SECRET'];

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
  const errors = watchErrors(page);

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Overview');

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

  expect(errors).toEqual([]);
});

test('the server sends a strict content security policy', async ({ request }) => {
  const response = await request.get('/');
  expect(response.ok()).toBe(true);
  const csp = response.headers()['content-security-policy'] ?? '';
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
});
