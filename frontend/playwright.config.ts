import { defineConfig, devices } from '@playwright/test';

// The smoke tests run against a running api-server that serves the built
// dashboard and has a database; see docs/dashboard.md.
const baseURL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:18080';
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [['list']],
  use: {
    baseURL,
    trace: 'off',
    screenshot: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ...(executablePath ? { launchOptions: { executablePath } } : {}),
      },
    },
  ],
});
