import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E tests for freeq web app.
 *
 * Nothing needs starting by hand. Global setup builds freeq-server from this
 * checkout, gives it a fresh temporary data directory, starts it and vite, and
 * refuses the run outright if 16799, 8080 or 5173 are already taken. Global
 * teardown stops both and deletes the directory.
 *
 * Run:
 *   cd freeq-app && npm run test:e2e:desktop
 */
export default defineConfig({
  testDir: './e2e',
  // The deep scrollback walk seeds thousands of rows against the server's
  // flood limits, so it costs minutes by construction. Excluded from the
  // default run; `npm run test:e2e:deep` runs it deliberately.
  testIgnore: process.env.FREEQ_E2E_DEEP ? [] : ['**/scrollback-deep.spec.ts'],
  globalSetup: './e2e/rig/global-setup.ts',
  globalTeardown: './e2e/rig/global-teardown.ts',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // tests share one server, run sequentially
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'mobile',
      use: {
        ...devices['iPhone 14'],
        // Use Chromium instead of WebKit to avoid needing WebKit binary
        browserName: 'chromium',
      },
    },
  ],
});
