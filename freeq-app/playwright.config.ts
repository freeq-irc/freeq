import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E tests for freeq web app.
 *
 * Requires:
 *   - freeq-server running on 127.0.0.1:16799 (IRC) + 127.0.0.1:8080 (HTTP/WS)
 *   - vite dev server on 127.0.0.1:5173 (or use webServer config below)
 *
 * Run:
 *   cd freeq-app && npx playwright test
 */
export default defineConfig({
  testDir: './e2e',
  // The deep scrollback walk seeds thousands of rows against the server's
  // flood limits, so it costs minutes by construction. Excluded from the
  // default run; `npm run test:e2e:deep` runs it deliberately.
  testIgnore: process.env.FREEQ_E2E_DEEP ? [] : ['**/scrollback-deep.spec.ts'],
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
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: true,
    timeout: 15_000,
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
