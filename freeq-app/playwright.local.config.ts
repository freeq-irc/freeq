import { defineConfig, devices } from '@playwright/test';

/**
 * Same harness as playwright.config.ts, on port 5174 with its own vite
 * pointed at the local test server — so a dev server on 5173 aimed at a
 * live deployment never becomes the test target by accident.
 *
 * Requires freeq-server on 127.0.0.1:16799 (IRC) + 127.0.0.1:8080 (HTTP/WS).
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:5174',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run dev -- --port 5174',
    url: 'http://127.0.0.1:5174',
    reuseExistingServer: true,
    timeout: 15_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
