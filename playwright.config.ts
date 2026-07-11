import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the accessibility (axe-core) gate.
 * Serves the built app via `vite preview` on a unique port and scans it in a
 * single Chromium project in the dark (default) color scheme.
 */

const PORT = 4223;
const BASE = '/crypto-lab-frost-threshold/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
