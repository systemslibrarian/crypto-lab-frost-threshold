import { defineConfig } from 'vitest/config';

// Unit tests for the attack exhibits live in src/**. The Playwright
// accessibility + functional suite lives in e2e/ and runs via
// `npm run test:a11y`; it must NOT be collected by Vitest.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
