import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-frost-threshold/',
  // Pin the preview port. Without this, `vite preview` binds its default 4173 —
  // a port a dozen labs in this fleet shared — so this lab could squat on a
  // sibling's harness. It also matches the BASE_URL fallback in
  // scripts/a11y-check.mjs, which only connects to a URL and never starts a
  // server. Callers that pin their own port (playwright.config.ts on 4640, the
  // verify:a11y script on 4400) pass --port explicitly and still override this.
  preview: { port: 4717, strictPort: true }
});
