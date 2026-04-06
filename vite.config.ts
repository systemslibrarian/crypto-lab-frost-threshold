import { defineConfig } from 'vite';

const repoSlug = process.env.GITHUB_REPOSITORY?.split('/')[1];
const pagesBase = process.env.GITHUB_ACTIONS && repoSlug ? `/${repoSlug}/` : '/';

export default defineConfig({
  base: pagesBase
});
