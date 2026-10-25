import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit({
    adapter: adapter({ fallback: 'index.html' }),
    paths: { base: '/account' },
    csp: {
      mode: 'hash',
      directives: { 'default-src': ['none'], 'script-src': ['self'], 'style-src': ['self'], 'img-src': ['self'], 'connect-src': ['self'], 'font-src': ['self'], 'object-src': ['none'], 'base-uri': ['none'], 'frame-ancestors': ['none'] }
    },
    prerender: { entries: ['/'] }
  })],
  test: {
    include: ['src/**/*.{test,spec}.ts', 'tests/e2e/**/*.{test,spec}.ts'],
    exclude: ['node_modules', '.svelte-kit', 'tests/portal.spec.ts'],
    environment: 'node',
    isolate: true,
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
    pool: 'forks',
    maxWorkers: 4
  }
});
