import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  test: {
    include: ['src/**/*.{test,spec}.ts', 'tests/e2e/**/*.{test,spec}.ts'],
    exclude: ['node_modules', '.svelte-kit', 'tests/portal.spec.ts'],
    environment: 'node',
    isolate: true,
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
    pool: 'forks',
    poolOptions: {
      forks: {
        isolate: true,
        maxForks: 4,
        minForks: 1
      },
      threads: {
        isolate: true,
        maxThreads: 4,
        minThreads: 1
      }
    }
  }
});
