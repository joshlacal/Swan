import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({ fallback: 'index.html' }),
    paths: { base: '/account' },
    csp: {
      mode: 'hash',
      directives: { 'default-src': ['none'], 'script-src': ['self'], 'style-src': ['self'], 'img-src': ['self'], 'connect-src': ['self'], 'font-src': ['self'], 'object-src': ['none'], 'base-uri': ['none'], 'frame-ancestors': ['none'] }
    },
    // `paths.base` prefixes emitted asset URLs; prerender entries are
    // route-relative and therefore stay at `/` here.
    prerender: { entries: ['/'] }
  }
};

export default config;
