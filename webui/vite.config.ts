// vite.config.ts
//
// Build the WebUI as a static SPA under dist/. The build output
// (index.html + assets/) gets copied to webroot/ by the package
// script (see /scripts/build_webui.sh).

import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';

export default defineConfig({
  plugins: [vue()],
  base: './',  // relative base so the WebUI works under any path
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
      output: {
        // Stable chunk names so the build is reproducible.
        entryFileNames: 'assets/index.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]',
      },
    },
  },
});
