import { builtinModules } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, '..');
const entry = resolve(projectRoot, 'src/cli/main.ts');
const outDir = resolve(projectRoot, 'dist/cli');
const builtins = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);

await build({
  root: projectRoot,
  configFile: false,
  clearScreen: false,
  logLevel: 'info',
  base: './',
  build: {
    target: 'node24',
    outDir,
    emptyOutDir: true,
    lib: {
      entry,
      formats: ['es'],
      fileName: () => 'bugpack.mjs',
    },
    rollupOptions: {
      external: (id) => builtins.has(id) || id.startsWith('node:'),
    },
  },
});
