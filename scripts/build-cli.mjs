import { builtinModules } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, '..');
const entry = resolve(projectRoot, 'src/cli/main.ts');
const outDir = resolve(projectRoot, 'dist/cli');
const packageInfo = JSON.parse(readFileSync(resolve(projectRoot, 'package.json'), 'utf8'));
if (typeof packageInfo.version !== 'string' || !packageInfo.version) throw new Error('The package version is missing or invalid.');
const builtins = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);

await build({
  root: projectRoot,
  configFile: false,
  clearScreen: false,
  logLevel: 'info',
  base: './',
  define: { __BUGPACK_VERSION__: JSON.stringify(packageInfo.version) },
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
