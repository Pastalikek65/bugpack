import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifact = path.join(root, 'artifacts', 'lighthouse');
await mkdir(artifact, { recursive: true });

const server = spawn(process.execPath, [path.join(root, 'scripts', 'serve.mjs'), '--root', path.join(root, 'dist'), '--port', '0'], {
  cwd: root,
  stdio: ['ignore', 'pipe', 'pipe'],
});

try {
  const url = await new Promise((resolve, reject) => {
    let output = '';
    let errors = '';
    const timer = setTimeout(() => reject(new Error(`Static server did not start: ${errors}`)), 10_000);
    server.stderr.on('data', chunk => { errors += chunk.toString(); });
    server.stdout.on('data', chunk => {
      output += chunk.toString();
      if (!output.includes('\n')) return;
      clearTimeout(timer);
      try { resolve(JSON.parse(output.split('\n')[0]).url); }
      catch (error) { reject(error); }
    });
    server.once('exit', code => { clearTimeout(timer); reject(new Error(`Static server exited with ${code}: ${errors}`)); });
  });

  const reportPath = path.join(artifact, 'report.json');
  const cli = path.join(root, 'node_modules', 'lighthouse', 'cli', 'index.js');
  const args = [cli, url, '--output=json', `--output-path=${reportPath}`, '--only-categories=performance,accessibility,best-practices', `--chrome-flags=--headless${process.platform === 'linux' ? ' --no-sandbox' : ''}`, '--quiet'];
  const result = await new Promise((resolve, reject) => {
    const processHandle = spawn(process.execPath, args, {
      cwd: root,
      env: { ...process.env, CHROME_PATH: chromium.executablePath() },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    processHandle.stdout.on('data', chunk => { output += chunk.toString(); });
    processHandle.stderr.on('data', chunk => { output += chunk.toString(); });
    processHandle.once('error', reject);
    processHandle.once('exit', code => resolve({ code, output }));
  });
  assert.equal(result.code, 0, `Lighthouse failed: ${result.output.slice(-4000)}`);
  const report = JSON.parse(await readFile(reportPath, 'utf8'));
  assert.equal(report.runtimeError, undefined, 'Lighthouse returned a runtime error.');
  const scores = Object.fromEntries(['performance', 'accessibility', 'best-practices'].map(name => [name, report.categories[name]?.score]));
  for (const [name, score] of Object.entries(scores)) assert.equal(typeof score, 'number', `Missing Lighthouse ${name} score.`);
  await writeFile(path.join(artifact, 'summary.json'), JSON.stringify({ url, scores }, null, 2) + '\n');
  console.log(JSON.stringify({ status: 'measured', scores, artifact }));
} finally {
  server.kill();
}
