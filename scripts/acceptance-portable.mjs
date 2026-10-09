import assert from 'node:assert/strict';
import { spawn, execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { readFile, writeFile, mkdir, stat, lstat, open, rmdir } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { inspectStaticPackage } from './inspect-static-package.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
assert.equal(args.length, 4, 'Usage: --app-root <root> --package <archive>');
assert.equal(args[0], '--app-root');
assert.equal(args[2], '--package');
const appRoot = path.resolve(args[1]);
const archive = path.resolve(args[3]);
assert.ok(appRoot.includes(' '), 'Portable qualification requires a path containing spaces.');
const artifact = path.join(root, 'artifacts', 'portable-' + randomUUID());
await mkdir(path.dirname(artifact), { recursive: true });
await mkdir(artifact);
const cwd = path.join(os.tmpdir(), 'bugpack portable cwd ' + randomUUID());
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const startedAt = new Date().toISOString();
let sourceCommit = null;
async function gitState() {
  const buffer = (args, limit) => execFileSync('git', args, { cwd: root, timeout: 10000, maxBuffer: limit, windowsHide: true });
  const paths = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 }).trim().split(/\r?\n/).filter(Boolean).sort();
  const commit = buffer(['rev-parse', 'HEAD'], 1024).toString('utf8').trim();
  const status = buffer(['status', '--porcelain=v1', '--untracked-files=all', '-z'], 4 * 1024 * 1024);
  const diff = buffer(['diff', '--binary', 'HEAD', '--'], 32 * 1024 * 1024);
  const untrackedPaths = buffer(['ls-files', '--others', '--exclude-standard', '-z'], 4 * 1024 * 1024).toString('utf8').split('\0').filter(Boolean).sort();
  assert.ok(untrackedPaths.length <= 2000, 'Source snapshot exceeds its file bound.');
  let total = 0;
  const untrackedFiles = [];
  for (const relative of untrackedPaths) {
    const absolute = path.resolve(root, relative);
    assert.ok(path.relative(root, absolute) !== '..' && !path.relative(root, absolute).startsWith('..' + path.sep) && !path.isAbsolute(path.relative(root, absolute)));
    const info = await lstat(absolute);
    assert.ok(info.isFile() && !info.isSymbolicLink() && info.size <= 64 * 1024 * 1024, 'Untracked source must be a bounded regular file.');
    total += info.size;
    assert.ok(total <= 128 * 1024 * 1024, 'Untracked source snapshot exceeds its byte bound.');
    const handle = await open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const opened = await handle.stat();
      assert.ok(opened.isFile() && opened.size === info.size && opened.dev === info.dev && opened.ino === info.ino, 'Source file changed while opening.');
      const digest = createHash('sha256');
      const chunk = Buffer.alloc(64 * 1024);
      let read = 0;
      while (read < opened.size) {
        const { bytesRead } = await handle.read(chunk, 0, Math.min(chunk.length, opened.size - read), read);
        assert.ok(bytesRead > 0, 'Source file shrank while reading.');
        digest.update(chunk.subarray(0, bytesRead));
        read += bytesRead;
      }
      const trailing = await handle.read(chunk, 0, 1, read);
      const after = await handle.stat();
      assert.ok(trailing.bytesRead === 0 && after.size === opened.size && after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs, 'Source file changed while reading.');
      untrackedFiles.push({ path: relative, bytes: read, sha256: digest.digest('hex') });
    } finally {
      await handle.close();
    }
  }
  return { commit, trackedChangedPaths: paths(['diff', '--name-only', 'HEAD']), untrackedPaths, statusSha256: hash(status), trackedDiffSha256: hash(diff), untrackedFiles };
}
let sourceState = null, before = null, appPackage = null;
const launcher = path.join(appRoot, process.platform === 'win32' ? 'start.cmd' : 'start.sh');
const steps = [];
let child;
let closeEvent;
let stdout = '', stderr = '';
const serverScript = path.join(appRoot, 'scripts/serve.mjs');
async function portOpen() {
  return await new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port: 4174 });
    let completed = false;
    const finish = open => { if (completed) return; completed = true; socket.destroy(); resolve(open); };
    socket.setTimeout(500, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}
function ownedWindowsChildren() {
  if (!child) return [];
  const literal = serverScript.replaceAll("'", "''");
  const script = `$ProgressPreference='SilentlyContinue'; $items=@(Get-CimInstance Win32_Process -Filter 'ParentProcessId=${child.pid}' | Where-Object { $_.Name -eq 'node.exe' -and $_.CommandLine.Contains('${literal}') } | Select-Object ProcessId,ParentProcessId,CommandLine,CreationDate); ConvertTo-Json -InputObject $items -Compress`;
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const bytes = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { timeout: 15000, maxBuffer: 512 * 1024, windowsHide: true });
  const rows = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
  assert.ok(Array.isArray(rows));
  return rows;
}
async function cleanup() {
  if (!child) return;
  if (process.platform === 'win32') {
    // Discover owned children even when startup failed before the HTTP probe.
    for (const row of ownedWindowsChildren()) {
      assert.equal(row.ParentProcessId, child.pid);
      assert.ok(Number.isSafeInteger(row.ProcessId) && row.ProcessId > 0);
      assert.ok(row.CommandLine.includes(serverScript));
      const result = spawnSync('taskkill.exe', ['/PID', String(row.ProcessId), '/F'], { timeout: 10000, maxBuffer: 512 * 1024, windowsHide: true });
      assert.equal(result.error, undefined);
      if (result.status !== 0) assert.equal(ownedWindowsChildren().some(item => item.ProcessId === row.ProcessId), false);
    }
    if (child.exitCode === null && child.signalCode === null) child.kill();
  } else if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
  }
  if (child.exitCode === null && child.signalCode === null) {
    const stopped = await Promise.race([closeEvent.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))]);
    if (!stopped) {
      child.kill('SIGKILL');
      await Promise.race([closeEvent, new Promise((_, reject) => setTimeout(() => reject(new Error('Owned launcher did not exit.')), 3000))]);
    }
  }
  for (let attempt = 0; attempt < 30; attempt++) {
    if (!await portOpen()) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Owned launcher port remained open after cleanup.');
}
try {
  await mkdir(cwd);
  sourceState = await gitState();
  sourceCommit = sourceState.commit;
  before = await inspectStaticPackage(archive, appRoot);
  appPackage = JSON.parse(await readFile(path.join(appRoot, 'package.json'), 'utf8'));
  const index = await readFile(path.join(appRoot, 'web/index.html'));
  assert.equal(await portOpen(), false, 'Port 4174 already belongs to another process.');
  if (process.platform === 'linux') assert.ok(((await stat(launcher)).mode & 0o111) !== 0, 'start.sh must be executable.');
  child = process.platform === 'win32'
    ? spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `""${launcher}""`], { cwd, windowsHide: true, windowsVerbatimArguments: true, stdio: ['ignore', 'pipe', 'pipe'] })
    : spawn(launcher, [], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  closeEvent = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  let outputLimitExceeded = false;
  const collect = (current, bytes) => {
    const combined = Buffer.concat([Buffer.from(current), bytes]);
    if (combined.length > 512 * 1024) { outputLimitExceeded = true; child.kill(); }
    return combined.subarray(0, 512 * 1024).toString('utf8');
  };
  child.stdout.on('data', bytes => { stdout = collect(stdout, bytes); });
  child.stderr.on('data', bytes => { stderr = collect(stderr, bytes); });
  const listening = await new Promise((resolve, reject) => {
    const fail = error => { clearTimeout(timeout); clearInterval(poll); reject(error); };
    const timeout = setTimeout(() => fail(new Error('Launcher did not announce startup.')), 15000);
    const poll = setInterval(() => {
      if (outputLimitExceeded) { fail(new Error('Launcher output exceeded its capture bound.')); return; }
      for (const line of stdout.split(/\r?\n/).filter(Boolean)) {
        try {
          const record = JSON.parse(line);
          if (record.status === 'listening') { clearTimeout(timeout); clearInterval(poll); resolve(record); return; }
        } catch { }
      }
      if (child.exitCode !== null || child.signalCode !== null) fail(new Error('Launcher exited before startup: ' + stderr));
    }, 50);
    child.once('error', fail);
    timeout.unref();
  });
  assert.equal(listening.url, 'http://127.0.0.1:4174');
  steps.push({ name: 'actual portable launcher announces loopback startup from path with spaces and outside CWD', status: 'passed' });
  const response = await fetch(listening.url, { signal: AbortSignal.timeout(5000), redirect: 'error' });
  assert.equal(response.status, 200);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), index);
  assert.ok(response.headers.get('content-security-policy').includes("connect-src 'none'"));
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  steps.push({ name: 'launcher serves exact packaged index bytes and security headers', status: 'passed' });
  const rejected = await fetch(listening.url, { method: 'POST', body: 'synthetic', signal: AbortSignal.timeout(5000), redirect: 'error' });
  assert.equal(rejected.status, 405);
  assert.equal(rejected.headers.get('allow'), 'GET, HEAD');
  steps.push({ name: 'portable server rejects evidence upload methods', status: 'passed' });
  const doctor = spawnSync(process.execPath, [path.join(appRoot, 'cli/bugpack.mjs'), 'doctor', '--json'], { cwd, windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 512 * 1024 });
  assert.equal(doctor.error, undefined);
  assert.equal(doctor.status, 0, doctor.stderr);
  assert.equal(doctor.stderr, '');
  const diagnostic = JSON.parse(doctor.stdout);
  assert.equal(diagnostic.ok, true);
  assert.equal(diagnostic.version, appPackage.version);
  steps.push({ name: 'bundled CLI doctor runs outside the application directory with distributed version', status: 'passed' });
  await cleanup();
  steps.push({ name: 'only owned launcher processes are stopped and loopback port closes', status: 'passed' });
  const after = await inspectStaticPackage(archive, appRoot);
  assert.deepEqual(after, before);
  assert.deepEqual(await gitState(), sourceState);
  steps.push({ name: 'complete package archive and extracted tree remain unchanged', status: 'passed' });
  await writeFile(path.join(artifact, 'startup.json'), JSON.stringify({ schemaVersion: 1, suite: 'actual-portable-startup', status: 'passed', version: appPackage.version, platform: process.platform + '/' + process.arch, sourceCommit, sourceState, startedAt, finishedAt: new Date().toISOString(), steps, packageInspection: before, launcher: { bytes: (await readFile(launcher)).length, sha256: hash(await readFile(launcher)) }, stdout, stderr, limits: ['Exact package startup on this reported host only; not an OS sandbox or other-platform proof.'] }, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ status: 'passed', artifact, steps: steps.length }));
} catch (error) {
  await cleanup().catch(cleanupError => { stderr += '\nCleanup failure: ' + String(cleanupError); });
  await writeFile(path.join(artifact, 'failure.json'), JSON.stringify({ schemaVersion: 1, suite: 'actual-portable-startup', status: 'failed', platform: process.platform + '/' + process.arch, version: appPackage?.version ?? null, startedAt, finishedAt: new Date().toISOString(), sourceCommit, sourceState, packageInspection: before, steps, stdout, stderr, error: String(error.stack ?? error) }, null, 2) + '\n', { flag: 'wx' });
  throw error;
} finally {
  await rmdir(cwd).catch(error => { if (error.code !== 'ENOENT') throw error; });
}
