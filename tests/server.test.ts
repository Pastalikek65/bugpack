import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

describe('local static distribution server', () => {
  it('serves owned static files, refuses traversal and methods, and sends privacy headers', async () => {
    const temp = await mkdtemp(path.join(os.tmpdir(), 'bugpack-server-'));
    const web = path.join(temp, 'web'); await mkdir(web);
    await writeFile(path.join(web, 'index.html'), '<!doctype html><title>BugPack fixture</title>');
    await writeFile(path.join(temp, 'outside.txt'), 'OUTSIDE-MUST-NOT-LEAK');
    const child = spawn(process.execPath, ['scripts/serve.mjs', '--root', web, '--port', '0'], { stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      const base = await new Promise<string>((resolve, reject) => {
        let data = ''; let error = ''; const timer = setTimeout(() => reject(new Error('server did not start: '+error)), 5000);
        child.stderr.on('data', b => { error += b.toString(); });
        child.stdout.on('data', b => { data += b.toString(); if (data.includes('\n')) { clearTimeout(timer); try { resolve(JSON.parse(data.split('\n')[0]).url); } catch (e) { reject(e); } } });
        child.on('exit', () => { clearTimeout(timer); reject(new Error('server exited before ready: '+error)); });
      });
      expect(new URL(base).hostname).toBe('127.0.0.1');
      const response = await fetch(base); expect(response.status).toBe(200); expect(await response.text()).toContain('BugPack fixture');
      expect(response.headers.get('content-security-policy')).toContain("connect-src 'none'");
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
      expect(response.headers.get('referrer-policy')).toBe('no-referrer');
      expect((await fetch(base+'/%2e%2e%2foutside.txt')).status).toBe(404);
      expect((await fetch(base+'/%00')).status).toBe(400);
      expect((await fetch(base, { method: 'POST', body: 'private input' })).status).toBe(405);
      expect((await fetch(base+'/missing.js')).status).toBe(404);
      expect((await fetch(base, { method: 'HEAD' })).status).toBe(200);
    } finally {
      child.kill(); await new Promise<void>(resolve => { if(child.exitCode!==null) resolve(); else child.once('exit',()=>resolve()); });
      const resolved = path.resolve(temp); expect(resolved.startsWith(path.resolve(os.tmpdir())+path.sep)).toBe(true); await rm(resolved, { recursive: true, force: true });
    }
  });
});
