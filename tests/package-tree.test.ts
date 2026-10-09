import { it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
// @ts-expect-error This Node packaging helper is deliberately independent of the browser compiler.
import { assertPackageTree } from '../scripts/package-tree.mjs';

it('accepts regular portable files and refuses links before packaging', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'bugpack-tree-'));
  try {
    const input = path.join(temp, 'input'), outside = path.join(temp, 'outside');
    await mkdir(input); await mkdir(outside);
    await writeFile(path.join(input, 'normal.txt'), 'safe');
    await writeFile(path.join(outside, 'secret.txt'), 'MUST-NOT-ENTER-PACKAGE');
    expect(await assertPackageTree(input)).toEqual({ files: 1, bytes: 4 });
    await symlink(outside, path.join(input, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    await expect(assertPackageTree(input)).rejects.toThrow(/links|junctions/);
    expect(await assertPackageTree(outside)).toEqual({ files: 1, bytes: 22 });
  } finally {
    expect(path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep)).toBe(true);
    await rm(temp, { recursive: true, force: true });
  }
});

it('refuses existing release archives and checksum files without altering retained output', async () => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'));
  const suffix = process.platform === 'win32' ? 'win-x64.zip' : 'linux-x64.tar.gz';
  for (const name of [`bugpack-${pkg.version}-${suffix}`, 'SHA256SUMS.txt']) {
    const temp = await mkdtemp(path.join(os.tmpdir(), 'bugpack-package-collision-'));
    try {
      const retained = Buffer.from('RETAINED-VERIFICATION-EVIDENCE');
      await writeFile(path.join(temp, name), retained);
      const child = spawnSync(process.execPath, ['scripts/package.mjs', '--output', temp], { encoding: 'utf8', timeout: 10000 });
      expect(child.status).not.toBe(0);
      expect(child.stderr).toContain('Package output already exists');
      expect(await readFile(path.join(temp, name))).toEqual(retained);
      expect(await readdir(temp)).toEqual([name]);
    } finally {
      expect(path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep)).toBe(true);
      await rm(temp, { recursive: true, force: true });
    }
  }
});

it('rejects outputs overlapping project inputs before creating anything', async () => {
  const before = await readdir('examples');
  const child = spawnSync(process.execPath, ['scripts/package.mjs', '--output', path.resolve('examples', 'must-not-be-created')], { encoding: 'utf8', timeout: 10000 });
  expect(child.status).not.toBe(0);
  expect(child.stderr).toContain('must not overlap project inputs');
  expect(await readdir('examples')).toEqual(before);
});
