import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, truncate, writeFile } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { zipSync } from 'fflate';

const MAX_COMPRESSED = 32 * 1024 * 1024;
const MAX_INFLATED = 128 * 1024 * 1024;
const MAX_MEMBERS = 1000;
const tempRoots: string[] = [];
const dynamicImport = (url: string) => import(/* @vite-ignore */ url) as Promise<{ inspectStaticPackage: (archivePath: string, appRoot: string) => Promise<Inspection> }>;
const inspectorUrl = new URL('../scripts/inspect-static-package.mjs', import.meta.url).href;

interface Inspection {
  archiveSha256: string;
  archiveBytes: number;
  files: Array<{ name: string; bytes: number; sha256: string }>;
}

interface ZipRecord {
  name: string;
  data: Uint8Array;
  method?: 0 | 8;
  localOffset?: number;
  centralCrc?: number;
  localCrc?: number;
  uncompressedSize?: number;
  externalAttributes?: number;
}

async function scratch(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'bugpack-static-inspection-'));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hash(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let value = 0; value < table.length; value++) {
    let crc = value;
    for (let bit = 0; bit < 8; bit++) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
    table[value] = crc >>> 0;
  }
  return table;
})();

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function makeStoreZip(records: ZipRecord[]): Uint8Array {
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;
  for (const record of records) {
    const name = bytes(record.name);
    const crc = crc32(record.data);
    const localCrc = record.localCrc ?? crc;
    const local = new Uint8Array(30 + name.length + record.data.length);
    const localView = new DataView(local.buffer);
    localView.setUint32(0, 0x04034b50, true);
    localView.setUint16(4, 20, true);
    localView.setUint16(6, 0x800, true);
    localView.setUint16(8, 0, true);
    localView.setUint32(14, localCrc, true);
    localView.setUint32(18, record.data.length, true);
    localView.setUint32(22, record.uncompressedSize ?? record.data.length, true);
    localView.setUint16(26, name.length, true);
    local.set(name, 30);
    local.set(record.data, 30 + name.length);
    localParts.push(local);

    const central = new Uint8Array(46 + name.length);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x02014b50, true);
    centralView.setUint16(4, record.externalAttributes ? 0x0314 : 20, true);
    centralView.setUint16(6, 20, true);
    centralView.setUint16(8, 0x800, true);
    centralView.setUint16(10, 0, true);
    centralView.setUint32(16, record.centralCrc ?? crc, true);
    centralView.setUint32(20, record.data.length, true);
    centralView.setUint32(24, record.uncompressedSize ?? record.data.length, true);
    centralView.setUint16(28, name.length, true);
    centralView.setUint32(38, record.externalAttributes ?? 0, true);
    centralView.setUint32(42, record.localOffset ?? offset, true);
    central.set(name, 46);
    centralParts.push(central);
    offset += local.length;
  }
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const centralOffset = offset;
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, records.length, true);
  eocdView.setUint16(10, records.length, true);
  eocdView.setUint32(12, centralSize, true);
  eocdView.setUint32(16, centralOffset, true);
  const output = new Uint8Array(centralOffset + centralSize + eocd.length);
  let position = 0;
  for (const part of [...localParts, ...centralParts, eocd]) {
    output.set(part, position);
    position += part.length;
  }
  return output;
}

function makeOverlappingZip(): Uint8Array {
  const prefix = 'bugpack-1.2.3-win-x64';
  const outerName = bytes(`${prefix}/outer.bin`);
  const innerName = bytes(`${prefix}/inner.bin`);
  const innerData = bytes('inner payload');
  const innerLocal = new Uint8Array(30 + innerName.length + innerData.length);
  const innerLocalView = new DataView(innerLocal.buffer);
  innerLocalView.setUint32(0, 0x04034b50, true);
  innerLocalView.setUint16(4, 20, true);
  innerLocalView.setUint16(6, 0x800, true);
  innerLocalView.setUint16(8, 0, true);
  innerLocalView.setUint32(14, crc32(innerData), true);
  innerLocalView.setUint32(18, innerData.length, true);
  innerLocalView.setUint32(22, innerData.length, true);
  innerLocalView.setUint16(26, innerName.length, true);
  innerLocal.set(innerName, 30);
  innerLocal.set(innerData, 30 + innerName.length);

  const outerData = innerLocal;
  const outerLocal = new Uint8Array(30 + outerName.length + outerData.length);
  const outerLocalView = new DataView(outerLocal.buffer);
  outerLocalView.setUint32(0, 0x04034b50, true);
  outerLocalView.setUint16(4, 20, true);
  outerLocalView.setUint16(6, 0x800, true);
  outerLocalView.setUint16(8, 0, true);
  outerLocalView.setUint32(14, crc32(outerData), true);
  outerLocalView.setUint32(18, outerData.length, true);
  outerLocalView.setUint32(22, outerData.length, true);
  outerLocalView.setUint16(26, outerName.length, true);
  outerLocal.set(outerName, 30);
  outerLocal.set(outerData, 30 + outerName.length);

  const centralRecord = (name: Uint8Array, data: Uint8Array, localOffset: number) => {
    const central = new Uint8Array(46 + name.length);
    const view = new DataView(central.buffer);
    view.setUint32(0, 0x02014b50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 20, true);
    view.setUint16(8, 0x800, true);
    view.setUint16(10, 0, true);
    view.setUint32(16, crc32(data), true);
    view.setUint32(20, data.length, true);
    view.setUint32(24, data.length, true);
    view.setUint16(28, name.length, true);
    view.setUint32(42, localOffset, true);
    central.set(name, 46);
    return central;
  };
  const centralParts = [
    centralRecord(outerName, outerData, 0),
    centralRecord(innerName, innerData, 30 + outerName.length),
  ];
  const centralOffset = outerLocal.length;
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, 2, true);
  eocdView.setUint16(10, 2, true);
  eocdView.setUint32(12, centralSize, true);
  eocdView.setUint32(16, centralOffset, true);
  const output = new Uint8Array(centralOffset + centralSize + eocd.length);
  output.set(outerLocal, 0);
  let offset = centralOffset;
  for (const central of centralParts) {
    output.set(central, offset);
    offset += central.length;
  }
  output.set(eocd, offset);
  return output;
}

function tarHeader(name: string, size: number, type: '0' | '5' | '2' = '0'): Uint8Array {
  const header = new Uint8Array(512);
  const nameBytes = bytes(name);
  if (nameBytes.length >= 100) throw new Error('Test tar name must fit in one header name field');
  header.set(nameBytes, 0);
  const setOctal = (offset: number, length: number, value: number) => {
    const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`;
    header.set(bytes(encoded), offset);
  };
  setOctal(100, 8, type === '5' ? 0o755 : 0o644);
  setOctal(108, 8, 0);
  setOctal(116, 8, 0);
  setOctal(124, 12, size);
  setOctal(136, 12, 1_700_000_000);
  header.fill(32, 148, 156);
  header[156] = type.charCodeAt(0);
  header.set(bytes('ustar\0'), 257);
  header.set(bytes('00'), 263);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.set(bytes(`${checksum.toString(8).padStart(6, '0')}\0 `), 148);
  return header;
}

function makeTarGz(entries: Array<{ name: string; data?: Uint8Array; type?: '0' | '5' | '2' }>): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const entry of entries) {
    const data = entry.data ?? new Uint8Array();
    blocks.push(tarHeader(entry.name, data.length, entry.type ?? '0'));
    if (data.length) {
      blocks.push(data);
      const padding = (512 - data.length % 512) % 512;
      if (padding) blocks.push(new Uint8Array(padding));
    }
  }
  blocks.push(new Uint8Array(1024));
  return gzipSync(Buffer.concat(blocks));
}

async function writeRoot(appRoot: string, entries: Record<string, string>): Promise<void> {
  for (const [name, text] of Object.entries(entries)) {
    const path = join(appRoot, ...name.split('/'));
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, text, 'utf8');
  }
}

async function createZipPackage(entries: Record<string, string>, options: { archivePrefix?: string; archiveEntries?: Record<string, string> } = {}) {
  const root = await scratch();
  const archiveName = 'bugpack-1.2.3-win-x64.zip';
  const prefix = basename(archiveName, '.zip');
  const appRoot = join(root, 'extracted');
  await mkdir(appRoot);
  await writeRoot(appRoot, entries);
  const zipEntries: Record<string, Uint8Array> = {};
  for (const [name, text] of Object.entries(options.archiveEntries ?? entries)) {
    zipEntries[`${options.archivePrefix ?? prefix}/${name}`] = bytes(text);
  }
  const archive = zipSync(zipEntries, { level: 6 });
  const archivePath = join(root, archiveName);
  await writeFile(archivePath, archive);
  return { archivePath, appRoot, archive };
}

async function createTarPackage(entries: Record<string, string>, overrides: Array<{ name: string; data?: Uint8Array; type?: '0' | '5' | '2' }> = []) {
  const root = await scratch();
  const archiveName = 'bugpack-1.2.3-linux-x64.tar.gz';
  const prefix = basename(archiveName, '.tar.gz');
  const appRoot = join(root, 'extracted');
  await mkdir(appRoot);
  await writeRoot(appRoot, entries);
  const names = new Set<string>([prefix]);
  for (const name of Object.keys(entries)) {
    let parent = name;
    while (parent.includes('/')) {
      parent = parent.slice(0, parent.lastIndexOf('/'));
      names.add(`${prefix}/${parent}`);
    }
  }
  const records: Array<{ name: string; data?: Uint8Array; type?: '0' | '5' | '2' }> = [...names].sort((a, b) => a.split('/').length - b.split('/').length).map((name) => ({ name: `${name}/`, type: '5' as const }));
  for (const [name, text] of Object.entries(entries)) records.push({ name: `${prefix}/${name}`, data: bytes(text), type: '0' as const });
  const archive = makeTarGz([...records, ...overrides]);
  const archivePath = join(root, archiveName);
  await writeFile(archivePath, archive);
  return { archivePath, appRoot, archive };
}

async function inspect(archivePath: string, appRoot: string): Promise<Inspection> {
  const { inspectStaticPackage } = await dynamicImport(inspectorUrl);
  return inspectStaticPackage(archivePath, appRoot);
}

describe('inspectStaticPackage', () => {
  it('binds a real ZIP member list and hashes to the extracted root tree', async () => {
    const entries = { 'package.json': '{"name":"portable"}', 'web/index.html': '<h1>BugPack</h1>', 'web/assets/app.js': 'window.app=1' };
    const { archivePath, appRoot, archive } = await createZipPackage(entries);
    const result = await inspect(archivePath, appRoot);

    expect(result.archiveBytes).toBe(archive.byteLength);
    expect(result.archiveSha256).toBe(hash(archive));
    expect(result.files).toEqual(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)).map(([name, text]) => ({ name, bytes: bytes(text).byteLength, sha256: hash(bytes(text)) })));
  });

  it('binds a real TAR.GZ member list and hashes to the extracted root tree', async () => {
    const entries = { 'package.json': '{"name":"portable"}', 'web/index.html': '<h1>Linux package</h1>', 'scripts/serve.mjs': 'process.exit(0)' };
    const { archivePath, appRoot, archive } = await createTarPackage(entries);
    const result = await inspect(archivePath, appRoot);
    expect(result.archiveBytes).toBe(archive.byteLength);
    expect(result.archiveSha256).toBe(hash(archive));
    expect(result.files.map((file) => file.name)).toEqual(Object.keys(entries).sort());
    expect(result.files.map((file) => file.sha256)).toEqual(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)).map(([, text]) => hash(bytes(text))));
  });

  it('rejects an archive with the wrong top-level package directory', async () => {
    const { archivePath, appRoot } = await createZipPackage({ 'package.json': '{}' }, { archivePrefix: 'different-root' });
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/top-level|archive root|prefix/i);
  });

  it('rejects changed and extra extracted files', async () => {
    const changed = await createZipPackage({ 'package.json': '{}' });
    await writeFile(join(changed.appRoot, 'package.json'), '{"changed":true}');
    await expect(inspect(changed.archivePath, changed.appRoot)).rejects.toThrow(/hash|size|match|differ/i);

    const extra = await createZipPackage({ 'package.json': '{}' });
    await writeFile(join(extra.appRoot, 'unexpected.txt'), 'extra');
    await expect(inspect(extra.archivePath, extra.appRoot)).rejects.toThrow(/match|extra|file list/i);
  });

  it('rejects archive-only extra entries and unsafe traversal paths', async () => {
    const archiveOnly = await createZipPackage({ 'package.json': '{}' }, { archiveEntries: { 'package.json': '{}', 'extra.txt': 'not in root' } });
    await expect(inspect(archiveOnly.archivePath, archiveOnly.appRoot)).rejects.toThrow(/match|file list/i);

    const root = await scratch();
    const archivePath = join(root, 'bugpack-1.2.3-win-x64.zip');
    const appRoot = join(root, 'extracted');
    await mkdir(appRoot);
    await writeFile(archivePath, makeStoreZip([{ name: 'bugpack-1.2.3-win-x64/../escape.txt', data: bytes('escape') }]));
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/unsafe|traversal|path/i);
  });

  it('rejects duplicate paths, overlapping ZIP records, bad CRCs, and symlink entries', async () => {
    const root = await scratch();
    const appRoot = join(root, 'extracted');
    await mkdir(appRoot);
    const archivePath = join(root, 'bugpack-1.2.3-win-x64.zip');
    const prefix = 'bugpack-1.2.3-win-x64';
    const name = `${prefix}/package.json`;

    await writeFile(archivePath, makeStoreZip([{ name, data: bytes('a') }, { name, data: bytes('b') }]));
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/duplicate/i);

    await writeFile(archivePath, makeOverlappingZip());
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/overlap|local record/i);

    await writeFile(archivePath, makeStoreZip([{ name, data: bytes('corrupt'), localCrc: 1, centralCrc: 1 }]));
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/crc|checksum/i);

    await writeFile(archivePath, makeStoreZip([{ name, data: bytes('link'), externalAttributes: (0xa1ff << 16) >>> 0 }]));
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/symlink|link|nonregular/i);

    await writeFile(archivePath, makeStoreZip([{ name, data: bytes('reparse'), externalAttributes: 0x400 }]));
    await expect(inspect(archivePath, appRoot)).rejects.toThrow(/reparse/i);
  });

  it('rejects TAR symlinks and duplicate members', async () => {
    const entries = { 'package.json': '{}' };
    const duplicate = await createTarPackage(entries, [{ name: 'bugpack-1.2.3-linux-x64/package.json', data: bytes('second') }]);
    await expect(inspect(duplicate.archivePath, duplicate.appRoot)).rejects.toThrow(/duplicate/i);

    const symlink = await createTarPackage(entries, [{ name: 'bugpack-1.2.3-linux-x64/link', data: new Uint8Array(), type: '2' }]);
    await expect(inspect(symlink.archivePath, symlink.appRoot)).rejects.toThrow(/symlink|nonregular|type/i);
  });

  it('enforces archive member, compressed byte, and inflated byte limits', async () => {
    const root = await scratch();
    const appRoot = join(root, 'extracted');
    await mkdir(appRoot);
    const zipPath = join(root, 'bugpack-1.2.3-win-x64.zip');
    const many = Array.from({ length: MAX_MEMBERS + 1 }, (_, index) => ({ name: `bugpack-1.2.3-win-x64/f${index}.txt`, data: bytes('x') }));
    await writeFile(zipPath, makeStoreZip(many));
    await expect(inspect(zipPath, appRoot)).rejects.toThrow(/member|entry|limit/i);

    await truncate(zipPath, MAX_COMPRESSED + 1);
    await expect(inspect(zipPath, appRoot)).rejects.toThrow(/compressed|archive.*limit|size/i);

    const gzBomb = gzipSync(Buffer.alloc(1024 * 1024));
    const repeatedGzip = Buffer.concat(Array.from({ length: 129 }, () => gzBomb));
    const tarPath = join(root, 'bugpack-1.2.3-linux-x64.tar.gz');
    await writeFile(tarPath, repeatedGzip);
    await expect(inspect(tarPath, appRoot)).rejects.toThrow(/inflated|output|large|buffer/i);
  });
});
