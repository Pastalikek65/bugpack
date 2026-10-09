#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { unzipSync } from 'fflate';
import { inspectStaticPackage } from './inspect-static-package.mjs';
import { redactionPolicyFingerprint, validateRedactionPolicy } from '../src/core/policy.ts';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const decoder = new TextDecoder('utf-8', { fatal: true });
const LOG_BYTES = 4 * 1024 * 1024;
const HAR_ENTRIES = 1_000;
const BODY_CHUNK_CHARS = 1_024;
const MAX_CHILD_BUFFER = 4 * 1024 * 1024;
const MAX_BENCHMARK_ZIP_BYTES = 32 * 1024 * 1024;
const MAX_BENCHMARK_ZIP_INFLATED_BYTES = 32 * 1024 * 1024;
const MAX_BENCHMARK_ZIP_MEMBERS = 1_000;
const BASELINE_KEYS = [
  'access-token', 'access_token', 'api-key', 'api_key', 'apikey', 'authorization', 'aws-access-key-id',
  'aws_access_key_id', 'client-secret', 'client_secret', 'code', 'cookie', 'google-access-id',
  'google_access_id', 'jwt', 'key-pair-id', 'key_pair_id', 'oauth-code', 'oauth-token', 'oauth-verifier',
  'oauth_code', 'oauth_token', 'oauth_verifier', 'passwd', 'password', 'pwd', 'refresh-token',
  'refresh_token', 'secret', 'session', 'session-id', 'sessionid', 'set-cookie', 'sig', 'signature',
  'state', 'token', 'x-amz-credential', 'x-amz-security-token', 'x-amz-signature', 'x-goog-credential',
  'x-goog-security-token', 'x-goog-signature',
];

function parseArguments(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index++) {
    const option = args[index];
    if (option === '--help' || option === '-h') return { help: true, values };
    if (!['--app-root', '--package'].includes(option) || !args[index + 1] || args[index + 1].startsWith('--')) {
      throw new Error('Usage: node scripts/benchmark.mjs [--app-root <extracted-package> --package <package-archive>]');
    }
    if (values.has(option)) throw new Error(`Option ${option} may only be provided once.`);
    values.set(option, path.resolve(args[++index]));
  }
  if (values.has('--app-root') !== values.has('--package')) {
    throw new Error('Packaged CLI runs require both --app-root and --package.');
  }
  return { help: false, values };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function zipU16(bytes, offset, label) {
  assert.ok(Number.isSafeInteger(offset) && offset >= 0 && offset + 2 <= bytes.length, `truncated ZIP ${label}`);
  return bytes.readUInt16LE(offset);
}

function zipU32(bytes, offset, label) {
  assert.ok(Number.isSafeInteger(offset) && offset >= 0 && offset + 4 <= bytes.length, `truncated ZIP ${label}`);
  return bytes.readUInt32LE(offset);
}

const zipCrcTable = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[index] = value >>> 0;
  }
  return table;
})();

function zipCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = zipCrcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Bounds and validates all raw ZIP framing and inflation before fflate allocates output entries. */
function validateBoundedZip(archive) {
  assert.ok(archive.byteLength >= 22, 'ZIP archive is truncated');
  assert.ok(archive.byteLength <= MAX_BENCHMARK_ZIP_BYTES, `ZIP archive exceeds ${MAX_BENCHMARK_ZIP_BYTES} bytes`);
  const searchStart = Math.max(0, archive.byteLength - 22 - 0xffff);
  let eocd = -1;
  for (let offset = archive.byteLength - 22; offset >= searchStart; offset--) {
    if (zipU32(archive, offset, 'end record') !== 0x06054b50) continue;
    if (offset + 22 + zipU16(archive, offset + 20, 'comment length') === archive.byteLength) {
      eocd = offset;
      break;
    }
  }
  assert.notEqual(eocd, -1, 'ZIP end-of-central-directory record is missing');
  assert.ok(eocd < 20 || zipU32(archive, eocd - 20, 'ZIP64 locator') !== 0x07064b50, 'ZIP64 output is unsupported');

  const disk = zipU16(archive, eocd + 4, 'disk number');
  const centralDisk = zipU16(archive, eocd + 6, 'central disk number');
  const diskMembers = zipU16(archive, eocd + 8, 'disk member count');
  const memberCount = zipU16(archive, eocd + 10, 'member count');
  const centralBytes = zipU32(archive, eocd + 12, 'central directory size');
  const centralOffset = zipU32(archive, eocd + 16, 'central directory offset');
  assert.equal(disk, 0, 'multi-disk ZIP output is unsupported');
  assert.equal(centralDisk, 0, 'multi-disk ZIP output is unsupported');
  assert.equal(diskMembers, memberCount, 'ZIP disk and total member counts disagree');
  assert.ok(memberCount > 0 && memberCount <= MAX_BENCHMARK_ZIP_MEMBERS, `ZIP member count must be between 1 and ${MAX_BENCHMARK_ZIP_MEMBERS}`);
  assert.notEqual(memberCount, 0xffff, 'ZIP64 member count is unsupported');
  assert.notEqual(centralBytes, 0xffffffff, 'ZIP64 central size is unsupported');
  assert.notEqual(centralOffset, 0xffffffff, 'ZIP64 central offset is unsupported');
  assert.equal(centralOffset + centralBytes, eocd, 'ZIP central directory framing is inconsistent');

  const decoder = new TextDecoder('utf-8', { fatal: true });
  const entries = [];
  const names = new Set();
  const foldedNames = new Set();
  const localRanges = [];
  let cursor = centralOffset;
  let inflatedTotal = 0;
  for (let index = 0; index < memberCount; index++) {
    assert.ok(cursor + 46 <= eocd && zipU32(archive, cursor, 'central record signature') === 0x02014b50, 'malformed ZIP central directory record');
    const flags = zipU16(archive, cursor + 8, 'central flags');
    const method = zipU16(archive, cursor + 10, 'central compression method');
    const crc = zipU32(archive, cursor + 16, 'central CRC');
    const compressedBytes = zipU32(archive, cursor + 20, 'central compressed size');
    const uncompressedBytes = zipU32(archive, cursor + 24, 'central uncompressed size');
    const nameBytes = zipU16(archive, cursor + 28, 'central name length');
    const extraBytes = zipU16(archive, cursor + 30, 'central extra length');
    const commentBytes = zipU16(archive, cursor + 32, 'central comment length');
    const memberDisk = zipU16(archive, cursor + 34, 'central member disk');
    const localOffset = zipU32(archive, cursor + 42, 'local member offset');
    const recordEnd = cursor + 46 + nameBytes + extraBytes + commentBytes;
    assert.ok(recordEnd <= eocd, 'central directory record exceeds its bounds');
    assert.notEqual(compressedBytes, 0xffffffff, 'ZIP64 compressed size is unsupported');
    assert.notEqual(uncompressedBytes, 0xffffffff, 'ZIP64 uncompressed size is unsupported');
    assert.notEqual(localOffset, 0xffffffff, 'ZIP64 local offset is unsupported');
    assert.equal(memberDisk, 0, 'split ZIP members are unsupported');
    assert.equal(flags & ~0x800, 0, 'ZIP member uses unsupported flags or a data descriptor');
    assert.ok(method === 0 || method === 8, 'ZIP compression method is unsupported');
    assert.equal(extraBytes, 0, 'ZIP member extra fields are unsupported');
    assert.equal(commentBytes, 0, 'ZIP member comments are unsupported');
    const rawName = archive.subarray(cursor + 46, cursor + 46 + nameBytes);
    const name = decoder.decode(rawName);
    assert.ok(name.length > 0 && !name.endsWith('/') && !name.includes('\\') && !name.includes(':') && !name.startsWith('/'), 'ZIP member path is unsafe or not a file');
    assert.ok(!name.split('/').some((part) => !part || part === '.' || part === '..'), 'ZIP member path contains an unsafe segment');
    assert.ok(!names.has(name), `ZIP contains a duplicate member name: ${name}`);
    const foldedName = name.toLowerCase();
    assert.ok(!foldedNames.has(foldedName), `ZIP contains a case-colliding member name: ${name}`);
    names.add(name);
    foldedNames.add(foldedName);
    inflatedTotal += uncompressedBytes;
    assert.ok(inflatedTotal <= MAX_BENCHMARK_ZIP_INFLATED_BYTES, `ZIP declared contents exceed ${MAX_BENCHMARK_ZIP_INFLATED_BYTES} bytes`);

    assert.ok(localOffset + 30 <= centralOffset && zipU32(archive, localOffset, 'local header signature') === 0x04034b50, 'ZIP local header is invalid');
    const localFlags = zipU16(archive, localOffset + 6, 'local flags');
    const localMethod = zipU16(archive, localOffset + 8, 'local compression method');
    const localCrc = zipU32(archive, localOffset + 14, 'local CRC');
    const localCompressedBytes = zipU32(archive, localOffset + 18, 'local compressed size');
    const localUncompressedBytes = zipU32(archive, localOffset + 22, 'local uncompressed size');
    const localNameBytes = zipU16(archive, localOffset + 26, 'local name length');
    const localExtraBytes = zipU16(archive, localOffset + 28, 'local extra length');
    assert.equal(localFlags, flags, 'local and central flags disagree');
    assert.equal(localMethod, method, 'local and central compression methods disagree');
    assert.equal(localCrc, crc, 'local and central CRC values disagree');
    assert.equal(localCompressedBytes, compressedBytes, 'local and central compressed sizes disagree');
    assert.equal(localUncompressedBytes, uncompressedBytes, 'local and central uncompressed sizes disagree');
    assert.equal(localNameBytes, nameBytes, 'local and central name lengths disagree');
    assert.equal(localExtraBytes, 0, 'ZIP local extra fields are unsupported');
    const localNameStart = localOffset + 30;
    const dataStart = localNameStart + localNameBytes;
    const dataEnd = dataStart + compressedBytes;
    assert.ok(dataEnd <= centralOffset, 'ZIP member payload exceeds local data bounds');
    assert.ok(archive.subarray(localNameStart, dataStart).equals(rawName), 'local and central member paths disagree');

    const compressed = archive.subarray(dataStart, dataEnd);
    let expanded;
    if (method === 0) {
      expanded = compressed;
    } else {
      const result = inflateRawSync(compressed, { maxOutputLength: uncompressedBytes + 1, info: true });
      expanded = result.buffer;
      assert.equal(result.engine.bytesWritten, compressedBytes, `ZIP member ${name} has trailing or unconsumed compressed bytes`);
    }
    assert.equal(expanded.byteLength, uncompressedBytes, `ZIP member ${name} actual inflation differs from its declaration`);
    assert.equal(zipCrc32(expanded), crc, `ZIP member ${name} has an invalid CRC`);
    localRanges.push({ start: localOffset, end: dataEnd });
    entries.push({ name, bytes: Buffer.from(expanded) });
    cursor = recordEnd;
  }
  assert.equal(cursor, eocd, 'ZIP central directory member count or size is inconsistent');

  localRanges.sort((left, right) => left.start - right.start);
  let localCursor = 0;
  for (const range of localRanges) {
    assert.ok(range.start >= localCursor, 'ZIP local member records overlap');
    assert.equal(range.start, localCursor, 'ZIP local member records contain an unaccounted gap');
    localCursor = range.end;
  }
  assert.equal(localCursor, centralOffset, 'ZIP local records do not end at the central directory');
  return new Map(entries.map(({ name, bytes }) => [name, bytes]));
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function writeNewJson(filePath, value) {
  await writeFile(filePath, jsonBytes(value), { flag: 'wx' });
}

async function fileIdentity(filePath) {
  const info = await lstat(filePath);
  assert.equal(info.isSymbolicLink(), false, `Expected a regular file: ${filePath}`);
  assert.equal(info.isFile(), true, `Expected a regular file: ${filePath}`);
  const bytes = await readFile(filePath);
  assert.equal(bytes.byteLength, info.size, `File changed while being read: ${filePath}`);
  return { bytes: bytes.byteLength, sha256: sha256(bytes) };
}

function sameFileObject(left, right) {
  if (left.dev !== 0 && left.ino !== 0 && right.dev !== 0 && right.ino !== 0) {
    return left.dev === right.dev && left.ino === right.ino;
  }
  return left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function sameFileVersion(left, right) {
  return sameFileObject(left, right)
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

async function readBoundedRegularFile(filePath, maxBytes) {
  const pathStatBefore = await lstat(filePath);
  assert.equal(pathStatBefore.isSymbolicLink(), false, `Expected a regular file: ${filePath}`);
  assert.equal(pathStatBefore.isFile(), true, `Expected a regular file: ${filePath}`);
  assert.ok(pathStatBefore.size <= maxBytes, `File exceeds the ${maxBytes} byte read bound: ${filePath}`);

  const handle = await open(filePath, 'r');
  try {
    const handleStatBefore = await handle.stat();
    assert.equal(handleStatBefore.isFile(), true, `Expected a regular file: ${filePath}`);
    assert.ok(handleStatBefore.size <= maxBytes, `File exceeds the ${maxBytes} byte read bound: ${filePath}`);
    assert.ok(sameFileObject(pathStatBefore, handleStatBefore), `File changed before it could be opened: ${filePath}`);
    assert.equal(handleStatBefore.size, pathStatBefore.size, `File size changed before it could be opened: ${filePath}`);

    const bytes = Buffer.allocUnsafe(handleStatBefore.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.byteLength - offset), offset);
      assert.ok(bytesRead > 0, `File was truncated while being read: ${filePath}`);
      offset += bytesRead;
    }

    const growthProbe = Buffer.allocUnsafe(1);
    const { bytesRead: extraBytes } = await handle.read(growthProbe, 0, 1, offset);
    assert.equal(extraBytes, 0, `File grew beyond its bounded size while being read: ${filePath}`);

    const handleStatAfter = await handle.stat();
    const pathStatAfter = await lstat(filePath);
    assert.equal(pathStatAfter.isSymbolicLink(), false, `File became a symbolic link while being read: ${filePath}`);
    assert.equal(pathStatAfter.isFile(), true, `File ceased to be a regular file while being read: ${filePath}`);
    assert.ok(sameFileVersion(handleStatBefore, handleStatAfter), `File changed while being read: ${filePath}`);
    assert.ok(sameFileVersion(handleStatBefore, pathStatAfter), `File path changed while being read: ${filePath}`);
    assert.equal(offset, handleStatAfter.size, `File size changed while being read: ${filePath}`);
    return { data: bytes, identity: { bytes: bytes.byteLength, sha256: sha256(bytes) } };
  } finally {
    await handle.close();
  }
}

function gitOutput(args) {
  return execFileSync('git', ['-C', repositoryRoot, ...args], {
    encoding: 'utf8',
    timeout: 20_000,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

async function sourceStateSnapshot() {
  const commit = gitOutput(['rev-parse', 'HEAD']);
  const changed = gitOutput(['diff', '--name-only', 'HEAD']).split(/\r?\n/).filter(Boolean);
  const untracked = gitOutput(['ls-files', '--others', '--exclude-standard']).split(/\r?\n/).filter(Boolean);
  const relativePaths = [...new Set([...changed, ...untracked])].sort();
  const files = [];
  for (const relativePath of relativePaths) {
    const absolutePath = path.resolve(repositoryRoot, relativePath);
    const relativeCheck = path.relative(repositoryRoot, absolutePath);
    if (path.isAbsolute(relativeCheck) || relativeCheck === '..' || relativeCheck.startsWith(`..${path.sep}`)) {
      throw new Error('Git reported a source path outside the project root.');
    }
    try {
      files.push({ path: relativePath.replaceAll(path.sep, '/'), ...await fileIdentity(absolutePath) });
    } catch (error) {
      if (error?.code === 'ENOENT') files.push({ path: relativePath.replaceAll(path.sep, '/'), missing: true });
      else throw error;
    }
  }
  const payload = { commit, files };
  return { ...payload, sha256: sha256(Buffer.from(JSON.stringify(payload), 'utf8')) };
}

function cpuPayload(seed, length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let state = (seed + 0x6d2b79f5) >>> 0;
  let value = '';
  for (let index = 0; index < length; index++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    value += alphabet[state & 63];
  }
  return value;
}

function makeHar(literalValue) {
  const entries = Array.from({ length: HAR_ENTRIES }, (_, index) => {
    const token = `BENCH_HAR_TOKEN_SECRET_${index}`;
    const bodyToken = `BENCH_BODY_TOKEN_SECRET_${index}`;
    const payload = cpuPayload(index + 1, BODY_CHUNK_CHARS);
    let content;
    if (index % 3 === 0) {
      const text = JSON.stringify({ kind: 'synthetic-json', index, note: literalValue, token: bodyToken, chunk: payload });
      content = { size: Buffer.byteLength(text), mimeType: 'application/json', text };
    } else if (index % 3 === 1) {
      const text = new URLSearchParams({ note: literalValue, token: bodyToken, chunk: payload }).toString();
      content = { size: Buffer.byteLength(text), mimeType: 'application/x-www-form-urlencoded', text };
    } else {
      const text = Buffer.from(payload, 'utf8').toString('base64');
      content = { size: Buffer.byteLength(payload), mimeType: 'application/octet-stream', encoding: 'base64', text };
    }
    return {
      startedDateTime: '2026-10-09T09:00:00.000Z',
      time: 1,
      request: {
        method: index % 3 === 0 ? 'POST' : 'GET',
        url: `https://benchmark.invalid/items/${index}?token=${token}`,
        headers: [{ name: 'X-Benchmark-Run', value: 'synthetic' }],
      },
      response: { status: index % 2 ? 200 : 500, statusText: index % 2 ? 'OK' : 'Synthetic', headers: [], content },
    };
  });
  return JSON.stringify({ log: { version: '1.2', creator: { name: 'BugPack benchmark', version: '1' }, entries } });
}

function makeLog(literalValue) {
  const prefix = `INFO synthetic benchmark note=${literalValue} token=BENCH_LOG_TOKEN_SECRET payload=`;
  const line = `${prefix}${cpuPayload(0x51f15e, 2_048)}\n`;
  return line.repeat(Math.ceil(LOG_BYTES / line.length)).slice(0, LOG_BYTES);
}

function profilerSource() {
  return String.raw`'use strict';
const fs = require('node:fs');
const started = process.hrtime.bigint();
const cpuStarted = process.cpuUsage();
const rssAtStartBytes = process.memoryUsage().rss;
const profilePath = process.env.BUGPACK_BENCH_PROFILE;
process.on('exit', (exitCode) => {
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const cpu = process.cpuUsage(cpuStarted);
  const usage = process.resourceUsage();
  const rawMaxRSS = Number(usage.maxRSS);
  const available = Number.isFinite(rawMaxRSS) && rawMaxRSS > 0;
  const profile = {
    schemaVersion: 1,
    scope: 'CLI child process only',
    exitCode,
    elapsedMs,
    cpuUserMicroseconds: cpu.user,
    cpuSystemMicroseconds: cpu.system,
    cpuTotalMicroseconds: cpu.user + cpu.system,
    processResourceUsageMaxRSSRaw: Number.isFinite(rawMaxRSS) ? rawMaxRSS : null,
    maxRSSUnit: available ? 'KiB' : null,
    maxRSSBytes: available ? rawMaxRSS * 1024 : null,
    maxRSSAvailable: available,
    processMemoryUsageRssAtStartBytes: rssAtStartBytes,
    processMemoryUsageRssAtExitBytes: process.memoryUsage().rss,
  };
  try {
    fs.writeFileSync(profilePath, JSON.stringify(profile, null, 2) + '\n', { flag: 'wx' });
  } catch (error) {
    process.stderr.write('benchmark profiler could not save its result\n');
    process.exitCode = 1;
  }
});
`;
}

function artifactDirectoryName() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `benchmark-${timestamp}-${randomUUID()}`;
}

function cliPackageIdentity({ appRoot, packageArchive }) {
  return { appRoot, packageArchive };
}

function assertInspectedPackageMembers(inspection, packageIdentity, cliIdentity) {
  assert.ok(inspection && Array.isArray(inspection.files), 'static package inspection must return its verified file members');
  const members = new Map(inspection.files.map((file) => [file.name, file]));
  const packageMember = members.get('package.json');
  const cliMember = members.get('cli/bugpack.mjs');
  assert.ok(packageMember, 'package archive must contain package.json');
  assert.ok(cliMember, 'package archive must contain cli/bugpack.mjs');
  assert.deepEqual(
    { bytes: packageMember.bytes, sha256: packageMember.sha256 },
    packageIdentity,
    'appRoot package.json must exactly match the archive member',
  );
  assert.deepEqual(
    { bytes: cliMember.bytes, sha256: cliMember.sha256 },
    cliIdentity,
    'appRoot CLI entry must exactly match the archive member',
  );
}

function checkHelp() {
  process.stdout.write('Usage: node scripts/benchmark.mjs [--app-root <extracted-package> --package <package-archive>]\n');
  process.stdout.write('Runs one synthetic Node 24 CLI bundle workload and creates a fresh ignored artifacts/benchmark-* directory.\n');
}

const cliArgs = parseArguments(process.argv.slice(2));
if (cliArgs.help) {
  checkHelp();
  process.exit(0);
}
if (Number(process.versions.node.split('.')[0]) !== 24) {
  throw new Error('The benchmark requires Node.js 24.');
}

const appRoot = cliArgs.values.get('--app-root') ?? repositoryRoot;
const packageArchive = cliArgs.values.get('--package');
const packaged = Boolean(packageArchive);
const cliEntry = path.join(appRoot, packaged ? 'cli' : path.join('dist', 'cli'), 'bugpack.mjs');
const packagePath = path.join(appRoot, 'package.json');
const packageInspectionBefore = packaged ? await inspectStaticPackage(packageArchive, appRoot) : null;
const packageIdentityBefore = packaged ? { bytes: packageInspectionBefore.archiveBytes, sha256: packageInspectionBefore.archiveSha256 } : null;
const packageInfo = JSON.parse(await readFile(packagePath, 'utf8'));
assert.match(packageInfo.version, /^\d+\.\d+\.\d+$/);
const cliIdentityBefore = await fileIdentity(cliEntry);
const packageSourceIdentityBefore = await fileIdentity(packagePath);
if (packaged) {
  assertInspectedPackageMembers(packageInspectionBefore, packageSourceIdentityBefore, cliIdentityBefore);
}
const runRoot = path.join(repositoryRoot, 'artifacts', artifactDirectoryName());
await mkdir(path.dirname(runRoot), { recursive: true });
await mkdir(runRoot, { recursive: false });

const profilerPath = path.join(runRoot, 'profiler.cjs');
const profileResultPath = path.join(runRoot, 'profiler.json');
const harPath = path.join(runRoot, 'capture.har');
const logPath = path.join(runRoot, 'capture.log');
const reportPath = path.join(runRoot, 'report.json');
const policyPath = path.join(runRoot, 'policy.json');
const bundlePath = path.join(runRoot, 'bundle.zip');
const runId = randomUUID().replaceAll('-', '');
const literalValue = `BENCH_LITERAL_${runId}`;
const policy = {
  schemaVersion: 1,
  name: 'Synthetic performance run',
  bodyMode: 'supported',
  sensitiveKeys: BASELINE_KEYS,
  literalRules: [{ value: literalValue, replacement: '[BENCH MASKED]' }],
};
const report = {
  title: 'Synthetic BugPack CLI performance run',
  steps: `Open the generated local request ${literalValue}.`,
  expected: 'The synthetic request is processed locally.',
  actual: `The synthetic diagnostic contained ${literalValue} and token=BENCH_REPORT_TOKEN_SECRET.`,
  environment: `Node.js 24 synthetic benchmark ${runId}`,
};
const harText = makeHar(literalValue);
const logText = makeLog(literalValue);
const reportBytes = jsonBytes(report);
const policyBytes = jsonBytes(policy);
const inputs = [
  ['capture.har', harPath, Buffer.from(harText, 'utf8')],
  ['capture.log', logPath, Buffer.from(logText, 'utf8')],
  ['report.json', reportPath, reportBytes],
  ['policy.json', policyPath, policyBytes],
];
for (const [, filePath, bytes] of inputs) await writeFile(filePath, bytes, { flag: 'wx' });
await writeFile(profilerPath, profilerSource(), { flag: 'wx' });
const inputIdentitiesBefore = {};
for (const [name, filePath] of inputs) inputIdentitiesBefore[name] = await fileIdentity(filePath);

const sourceStateBefore = await sourceStateSnapshot();
const syntheticMarkers = [
  { label: 'custom-literal', value: literalValue, source: ['capture.har', 'capture.log', 'report.json', 'policy.json'] },
  { label: 'log-token', value: 'BENCH_LOG_TOKEN_SECRET', source: ['capture.log'] },
  { label: 'har-token', value: 'BENCH_HAR_TOKEN_SECRET_', source: ['capture.har'] },
  { label: 'body-token', value: 'BENCH_BODY_TOKEN_SECRET_', source: ['capture.har'] },
  { label: 'report-token', value: 'BENCH_REPORT_TOKEN_SECRET', source: ['report.json'] },
];
const positiveMarkerChecks = syntheticMarkers.map(({ label, value, source }) => {
  const joined = source.map((name) => {
    const item = inputs.find(([inputName]) => inputName === name);
    return item[2].toString('utf8');
  }).join('\n');
  return { label, sourceFiles: source, presentBefore: joined.includes(value) };
});
assert.equal(positiveMarkerChecks.every((item) => item.presentBefore), true, 'all synthetic markers must be present in their source inputs');

const cliCommandArgs = [
  '--require', profilerPath,
  cliEntry,
  'bundle',
  '--har', harPath,
  '--log', logPath,
  '--report', reportPath,
  '--policy', policyPath,
  '--out', bundlePath,
  '--reviewed',
  '--json',
];
const exactCommand = [process.execPath, ...cliCommandArgs];
const commandStartedAt = new Date().toISOString();
const commandStarted = performance.now();
const child = spawnSync(process.execPath, cliCommandArgs, {
  cwd: runRoot,
  encoding: 'utf8',
  env: { ...process.env, NODE_OPTIONS: '', BUGPACK_BENCH_PROFILE: profileResultPath },
  timeout: 180_000,
  windowsHide: true,
  maxBuffer: MAX_CHILD_BUFFER,
});
const parentElapsedMs = performance.now() - commandStarted;
const commandFinishedAt = new Date().toISOString();

const rawCliResult = {
  exitCode: child.status,
  signal: child.signal,
  spawnError: child.error ? { code: child.error.code ?? null, name: child.error.name } : null,
  stdout: child.stdout ?? '',
  stderr: child.stderr ?? '',
};
let parsedCliResult = null;
let profile = null;
let bundleIdentity = null;
let validation = { passed: false, checks: [] };
let negativeMarkerChecks = [];
let status = 'failed';
let error = null;
try {
  assert.equal(child.error, undefined, 'CLI process must start and finish within the timeout');
  assert.equal(child.status, 0, 'CLI bundle command must exit successfully');
  assert.equal(child.signal, null, 'CLI bundle command must not be interrupted');
  assert.equal(child.stderr, '', 'CLI JSON mode must not write diagnostics to stderr');
  parsedCliResult = JSON.parse(child.stdout);
  assert.equal(parsedCliResult.ok, true, 'CLI result must report success');
  assert.equal(parsedCliResult.command, 'bundle');
  assert.equal(parsedCliResult.includedFiles, 2);
  assert.equal(parsedCliResult.summarySchemaVersion, 2);
  profile = JSON.parse(await readFile(profileResultPath, 'utf8'));
  assert.equal(profile.exitCode, 0, 'child profiler exit code must match the successful CLI process');
  const boundedBundle = await readBoundedRegularFile(bundlePath, MAX_BENCHMARK_ZIP_BYTES);
  bundleIdentity = boundedBundle.identity;
  const bundleBytes = boundedBundle.data;
  const boundedZipEntries = validateBoundedZip(bundleBytes);
  const zipped = unzipSync(bundleBytes);
  const names = Object.keys(zipped).sort();
  assert.deepEqual(names, ['bug-report.md', 'evidence-001.har', 'evidence-002.log', 'processing-summary.json']);
  assert.deepEqual(names, [...boundedZipEntries.keys()].sort(), 'fflate member list must match the independently bounded ZIP parser');
  for (const name of names) {
    assert.ok(Buffer.from(zipped[name]).equals(boundedZipEntries.get(name)), `fflate output must match independently verified member bytes: ${name}`);
  }
  const textEntries = Object.fromEntries(Object.entries(zipped).map(([name, bytes]) => [name, decoder.decode(bytes)]));
  const summary = JSON.parse(textEntries['processing-summary.json']);
  const cleanedHar = JSON.parse(textEntries['evidence-001.har']);
  const canonicalPolicy = validateRedactionPolicy(JSON.parse(policyBytes.toString('utf8')));
  const canonicalPolicyId = redactionPolicyFingerprint(canonicalPolicy);
  const expectedSummaryPolicy = { schemaVersion: 1, id: canonicalPolicyId, bodyMode: canonicalPolicy.bodyMode };
  const expectedCliPolicy = { schemaVersion: 1, redactionPolicyId: canonicalPolicyId, bodyMode: canonicalPolicy.bodyMode };
  assert.deepEqual(Object.keys(summary).sort(), ['files', 'limitations', 'policy', 'schemaVersion']);
  assert.equal(summary.schemaVersion, 2, 'policy-bearing bundle summary must use schema version 2');
  assert.deepEqual(Object.keys(summary.policy).sort(), ['bodyMode', 'id', 'schemaVersion']);
  assert.deepEqual(summary.policy, expectedSummaryPolicy, 'ZIP policy identity must match the generated canonical policy');
  assert.deepEqual(Object.keys(parsedCliResult.policy).sort(), ['bodyMode', 'redactionPolicyId', 'schemaVersion']);
  assert.deepEqual(parsedCliResult.policy, expectedCliPolicy, 'CLI stdout policy identity must match the generated canonical policy');
  const allOutputText = Object.values(textEntries).join('\n');
  const forbiddenValues = syntheticMarkers.map((item) => item.value);
  for (const value of forbiddenValues) assert.equal(allOutputText.includes(value), false, `ZIP must omit synthetic marker ${value}`);
  negativeMarkerChecks = syntheticMarkers.map(({ label, value }) => ({ label, absentAfter: !allOutputText.includes(value) }));
  assert.equal(negativeMarkerChecks.every((item) => item.absentAfter), true, 'all synthetic markers must be absent from cleaned ZIP text');
  assert.equal(cleanedHar.log.entries.length, HAR_ENTRIES, 'all synthetic HAR entries must remain represented');
  const bodyKinds = { json: 0, form: 0, binaryOmitted: 0 };
  for (const [index, entry] of cleanedHar.log.entries.entries()) {
    const content = entry.response.content;
    if (index % 3 === 0) {
      assert.equal(content.mimeType, 'application/json', `HAR entry ${index} must retain a JSON response body`);
      assert.equal(typeof content.text, 'string', `HAR entry ${index} JSON body must be text`);
      assert.equal(content.encoding, undefined, `HAR entry ${index} JSON body must not be base64 encoded`);
      const body = JSON.parse(content.text);
      assert.equal(body.kind, 'synthetic-json');
      assert.equal(body.index, index);
      assert.equal(body.note, '[BENCH MASKED]');
      assert.equal(body.token, '[REDACTED]');
      assert.equal(body.chunk, cpuPayload(index + 1, BODY_CHUNK_CHARS), 'JSON chunk contents must match the generated fixture at this index');
      bodyKinds.json++;
    } else if (index % 3 === 1) {
      assert.equal(content.mimeType, 'application/x-www-form-urlencoded', `HAR entry ${index} must retain a form response body`);
      assert.equal(typeof content.text, 'string', `HAR entry ${index} form body must be text`);
      assert.equal(content.encoding, undefined, `HAR entry ${index} form body must not be base64 encoded`);
      const body = new URLSearchParams(content.text);
      assert.equal(body.get('note'), '[BENCH MASKED]');
      assert.equal(body.get('token'), '[REDACTED]');
      assert.equal(body.get('chunk'), cpuPayload(index + 1, BODY_CHUNK_CHARS), 'form chunk contents must match the generated fixture at this index');
      bodyKinds.form++;
    } else {
      assert.equal(content.mimeType, 'application/octet-stream', `HAR entry ${index} must identify its binary response body`);
      assert.equal(content.text, undefined, `HAR entry ${index} binary response body must be omitted`);
      assert.equal(content.encoding, undefined, `HAR entry ${index} binary encoding must be omitted`);
      bodyKinds.binaryOmitted++;
    }
  }
  assert.deepEqual(bodyKinds, { json: 334, form: 333, binaryOmitted: 333 }, 'each generated HAR index must retain or omit its expected body kind');
  const retainedBodies = bodyKinds.json + bodyKinds.form;
  const omittedBodies = bodyKinds.binaryOmitted;
  const harSummary = summary.files.find((item) => item.name === 'evidence-001.har');
  assert.ok(harSummary, 'summary must include the HAR evidence file');
  assert.ok(harSummary.omissions.some((item) => item.code === 'body-binary' && item.count === 333));
  assert.ok(textEntries['evidence-002.log'].includes('[BENCH MASKED]'));
  assert.ok(textEntries['bug-report.md'].includes('BENCH MASKED'));
  assert.ok(Number.isSafeInteger(parsedCliResult.outputBytes) && parsedCliResult.outputBytes === bundleIdentity.bytes);
  validation = {
    passed: true,
    checks: [
      'CLI exit status and JSON success',
      'bounded raw ZIP framing, duplicate path, inflation, CRC, and fflate agreement checks',
      'bundle entry names and exact schema 2 policy identity in ZIP summary and CLI stdout',
      'all 1,000 HAR entries retained',
      'per-index verification of 334 JSON, 333 form, and 333 omitted binary response bodies',
      'synthetic secret seeds present in source and absent from ZIP text',
      'log and report custom literal replacement visible',
      'reported output byte count matches the ZIP file',
    ],
    retainedBodies,
    omittedBodies,
    bodyKinds,
    zipEntries: names,
    summarySchemaVersion: summary.schemaVersion,
    policy: summary.policy,
    omissions: summary.files[0].omissions,
  };
  status = 'passed';
} catch (caught) {
  error = { name: caught?.name ?? 'Error', message: caught?.message ?? 'Benchmark validation failed.' };
}

const inputIdentitiesAfter = {};
for (const [name, filePath] of inputs) inputIdentitiesAfter[name] = await fileIdentity(filePath);
const inputsUnchanged = JSON.stringify(inputIdentitiesAfter) === JSON.stringify(inputIdentitiesBefore);
const sourceStateAfter = await sourceStateSnapshot();
const sourceUnchanged = JSON.stringify(sourceStateAfter) === JSON.stringify(sourceStateBefore);
const cliIdentityAfter = await fileIdentity(cliEntry);
const packageSourceIdentityAfter = await fileIdentity(packagePath);
let packageInspectionAfter = null;
let packageIdentityAfter = null;
if (packaged) {
  try {
    packageInspectionAfter = await inspectStaticPackage(packageArchive, appRoot);
    packageIdentityAfter = { bytes: packageInspectionAfter.archiveBytes, sha256: packageInspectionAfter.archiveSha256 };
    assertInspectedPackageMembers(packageInspectionAfter, packageSourceIdentityAfter, cliIdentityAfter);
    assert.deepEqual(packageInspectionAfter, packageInspectionBefore, 'verified package members must remain identical during the benchmark');
  } catch (caught) {
    status = 'failed';
    error ??= { name: caught?.name ?? 'PackageIntegrityError', message: caught?.message ?? 'Package verification failed after the CLI run.' };
  }
}
const cliUnchanged = JSON.stringify(cliIdentityAfter) === JSON.stringify(cliIdentityBefore)
  && JSON.stringify(packageSourceIdentityAfter) === JSON.stringify(packageSourceIdentityBefore)
  && JSON.stringify(packageIdentityAfter) === JSON.stringify(packageIdentityBefore);
if (!inputsUnchanged || !sourceUnchanged || !cliUnchanged) {
  status = 'failed';
  error ??= { name: 'IntegrityError', message: 'Source, CLI, package, or synthetic input identities changed during the benchmark.' };
}

const inputSummary = Object.fromEntries(Object.entries(inputIdentitiesBefore).map(([name, identity]) => [name, identity]));
const runRecord = {
  schemaVersion: 1,
  benchmark: 'bugpack-cli-local-synthetic-bundle',
  status,
  ...(error ? { error } : {}),
  startedAt: commandStartedAt,
  finishedAt: commandFinishedAt,
  source: {
    repositoryRoot,
    commit: sourceStateBefore.commit,
    sourceStateBefore,
    sourceStateAfter,
    unchangedDuringRun: sourceUnchanged,
    packageVersion: packageInfo.version,
    appRoot: path.resolve(appRoot),
    packaged,
    packageArchive: packageArchive ? { path: packageArchive, ...packageIdentityBefore } : null,
    packageInspection: packaged ? {
      before: packageInspectionBefore,
      after: packageInspectionAfter,
      unchangedDuringRun: JSON.stringify(packageInspectionAfter) === JSON.stringify(packageInspectionBefore),
    } : null,
    packageIdentityBefore: packageSourceIdentityBefore,
    packageIdentityAfter: packageSourceIdentityAfter,
    cliEntry: path.resolve(cliEntry),
    cliEntryBefore: cliIdentityBefore,
    cliEntryAfter: cliIdentityAfter,
    cliUnchangedDuringRun: cliUnchanged,
  },
  host: {
    node: process.version,
    nodeExecutable: process.execPath,
    platform: process.platform,
    architecture: process.arch,
    osRelease: os.release(),
    cpuModel: os.cpus()[0]?.model ?? null,
    logicalCpuCount: os.cpus().length,
    totalMemoryBytes: os.totalmem(),
  },
  workload: {
    kind: 'synthetic-only',
    harEntries: HAR_ENTRIES,
    logBytesTarget: LOG_BYTES,
    logBytesActual: inputIdentitiesBefore['capture.log'].bytes,
    harBytes: inputIdentitiesBefore['capture.har'].bytes,
    reportJsonBytes: reportBytes.byteLength,
    policyJsonBytes: policyBytes.byteLength,
    bodyChunkCharacters: BODY_CHUNK_CHARS,
    policyBodyMode: policy.bodyMode,
    bodyMix: { json: 334, form: 333, binaryOmitted: 333 },
    inputs: inputSummary,
    positiveMarkerChecks,
    negativeMarkerChecks,
    inputIdentitiesAfter,
    inputsUnchanged,
  },
  command: {
    argv: exactCommand,
    cwd: runRoot,
    timeoutMs: 180_000,
    startedAt: commandStartedAt,
    finishedAt: commandFinishedAt,
    parentElapsedMs,
    rawCliResult,
    parsedCliResult,
  },
  profiling: profile ? {
    file: profileResultPath,
    scope: profile.scope,
    maxRSSAvailable: profile.maxRSSAvailable,
    maxRSSUnit: profile.maxRSSUnit,
    maxRSSBytes: profile.maxRSSBytes,
    processMemoryUsageRssAtStartBytes: profile.processMemoryUsageRssAtStartBytes,
    processMemoryUsageRssAtExitBytes: profile.processMemoryUsageRssAtExitBytes,
    elapsedMs: profile.elapsedMs,
    cpuUserMicroseconds: profile.cpuUserMicroseconds,
    cpuSystemMicroseconds: profile.cpuSystemMicroseconds,
    cpuTotalMicroseconds: profile.cpuTotalMicroseconds,
  } : { file: profileResultPath, available: false },
  validation,
  output: bundleIdentity ? { file: bundlePath, ...bundleIdentity } : null,
  packageIdentity: cliPackageIdentity({ appRoot: path.resolve(appRoot), packageArchive: packageArchive ?? null }),
};
await writeNewJson(path.join(runRoot, 'benchmark.json'), runRecord);
process.stdout.write(`${JSON.stringify({ status, artifactDirectory: runRoot, parentElapsedMs, maxRSSBytes: runRecord.profiling.maxRSSBytes ?? null })}\n`);
if (status !== 'passed') process.exitCode = 1;
