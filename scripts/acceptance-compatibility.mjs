import assert from 'node:assert/strict';
import { constants as fsConstants } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import { inspectStaticPackage } from './inspect-static-package.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LEGACY_COMMIT = 'de47154576f9e260fa6de286d785bbca56c1f77d';
const POLICY_SOURCE_COMMIT = '20c6cc524dc0cd4153c0ae718a606507c6ee9aad';
const LEGACY_INPUTS = [
  {
    kind: 'har',
    name: 'evidence-001.har',
    gitPath: 'examples/outputs/evidence-001.har',
    bytes: 1155,
    sha256: '796f8d7abec7d4d18b7cad94525fbc2150118e4c4f1c5564f748ef7968c092f5',
  },
  {
    kind: 'log',
    name: 'evidence-002.log',
    gitPath: 'examples/outputs/evidence-002.log',
    bytes: 166,
    sha256: 'a3614ad683a392378b4ea997dfcf13db27f2ecca9373b7cf24056e67fb1dee4c',
  },
];
const FIXTURE_FILE = 'examples/policy-v1.json';
const PROVENANCE_FILE = 'examples/policy-v1.provenance.json';
const MAX_FIXTURE_BYTES = 64 * 1024;
const MAX_SOURCE_DIFF_BYTES = 32 * 1024 * 1024;
const MAX_SOURCE_STATUS_BYTES = 4 * 1024 * 1024;
const MAX_UNTRACKED_COUNT = 2000;
const MAX_UNTRACKED_FILE_BYTES = 64 * 1024 * 1024;
const MAX_UNTRACKED_TOTAL_BYTES = 128 * 1024 * 1024;
const MAX_CLI_BYTES = 8 * 1024 * 1024;
const MAX_CLI_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS = 16;
const MAX_ARCHIVE_EXPANDED_BYTES = 128 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function decodeUtf8(bytes, label) {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8.`);
  }
}

function parseArguments(args) {
  assert.equal(args.length, 4, 'Usage: node scripts/acceptance-compatibility.mjs --app-root <fresh-package-root> --package <archive>');
  assert.equal(args[0], '--app-root', 'Usage: node scripts/acceptance-compatibility.mjs --app-root <fresh-package-root> --package <archive>');
  assert.equal(args[2], '--package', 'Usage: node scripts/acceptance-compatibility.mjs --app-root <fresh-package-root> --package <archive>');
  const appRoot = path.resolve(args[1]);
  const archivePath = path.resolve(args[3]);
  assert.ok(appRoot.includes(' '), 'Compatibility qualification requires a fresh package path containing spaces.');
  assert.ok(archivePath.includes(' '), 'Compatibility qualification requires an archive path containing spaces.');
  return { appRoot, archivePath };
}

async function readBoundedRegular(filePath, limit, label) {
  let handle;
  try {
    const before = await lstat(filePath);
    assert.ok(!before.isSymbolicLink() && before.isFile(), `${label} must be a regular file.`);
    assert.ok(before.size <= limit, `${label} exceeds its ${limit}-byte read limit.`);
    handle = await open(filePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    assert.ok(opened.isFile() && opened.size === before.size, `${label} changed while it was opened.`);
    assert.ok(opened.size <= limit, `${label} exceeds its ${limit}-byte read limit.`);
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
      assert.ok(bytesRead > 0, `${label} changed while it was read.`);
      offset += bytesRead;
    }
    const extra = Buffer.alloc(1);
    const { bytesRead: trailingBytes } = await handle.read(extra, 0, 1, offset);
    const after = await handle.stat();
    assert.equal(trailingBytes, 0, `${label} grew while it was read.`);
    assert.equal(after.size, opened.size, `${label} changed while it was read.`);
    return bytes;
  } finally {
    await handle?.close();
  }
}

async function writeNew(filePath, bytes) {
  await writeFile(filePath, bytes, { flag: 'wx' });
}

async function writeJsonNew(filePath, value) {
  await writeNew(filePath, Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8'));
}

function gitBuffer(args, maxBuffer) {
  return execFileSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer, windowsHide: true });
}

function gitText(args, maxBuffer = 1024 * 1024) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer, windowsHide: true }).trim();
}

function safeSourcePath(relativePath) {
  const absolute = path.resolve(root, relativePath);
  const relative = path.relative(root, absolute);
  assert.ok(relative && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative), 'Git returned a path outside the source root.');
  return absolute;
}

async function captureSourceIdentity() {
  const commit = gitText(['rev-parse', 'HEAD']);
  const statusBytes = gitBuffer(['status', '--porcelain=v1', '--untracked-files=all', '-z'], MAX_SOURCE_STATUS_BYTES);
  const trackedDiff = gitBuffer(['diff', '--binary', 'HEAD', '--'], MAX_SOURCE_DIFF_BYTES);
  const untrackedBytes = gitBuffer(['ls-files', '--others', '--exclude-standard', '-z'], MAX_SOURCE_STATUS_BYTES);
  const untrackedPaths = decodeUtf8(untrackedBytes, 'Git untracked-path output').split('\0').filter(Boolean).sort();
  assert.ok(untrackedPaths.length <= MAX_UNTRACKED_COUNT, `Source has more than ${MAX_UNTRACKED_COUNT} untracked files.`);
  let untrackedTotal = 0;
  const untrackedFiles = [];
  for (const relativePath of untrackedPaths) {
    const absolute = safeSourcePath(relativePath);
    const statBefore = await lstat(absolute);
    assert.ok(!statBefore.isSymbolicLink() && statBefore.isFile(), `Untracked source path is not a regular file: ${relativePath}`);
    assert.ok(statBefore.size <= MAX_UNTRACKED_FILE_BYTES, `Untracked source file exceeds ${MAX_UNTRACKED_FILE_BYTES} bytes: ${relativePath}`);
    untrackedTotal += statBefore.size;
    assert.ok(untrackedTotal <= MAX_UNTRACKED_TOTAL_BYTES, `Untracked source files exceed ${MAX_UNTRACKED_TOTAL_BYTES} bytes.`);
    const bytes = await readBoundedRegular(absolute, MAX_UNTRACKED_FILE_BYTES, `Untracked source file ${relativePath}`);
    untrackedFiles.push({ path: relativePath, bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  return {
    commit,
    dirty: statusBytes.byteLength > 0,
    statusBytes: statusBytes.byteLength,
    statusSha256: sha256(statusBytes),
    statusBase64: statusBytes.toString('base64'),
    trackedDiffBytes: trackedDiff.byteLength,
    trackedDiffSha256: sha256(trackedDiff),
    untrackedFiles,
  };
}

async function ensureDirectory(directory, label) {
  try {
    const info = await lstat(directory);
    assert.ok(!info.isSymbolicLink() && info.isDirectory(), `${label} must be a regular directory.`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    await mkdir(directory);
  }
}

function u16(bytes, offset, label) {
  assert.ok(Number.isSafeInteger(offset) && offset >= 0 && offset + 2 <= bytes.length, `${label} has truncated 16-bit ZIP metadata.`);
  return bytes.readUInt16LE(offset);
}

function u32(bytes, offset, label) {
  assert.ok(Number.isSafeInteger(offset) && offset >= 0 && offset + 4 <= bytes.length, `${label} has truncated 32-bit ZIP metadata.`);
  return bytes.readUInt32LE(offset);
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function decodeZipName(bytes, label) {
  const name = decodeUtf8(bytes, `${label} ZIP member name`);
  assert.ok(name && name.length <= 255 && !/[\\/:\u0000-\u001f\u007f]/.test(name) && name !== '.' && name !== '..', `${label} has an unsafe ZIP member name.`);
  return name;
}

function inspectReviewedBundle(archive, label) {
  assert.ok(Buffer.isBuffer(archive) && archive.byteLength >= 22, `${label} ZIP is truncated.`);
  assert.ok(archive.byteLength <= MAX_ARCHIVE_BYTES, `${label} ZIP exceeds ${MAX_ARCHIVE_BYTES} bytes.`);
  const searchStart = Math.max(0, archive.byteLength - 22 - 0xffff);
  let eocd = -1;
  for (let offset = archive.byteLength - 22; offset >= searchStart; offset--) {
    if (archive.readUInt32LE(offset) !== 0x06054b50) continue;
    if (offset + 22 + u16(archive, offset + 20, label) === archive.byteLength) {
      eocd = offset;
      break;
    }
  }
  assert.ok(eocd >= 0, `${label} ZIP end-of-central-directory record is missing.`);
  if (eocd >= 20) assert.notEqual(u32(archive, eocd - 20, label), 0x07064b50, `${label} ZIP64 archives are unsupported.`);
  const disk = u16(archive, eocd + 4, label);
  const centralDisk = u16(archive, eocd + 6, label);
  const diskEntries = u16(archive, eocd + 8, label);
  const entryCount = u16(archive, eocd + 10, label);
  const centralSize = u32(archive, eocd + 12, label);
  const centralOffset = u32(archive, eocd + 16, label);
  const archiveCommentLength = u16(archive, eocd + 20, label);
  assert.equal(disk, 0, `${label} split ZIP archives are unsupported.`);
  assert.equal(centralDisk, 0, `${label} split ZIP archives are unsupported.`);
  assert.equal(diskEntries, entryCount, `${label} multi-disk ZIP archives are unsupported.`);
  assert.ok(entryCount > 0 && entryCount <= MAX_ARCHIVE_MEMBERS, `${label} ZIP has an invalid member count.`);
  assert.notEqual(entryCount, 0xffff, `${label} ZIP64 member counts are unsupported.`);
  assert.notEqual(centralSize, 0xffffffff, `${label} ZIP64 central directories are unsupported.`);
  assert.notEqual(centralOffset, 0xffffffff, `${label} ZIP64 central directories are unsupported.`);
  assert.equal(archiveCommentLength, 0, `${label} ZIP comments are unsupported.`);
  assert.equal(centralOffset + centralSize, eocd, `${label} ZIP central directory bounds are inconsistent.`);

  const entries = [];
  const names = new Set();
  const foldedNames = new Set();
  const localRanges = [];
  let expandedTotal = 0;
  let cursor = centralOffset;
  for (let index = 0; index < entryCount; index++) {
    assert.ok(cursor + 46 <= eocd && u32(archive, cursor, label) === 0x02014b50, `${label} ZIP central directory record is malformed.`);
    const madeBy = u16(archive, cursor + 4, label);
    const versionNeeded = u16(archive, cursor + 6, label);
    const flags = u16(archive, cursor + 8, label);
    const method = u16(archive, cursor + 10, label);
    const checksum = u32(archive, cursor + 16, label);
    const compressedSize = u32(archive, cursor + 20, label);
    const uncompressedSize = u32(archive, cursor + 24, label);
    const nameLength = u16(archive, cursor + 28, label);
    const extraLength = u16(archive, cursor + 30, label);
    const commentLength = u16(archive, cursor + 32, label);
    const startDisk = u16(archive, cursor + 34, label);
    const externalAttributes = u32(archive, cursor + 38, label);
    const localOffset = u32(archive, cursor + 42, label);
    const recordEnd = cursor + 46 + nameLength + extraLength + commentLength;
    assert.ok(recordEnd <= eocd, `${label} ZIP central record exceeds its bounds.`);
    assert.notEqual(compressedSize, 0xffffffff, `${label} ZIP64 members are unsupported.`);
    assert.notEqual(uncompressedSize, 0xffffffff, `${label} ZIP64 members are unsupported.`);
    assert.notEqual(localOffset, 0xffffffff, `${label} ZIP64 members are unsupported.`);
    assert.equal(startDisk, 0, `${label} split ZIP members are unsupported.`);
    assert.equal(flags & ~0x0800, 0, `${label} ZIP uses encryption, a data descriptor, or unsupported flags.`);
    assert.ok((method === 0 || method === 8) && versionNeeded <= 20, `${label} ZIP method or version is unsupported.`);
    assert.equal(extraLength, 0, `${label} ZIP extra fields are unsupported.`);
    assert.equal(commentLength, 0, `${label} ZIP member comments are unsupported.`);
    const rawName = archive.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = decodeZipName(rawName, label);
    assert.equal(Buffer.from(name, 'utf8').equals(rawName), true, `${label} ZIP member name encoding is not canonical UTF-8.`);
    assert.equal(names.has(name), false, `${label} ZIP contains a duplicate member: ${name}`);
    const folded = name.toLocaleLowerCase('en-US');
    assert.equal(foldedNames.has(folded), false, `${label} ZIP contains case-colliding members: ${name}`);
    names.add(name);
    foldedNames.add(folded);
    const hostOs = madeBy >>> 8;
    const unixType = (externalAttributes >>> 16) & 0xf000;
    if (hostOs === 3 && unixType) assert.equal(unixType, 0x8000, `${label} ZIP contains a nonregular member.`);
    assert.equal((externalAttributes & 0x400) !== 0, false, `${label} ZIP contains a reparse-point member.`);
    assert.equal((externalAttributes & 0x10) !== 0, false, `${label} ZIP directory entries are unsupported.`);
    expandedTotal += uncompressedSize;
    assert.ok(expandedTotal <= MAX_ARCHIVE_EXPANDED_BYTES, `${label} ZIP expanded bytes exceed ${MAX_ARCHIVE_EXPANDED_BYTES}.`);

    assert.ok(localOffset + 30 <= centralOffset && u32(archive, localOffset, label) === 0x04034b50, `${label} ZIP local header is invalid.`);
    const localVersion = u16(archive, localOffset + 4, label);
    const localFlags = u16(archive, localOffset + 6, label);
    const localMethod = u16(archive, localOffset + 8, label);
    const localChecksum = u32(archive, localOffset + 14, label);
    const localCompressedSize = u32(archive, localOffset + 18, label);
    const localUncompressedSize = u32(archive, localOffset + 22, label);
    const localNameLength = u16(archive, localOffset + 26, label);
    const localExtraLength = u16(archive, localOffset + 28, label);
    assert.equal(localVersion, versionNeeded, `${label} ZIP local and central versions disagree.`);
    assert.equal(localFlags, flags, `${label} ZIP local and central flags disagree.`);
    assert.equal(localMethod, method, `${label} ZIP local and central methods disagree.`);
    assert.equal(localChecksum, checksum, `${label} ZIP local and central CRC values disagree.`);
    assert.equal(localCompressedSize, compressedSize, `${label} ZIP local and central compressed sizes disagree.`);
    assert.equal(localUncompressedSize, uncompressedSize, `${label} ZIP local and central expanded sizes disagree.`);
    assert.equal(localNameLength, nameLength, `${label} ZIP local and central member names disagree.`);
    assert.equal(localExtraLength, 0, `${label} ZIP local extra fields are unsupported.`);
    const nameStart = localOffset + 30;
    const dataStart = nameStart + localNameLength;
    const dataEnd = dataStart + compressedSize;
    assert.ok(dataEnd <= centralOffset && archive.subarray(nameStart, dataStart).equals(rawName), `${label} ZIP local member bounds or name are invalid.`);
    localRanges.push({ start: localOffset, end: dataEnd });
    entries.push({ name, method, checksum, compressedSize, uncompressedSize, dataStart });
    cursor = recordEnd;
  }
  assert.equal(cursor, eocd, `${label} ZIP central directory size or entry count is inconsistent.`);

  localRanges.sort((left, right) => left.start - right.start);
  let localCursor = 0;
  for (const range of localRanges) {
    assert.ok(range.start >= localCursor, `${label} ZIP local member records overlap.`);
    assert.equal(range.start, localCursor, `${label} ZIP local member records contain an unaccounted gap.`);
    localCursor = range.end;
  }
  assert.equal(localCursor, centralOffset, `${label} ZIP local records do not end at the central directory.`);

  const files = new Map();
  for (const entry of entries) {
    const compressed = archive.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
    let expanded;
    try {
      expanded = entry.method === 0
        ? Buffer.from(compressed)
        : inflateRawSync(compressed, { maxOutputLength: entry.uncompressedSize + 1 });
    } catch {
      throw new Error(`${label} ZIP member could not be safely inflated: ${entry.name}`);
    }
    assert.equal(expanded.byteLength, entry.uncompressedSize, `${label} ZIP member size differs from its declaration: ${entry.name}`);
    assert.equal(crc32(expanded), entry.checksum, `${label} ZIP member CRC is invalid: ${entry.name}`);
    files.set(entry.name, expanded);
  }
  return files;
}

function assertMemberNames(files, label) {
  assert.deepEqual([...files.keys()].sort(), ['bug-report.md', 'evidence-001.har', 'evidence-002.log', 'processing-summary.json'], `${label} ZIP members differ from the expected text bundle.`);
}

function assertResultOk(result, expectedCommand) {
  assert.equal(result.status, 0, `${expectedCommand} exited with ${result.status}: ${result.stderrText}`);
  assert.equal(result.stderr.byteLength, 0, `${expectedCommand} wrote unexpected stderr.`);
  assert.equal(result.response?.ok, true, `${expectedCommand} did not return a successful JSON response.`);
  if (expectedCommand) assert.equal(result.response.command, expectedCommand);
}

async function assertMissing(filePath, label) {
  try {
    await lstat(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  assert.fail(`${label} unexpectedly exists.`);
}

async function main() {
  const { appRoot, archivePath } = parseArguments(process.argv.slice(2));
  const nodeMajor = Number(/^v?(\d+)/.exec(process.versions.node)?.[1] ?? 0);
  assert.equal(nodeMajor, 24, 'Compatibility qualification requires a Node.js 24 parent and CLI runtime.');

  const artifactParent = path.join(root, 'artifacts');
  await ensureDirectory(artifactParent, 'Artifact directory');
  const artifactRoot = path.join(artifactParent, `compatibility-${randomUUID()}`);
  await mkdir(artifactRoot);
  const inputsDirectory = path.join(artifactRoot, 'inputs');
  const outputsDirectory = path.join(artifactRoot, 'outputs');
  const stepsDirectory = path.join(artifactRoot, 'steps');
  await Promise.all([mkdir(inputsDirectory), mkdir(outputsDirectory), mkdir(stepsDirectory)]);

  const startedAt = new Date().toISOString();
  const cliPath = path.resolve(appRoot, 'cli', 'bugpack.mjs');
  const checks = [];
  const childRuns = [];
  const inputs = [];
  const outputs = [];
  let sourceBefore;
  let sourceAfter;
  let packageBefore;
  let packageAfter;
  let childCwd;
  let packageInfo;
  let fixtureSha256;
  let provenanceSha256;
  let failure;
  const addCheck = (name) => checks.push({ name, status: 'passed' });
  const artifactRelative = (filePath) => path.relative(root, filePath).split(path.sep).join('/');
  const registerOutput = (name, filePath, bytes) => outputs.push({ name, path: artifactRelative(filePath), bytes: bytes.byteLength, sha256: sha256(bytes) });

  async function assertPackageUnchanged(label) {
    const current = await inspectStaticPackage(archivePath, appRoot);
    assert.deepEqual(current, packageBefore, `The package archive or extracted tree changed ${label}.`);
    return current;
  }

  async function assertSourceUnchanged(label) {
    const current = await captureSourceIdentity();
    assert.deepEqual(current, sourceBefore, `The source commit or dirty working tree changed ${label}.`);
    return current;
  }

  async function runCli(name, args, { json = true } = {}) {
    await assertPackageUnchanged(`before ${name}`);
    await assertSourceUnchanged(`before ${name}`);
    const index = String(childRuns.length + 1).padStart(2, '0');
    const stepDirectory = path.join(stepsDirectory, `${index}-${name}`);
    await mkdir(stepDirectory);
    const commandArgs = [cliPath, ...args, ...(json ? ['--json'] : [])];
    const processArgv = [process.execPath, ...commandArgs];
    const callStarted = new Date().toISOString();
    const child = spawnSync(process.execPath, commandArgs, {
      cwd: childCwd,
      encoding: 'buffer',
      timeout: 30_000,
      maxBuffer: MAX_CLI_OUTPUT_BYTES,
      windowsHide: true,
    });
    const callFinished = new Date().toISOString();
    const stdout = Buffer.isBuffer(child.stdout) ? child.stdout : Buffer.alloc(0);
    const stderr = Buffer.isBuffer(child.stderr) ? child.stderr : Buffer.alloc(0);
    const stdoutPath = path.join(stepDirectory, 'stdout.raw');
    const stderrPath = path.join(stepDirectory, 'stderr.raw');
    await writeNew(stdoutPath, stdout);
    await writeNew(stderrPath, stderr);
    const step = {
      name,
      argv: processArgv,
      cwd: childCwd,
      startedAt: callStarted,
      finishedAt: callFinished,
      status: child.status,
      signal: child.signal,
      spawnError: child.error ? { message: child.error.message, code: child.error.code } : null,
      stdout: { path: artifactRelative(stdoutPath), bytes: stdout.byteLength, sha256: sha256(stdout) },
      stderr: { path: artifactRelative(stderrPath), bytes: stderr.byteLength, sha256: sha256(stderr) },
    };
    childRuns.push(step);
    await assertPackageUnchanged(`after ${name}`);
    await assertSourceUnchanged(`after ${name}`);
    if (child.error) throw child.error;
    const stdoutText = decodeUtf8(stdout, `${name} stdout`);
    const stderrText = decodeUtf8(stderr, `${name} stderr`);
    let response;
    if (json) {
      response = JSON.parse(stdoutText);
      step.response = response;
    }
    return { ...step, stdout, stderr, stdoutText, stderrText, response };
  }

  try {
    sourceBefore = await captureSourceIdentity();
    packageBefore = await inspectStaticPackage(archivePath, appRoot);
    assert.ok(packageBefore.files.some((file) => file.name === 'package.json'), 'The distributed package has no package.json.');
    const cliManifest = packageBefore.files.find((file) => file.name === 'cli/bugpack.mjs');
    assert.ok(cliManifest && cliManifest.bytes <= MAX_CLI_BYTES, 'The distributed CLI is missing or exceeds its read bound.');
    const cliBytes = await readBoundedRegular(cliPath, MAX_CLI_BYTES, 'Distributed CLI entry');
    assert.equal(sha256(cliBytes), cliManifest.sha256, 'The distributed CLI entry differs from the inspected package.');
    packageInfo = JSON.parse(decodeUtf8(await readBoundedRegular(path.join(appRoot, 'package.json'), MAX_FIXTURE_BYTES, 'Distributed package.json'), 'Distributed package.json'));
    assert.equal(packageInfo.name, 'bugpack-portable');
    assert.equal(typeof packageInfo.version, 'string');

    const sourceFixtureBytes = await readBoundedRegular(path.join(root, FIXTURE_FILE), MAX_FIXTURE_BYTES, 'Source schema-1 policy fixture');
    const sourceProvenanceBytes = await readBoundedRegular(path.join(root, PROVENANCE_FILE), MAX_FIXTURE_BYTES, 'Source policy fixture provenance');
    assert.ok(packageBefore.files.some((file) => file.name === FIXTURE_FILE), 'The fresh distributed package does not contain the schema-1 policy fixture.');
    assert.ok(packageBefore.files.some((file) => file.name === PROVENANCE_FILE), 'The fresh distributed package does not contain policy fixture provenance.');
    const fixtureBytes = await readBoundedRegular(path.join(appRoot, FIXTURE_FILE), MAX_FIXTURE_BYTES, 'Distributed schema-1 policy fixture');
    const provenanceBytes = await readBoundedRegular(path.join(appRoot, PROVENANCE_FILE), MAX_FIXTURE_BYTES, 'Distributed policy fixture provenance');
    assert.deepEqual(fixtureBytes, sourceFixtureBytes, 'The distributed policy fixture differs from the source fixture.');
    assert.deepEqual(provenanceBytes, sourceProvenanceBytes, 'The distributed policy fixture provenance differs from its source.');
    fixtureSha256 = sha256(fixtureBytes);
    provenanceSha256 = sha256(provenanceBytes);
    addCheck('the fresh distribution contains exact source copies of the policy fixture and its provenance');
    const provenance = JSON.parse(decodeUtf8(provenanceBytes, 'Policy fixture provenance'));
    assert.equal(provenance.kind, 'synthetic-policy-example-fixture-provenance');
    assert.equal(provenance.fixture.path, FIXTURE_FILE);
    assert.equal(provenance.fixture.bytes, fixtureBytes.byteLength);
    assert.equal(provenance.fixture.sha256, sha256(fixtureBytes));
    assert.equal(provenance.source.savedUiExportSha256, sha256(fixtureBytes));
    assert.equal(provenance.source.sourceCommit, POLICY_SOURCE_COMMIT);
    assert.equal(provenance.source.policyAcceptanceRecordSha256, 'fcbe061544dc0757d5e3a01de69c9231d4c75aa265937eaedfaa53fcb4713621');
    assert.equal(provenance.source.windowsAdditionalProofSha256, '548f4e2bc3857a519a7bbe5c35e532dd4a97ca65cfc1ad04a222ed93b16f9bcc');
    const fixturePolicy = JSON.parse(decodeUtf8(fixtureBytes, 'Schema-1 policy fixture'));
    assert.equal(fixturePolicy.schemaVersion, 1);
    assert.equal(fixturePolicy.name, provenance.fixture.demonstrationName);
    assert.equal(fixturePolicy.bodyMode, 'supported');
    const extraSensitiveKey = provenance.fixture.demonstrationExtraSensitiveKey;
    const literalRule = fixturePolicy.literalRules.find((rule) => rule.value === provenance.fixture.demonstrationLiteral);
    assert.ok(fixturePolicy.sensitiveKeys.includes(extraSensitiveKey), `The policy fixture no longer contains its extra key ${extraSensitiveKey}.`);
    assert.ok(literalRule, 'The policy fixture no longer contains its demonstration literal rule.');
    assert.equal(literalRule.replacement, provenance.fixture.demonstrationReplacement);

    const archiveInputsDirectory = path.join(inputsDirectory, 'legacy');
    const policyInputsDirectory = path.join(inputsDirectory, 'policy');
    const syntheticInputsDirectory = path.join(inputsDirectory, 'synthetic');
    await Promise.all([mkdir(archiveInputsDirectory), mkdir(policyInputsDirectory), mkdir(syntheticInputsDirectory)]);
    const legacyInputs = [];
    for (const item of LEGACY_INPUTS) {
      const bytes = execFileSync('git', ['show', `${LEGACY_COMMIT}:${item.gitPath}`], {
        cwd: root,
        encoding: 'buffer',
        maxBuffer: 1024 * 1024,
        windowsHide: true,
      });
      assert.equal(bytes.byteLength, item.bytes, `${item.gitPath} byte length changed at the pinned legacy commit.`);
      assert.equal(sha256(bytes), item.sha256, `${item.gitPath} changed at the pinned legacy commit.`);
      const filePath = path.join(archiveInputsDirectory, item.name);
      await writeNew(filePath, bytes);
      const staged = { ...item, path: artifactRelative(filePath), absolutePath: filePath };
      inputs.push(staged);
      legacyInputs.push({ ...staged, absolutePath: filePath, raw: bytes });
    }
    addCheck('legacy inputs are exact Git blobs from the pinned MVP commit');

    const policyPath = path.join(policyInputsDirectory, 'policy-v1.json');
    const provenancePath = path.join(policyInputsDirectory, 'policy-v1.provenance.json');
    await writeNew(policyPath, fixtureBytes);
    await writeNew(provenancePath, provenanceBytes);
    inputs.push({ name: 'policy-v1.json', path: artifactRelative(policyPath), absolutePath: policyPath, bytes: fixtureBytes.byteLength, sha256: sha256(fixtureBytes), source: 'exact-example-fixture' });
    inputs.push({ name: 'policy-v1.provenance.json', path: artifactRelative(provenancePath), absolutePath: provenancePath, bytes: provenanceBytes.byteLength, sha256: sha256(provenanceBytes), source: 'exact-example-fixture-metadata' });

    const demonstrationLiteral = provenance.fixture.demonstrationLiteral;
    const demonstrationReplacement = provenance.fixture.demonstrationReplacement;
    const demonstrationCustomerId = 'demo-customer-2042';
    const harBody = {
      customer_id: demonstrationCustomerId,
      diagnostic: `Synthetic HAR includes ${demonstrationLiteral}.`,
      safe_marker: 'HAR_BODY_SAFE_MARKER_2042',
    };
    const harResponseBody = { ticket: 'BP-COMPAT-2042', safe_marker: 'HAR_RESPONSE_SAFE_MARKER_2042' };
    const syntheticHarText = `${JSON.stringify({
      log: {
        version: '1.2',
        creator: { name: 'BugPack compatibility fixture', version: '1' },
        entries: [{
          request: {
            method: 'POST',
            url: `https://example.test/api/items?customer_id=${encodeURIComponent(demonstrationCustomerId)}&page=7`,
            headers: [{ name: 'content-type', value: 'application/json' }],
            postData: { mimeType: 'application/json', text: JSON.stringify(harBody) },
          },
          response: {
            status: 500,
            content: { mimeType: 'application/json', text: JSON.stringify(harResponseBody) },
          },
        }],
      },
    }, null, 2)}\n`;
    const syntheticLogText = [
      'compatibility_run=BP-COMPAT-2042',
      `customer_id=${demonstrationCustomerId}`,
      `message=Synthetic policy literal ${demonstrationLiteral} should be substituted.`,
      'safe_marker=LOG_SAFE_MARKER_2042',
      '',
    ].join('\n');
    const report = {
      title: 'Synthetic BugPack compatibility fixture',
      steps: 'Run the local synthetic request and inspect the retained safe markers.',
      expected: 'The extra customer_id key and configured demonstration literal are redacted.',
      actual: `The demo client emitted ${demonstrationLiteral} for customer_id=${demonstrationCustomerId}; keep REPORT_SAFE_MARKER_2042.`,
      environment: 'Synthetic compatibility test data only.',
    };
    const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`, 'utf8');
    const reportPath = path.join(syntheticInputsDirectory, 'report.json');
    const syntheticHarPath = path.join(syntheticInputsDirectory, 'synthetic-policy.har');
    const syntheticLogPath = path.join(syntheticInputsDirectory, 'synthetic-policy.log');
    await Promise.all([
      writeNew(reportPath, reportBytes),
      writeNew(syntheticHarPath, Buffer.from(syntheticHarText, 'utf8')),
      writeNew(syntheticLogPath, Buffer.from(syntheticLogText, 'utf8')),
    ]);
    inputs.push(
      { name: 'report.json', path: artifactRelative(reportPath), absolutePath: reportPath, bytes: reportBytes.byteLength, sha256: sha256(reportBytes), source: 'canonical-synthetic-report' },
      { name: 'synthetic-policy.har', path: artifactRelative(syntheticHarPath), absolutePath: syntheticHarPath, bytes: Buffer.byteLength(syntheticHarText), sha256: sha256(Buffer.from(syntheticHarText)), source: 'synthetic-fixture-literal-and-extra-key' },
      { name: 'synthetic-policy.log', path: artifactRelative(syntheticLogPath), absolutePath: syntheticLogPath, bytes: Buffer.byteLength(syntheticLogText), sha256: sha256(Buffer.from(syntheticLogText)), source: 'synthetic-fixture-literal-and-extra-key' },
    );
    const policyV2Path = path.join(policyInputsDirectory, 'policy-v2-unsupported.json');
    const unsupportedPolicy = { ...fixturePolicy, schemaVersion: 2 };
    const policyV2Bytes = Buffer.from(`${JSON.stringify(unsupportedPolicy, null, 2)}\n`, 'utf8');
    await writeNew(policyV2Path, policyV2Bytes);
    inputs.push({ name: 'policy-v2-unsupported.json', path: artifactRelative(policyV2Path), absolutePath: policyV2Path, bytes: policyV2Bytes.byteLength, sha256: sha256(policyV2Bytes), source: 'controlled-negative-derived-from-schema-1-fixture' });

    childCwd = await mkdtemp(path.join(os.tmpdir(), 'bugpack compatibility cwd '));
    assert.ok(childCwd.includes(' '), 'CLI child working directory must contain spaces.');
    assert.ok(!path.resolve(childCwd).toLowerCase().startsWith(`${root.toLowerCase()}${path.sep}`), 'CLI child working directory must be outside the source root.');
    assert.ok(!path.resolve(childCwd).toLowerCase().startsWith(`${appRoot.toLowerCase()}${path.sep}`), 'CLI child working directory must be outside the package root.');

    const doctor = await runCli('doctor', ['doctor']);
    assertResultOk(doctor, 'doctor');
    assert.equal(doctor.response.version, packageInfo.version, 'Distributed CLI doctor version differs from package.json.');
    assert.equal(doctor.response.supported, true, 'Distributed CLI did not report the supported Node 24 runtime.');
    assert.equal(doctor.response.network, 'not used');
    assert.equal(doctor.response.mode, 'offline');
    addCheck('distributed CLI doctor runs offline from a CWD outside the package and reports its package version');

    const versionJson = await runCli('version-json', ['--version']);
    assertResultOk(versionJson, 'version');
    assert.equal(versionJson.response.version, packageInfo.version);
    const versionHuman = await runCli('version-human', ['--version'], { json: false });
    assert.equal(versionHuman.status, 0);
    assert.equal(versionHuman.stderr.byteLength, 0);
    assert.equal(versionHuman.stdoutText, `BugPack CLI ${packageInfo.version}\n`);
    addCheck('distributed CLI version modes agree with the packaged product version');

    for (const legacy of legacyInputs) {
      const outputPath = path.join(outputsDirectory, `legacy-default-clean.${legacy.kind}`);
      await assertMissing(outputPath, `Legacy ${legacy.kind} clean output`);
      const clean = await runCli(`legacy-default-clean-${legacy.kind}`, [
        'clean', '--kind', legacy.kind, '--input', legacy.absolutePath, '--out', outputPath,
      ]);
      assertResultOk(clean, 'clean');
      const cleaned = await readBoundedRegular(outputPath, MAX_ARCHIVE_EXPANDED_BYTES, `Legacy ${legacy.kind} clean output`);
      assert.deepEqual(cleaned, legacy.raw, `Default clean changed the legacy ${legacy.kind} bytes.`);
      registerOutput(`legacy-default-clean-${legacy.kind}`, outputPath, cleaned);
    }
    addCheck('default cleanup preserves both pinned previously reviewed text files byte-for-byte');

    const defaultZipPath = path.join(outputsDirectory, 'legacy-default-reviewed.zip');
    await assertMissing(defaultZipPath, 'Default legacy bundle output');
    const defaultBundle = await runCli('legacy-default-bundle', [
      'bundle', '--har', legacyInputs[0].absolutePath, '--log', legacyInputs[1].absolutePath,
      '--out', defaultZipPath, '--reviewed',
    ]);
    assertResultOk(defaultBundle, 'bundle');
    const defaultZip = await readBoundedRegular(defaultZipPath, MAX_ARCHIVE_BYTES, 'Default legacy bundle ZIP');
    const defaultMembers = inspectReviewedBundle(defaultZip, 'Default legacy bundle');
    assertMemberNames(defaultMembers, 'Default legacy bundle');
    assert.deepEqual(defaultMembers.get('evidence-001.har'), legacyInputs[0].raw, 'Default legacy bundle changed the pinned HAR text.');
    assert.deepEqual(defaultMembers.get('evidence-002.log'), legacyInputs[1].raw, 'Default legacy bundle changed the pinned log text.');
    const defaultSummaryBytes = defaultMembers.get('processing-summary.json');
    const defaultSummaryPath = path.join(outputsDirectory, 'legacy-default-processing-summary.json');
    await writeNew(defaultSummaryPath, defaultSummaryBytes);
    const defaultSummary = JSON.parse(decodeUtf8(defaultSummaryBytes, 'Default bundle summary'));
    assert.equal(defaultSummary.schemaVersion, 1);
    assert.equal(Object.hasOwn(defaultSummary, 'policy'), false);
    assert.equal(defaultSummary.files.length, 2);
    assert.equal(defaultBundle.response.summarySchemaVersion, 1);
    registerOutput('legacy-default-reviewed-zip', defaultZipPath, defaultZip);
    registerOutput('legacy-default-processing-summary', defaultSummaryPath, defaultSummaryBytes);
    addCheck('default bundle preserves the pinned text members and emits an unbound schema-1 summary');

    const validation = await runCli('schema-1-policy-validate', ['policy', 'validate', '--file', policyPath]);
    assertResultOk(validation, 'policy validate');
    assert.equal(validation.response.policy.schemaVersion, 1);
    assert.equal(validation.response.policy.bodyMode, 'supported');
    assert.match(validation.response.policy.redactionPolicyId, /^[a-f0-9]{64}$/);
    assert.ok(!validation.stdoutText.includes(demonstrationLiteral), 'Policy validation echoed its configured literal.');
    addCheck('the exact exported schema-1 policy validates without echoing configured values');

    const cleanHarPath = path.join(outputsDirectory, 'policy-clean.har');
    await assertMissing(cleanHarPath, 'Policy HAR clean output');
    const cleanHarResult = await runCli('schema-1-policy-clean-har', [
      'clean', '--kind', 'har', '--input', syntheticHarPath, '--policy', policyPath, '--out', cleanHarPath,
    ]);
    assertResultOk(cleanHarResult, 'clean');
    assert.equal(cleanHarResult.response.policy.schemaVersion, 1);
    assert.equal(cleanHarResult.response.policy.bodyMode, 'supported');
    assert.equal(cleanHarResult.response.policy.redactionPolicyId, validation.response.policy.redactionPolicyId);
    const cleanHarBytes = await readBoundedRegular(cleanHarPath, MAX_ARCHIVE_EXPANDED_BYTES, 'Policy HAR clean output');
    const cleanHarText = decodeUtf8(cleanHarBytes, 'Policy HAR clean output');
    const cleanHarJson = JSON.parse(cleanHarText);
    const cleanedEntry = cleanHarJson.log.entries[0];
    const cleanRequestBody = JSON.parse(cleanedEntry.request.postData.text);
    const cleanResponseBody = JSON.parse(cleanedEntry.response.content.text);
    assert.equal(cleanRequestBody.customer_id, demonstrationReplacement, 'The extra sensitive key was not redacted in the supported JSON body.');
    assert.equal(new URL(cleanedEntry.request.url).searchParams.get('customer_id'), demonstrationReplacement, 'The extra sensitive key was not redacted in the HAR URL.');
    assert.ok(!cleanHarText.includes(demonstrationLiteral) && !cleanHarText.includes(demonstrationCustomerId));
    assert.ok(cleanHarText.includes(demonstrationReplacement));
    assert.equal(cleanRequestBody.safe_marker, 'HAR_BODY_SAFE_MARKER_2042');
    assert.equal(cleanResponseBody.safe_marker, 'HAR_RESPONSE_SAFE_MARKER_2042');
    registerOutput('policy-clean-har', cleanHarPath, cleanHarBytes);

    const cleanLogPath = path.join(outputsDirectory, 'policy-clean.log');
    await assertMissing(cleanLogPath, 'Policy log clean output');
    const cleanLogResult = await runCli('schema-1-policy-clean-log', [
      'clean', '--kind', 'log', '--input', syntheticLogPath, '--policy', policyPath, '--out', cleanLogPath,
    ]);
    assertResultOk(cleanLogResult, 'clean');
    assert.equal(cleanLogResult.response.policy.schemaVersion, 1);
    assert.equal(cleanLogResult.response.policy.bodyMode, 'supported');
    assert.equal(cleanLogResult.response.policy.redactionPolicyId, validation.response.policy.redactionPolicyId);
    const cleanLogBytes = await readBoundedRegular(cleanLogPath, MAX_ARCHIVE_EXPANDED_BYTES, 'Policy log clean output');
    const cleanLogText = decodeUtf8(cleanLogBytes, 'Policy log clean output');
    assert.ok(!cleanLogText.includes(demonstrationLiteral) && !cleanLogText.includes(demonstrationCustomerId));
    assert.ok(cleanLogText.includes(demonstrationReplacement));
    assert.ok(cleanLogText.includes('LOG_SAFE_MARKER_2042'));
    registerOutput('policy-clean-log', cleanLogPath, cleanLogBytes);
    addCheck('policy cleanup redacts the exported literal and extra key while retaining supported body and safe context');

    const policyZipPath = path.join(outputsDirectory, 'policy-reviewed.zip');
    await assertMissing(policyZipPath, 'Policy bundle output');
    const policyBundle = await runCli('schema-1-policy-bundle', [
      'bundle', '--har', syntheticHarPath, '--log', syntheticLogPath, '--report', reportPath,
      '--policy', policyPath, '--out', policyZipPath, '--reviewed',
    ]);
    assertResultOk(policyBundle, 'bundle');
    assert.equal(policyBundle.response.summarySchemaVersion, 2);
    assert.equal(policyBundle.response.policy.schemaVersion, 1);
    assert.equal(policyBundle.response.policy.bodyMode, 'supported');
    assert.equal(policyBundle.response.policy.redactionPolicyId, validation.response.policy.redactionPolicyId);
    const policyZip = await readBoundedRegular(policyZipPath, MAX_ARCHIVE_BYTES, 'Policy bundle ZIP');
    const policyMembers = inspectReviewedBundle(policyZip, 'Policy bundle');
    assertMemberNames(policyMembers, 'Policy bundle');
    const policySummaryBytes = policyMembers.get('processing-summary.json');
    const policySummaryPath = path.join(outputsDirectory, 'policy-processing-summary.json');
    await writeNew(policySummaryPath, policySummaryBytes);
    const policySummary = JSON.parse(decodeUtf8(policySummaryBytes, 'Policy bundle summary'));
    assert.equal(policySummary.schemaVersion, 2);
    assert.deepEqual(policySummary.policy, {
      schemaVersion: 1,
      id: validation.response.policy.redactionPolicyId,
      bodyMode: 'supported',
    });
    assert.equal(policySummary.files.length, 2);
    assert.ok(policySummary.limitations.some((item) => item.includes('Only valid JSON and UTF-8 URL-encoded')));
    const policyHarText = decodeUtf8(policyMembers.get('evidence-001.har'), 'Policy bundle HAR');
    const policyLogText = decodeUtf8(policyMembers.get('evidence-002.log'), 'Policy bundle log');
    const policyReportText = decodeUtf8(policyMembers.get('bug-report.md'), 'Policy bundle report');
    for (const [label, text] of [['HAR', policyHarText], ['log', policyLogText], ['report', policyReportText]]) {
      assert.ok(!text.includes(demonstrationLiteral), `Policy bundle ${label} contains the configured literal.`);
      assert.ok(!text.includes(demonstrationCustomerId), `Policy bundle ${label} contains the synthetic customer identifier.`);
      const replacementInOutput = label === 'report' ? '\\[REDACTED\\]' : demonstrationReplacement;
      assert.ok(text.includes(replacementInOutput), `Policy bundle ${label} omits the configured replacement.`);
    }
    assert.ok(policyHarText.includes('HAR_BODY_SAFE_MARKER_2042'));
    assert.ok(policyHarText.includes('HAR_RESPONSE_SAFE_MARKER_2042'));
    assert.ok(policyLogText.includes('LOG_SAFE_MARKER_2042'));
    assert.ok(policyReportText.includes('REPORT\\_SAFE\\_MARKER\\_2042'));
    registerOutput('policy-reviewed-zip', policyZipPath, policyZip);
    registerOutput('policy-processing-summary', policySummaryPath, policySummaryBytes);
    addCheck('policy-bound bundle emits schema 2 with the validated schema-1 policy id and retains safe request, response, log, and report context');

    const unknownOutputPath = path.join(outputsDirectory, 'unsupported-policy-output-must-not-exist.har');
    await assertMissing(unknownOutputPath, 'Unsupported schema output');
    const invalidPolicy = await runCli('schema-2-policy-rejected', [
      'clean', '--kind', 'har', '--input', syntheticHarPath, '--policy', policyV2Path, '--out', unknownOutputPath,
    ]);
    assert.equal(invalidPolicy.status, 2);
    assert.equal(invalidPolicy.stderr.byteLength, 0);
    assert.deepEqual(invalidPolicy.response, {
      ok: false,
      error: { code: 'INVALID_POLICY', message: 'The redaction policy is invalid. Check its version and fields.' },
    });
    await assertMissing(unknownOutputPath, 'Unsupported schema output');
    addCheck('schema-2 policy is rejected with INVALID_POLICY before any output file is created');

    for (const item of inputs) {
      const actual = await readBoundedRegular(item.absolutePath, MAX_ARCHIVE_EXPANDED_BYTES, `Retained input ${item.name}`);
      assert.equal(actual.byteLength, item.bytes, `Retained input changed size: ${item.name}`);
      assert.equal(sha256(actual), item.sha256, `Retained input changed bytes: ${item.name}`);
    }
    addCheck('all staged legacy, policy, report, and synthetic input bytes remain unchanged');

  } catch (error) {
    failure = error;
  } finally {
    if (childCwd) {
      try {
        await rm(childCwd, { recursive: true, force: true });
      } catch (error) {
        failure ??= error;
      }
    }
    if (sourceBefore) {
      try {
        sourceAfter = await captureSourceIdentity();
        assert.deepEqual(sourceAfter, sourceBefore, 'The source commit or dirty working tree changed during compatibility qualification.');
      } catch (error) {
        failure ??= error;
      }
    }
    if (packageBefore) {
      try {
        packageAfter = await inspectStaticPackage(archivePath, appRoot);
        assert.deepEqual(packageAfter, packageBefore, 'The package archive or extracted tree changed during compatibility qualification.');
      } catch (error) {
        failure ??= error;
      }
    }
  }

  const record = {
    schemaVersion: 1,
    suite: 'actual-distributed-cli-legacy-text-compatibility',
    status: failure ? 'failed' : 'passed',
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
    sourceBefore,
    sourceAfter,
    legacySource: { commit: LEGACY_COMMIT, paths: LEGACY_INPUTS.map(({ gitPath, bytes, sha256: digest }) => ({ path: gitPath, bytes, sha256: digest })) },
    package: packageBefore ? { archivePath, appRoot, before: packageBefore, after: packageAfter, productVersion: packageInfo?.version } : { archivePath, appRoot, before: null, after: packageAfter },
      policyFixture: { source: FIXTURE_FILE, distributedPath: `appRoot/${FIXTURE_FILE}`, provenance: PROVENANCE_FILE, sha256: fixtureSha256, metadataSha256: provenanceSha256 },
    inputs: inputs.map(({ absolutePath, ...item }) => item),
    outputs,
    childRuns,
    checks,
    startedAt,
    finishedAt: new Date().toISOString(),
    limits: [
      'The old reviewed HAR/log text blobs are reprocessed as fresh input; old ZIPs and summaries are not imported.',
      'This does not reconstruct request or response bodies that the earlier MVP omitted or recover prior processing counts.',
      'The policy values and generated positive-case evidence are synthetic demonstration values.',
      'Commands are local Node 24 CLI children started from a temporary CWD; no package install or network request is made by this harness.',
    ],
    ...(failure ? { error: String(failure?.stack ?? failure) } : {}),
  };
  try {
    await writeJsonNew(path.join(artifactRoot, failure ? 'failure.json' : 'compatibility.json'), record);
  } catch (error) {
    failure ??= error;
  }

  if (failure) {
    console.error(JSON.stringify({ status: 'failed', artifact: artifactRoot, error: String(failure?.stack ?? failure) }));
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify({ status: 'passed', artifact: artifactRoot, checks: checks.length, cliCalls: childRuns.length, version: packageInfo.version }));
  }
}

await main();
