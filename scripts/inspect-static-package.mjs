import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { inflateSync, unzipSync } from 'fflate';

const MAX_COMPRESSED_BYTES = 32 * 1024 * 1024;
const MAX_INFLATED_BYTES = 128 * 1024 * 1024;
const MAX_MEMBERS = 1000;
const MAX_ROOT_NODES = 1000;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const WIN_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function fail(message) {
  throw new Error(`Static package inspection failed: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function u16(data, offset) {
  if (offset < 0 || offset + 2 > data.length) fail('truncated ZIP metadata');
  return data.readUInt16LE(offset);
}

function u32(data, offset) {
  if (offset < 0 || offset + 4 > data.length) fail('truncated ZIP metadata');
  return data.readUInt32LE(offset);
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < table.length; i++) {
    let value = i;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[i] = value >>> 0;
  }
  return table;
})();

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function decodeZipName(rawName, flags) {
  if (!rawName.length) fail('empty ZIP member path');
  if (!(flags & 0x800) && rawName.some((byte) => byte > 0x7f)) fail('non-ASCII ZIP names must set the UTF-8 flag');
  try {
    return UTF8.decode(rawName);
  } catch {
    fail('ZIP member name is not valid UTF-8');
  }
}

function validateMemberPath(name, packagePrefix, allowDirectory) {
  if (typeof name !== 'string' || !name || name.length > 4096) fail('member path is empty or too long');
  if (/[\u0000-\u001f\u007f]/.test(name) || name.includes('\\') || name.includes(':') || name.startsWith('/')) fail('unsafe absolute, control, drive, or backslash member path');
  const isDirectory = name.endsWith('/');
  if (isDirectory && !allowDirectory) fail('directory member is not supported in this archive record');
  const cleanName = isDirectory ? name.slice(0, -1) : name;
  const segments = cleanName.split('/');
  if (segments.some((part) => !part || part === '.' || part === '..' || part.endsWith('.') || part.endsWith(' ') || /[<>"|?*]/.test(part) || WIN_RESERVED.test(part))) {
    fail('unsafe member path segment');
  }
  if (segments[0] !== packagePrefix) fail('archive members must share the archive root prefix');
  if (segments.length < 2 && !isDirectory) fail('archive member must be below its package root directory');
  if (segments.length === 1 && segments[0] !== packagePrefix) fail('archive has multiple top-level directories');
  return { isDirectory, relativeName: segments.length === 1 ? '' : segments.slice(1).join('/') };
}

function addPath(paths, caseFolded, name, kind) {
  if (paths.has(name)) fail(`duplicate archive path: ${name}`);
  const folded = name.toLocaleLowerCase('en-US');
  if (caseFolded.has(folded)) fail(`archive paths collide on Windows: ${name}`);
  paths.add(name);
  caseFolded.add(folded);
  if (kind === 'directory') return;
}

function addParents(directorySet, fileName) {
  let cursor = fileName;
  while (cursor.includes('/')) {
    cursor = cursor.slice(0, cursor.lastIndexOf('/'));
    if (cursor) directorySet.add(cursor);
  }
}

function readZipDirectory(archive, packagePrefix) {
  if (archive.length < 22) fail('ZIP archive is truncated');
  const searchStart = Math.max(0, archive.length - 22 - 0xffff);
  let eocd = -1;
  for (let at = archive.length - 22; at >= searchStart; at--) {
    if (archive.readUInt32LE(at) !== 0x06054b50) continue;
    const commentLength = u16(archive, at + 20);
    if (at + 22 + commentLength === archive.length) {
      eocd = at;
      break;
    }
  }
  if (eocd < 0) fail('ZIP end-of-central-directory record is missing');
  if (eocd >= 20 && archive.readUInt32LE(eocd - 20) === 0x07064b50) fail('ZIP64 archives are not supported');

  const diskNumber = u16(archive, eocd + 4);
  const centralDisk = u16(archive, eocd + 6);
  const diskEntries = u16(archive, eocd + 8);
  const entryCount = u16(archive, eocd + 10);
  const centralSize = u32(archive, eocd + 12);
  const centralOffset = u32(archive, eocd + 16);
  if (diskNumber !== 0 || centralDisk !== 0 || diskEntries !== entryCount) fail('multi-disk ZIP archives are not supported');
  if (entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) fail('ZIP64 archives are not supported');
  if (!entryCount || entryCount > MAX_MEMBERS) fail(`ZIP member count exceeds ${MAX_MEMBERS} or is empty`);
  if (centralOffset + centralSize !== eocd) fail('ZIP central directory bounds are inconsistent');

  const entries = [];
  const paths = new Set();
  const foldedPaths = new Set();
  const directories = new Set();
  const localRanges = [];
  let inflatedTotal = 0;
  let cursor = centralOffset;

  for (let index = 0; index < entryCount; index++) {
    if (cursor + 46 > eocd || u32(archive, cursor) !== 0x02014b50) fail('malformed ZIP central directory record');
    const madeBy = u16(archive, cursor + 4);
    const versionNeeded = u16(archive, cursor + 6);
    const flags = u16(archive, cursor + 8);
    const method = u16(archive, cursor + 10);
    const checksum = u32(archive, cursor + 16);
    const compressedSize = u32(archive, cursor + 20);
    const uncompressedSize = u32(archive, cursor + 24);
    const nameLength = u16(archive, cursor + 28);
    const extraLength = u16(archive, cursor + 30);
    const commentLength = u16(archive, cursor + 32);
    const startDisk = u16(archive, cursor + 34);
    const externalAttributes = u32(archive, cursor + 38);
    const localOffset = u32(archive, cursor + 42);
    const recordEnd = cursor + 46 + nameLength + extraLength + commentLength;
    if (recordEnd > eocd) fail('ZIP central record exceeds its declared bounds');
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff || startDisk === 0xffff) fail('ZIP64 member metadata is not supported');
    if (startDisk !== 0) fail('split ZIP members are not supported');
    if (flags & 1) fail('encrypted ZIP entries are not supported');
    if (flags & ~0x800) fail('ZIP entry uses unsupported flags or a data descriptor');
    if ((method !== 0 && method !== 8) || versionNeeded > 20) fail('ZIP compression method or version is unsupported');
    if (extraLength !== 0 || commentLength !== 0) fail('ZIP extra fields and member comments are not supported');

    const rawName = archive.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = decodeZipName(rawName, flags);
    const path = validateMemberPath(name, packagePrefix, true);
    if (!path.relativeName && !path.isDirectory) fail('ZIP package root must be a directory');

    const hostOs = madeBy >>> 8;
    const unixMode = externalAttributes >>> 16;
    const unixType = unixMode & 0xf000;
    if (hostOs === 3 && unixType && unixType !== 0x8000 && unixType !== 0x4000) fail('ZIP symlinks and nonregular file types are not supported');
    if (hostOs === 3 && unixType && (unixType === 0x4000) !== path.isDirectory) fail('ZIP POSIX file type and path disagree');
    if ((externalAttributes & 0x400) !== 0) fail('ZIP reparse-point entries are not supported');
    if (unixType === 0xa000) fail('ZIP symlink entries are not supported');
    const dosDirectory = (externalAttributes & 0x10) !== 0;
    const isDirectory = path.isDirectory || dosDirectory || unixType === 0x4000;
    if (isDirectory !== path.isDirectory) fail('ZIP directory attributes and path name disagree');
    if (isDirectory && (compressedSize !== 0 || uncompressedSize !== 0 || checksum !== 0)) fail('ZIP directory entries must be empty');
    if (!isDirectory) {
      addPath(paths, foldedPaths, path.relativeName, 'file');
      inflatedTotal += uncompressedSize;
      if (inflatedTotal > MAX_INFLATED_BYTES) fail(`ZIP inflated contents exceed ${MAX_INFLATED_BYTES} bytes`);
    } else if (path.relativeName) {
      addPath(paths, foldedPaths, path.relativeName, 'directory');
      directories.add(path.relativeName);
    }

    if (localOffset + 30 > centralOffset || u32(archive, localOffset) !== 0x04034b50) fail('ZIP local file header is invalid');
    const localVersion = u16(archive, localOffset + 4);
    const localFlags = u16(archive, localOffset + 6);
    const localMethod = u16(archive, localOffset + 8);
    const localCrc = u32(archive, localOffset + 14);
    const localCompressedSize = u32(archive, localOffset + 18);
    const localUncompressedSize = u32(archive, localOffset + 22);
    const localNameLength = u16(archive, localOffset + 26);
    const localExtraLength = u16(archive, localOffset + 28);
    if (localVersion !== versionNeeded || localFlags !== flags || localMethod !== method) fail('ZIP local and central metadata disagree');
    if (localCrc !== checksum || localCompressedSize !== compressedSize || localUncompressedSize !== uncompressedSize) fail('ZIP local and central sizes or CRC disagree');
    if (localExtraLength !== 0 || localNameLength !== nameLength) fail('ZIP local path or extra metadata is unsupported');
    const localNameStart = localOffset + 30;
    if (localNameStart + localNameLength + compressedSize > centralOffset) fail('ZIP local payload exceeds its declared bounds');
    if (!archive.subarray(localNameStart, localNameStart + localNameLength).equals(rawName)) fail('ZIP local and central path names disagree');
    const dataStart = localNameStart + localNameLength;
    const dataEnd = dataStart + compressedSize;
    localRanges.push({ start: localOffset, end: dataEnd });
    entries.push({ name, relativeName: path.relativeName, isDirectory, method, checksum, compressedSize, uncompressedSize, dataStart });
    cursor = recordEnd;
  }
  if (cursor !== eocd) fail('ZIP central directory member count or size is inconsistent');

  localRanges.sort((a, b) => a.start - b.start);
  let localCursor = 0;
  for (const range of localRanges) {
    if (range.start < localCursor) fail('ZIP local file records overlap');
    if (range.start !== localCursor) fail('ZIP local file records contain an unaccounted gap');
    localCursor = range.end;
  }
  if (localCursor !== centralOffset) fail('ZIP local records do not end at the central directory');

  for (const entry of entries) {
    const compressed = archive.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
    let expanded;
    try {
      if (entry.method === 0) expanded = compressed;
      else expanded = inflateSync(compressed, { out: new Uint8Array(entry.uncompressedSize + 1) });
    } catch {
      fail('ZIP member decompression failed');
    }
    if (expanded.byteLength !== entry.uncompressedSize) fail('ZIP member actual size differs from its declared size');
    if (crc32(expanded) !== entry.checksum) fail('ZIP member CRC checksum is invalid');
  }

  let unpacked;
  try {
    unpacked = unzipSync(archive);
  } catch {
    fail('ZIP decompression failed');
  }
  const unpackedNames = Object.keys(unpacked);
  if (unpackedNames.length !== entries.length || entries.some((entry) => !Object.hasOwn(unpacked, entry.name))) fail('ZIP decompressor returned a different member list');

  const files = new Map();
  const impliedDirectories = new Set(directories);
  for (const entry of entries) {
    const content = unpacked[entry.name];
    if (!(content instanceof Uint8Array) || content.byteLength !== entry.uncompressedSize) fail('ZIP decompressed file size differs from its declaration');
    if (crc32(content) !== entry.checksum) fail('ZIP decompressed file CRC checksum is invalid');
    if (entry.isDirectory) continue;
    addParents(impliedDirectories, entry.relativeName);
    files.set(entry.relativeName, { name: entry.relativeName, bytes: content.byteLength, sha256: sha256(content) });
  }
  return { files: [...files.values()], directories: impliedDirectories };
}

function readTarString(header, start, length) {
  const field = header.subarray(start, start + length);
  const zeroAt = field.indexOf(0);
  const content = zeroAt < 0 ? field : field.subarray(0, zeroAt);
  try {
    return UTF8.decode(content);
  } catch {
    fail('TAR header contains invalid UTF-8');
  }
}

function parseTarOctal(header, start, length, label) {
  const field = header.subarray(start, start + length);
  if (field.length !== length || field.some((byte) => byte & 0x80)) fail(`TAR ${label} uses unsupported base-256 encoding`);
  const text = field.toString('ascii').replace(/\0.*$/s, '').trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) fail(`TAR ${label} is not a valid octal number`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) fail(`TAR ${label} is outside the supported range`);
  return value;
}

function verifyTarChecksum(header) {
  const declared = parseTarOctal(header, 148, 8, 'checksum');
  let actual = 0;
  for (let i = 0; i < header.length; i++) actual += i >= 148 && i < 156 ? 32 : header[i];
  if (actual !== declared) fail('TAR header checksum is invalid');
}

function readTarGzip(archive, packagePrefix) {
  let tar;
  try {
    tar = gunzipSync(archive, { maxOutputLength: MAX_INFLATED_BYTES });
  } catch {
    fail(`gzip stream is invalid or TAR inflated output exceeds ${MAX_INFLATED_BYTES} bytes`);
  }
  if (tar.byteLength > MAX_INFLATED_BYTES) fail(`TAR inflated contents exceed ${MAX_INFLATED_BYTES} bytes`);
  const files = new Map();
  const paths = new Set();
  const foldedPaths = new Set();
  const directories = new Set();
  let members = 0;
  let offset = 0;
  let zeroBlocks = 0;
  let sawRoot = false;
  let inflatedFiles = 0;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks++;
      offset += 512;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks) fail('TAR has only one zero end block before another header');
    if (++members > MAX_MEMBERS) fail(`TAR member count exceeds ${MAX_MEMBERS}`);
    verifyTarChecksum(header);
    const magic = readTarString(header, 257, 6);
    if (magic !== 'ustar' && magic !== 'ustar ') fail('TAR format is not supported');
    const prefixField = readTarString(header, 345, 155);
    if (prefixField) fail('TAR prefix and long-path extensions are not supported');
    const name = readTarString(header, 0, 100);
    if (!name || Buffer.byteLength(name, 'utf8') >= 100) fail('TAR member name must be shorter than 100 bytes');

    parseTarOctal(header, 100, 8, 'mode');
    parseTarOctal(header, 108, 8, 'owner');
    parseTarOctal(header, 116, 8, 'group');
    const size = parseTarOctal(header, 124, 12, 'size');
    parseTarOctal(header, 136, 12, 'timestamp');
    parseTarOctal(header, 329, 8, 'device major');
    parseTarOctal(header, 337, 8, 'device minor');
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    if (type !== '0' && type !== '5') fail('TAR symlinks and nonregular member types are not supported');
    const linkName = readTarString(header, 157, 100);
    if (linkName) fail('TAR link targets are not supported');
    const path = validateMemberPath(name, packagePrefix, type === '5');
    if (type === '5' && !path.isDirectory) fail('TAR directory entries must end in a slash');
    if (type === '0' && path.isDirectory) fail('TAR regular file path cannot end in a slash');
    if (!path.relativeName && type !== '5') fail('TAR package root must be a directory');
    if (!path.relativeName) {
      if (sawRoot) fail('TAR contains a duplicate package root');
      sawRoot = true;
    } else if (type === '5') {
      addPath(paths, foldedPaths, path.relativeName, 'directory');
      directories.add(path.relativeName);
    } else {
      addPath(paths, foldedPaths, path.relativeName, 'file');
      inflatedFiles += size;
      if (inflatedFiles > MAX_INFLATED_BYTES) fail(`TAR files exceed ${MAX_INFLATED_BYTES} bytes`);
    }

    if (type === '5' && size !== 0) fail('TAR directory entries must be empty');
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const paddedEnd = dataEnd + ((512 - (size % 512)) % 512);
    if (dataEnd > tar.length || paddedEnd > tar.length) fail('TAR member data exceeds its bounds');
    if (type === '0') {
      const content = tar.subarray(dataStart, dataEnd);
      files.set(path.relativeName, { name: path.relativeName, bytes: size, sha256: sha256(content) });
    }
    offset = paddedEnd;
  }

  if (zeroBlocks !== 2) fail('TAR must end with two zero blocks');
  if (!sawRoot) fail('TAR is missing its package root directory');
  if (offset < tar.length) {
    if ((tar.length - offset) % 512 !== 0 || tar.subarray(offset).some((byte) => byte !== 0)) fail('TAR has nonzero data after its end blocks');
  }
  const impliedDirectories = new Set(directories);
  for (const name of files.keys()) addParents(impliedDirectories, name);
  return { files: [...files.values()], directories: impliedDirectories };
}

async function walkApplicationRoot(appRoot) {
  const root = resolve(appRoot);
  const rootStat = await lstat(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) fail('application root must be a regular directory');
  const files = new Map();
  const directories = new Set();
  const seenFolded = new Set();
  const pending = [{ absolute: root, relative: '' }];
  let visited = 0;
  let totalBytes = 0;

  while (pending.length) {
    const current = pending.pop();
    const children = await readdir(current.absolute);
    children.sort();
    for (const childName of children) {
      if (++visited > MAX_ROOT_NODES) fail(`application root exceeds ${MAX_ROOT_NODES} members`);
      const relativeName = current.relative ? `${current.relative}/${childName}` : childName;
      validateMemberPath(`${'root'}/${relativeName}`, 'root', false);
      const folded = relativeName.toLocaleLowerCase('en-US');
      if (seenFolded.has(folded)) fail('application root contains paths that collide on Windows');
      seenFolded.add(folded);
      const absolute = join(current.absolute, childName);
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) fail('application root contains a symbolic link');
      if (info.isDirectory()) {
        directories.add(relativeName);
        pending.push({ absolute, relative: relativeName });
      } else if (info.isFile()) {
        totalBytes += info.size;
        if (totalBytes > MAX_INFLATED_BYTES) fail(`application root exceeds ${MAX_INFLATED_BYTES} bytes`);
        const content = await readFile(absolute);
        if (content.byteLength !== info.size) fail('application file changed while it was inspected');
        files.set(relativeName, { name: relativeName, bytes: content.byteLength, sha256: sha256(content) });
      } else {
        fail('application root contains a special file');
      }
    }
  }
  return { files, directories, totalBytes };
}

function sameFileTree(archiveTree, rootTree) {
  const archiveFiles = new Map(archiveTree.files.map((file) => [file.name, file]));
  if (archiveFiles.size !== rootTree.files.size) fail('archive and extracted root have different file lists');
  if (archiveTree.directories.size !== rootTree.directories.size) fail('archive and extracted root have different directory lists');
  for (const [name, expected] of archiveFiles) {
    const actual = rootTree.files.get(name);
    if (!actual || actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) fail(`archive and extracted root differ for ${name}`);
  }
  for (const name of archiveTree.directories) if (!rootTree.directories.has(name)) fail(`archive directory is missing from extracted root: ${name}`);
}

/** Verifies a generated static package archive against its exact extracted file tree. */
export async function inspectStaticPackage(archivePath, appRoot) {
  if (typeof archivePath !== 'string' || typeof appRoot !== 'string') fail('archive path and application root are required');
  const resolvedArchive = resolve(archivePath);
  const archiveName = basename(resolvedArchive);
  let packagePrefix;
  let archiveKind;
  if (archiveName.endsWith('.zip')) {
    packagePrefix = archiveName.slice(0, -4);
    archiveKind = 'zip';
  } else if (archiveName.endsWith('.tar.gz')) {
    packagePrefix = archiveName.slice(0, -7);
    archiveKind = 'tar.gz';
  } else {
    fail('archive extension must be .zip or .tar.gz');
  }
  if (!packagePrefix || packagePrefix === '.' || packagePrefix === '..') fail('archive filename does not provide a package root name');

  const archiveInfo = await lstat(resolvedArchive);
  if (archiveInfo.isSymbolicLink() || !archiveInfo.isFile()) fail('archive path must be a regular file');
  if (archiveInfo.size > MAX_COMPRESSED_BYTES) fail(`compressed archive exceeds ${MAX_COMPRESSED_BYTES} bytes`);
  const archive = await readFile(resolvedArchive);
  if (archive.byteLength > MAX_COMPRESSED_BYTES) fail(`compressed archive exceeds ${MAX_COMPRESSED_BYTES} bytes`);

  let archiveTree;
  if (archiveKind === 'zip') archiveTree = readZipDirectory(archive, packagePrefix);
  else archiveTree = readTarGzip(archive, packagePrefix);
  if (!archiveTree.files.length) fail('archive contains no regular files');

  const rootTree = await walkApplicationRoot(appRoot);
  sameFileTree(archiveTree, rootTree);
  const files = [...archiveTree.files.values()].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  return { archiveSha256: sha256(archive), archiveBytes: archive.byteLength, files };
}
