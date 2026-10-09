import { zipSync } from 'fflate';
import { LIMITS, type BugReport, type BundleFile, type BundleResult, type EvidenceKind, type Omission, type RedactionPolicy } from './contracts.ts';
import { sanitizeHar, sanitizeLog } from './redaction.ts';
import { DEFAULT_REDACTION_POLICY, redactionPolicyFingerprint, validateRedactionPolicy } from './policy.ts';

const encoder = new TextEncoder();
const PNG_SIGNATURE = Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]);
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const PNG_CRITICAL = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND']);
const OMISSION_DESCRIPTIONS: Readonly<Record<string, string>> = Object.freeze({
  'unknown-field': 'Unknown HAR fields and extensions were omitted.',
  'url-credentials': 'URL user information was removed.',
  'url-fragment': 'URL fragments were removed.',
  header: 'Sensitive and unapproved HTTP headers were omitted.',
  'query-string': 'HAR queryString copies were omitted; the sanitized request URL is retained.',
  cookie: 'HAR cookies were omitted.',
  body: 'HAR request and response bodies were omitted.',
  'body-invalid': 'A malformed or ambiguous request or response body was omitted.',
  'body-binary': 'A binary or base64 request or response body was omitted.',
  'body-unsupported': 'An unsupported request or response body format was omitted.',
  comment: 'HAR comments were omitted.',
  cache: 'HAR cache data was omitted.',
  'entry-metadata': 'HAR network and page metadata were omitted.',
  'page-metadata': 'HAR page identifiers, titles, and comments were omitted.',
  'png-metadata': 'Ancillary PNG metadata chunks were removed.',
  'image-regenerated': 'Image pixels were regenerated as PNG; source metadata was omitted.',
});
const PRIOR_CODES_BY_KIND: Readonly<Record<EvidenceKind, ReadonlySet<string>>> = Object.freeze({
  har: new Set(['unknown-field', 'url-credentials', 'url-fragment', 'header', 'query-string', 'cookie', 'body', 'body-invalid', 'body-binary', 'body-unsupported', 'comment', 'cache', 'entry-metadata', 'page-metadata']),
  log: new Set<string>(),
  image: new Set(['png-metadata', 'image-regenerated']),
});

interface CleanFile {
  name: string;
  kind: EvidenceKind;
  bytes: Uint8Array;
  changes: number;
  omissions: Omission[];
  masks: number;
}

interface CleanPng {
  bytes: Uint8Array;
  omissions: Omission[];
  changes: number;
}

function fail(message: string): never {
  throw new Error(message);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength < right.byteLength) return false;
  for (let index = 0; index < right.length; index++) if (left[index] !== right[index]) return false;
  return true;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] * 0x1000000) + ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])) >>> 0;
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array, start: number, end: number): number {
  let crc = 0xffffffff;
  for (let index = start; index < end; index++) crc = crcTable[(crc ^ bytes[index]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function validatePng(source: Uint8Array): CleanPng {
  if (!(source instanceof Uint8Array) || source.byteLength < PNG_SIGNATURE.length + 12 || source.byteLength > LIMITS.outputBytes) {
    fail('Processed PNG is missing, malformed, or exceeds the output limit');
  }
  if (!sameBytes(source, PNG_SIGNATURE)) fail('PNG signature is invalid');

  let offset = PNG_SIGNATURE.length;
  let sawHeader = false;
  let sawPalette = false;
  let sawData = false;
  let endedData = false;
  let sawEnd = false;
  let width = 0;
  let height = 0;
  let colorType = -1;
  const retained: Uint8Array[] = [source.slice(0, PNG_SIGNATURE.length)];
  let removedAncillary = 0;

  while (offset < source.length) {
    if (source.length - offset < 12) fail('PNG has a truncated chunk header');
    const length = readUint32(source, offset);
    if (length > source.length - offset - 12) fail('PNG chunk length exceeds the available bytes');
    const typeBytes = source.subarray(offset + 4, offset + 8);
    const type = String.fromCharCode(...typeBytes);
    if (!/^[A-Za-z]{4}$/.test(type)) fail('PNG contains an invalid chunk name');
    const dataStart = offset + 8;
    const crcOffset = dataStart + length;
    const nextOffset = crcOffset + 4;
    if (readUint32(source, crcOffset) !== crc32(source, offset + 4, crcOffset)) fail(`PNG ${type} chunk checksum is invalid`);
    if (sawEnd) fail('PNG contains bytes after IEND');

    const critical = (typeBytes[0] & 0x20) === 0;
    if (critical && !PNG_CRITICAL.has(type)) fail(`PNG contains unsupported critical chunk ${type}`);
    if (!sawHeader && type !== 'IHDR') fail('PNG must start with IHDR');

    if (type === 'IHDR') {
      if (sawHeader || offset !== PNG_SIGNATURE.length || length !== 13) fail('PNG IHDR is invalid or repeated');
      sawHeader = true;
      width = readUint32(source, dataStart);
      height = readUint32(source, dataStart + 4);
      const bitDepth = source[dataStart + 8];
      colorType = source[dataStart + 9];
      const validDepths: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
      if (!width || !height || width > LIMITS.imageDimension || height > LIMITS.imageDimension || width * height > LIMITS.imagePixels) {
        fail('PNG dimensions exceed the supported image limits');
      }
      if (!validDepths[colorType]?.includes(bitDepth) || source[dataStart + 10] !== 0 || source[dataStart + 11] !== 0 || source[dataStart + 12] > 1) {
        fail('PNG IHDR uses unsupported image settings');
      }
      retained.push(source.slice(offset, nextOffset));
    } else if (type === 'PLTE') {
      if (sawPalette || sawData || length === 0 || length > 768 || length % 3 !== 0 || colorType === 0 || colorType === 4) {
        fail('PNG PLTE is invalid or misplaced');
      }
      sawPalette = true;
      retained.push(source.slice(offset, nextOffset));
    } else if (type === 'IDAT') {
      if (endedData || (colorType === 3 && !sawPalette)) fail('PNG IDAT is invalid or misplaced');
      sawData = true;
      retained.push(source.slice(offset, nextOffset));
    } else if (type === 'IEND') {
      if (length !== 0 || !sawData || (colorType === 3 && !sawPalette)) fail('PNG IEND is invalid or misplaced');
      sawEnd = true;
      retained.push(source.slice(offset, nextOffset));
    } else if (!critical) {
      removedAncillary++;
      if (sawData) endedData = true;
    }

    if (type !== 'IHDR' && type !== 'PLTE' && type !== 'IDAT' && type !== 'IEND' && critical) {
      fail(`PNG contains unsupported critical chunk ${type}`);
    }
    offset = nextOffset;
  }

  if (!sawEnd || offset !== source.length) fail('PNG is missing a final IEND chunk');
  const totalLength = retained.reduce((sum, part) => sum + part.length, 0);
  const cleanBytes = new Uint8Array(totalLength);
  let writeOffset = 0;
  for (const part of retained) {
    cleanBytes.set(part, writeOffset);
    writeOffset += part.length;
  }
  const omissions = removedAncillary ? [{ code: 'png-metadata', count: removedAncillary, description: 'Ancillary PNG metadata chunks were removed.' }] : [];
  return { bytes: cleanBytes, omissions, changes: removedAncillary };
}

function safeReportField(value: unknown, label: string, maxLength: number, policy: RedactionPolicy): string {
  if (typeof value !== 'string') fail(`Bug report ${label} must be text`);
  if (value.length > maxLength || encoder.encode(value).byteLength > maxLength * 4) fail(`Bug report ${label} exceeds the supported length`);
  return sanitizeLog(value, policy).text;
}

function escapeMarkdown(value: string): string {
  return value.replace(/[\\`*_{}\[\]<>\(\)#+\-.!|~]/g, (character) => `\\${character}`);
}

function buildReport(report: BugReport, policy: RedactionPolicy): { bytes: Uint8Array } {
  if (!report || typeof report !== 'object') fail('Bug report is required');
  const fields = {
    title: safeReportField(report.title, 'title', 1024, policy),
    steps: safeReportField(report.steps, 'steps', 64 * 1024, policy),
    expected: safeReportField(report.expected, 'expected result', 64 * 1024, policy),
    actual: safeReportField(report.actual, 'actual result', 64 * 1024, policy),
    environment: safeReportField(report.environment, 'environment', 64 * 1024, policy),
  };
  const markdown = [
    '# Bug report',
    '',
    `## Title\n\n${escapeMarkdown(fields.title)}`,
    `## Steps to reproduce\n\n${escapeMarkdown(fields.steps)}`,
    `## Expected result\n\n${escapeMarkdown(fields.expected)}`,
    `## Actual result\n\n${escapeMarkdown(fields.actual)}`,
    `## Environment\n\n${escapeMarkdown(fields.environment)}`,
    '',
    'Review every included item before sharing. Automatic redaction is incomplete.',
    '',
  ].join('\n');
  return { bytes: encoder.encode(markdown) };
}

function summarizeOmissions(omissions: Omission[]): Omission[] {
  return omissions.map((item) => ({ code: item.code, count: item.count, description: item.description }));
}

function validatePrior(prior: BundleFile['prior'], kind: EvidenceKind): { changes: number; omissions: Omission[] } {
  if (prior === undefined) return { changes: 0, omissions: [] };
  if (!prior || typeof prior !== 'object' || Array.isArray(prior)) fail('Prior processing summary is malformed');
  if (!Number.isSafeInteger(prior.changes) || prior.changes < 0 || prior.changes > LIMITS.inputBytes) fail('Prior change count is invalid');
  if (!Array.isArray(prior.omissions) || prior.omissions.length > 64) fail('Prior omissions are malformed or exceed the limit');
  let countTotal = 0;
  const byCode = new Map<string, number>();
  for (const item of prior.omissions) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail('Prior omission record is malformed');
    if (typeof item.code !== 'string' || !PRIOR_CODES_BY_KIND[kind].has(item.code) || !OMISSION_DESCRIPTIONS[item.code]) fail('Prior omission uses an unsupported code');
    if (!Number.isSafeInteger(item.count) || item.count <= 0 || item.count > LIMITS.inputBytes) fail('Prior omission count is invalid');
    if (typeof item.description !== 'string' || item.description.length > 512) fail('Prior omission description is malformed');
    countTotal += item.count;
    if (countTotal > LIMITS.inputBytes) fail('Prior omission counts exceed the supported limit');
    byCode.set(item.code, (byCode.get(item.code) ?? 0) + item.count);
  }
  const omissions = [...byCode].map(([code, count]) => ({ code, count, description: OMISSION_DESCRIPTIONS[code] }));
  return { changes: prior.changes, omissions };
}

function mergeOmissions(kind: EvidenceKind, ...groups: Omission[][]): Omission[] {
  const byCode = new Map<string, number>();
  for (const omissions of groups) {
    for (const item of omissions) {
      if (!PRIOR_CODES_BY_KIND[kind].has(item.code) || !OMISSION_DESCRIPTIONS[item.code]) fail('Core omission uses an unsupported code');
      byCode.set(item.code, (byCode.get(item.code) ?? 0) + item.count);
    }
  }
  return [...byCode].map(([code, count]) => ({ code, count, description: OMISSION_DESCRIPTIONS[code] }));
}

/** Creates a ZIP from freshly sanitized evidence and generated neutral filenames. */
export function buildBundle(files: BundleFile[], report: BugReport, policyValue?: RedactionPolicy): BundleResult {
  if (!Array.isArray(files)) fail('Bundle files must be an array');
  if (files.length === 0) fail('Bundle requires at least one evidence file');
  if (files.length > LIMITS.files) fail(`Bundle exceeds the ${LIMITS.files} file limit`);
  const hasPolicy = policyValue !== undefined;
  const policy = hasPolicy ? validateRedactionPolicy(policyValue) : DEFAULT_REDACTION_POLICY;
  const ids = new Set<string>();
  const cleanFiles: CleanFile[] = [];
  let totalInputBytes = 0;

  for (const [index, file] of files.entries()) {
    if (!file || typeof file !== 'object') fail(`Bundle file ${index + 1} is malformed`);
    if (typeof file.id !== 'string' || !SAFE_ID.test(file.id)) fail(`Bundle file ${index + 1} has an unsafe ID or filename`);
    if (ids.has(file.id)) fail(`Bundle file IDs must be unique; duplicate ID: ${file.id}`);
    ids.add(file.id);
    if (file.kind !== 'har' && file.kind !== 'log' && file.kind !== 'image') fail(`Bundle file ${index + 1} has an unsupported evidence kind`);
    const prior = validatePrior(file.prior, file.kind);

    const nameIndex = String(index + 1).padStart(3, '0');
    if (file.kind === 'har' || file.kind === 'log') {
      if (typeof file.text !== 'string' || file.png !== undefined) fail(`Bundle ${file.kind} evidence must contain only text`);
      const inputSize = encoder.encode(file.text).byteLength;
      if (inputSize > LIMITS.inputBytes) fail(`${file.kind.toUpperCase()} input exceeds the byte limit`);
      totalInputBytes += inputSize;
      if (totalInputBytes > LIMITS.totalInputBytes) fail(`Bundle exceeds the ${LIMITS.totalInputBytes} byte aggregate input limit`);
      const clean = file.kind === 'har' ? sanitizeHar(file.text, policy) : sanitizeLog(file.text, policy);
      cleanFiles.push({
        name: `evidence-${nameIndex}.${file.kind}`,
        kind: file.kind,
        bytes: encoder.encode(clean.text),
        changes: clean.changes + prior.changes,
        omissions: mergeOmissions(file.kind, prior.omissions, clean.omissions),
        masks: 0,
      });
    } else if (file.kind === 'image') {
      if (file.text !== undefined || !(file.png instanceof Uint8Array)) fail('Bundle image evidence must contain PNG bytes only');
      if (file.masks !== undefined && (!Number.isSafeInteger(file.masks) || file.masks < 0 || file.masks > 1_000_000)) fail('Image mask count is invalid');
      totalInputBytes += file.png.byteLength;
      if (totalInputBytes > LIMITS.totalInputBytes) fail(`Bundle exceeds the ${LIMITS.totalInputBytes} byte aggregate input limit`);
      const clean = validatePng(file.png);
      cleanFiles.push({
        name: `evidence-${nameIndex}.png`,
        kind: 'image',
        bytes: clean.bytes,
        changes: clean.changes + prior.changes,
        omissions: mergeOmissions(file.kind, prior.omissions, clean.omissions),
        masks: file.masks ?? 0,
      });
    } else {
      fail(`Bundle file ${index + 1} has an unsupported evidence kind`);
    }
  }

  const cleanReport = buildReport(report, policy);

  const summaryFiles = cleanFiles.map((file) => ({
      name: file.name,
      kind: file.kind,
      bytes: file.bytes.byteLength,
      changes: file.changes,
      omissions: summarizeOmissions(file.omissions),
      masks: file.masks,
    }));
  const limitations = [
    'Automatic redaction is incomplete; inspect every included item before sharing.',
    'HAR request and response bodies, cookies, unapproved headers, and unknown fields are omitted.',
    'The bug report uses bounded credential patterns and has no automatic personal-information guarantee.',
    'PNG ancillary metadata is removed; verify image masks before sharing.',
    'Prior processing counts are app-reported and are not an independent audit of original inputs.',
  ];
  const summary: BundleResult['summary'] = hasPolicy ? {
    schemaVersion: 2,
    policy: { schemaVersion: 1, id: redactionPolicyFingerprint(policy), bodyMode: policy.bodyMode },
    files: summaryFiles,
    limitations: policy.bodyMode === 'supported'
      ? [...limitations, 'Only valid JSON and UTF-8 URL-encoded request and response bodies are included; other bodies are omitted.']
      : limitations,
  } : {
    schemaVersion: 1,
    files: summaryFiles,
    limitations,
  };
  const summaryBytes = encoder.encode(JSON.stringify(summary, null, 2));
  const uncompressedOutputBytes = cleanReport.bytes.byteLength + summaryBytes.byteLength + cleanFiles.reduce((sum, file) => sum + file.bytes.byteLength, 0);
  if (uncompressedOutputBytes > LIMITS.outputBytes) fail(`Generated bundle contents exceed the ${LIMITS.outputBytes} byte output limit`);
  const zipEntries: Record<string, Uint8Array> = {
    'bug-report.md': cleanReport.bytes,
    'processing-summary.json': summaryBytes,
  };
  for (const file of cleanFiles) zipEntries[file.name] = file.bytes;

  const bytes = zipSync(zipEntries, { level: 6 });
  if (bytes.byteLength > LIMITS.outputBytes) fail(`Generated bundle exceeds the ${LIMITS.outputBytes} byte output limit`);
  return { bytes, summary };
}
