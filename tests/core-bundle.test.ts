import { describe, expect, it } from 'vitest';
import { strFromU8, unzipSync } from 'fflate';
import type { BugReport, BundleFile } from '../src/core/contracts';
import { LIMITS } from '../src/core/contracts';
import { buildBundle } from '../src/core/bundle';
import { sanitizeHar } from '../src/core/redaction';

const report: BugReport = {
  title: 'Crash with token=report-secret',
  steps: '1. Open the page\n2. Trigger the error',
  expected: 'The operation succeeds',
  actual: 'Authorization: Bearer report-bearer-secret',
  environment: 'Browser version 1',
};

function tinyPng(): Uint8Array {
  return Uint8Array.from([
    137, 80, 78, 71, 13, 10, 26, 10,
    0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137,
    0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240, 31, 0, 5, 0, 1, 255, 137, 153, 61, 29,
    0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
  ]);
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

function chunk(type: string, data: Uint8Array): Uint8Array {
  const typeBytes = new TextEncoder().encode(type);
  const crcInput = new Uint8Array(typeBytes.length + data.length);
  crcInput.set(typeBytes);
  crcInput.set(data, typeBytes.length);
  let crc = 0xffffffff;
  for (const byte of crcInput) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  crc = (crc ^ 0xffffffff) >>> 0;
  const result = new Uint8Array(12 + data.length);
  new DataView(result.buffer).setUint32(0, data.length);
  result.set(typeBytes, 4);
  result.set(data, 8);
  new DataView(result.buffer).setUint32(8 + data.length, crc);
  return result;
}

function tinyPngWithAncillary(data: Uint8Array): Uint8Array {
  const png = tinyPng();
  const textChunk = chunk('tEXt', data);
  const iendStart = png.length - 12;
  const result = new Uint8Array(png.length + textChunk.length);
  result.set(png.subarray(0, iendStart), 0);
  result.set(textChunk, iendStart);
  result.set(png.subarray(iendStart), iendStart + textChunk.length);
  return result;
}

function tinyPngWithText(): Uint8Array {
  return tinyPngWithAncillary(new TextEncoder().encode('Comment\0png-metadata-secret'));
}

const har = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{ request: { method: 'GET', url: 'https://example.test/?token=har-secret', headers: [{ name: 'Authorization', value: 'har-header-secret' }], postData: { text: 'har-body-secret', encoding: 'base64', binary: 'YmluYXJ5LWJvZHktc2VjcmV0' } }, response: { status: 200, content: { text: 'response-secret', encoding: 'base64' } } }] } });

describe('buildBundle', () => {
  it('preserves first-pass HAR omission counts when bundling the sanitized text', () => {
    const firstPass = sanitizeHar(har);
    const result = buildBundle([{ id: 'first-pass-har', kind: 'har', text: firstPass.text, prior: firstPass }], report);
    const zippedSummary = JSON.parse(strFromU8(unzipSync(result.bytes)['processing-summary.json']));
    const fileSummary = zippedSummary.files[0];

    expect(fileSummary.changes).toBe(firstPass.changes);
    expect(fileSummary.omissions.map((item: { code: string; count: number }) => [item.code, item.count]).sort()).toEqual(
      firstPass.omissions.map((item) => [item.code, item.count]).sort(),
    );
    expect(fileSummary.omissions.find((item: { code: string }) => item.code === 'body')?.description).toBe('HAR request and response bodies were omitted.');
    expect(zippedSummary.limitations.join(' ')).toMatch(/app-reported|prior/i);
  });

  it('validates prior records and uses fixed descriptions instead of caller text', () => {
    const image = buildBundle([{
      id: 'regenerated',
      kind: 'image',
      png: tinyPng(),
      prior: { changes: 1, omissions: [{ code: 'image-regenerated', count: 1, description: 'token=untrusted-prior-description' }] },
    }], report);
    const imageSummary = image.summary.files[0];
    expect(imageSummary.omissions).toEqual([{ code: 'image-regenerated', count: 1, description: 'Image pixels were regenerated as PNG; source metadata was omitted.' }]);
    expect(JSON.stringify(image.summary)).not.toContain('untrusted-prior-description');
    expect(() => buildBundle([{ id: 'bad-code', kind: 'log', text: 'safe', prior: { changes: 1, omissions: [{ code: 'unknown', count: 1, description: 'secret' }] } }], report)).toThrow(/unsupported code/i);
    expect(() => buildBundle([{ id: 'bad-count', kind: 'har', text: har, prior: { changes: -1, omissions: [] } }], report)).toThrow(/change count/i);
    expect(() => buildBundle([{ id: 'bad-omission-count', kind: 'har', text: har, prior: { changes: 1, omissions: [{ code: 'body', count: Number.MAX_SAFE_INTEGER, description: 'x' }] } }], report)).toThrow(/omission count/i);
  });

  it('re-sanitizes edited evidence and emits only neutral entries in an openable ZIP', () => {
    const png = tinyPng();
    const originalPng = png.slice();
    const files: BundleFile[] = [
      { id: 'edited-har', kind: 'har', text: har },
      { id: 'edited-log', kind: 'log', text: 'Authorization: Bearer log-secret-123\napi_key=log-key-secret' },
      { id: 'shot', kind: 'image', png, masks: 2 },
    ];
    const inputSnapshot = JSON.stringify(files.map((file) => ({ ...file, png: undefined })));

    const result = buildBundle(files, report);
    const entries = unzipSync(result.bytes);
    const names = Object.keys(entries).sort();
    const allText = names.filter((name) => !name.endsWith('.png')).map((name) => strFromU8(entries[name])).join('\n');

    expect(names).toEqual(['bug-report.md', 'evidence-001.har', 'evidence-002.log', 'evidence-003.png', 'processing-summary.json']);
    expect(allText).not.toMatch(/har-secret|har-header-secret|har-body-secret|response-secret|YmluYXJ5LWJvZHktc2VjcmV0|log-secret-123|log-key-secret|report-secret|report-bearer-secret/);
    expect(entries['evidence-003.png']).toEqual(png);
    expect(png).toEqual(originalPng);
    expect(JSON.stringify(files.map((file) => ({ ...file, png: undefined })))).toBe(inputSnapshot);
    expect(JSON.parse(strFromU8(entries['processing-summary.json'])).files[2].masks).toBe(2);
    expect(result.summary.files.map((file) => file.name)).toEqual(names.filter((name) => name.startsWith('evidence-')));
  });

  it('rejects traversal or duplicate IDs, unsupported HAR versions, invalid PNG chunks, and size violations', () => {
    expect(() => buildBundle([], report)).toThrow(/at least one evidence/i);
    expect(() => buildBundle([{ id: '../escape', kind: 'log', text: 'safe' }], report)).toThrow(/id|filename/i);
    expect(() => buildBundle([{ id: 'same', kind: 'log', text: 'a' }, { id: 'same', kind: 'log', text: 'b' }], report)).toThrow(/duplicate|id/i);
    expect(() => buildBundle([{ id: 'bad-version', kind: 'har', text: '{"log":{"version":"2.0","entries":[]}}' }], report)).toThrow(/version/i);
    expect(() => buildBundle([{ id: 'bad-png', kind: 'image', png: Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]) }], report)).toThrow(/png|chunk/i);
    expect(() => buildBundle([{ id: 'missing', kind: 'image', png: new Uint8Array() }], report)).toThrow(/png/i);
  });

  it('strips ancillary PNG metadata and records a mask count in the processing summary', () => {
    const result = buildBundle([{ id: 'shot', kind: 'image', png: tinyPngWithText(), masks: 3 }], report);
    const entries = unzipSync(result.bytes);
    const summary = JSON.parse(strFromU8(entries['processing-summary.json']));
    expect(summary.files[0].masks).toBe(3);
    expect(summary.files[0].omissions).toEqual([{ code: 'png-metadata', count: 1, description: 'Ancillary PNG metadata chunks were removed.' }]);
    expect(strFromU8(entries['evidence-001.png'])).not.toContain('png-metadata-secret');
    expect(summary.limitations.join(' ')).toMatch(/review|redaction/i);
  });

  it('accepts regenerated PNGs above the raw input limit while keeping the ZIP payload bounded', () => {
    const largeText = new Uint8Array(LIMITS.inputBytes + 1).fill(65);
    largeText.set(new TextEncoder().encode('Comment\0'));
    const oversizedProcessedPng = tinyPngWithAncillary(largeText);
    expect(oversizedProcessedPng.byteLength).toBeGreaterThan(LIMITS.inputBytes);
    const result = buildBundle([{ id: 'processed-large', kind: 'image', png: oversizedProcessedPng }], report);
    expect(result.summary.files[0].bytes).toBe(tinyPng().byteLength);
    expect(result.summary.files[0].omissions[0].code).toBe('png-metadata');
  });
});
