import { describe, expect, it } from 'vitest';
import { parseImageHeader } from '../src/image/format.ts';

const signature = Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]);

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const typeBytes = new TextEncoder().encode(type);
  const chunk = new Uint8Array(12 + data.length);
  const view = new DataView(chunk.buffer);
  view.setUint32(0, data.length, false);
  chunk.set(typeBytes, 4);
  chunk.set(data, 8);
  const crcBytes = new Uint8Array(typeBytes.length + data.length);
  crcBytes.set(typeBytes);
  crcBytes.set(data, typeBytes.length);
  view.setUint32(8 + data.length, crc32(crcBytes), false);
  return chunk;
}

function pngHeader({ bitDepth = 8, colorType = 6, crcValid = true }: { bitDepth?: number; colorType?: number; crcValid?: boolean } = {}): Uint8Array {
  const data = Uint8Array.from([0, 0, 0, 1, 0, 0, 0, 1, bitDepth, colorType, 0, 0, 0]);
  const chunk = pngChunk('IHDR', data);
  if (!crcValid) chunk[chunk.length - 1] ^= 0xff;
  return chunk;
}

function png(chunks: Uint8Array[]): Uint8Array {
  const size = signature.length + chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(size);
  result.set(signature);
  let offset = signature.length;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function jpegSegment(marker: number, data: Uint8Array): Uint8Array {
  const segment = new Uint8Array(data.length + 4);
  segment[0] = 0xff;
  segment[1] = marker;
  new DataView(segment.buffer).setUint16(2, data.length + 2, false);
  segment.set(data, 4);
  return segment;
}

function jpegFrame(marker: number, width: number, height: number): Uint8Array {
  return jpegSegment(marker, Uint8Array.from([8, height >>> 8, height & 0xff, width >>> 8, width & 0xff, 1, 1, 0x11, 0]));
}

function jpeg(...segments: Uint8Array[]): Uint8Array {
  const size = 4 + segments.reduce((sum, segment) => sum + segment.length, 0);
  const result = new Uint8Array(size);
  result.set([0xff, 0xd8]);
  let offset = 2;
  for (const segment of segments) {
    result.set(segment, offset);
    offset += segment.length;
  }
  result.set([0xff, 0xd9], offset);
  return result;
}

function malformedExifOffset(): Uint8Array {
  const data = new Uint8Array(32);
  data.set([0x45, 0x78, 0x69, 0x66, 0, 0, 0x49, 0x49, 42, 0, 8, 0, 0, 0], 0);
  const view = new DataView(data.buffer);
  view.setUint16(14, 1, true);
  view.setUint16(16, 0x0112, true);
  view.setUint16(18, 3, true);
  view.setUint32(20, 2, true);
  view.setUint32(24, 0xfffffff0, true);
  return jpeg(jpegSegment(0xe1, data), jpegFrame(0xc0, 10, 10));
}

describe('image header preflight', () => {
  it('rejects an oversized first JPEG frame instead of trusting a later frame', () => {
    const source = jpeg(jpegFrame(0xc0, 8193, 1), jpegFrame(0xc0, 10, 10));
    expect(() => parseImageHeader(source)).toThrow(/dimensions exceed/i);
  });

  it('rejects repeated JPEG frame headers', () => {
    const source = jpeg(jpegFrame(0xc0, 10, 10), jpegFrame(0xc0, 10, 10));
    expect(() => parseImageHeader(source)).toThrow(/multiple|repeated.*frame/i);
  });

  it('rejects JPEG frame types the browser decoder is not approved to process', () => {
    expect(() => parseImageHeader(jpeg(jpegFrame(0xc1, 10, 10)))).toThrow(/unsupported JPEG frame/i);
  });

  it('returns bounded dimensions for a supported baseline JPEG', () => {
    expect(parseImageHeader(jpeg(jpegFrame(0xc0, 640, 480)))).toMatchObject({ format: 'jpeg', width: 640, height: 480 });
  });

  it('rejects EXIF indirect orientation values whose offset is outside the segment', () => {
    expect(() => parseImageHeader(malformedExifOffset())).toThrow(/EXIF orientation value offset is invalid/i);
  });

  it('checks the IHDR checksum before browser decoding', () => {
    expect(() => parseImageHeader(png([pngHeader({ crcValid: false })]))).toThrow(/IHDR checksum/i);
  });

  it('rejects invalid PNG IHDR color settings before browser decoding', () => {
    expect(() => parseImageHeader(png([pngHeader({ bitDepth: 3 })]))).toThrow(/IHDR.*settings/i);
  });

  it('rejects APNG animation chunks instead of silently processing one frame', () => {
    const animationControl = pngChunk('acTL', Uint8Array.from([0, 0, 0, 2, 0, 0, 0, 0]));
    expect(() => parseImageHeader(png([pngHeader(), animationControl]))).toThrow(/animated PNG/i);
  });

  it('returns dimensions for a complete static PNG with a valid IHDR', () => {
    const staticPng = png([pngHeader(), pngChunk('IDAT', Uint8Array.from([0])), pngChunk('IEND', new Uint8Array())]);
    expect(parseImageHeader(staticPng)).toMatchObject({ format: 'png', width: 1, height: 1 });
  });
});
