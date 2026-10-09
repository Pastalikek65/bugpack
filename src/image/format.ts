import { LIMITS } from '../core/contracts.ts';

export interface ImageHeader {
  format: 'png' | 'jpeg';
  width: number;
  height: number;
  orientation: number;
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

function fail(message: string): never {
  throw new Error(message);
}

function validateDimensions(width: number, height: number, orientation = 1): ImageHeader {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) {
    return fail('The image header has invalid dimensions.');
  }
  if (width > LIMITS.imageDimension || height > LIMITS.imageDimension || width * height > LIMITS.imagePixels) {
    return fail(`Image dimensions exceed the ${LIMITS.imageDimension}px side or ${LIMITS.imagePixels.toLocaleString()} pixel limit.`);
  }
  const swapsAxes = orientation >= 5 && orientation <= 8;
  const displayWidth = swapsAxes ? height : width;
  const displayHeight = swapsAxes ? width : height;
  if (displayWidth > LIMITS.imageDimension || displayHeight > LIMITS.imageDimension || displayWidth * displayHeight > LIMITS.imagePixels) {
    return fail('The oriented image dimensions exceed the supported limit.');
  }
  return { format: 'jpeg', width: displayWidth, height: displayHeight, orientation };
}

export function parseImageHeader(bytes: Uint8Array): ImageHeader {
  if (bytes.length >= PNG_SIGNATURE.length && PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)) return parsePngHeader(bytes);

  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    return fail('Image signature does not match a PNG or JPEG file.');
  }

  let offset = 2;
  let width: number | undefined;
  let height: number | undefined;
  let orientation = 1;
  let markerCount = 0;
  let sawFrame = false;
  while (offset < bytes.length && markerCount < 10000) {
    markerCount++;
    if (bytes[offset] !== 0xff) return fail('The JPEG marker stream is malformed.');
    while (offset < bytes.length && bytes[offset] === 0xff) offset++;
    if (offset >= bytes.length) return fail('The JPEG marker stream is truncated.');
    const marker = bytes[offset++]!;
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) return fail('The JPEG segment length is truncated.');
    const segmentLength = (bytes[offset]! << 8) | bytes[offset + 1]!;
    if (segmentLength < 2 || offset + segmentLength > bytes.length) return fail('The JPEG segment length is invalid.');
    const dataStart = offset + 2;
    const dataLength = segmentLength - 2;

    if (marker === 0xe1) orientation = parseExifOrientation(bytes, dataStart, dataLength) ?? orientation;
    if (isStartOfFrame(marker)) {
      if (marker !== 0xc0 && marker !== 0xc2) return fail('Unsupported JPEG frame type; only baseline or progressive JPEG is accepted.');
      if (sawFrame) return fail('The JPEG contains a repeated frame header.');
      if (dataLength < 6) return fail('The JPEG frame header is truncated.');
      const componentCount = bytes[dataStart + 5]!;
      if (componentCount < 1 || dataLength < 6 + componentCount * 3) return fail('The JPEG frame component table is truncated.');
      height = (bytes[dataStart + 1]! << 8) | bytes[dataStart + 2]!;
      width = (bytes[dataStart + 3]! << 8) | bytes[dataStart + 4]!;
      validateDimensions(width, height);
      sawFrame = true;
    }
    offset += segmentLength;
  }
  if (markerCount >= 10000) return fail('The JPEG has too many marker segments.');
  if (width === undefined || height === undefined) return fail('The JPEG does not contain a supported frame header.');
  const dimensions = validateDimensions(width, height, orientation);
  return { ...dimensions, format: 'jpeg' };
}

function parsePngHeader(bytes: Uint8Array): ImageHeader {
  if (bytes.length < 33) return fail('The PNG is missing a complete IHDR header.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = view.getUint32(8, false);
  const headerType = String.fromCharCode(bytes[12]!, bytes[13]!, bytes[14]!, bytes[15]!);
  if (headerLength !== 13 || headerType !== 'IHDR') return fail('The PNG is missing a valid first IHDR header.');
  const expectedCrc = readUint32(view, 29);
  if (crc32Range(bytes, 12, 29) !== expectedCrc) return fail('The PNG IHDR checksum is invalid.');

  const width = view.getUint32(16, false);
  const height = view.getUint32(20, false);
  const bitDepth = bytes[24]!;
  const colorType = bytes[25]!;
  const validDepths: Record<number, readonly number[]> = {
    0: [1, 2, 4, 8, 16],
    2: [8, 16],
    3: [1, 2, 4, 8],
    4: [8, 16],
    6: [8, 16],
  };
  if (!validDepths[colorType]?.includes(bitDepth) || bytes[26] !== 0 || bytes[27] !== 0 || bytes[28] > 1) {
    return fail('The PNG IHDR uses unsupported color or compression settings.');
  }
  const dimensions = validateDimensions(width, height);

  let offset = 8;
  let chunks = 0;
  let sawHeader = false;
  let sawData = false;
  let sawEnd = false;
  while (offset < bytes.length && chunks < 10000) {
    chunks++;
    if (offset + 12 > bytes.length) return fail('The PNG chunk header is truncated.');
    const length = readUint32(view, offset);
    if (length > bytes.length - offset - 12) return fail('The PNG chunk length exceeds the available bytes.');
    const type = String.fromCharCode(bytes[offset + 4]!, bytes[offset + 5]!, bytes[offset + 6]!, bytes[offset + 7]!);
    if (!/^[A-Za-z]{4}$/.test(type)) return fail('The PNG contains an invalid chunk name.');
    if (chunks === 1 && (type !== 'IHDR' || length !== 13)) return fail('The PNG must start with one IHDR chunk.');
    if (type === 'acTL' || type === 'fcTL' || type === 'fdAT') return fail('Animated PNG files are not supported.');
    if (type === 'IHDR') {
      if (sawHeader || chunks !== 1) return fail('The PNG contains a repeated or misplaced IHDR chunk.');
      sawHeader = true;
    } else if (type === 'IDAT') {
      if (!sawHeader || sawEnd) return fail('The PNG IDAT chunk is misplaced.');
      sawData = true;
    } else if (type === 'IEND') {
      if (length !== 0 || !sawData || sawEnd) return fail('The PNG IEND chunk is invalid.');
      sawEnd = true;
    }
    offset += 12 + length;
    if (sawEnd) break;
  }
  if (chunks >= 10000 || !sawHeader || !sawData || !sawEnd || offset !== bytes.length) return fail('The PNG chunk stream is incomplete or oversized.');
  return { ...dimensions, format: 'png' };
}

function readUint32(view: DataView, offset: number): number {
  return view.getUint32(offset, false);
}

function crc32Range(bytes: Uint8Array, start: number, end: number): number {
  let crc = 0xffffffff;
  for (let index = start; index < end; index++) {
    crc ^= bytes[index]!;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function isStartOfFrame(marker: number): boolean {
  return [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker);
}

function parseExifOrientation(bytes: Uint8Array, start: number, length: number): number | undefined {
  if (length < 14 || String.fromCharCode(...bytes.subarray(start, start + 6)) !== 'Exif\0\0') return undefined;
  const tiff = start + 6;
  const littleEndian = bytes[tiff] === 0x49 && bytes[tiff + 1] === 0x49;
  if (!littleEndian && !(bytes[tiff] === 0x4d && bytes[tiff + 1] === 0x4d)) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const within = (position: number, size: number) => position >= tiff && position + size <= start + length;
  if (!within(tiff, 8) || view.getUint16(tiff + 2, littleEndian) !== 42) return undefined;
  const ifdOffset = view.getUint32(tiff + 4, littleEndian);
  const ifd = tiff + ifdOffset;
  if (!within(ifd, 2)) return undefined;
  const count = view.getUint16(ifd, littleEndian);
  if (count > 1024 || !within(ifd + 2, count * 12)) return undefined;
  for (let index = 0; index < count; index++) {
    const entry = ifd + 2 + index * 12;
    if (view.getUint16(entry, littleEndian) !== 0x0112) continue;
    const type = view.getUint16(entry + 2, littleEndian);
    const itemCount = view.getUint32(entry + 4, littleEndian);
    if (type !== 3 || itemCount < 1) return undefined;
    let value: number;
    if (itemCount === 1) {
      value = view.getUint16(entry + 8, littleEndian);
    } else {
      const indirect = tiff + view.getUint32(entry + 8, littleEndian);
      if (indirect < tiff + 8 || !within(indirect, 2)) return fail('JPEG EXIF orientation value offset is invalid.');
      value = view.getUint16(indirect, littleEndian);
    }
    return value >= 1 && value <= 8 ? value : undefined;
  }
  return undefined;
}

export function assertPngSignature(bytes: Uint8Array): void {
  if (bytes.length < PNG_SIGNATURE.length || !PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)) {
    fail('The file extension says PNG, but its signature is different.');
  }
}

export function assertJpegSignature(bytes: Uint8Array): void {
  if (bytes.length < 2 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    fail('The file extension says JPEG, but its signature is different.');
  }
}

export function stripPngAncillaryChunks(bytes: Uint8Array): Uint8Array {
  assertPngSignature(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kept: Uint8Array[] = [bytes.subarray(0, 8)];
  let offset = 8;
  let chunks = 0;
  let sawHeader = false;
  let sawData = false;
  let sawEnd = false;
  let total = 8;

  while (offset < bytes.length && chunks < 10000) {
    chunks++;
    if (offset + 12 > bytes.length) return fail('The generated PNG contains a truncated chunk.');
    const length = view.getUint32(offset, false);
    const end = offset + 12 + length;
    if (end > bytes.length) return fail('The generated PNG chunk exceeds the available output.');
    const type = String.fromCharCode(bytes[offset + 4]!, bytes[offset + 5]!, bytes[offset + 6]!, bytes[offset + 7]!);
    const critical = (bytes[offset + 4]! & 0x20) === 0;

    if (chunks === 1 && (type !== 'IHDR' || length !== 13)) return fail('The generated PNG has no valid first IHDR chunk.');
    if (type === 'IHDR') {
      if (sawHeader) return fail('The generated PNG contains multiple IHDR chunks.');
      sawHeader = true;
    } else if (type === 'IDAT') {
      if (!sawHeader || sawEnd) return fail('The generated PNG has IDAT chunks in an invalid position.');
      sawData = true;
    } else if (type === 'IEND') {
      if (!sawData || length !== 0 || sawEnd) return fail('The generated PNG has an invalid IEND chunk.');
      sawEnd = true;
    } else if (critical && type !== 'PLTE') {
      return fail(`The generated PNG uses an unsupported critical chunk (${type}).`);
    } else if (type === 'PLTE' && sawData) {
      return fail('The generated PNG palette appears after image data.');
    }

    if (critical) {
      if (type !== 'IHDR' && !sawHeader) return fail('The generated PNG is missing its IHDR chunk.');
      const chunk = bytes.subarray(offset, end);
      kept.push(chunk);
      total += chunk.length;
      if (total > LIMITS.outputBytes) return fail('The regenerated PNG exceeds the output size limit.');
    }
    offset = end;
    if (sawEnd) break;
  }
  if (chunks >= 10000 || !sawHeader || !sawData || !sawEnd || offset !== bytes.length) {
    return fail('The generated PNG has an incomplete or oversized chunk stream.');
  }
  const output = new Uint8Array(total);
  let destination = 0;
  for (const chunk of kept) {
    output.set(chunk, destination);
    destination += chunk.length;
  }
  return output;
}
