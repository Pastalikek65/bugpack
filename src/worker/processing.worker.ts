import { buildBundle } from '../core/bundle.ts';
import { LIMITS, type BugReport, type BundleFile, type EvidenceKind, type SanitizedText } from '../core/contracts.ts';
import { sanitizeHar, sanitizeLog } from '../core/redaction.ts';
import { parseImageHeader, stripPngAncillaryChunks } from '../image/format.ts';

export interface PixelMask {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

export type WorkerRequest =
  | { id: number; type: 'sanitize-text'; kind: 'har' | 'log'; text: string }
  | { id: number; type: 'process-image'; bytes: ArrayBuffer; masks: PixelMask[]; allowZeroArea: boolean }
  | { id: number; type: 'build-bundle'; files: BundleFile[]; report: BugReport };

export interface ImageProcessResult {
  png: Uint8Array;
  width: number;
  height: number;
  masks: number;
}

export interface WorkerResponse {
  id: number;
  ok: boolean;
  result?: SanitizedText | ImageProcessResult | Awaited<ReturnType<typeof buildBundle>>;
  error?: string;
}

interface WorkerScope {
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
}

const scope = self as unknown as WorkerScope;
const MAX_OPERATION_ID = 0x7ffffffe;

scope.addEventListener('message', (event) => {
  const request = event.data;
  if (!request || !Number.isSafeInteger(request.id) || request.id < 1 || request.id > MAX_OPERATION_ID) return;
  void handleRequest(request);
});

async function handleRequest(request: WorkerRequest): Promise<void> {
  try {
    if (request.type === 'sanitize-text') {
      if (typeof request.text !== 'string') throw new Error('Text input is missing.');
      const result = request.kind === 'har' ? sanitizeHar(request.text) : sanitizeLog(request.text);
      if (new TextEncoder().encode(result.text).byteLength > LIMITS.inputBytes) {
        throw new Error('Cleaned text exceeds the 16 MiB review/export limit.');
      }
      scope.postMessage({ id: request.id, ok: true, result });
      return;
    }

    if (request.type === 'process-image') {
      const result = await processImage(new Uint8Array(request.bytes), request.masks, request.allowZeroArea);
      scope.postMessage({ id: request.id, ok: true, result }, [result.png.buffer]);
      return;
    }

    if (request.type === 'build-bundle') {
      validateBundleInputs(request.files, request.report);
      const result = await buildBundle(request.files, request.report);
      if (!(result.bytes instanceof Uint8Array) || result.bytes.byteLength === 0 || result.bytes.byteLength > LIMITS.outputBytes) {
        throw new Error('The generated bundle is empty or exceeds the output limit.');
      }
      scope.postMessage({ id: request.id, ok: true, result }, [result.bytes.buffer]);
      return;
    }
    throw new Error('Unsupported worker operation.');
  } catch (error) {
    scope.postMessage({ id: request.id, ok: false, error: error instanceof Error ? error.message : 'Worker processing failed.' });
  }
}

async function processImage(input: Uint8Array, masks: PixelMask[], allowZeroArea: boolean): Promise<ImageProcessResult> {
  if (input.byteLength === 0 || input.byteLength > LIMITS.inputBytes) throw new Error('Image input is empty or exceeds the per-file limit.');
  if (!Array.isArray(masks) || masks.length > 500) throw new Error('The image has too many mask rectangles.');

  // Read the dimensions and JPEG orientation before any browser image decoder allocates pixels.
  const header = parseImageHeader(input);
  if (header.format === 'jpeg') {
    // The magic bytes and full JPEG frame must agree with the selected .jpg/.jpeg extension in the UI.
    // parseImageHeader walks bounded segments and rejects JPEGs without a supported frame header.
  }

  for (const mask of masks) {
    if (!mask || typeof mask.id !== 'string' || mask.id.length > 80) throw new Error('A mask has an invalid identifier.');
    for (const value of [mask.x, mask.y, mask.width, mask.height]) {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error('Mask coordinates must be non-negative whole pixels.');
    }
    if (mask.x + mask.width > header.width || mask.y + mask.height > header.height) throw new Error('A mask extends beyond the image bounds.');
    if ((mask.width === 0 || mask.height === 0) && !allowZeroArea) throw new Error('Zero-area masks require the explicit review acknowledgement.');
  }

  const mime = header.format === 'png' ? 'image/png' : 'image/jpeg';
  const imageBuffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(imageBuffer).set(input);
  const bitmap = await createImageBitmap(new Blob([imageBuffer], { type: mime }), { imageOrientation: 'from-image' });
  try {
    if (bitmap.width !== header.width || bitmap.height !== header.height) {
      throw new Error('Decoded image dimensions do not match the validated orientation header.');
    }
    if (bitmap.width > LIMITS.imageDimension || bitmap.height > LIMITS.imageDimension || bitmap.width * bitmap.height > LIMITS.imagePixels) {
      throw new Error('Decoded image dimensions exceed the supported limit.');
    }

    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext('2d', { alpha: true });
    if (!context) throw new Error('The browser could not create an image canvas.');
    context.clearRect(0, 0, bitmap.width, bitmap.height);
    context.drawImage(bitmap, 0, 0, bitmap.width, bitmap.height);
    context.globalCompositeOperation = 'source-over';
    context.fillStyle = '#000000';
    for (const mask of masks) {
      if (mask.width > 0 && mask.height > 0) context.fillRect(mask.x, mask.y, mask.width, mask.height);
    }

    const blob = await canvas.convertToBlob({ type: 'image/png' });
    if (blob.size === 0 || blob.size > LIMITS.outputBytes) throw new Error('The regenerated image exceeds the output limit.');
    const encoded = new Uint8Array(await blob.arrayBuffer());
    const png = stripPngAncillaryChunks(encoded);
    return {
      png,
      width: bitmap.width,
      height: bitmap.height,
      masks: masks.filter((mask) => mask.width > 0 && mask.height > 0).length,
    };
  } finally {
    bitmap.close();
  }
}

function validateBundleInputs(files: BundleFile[], report: BugReport): void {
  if (!Array.isArray(files) || files.length < 1 || files.length > LIMITS.files) throw new Error('Select at least one ready evidence file before exporting.');
  let totalTextBytes = 0;
  let totalImageBytes = 0;
  for (const file of files) {
    if (!file || typeof file.id !== 'string' || !file.id || file.id.length > 100) throw new Error('A bundle input has an invalid identifier.');
    if (!['har', 'log', 'image'].includes(file.kind)) throw new Error('A bundle input has an unsupported type.');
    if (file.kind === 'har' || file.kind === 'log') {
      if (typeof file.text !== 'string') throw new Error('A cleaned text file is missing its edited text.');
      const bytes = new TextEncoder().encode(file.text).byteLength;
      totalTextBytes += bytes;
      if (bytes > LIMITS.inputBytes) throw new Error('A cleaned text file exceeds the 16 MiB review/export limit.');
      if (file.kind === 'har') {
        try {
          JSON.parse(file.text);
        } catch {
          throw new Error('The edited HAR must remain valid JSON before export.');
        }
      }
    } else {
      if (!(file.png instanceof Uint8Array) || file.png.byteLength === 0) throw new Error('An image must be regenerated as a clean PNG before export.');
      totalImageBytes += file.png.byteLength;
    }
  }
  if (totalTextBytes + totalImageBytes > LIMITS.outputBytes) throw new Error('The cleaned files exceed the bundle output limit.');
  for (const field of ['title', 'steps', 'expected', 'actual', 'environment'] as const) {
    if (typeof report?.[field] !== 'string' || !report[field].trim()) throw new Error(`Complete the bug report field: ${field}.`);
  }
}
