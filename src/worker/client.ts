import { LIMITS, type BundleResult, type SanitizedText } from '../core/contracts.ts';
import type { ImageProcessResult, PixelMask, WorkerRequest, WorkerResponse } from './processing.worker.ts';

export type WorkerCommand =
  | { type: 'sanitize-text'; kind: 'har' | 'log'; text: string }
  | { type: 'process-image'; bytes: ArrayBuffer; masks: PixelMask[]; allowZeroArea: boolean }
  | { type: 'build-bundle'; files: import('../core/contracts.ts').BundleFile[]; report: import('../core/contracts.ts').BugReport };

export type WorkerResult = SanitizedText | ImageProcessResult | BundleResult;

export interface WorkerOperation<T extends WorkerResult> {
  id: number;
  promise: Promise<T>;
  cancel: () => void;
}

export class WorkerOperationError extends Error {
  readonly code: 'worker' | 'timeout' | 'cancelled';

  constructor(message: string, code: WorkerOperationError['code']) {
    super(message);
    this.name = 'WorkerOperationError';
    this.code = code;
  }
}

let nextId = 1;
const MAX_ID = 0x7ffffffe;

export function startWorkerOperation<T extends WorkerResult>(command: WorkerCommand, transfer: Transferable[] = []): WorkerOperation<T> {
  const id = nextId;
  nextId = nextId >= MAX_ID ? 1 : nextId + 1;
  const worker = new Worker(new URL('./processing.worker.ts', import.meta.url), { type: 'module', name: `bugpack-${id}` });
  let settled = false;
  let timeout = 0;
  let rejectPromise: (reason: Error) => void = () => {};

  const finish = () => {
    if (timeout) window.clearTimeout(timeout);
    worker.onmessage = null;
    worker.onerror = null;
    worker.onmessageerror = null;
    worker.terminate();
  };

  const promise = new Promise<T>((resolve, reject) => {
    rejectPromise = reject;
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      if (settled || event.data?.id !== id) return;
      settled = true;
      finish();
      if (!event.data.ok) {
        reject(new WorkerOperationError(event.data.error || 'Worker processing failed.', 'worker'));
        return;
      }
      if (event.data.result === undefined) {
        reject(new WorkerOperationError('The worker returned an empty result.', 'worker'));
        return;
      }
      resolve(event.data.result as T);
    };
    worker.onerror = (event) => {
      if (settled) return;
      settled = true;
      finish();
      reject(new WorkerOperationError(event.message || 'Worker processing failed unexpectedly.', 'worker'));
    };
    worker.onmessageerror = () => {
      if (settled) return;
      settled = true;
      finish();
      reject(new WorkerOperationError('The worker result could not be read.', 'worker'));
    };
    timeout = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      finish();
      reject(new WorkerOperationError(`Worker operation exceeded the ${Math.round(LIMITS.operationMs / 1000)} second deadline.`, 'timeout'));
    }, LIMITS.operationMs);
    try {
      worker.postMessage({ ...command, id } as WorkerRequest, transfer);
    } catch (error) {
      settled = true;
      finish();
      reject(new WorkerOperationError(error instanceof Error ? error.message : 'Could not start worker operation.', 'worker'));
    }
  });

  return {
    id,
    promise,
    cancel: () => {
      if (settled) return;
      settled = true;
      finish();
      rejectPromise(new WorkerOperationError('Worker operation was cancelled.', 'cancelled'));
    },
  };
}
