import { afterEach, beforeEach, it, expect, vi } from 'vitest';
import { startWorkerOperation } from '../src/worker/client.ts';
import { LIMITS } from '../src/core/contracts.ts';

class ControlledWorker {
  static latest: ControlledWorker;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror = null; onmessageerror = null;
  request!: { id: number }; terminated = false;
  constructor() { ControlledWorker.latest = this; }
  postMessage(request: { id: number }) { this.request = request; }
  terminate() { this.terminated = true; }
}
beforeEach(() => { vi.useFakeTimers(); vi.stubGlobal('Worker', ControlledWorker); vi.stubGlobal('window', globalThis); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it('enforces the unchanged production deadline and terminates a stalled worker', async () => {
  const operation = startWorkerOperation({ type: 'sanitize-text', kind: 'log', text: 'ordinary text' });
  const rejection = expect(operation.promise).rejects.toMatchObject({ code: 'timeout' });
  await vi.advanceTimersByTimeAsync(LIMITS.operationMs - 1);
  expect(ControlledWorker.latest.terminated).toBe(false);
  await vi.advanceTimersByTimeAsync(1);
  await rejection;
  expect(ControlledWorker.latest.terminated).toBe(true);
  expect(ControlledWorker.latest.onmessage).toBe(null);
});
it('ignores a mismatched response and accepts only the current operation', async () => {
  const operation = startWorkerOperation({ type: 'sanitize-text', kind: 'log', text: 'ordinary text' });
  const worker = ControlledWorker.latest;
  worker.onmessage!({ data: { id: worker.request.id + 1, ok: true, result: { text: 'stale' } } });
  expect(worker.terminated).toBe(false);
  const result = { text: 'ordinary text', changes: 0, omissions: [] };
  worker.onmessage!({ data: { id: worker.request.id, ok: true, result } });
  expect(await operation.promise).toEqual(result);
  expect(worker.terminated).toBe(true);
});
it('cancels once and disconnects handlers so late results cannot resolve it', async () => {
  const operation = startWorkerOperation({ type: 'sanitize-text', kind: 'log', text: 'ordinary text' });
  const rejection = expect(operation.promise).rejects.toMatchObject({ code: 'cancelled' });
  operation.cancel(); operation.cancel();
  await rejection;
  expect(ControlledWorker.latest.terminated).toBe(true);
  expect(ControlledWorker.latest.onmessage).toBe(null);
  await vi.advanceTimersByTimeAsync(LIMITS.operationMs);
});
