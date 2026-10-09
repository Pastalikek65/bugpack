import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type PointerEvent } from 'react';
import { LIMITS, type BugReport, type BundleFile, type BundleResult, type EvidenceKind, type Omission, type SanitizedText } from '../core/contracts.ts';
import { assertJpegSignature, assertPngSignature, parseImageHeader } from '../image/format.ts';
import { startWorkerOperation, WorkerOperationError, type WorkerOperation, type WorkerResult } from '../worker/client.ts';
import type { ImageProcessResult, PixelMask } from '../worker/processing.worker.ts';

type Status = 'queued' | 'processing' | 'ready' | 'failed';

interface BaseEvidence {
  id: string;
  name: string;
  size: number;
  status: Status;
  error?: string;
}

interface TextEvidence extends BaseEvidence {
  kind: 'har' | 'log';
  source: File;
  sourceText?: string;
  cleanText?: string;
  changes?: number;
  omissions?: Omission[];
}

interface ImageEvidence extends BaseEvidence {
  kind: 'image';
  source: File;
  width?: number;
  height?: number;
  cleanPng?: Uint8Array;
  masks: PixelMask[];
  appliedMasks: PixelMask[];
  allowZeroArea: boolean;
  imageError?: string;
}

interface UnsupportedEvidence extends BaseEvidence {
  kind?: undefined;
}

type Evidence = TextEvidence | ImageEvidence | UnsupportedEvidence;

interface MaskDraft {
  id: string;
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

const EMPTY_REPORT: BugReport = { title: '', steps: '', expected: '', actual: '', environment: '' };
const MAX_TEXT_BYTES = LIMITS.inputBytes;
let maskSequence = 1;
let evidenceSequence = 1;

export default function App() {
  const [entries, setEntries] = useState<Evidence[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [report, setReport] = useState<BugReport>(EMPTY_REPORT);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState('');
  const [globalError, setGlobalError] = useState('');
  const [exportUrl, setExportUrl] = useState<string | null>(null);
  const [exportSummary, setExportSummary] = useState<BundleResult['summary'] | null>(null);
  const [exportError, setExportError] = useState('');
  const [maskDraft, setMaskDraft] = useState<MaskDraft | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const workerRef = useRef<{ id: number; cancel: () => void } | null>(null);
  const cancelRequested = useRef(false);
  const revisionRef = useRef(0);
  const exportUrlRef = useRef<string | null>(null);
  const bundleDownloadRef = useRef<HTMLAnchorElement>(null);

  const selected = useMemo(() => entries.find((item) => item.id === selectedId) ?? null, [entries, selectedId]);
  const totalBytes = entries.reduce((sum, item) => sum + item.size, 0);
  const readyCount = entries.filter((item) => item.status === 'ready').length;
  const failedCount = entries.filter((item) => item.status === 'failed').length;
  const allReady = entries.length > 0 && entries.every((item) => item.status === 'ready');
  const reportComplete = Object.values(report).every((value) => value.trim().length > 0);
  const imageReady = entries.every((item) => item.kind !== 'image' || (
    Boolean(item.cleanPng) && item.masks.length === item.appliedMasks.length && item.masks.every((mask, index) => sameMask(mask, item.appliedMasks[index]!)) &&
    (!item.masks.some((mask) => mask.width === 0 || mask.height === 0) || item.allowZeroArea)
  ));
  const canAcknowledge = allReady && reportComplete && imageReady && !busy;

  useEffect(() => () => {
    workerRef.current?.cancel();
    if (exportUrlRef.current) URL.revokeObjectURL(exportUrlRef.current);
  }, []);

  useEffect(() => {
    if (exportUrl) bundleDownloadRef.current?.click();
  }, [exportUrl]);

  useEffect(() => setMaskDraft(null), [selectedId]);

  const revokeExport = useCallback(() => {
    if (exportUrlRef.current) URL.revokeObjectURL(exportUrlRef.current);
    exportUrlRef.current = null;
    setExportUrl(null);
    setExportSummary(null);
  }, []);

  const invalidateReview = useCallback(() => {
    revisionRef.current += 1;
    setReviewed(false);
    revokeExport();
    setExportError('');
  }, [revokeExport]);

  const updateEntry = useCallback((id: string, update: (current: Evidence) => Evidence, invalidate = false) => {
    if (invalidate) invalidateReview();
    setEntries((current) => current.map((item) => item.id === id ? update(item) : item));
  }, [invalidateReview]);

  const setOperation = <T extends WorkerResult,>(operation: WorkerOperation<T>): Promise<T> => {
    workerRef.current = operation;
    return operation.promise.finally(() => {
      if (workerRef.current?.id === operation.id) workerRef.current = null;
    });
  };

  const processFiles = async (items: Evidence[]) => {
    const processable = items.filter((item): item is TextEvidence | ImageEvidence => Boolean(item.kind) && item.status === 'queued');
    if (processable.length === 0) return;
    cancelRequested.current = false;
    setBusy(true);
    setGlobalError('');
    let cancelledIds: string[] = [];
    try {
      for (let index = 0; index < processable.length; index++) {
        const item = processable[index]!;
        if (cancelRequested.current) {
          cancelledIds = processable.slice(index).map((queued) => queued.id);
          break;
        }
        setBusyLabel(`Processing ${index + 1} of ${processable.length}: ${item.name}`);
        updateEntry(item.id, (current) => ({ ...current, status: 'processing', error: undefined } as Evidence));
        try {
          if (item.kind === 'image') {
            const buffer = await item.source.arrayBuffer();
            if (buffer.byteLength !== item.size || buffer.byteLength > LIMITS.inputBytes) throw new Error('The image size changed or exceeds the per-file limit.');
            const bytes = new Uint8Array(buffer);
            const header = parseImageHeader(bytes);
            const extension = extensionFor(item.name);
            if ((extension === '.png' && header.format !== 'png') || ((extension === '.jpg' || extension === '.jpeg') && header.format !== 'jpeg')) {
              throw new Error('The filename extension does not match the image signature.');
            }
            if (extension === '.png') assertPngSignature(bytes);
            else assertJpegSignature(bytes);
            if (cancelRequested.current) throw new WorkerOperationError('Worker operation was cancelled.', 'cancelled');
            const operation = startWorkerOperation<ImageProcessResult>({
              type: 'process-image', bytes: buffer, masks: [], allowZeroArea: false,
            }, [buffer]);
            const result = await setOperation(operation);
            invalidateReview();
            updateEntry(item.id, (current) => current.kind === 'image' ? {
              ...current, status: 'ready', cleanPng: result.png, width: result.width, height: result.height,
              masks: [], appliedMasks: [], imageError: undefined, error: undefined,
            } : current);
          } else {
            const buffer = await item.source.arrayBuffer();
            if (buffer.byteLength !== item.size || buffer.byteLength > MAX_TEXT_BYTES) throw new Error('The text file size changed or exceeds the per-file limit.');
            let raw: string;
            try {
              raw = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
            } catch {
              throw new Error('Only valid UTF-8 text files are supported.');
            }
            if (raw.includes('\0')) throw new Error('Text files containing NUL bytes are not supported.');
            updateEntry(item.id, (current) => current.kind === 'har' || current.kind === 'log' ? { ...current, sourceText: raw } : current, true);
            if (cancelRequested.current) throw new WorkerOperationError('Worker operation was cancelled.', 'cancelled');
            const operation = startWorkerOperation<SanitizedText>({
              type: 'sanitize-text', kind: item.kind, text: raw,
            });
            const result = await setOperation(operation);
            invalidateReview();
            updateEntry(item.id, (current) => current.kind === 'har' || current.kind === 'log' ? {
              ...current, status: 'ready', cleanText: result.text, changes: result.changes, omissions: result.omissions, error: undefined,
            } : current);
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : 'File processing failed.';
          updateEntry(item.id, (current) => ({ ...current, status: 'failed', error: message } as Evidence), true);
          if (cancelRequested.current || (error instanceof WorkerOperationError && error.code === 'cancelled')) {
            cancelledIds = processable.slice(index + 1).map((queued) => queued.id);
            break;
          }
        }
      }
      if (cancelRequested.current) {
        const queued = new Set(cancelledIds);
        setEntries((current) => current.map((item) => queued.has(item.id) && item.status === 'queued' ? { ...item, status: 'failed', error: 'Processing was cancelled before this file started.' } : item));
      }
    } finally {
      setBusy(false);
      setBusyLabel('');
      workerRef.current = null;
    }
  };

  const addFiles = async (files: File[]) => {
    if (busy || files.length === 0) return;
    setGlobalError('');
    if (entries.length + files.length > LIMITS.files) {
      setGlobalError(`The ${LIMITS.files}-file limit would be exceeded. Remove files before adding this selection.`);
      return;
    }
    const newTotal = totalBytes + files.reduce((sum, file) => sum + file.size, 0);
    if (newTotal > LIMITS.totalInputBytes) {
      setGlobalError(`The ${Math.round(LIMITS.totalInputBytes / 1024 / 1024)} MiB total input limit would be exceeded. This selection was not processed.`);
      return;
    }

    const additions: Evidence[] = files.map((file) => {
      const id = `evidence-${evidenceSequence++}`;
      const safeName = validateFileName(file.name);
      const kind = kindForName(file.name);
      const base: BaseEvidence = { id, name: safeName.displayName, size: file.size, status: 'queued' };
      if (!safeName.valid) return { ...base, status: 'failed', error: safeName.error };
      if (!kind) return { ...base, status: 'failed', error: 'Choose a HAR, UTF-8 log or PNG/JPEG image file.' };
      if (file.size < 1) return { ...base, status: 'failed', error: 'The input file is empty.' };
      if (file.size > LIMITS.inputBytes) return { ...base, status: 'failed', error: `The per-file limit is ${Math.round(LIMITS.inputBytes / 1024 / 1024)} MiB.` };
      if (kind === 'image') return {
        ...base, kind, source: file, masks: [], appliedMasks: [], allowZeroArea: false,
      };
      return { ...base, kind, source: file };
    });

    invalidateReview();
    setEntries((current) => [...current, ...additions]);
    setSelectedId(additions[0]?.id ?? selectedId);
    const processable = additions.filter((item): item is TextEvidence | ImageEvidence => Boolean(item.kind) && item.status === 'queued');
    if (processable.length) void processFiles(processable);
  };

  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(event.currentTarget.files ?? []);
    event.currentTarget.value = '';
    void addFiles(selectedFiles);
  };

  const onDrop = (event: DragEvent<HTMLElement>) => {
    event.preventDefault();
    if (busy) return;
    void addFiles(Array.from(event.dataTransfer.files));
  };

  const cancelProcessing = () => {
    cancelRequested.current = true;
    workerRef.current?.cancel();
  };

  const removeEntry = (id: string) => {
    if (busy) return;
    invalidateReview();
    setEntries((current) => current.filter((item) => item.id !== id));
    if (selectedId === id) setSelectedId(entries.find((item) => item.id !== id)?.id ?? null);
  };

  const editCleanText = (item: TextEvidence, text: string) => {
    updateEntry(item.id, (current) => current.kind === 'har' || current.kind === 'log' ? { ...current, cleanText: text } : current, true);
  };

  const editReport = (field: keyof BugReport, value: string) => {
    invalidateReview();
    setReport((current) => ({ ...current, [field]: value }));
  };

  const changeMasks = (item: ImageEvidence, masks: PixelMask[], options: { allowZeroArea?: boolean } = {}) => {
    const allowZeroArea = options.allowZeroArea ?? item.allowZeroArea;
    invalidateReview();
    updateEntry(item.id, (current) => current.kind === 'image' ? {
      ...current, masks, allowZeroArea, imageError: undefined,
    } : current);
  };

  const applyMasks = async (item: ImageEvidence) => {
    if (busy) return;
    const error = validateMasks(item.masks, item.width!, item.height!, item.allowZeroArea);
    if (error) {
      updateEntry(item.id, (current) => current.kind === 'image' ? { ...current, imageError: error } : current);
      return;
    }
    cancelRequested.current = false;
    setBusy(true);
    setBusyLabel(`Applying ${activeMaskCount(item.masks)} opaque pixel masks…`);
    setExportError('');
    try {
      const buffer = await item.source.arrayBuffer();
      if (buffer.byteLength !== item.size || buffer.byteLength > LIMITS.inputBytes) throw new Error('The image size changed or exceeds the per-file limit.');
      const operation = startWorkerOperation<ImageProcessResult>({
        type: 'process-image', bytes: buffer, masks: item.masks, allowZeroArea: item.allowZeroArea,
      }, [buffer]);
      const result = await setOperation(operation);
      invalidateReview();
      updateEntry(item.id, (current) => current.kind === 'image' ? {
        ...current, cleanPng: result.png, width: result.width, height: result.height,
        appliedMasks: item.masks.map((mask) => ({ ...mask })), imageError: undefined,
      } : current);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Image mask processing failed.';
      updateEntry(item.id, (current) => current.kind === 'image' ? { ...current, imageError: message } : current);
    } finally {
      setBusy(false);
      setBusyLabel('');
      workerRef.current = null;
    }
  };

  const addMask = (item: ImageEvidence) => {
    if (!item.width || !item.height || busy) return;
    const mask: PixelMask = { id: `mask-${maskSequence++}`, x: 0, y: 0, width: 1, height: 1 };
    changeMasks(item, [...item.masks, mask]);
  };

  const updateMask = (item: ImageEvidence, id: string, field: keyof Omit<PixelMask, 'id'>, value: string) => {
    const numeric = value === '' ? 0 : Number(value);
    if (!Number.isFinite(numeric)) return;
    changeMasks(item, item.masks.map((mask) => mask.id === id ? { ...mask, [field]: numeric } : mask));
  };

  const beginMaskDrag = (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => {
    if (busy || !item.width || !item.height || event.button !== 0) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const point = toPixelPoint(event.clientX, event.clientY, bounds, item.width, item.height);
    event.currentTarget.setPointerCapture(event.pointerId);
    setMaskDraft({ id: `mask-${maskSequence++}`, startX: point.x, startY: point.y, endX: point.x, endY: point.y });
  };

  const moveMaskDrag = (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => {
    if (!maskDraft || !item.width || !item.height || !event.currentTarget.hasPointerCapture(event.pointerId)) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const point = toPixelPoint(event.clientX, event.clientY, bounds, item.width, item.height);
    setMaskDraft((current) => current ? { ...current, endX: point.x, endY: point.y } : null);
  };

  const finishMaskDrag = (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => {
    if (!maskDraft || !item.width || !item.height) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    const left = Math.min(maskDraft.startX, maskDraft.endX);
    const top = Math.min(maskDraft.startY, maskDraft.endY);
    const right = Math.max(maskDraft.startX, maskDraft.endX);
    const bottom = Math.max(maskDraft.startY, maskDraft.endY);
    const mask: PixelMask = {
      id: maskDraft.id,
      x: left,
      y: top,
      width: Math.max(1, right - left),
      height: Math.max(1, bottom - top),
    };
    setMaskDraft(null);
    changeMasks(item, [...item.masks, mask]);
  };

  const exportBundle = async () => {
    if (!canAcknowledge || !reviewed) return;
    setBusy(true);
    setBusyLabel('Building the reviewed ZIP in a local worker…');
    setExportError('');
    const sourceRevision = revisionRef.current;
    try {
      const bundleFiles: BundleFile[] = [];
      const transfer: Transferable[] = [];
      for (const item of entries) {
        if (item.kind === 'har' || item.kind === 'log') {
          bundleFiles.push({
            id: item.id,
            kind: item.kind,
            text: item.cleanText ?? '',
            prior: { changes: item.changes ?? 0, omissions: item.omissions ?? [] },
          });
        } else if (item.kind === 'image') {
          if (!item.cleanPng || !item.width || !item.height) throw new Error(`${item.name} has no regenerated clean image.`);
          const png = item.cleanPng.slice();
          transfer.push(png.buffer);
          bundleFiles.push({
            id: item.id,
            kind: 'image',
            png,
            masks: activeMaskCount(item.masks),
            prior: {
              changes: 1,
              omissions: [{ code: 'image-regenerated', count: 1, description: 'Image pixels were regenerated as PNG; source metadata was omitted.' }],
            },
          });
        } else {
          throw new Error(`${item.name} is not a supported evidence file.`);
        }
      }
      const operation = startWorkerOperation<import('../core/contracts.ts').BundleResult>({ type: 'build-bundle', files: bundleFiles, report }, transfer);
      const result = await setOperation(operation);
      if (sourceRevision !== revisionRef.current) throw new Error('Inputs changed while the ZIP was being built. Review the files again before exporting.');
      revokeExport();
      const url = URL.createObjectURL(new Blob([ownArrayBuffer(result.bytes)], { type: 'application/zip' }));
      exportUrlRef.current = url;
      setExportUrl(url);
      setExportSummary(result.summary);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : 'Could not build the ZIP.');
    } finally {
      setBusy(false);
      setBusyLabel('');
      workerRef.current = null;
    }
  };

  const acknowledge = (checked: boolean) => {
    setReviewed(checked);
    if (!checked) {
      revisionRef.current += 1;
      revokeExport();
    }
  };

  const sourceUrl = useObjectUrl(selected?.kind === 'image' ? selected.source : null);
  const cleanImageUrl = useObjectUrl(selected?.kind === 'image' ? selected.cleanPng ?? null : null, 'image/png');

  return (
    <div className="app-shell" onDragOver={(event) => { event.preventDefault(); }} onDrop={onDrop}>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="BugPack home">
          <span className="brand-mark" aria-hidden="true">B</span>
          <span>BugPack</span>
        </a>
        <div className="topbar-meta">
          <span className="local-chip"><span className="local-dot" />Local workbench</span>
          <span className="topbar-divider" aria-hidden="true" />
          <span className="topbar-caption">Evidence stays in this browser</span>
        </div>
        <a className="quiet-link" href="#review-panel">Review &amp; export</a>
      </header>

      <main id="top" className="workbench">
        <section className="workspace-heading" aria-labelledby="page-title">
          <div>
            <p className="eyebrow">LOCAL EVIDENCE REVIEW</p>
            <h1 id="page-title">Prepare a reviewed bug report</h1>
            <p className="heading-copy">Inspect the original evidence, review each cleaned file, then export only the content you approve.</p>
          </div>
          <div className="capacity-card" aria-label={`${entries.length} of ${LIMITS.files} files, ${formatBytes(totalBytes)} of 64 MiB used`}>
            <span className="capacity-label">WORKSPACE</span>
            <strong>{entries.length}<span> / {LIMITS.files} files</span></strong>
            <span className="capacity-detail">{formatBytes(totalBytes)} of 64 MiB</span>
          </div>
        </section>

        {globalError && <div className="alert alert-error" role="alert">{globalError}</div>}
        {busy && <div className="operation-bar" role="status" aria-live="polite">
          <span className="spinner" aria-hidden="true" />
          <span>{busyLabel}</span>
          <button className="button button-quiet button-small" type="button" onClick={cancelProcessing}>Cancel</button>
        </div>}

        <div className="workbench-grid">
          <aside className="panel evidence-panel" aria-labelledby="evidence-title">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">01 · ADD EVIDENCE</p>
                <h2 id="evidence-title">Files</h2>
              </div>
              <span className="count-pill">{entries.length}</span>
            </div>

            <button className="upload-dropzone" type="button" onClick={() => inputRef.current?.click()} disabled={busy}>
              <span className="upload-icon" aria-hidden="true">＋</span>
              <strong>Choose files</strong>
              <span>or drop them anywhere in the workbench</span>
              <small>HAR · UTF-8 LOG / TXT · PNG / JPEG</small>
            </button>
            <input ref={inputRef} className="visually-hidden" type="file" multiple accept=".har,.log,.txt,.png,.jpg,.jpeg,application/json,text/plain,image/png,image/jpeg" onChange={onInputChange} aria-label="Choose HAR, log, or image files" />

            <div className="file-list-heading">
              <span>Evidence list</span>
              <span>{readyCount} ready{failedCount > 0 ? ` · ${failedCount} failed` : ''}</span>
            </div>
            <ul className="file-list" aria-label="Evidence files">
              {entries.map((item) => (
                <li key={item.id}>
                  <button className={`file-row ${selectedId === item.id ? 'is-selected' : ''}`} type="button" onClick={() => setSelectedId(item.id)} aria-label={`Select ${item.name}`} aria-current={selectedId === item.id ? 'true' : undefined}>
                    <span className={`file-type-icon type-${item.kind ?? 'unknown'}`} aria-hidden="true">{iconForKind(item.kind)}</span>
                    <span className="file-row-copy">
                      <strong title={item.name}>{item.name}</strong>
                      <span>{item.kind ? kindLabel(item.kind) : 'Unsupported'} · {formatBytes(item.size)}</span>
                    </span>
                    <span className={`status-dot status-${item.status}`} aria-label={statusLabel(item.status)} title={statusLabel(item.status)} />
                  </button>
                  {!busy && <button className="file-remove" type="button" aria-label={`Remove ${item.name}`} onClick={() => removeEntry(item.id)}>×</button>}
                </li>
              ))}
            </ul>

            {entries.length === 0 ? (
              <div className="empty-list-note"><span className="empty-mark" aria-hidden="true">↳</span>Choose a file to start your review.</div>
            ) : (
              <div className="limits-note">
                <span className="limits-icon" aria-hidden="true">i</span>
                <span>Up to 16 MiB per file, 64 MiB total and 50 files. Failed files remain visible until removed.</span>
              </div>
            )}
          </aside>

          <section className="panel preview-panel" aria-labelledby="preview-title">
            <div className="panel-heading preview-panel-heading">
              <div>
                <p className="eyebrow">02 · INSPECT AND CLEAN</p>
                <h2 id="preview-title">Evidence review</h2>
              </div>
              {selected && <span className={`state-tag state-${selected.status}`}>{statusLabel(selected.status)}</span>}
            </div>
            {!selected ? (
              <div className="welcome-state">
                <span className="welcome-glyph" aria-hidden="true">⌁</span>
                <h3>Your evidence workspace is ready</h3>
                <p>Add a HAR, UTF-8 log or screenshot. BugPack creates a separate cleaned copy for review; your source file is not changed.</p>
                <button className="button button-primary" type="button" onClick={() => inputRef.current?.click()} disabled={busy}>Choose evidence</button>
              </div>
            ) : selected.status === 'queued' || selected.status === 'processing' ? (
              <div className="inline-state"><span className="spinner" aria-hidden="true" /><h3>{selected.status === 'queued' ? 'Waiting to process' : 'Preparing a clean copy'}</h3><p>The source remains in this browser while the local worker validates and processes it.</p></div>
            ) : selected.status === 'failed' ? (
              <div className="failure-state" role="alert">
                <span className="failure-icon" aria-hidden="true">!</span>
                <h3>This file could not be prepared</h3>
                <p>{selected.error}</p>
                <span className="failure-help">It will not be included in an export. Remove it or choose another file.</span>
              </div>
            ) : selected.kind === 'har' || selected.kind === 'log' ? (
              <TextReview item={selected} onEdit={editCleanText} />
            ) : selected.kind === 'image' ? (
              <ImageReview
                item={selected}
                sourceUrl={sourceUrl}
                cleanUrl={cleanImageUrl}
                draft={maskDraft}
                onBeginDrag={beginMaskDrag}
                onMoveDrag={moveMaskDrag}
                onEndDrag={finishMaskDrag}
                onCancelDrag={() => setMaskDraft(null)}
                onAddMask={addMask}
                onUpdateMask={updateMask}
                onRemoveMask={(item, id) => changeMasks(item, item.masks.filter((mask) => mask.id !== id))}
                onAllowZero={(item, value) => changeMasks(item, item.masks, { allowZeroArea: value })}
                onApplyMasks={applyMasks}
                busy={busy}
              />
            ) : (
              <div className="failure-state"><h3>Unsupported file</h3><p>Choose a HAR, UTF-8 log or PNG/JPEG image.</p></div>
            )}
          </section>

          <aside id="review-panel" className="panel report-panel" aria-labelledby="report-title">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">03 · REPORT AND EXPORT</p>
                <h2 id="report-title">Bug report</h2>
              </div>
              <span className="report-step">ZIP</span>
            </div>
            <div className="report-form">
              <label className="field-label" htmlFor="report-summary">Title</label>
              <input id="report-summary" type="text" maxLength={160} value={report.title} onChange={(event) => editReport('title', event.currentTarget.value)} placeholder="Short, specific issue title" disabled={busy} />
              <label className="field-label" htmlFor="report-steps">Steps to reproduce</label>
              <textarea id="report-steps" rows={4} maxLength={8000} value={report.steps} onChange={(event) => editReport('steps', event.currentTarget.value)} placeholder={'1. Open the settings page\n2. Change the display option\n3. Select Save'} disabled={busy} />
              <label className="field-label" htmlFor="report-expected">Expected result</label>
              <textarea id="report-expected" rows={3} maxLength={4000} value={report.expected} onChange={(event) => editReport('expected', event.currentTarget.value)} placeholder="What should have happened?" disabled={busy} />
              <label className="field-label" htmlFor="report-actual">Actual result</label>
              <textarea id="report-actual" rows={3} maxLength={4000} value={report.actual} onChange={(event) => editReport('actual', event.currentTarget.value)} placeholder="What happened instead?" disabled={busy} />
              <label className="field-label" htmlFor="report-environment">Environment</label>
              <textarea id="report-environment" rows={2} maxLength={2000} value={report.environment} onChange={(event) => editReport('environment', event.currentTarget.value)} placeholder="App version, OS, browser, device" disabled={busy} />
            </div>

            <div className="export-includes">
              <span className="export-includes-title">Bundle contents</span>
              <span><i className="include-check" aria-hidden="true">✓</i> Cleaned evidence only</span>
              <span><i className="include-check" aria-hidden="true">✓</i> Bug report and processing summary</span>
              <span className="includes-warning"><i aria-hidden="true">!</i> Original files are never added</span>
            </div>

            <label className={`review-check ${canAcknowledge ? '' : 'is-disabled'}`}>
              <input type="checkbox" checked={reviewed} onChange={(event) => acknowledge(event.currentTarget.checked)} disabled={!canAcknowledge} />
              <span className="review-check-box" aria-hidden="true" />
              <span>I reviewed each cleaned file and report, including any omissions and masks.</span>
            </label>
            {!canAcknowledge && <p className="form-hint">Ready files, a complete report and applied image masks are required before review.</p>}

            <button className="button button-primary export-button" type="button" onClick={() => void exportBundle()} disabled={!canAcknowledge || !reviewed || busy}>
              <span aria-hidden="true">↓</span> Build and download ZIP
            </button>
            {exportError && <div className="alert alert-error export-error" role="alert">{exportError}</div>}
            {exportUrl && <a className="download-link" ref={bundleDownloadRef} href={exportUrl} download="bugpack-report.zip">Download reviewed ZIP <span aria-hidden="true">↗</span></a>}
            {exportSummary && <ExportSummary summary={exportSummary} />}
          </aside>
        </div>

        <footer className="workbench-footer">
          <span>BugPack · local evidence review</span>
          <span>Cleaned outputs still need your review. Redaction cannot find every secret.</span>
        </footer>
      </main>
    </div>
  );
}

function TextReview({ item, onEdit }: { item: TextEvidence; onEdit: (item: TextEvidence, text: string) => void }) {
  const omissions = item.omissions ?? [];
  return (
    <div className="text-review">
      <div className="review-toolbar">
        <div>
          <strong>{item.name}</strong>
          <span>{kindLabel(item.kind)} · {formatBytes(item.size)}</span>
        </div>
        <span className="change-count">{item.changes ?? 0} changes</span>
      </div>
      {omissions.length > 0 && <div className="omission-strip"><strong>Review omissions</strong><span>{omissions.map((entry) => `${entry.description}: ${entry.count}`).join(' · ')}</span></div>}
      <div className="text-comparison">
        <section className="text-column" aria-labelledby="source-heading">
          <div className="editor-heading"><div><span className="column-state raw-state">SOURCE</span><h3 id="source-heading">Original text</h3></div><span className="editor-subtitle">Read only</span></div>
          <textarea className="code-editor source-editor" aria-label="Original raw text, read only" value={item.sourceText ?? ''} readOnly spellCheck={false} />
        </section>
        <section className="text-column" aria-labelledby="clean-heading">
          <div className="editor-heading"><div><span className="column-state clean-state">CLEAN COPY</span><h3 id="clean-heading">Review and edit</h3></div><span className="editor-subtitle">Editable</span></div>
          <textarea className="code-editor clean-editor" aria-label="Cleaned text, editable" value={item.cleanText ?? ''} onChange={(event) => onEdit(item, event.currentTarget.value)} spellCheck={false} />
          {item.kind === 'har' && <p className="editor-note">Keep this content as valid JSON. The worker validates edited HAR content again when you export.</p>}
          {item.kind === 'log' && <p className="editor-note">Inspect the clean copy for values that automated rules may not recognize.</p>}
        </section>
      </div>
      <p className="review-reminder"><span aria-hidden="true">↗</span> Compare both sides before approving this file for export.</p>
    </div>
  );
}

function ImageReview(props: {
  item: ImageEvidence;
  sourceUrl: string | null;
  cleanUrl: string | null;
  draft: MaskDraft | null;
  onBeginDrag: (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => void;
  onMoveDrag: (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => void;
  onEndDrag: (event: PointerEvent<HTMLDivElement>, item: ImageEvidence) => void;
  onCancelDrag: () => void;
  onAddMask: (item: ImageEvidence) => void;
  onUpdateMask: (item: ImageEvidence, id: string, field: keyof Omit<PixelMask, 'id'>, value: string) => void;
  onRemoveMask: (item: ImageEvidence, id: string) => void;
  onAllowZero: (item: ImageEvidence, value: boolean) => void;
  onApplyMasks: (item: ImageEvidence) => void;
  busy: boolean;
}) {
  const { item } = props;
  const size = item.width && item.height ? `${item.width} × ${item.height} px` : 'Dimensions pending';
  const draftRect = props.draft && item.width && item.height ? draftToRect(props.draft) : null;
  const maskError = item.imageError || validateMasks(item.masks, item.width ?? 0, item.height ?? 0, item.allowZeroArea);
  return (
    <div className="image-review">
      <div className="review-toolbar">
        <div><strong>{item.name}</strong><span>Image · {size}</span></div>
        <span className="change-count">{activeMaskCount(item.masks)} active masks</span>
      </div>
      <div className="image-comparison">
        <section className="image-column" aria-label="Original image with planned opaque masks">
          <div className="editor-heading"><div><span className="column-state raw-state">SOURCE</span><h3>Original + planned masks</h3></div><span className="editor-subtitle">Drag to cover pixels</span></div>
          <div
            className="image-stage source-stage"
            style={{ aspectRatio: item.width && item.height ? `${item.width} / ${item.height}` : '4 / 3' }}
            onPointerDown={(event) => props.onBeginDrag(event, item)}
            onPointerMove={(event) => props.onMoveDrag(event, item)}
            onPointerUp={(event) => props.onEndDrag(event, item)}
            onPointerCancel={props.onCancelDrag}
            role="img"
            aria-label={`Original image, ${size}. Drag over sensitive pixels to add a mask.`}
          >
            {props.sourceUrl ? <img src={props.sourceUrl} alt="Original evidence preview" draggable={false} /> : <span>Loading image preview…</span>}
            {item.masks.map((mask) => <span key={mask.id} className="pixel-mask-overlay" style={rectStyle(mask, item.width ?? 1, item.height ?? 1)} title={`Opaque mask at ${mask.x}, ${mask.y}, ${mask.width} × ${mask.height} pixels`} />)}
            {draftRect && <span className="pixel-mask-overlay is-draft" style={rectStyle(draftRect, item.width ?? 1, item.height ?? 1)} />}
          </div>
          <div className="image-stage-caption"><span>{item.width ? `${item.width} × ${item.height} pixels` : 'Header validation in progress'}</span><span>Black masks are opaque</span></div>
        </section>
        <section className="image-column" aria-label="Regenerated clean PNG preview">
          <div className="editor-heading"><div><span className="column-state clean-state">CLEAN PNG</span><h3>Clean output</h3></div><span className="editor-subtitle">Freshly regenerated</span></div>
          <div className="image-stage clean-stage" style={{ aspectRatio: item.width && item.height ? `${item.width} / ${item.height}` : '4 / 3' }}>
            {props.cleanUrl ? <img src={props.cleanUrl} alt="Regenerated clean PNG preview with applied masks" /> : <span>Clean image preview is not available.</span>}
          </div>
          <div className="image-stage-caption"><span>PNG · metadata stripped</span><span>{item.masks.length === item.appliedMasks.length && item.masks.every((mask, index) => sameMask(mask, item.appliedMasks[index]!)) ? 'Masks applied' : 'Masks need applying'}</span></div>
        </section>
      </div>
      <div className="mask-tools">
        <div className="mask-tools-heading"><div><h3>Opaque pixel masks</h3><p>Drag on the source or enter exact pixel coordinates.</p></div>
          <button className="button button-secondary button-small" type="button" onClick={() => props.onAddMask(item)} disabled={props.busy || !item.width}>＋ Add mask</button>
        </div>
        {item.masks.length === 0 ? <div className="no-masks">No masks added. Check the full image for sensitive content before export.</div> : (
          <div className="mask-list">
            {item.masks.map((mask, index) => (
              <fieldset className="mask-row" key={mask.id}>
                <legend>Mask {index + 1}</legend>
                {(['x', 'y', 'width', 'height'] as const).map((field) => (
                  <label className="coordinate-field" key={field}>
                    <span>{field === 'x' ? 'X' : field === 'y' ? 'Y' : field === 'width' ? 'Width' : 'Height'}</span>
                    <input type="number" min="0" step="1" max={field === 'x' || field === 'width' ? item.width : item.height} value={mask[field]} onChange={(event) => props.onUpdateMask(item, mask.id, field, event.currentTarget.value)} disabled={props.busy} aria-label={`Mask ${index + 1} ${field === 'x' ? 'X' : field === 'y' ? 'Y' : field}`} />
                  </label>
                ))}
                <button className="mask-remove" type="button" onClick={() => props.onRemoveMask(item, mask.id)} disabled={props.busy} aria-label={`Remove mask ${index + 1}`}>Remove</button>
              </fieldset>
            ))}
          </div>
        )}
        {item.masks.some((mask) => mask.width === 0 || mask.height === 0) && (
          <label className="zero-mask-review"><input type="checkbox" checked={item.allowZeroArea} onChange={(event) => props.onAllowZero(item, event.currentTarget.checked)} disabled={props.busy} /> I reviewed the zero-area mask; it covers no pixels.</label>
        )}
        {maskError && <p className="inline-error" role="alert">{maskError}</p>}
        {item.masks.length > 0 && <button className="button button-primary apply-mask-button" type="button" onClick={() => props.onApplyMasks(item)} disabled={props.busy || Boolean(maskError)}>{props.busy ? 'Processing…' : 'Apply masks and regenerate PNG'}</button>}
        <p className="mask-note">The regenerated image uses fully opaque black rectangles on whole-pixel boundaries. Review the clean result before exporting.</p>
      </div>
    </div>
  );
}

function ExportSummary({ summary }: { summary: BundleResult['summary'] }) {
  return (
    <div className="export-summary" aria-live="polite">
      <div className="summary-heading"><span className="summary-check" aria-hidden="true">✓</span><div><strong>ZIP is ready</strong><span>Processing summary</span></div></div>
      <ul>
        {summary.files.map((file, index) => <li key={`${file.name}-${index}`}><span>{file.name}</span><span>{file.kind === 'image' ? `${file.masks} masks` : `${file.changes} changes`}{file.omissions.length ? ` · ${file.omissions.reduce((sum, item) => sum + item.count, 0)} omissions` : ''}</span></li>)}
      </ul>
      {summary.limitations.length > 0 && <p>{summary.limitations.join(' ')}</p>}
    </div>
  );
}

function useObjectUrl(blob: Blob | File | Uint8Array | null, type = 'application/octet-stream'): string | null {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!blob) {
      setUrl(null);
      return;
    }
    const next = URL.createObjectURL(blob instanceof Uint8Array ? new Blob([ownArrayBuffer(blob)], { type }) : blob);
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [blob, type]);
  return url;
}

function ownArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function validateFileName(name: string): { valid: true; displayName: string } | { valid: false; displayName: string; error: string } {
  const invalid = (error: string) => ({ valid: false as const, displayName: 'Invalid file name', error });
  if (!name || name.length > 255 || name === '.' || name === '..') return invalid('The filename is empty or too long.');
  if (/[\\/:]/.test(name) || /[\p{Cc}\p{Cf}]/u.test(name)) return invalid('File paths and control characters are not accepted in filenames.');
  if (name !== name.trim() || /[. ]$/.test(name)) return invalid('Filename leading or trailing spaces and trailing periods are not accepted.');
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) return invalid('This is a reserved device filename.');
  return { valid: true, displayName: name };
}

function kindForName(name: string): EvidenceKind | undefined {
  const ext = extensionFor(name);
  if (ext === '.har') return 'har';
  if (ext === '.log' || ext === '.txt') return 'log';
  if (ext === '.png' || ext === '.jpg' || ext === '.jpeg') return 'image';
  return undefined;
}

function extensionFor(name: string): string {
  const lastDot = name.lastIndexOf('.');
  return lastDot < 0 ? '' : name.slice(lastDot).toLowerCase();
}

function validateMasks(masks: PixelMask[], width: number, height: number, allowZeroArea: boolean): string {
  if (masks.length > 500) return 'A file can have at most 500 mask rectangles.';
  for (const [index, mask] of masks.entries()) {
    if (![mask.x, mask.y, mask.width, mask.height].every(Number.isSafeInteger)) return `Mask ${index + 1} coordinates must be whole pixel values.`;
    if (mask.x < 0 || mask.y < 0 || mask.width < 0 || mask.height < 0) return `Mask ${index + 1} coordinates must be zero or greater.`;
    if (mask.x + mask.width > width || mask.y + mask.height > height) return `Mask ${index + 1} extends beyond the ${width} × ${height} image.`;
    if ((mask.width === 0 || mask.height === 0) && !allowZeroArea) return 'A zero-area mask covers no pixels. Review and acknowledge it before applying.';
  }
  return '';
}

function activeMaskCount(masks: PixelMask[]): number {
  return masks.filter((mask) => mask.width > 0 && mask.height > 0).length;
}

function sameMask(first: PixelMask, second: PixelMask): boolean {
  return first.id === second.id && first.x === second.x && first.y === second.y && first.width === second.width && first.height === second.height;
}

function toPixelPoint(clientX: number, clientY: number, bounds: DOMRect, width: number, height: number) {
  return {
    x: clamp(Math.round((clientX - bounds.left) * width / bounds.width), 0, width),
    y: clamp(Math.round((clientY - bounds.top) * height / bounds.height), 0, height),
  };
}

function clamp(value: number, min: number, max: number): number { return Math.min(max, Math.max(min, value)); }

function draftToRect(draft: MaskDraft): PixelMask {
  const x = Math.min(draft.startX, draft.endX);
  const y = Math.min(draft.startY, draft.endY);
  return { id: draft.id, x, y, width: Math.abs(draft.endX - draft.startX), height: Math.abs(draft.endY - draft.startY) };
}

function rectStyle(mask: PixelMask, width: number, height: number) {
  return {
    left: `${mask.x / width * 100}%`, top: `${mask.y / height * 100}%`,
    width: `${mask.width / width * 100}%`, height: `${mask.height / height * 100}%`,
  };
}

function iconForKind(kind: EvidenceKind | undefined): string {
  if (kind === 'har') return '{ }';
  if (kind === 'log') return '≡';
  if (kind === 'image') return '▧';
  return '?';
}

function kindLabel(kind: EvidenceKind): string {
  if (kind === 'har') return 'HAR archive';
  if (kind === 'log') return 'UTF-8 log';
  return 'Image';
}

function statusLabel(status: Status): string {
  if (status === 'ready') return 'Ready';
  if (status === 'processing') return 'Processing';
  if (status === 'queued') return 'Queued';
  return 'Failed';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}
