export const LIMITS = Object.freeze({ inputBytes: 16 * 1024 * 1024, totalInputBytes: 64 * 1024 * 1024, files: 50, harEntries: 5000, jsonDepth: 40, jsonNodes: 200000, imagePixels: 16000000, imageDimension: 8192, outputBytes: 128 * 1024 * 1024, operationMs: 60000 });
export type TextKind = 'har' | 'log';
export type EvidenceKind = TextKind | 'image';
export interface Omission { code: string; count: number; description: string }
export interface SanitizedText { text: string; changes: number; omissions: Omission[] }
export interface BundleFile { id: string; kind: EvidenceKind; text?: string; png?: Uint8Array; masks?: number; prior?: { changes: number; omissions: Omission[] } }
export interface BugReport { title: string; steps: string; expected: string; actual: string; environment: string }
export interface BundleResult { bytes: Uint8Array; summary: { schemaVersion: 1; files: { name: string; kind: EvidenceKind; bytes: number; changes: number; omissions: Omission[]; masks: number }[]; limitations: string[] } }
