export const LIMITS = Object.freeze({ inputBytes: 16 * 1024 * 1024, totalInputBytes: 64 * 1024 * 1024, files: 50, harEntries: 5000, jsonDepth: 40, jsonNodes: 200000, imagePixels: 16000000, imageDimension: 8192, outputBytes: 128 * 1024 * 1024, operationMs: 60000 });
export type TextKind = 'har' | 'log';
export type EvidenceKind = TextKind | 'image';
export type BodyMode = 'omit' | 'supported';
export interface LiteralRedactionRule { value: string; replacement: string }
export interface RedactionPolicy {
  schemaVersion: 1;
  name: string;
  bodyMode: BodyMode;
  sensitiveKeys: readonly string[];
  literalRules: readonly LiteralRedactionRule[];
}
export interface Omission { code: string; count: number; description: string }
export interface SanitizedText { text: string; changes: number; omissions: Omission[] }
export interface BundleFile { id: string; kind: EvidenceKind; text?: string; png?: Uint8Array; masks?: number; prior?: { changes: number; omissions: Omission[] } }
export interface BugReport { title: string; steps: string; expected: string; actual: string; environment: string }
export interface BundleSummaryFile { name: string; kind: EvidenceKind; bytes: number; changes: number; omissions: Omission[]; masks: number }
export interface BundleSummaryV1 { schemaVersion: 1; files: BundleSummaryFile[]; limitations: string[] }
export interface BundleSummaryV2 extends Omit<BundleSummaryV1, 'schemaVersion'> {
  schemaVersion: 2;
  policy: { schemaVersion: 1; id: string; bodyMode: BodyMode };
}
export type BundleSummary = BundleSummaryV1 | BundleSummaryV2;
export interface BundleResult { bytes: Uint8Array; summary: BundleSummary }
