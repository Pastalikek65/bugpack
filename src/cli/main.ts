#!/usr/bin/env node
import { constants as fsConstants } from 'node:fs';
import { lstat, open, link, unlink } from 'node:fs/promises';
import { builtinModules } from 'node:module';
import { basename, dirname, join, parse as parsePath, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { LIMITS, type BugReport, type BundleFile, type RedactionPolicy } from '../core/contracts.ts';
import { buildBundle } from '../core/bundle.ts';
import {
  DEFAULT_REDACTION_POLICY,
  parseRedactionPolicy,
  parseStrictJson,
  redactionPolicyFingerprint,
} from '../core/policy.ts';
import { sanitizeHar, sanitizeLog } from '../core/redaction.ts';

declare const __BUGPACK_VERSION__: string;

const HELP = `BugPack local text CLI

Usage:
  bugpack doctor [--json]
  bugpack policy validate --file <policy.json> [--json]
  bugpack clean --kind har|log --input <file> --out <file> [--policy <policy.json>] [--json]
  bugpack bundle --har <file>... --log <file>... [--report <report.json>]
                  --out <bundle.zip> --reviewed [--policy <policy.json>] [--json]

Commands:
  doctor          Check the local runtime. This command makes no network requests.
  policy validate Validate a version 1 redaction policy without printing its rules.
  clean           Clean one HAR or text log and write a new file without replacing anything.
  bundle          Build a ZIP from HAR/log files and an optional JSON report.

Options:
  --file          Policy file for "policy validate".
  --kind          Input type for "clean": har or log.
  --input         Input file for "clean".
  --har           HAR input for "bundle"; may be repeated.
  --log           Text log input for "bundle"; may be repeated.
  --report        Optional report JSON with title, steps, expected, actual, and environment strings.
  --policy        Optional version 1 redaction policy.
  --out           Required new output path. Existing files are never replaced.
  --reviewed      Confirm that you reviewed the inputs and will review the resulting bundle.
  --json          Write a stable JSON result or error to standard output.
  --help          Show this help.

Images are not supported by this CLI. Use the BugPack browser app to process images.
Automatic redaction is incomplete and does not guarantee removal of personal information.
`;

type ErrorCode = 'INVALID_ARGUMENT' | 'INVALID_INPUT' | 'INVALID_POLICY' | 'OUTPUT_UNSAFE' | 'OUTPUT_EXISTS' | 'NODE_VERSION_UNSUPPORTED';
class CliError extends Error {
  constructor(readonly code: ErrorCode, message: string) {
    super(message);
  }
}

type ParsedArgs = { values: Map<string, string[]>; flags: Set<string> };

function fail(code: ErrorCode, message: string): never {
  throw new CliError(code, message);
}

function parseOptions(args: string[], allowedValues: readonly string[], allowedFlags: readonly string[], repeatable: readonly string[] = []): ParsedArgs {
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
    if (!token.startsWith('--')) fail('INVALID_ARGUMENT', 'Unexpected command argument. Use --help to see valid options.');
    const name = token.slice(2);
    if (allowedFlags.includes(name)) {
      if (flags.has(name)) fail('INVALID_ARGUMENT', 'An option was provided more than once.');
      flags.add(name);
      continue;
    }
    if (!allowedValues.includes(name)) {
      if (name === 'image') fail('INVALID_ARGUMENT', 'Image processing is supported in the BugPack browser app, not this text-only CLI.');
      fail('INVALID_ARGUMENT', 'An unsupported option was provided. Use --help to see valid options.');
    }
    const value = args[++index];
    if (!value || value.startsWith('--')) fail('INVALID_ARGUMENT', 'An option is missing its value.');
    const collected = values.get(name) ?? [];
    if (!repeatable.includes(name) && collected.length) fail('INVALID_ARGUMENT', 'An option was provided more than once.');
    collected.push(value);
    values.set(name, collected);
  }
  return { values, flags };
}

function requiredOption(args: ParsedArgs, key: string): string {
  const value = args.values.get(key)?.[0];
  if (!value) fail('INVALID_ARGUMENT', `The --${key} option is required.`);
  return value;
}

function optionalOption(args: ParsedArgs, key: string): string | undefined {
  return args.values.get(key)?.[0];
}

function safeLexicalPath(input: string, code: ErrorCode = 'OUTPUT_UNSAFE'): string {
  if (!input || /[\u0000-\u001f\u007f]/.test(input)) fail(code, 'The supplied path is unsafe.');
  const absolute = resolve(process.cwd(), input);
  if (absolute.startsWith('\\\\?\\') || absolute.startsWith('\\\\.\\')) fail(code, 'Device and extended-length paths are unsupported.');
  const root = parsePath(absolute).root;
  if (absolute.slice(root.length).includes(':')) fail(code, 'Alternate data stream paths are unsupported.');
  return absolute;
}

async function assertNoSymlinkParents(absolute: string, includeLeaf: boolean, code: ErrorCode): Promise<void> {
  const parsed = parsePath(absolute);
  const relativeParts = absolute.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean);
  let cursor = parsed.root;
  const limit = includeLeaf ? relativeParts.length : Math.max(0, relativeParts.length - 1);
  for (let index = 0; index < limit; index++) {
    cursor = join(cursor, relativeParts[index]);
    let info;
    try {
      info = await lstat(cursor);
    } catch {
      fail(code, 'The path does not exist or cannot be inspected safely.');
    }
    if (info.isSymbolicLink()) fail(code, 'Paths through symbolic links are unsupported.');
    if (index < limit - 1 && !info.isDirectory()) fail(code, 'A path parent is not a directory.');
    if (index === limit - 1 && includeLeaf && !info.isFile()) fail(code, 'Input paths must name regular files.');
  }
}

async function readRegularFile(pathValue: string, limit: number, code: 'INVALID_INPUT' | 'INVALID_POLICY', message: string): Promise<Uint8Array> {
  let absolute: string;
  try {
    absolute = safeLexicalPath(pathValue, code);
    await assertNoSymlinkParents(absolute, true, code);
    const handle = await open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > limit) fail(code, message);
      const bytes = new Uint8Array(info.size);
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
        if (!bytesRead) fail(code, message);
        offset += bytesRead;
      }
      const extra = new Uint8Array(1);
      const { bytesRead: trailing } = await handle.read(extra, 0, 1, offset);
      if (trailing || (await handle.stat()).size !== info.size) fail(code, message);
      return bytes;
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail(code, message);
  }
}

function decodeUtf8(bytes: Uint8Array, code: 'INVALID_INPUT' | 'INVALID_POLICY', message: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(code, message);
  }
}

async function createOutputExclusive(pathValue: string, bytes: Uint8Array): Promise<void> {
  const absolute = safeLexicalPath(pathValue);
  const leaf = basename(absolute);
  if (!leaf || leaf === '.' || leaf === '..' || /[:\\/]/.test(leaf) || /[. ]$/.test(leaf) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(leaf)) {
    fail('OUTPUT_UNSAFE', 'The output filename is unsafe.');
  }
  await assertNoSymlinkParents(absolute, false, 'OUTPUT_UNSAFE');
  const parent = dirname(absolute);
  let parentInfo;
  try {
    parentInfo = await lstat(parent);
  } catch {
    fail('OUTPUT_UNSAFE', 'The output directory must already exist.');
  }
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) fail('OUTPUT_UNSAFE', 'The output directory is unsafe.');
  const temporary = join(parent, `.bugpack-${randomUUID()}.tmp`);
  let created = false;
  try {
    const handle = await open(temporary, 'wx', 0o600);
    created = true;
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await link(temporary, absolute);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST' || code === 'EPERM') fail('OUTPUT_EXISTS', 'The output already exists or cannot be created exclusively.');
      fail('OUTPUT_UNSAFE', 'The output could not be created atomically.');
    }
  } finally {
    if (created) {
      try { await unlink(temporary); } catch { /* Keep an already-linked output; temporary cleanup is best effort. */ }
    }
  }
}

async function loadPolicy(pathValue?: string, accountInput?: (bytes: number) => void): Promise<RedactionPolicy | undefined> {
  if (!pathValue) return undefined;
  const bytes = await readRegularFile(pathValue, 64 * 1024, 'INVALID_POLICY', 'The redaction policy is invalid or unreadable.');
  accountInput?.(bytes.byteLength);
  const source = decodeUtf8(bytes, 'INVALID_POLICY', 'The redaction policy is invalid or unreadable.');
  try {
    return parseRedactionPolicy(source);
  } catch {
    fail('INVALID_POLICY', 'The redaction policy is invalid. Check its version and fields.');
  }
}

async function loadReport(pathValue?: string, accountInput?: (bytes: number) => void): Promise<BugReport> {
  if (!pathValue) {
    return {
      title: 'Report details not provided',
      steps: 'No reproduction steps were supplied. Add steps you have verified before sharing.',
      expected: 'No expected result was supplied.',
      actual: 'No actual result was supplied.',
      environment: 'No environment details were supplied.',
    };
  }
  const bytes = await readRegularFile(pathValue, 256 * 1024, 'INVALID_INPUT', 'The report JSON is invalid or unreadable.');
  accountInput?.(bytes.byteLength);
  const source = decodeUtf8(bytes, 'INVALID_INPUT', 'The report JSON is invalid or unreadable.');
  let value: unknown;
  try {
    value = parseStrictJson(source, { maxBytes: 256 * 1024, maxDepth: 8, maxNodes: 128 });
  } catch {
    fail('INVALID_INPUT', 'The report JSON is invalid or unreadable.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_INPUT', 'The report JSON must contain exactly title, steps, expected, actual, and environment text fields.');
  const record = value as Record<string, unknown>;
  const allowed = ['title', 'steps', 'expected', 'actual', 'environment'];
  if (Object.keys(record).length !== allowed.length || allowed.some((key) => typeof record[key] !== 'string') || Object.keys(record).some((key) => !allowed.includes(key))) {
    fail('INVALID_INPUT', 'The report JSON must contain exactly title, steps, expected, actual, and environment text fields.');
  }
  return record as unknown as BugReport;
}

function outputPolicy(policy: RedactionPolicy | undefined): Record<string, unknown> {
  return policy ? { schemaVersion: 1, redactionPolicyId: redactionPolicyFingerprint(policy), bodyMode: policy.bodyMode } : { schemaVersion: 1, redactionPolicyId: null, bodyMode: DEFAULT_REDACTION_POLICY.bodyMode };
}

function resultJson(value: unknown): string {
  return `${JSON.stringify(value)}\n`;
}

async function run(args: string[]): Promise<{ result: unknown; human: string }> {
  if (args.length === 0) fail('INVALID_ARGUMENT', 'Choose a command. Use --help to see available commands.');
  const command = args[0];
  if (command === 'doctor') {
    const parsed = parseOptions(args.slice(1), [], []);
    if (parsed.values.size || parsed.flags.size) fail('INVALID_ARGUMENT', 'The doctor command accepts only --json.');
    const major = Number(/^v?(\d+)/.exec(process.versions.node)?.[1] ?? 0);
    const result = { ok: major === 24, command: 'doctor', version: __BUGPACK_VERSION__, runtime: `node ${process.versions.node}`, supported: major === 24, network: 'not used', mode: 'offline' };
    if (!result.ok) fail('NODE_VERSION_UNSUPPORTED', 'BugPack CLI requires Node.js 24.');
    return { result, human: `BugPack CLI is ready on Node.js ${process.versions.node}. This check made no network requests.` };
  }
  if (command === 'policy' && args[1] === 'validate') {
    const parsed = parseOptions(args.slice(2), ['file'], []);
    const policy = await loadPolicy(requiredOption(parsed, 'file'));
    if (!policy) fail('INVALID_POLICY', 'The redaction policy is invalid.');
    const result = { ok: true, command: 'policy validate', policy: outputPolicy(policy) };
    return { result, human: `Policy is valid (schema 1, body mode ${policy.bodyMode}). Fingerprint: ${redactionPolicyFingerprint(policy)}.` };
  }
  if (command === 'clean') {
    const parsed = parseOptions(args.slice(1), ['kind', 'input', 'out', 'policy'], []);
    const kind = requiredOption(parsed, 'kind');
    if (kind !== 'har' && kind !== 'log') fail('INVALID_ARGUMENT', 'The --kind value must be har or log.');
    const sourceBytes = await readRegularFile(requiredOption(parsed, 'input'), LIMITS.inputBytes, 'INVALID_INPUT', 'The input is invalid, unreadable, or exceeds its byte limit.');
    const source = decodeUtf8(sourceBytes, 'INVALID_INPUT', 'The input is not valid UTF-8.');
    const policy = await loadPolicy(optionalOption(parsed, 'policy'));
    let clean;
    try {
      clean = kind === 'har' ? sanitizeHar(source, policy) : sanitizeLog(source, policy);
    } catch {
      fail('INVALID_INPUT', `The ${kind.toUpperCase()} input could not be safely cleaned.`);
    }
    const output = new TextEncoder().encode(clean.text);
    if (output.byteLength > LIMITS.outputBytes) fail('INVALID_INPUT', 'The cleaned output exceeds its byte limit.');
    await createOutputExclusive(requiredOption(parsed, 'out'), output);
    const result = { ok: true, command: 'clean', kind, outputBytes: output.byteLength, changes: clean.changes, omissions: clean.omissions, policy: outputPolicy(policy) };
    return { result, human: `Cleaned ${kind.toUpperCase()} written to a new file (${output.byteLength} bytes; ${clean.changes} changes). Review the output before sharing.` };
  }
  if (command === 'bundle') {
    const parsed = parseOptions(args.slice(1), ['har', 'log', 'report', 'out', 'policy'], ['reviewed'], ['har', 'log']);
    const harInputs = parsed.values.get('har') ?? [];
    const logInputs = parsed.values.get('log') ?? [];
    if (parsed.values.has('image')) fail('INVALID_ARGUMENT', 'Image processing is supported in the BugPack browser app, not this text-only CLI.');
    if (!harInputs.length && !logInputs.length) fail('INVALID_ARGUMENT', 'Provide at least one --har or --log input. Images are supported in the BugPack browser app.');
    if (harInputs.length + logInputs.length > LIMITS.files) fail('INVALID_ARGUMENT', 'The bundle has too many input files.');
    if (!parsed.flags.has('reviewed')) fail('INVALID_ARGUMENT', 'Bundle creation requires --reviewed after you have inspected the inputs.');
    let total = 0;
    const files: BundleFile[] = [];
    for (const [kind, paths] of [['har', harInputs], ['log', logInputs]] as const) {
      for (const pathValue of paths) {
        const bytes = await readRegularFile(pathValue, LIMITS.inputBytes, 'INVALID_INPUT', 'An evidence input is invalid, unreadable, or exceeds its byte limit.');
        total += bytes.byteLength;
        if (total > LIMITS.totalInputBytes) fail('INVALID_INPUT', 'The evidence inputs exceed the aggregate byte limit.');
        files.push({ id: `${kind}-${files.length + 1}`, kind, text: decodeUtf8(bytes, 'INVALID_INPUT', 'An evidence input is not valid UTF-8.') });
      }
    }
    const accountAdditionalInput = (bytes: number): void => {
      total += bytes;
      if (total > LIMITS.totalInputBytes) fail('INVALID_INPUT', 'The evidence, report, and policy inputs exceed the aggregate byte limit.');
    };
    const report = await loadReport(optionalOption(parsed, 'report'), accountAdditionalInput);
    const policy = await loadPolicy(optionalOption(parsed, 'policy'), accountAdditionalInput);
    let bundled;
    try {
      bundled = buildBundle(files, report, policy);
    } catch {
      fail('INVALID_INPUT', 'The evidence or report could not be safely bundled.');
    }
    await createOutputExclusive(requiredOption(parsed, 'out'), bundled.bytes);
    const summary = bundled.summary;
    const result = {
      ok: true,
      command: 'bundle',
      outputBytes: bundled.bytes.byteLength,
      includedFiles: files.length,
      summarySchemaVersion: summary.schemaVersion,
      policy: outputPolicy(policy),
      reviewRequired: true,
      limitations: summary.limitations,
      reportDetailsProvided: optionalOption(parsed, 'report') !== undefined,
    };
    return { result, human: `Created a reviewed ${files.length}-file bundle (${bundled.bytes.byteLength} bytes). Inspect every included item and verify the automatic redaction before sharing.` };
  }
  fail('INVALID_ARGUMENT', 'Unknown command. Use --help to see available commands.');
}

function printError(error: unknown, json: boolean): number {
  const cliError = error instanceof CliError ? error : new CliError('INVALID_INPUT', 'The command could not be completed safely.');
  if (json) process.stdout.write(resultJson({ ok: false, error: { code: cliError.code, message: cliError.message } }));
  else process.stderr.write(`bugpack: ${cliError.message}\n`);
  return cliError.code === 'NODE_VERSION_UNSUPPORTED' ? 3 : 2;
}

async function main(): Promise<void> {
  const raw = process.argv.slice(2);
  if (raw.includes('--help') || raw.includes('-h')) {
    process.stdout.write(HELP);
    return;
  }
  const json = raw.includes('--json');
  const args = raw.filter((token) => token !== '--json');
  try {
    if (raw.includes('--version')) {
      const jsonOptions = raw.filter((token) => token === '--json');
      if (args.length !== 1 || args[0] !== '--version' || jsonOptions.length > 1) {
        fail('INVALID_ARGUMENT', 'The --version option cannot be combined with other arguments.');
      }
      const result = { ok: true, command: 'version', version: __BUGPACK_VERSION__ };
      process.stdout.write(json ? resultJson(result) : `BugPack CLI ${__BUGPACK_VERSION__}\n`);
      return;
    }
    const { result, human } = await run(args);
    process.stdout.write(json ? resultJson(result) : `${human}\n`);
  } catch (error) {
    process.exitCode = printError(error, json);
  }
}

void main();
