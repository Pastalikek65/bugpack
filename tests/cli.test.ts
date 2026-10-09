import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unzipSync } from 'fflate';
import { beforeAll, afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_REDACTION_POLICY } from '../src/core/policy';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const entry = resolve(root, 'dist/cli/bugpack.mjs');
const buildScript = resolve(root, 'scripts/build-cli.mjs');
const temporaryDirectories: string[] = [];
const decoder = new TextDecoder();

const secret = 'cli-custom-secret-6f592e0c';
const policy = {
  ...DEFAULT_REDACTION_POLICY,
  name: 'CLI test policy',
  literalRules: [{ value: secret, replacement: '[CUSTOM MASKED]' }],
};
const har = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{
  request: { method: 'GET', url: 'https://example.test/?token=cli-har-secret', headers: [{ name: 'Authorization', value: 'cli-header-secret' }] },
  response: { status: 200, content: { text: 'cli-response-secret' } },
}] } });
const report = {
  title: 'CLI bundle test',
  steps: 'Open the local test page.',
  expected: 'The page opens.',
  actual: `The diagnostic emitted ${secret}`,
  environment: 'Node.js 24 test process',
};

function hash(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function invoke(cwd: string, ...args: string[]) {
  expect(cwd.startsWith(root)).toBe(false);
  return spawnSync(process.execPath, [entry, ...args], { cwd, encoding: 'utf8', timeout: 30_000, windowsHide: true });
}

async function makeWorkspace(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'bugpack-cli-test-'));
  temporaryDirectories.push(directory);
  return directory;
}

async function writePolicy(directory: string, value: unknown = policy): Promise<string> {
  const path = join(directory, 'policy.json');
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
  return path;
}

function zipText(bytes: Uint8Array): { [name: string]: string } {
  const entries = unzipSync(bytes);
  return Object.fromEntries(Object.entries(entries).map(([name, data]) => [name, decoder.decode(data)]));
}

beforeAll(() => {
  const build = spawnSync(process.execPath, [buildScript], { cwd: root, encoding: 'utf8', timeout: 120_000, windowsHide: true });
  if (build.error || build.status !== 0) throw new Error(`CLI build failed: ${build.stderr || build.error?.message || build.status}`);
});

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('built CLI from an unrelated working directory', () => {
  it('provides help and a stable offline doctor result', async () => {
    const directory = await makeWorkspace();
    const help = invoke(directory, '--help');
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('policy validate');
    expect(help.stdout).toContain('Images are not supported by this CLI');

    const doctor = invoke(directory, 'doctor', '--json');
    expect(doctor.status).toBe(0);
    expect(doctor.stderr).toBe('');
    expect(JSON.parse(doctor.stdout)).toMatchObject({ ok: true, command: 'doctor', supported: true, network: 'not used', mode: 'offline' });
  });

  it('validates policies without echoing configured literal values and rejects unknown versions', async () => {
    const directory = await makeWorkspace();
    const policyPath = await writePolicy(directory);
    const valid = invoke(directory, 'policy', 'validate', '--file', policyPath, '--json');
    expect(valid.status).toBe(0);
    expect(valid.stdout).not.toContain(secret);
    expect(JSON.parse(valid.stdout)).toMatchObject({ ok: true, command: 'policy validate', policy: { schemaVersion: 1, bodyMode: 'omit' } });

    const invalidPolicy = await writePolicy(directory, { ...policy, schemaVersion: 2 });
    const invalid = invoke(directory, 'policy', 'validate', '--file', invalidPolicy, '--json');
    expect(invalid.status).not.toBe(0);
    expect(invalid.stderr).toBe('');
    expect(JSON.parse(invalid.stdout)).toMatchObject({ ok: false, error: { code: 'INVALID_POLICY' } });
    expect(invalid.stdout).not.toContain(secret);
  });

  it('cleans logs to a new file, preserves the source, and refuses overwrite', async () => {
    const directory = await makeWorkspace();
    const input = join(directory, 'source.log');
    const output = join(directory, 'cleaned.log');
    const policyPath = await writePolicy(directory);
    const source = `diagnostic ${secret}\nAuthorization: Bearer another-cli-secret\nordinary diagnostic line\n`;
    await writeFile(input, source);
    const before = hash(await readFile(input));

    const clean = invoke(directory, 'clean', '--kind', 'log', '--input', input, '--out', output, '--policy', policyPath, '--json');
    expect(clean.status).toBe(0);
    expect(clean.stdout).not.toContain(secret);
    expect(JSON.parse(clean.stdout)).toMatchObject({ ok: true, command: 'clean', kind: 'log', policy: { schemaVersion: 1 } });
    const cleaned = await readFile(output, 'utf8');
    expect(cleaned).toContain('[CUSTOM MASKED]');
    expect(cleaned).not.toContain(secret);
    expect(hash(await readFile(input))).toBe(before);

    const protectedPath = join(directory, 'protected.log');
    await writeFile(protectedPath, 'keep this original');
    const overwrite = invoke(directory, 'clean', '--kind', 'log', '--input', input, '--out', protectedPath, '--json');
    expect(overwrite.status).not.toBe(0);
    expect(JSON.parse(overwrite.stdout)).toMatchObject({ ok: false, error: { code: 'OUTPUT_EXISTS' } });
    expect(await readFile(protectedPath, 'utf8')).toBe('keep this original');
  });

  it('builds a reviewed policy-bound ZIP without leaking secrets or changing originals', async () => {
    const directory = await makeWorkspace();
    const harPath = join(directory, 'capture.har');
    const logPath = join(directory, 'capture.log');
    const reportPath = join(directory, 'report.json');
    const policyPath = await writePolicy(directory);
    const output = join(directory, 'reviewed.zip');
    const log = `request started\nThe diagnostic emitted ${secret}\nAuthorization: Bearer another-cli-secret\n`;
    await writeFile(harPath, har);
    await writeFile(logPath, log);
    await writeFile(reportPath, JSON.stringify(report));
    const sourceHashes = await Promise.all([harPath, logPath, reportPath, policyPath].map(async (path) => hash(await readFile(path))));

    const result = invoke(directory, 'bundle', '--har', harPath, '--log', logPath, '--report', reportPath, '--policy', policyPath, '--out', output, '--reviewed', '--json');
    expect(result.status).toBe(0);
    expect(result.stdout).not.toContain(secret);
    const resultJson = JSON.parse(result.stdout);
    expect(resultJson).toMatchObject({ ok: true, command: 'bundle', includedFiles: 2, summarySchemaVersion: 2, reviewRequired: true, reportDetailsProvided: true, policy: { schemaVersion: 1 } });
    const entries = zipText(await readFile(output));
    expect(Object.keys(entries).sort()).toEqual(['bug-report.md', 'evidence-001.har', 'evidence-002.log', 'processing-summary.json']);
    const allText = Object.values(entries).join('\n');
    for (const sensitive of [secret, 'cli-har-secret', 'cli-header-secret', 'cli-response-secret']) expect(allText).not.toContain(sensitive);
    const summary = JSON.parse(entries['processing-summary.json']);
    expect(summary).toMatchObject({ schemaVersion: 2, policy: { schemaVersion: 1, bodyMode: 'omit' } });
    expect(summary.policy.id).toMatch(/^[a-f0-9]{64}$/);
    expect(entries['evidence-002.log']).toContain('[CUSTOM MASKED]');
    expect(entries['bug-report.md']).toContain('CUSTOM MASKED');
    expect(summary.limitations.join(' ')).toContain('no automatic personal-information guarantee');
    expect(await Promise.all([harPath, logPath, reportPath, policyPath].map(async (path) => hash(await readFile(path))))).toEqual(sourceHashes);
  });

  it('rejects unsafe or unsupported input without creating an output or echoing source data', async () => {
    const directory = await makeWorkspace();
    const output = join(directory, 'invalid.zip');
    const malformed = join(directory, 'bad.har');
    const marker = 'should-not-appear-in-errors-1c12';
    await writeFile(malformed, `not a HAR ${marker}`);
    const bad = invoke(directory, 'bundle', '--har', malformed, '--out', output, '--reviewed', '--json');
    expect(bad.status).not.toBe(0);
    expect(JSON.parse(bad.stdout)).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });
    expect(bad.stdout).not.toContain(marker);
    await expect(readFile(output)).rejects.toMatchObject({ code: 'ENOENT' });

    const image = invoke(directory, 'bundle', '--image', join(directory, 'screenshot.png'), '--out', output, '--reviewed', '--json');
    expect(image.status).not.toBe(0);
    expect(JSON.parse(image.stdout).error.message).toContain('browser app');

    const missingReview = invoke(directory, 'bundle', '--har', malformed, '--out', output, '--json');
    expect(missingReview.status).not.toBe(0);
    expect(JSON.parse(missingReview.stdout).error.message).toContain('--reviewed');

    const validLog = join(directory, 'valid.log');
    const defaultOutput = join(directory, 'default-report.zip');
    await writeFile(validLog, 'one local diagnostic line\n');
    const defaultReport = invoke(directory, 'bundle', '--log', validLog, '--out', defaultOutput, '--reviewed', '--json');
    expect(defaultReport.status).toBe(0);
    expect(JSON.parse(defaultReport.stdout)).toMatchObject({ reportDetailsProvided: false, summarySchemaVersion: 1 });
    const defaultEntries = zipText(await readFile(defaultOutput));
    expect(defaultEntries['bug-report.md']).toContain('No reproduction steps were supplied');
    expect(defaultEntries['bug-report.md']).toContain('No expected result was supplied');
  });

  it('refuses output paths that traverse a symbolic-link directory', async () => {
    const directory = await makeWorkspace();
    const realDirectory = join(directory, 'real-output');
    const aliasDirectory = join(directory, 'output-alias');
    const input = join(directory, 'source.log');
    await mkdir(realDirectory);
    await symlink(realDirectory, aliasDirectory, process.platform === 'win32' ? 'junction' : 'dir');
    await writeFile(input, 'safe local diagnostic line\n');

    const result = invoke(directory, 'clean', '--kind', 'log', '--input', input, '--out', join(aliasDirectory, 'cleaned.log'), '--json');
    expect(result.status).not.toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ ok: false, error: { code: 'OUTPUT_UNSAFE' } });
    await expect(readFile(join(realDirectory, 'cleaned.log'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('enforces the aggregate evidence input limit before creating the ZIP', async () => {
    const directory = await makeWorkspace();
    const paths: string[] = [];
    const chunk = Buffer.alloc(13 * 1024 * 1024, 0x61);
    for (let index = 0; index < 5; index++) {
      const path = join(directory, `input-${index}.log`);
      await writeFile(path, chunk);
      paths.push(path);
    }
    const output = join(directory, 'too-large.zip');
    const args = ['bundle'];
    for (const path of paths) args.push('--log', path);
    args.push('--out', output, '--reviewed', '--json');
    const oversized = invoke(directory, ...args);
    expect(oversized.status).not.toBe(0);
    expect(JSON.parse(oversized.stdout)).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });
    expect(oversized.stdout).not.toContain('a'.repeat(100));
    await expect(readFile(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
