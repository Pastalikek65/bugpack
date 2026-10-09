import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os, { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { unzipSync } from 'fflate';
import { inspectStaticPackage } from './inspect-static-package.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
let appRoot = repositoryRoot;
let packageArchive;
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--app-root' && args[index + 1]) appRoot = path.resolve(args[++index]);
  else if (args[index] === '--package' && args[index + 1]) packageArchive = path.resolve(args[++index]);
  else throw new Error('Usage: node scripts/acceptance-cli.mjs [--app-root extracted-package --package archive]');
}
const packaged = path.resolve(appRoot) !== repositoryRoot;
if (packaged !== Boolean(packageArchive)) throw new Error('A packaged run requires both --app-root and the exact --package archive.');
const entry = path.join(appRoot, packaged ? 'cli' : path.join('dist', 'cli'), 'bugpack.mjs');
const artifactRoot = path.join(repositoryRoot, 'artifacts', `cli-${randomUUID()}`);
const decoder = new TextDecoder();
const SECRET = 'acceptance-cli-literal-8cba67';
const BASELINE_KEYS = [
  'access-token', 'access_token', 'api-key', 'api_key', 'apikey', 'authorization', 'aws-access-key-id',
  'aws_access_key_id', 'client-secret', 'client_secret', 'code', 'cookie', 'google-access-id',
  'google_access_id', 'jwt', 'key-pair-id', 'key_pair_id', 'oauth-code', 'oauth-token', 'oauth-verifier',
  'oauth_code', 'oauth_token', 'oauth_verifier', 'passwd', 'password', 'pwd', 'refresh-token',
  'refresh_token', 'secret', 'session', 'session-id', 'sessionid', 'set-cookie', 'sig', 'signature',
  'state', 'token', 'x-amz-credential', 'x-amz-security-token', 'x-amz-signature', 'x-goog-credential',
  'x-goog-security-token', 'x-goog-signature',
];
const policy = {
  schemaVersion: 1,
  name: 'CLI acceptance policy',
  bodyMode: 'omit',
  sensitiveKeys: BASELINE_KEYS,
  literalRules: [{ value: SECRET, replacement: '[CLI MASKED]' }],
};
const report = {
  title: 'CLI acceptance report',
  steps: 'Open the local synthetic request.',
  expected: 'The local request is reviewed.',
  actual: `The diagnostic emitted ${SECRET}`,
  environment: 'Node.js 24 local acceptance process',
};
const har = JSON.stringify({ log: { version: '1.2', creator: { name: 'acceptance', version: '1' }, entries: [{
  request: { method: 'GET', url: 'https://example.test/?token=acceptance-har-secret', headers: [{ name: 'Authorization', value: 'acceptance-header-secret' }] },
  response: { status: 500, content: { text: 'acceptance-response-secret' } },
}] } });

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const steps = [];
let workspace;
let initialIdentity;
let finalIdentity;
let initialSourceIdentities = [];
let finalSourceIdentities = [];
let sourceCommit = null;
let sourceState = null;
let sourceVersion = null;
const startedAt = new Date().toISOString();

function outside(candidate, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`);
}

function gitIdentity() {
  const options = { cwd: repositoryRoot, encoding: 'utf8', timeout: 10_000, windowsHide: true, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] };
  try {
    sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], options).trim();
    const changed = (argv) => execFileSync('git', argv, options).trim().split(/\r?\n/).filter(Boolean).sort();
    sourceState = {
      trackedChangedPaths: changed(['diff', '--name-only', 'HEAD']),
      untrackedPaths: changed(['ls-files', '--others', '--exclude-standard']),
    };
  } catch {
    sourceCommit = null;
    sourceState = null;
  }
}

async function inspectIdentity() {
  if (packaged) return await inspectStaticPackage(packageArchive, appRoot);
  const info = await lstat(entry);
  assert.equal(info.isSymbolicLink(), false, 'CLI entry must be a regular package file');
  assert.equal(info.isFile(), true, 'CLI entry must be a regular package file');
  const bytes = await readFile(entry);
  assert.equal(bytes.byteLength, info.size, 'CLI entry must remain stable during inspection');
  return { entryBytes: bytes.byteLength, entrySha256: sha256(bytes) };
}

function recordProcess(name, commandArgs) {
  const displayArgs = commandArgs.map((arg) => typeof arg === 'string' && workspace && arg.startsWith(workspace)
    ? `<workspace>${arg.slice(workspace.length)}`
    : arg);
  const started = performance.now();
  const child = spawnSync(process.execPath, [entry, ...commandArgs], {
    cwd: workspace,
    encoding: 'utf8',
    timeout: 30_000,
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
  });
  const record = {
    name,
    argv: ['<node>', packaged ? 'cli/bugpack.mjs' : 'dist/cli/bugpack.mjs', ...displayArgs],
    cwd: '<temporary directory outside the application root>',
    exitCode: child.status,
    signal: child.signal,
    spawnError: child.error ? (child.error.code ?? 'spawn-failed') : null,
    durationMs: Math.round(performance.now() - started),
    stdout: child.stdout ?? '',
    stderr: child.stderr ?? '',
  };
  steps.push(record);
  if (child.error) throw new Error(`Subprocess failed during ${name}.`);
  return record;
}

function expectJsonSuccess(record) {
  assert.equal(record.exitCode, 0, `${record.name} must exit successfully`);
  assert.equal(record.stderr, '', `${record.name} must not write diagnostics to stderr in JSON mode`);
  const result = JSON.parse(record.stdout);
  assert.equal(result.ok, true, `${record.name} must return ok:true`);
  return result;
}

function expectJsonError(record, code) {
  assert.notEqual(record.exitCode, 0, `${record.name} must fail`);
  assert.equal(record.stderr, '', `${record.name} must keep JSON errors on stdout`);
  const result = JSON.parse(record.stdout);
  assert.equal(result.ok, false, `${record.name} must return ok:false`);
  assert.equal(result.error.code, code, `${record.name} must use its stable error code`);
  return result;
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
}

async function writeRecord(status, errorMessage = null) {
  const record = {
    schemaVersion: 1,
    suite: 'actual-cli-beta',
    status,
    ...(errorMessage ? { error: errorMessage } : {}),
    version: sourceVersion,
    packaged,
    platform: `${process.platform}/${process.arch}`,
    host: { node: process.version, osRelease: os.release() },
    sourceCommit,
    sourceState,
    startedAt,
    finishedAt: new Date().toISOString(),
    packageIdentityBefore: initialIdentity,
    packageIdentityAfter: finalIdentity,
    syntheticSourcesBefore: initialSourceIdentities,
    syntheticSourcesAfter: finalSourceIdentities,
    outputs: workspace ? await outputIdentities() : [],
    steps,
  };
  await writeJson(path.join(artifactRoot, 'acceptance.json'), record);
  await writeJson(path.join(artifactRoot, 'steps.json'), steps);
}

async function sourceIdentities() {
  const names = ['capture.har', 'capture.log', 'report.json', 'policy.json', 'unknown-policy.json', 'invalid.har'];
  const identities = [];
  for (const name of names) {
    const absolute = path.join(workspace, name);
    try {
      const bytes = await readFile(absolute);
      identities.push({ name, bytes: bytes.byteLength, sha256: sha256(bytes) });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return identities;
}

async function outputIdentities() {
  const names = ['cleaned.log', 'custom-policy.zip', 'default-policy.zip'];
  const identities = [];
  for (const name of names) {
    const absolute = path.join(workspace, name);
    try {
      const bytes = await readFile(absolute);
      identities.push({ name, bytes: bytes.byteLength, sha256: sha256(bytes) });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return identities;
}

async function verifyZip(zipPath, expectedNames, forbiddenValues) {
  const bytes = await readFile(zipPath);
  const entries = unzipSync(bytes);
  assert.deepEqual(Object.keys(entries).sort(), [...expectedNames].sort());
  const textEntries = Object.fromEntries(Object.entries(entries).map(([name, content]) => [name, decoder.decode(content)]));
  const allText = Object.values(textEntries).join('\n');
  for (const value of forbiddenValues) assert.equal(allText.includes(value), false, `ZIP must not contain sensitive marker ${value}`);
  return { bytes: bytes.byteLength, sha256: sha256(bytes), entries: textEntries };
}

async function retainBundleEvidence(zipPath, name, entries) {
  const archiveBytes = await readFile(zipPath);
  await writeFile(path.join(artifactRoot, `${name}.zip`), archiveBytes, { flag: 'wx' });
  const summary = entries['processing-summary.json'];
  assert.equal(typeof summary, 'string', 'bundle evidence must contain its processing summary');
  await writeFile(path.join(artifactRoot, `${name}-processing-summary.json`), summary, { flag: 'wx' });
}

async function main() {
  await mkdir(path.join(repositoryRoot, 'artifacts'), { recursive: true });
  await mkdir(artifactRoot, { recursive: false });
  gitIdentity();
  assert.ok(sourceCommit, 'source commit must be recorded');
  assert.ok(sourceState, 'source state must be recorded');
  const rootPackage = JSON.parse(await readFile(path.join(repositoryRoot, 'package.json'), 'utf8'));
  const appPackage = JSON.parse(await readFile(path.join(appRoot, 'package.json'), 'utf8'));
  sourceVersion = appPackage.version;
  assert.equal(typeof sourceVersion, 'string');
  assert.match(sourceVersion, /^\d+\.\d+\.\d+$/);
  assert.ok(Number(process.versions.node.split('.')[0]) === 24, 'CLI acceptance requires Node.js 24');
  assert.equal(rootPackage.version, sourceVersion, 'package and source versions must match');
  const entryInfo = await lstat(entry);
  assert.equal(entryInfo.isFile(), true, 'built CLI entry is required');
  initialIdentity = await inspectIdentity();

  workspace = await mkdtemp(path.join(tmpdir(), 'bugpack-cli-acceptance-'));
  assert.equal(outside(workspace, repositoryRoot), true, 'CLI CWD must be outside the source repository');
  assert.equal(outside(workspace, appRoot), true, 'CLI CWD must be outside the packaged application');

  try {
    const sourcePaths = {
      har: path.join(workspace, 'capture.har'),
      log: path.join(workspace, 'capture.log'),
      report: path.join(workspace, 'report.json'),
      policy: path.join(workspace, 'policy.json'),
      unknownPolicy: path.join(workspace, 'unknown-policy.json'),
      invalidHar: path.join(workspace, 'invalid.har'),
    };
    const logText = `Contact ${SECRET}\nAuthorization: Bearer acceptance-bearer-secret\nordinary line\n`;
    await writeFile(sourcePaths.har, har, { flag: 'wx' });
    await writeFile(sourcePaths.log, logText, { flag: 'wx' });
    await writeJson(sourcePaths.report, report);
    await writeJson(sourcePaths.policy, policy);
    await writeJson(sourcePaths.unknownPolicy, { ...policy, schemaVersion: 9 });
    await writeFile(sourcePaths.invalidHar, 'malformed HAR marker acceptance-invalid-secret', { flag: 'wx' });
    initialSourceIdentities = await sourceIdentities();

    const help = recordProcess('help', ['--help']);
    assert.equal(help.exitCode, 0);
    assert.match(help.stdout, /policy validate/);
    assert.match(help.stdout, /Images are not supported by this CLI/);

    const doctor = expectJsonSuccess(recordProcess('doctor', ['doctor', '--json']));
    assert.deepEqual({ supported: doctor.supported, network: doctor.network, mode: doctor.mode }, { supported: true, network: 'not used', mode: 'offline' });

    const validPolicyStep = recordProcess('policy-valid', ['policy', 'validate', '--file', sourcePaths.policy, '--json']);
    const validPolicy = expectJsonSuccess(validPolicyStep);
    assert.equal(validPolicy.policy.schemaVersion, 1);
    assert.equal(validPolicy.policy.bodyMode, 'omit');
    assert.equal(validPolicyStep.stdout.includes(SECRET), false);

    const invalidPolicy = expectJsonError(recordProcess('policy-unknown-version', ['policy', 'validate', '--file', sourcePaths.unknownPolicy, '--json']), 'INVALID_POLICY');
    assert.equal(JSON.stringify(invalidPolicy).includes(SECRET), false);

    const cleanPath = path.join(workspace, 'cleaned.log');
    const cleaned = expectJsonSuccess(recordProcess('clean', ['clean', '--kind', 'log', '--input', sourcePaths.log, '--out', cleanPath, '--policy', sourcePaths.policy, '--json']));
    assert.equal(cleaned.kind, 'log');
    const cleanedText = await readFile(cleanPath, 'utf8');
    assert.match(cleanedText, /\[CLI MASKED\]/);
    assert.equal(cleanedText.includes(SECRET), false);
    const cleanHash = sha256(await readFile(cleanPath));
    const overwrite = expectJsonError(recordProcess('clean-overwrite', ['clean', '--kind', 'log', '--input', sourcePaths.log, '--out', cleanPath, '--json']), 'OUTPUT_EXISTS');
    assert.equal(JSON.stringify(overwrite).includes(SECRET), false);
    assert.equal(sha256(await readFile(cleanPath)), cleanHash, 'existing output must remain byte-identical');

    const customZipPath = path.join(workspace, 'custom-policy.zip');
    const customBundle = expectJsonSuccess(recordProcess('bundle-policy-v2', [
      'bundle', '--har', sourcePaths.har, '--log', sourcePaths.log, '--report', sourcePaths.report,
      '--policy', sourcePaths.policy, '--out', customZipPath, '--reviewed', '--json',
    ]));
    assert.equal(customBundle.summarySchemaVersion, 2);
    assert.equal(customBundle.includedFiles, 2);
    assert.equal(JSON.stringify(customBundle).includes(SECRET), false);
    const customZip = await verifyZip(customZipPath,
      ['bug-report.md', 'evidence-001.har', 'evidence-002.log', 'processing-summary.json'],
      [SECRET, 'acceptance-bearer-secret', 'acceptance-har-secret', 'acceptance-header-secret', 'acceptance-response-secret']);
    const customSummary = JSON.parse(customZip.entries['processing-summary.json']);
    assert.equal(customSummary.schemaVersion, 2);
    assert.deepEqual(Object.keys(customSummary.policy).sort(), ['bodyMode', 'id', 'schemaVersion']);
    assert.match(customSummary.policy.id, /^[a-f0-9]{64}$/);
    assert.match(customZip.entries['evidence-002.log'], /\[CLI MASKED\]/);
    assert.match(customZip.entries['bug-report.md'], /CLI MASKED/);
    await retainBundleEvidence(customZipPath, 'custom-policy', customZip.entries);

    const defaultZipPath = path.join(workspace, 'default-policy.zip');
    const defaultBundle = expectJsonSuccess(recordProcess('bundle-default-v1', ['bundle', '--log', cleanPath, '--out', defaultZipPath, '--reviewed', '--json']));
    assert.equal(defaultBundle.summarySchemaVersion, 1);
    assert.equal(defaultBundle.reportDetailsProvided, false);
    const defaultZip = await verifyZip(defaultZipPath,
      ['bug-report.md', 'evidence-001.log', 'processing-summary.json'],
      [SECRET, 'acceptance-bearer-secret']);
    const defaultSummary = JSON.parse(defaultZip.entries['processing-summary.json']);
    assert.equal(defaultSummary.schemaVersion, 1);
    assert.equal(Object.hasOwn(defaultSummary, 'policy'), false);
    assert.match(defaultZip.entries['bug-report.md'], /No reproduction steps were supplied/);
    assert.match(defaultZip.entries['bug-report.md'], /No expected result was supplied/);
    await retainBundleEvidence(defaultZipPath, 'default-policy', defaultZip.entries);

    const invalidZipPath = path.join(workspace, 'invalid-input.zip');
    const invalidBundle = expectJsonError(recordProcess('bundle-invalid-har', ['bundle', '--har', sourcePaths.invalidHar, '--out', invalidZipPath, '--reviewed', '--json']), 'INVALID_INPUT');
    assert.equal(JSON.stringify(invalidBundle).includes('acceptance-invalid-secret'), false);
    await assert.rejects(readFile(invalidZipPath), { code: 'ENOENT' });

    const imagePath = path.join(workspace, 'unsupported-image.zip');
    const imageError = expectJsonError(recordProcess('bundle-image-rejected', ['bundle', '--image', path.join(workspace, 'screen.png'), '--out', imagePath, '--reviewed', '--json']), 'INVALID_ARGUMENT');
    assert.match(imageError.error.message, /browser app/);
    const reviewError = expectJsonError(recordProcess('bundle-review-required', ['bundle', '--log', sourcePaths.log, '--out', imagePath, '--json']), 'INVALID_ARGUMENT');
    assert.match(reviewError.error.message, /--reviewed/);
    await assert.rejects(readFile(imagePath), { code: 'ENOENT' });

    finalSourceIdentities = await sourceIdentities();
    assert.deepEqual(finalSourceIdentities, initialSourceIdentities, 'the original HAR, log, report, and policies must remain byte-identical');
    finalIdentity = await inspectIdentity();
    assert.deepEqual(finalIdentity, initialIdentity, 'the package archive and extracted tree must remain byte-identical');
    await writeRecord('passed');
    process.stdout.write(`${JSON.stringify({ status: 'passed', suite: 'actual-cli-beta', steps: steps.length, packaged, packageIdentity: packaged ? initialIdentity : undefined, artifact: artifactRoot })}\n`);
  } catch (error) {
    finalIdentity = await inspectIdentity().catch(() => null);
    await writeRecord('failed', 'CLI acceptance did not complete.').catch(() => {});
    throw error;
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

await main();
