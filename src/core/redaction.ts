import { LIMITS, type Omission, type SanitizedText } from './contracts';

const encoder = new TextEncoder();
const FORBIDDEN_CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const HEADER_ALLOWLIST = new Set([
  'accept',
  'cache-control',
  'content-length',
  'content-type',
  'date',
  'expires',
  'pragma',
]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
const TIMING_FIELDS = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl'] as const;
const QUERY_SECRET_KEY = /(?:pass(?:word|wd)?|pwd|token|auth(?:orization)?|api[_-]?key|client[_-]?secret|secret|session(?:id)?|cookie|jwt|x-amz-(?:signature|credential|security-token)|x-goog-(?:signature|credential|security-token)|google[_-]?access[_-]?id|oauth[_-]?(?:token|code|verifier)|aws[_-]?access[_-]?key[_-]?id|key[_-]?pair[_-]?id|(?:^|[^a-z0-9])(?:code|state|sig|signature)(?:$|[^a-z0-9]))/i;

function isRedactedMarker(value: string): boolean {
  return /^\[REDACTED\]$/i.test(value.trim()) || /^%5BREDACTED%5D$/i.test(value.trim());
}

interface BuildContext {
  changes: number;
  omissions: Map<string, { count: number; description: string }>;
}

function omit(context: BuildContext, code: string, description: string, count = 1): void {
  if (!count) return;
  const current = context.omissions.get(code);
  if (current) current.count += count;
  else context.omissions.set(code, { count, description });
  context.changes += count;
}

function addChanges(context: BuildContext, count: number): void {
  context.changes += count;
}

function assertNoUnsafeControls(value: string, label: string): void {
  if (FORBIDDEN_CONTROLS.test(value)) throw new Error(`${label} contains unsupported control characters`);
}

function checkUtf8Limit(source: string, label: string): void {
  if (encoder.encode(source).byteLength > LIMITS.inputBytes) throw new Error(`${label} exceeds the ${LIMITS.inputBytes} byte input limit`);
}

function redactBounded(source: string): { text: string; changes: number } {
  let text = source;
  let changes = 0;

  text = text.replace(/(^|[\r\n])([ \t]*authorization[ \t]*:[ \t]*)([^\r\n]*)/gim, (match, lineStart: string, prefix: string, value: string) => {
    if (isRedactedMarker(value)) return match;
    changes++;
    return `${lineStart}${prefix}[REDACTED]`;
  });

  text = text.replace(/(^|[\r\n])([ \t]*(?:cookie|set-cookie)[ \t]*:[ \t]*)([^\r\n]*)/gim, (match, lineStart: string, prefix: string, value: string) => {
    if (isRedactedMarker(value)) return match;
    changes++;
    return `${lineStart}${prefix}[REDACTED]`;
  });

  text = text.replace(/\b(["']?)(password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|authorization|api[_-]?key|apikey|secret|client[_-]?secret|cookie|set-cookie|x-amz-(?:signature|credential|security-token)|x-goog-(?:signature|credential|security-token)|google[_-]?access[_-]?id|aws[_-]?access[_-]?key[_-]?id|key[_-]?pair[_-]?id|oauth[_-]?(?:token|code|verifier)|code|state|sig|signature)(["']?)([ \t]*[:=][ \t]*)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;&]+))/gi,
    (match, _openingKeyQuote: string, key: string, closingKeyQuote: string, separator: string, doubleQuoted: string | undefined, singleQuoted: string | undefined, bare: string | undefined) => {
      const value = doubleQuoted ?? singleQuoted ?? bare ?? '';
      if (isRedactedMarker(value)) return match;
      changes++;
      const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
      return `${key}${closingKeyQuote}${separator}${quote}[REDACTED]${quote}`;
    });

  text = text.replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]{6,}={0,2}/gi, (_match, prefix: string) => {
    changes++;
    return `${prefix}[REDACTED]`;
  });

  text = text.replace(/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g, () => {
    changes++;
    return '[REDACTED]';
  });

  return { text, changes };
}

/** Redacts the fixed set of common credential patterns used by BugPack. */
export function sanitizeLog(source: string): SanitizedText {
  if (typeof source !== 'string') throw new Error('Log input must be text');
  checkUtf8Limit(source, 'Log');
  assertNoUnsafeControls(source, 'Log');
  const redacted = redactBounded(source);
  return { text: redacted.text, changes: redacted.changes, omissions: [] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`Malformed HAR: ${label} must be an object`);
  return value;
}

function requireArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`Malformed HAR: ${label} must be an array`);
  if (value.length > LIMITS.jsonNodes) throw new Error(`HAR ${label} exceeds the JSON node limit`);
  return value;
}

function assertHarBudget(root: unknown): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const next = pending.pop()!;
    nodes++;
    if (nodes > LIMITS.jsonNodes) throw new Error(`HAR exceeds the ${LIMITS.jsonNodes} JSON node limit`);
    if (next.depth > LIMITS.jsonDepth) throw new Error(`HAR exceeds the depth ${LIMITS.jsonDepth} limit`);
    if (typeof next.value === 'string') {
      assertNoUnsafeControls(next.value, 'HAR string');
    } else if (Array.isArray(next.value)) {
      for (const item of next.value) pending.push({ value: item, depth: next.depth + 1 });
    } else if (isRecord(next.value)) {
      for (const [key, child] of Object.entries(next.value)) {
        assertNoUnsafeControls(key, 'HAR field name');
        pending.push({ value: child, depth: next.depth + 1 });
      }
    }
  }
}

function dropUnknownFields(record: Record<string, unknown>, allowed: ReadonlySet<string>, context: BuildContext): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) omit(context, 'unknown-field', 'Unknown HAR fields and extensions were omitted.');
  }
}

function requiredString(value: unknown, label: string, context: BuildContext, maxLength = 8192): string {
  if (typeof value !== 'string') throw new Error(`Malformed HAR: ${label} must be text`);
  if (value.length > maxLength) throw new Error(`HAR ${label} exceeds the supported length`);
  const result = redactBounded(value);
  addChanges(context, result.changes);
  return result.text;
}

function optionalString(record: Record<string, unknown>, key: string, label: string, context: BuildContext, maxLength = 8192): string | undefined {
  if (!(key in record)) return undefined;
  return requiredString(record[key], label, context, maxLength);
}

function optionalNumber(record: Record<string, unknown>, key: string, label: string): number | undefined {
  if (!(key in record)) return undefined;
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value) || Math.abs(value) > 1_000_000_000) {
    throw new Error(`Malformed HAR: ${label} must be a finite bounded number`);
  }
  return value;
}

function projectNamedVersion(value: unknown, label: string, context: BuildContext): Record<string, string> {
  const input = requireRecord(value, label);
  dropUnknownFields(input, new Set(['name', 'version']), context);
  const result: Record<string, string> = {};
  if ('name' in input) result.name = requiredString(input.name, `${label}.name`, context, 512);
  if ('version' in input) result.version = requiredString(input.version, `${label}.version`, context, 128);
  if (!result.name || !result.version) throw new Error(`Malformed HAR: ${label} requires name and version`);
  return result;
}

function sanitizeUrl(value: unknown, label: string, context: BuildContext): string {
  const input = requiredString(value, label, context, 16_384);
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`Malformed HAR: ${label} must be an absolute HTTP(S) URL`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error(`Malformed HAR: ${label} uses an unsupported URL scheme`);
  if (url.username || url.password) {
    url.username = '';
    url.password = '';
    omit(context, 'url-credentials', 'URL user information was removed.');
  }
  if (url.hash) {
    url.hash = '';
    omit(context, 'url-fragment', 'URL fragments were removed.');
  }
  for (const [key, valueInQuery] of [...url.searchParams.entries()]) {
    if (QUERY_SECRET_KEY.test(key)) {
      url.searchParams.set(key, '[REDACTED]');
      if (!isRedactedMarker(valueInQuery)) addChanges(context, 1);
      continue;
    }
    const sanitized = redactBounded(valueInQuery);
    if (sanitized.changes) {
      url.searchParams.set(key, sanitized.text);
      addChanges(context, sanitized.changes);
    }
  }
  return url.toString();
}

function projectHeaderList(value: unknown, label: string, context: BuildContext): Array<{ name: string; value: string }> {
  const headers = requireArray(value, label);
  if (headers.length > 1000) throw new Error(`HAR ${label} exceeds the header limit`);
  const output: Array<{ name: string; value: string }> = [];
  for (const [index, item] of headers.entries()) {
    const header = requireRecord(item, `${label}[${index}]`);
    dropUnknownFields(header, new Set(['name', 'value', 'comment']), context);
    if ('comment' in header) omit(context, 'comment', 'HAR comments were omitted.');
    const name = requiredString(header.name, `${label}[${index}].name`, context, 128);
    const lowerName = name.toLowerCase();
    if (!HEADER_NAME.test(name)) throw new Error(`Malformed HAR: ${label} contains an invalid header name`);
    const headerValue = requiredString(header.value, `${label}[${index}].value`, context, 8192);
    if (!HEADER_ALLOWLIST.has(lowerName)) {
      omit(context, 'header', 'Sensitive and unapproved HTTP headers were omitted.');
      continue;
    }
    let safeValue = headerValue.trim();
    if (lowerName === 'content-type') safeValue = safeValue.split(';', 1)[0].trim();
    output.push({ name: lowerName, value: safeValue });
  }
  return output;
}

function projectHeaderField(input: Record<string, unknown>, key: string, label: string, output: Record<string, unknown>, context: BuildContext): void {
  if (key in input) output[key] = projectHeaderList(input[key], `${label}.${key}`, context);
}

function omitCookieField(input: Record<string, unknown>, key: string, label: string, context: BuildContext): void {
  if (!(key in input)) return;
  const cookies = requireArray(input[key], `${label}.${key}`);
  for (const [index, value] of cookies.entries()) {
    const cookie = requireRecord(value, `${label}.${key}[${index}]`);
    dropUnknownFields(cookie, new Set(['name', 'value', 'path', 'domain', 'expires', 'httpOnly', 'secure', 'comment']), context);
    if (typeof cookie.name !== 'string' || typeof cookie.value !== 'string') throw new Error(`Malformed HAR: ${label}.${key} entries require text names and values`);
    for (const field of ['path', 'domain', 'expires'] as const) {
      if (field in cookie && typeof cookie[field] !== 'string') throw new Error(`Malformed HAR: ${label}.${key}.${field} must be text`);
    }
    for (const field of ['httpOnly', 'secure'] as const) {
      if (field in cookie && typeof cookie[field] !== 'boolean') throw new Error(`Malformed HAR: ${label}.${key}.${field} must be boolean`);
    }
    if ('comment' in cookie) omit(context, 'comment', 'HAR comments were omitted.');
  }
  omit(context, 'cookie', `${label} cookies were omitted.`, Math.max(1, cookies.length));
}

function projectRequest(value: unknown, context: BuildContext): Record<string, unknown> {
  const input = requireRecord(value, 'entry.request');
  const allowed = new Set(['method', 'url', 'httpVersion', 'headers', 'queryString', 'cookies', 'headersSize', 'bodySize', 'postData', 'comment']);
  dropUnknownFields(input, allowed, context);
  const output: Record<string, unknown> = {
    method: requiredString(input.method, 'entry.request.method', context, 64),
    url: sanitizeUrl(input.url, 'entry.request.url', context),
  };
  const httpVersion = optionalString(input, 'httpVersion', 'entry.request.httpVersion', context, 64);
  if (httpVersion !== undefined) output.httpVersion = httpVersion;
  projectHeaderField(input, 'headers', 'entry.request', output, context);
  if ('queryString' in input) {
    const query = requireArray(input.queryString, 'entry.request.queryString');
    for (const [index, item] of query.entries()) {
      const pair = requireRecord(item, `entry.request.queryString[${index}]`);
      dropUnknownFields(pair, new Set(['name', 'value', 'comment']), context);
      if (typeof pair.name !== 'string' || typeof pair.value !== 'string') throw new Error('Malformed HAR: queryString entries require text names and values');
      if ('comment' in pair) omit(context, 'comment', 'HAR comments were omitted.');
    }
    omit(context, 'query-string', 'HAR queryString copies were omitted; the sanitized request URL is retained.', Math.max(1, query.length));
  }
  omitCookieField(input, 'cookies', 'entry.request', context);
  if ('postData' in input) {
    requireRecord(input.postData, 'entry.request.postData');
    omit(context, 'body', 'Request bodies were omitted.');
  }
  for (const key of ['headersSize', 'bodySize'] as const) {
    const number = optionalNumber(input, key, `entry.request.${key}`);
    if (number !== undefined) output[key] = number;
  }
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  return output;
}

function projectContent(value: unknown, context: BuildContext): Record<string, unknown> {
  const input = requireRecord(value, 'entry.response.content');
  dropUnknownFields(input, new Set(['size', 'mimeType', 'compression', 'text', 'encoding', 'comment']), context);
  const output: Record<string, unknown> = {};
  for (const key of ['size', 'compression'] as const) {
    const number = optionalNumber(input, key, `entry.response.content.${key}`);
    if (number !== undefined) output[key] = number;
  }
  const mimeType = optionalString(input, 'mimeType', 'entry.response.content.mimeType', context, 256);
  if (mimeType !== undefined) output.mimeType = mimeType.split(';', 1)[0].trim();
  if ('text' in input || 'encoding' in input) omit(context, 'body', 'Response bodies were omitted.');
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  return output;
}

function projectResponse(value: unknown, context: BuildContext): Record<string, unknown> {
  const input = requireRecord(value, 'entry.response');
  const allowed = new Set(['status', 'statusText', 'httpVersion', 'headers', 'cookies', 'content', 'redirectURL', 'headersSize', 'bodySize', 'comment']);
  dropUnknownFields(input, allowed, context);
  const status = optionalNumber(input, 'status', 'entry.response.status');
  if (status === undefined || status < 0 || status > 999 || !Number.isInteger(status)) throw new Error('Malformed HAR: response.status must be an HTTP status number');
  const output: Record<string, unknown> = { status };
  const statusText = optionalString(input, 'statusText', 'entry.response.statusText', context, 512);
  if (statusText !== undefined) output.statusText = statusText;
  const httpVersion = optionalString(input, 'httpVersion', 'entry.response.httpVersion', context, 64);
  if (httpVersion !== undefined) output.httpVersion = httpVersion;
  projectHeaderField(input, 'headers', 'entry.response', output, context);
  omitCookieField(input, 'cookies', 'entry.response', context);
  if (!('content' in input)) throw new Error('Malformed HAR: entry.response.content is required');
  output.content = projectContent(input.content, context);
  const redirectURL = optionalString(input, 'redirectURL', 'entry.response.redirectURL', context, 16_384);
  if (redirectURL !== undefined && redirectURL !== '') output.redirectURL = sanitizeUrl(redirectURL, 'entry.response.redirectURL', context);
  for (const key of ['headersSize', 'bodySize'] as const) {
    const number = optionalNumber(input, key, `entry.response.${key}`);
    if (number !== undefined) output[key] = number;
  }
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  return output;
}

function projectTimings(value: unknown, label: string, context: BuildContext): Record<string, number> {
  const input = requireRecord(value, label);
  dropUnknownFields(input, new Set([...TIMING_FIELDS, 'comment']), context);
  const output: Record<string, number> = {};
  for (const key of TIMING_FIELDS) {
    const number = optionalNumber(input, key, `${label}.${key}`);
    if (number !== undefined) output[key] = number;
  }
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  return output;
}

function projectPageTimings(value: unknown, label: string, context: BuildContext): Record<string, number> {
  const input = requireRecord(value, label);
  dropUnknownFields(input, new Set(['onContentLoad', 'onLoad', 'comment']), context);
  const output: Record<string, number> = {};
  for (const key of ['onContentLoad', 'onLoad'] as const) {
    const number = optionalNumber(input, key, `${label}.${key}`);
    if (number !== undefined) output[key] = number;
  }
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  return output;
}

function projectEntry(value: unknown, context: BuildContext): Record<string, unknown> {
  const input = requireRecord(value, 'log.entries[]');
  const allowed = new Set(['startedDateTime', 'time', 'request', 'response', 'cache', 'timings', 'serverIPAddress', 'connection', 'pageref', 'comment']);
  dropUnknownFields(input, allowed, context);
  const output: Record<string, unknown> = {
    request: projectRequest(input.request, context),
    response: projectResponse(input.response, context),
  };
  const started = optionalString(input, 'startedDateTime', 'entry.startedDateTime', context, 128);
  if (started !== undefined) output.startedDateTime = started;
  const time = optionalNumber(input, 'time', 'entry.time');
  if (time !== undefined) output.time = time;
  if ('timings' in input) output.timings = projectTimings(input.timings, 'entry.timings', context);
  if ('cache' in input) {
    requireRecord(input.cache, 'entry.cache');
    omit(context, 'cache', 'HAR cache data was omitted.');
  }
  for (const key of ['serverIPAddress', 'connection', 'pageref', 'comment']) {
    if (key in input) omit(context, 'entry-metadata', 'HAR network and page metadata were omitted.');
  }
  return output;
}

function projectPage(value: unknown, index: number, context: BuildContext): Record<string, unknown> {
  const input = requireRecord(value, `log.pages[${index}]`);
  dropUnknownFields(input, new Set(['startedDateTime', 'id', 'title', 'pageTimings', 'comment']), context);
  const output: Record<string, unknown> = {};
  const started = optionalString(input, 'startedDateTime', `log.pages[${index}].startedDateTime`, context, 128);
  if (started !== undefined) output.startedDateTime = started;
  for (const key of ['id', 'title', 'comment']) {
    if (key in input) omit(context, 'page-metadata', 'HAR page identifiers, titles, and comments were omitted.');
  }
  if ('pageTimings' in input) output.pageTimings = projectPageTimings(input.pageTimings, `log.pages[${index}].pageTimings`, context);
  return output;
}

function toSanitizedText(text: string, context: BuildContext): SanitizedText {
  return {
    text,
    changes: context.changes,
    omissions: [...context.omissions.entries()].map(([code, value]): Omission => ({ code, count: value.count, description: value.description })),
  };
}

/** Parses HAR 1.2 and projects it onto a fresh, bounded, privacy-conscious subset. */
export function sanitizeHar(source: string): SanitizedText {
  if (typeof source !== 'string') throw new Error('HAR input must be text');
  checkUtf8Limit(source, 'HAR');
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error('Malformed HAR JSON');
  }
  assertHarBudget(parsed);
  const context: BuildContext = { changes: 0, omissions: new Map() };
  const root = requireRecord(parsed, 'root');
  dropUnknownFields(root, new Set(['log']), context);
  const log = requireRecord(root.log, 'root.log');
  if (log.version !== '1.2') throw new Error('Unsupported HAR version; only HAR 1.2 is accepted');
  dropUnknownFields(log, new Set(['version', 'creator', 'browser', 'pages', 'entries', 'comment']), context);
  if (!('creator' in log)) throw new Error('Malformed HAR: log.creator is required');
  const entries = requireArray(log.entries, 'log.entries');
  if (entries.length > LIMITS.harEntries) throw new Error(`HAR exceeds the ${LIMITS.harEntries} entry limit`);

  const outputLog: Record<string, unknown> = {
    version: '1.2',
    creator: projectNamedVersion(log.creator, 'log.creator', context),
    entries: entries.map((entry) => projectEntry(entry, context)),
  };
  if ('browser' in log) outputLog.browser = projectNamedVersion(log.browser, 'log.browser', context);
  if ('pages' in log) {
    const pages = requireArray(log.pages, 'log.pages');
    outputLog.pages = pages.map((page, index) => projectPage(page, index, context));
  }
  if ('comment' in log) omit(context, 'comment', 'HAR comments were omitted.');
  return toSanitizedText(JSON.stringify({ log: outputLog }, null, 2), context);
}
