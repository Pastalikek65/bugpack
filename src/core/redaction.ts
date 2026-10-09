import { LIMITS, type Omission, type RedactionPolicy, type SanitizedText } from './contracts.ts';
import { DEFAULT_REDACTION_POLICY, parseStrictJson, validateRedactionPolicy } from './policy.ts';

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
const MAX_EMBEDDED_URL_DEPTH = 4;
const MAX_TEXT_URLS = LIMITS.harEntries;
const MAX_URL_PARAMETERS = 50_000;

function isRedactedMarker(value: string): boolean {
  return /^\[REDACTED\]$/i.test(value.trim()) || /^%5BREDACTED%5D$/i.test(value.trim());
}

interface BuildContext {
  changes: number;
  omissions: Map<string, { count: number; description: string }>;
  policy: RedactionPolicy;
  sensitiveKeySet: ReadonlySet<string>;
  urlBudget: UrlScanBudget;
}

interface UrlScanBudget {
  urls: number;
  parameters: number;
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

const policySensitivePatterns = new WeakMap<RedactionPolicy, RegExp>();

function escapeRegularExpressionLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getSensitiveKeyPattern(policy: RedactionPolicy): RegExp {
  let pattern = policySensitivePatterns.get(policy);
  if (pattern) return pattern;
  const alternatives = [...policy.sensitiveKeys].sort((left, right) => right.length - left.length || (left < right ? -1 : left > right ? 1 : 0))
    .map(escapeRegularExpressionLiteral)
    .join('|');
  pattern = new RegExp(`(^|[^A-Za-z0-9_.-])([\\"']?)(${alternatives})([\\"']?)([ \\t]*[:=][ \\t]*)(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|([^\\s,;&]+))`, 'gi');
  policySensitivePatterns.set(policy, pattern);
  return pattern;
}

function redactPolicySensitiveKeys(source: string, policy: RedactionPolicy): { text: string; changes: number } {
  let changes = 0;
  const pattern = getSensitiveKeyPattern(policy);
  const text = source.replace(pattern, (match, before: string, openQuote: string, key: string, closeQuote: string, separator: string, doubleQuoted: string | undefined, singleQuoted: string | undefined, bare: string | undefined) => {
    const value = doubleQuoted ?? singleQuoted ?? bare ?? '';
    if (isRedactedMarker(value)) return match;
    changes++;
    const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
    return `${before}${openQuote}${key}${closeQuote}${separator}${quote}[REDACTED]${quote}`;
  });
  return { text, changes };
}

function replaceLiteralBounded(source: string, value: string, replacement: string): { text: string; count: number } {
  let count = 0;
  let searchFrom = 0;
  while (true) {
    const found = source.indexOf(value, searchFrom);
    if (found < 0) break;
    count++;
    searchFrom = found + value.length;
  }
  if (!count) return { text: source, count: 0 };
  const projectedBytes = encoder.encode(source).byteLength
    + count * (encoder.encode(replacement).byteLength - encoder.encode(value).byteLength);
  if (projectedBytes > LIMITS.inputBytes) throw new Error('Sanitized text exceeds the output byte limit');
  const chunks: string[] = [];
  let cursor = 0;
  while (true) {
    const found = source.indexOf(value, cursor);
    if (found < 0) break;
    chunks.push(source.slice(cursor, found), replacement);
    cursor = found + value.length;
  }
  chunks.push(source.slice(cursor));
  return { text: chunks.join(''), count };
}

function hasConfiguredLiteral(source: string, policy: RedactionPolicy): boolean {
  return policy.literalRules.some((rule) => source.includes(rule.value));
}

function redactUriUserInfo(source: string, budget: UrlScanBudget): { text: string; changes: number } {
  let changes = 0;
  const text = source.replace(/\b([a-z][a-z0-9+.-]{0,31}:\/\/)([^/?#\s<>"']*)/gi, (match, prefix: string, authority: string) => {
    const scheme = prefix.slice(0, -3).toLowerCase();
    if (scheme === 'mailto') return match;
    const separator = authority.lastIndexOf('@');
    if (separator < 0) return match;
    budget.urls++;
    if (budget.urls > MAX_TEXT_URLS) throw new Error('Text contains too many URLs to sanitize safely');
    let parsed: URL;
    try {
      parsed = new URL(`${prefix}${authority}`);
    } catch {
      // An invalid hierarchical authority with userinfo is unsafe to retain.
      changes++;
      return `${prefix}[REDACTED]`;
    }
    if (parsed.protocol === 'mailto:' || (!parsed.username && !parsed.password)) return match;
    changes++;
    return `${prefix}[REDACTED]@${authority.slice(separator + 1)}`;
  });
  return { text, changes };
}

function sanitizePolicyText(source: string, policy: RedactionPolicy, scanUrls = true, urlBudget: UrlScanBudget = { urls: 0, parameters: 0 }): { text: string; changes: number } {
  const baseline = redactBounded(source);
  const authorityRedacted = redactUriUserInfo(baseline.text, urlBudget);
  const keyRedacted = redactPolicySensitiveKeys(authorityRedacted.text, policy);
  let text = keyRedacted.text;
  let changes = baseline.changes + authorityRedacted.changes + keyRedacted.changes;
  const orderedRules = [...policy.literalRules].sort((left, right) => right.value.length - left.value.length || (left.value < right.value ? -1 : left.value > right.value ? 1 : 0));
  for (const rule of orderedRules) {
    const result = replaceLiteralBounded(text, rule.value, rule.replacement);
    text = result.text;
    changes += result.count;
  }
  // A replacement is user-controlled text too. Run mandatory credential masks
  // after substitutions so a benign source literal cannot expand into a secret.
  const finalBaseline = redactBounded(text);
  const finalAuthority = redactUriUserInfo(finalBaseline.text, urlBudget);
  const finalKeys = redactPolicySensitiveKeys(finalAuthority.text, policy);
  text = finalKeys.text;
  changes += finalBaseline.changes + finalAuthority.changes + finalKeys.changes;
  if (scanUrls) {
    const urls = redactEncodedUrlQueries(text, policy, urlBudget);
    text = urls.text;
    changes += urls.changes;
  }
  if (hasConfiguredLiteral(text, policy)) {
    throw new Error('Configured literal text could not be removed safely from the output');
  }
  if (encoder.encode(text).byteLength > LIMITS.inputBytes) throw new Error('Sanitized text exceeds the output byte limit');
  return { text, changes };
}

function isSensitivePolicyKey(key: string, policy: RedactionPolicy): boolean {
  let candidate = key;
  for (let layer = 0; layer <= 4; layer++) {
    if (policy.sensitiveKeys.includes(candidate.toLowerCase()) || QUERY_SECRET_KEY.test(candidate)) return true;
    try {
      const decoded = decodeURIComponent(candidate);
      if (decoded === candidate) return false;
      candidate = decoded;
    } catch {
      // Malformed encoded key names are not trusted as public identifiers.
      return candidate.includes('%');
    }
  }
  // Keys that remain encoded after the bounded scan are treated as sensitive.
  return true;
}

function sanitizeEncodedUrlComponent(value: string, policy: RedactionPolicy, budget: UrlScanBudget): { text: string; changes: number } {
  let decoded = value;
  let changed = false;
  let changes = 0;
  for (let layer = 0; layer <= 4; layer++) {
    const safe = sanitizePolicyText(decoded, policy, false, budget);
    if (safe.text !== decoded) {
      decoded = safe.text;
      changed = true;
      changes += safe.changes;
    }
    if (layer === 4) break;
    // Preserve malformed percent signs for scanning while still decoding valid
    // escapes around them. Invalid UTF-8 remains fail-closed below.
    let next: string;
    try {
      next = decodeURIComponent(decoded.replace(/%(?![0-9a-f]{2})/gi, '%25'));
    } catch {
      const marker = sanitizePolicyText('[REDACTED]', policy, false, budget);
      return { text: marker.text, changes: marker.changes + 1 };
    }
    if (next === decoded) return { text: changed ? decoded : value, changes };
    decoded = next;
  }
  // A component still changing after the scan cap may contain hidden policy
  // text, so it is omitted instead of being passed through unchanged.
  try {
    const next = decodeURIComponent(decoded.replace(/%(?![0-9a-f]{2})/gi, '%25'));
    if (next !== decoded) {
      const marker = sanitizePolicyText('[REDACTED]', policy, false, budget);
      return { text: marker.text, changes: marker.changes + 1 };
    }
  } catch {
    const marker = sanitizePolicyText('[REDACTED]', policy, false, budget);
    return { text: marker.text, changes: marker.changes + 1 };
  }
  return { text: changed ? decoded : value, changes };
}

function findEmbeddedUrl(value: string): { url: string; encodedLayers: number } | { depthExceeded: true } | undefined {
  let decoded = value;
  for (let encodedLayers = 0; encodedLayers <= 8; encodedLayers++) {
    const hasSupportedUri = [...decoded.matchAll(/\b([a-z][a-z0-9+.-]{0,31}):\/\//gi)]
      .some((match) => match[1].toLowerCase() !== 'mailto');
    if (hasSupportedUri) return { url: decoded, encodedLayers };
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) return undefined;
      decoded = next;
    } catch {
      return undefined;
    }
  }
  // Continuing to decode arbitrary attacker-controlled nesting would make the
  // scan unbounded. The caller omits a value that still changes after the cap.
  return { depthExceeded: true };
}

function redactEncodedUrlQueries(source: string, policy: RedactionPolicy, budget: UrlScanBudget, embeddedDepth = 0): { text: string; changes: number } {
  let changes = 0;
  const pattern = /\b([a-z][a-z0-9+.-]{0,31}):\/\/[^\s<>"']+/gi;
  const text = source.replace(pattern, (candidate, scheme: string) => {
    if (scheme.toLowerCase() === 'mailto') return candidate;
    budget.urls++;
    if (budget.urls > MAX_TEXT_URLS) throw new Error('Text contains too many URLs to sanitize safely');
    const queryStart = candidate.indexOf('?');
    if (queryStart >= 0) {
      const fragmentStart = candidate.indexOf('#', queryStart + 1);
      const queryEnd = fragmentStart < 0 ? candidate.length : fragmentStart;
      if (queryEnd > queryStart + 1) {
        let parameterCount = 1;
        for (let index = queryStart + 1; index < queryEnd; index++) if (candidate[index] === '&') parameterCount++;
        budget.parameters += parameterCount;
        if (budget.parameters > MAX_URL_PARAMETERS) throw new Error('Text contains too many URL parameters to sanitize safely');
      }
    }
    let url: URL;
    try {
      url = new URL(candidate);
    } catch {
      changes++;
      return `${scheme}://[REDACTED]`;
    }
    if (url.protocol === 'mailto:') return candidate;
    let changed = false;
    if (url.username || url.password) {
      url.username = '';
      url.password = '';
      changes++;
      changed = true;
    }
    if (url.hash) {
      url.hash = '';
      changes++;
      changed = true;
    }
    let decodedPath = url.pathname;
    let pathMustBeDropped = false;
    for (let layer = 0; layer < 4; layer++) {
      const safePath = sanitizePolicyText(decodedPath, policy, false, budget);
      changes += safePath.changes;
      if (safePath.text !== decodedPath) {
        pathMustBeDropped = true;
        break;
      }
      try {
        const next = decodeURIComponent(decodedPath);
        if (next === decodedPath) break;
        decodedPath = next;
        if (layer === 3) pathMustBeDropped = true;
      } catch {
        // Invalid percent escapes make the path unsafe to inspect reliably.
        if (decodedPath.includes('%')) pathMustBeDropped = true;
        break;
      }
    }
    if (pathMustBeDropped) {
      // Drop the complete path if sanitization or the decoding cap was reached;
      // rebuilding it could change routing semantics or preserve an encoded secret.
      url.pathname = '/';
      changed = true;
      changes++;
    }
    const outputParams = new URLSearchParams();
    let parametersSeen = 0;
    for (const [key, value] of url.searchParams) {
      parametersSeen++;
      if (parametersSeen > MAX_URL_PARAMETERS) throw new Error('URL contains too many query parameters to sanitize safely');
      const cleanKey = sanitizeEncodedUrlComponent(key, policy, budget);
      changes += cleanKey.changes;
      const sensitive = isSensitivePolicyKey(key, policy) || isSensitivePolicyKey(cleanKey.text, policy);
      let cleanValue: string;
      if (sensitive) {
        const marker = sanitizePolicyText('[REDACTED]', policy, false);
        changes += marker.changes;
        cleanValue = marker.text;
        if (!isRedactedMarker(value)) changes++;
      } else {
        const sanitized = sanitizeEncodedUrlComponent(value, policy, budget);
        changes += sanitized.changes;
        cleanValue = sanitized.text;
        const nestedUrl = findEmbeddedUrl(cleanValue);
        if (nestedUrl && 'depthExceeded' in nestedUrl) {
          const marker = sanitizePolicyText('[REDACTED]', policy, false);
          changes += marker.changes + 1;
          cleanValue = marker.text;
        } else if (nestedUrl) {
          if (embeddedDepth >= MAX_EMBEDDED_URL_DEPTH) {
            const marker = sanitizePolicyText('[REDACTED]', policy, false);
            changes += marker.changes + 1;
            cleanValue = marker.text;
          } else {
            const nested = redactEncodedUrlQueries(nestedUrl.url, policy, budget, embeddedDepth + 1);
            changes += nested.changes;
            let sanitizedNested = nested.text;
            for (let layer = 0; layer < nestedUrl.encodedLayers; layer++) sanitizedNested = encodeURIComponent(sanitizedNested);
            if (sanitizedNested !== cleanValue) changes++;
            cleanValue = sanitizedNested;
          }
        }
      }
      if (sensitive || cleanKey.text !== key || cleanValue !== value) changed = true;
      outputParams.append(cleanKey.text, cleanValue);
    }
    if (!changed) return candidate;
    url.search = outputParams.toString();
    const sanitizedUrl = url.toString();
    if (hasConfiguredLiteral(sanitizedUrl, policy)) {
      throw new Error('Configured literal text could not be removed safely from a URL');
    }
    return sanitizedUrl;
  });
  return { text, changes };
}

function isSensitiveKey(key: string, context: BuildContext): boolean {
  return context.sensitiveKeySet.has(key.toLowerCase()) || isSensitivePolicyKey(key, context.policy);
}

function sanitizeContextText(source: string, context: BuildContext, scanUrls = true): { text: string; changes: number } {
  return sanitizePolicyText(source, context.policy, scanUrls, context.urlBudget);
}

function redactBodyValue(value: unknown, context: BuildContext): unknown {
  if (typeof value === 'string') {
    const sanitized = sanitizeContextText(value, context);
    addChanges(context, sanitized.changes);
    return sanitized.text;
  }
  if (Array.isArray(value)) return value.map((item) => redactBodyValue(item, context));
  if (isRecord(value)) {
    const output = Object.create(null) as Record<string, unknown>;
    for (const [key, child] of Object.entries(value)) {
      const sanitizedKey = sanitizeContextText(key, context);
      addChanges(context, sanitizedKey.changes);
      if (sanitizedKey.text === '__proto__' || sanitizedKey.text === 'prototype' || sanitizedKey.text === 'constructor') {
        throw new Error('Redacted body key is prototype-sensitive');
      }
      if (Object.prototype.hasOwnProperty.call(output, sanitizedKey.text)) {
        throw new Error('Redacted body keys collide');
      }
      if (isSensitiveKey(key, context) || isSensitiveKey(sanitizedKey.text, context)) {
        if (typeof child !== 'string' || !isRedactedMarker(child)) addChanges(context, 1);
        const marker = sanitizeContextText('[REDACTED]', context);
        addChanges(context, marker.changes);
        output[sanitizedKey.text] = marker.text;
      } else {
        output[sanitizedKey.text] = redactBodyValue(child, context);
      }
    }
    return output;
  }
  return value;
}

function decodeFormComponent(value: string): string {
  if (/%(?![0-9a-f]{2})/i.test(value)) throw new Error('Malformed percent escape');
  const decoded = decodeURIComponent(value.replace(/\+/g, ' '));
  assertNoUnsafeControls(decoded, 'HAR form body');
  return decoded;
}

function sanitizeFormBody(source: string, context: BuildContext): string {
  const output = new URLSearchParams();
  let start = 0;
  let parts = 0;
  while (start <= source.length) {
    parts++;
    if (parts > LIMITS.jsonNodes) throw new Error('HAR form body exceeds the parameter limit');
    const separatorIndex = source.indexOf('&', start);
    const end = separatorIndex < 0 ? source.length : separatorIndex;
    const part = source.slice(start, end);
    if (part) {
      const separator = part.indexOf('=');
      const rawName = separator < 0 ? part : part.slice(0, separator);
      const rawValue = separator < 0 ? '' : part.slice(separator + 1);
      const name = decodeFormComponent(rawName);
      const value = decodeFormComponent(rawValue);
      const componentName = sanitizeEncodedUrlComponent(name, context.policy, context.urlBudget);
      const cleanName = sanitizeContextText(componentName.text, context);
      addChanges(context, componentName.changes + cleanName.changes);
      if (isSensitiveKey(name, context) || isSensitiveKey(cleanName.text, context)) {
        if (!isRedactedMarker(value)) addChanges(context, 1);
        const marker = sanitizePolicyText('[REDACTED]', context.policy, false);
        addChanges(context, marker.changes);
        output.append(cleanName.text, marker.text);
      } else {
        const componentValue = sanitizeEncodedUrlComponent(value, context.policy, context.urlBudget);
        const cleanValue = sanitizeContextText(componentValue.text, context);
        addChanges(context, componentValue.changes + cleanValue.changes);
        output.append(cleanName.text, cleanValue.text);
      }
    }
    if (separatorIndex < 0) break;
    start = separatorIndex + 1;
  }
  const encoded = output.toString();
  if (encoder.encode(encoded).byteLength > LIMITS.inputBytes) throw new Error('HAR form body output exceeds its byte limit');
  return encoded;
}

function omitUnsupportedBody(context: BuildContext, reason: 'body-invalid' | 'body-binary' | 'body-unsupported'): void {
  const descriptions = {
    'body-invalid': 'A malformed or ambiguous request or response body was omitted.',
    'body-binary': 'A binary or base64 request or response body was omitted.',
    'body-unsupported': 'An unsupported request or response body format was omitted.',
  } as const;
  omit(context, reason, descriptions[reason]);
}

function sanitizeSupportedBody(input: Record<string, unknown>, label: string, context: BuildContext): { mimeType: string; text: string } | undefined {
  dropUnknownFields(input, new Set(['mimeType', 'text', 'encoding', 'params', 'comment']), context);
  if ('comment' in input) omit(context, 'comment', 'HAR comments were omitted.');
  if ('params' in input) {
    const params = input.params;
    if (!Array.isArray(params)) {
      omitUnsupportedBody(context, 'body-invalid');
      return undefined;
    }
    if (params.length) {
      omitUnsupportedBody(context, 'body-unsupported');
      return undefined;
    }
  }
  if ('encoding' in input) {
    omitUnsupportedBody(context, input.encoding === 'base64' ? 'body-binary' : 'body-unsupported');
    return undefined;
  }
  if (typeof input.mimeType !== 'string') {
    omitUnsupportedBody(context, 'body-unsupported');
    return undefined;
  }
  const parts = input.mimeType.split(';');
  const mediaType = parts.shift()?.trim().toLowerCase() ?? '';
  let charsetCount = 0;
  for (const parameter of parts) {
    const match = /^\s*charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;]+))\s*$/i.exec(parameter);
    if (!match || (match[1] ?? match[2] ?? match[3]).toLowerCase() !== 'utf-8') {
      omitUnsupportedBody(context, 'body-unsupported');
      return undefined;
    }
    charsetCount++;
  }
  if (charsetCount > 1 || (mediaType !== 'application/json' && mediaType !== 'application/x-www-form-urlencoded')) {
    omitUnsupportedBody(context, 'body-unsupported');
    return undefined;
  }
  const safeMimeType = sanitizeContextText(mediaType, context);
  addChanges(context, safeMimeType.changes);
  if (safeMimeType.text !== mediaType) {
    omitUnsupportedBody(context, 'body-unsupported');
    return undefined;
  }
  if (typeof input.text !== 'string') {
    omitUnsupportedBody(context, 'body-invalid');
    return undefined;
  }
  try {
    checkUtf8Limit(input.text, label);
    assertNoUnsafeControls(input.text, label);
    const cleaned = mediaType === 'application/json'
      ? JSON.stringify(redactBodyValue(parseStrictJson(input.text), context))
      : sanitizeFormBody(input.text, context);
    if (encoder.encode(cleaned).byteLength > LIMITS.inputBytes) throw new Error('Sanitized body exceeds its byte limit');
    return { mimeType: mediaType, text: cleaned };
  } catch {
    omitUnsupportedBody(context, 'body-invalid');
    return undefined;
  }
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
export function sanitizeLog(source: string, policyValue: RedactionPolicy = DEFAULT_REDACTION_POLICY): SanitizedText {
  if (typeof source !== 'string') throw new Error('Log input must be text');
  checkUtf8Limit(source, 'Log');
  assertNoUnsafeControls(source, 'Log');
  const policy = validateRedactionPolicy(policyValue);
  const redacted = sanitizePolicyText(source, policy, true, { urls: 0, parameters: 0 });
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
  const result = sanitizeContextText(value, context);
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
  let decodedPath = url.pathname;
  try {
    decodedPath = decodeURI(url.pathname);
  } catch {
    // Preserve the encoded path and still run literal cleanup on its visible text.
  }
  const safePath = sanitizeContextText(decodedPath, context);
  addChanges(context, safePath.changes);
  url.pathname = safePath.text;
  const outputParams = new URLSearchParams();
  let queryChanged = false;
  let parametersSeen = 0;
  for (const [key, valueInQuery] of url.searchParams) {
    parametersSeen++;
    if (parametersSeen > MAX_URL_PARAMETERS || context.urlBudget.parameters + parametersSeen > MAX_URL_PARAMETERS) throw new Error('HAR URL contains too many query parameters');
    const safeKey = sanitizeContextText(key, context);
    addChanges(context, safeKey.changes);
    if (isSensitiveKey(key, context) || isSensitiveKey(safeKey.text, context)) {
      const marker = sanitizeContextText('[REDACTED]', context);
      addChanges(context, marker.changes);
      outputParams.append(safeKey.text, marker.text);
      if (!isRedactedMarker(valueInQuery)) addChanges(context, 1);
      queryChanged = true;
      continue;
    }
    const sanitized = sanitizeContextText(valueInQuery, context);
    outputParams.append(safeKey.text, sanitized.text);
    if (sanitized.changes) {
      addChanges(context, sanitized.changes);
    }
    if (sanitized.changes || safeKey.text !== key) queryChanged = true;
  }
  if (queryChanged) url.search = outputParams.toString();
  const sanitizedUrl = url.toString();
  if (hasConfiguredLiteral(sanitizedUrl, context.policy)) throw new Error('Configured literal text could not be removed safely from a HAR URL');
  return sanitizedUrl;
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
    const postData = requireRecord(input.postData, 'entry.request.postData');
    if (context.policy.bodyMode === 'omit') {
      omit(context, 'body', 'Request bodies were omitted.');
    } else {
      const sanitized = sanitizeSupportedBody(postData, 'entry.request.postData', context);
      if (sanitized) output.postData = sanitized;
    }
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
  if ('text' in input || 'encoding' in input) {
    if (context.policy.bodyMode === 'omit') {
      omit(context, 'body', 'Response bodies were omitted.');
    } else {
      const bodyInput: Record<string, unknown> = {};
      for (const key of ['mimeType', 'text', 'encoding'] as const) if (key in input) bodyInput[key] = input[key];
      const sanitized = sanitizeSupportedBody(bodyInput, 'entry.response.content', context);
      if (sanitized) {
        output.mimeType = sanitized.mimeType;
        output.text = sanitized.text;
      }
    }
  }
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
export function sanitizeHar(source: string, policyValue: RedactionPolicy = DEFAULT_REDACTION_POLICY): SanitizedText {
  if (typeof source !== 'string') throw new Error('HAR input must be text');
  checkUtf8Limit(source, 'HAR');
  const policy = validateRedactionPolicy(policyValue);
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch (error) {
    if (error instanceof Error && /duplicate JSON object key|prototype-sensitive JSON object key|exceeds .*?(?:node|depth).*?limit/i.test(error.message)) throw error;
    throw new Error('Malformed HAR JSON');
  }
  assertHarBudget(parsed);
  const context: BuildContext = { changes: 0, omissions: new Map(), policy, sensitiveKeySet: new Set(policy.sensitiveKeys), urlBudget: { urls: 0, parameters: 0 } };
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
  const output = JSON.stringify({ log: outputLog }, null, 2);
  checkUtf8Limit(output, 'Sanitized HAR');
  return toSanitizedText(output, context);
}
