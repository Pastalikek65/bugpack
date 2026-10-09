import { LIMITS, type RedactionPolicy } from './contracts.ts';

const encoder = new TextEncoder();
const POLICY_BYTES = 64 * 1024;
const POLICY_DEPTH = 12;
const POLICY_NODES = 2048;
const MAX_SENSITIVE_KEYS = 64;
const MAX_SENSITIVE_KEY_BYTES = 4096;
const MAX_LITERAL_RULES = 128;
const MAX_LITERAL_PART_LENGTH = 256;
const MAX_LITERAL_BYTES = 16 * 1024;

export const BASELINE_SENSITIVE_KEYS: readonly string[] = Object.freeze([
  'access-token', 'access_token', 'api-key', 'api_key', 'apikey', 'authorization', 'aws-access-key-id',
  'aws_access_key_id', 'client-secret', 'client_secret', 'code', 'cookie', 'google-access-id',
  'google_access_id', 'jwt', 'key-pair-id', 'key_pair_id', 'oauth-code', 'oauth-token', 'oauth-verifier',
  'oauth_code', 'oauth_token', 'oauth_verifier', 'passwd', 'password', 'pwd', 'refresh-token',
  'refresh_token', 'secret', 'session', 'session-id', 'sessionid', 'set-cookie', 'sig', 'signature',
  'state', 'token', 'x-amz-credential', 'x-amz-security-token', 'x-amz-signature', 'x-goog-credential',
  'x-goog-security-token', 'x-goog-signature',
]);

export const DEFAULT_REDACTION_POLICY: RedactionPolicy = Object.freeze({
  schemaVersion: 1,
  name: 'BugPack default',
  bodyMode: 'omit',
  sensitiveKeys: BASELINE_SENSITIVE_KEYS,
  literalRules: Object.freeze([]),
});

export interface StrictJsonLimits {
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

function fail(message: string): never {
  throw new Error(message);
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** Parses bounded JSON while rejecting duplicate or prototype-sensitive object keys. */
export function parseStrictJson(source: string, limits: StrictJsonLimits = {}): unknown {
  if (typeof source !== 'string') fail('JSON input must be text');
  const maxBytes = limits.maxBytes ?? LIMITS.inputBytes;
  const maxDepth = limits.maxDepth ?? LIMITS.jsonDepth;
  const maxNodes = limits.maxNodes ?? LIMITS.jsonNodes;
  if (encoder.encode(source).byteLength > maxBytes) fail('JSON input exceeds its byte limit');
  let cursor = 0;
  let nodes = 0;

  const skipWhitespace = (): void => {
    while (cursor < source.length && (source[cursor] === ' ' || source[cursor] === '\t' || source[cursor] === '\r' || source[cursor] === '\n')) cursor++;
  };

  const parseString = (): string => {
    const start = cursor;
    cursor++;
    while (cursor < source.length) {
      const character = source[cursor++];
      if (character === '"') {
        let value: string;
        try {
          value = JSON.parse(source.slice(start, cursor)) as string;
        } catch {
          return fail('Malformed JSON string');
        }
        if (!isWellFormedUnicode(value)) fail('JSON contains an invalid Unicode surrogate');
        return value;
      }
      if (character === '\\') {
        if (cursor >= source.length) break;
        cursor++;
      }
    }
    return fail('Malformed JSON string');
  };

  const parseValue = (depth: number): unknown => {
    nodes++;
    if (nodes > maxNodes) fail(`JSON exceeds the ${maxNodes} node limit`);
    if (depth > maxDepth) fail(`JSON exceeds the depth ${maxDepth} limit`);
    skipWhitespace();
    const current = source[cursor];
    if (current === '"') return parseString();
    if (current === '{') {
      cursor++;
      const output = Object.create(null) as Record<string, unknown>;
      const seen = new Set<string>();
      skipWhitespace();
      if (source[cursor] === '}') {
        cursor++;
        return output;
      }
      while (cursor < source.length) {
        skipWhitespace();
        if (source[cursor] !== '"') fail('Malformed JSON object key');
        const key = parseString();
        if (seen.has(key)) fail(`Duplicate JSON object key: ${key}`);
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') fail(`Prototype-sensitive JSON object key is unsupported: ${key}`);
        seen.add(key);
        skipWhitespace();
        if (source[cursor++] !== ':') fail('Malformed JSON object separator');
        output[key] = parseValue(depth + 1);
        skipWhitespace();
        if (source[cursor] === '}') {
          cursor++;
          return output;
        }
        if (source[cursor++] !== ',') fail('Malformed JSON object delimiter');
      }
      return fail('Malformed JSON object');
    }
    if (current === '[') {
      cursor++;
      const output: unknown[] = [];
      skipWhitespace();
      if (source[cursor] === ']') {
        cursor++;
        return output;
      }
      while (cursor < source.length) {
        output.push(parseValue(depth + 1));
        skipWhitespace();
        if (source[cursor] === ']') {
          cursor++;
          return output;
        }
        if (source[cursor++] !== ',') fail('Malformed JSON array delimiter');
      }
      return fail('Malformed JSON array');
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (source.startsWith(literal, cursor)) {
        cursor += literal.length;
        return value;
      }
    }
    const numberMatch = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(cursor));
    if (numberMatch) {
      cursor += numberMatch[0].length;
      const number = Number(numberMatch[0]);
      if (!Number.isFinite(number)) fail('JSON number is outside the supported finite range');
      return number;
    }
    return fail('Malformed JSON value');
  };

  const value = parseValue(0);
  skipWhitespace();
  if (cursor !== source.length) fail('Malformed JSON trailing data');
  return value;
}

function plainRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(`${label} must be a plain object`);
  return value as Record<string, unknown>;
}

function exactKeys(record: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== 'string' || !allowed.includes(key)) fail(`${label} has an unknown field: ${String(key)}`);
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) fail(`${label} fields must be plain data values`);
  }
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) fail(`${label} is missing ${key}`);
  }
}

function denseDataArray(value: unknown, label: string, maximumLength: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail(`${label} must be a bounded plain array`);
  }
  if (value.length > maximumLength) fail(`${label} exceeds its maximum item limit`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) fail(`${label} must not have extra array properties`);
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) fail(`${label} must not contain holes or accessors`);
  }
  return value;
}

function normalizeLiteralRules(value: unknown): readonly { value: string; replacement: string }[] {
  const items = denseDataArray(value, 'Redaction policy literalRules', MAX_LITERAL_RULES);
  let totalBytes = 0;
  const values = new Set<string>();
  const rules = items.map((item, index) => {
    const rule = plainRecord(item, `Redaction policy literalRules[${index}]`);
    exactKeys(rule, ['value', 'replacement'], `Redaction policy literalRules[${index}]`);
    const source = rule.value;
    const replacement = rule.replacement;
    if (typeof source !== 'string' || !source.length || source.length > MAX_LITERAL_PART_LENGTH || !isWellFormedUnicode(source)) {
      fail(`Redaction policy literalRules[${index}].value is invalid or too long`);
    }
    if (typeof replacement !== 'string' || replacement.length > MAX_LITERAL_PART_LENGTH || !isWellFormedUnicode(replacement)) {
      fail(`Redaction policy literalRules[${index}].replacement is invalid or too long`);
    }
    if (/[\u0000-\u001f\u007f]/.test(source) || /[\u0000-\u001f\u007f]/.test(replacement)) {
      fail(`Redaction policy literalRules[${index}] contains unsupported control characters`);
    }
    totalBytes += encoder.encode(source).byteLength + encoder.encode(replacement).byteLength;
    if (totalBytes > MAX_LITERAL_BYTES) fail('Redaction policy literal rules exceed their total byte limit');
    if (values.has(source)) fail('Redaction policy literal values must be unique');
    values.add(source);
    return { value: source, replacement };
  });
  for (const rule of rules) {
    if (rules.some((other) => rule.replacement.includes(other.value))) {
      fail('Redaction policy replacements must not contain a configured sensitive literal');
    }
  }
  return Object.freeze(rules.sort((left, right) => left.value < right.value ? -1 : left.value > right.value ? 1 : 0)
    .map((rule) => Object.freeze(rule)));
}

/** Validates and normalizes a policy without accepting unknown fields or weakening baseline keys. */
export function validateRedactionPolicy(value: unknown): RedactionPolicy {
  const input = plainRecord(value, 'Redaction policy');
  exactKeys(input, ['schemaVersion', 'name', 'bodyMode', 'sensitiveKeys', 'literalRules'], 'Redaction policy');
  if (input.schemaVersion !== 1) fail(`Unsupported redaction policy schema version: ${String(input.schemaVersion)}`);
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 80 || !isWellFormedUnicode(input.name) || /[\u0000-\u001f\u007f]/.test(input.name)) {
    fail('Redaction policy name must be bounded text without controls');
  }
  if (input.bodyMode !== 'omit' && input.bodyMode !== 'supported') fail('Redaction policy body mode must be omit or supported');
  const inputKeys = denseDataArray(input.sensitiveKeys, 'Redaction policy sensitiveKeys', MAX_SENSITIVE_KEYS);
  const keySet = new Set<string>();
  let keyBytes = 0;
  const sensitiveKeys = inputKeys.map((key, index) => {
    if (typeof key !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(key)) fail(`Redaction policy sensitiveKeys[${index}] is invalid`);
    const normalized = key.toLowerCase();
    if (keySet.has(normalized)) fail('Redaction policy sensitive keys must be unique ignoring case');
    keySet.add(normalized);
    keyBytes += encoder.encode(normalized).byteLength;
    if (keyBytes > MAX_SENSITIVE_KEY_BYTES) fail('Redaction policy sensitive keys exceed their total byte limit');
    return normalized;
  });
  for (const key of BASELINE_SENSITIVE_KEYS) {
    if (!keySet.has(key)) fail(`Redaction policy cannot remove mandatory credential key: ${key}`);
  }
  sensitiveKeys.sort();
  const normalized: RedactionPolicy = {
    schemaVersion: 1,
    name: input.name.trim(),
    bodyMode: input.bodyMode,
    sensitiveKeys: Object.freeze(sensitiveKeys),
    literalRules: normalizeLiteralRules(input.literalRules),
  };
  return Object.freeze(normalized);
}

/** Imports the versioned JSON policy format; duplicate keys are rejected as ambiguous. */
export function parseRedactionPolicy(source: string): RedactionPolicy {
  const value = parseStrictJson(source, { maxBytes: POLICY_BYTES, maxDepth: POLICY_DEPTH, maxNodes: POLICY_NODES });
  return validateRedactionPolicy(value);
}

/** Exports a canonical JSON policy suitable for review and later import. */
export function exportRedactionPolicy(value: unknown): string {
  const policy = validateRedactionPolicy(value);
  return `${JSON.stringify(policy, null, 2)}\n`;
}

// Synchronous SHA-256 keeps the shared browser and CLI core API synchronous.
export function redactionPolicyFingerprint(value: unknown): string {
  const policy = validateRedactionPolicy(value);
  const input = encoder.encode(JSON.stringify(policy));
  const constants = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const state = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(paddedLength - 8, BigInt(input.length) * 8n, false);
  const words = new Uint32Array(64);
  const rotateRight = (value: number, count: number): number => (value >>> count) | (value << (32 - count));
  for (let offset = 0; offset < padded.length; offset += 64) {
    const view = new DataView(padded.buffer, offset, 64);
    for (let index = 0; index < 16; index++) words[index] = view.getUint32(index * 4, false);
    for (let index = 16; index < 64; index++) {
      const left = words[index - 15];
      const right = words[index - 2];
      const small0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
      const small1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
      words[index] = (words[index - 16] + small0 + words[index - 7] + small1) >>> 0;
    }
    let a = state[0], b = state[1], c = state[2], d = state[3];
    let e = state[4], f = state[5], g = state[6], h = state[7];
    for (let index = 0; index < 64; index++) {
      const big1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temporary1 = (h + big1 + choice + constants[index] + words[index]) >>> 0;
      const big0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (big0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + temporary1) >>> 0;
      d = c; c = b; b = a; a = (temporary1 + temporary2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0; state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0; state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0; state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0; state[7] = (state[7] + h) >>> 0;
  }
  return [...state].map((word) => word.toString(16).padStart(8, '0')).join('');
}
