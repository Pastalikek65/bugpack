import { describe, expect, it } from 'vitest';
import { sanitizeHar, sanitizeLog } from '../src/core/redaction';
import { LIMITS } from '../src/core/contracts';

describe('sanitizeHar', () => {
  it('projects HAR 1.2 to safe fields, redacts URL credentials and tokens, and omits bodies and extensions', () => {
    const source = JSON.stringify({
      log: {
        version: '1.2',
        creator: { name: 'BugPack', version: '1', privateExtension: 'creator-secret' },
        privateExtension: 'root-secret',
        entries: [{
          startedDateTime: '2026-10-09T10:00:00.000Z',
          time: 4,
          request: {
            method: 'POST',
            url: 'https://alice:password@example.test/api?keep=yes&access_token=query-secret#fragment-secret',
            httpVersion: 'HTTP/2',
            headers: [
              { name: 'content-type', value: 'application/json' },
              { name: 'Authorization', value: 'Bearer header-secret' },
              { name: 'X-Private-Header', value: 'unknown-header-secret' },
            ],
            cookies: [{ name: 'sid', value: 'cookie-secret' }],
            queryString: [{ name: 'access_token', value: 'query-string-secret' }],
            postData: { mimeType: 'application/json', text: 'request-body-secret' },
            bodySize: 21,
            headersSize: 10,
            extensionField: 'request-extension-secret',
          },
          response: {
            status: 200,
            statusText: 'OK',
            httpVersion: 'HTTP/2',
            headers: [{ name: 'content-type', value: 'application/json' }],
            cookies: [{ name: 'sid', value: 'response-cookie-secret' }],
            content: { size: 25, mimeType: 'application/json', text: 'response-body-secret', encoding: 'base64' },
            redirectURL: '',
            headersSize: 9,
            bodySize: 25,
          },
          timings: { send: 1, wait: 2, receive: 1 },
          cache: { afterRequest: { headers: [{ name: 'x', value: 'cache-secret' }] } },
          extensionField: 'entry-extension-secret',
        }],
      },
    });
    const original = source;

    const result = sanitizeHar(source);
    const output = JSON.parse(result.text) as any;
    const clean = result.text;

    expect(source).toBe(original);
    expect(output.log.entries[0].request.url).toBe('https://example.test/api?keep=yes&access_token=%5BREDACTED%5D');
    expect(output.log.entries[0].request.headers).toEqual([{ name: 'content-type', value: 'application/json' }]);
    expect(output.log.entries[0].response.content).toEqual({ size: 25, mimeType: 'application/json' });
    expect(clean).not.toMatch(/password|header-secret|unknown-header-secret|cookie-secret|query-string-secret|request-body-secret|response-body-secret|root-secret|extension-secret|fragment-secret|cache-secret/);
    expect(result.changes).toBeGreaterThan(0);
    expect(result.omissions.reduce((sum, item) => sum + item.count, 0)).toBeGreaterThan(0);
  });

  it('rejects unsupported HAR versions, malformed JSON, control characters, and bounded-resource violations', () => {
    expect(() => sanitizeHar('{"log":{"version":"2.0","entries":[]}}')).toThrow(/version/i);
    expect(() => sanitizeHar('{')).toThrow(/json|malformed/i);
    expect(() => sanitizeHar('{"log":{"version":"1.2","entries":[],"comment":"bad\\u0000value"}}')).toThrow(/control/i);
    expect(() => sanitizeHar(JSON.stringify({ log: { version: '1.2', creator: { name: 'fixture', version: '1' }, entries: Array.from({ length: 5001 }, () => ({})) } }))).toThrow(/entry|limit/i);
    const nested: unknown[] = [];
    let current: unknown = nested;
    for (let depth = 0; depth <= LIMITS.jsonDepth; depth++) {
      const child: unknown[] = [];
      (current as unknown[]).push(child);
      current = child;
    }
    expect(() => sanitizeHar(JSON.stringify({ log: { version: '1.2', creator: { name: 'fixture', version: '1' }, entries: [], extension: nested } }))).toThrow(/depth/i);
    expect(() => sanitizeHar(JSON.stringify({ log: { version: '1.2', creator: { name: 'fixture', version: '1' }, entries: [], extension: Array.from({ length: LIMITS.jsonNodes + 1 }, () => null) } }))).toThrow(/node limit/i);
  });
});

describe('sanitizeLog', () => {
  it('redacts authorization, bearer tokens, JWTs, and sensitive key-value fields without changing the input', () => {
    const source = [
      'Authorization: Bearer authorization-secret',
      'request bearer bearer-secret-123',
      'password="pw-secret" token=token-secret api_key: api-secret',
      'cookie: sid=session-secret; theme=theme-cookie-secret',
      'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signatureSecret123',
      'ordinary status=200',
    ].join('\n');

    const result = sanitizeLog(source);

    expect(source).toContain('authorization-secret');
    expect(result.text).not.toMatch(/authorization-secret|bearer-secret-123|pw-secret|token-secret|api-secret|session-secret|theme-cookie-secret|eyJhbGciOiJIUzI1NiJ9|signatureSecret123/);
    expect(result.text).toContain('status=200');
    expect(result.changes).toBeGreaterThanOrEqual(5);
    expect(result.omissions).toEqual([]);
  });

  it('does not count already-redacted markers again when text is sanitized twice', () => {
    const first = sanitizeLog('Authorization: Bearer repeat-secret\ntoken=repeat-token');
    const second = sanitizeLog(first.text);
    expect(second.text).toBe(first.text);
    expect(second.changes).toBe(0);
  });

  it('redacts quoted JSON credential keys and common signed URL and OAuth parameters', () => {
    const source = '{"password":"json-password-secret","client_secret":"json-client-secret"} https://example.test/?X-Amz-Signature=aws-signature-secret&X-Amz-Credential=aws-credential-secret&code=oauth-code-secret&keep=visible';
    const result = sanitizeLog(source);
    expect(result.text).not.toMatch(/json-password-secret|json-client-secret|aws-signature-secret|aws-credential-secret|oauth-code-secret/);
    expect(JSON.parse(result.text.slice(0, result.text.indexOf(' https')))).toEqual({ password: '[REDACTED]', client_secret: '[REDACTED]' });
    expect(result.text).toContain('keep=visible');
    expect(result.changes).toBeGreaterThanOrEqual(5);
  });

  it('redacts Azure SAS signatures and Google Cloud signed URL credentials', () => {
    const source = 'https://blob.example.test/document?sv=2026-01-01&sig=azure-sas-secret&X-Goog-Signature=gcs-signature-secret&GoogleAccessId=gcs-access-secret&keep=visible';
    const result = sanitizeLog(source);
    expect(result.text).not.toMatch(/azure-sas-secret|gcs-signature-secret|gcs-access-secret/);
    expect(result.text).toContain('keep=visible');
  });

  it('redacts Azure and Google Cloud signed credentials in HAR request URLs', () => {
    const source = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{ request: { method: 'GET', url: 'https://blob.example.test/object?sig=azure-secret&X-Goog-Signature=gcs-signature&GoogleAccessId=gcs-access&keep=visible' }, response: { status: 200, content: {} } }] } });
    const result = sanitizeHar(source);
    const url = (JSON.parse(result.text) as any).log.entries[0].request.url as string;
    expect(url).not.toMatch(/azure-secret|gcs-signature|gcs-access/);
    expect(url).toContain('keep=visible');
  });

  it('redacts CloudFront and S3 Signature V2 credentials in HAR URLs and logs', () => {
    const url = 'https://cdn.example.test/file?Expires=1790000000&Signature=cloudfront-signature-secret&Key-Pair-Id=cloudfront-key-id-secret&AWSAccessKeyId=s3-access-key-secret&keep=visible';
    const log = sanitizeLog(`GET ${url}`);
    const harSource = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{ request: { method: 'GET', url }, response: { status: 200, content: {} } }] } });
    const harResult = sanitizeHar(harSource);
    const harUrl = (JSON.parse(harResult.text) as any).log.entries[0].request.url as string;

    expect(log.text).not.toMatch(/cloudfront-signature-secret|cloudfront-key-id-secret|s3-access-key-secret/);
    expect(harUrl).not.toMatch(/cloudfront-signature-secret|cloudfront-key-id-secret|s3-access-key-secret/);
    expect(log.text).toContain('keep=visible');
    expect(harUrl).toContain('keep=visible');
  });

  it('rejects unsupported controls and input exceeding the byte limit', () => {
    expect(() => sanitizeLog('line\u0000secret')).toThrow(/control/i);
    expect(() => sanitizeLog('x'.repeat(16 * 1024 * 1024 + 1))).toThrow(/limit|large/i);
  });
});
