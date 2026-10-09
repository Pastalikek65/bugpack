import { describe, expect, it } from 'vitest';
import { sanitizeHar, sanitizeLog } from '../src/core/redaction';
import { LIMITS, type RedactionPolicy } from '../src/core/contracts';
import { DEFAULT_REDACTION_POLICY, validateRedactionPolicy } from '../src/core/policy';

const sanitizeHarWithPolicy = sanitizeHar;
const sanitizeLogWithPolicy = sanitizeLog;

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

  it('rejects duplicate HAR object keys instead of accepting an ambiguous last value', () => {
    const ambiguous = '{"log":{"version":"1.2","creator":{"name":"test","version":"1"},"entries":[],"entries":[]}}';
    expect(() => sanitizeHar(ambiguous)).toThrow(/duplicate.*key/i);
  });

  it('redacts percent-encoded credential query keys in free-form logs', () => {
    const source = 'https://example.test/?%74oken=ENCODED_TOKEN_SECRET&keep=visible';
    const result = sanitizeLog(source);

    expect(result.text).not.toContain('ENCODED_TOKEN_SECRET');
    expect(result.text).toContain('keep=visible');
    expect(sanitizeLog(result.text).text).toBe(result.text);

    const doubleEncoded = sanitizeLog('https://example.test/?%2574oken=DOUBLE_ENCODED_TOKEN_SECRET');
    expect(doubleEncoded.text).not.toContain('DOUBLE_ENCODED_TOKEN_SECRET');
    let deeplyEncodedKey = '%74oken';
    for (let index = 0; index < 10; index++) deeplyEncodedKey = encodeURIComponent(deeplyEncodedKey);
    const cappedKey = sanitizeLog(`https://example.test/?${deeplyEncodedKey}=CAPPED_KEY_SECRET`);
    expect(cappedKey.text).not.toContain('CAPPED_KEY_SECRET');

    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: 'path-literal-7f3a', replacement: '[LOCAL]' }],
    });
    const encodedPath = sanitizeLogWithPolicy('https://example.test/%70ath-literal-7f3a', policy);
    expect(encodedPath.text).not.toContain('path-literal-7f3a');
  });

  it('removes authority credentials from common non-HTTP connection URLs', () => {
    const result = sanitizeLog('postgres://alice:DB_SECRET_777@db.example/app redis://:CACHE_SECRET_888@cache.example/0 ftp://alice:FTP_SECRET_999@files.example/path');

    expect(result.text).not.toMatch(/alice|DB_SECRET_777|CACHE_SECRET_888|FTP_SECRET_999/);
    expect(result.text).toContain('postgres://db.example/app');
    expect(result.text).toContain('redis://cache.example/0');
    expect(result.text).toContain('ftp://files.example/path');
    expect(sanitizeLog(result.text).text).toBe(result.text);

    const invalid = sanitizeLog('postgres://alice:INVALID_URI_SECRET@[broken/path');
    expect(invalid.text).not.toContain('INVALID_URI_SECRET');
  });

  it('applies bounded query and path cleanup to parsed hierarchical network URLs', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: 'private/segment', replacement: '[LOCAL]' }],
    });
    const result = sanitizeLogWithPolicy('redis://cache.example/private%2Fsegment?%2574oken=REDIS_TOKEN_SECRET', policy);

    expect(result.text).not.toMatch(/private|segment|REDIS_TOKEN_SECRET/);
    expect(result.text).toContain('redis://cache.example/');
    expect(sanitizeLogWithPolicy(result.text, policy).text).toBe(result.text);
  });

  it('sanitizes bounded nested redirect URLs and fails closed beyond the nested depth cap', () => {
    const direct = sanitizeLog('https://example.test/?redirect=https%3A%2F%2Fevil.test%2F%3F%2574oken%3DNESTED_SECRET');
    expect(direct.text).not.toContain('NESTED_SECRET');

    const nestedDatabase = sanitizeLog('https://outer.example/?next=postgres%3A%2F%2Falice%3ADB_SECRET%40db.example%2Fapp%3Ftoken%3DNESTED_DB_TOKEN');
    expect(nestedDatabase.text).not.toMatch(/alice|DB_SECRET|NESTED_DB_TOKEN/);

    let deepUrl = 'https://evil.test/?public=TOO_DEEP_SECRET';
    for (let index = 0; index < 5; index++) deepUrl = `https://redirect.test/?next=${encodeURIComponent(deepUrl)}`;
    const deep = sanitizeLog(deepUrl);
    expect(deep.text).not.toContain('TOO_DEEP_SECRET');

    let multiplyEncoded = 'https://evil.test/?public=DEEP_SECRET_ABC123';
    for (let index = 0; index < 10; index++) multiplyEncoded = encodeURIComponent(multiplyEncoded);
    const capped = sanitizeLog(`https://outer.example/?next=${multiplyEncoded}`);
    expect(capped.text).not.toContain('DEEP_SECRET_ABC123');
  });

  it('redacts configured literals in paths with encoded reserved separators', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: 'private/segment', replacement: '[LOCAL]' }],
    });
    const result = sanitizeLogWithPolicy('https://example.test/private%2Fsegment', policy);

    expect(result.text).not.toContain('private');
    expect(result.text).not.toContain('segment');
    expect(result.text).toContain('example.test');

    const multiplyEncoded = sanitizeLogWithPolicy('https://example.test/private%252Fsegment', policy);
    expect(multiplyEncoded.text).not.toContain('private');
    expect(multiplyEncoded.text).not.toContain('segment');
  });

  it('sanitizes layered-encoded query values and baseline credential syntax', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: 'private/segment', replacement: '[LOCAL]' }],
    });
    const literal = sanitizeLogWithPolicy('https://example.test/?note=private%252Fsegment', policy);
    expect(literal.text).not.toContain('private');
    expect(literal.text).not.toContain('segment');
    expect(sanitizeLogWithPolicy(literal.text, policy).text).toBe(literal.text);

    const baseline = sanitizeLog('https://example.test/?note=password%253DVALUE_SECRET_9981');
    expect(baseline.text).not.toContain('VALUE_SECRET_9981');
    expect(sanitizeLog(baseline.text).text).toBe(baseline.text);

    const mixedDepthValue = encodeURIComponent('password=VISIBLE_SECRET&other=password%3DDEEP_SECRET_123');
    const mixedDepth = sanitizeLog(`https://example.test/?note=${mixedDepthValue}`);
    expect(mixedDepth.text).not.toContain('VISIBLE_SECRET');
    expect(mixedDepth.text).not.toContain('DEEP_SECRET_123');
  });

  it('enforces one aggregate query-parameter budget across all text URLs', () => {
    const params = Array.from({ length: 1000 }, (_, index) => `p${index}=v`).join('&');
    const url = `https://example.test/?${params}`;
    const source = Array.from({ length: 51 }, () => url).join(' ');

    expect(() => sanitizeLog(source)).toThrow(/too many URL parameters/i);
  });

  it('rebuilds URL parameters independently when a renamed sensitive key collides', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      sensitiveKeys: [...DEFAULT_REDACTION_POLICY.sensitiveKeys, 'private_id'],
      literalRules: [{ value: 'alias', replacement: 'private_id' }],
    });
    const result = sanitizeLog('https://example.test/?%61lias=ALIASSECRET&private_id=OWNSECRET', policy);

    expect(result.text).not.toMatch(/ALIASSECRET|OWNSECRET/);
    expect(result.text.match(/private_id=%5BREDACTED%5D/g)).toHaveLength(2);
  });

  it('applies literal and additional sensitive-key rules to logs and HAR URL paths and parameters', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      sensitiveKeys: [...DEFAULT_REDACTION_POLICY.sensitiveKeys, 'private_id'],
      literalRules: [
        { value: 'private-literal-7f3a', replacement: '[LOCAL]' },
        { value: 'alias-id', replacement: 'private_id' },
      ],
    });
    const source = 'private_id=private-key-value alias-id=alias-log-secret private-literal-7f3a https://example.test/private-literal-7f3a?private_id=private-key-value';
    const sanitizedLog = sanitizeLogWithPolicy(source, policy);
    expect(sanitizedLog.text).not.toContain('private-key-value');
    expect(sanitizedLog.text).not.toContain('alias-log-secret');
    expect(sanitizedLog.text).not.toContain('private-literal-7f3a');
    expect(sanitizeLogWithPolicy(sanitizedLog.text, policy).text).toBe(sanitizedLog.text);

    const har = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{
      request: { method: 'GET', url: 'https://example.test/private-literal-7f3a?private_id=private-key-value&alias-id=alias-query-secret&keep=private-literal-7f3a' },
      response: { status: 200, content: {} },
    }] } });
    const output = sanitizeHarWithPolicy(har, policy);
    expect(output.text).not.toContain('private-key-value');
    expect(output.text).not.toContain('alias-query-secret');
    expect(output.text).not.toContain('private-literal-7f3a');
    expect(JSON.parse(output.text).log.entries[0].request.url).toContain('keep=%5BLOCAL%5D');
  });

  it('cleans supported JSON request and response bodies recursively and sanitizes UTF-8 forms', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      bodyMode: 'supported',
      sensitiveKeys: [...DEFAULT_REDACTION_POLICY.sensitiveKeys, 'private_id'],
      literalRules: [
        { value: 'private-body-literal', replacement: '[LOCAL]' },
        { value: 'private/segment', replacement: '[LOCAL]' },
        { value: 'access-alias', replacement: 'access_token' },
      ],
    });
    const source = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [
      {
        request: { method: 'POST', url: 'https://example.test/', postData: { mimeType: 'application/json', text: JSON.stringify({ profile: { password: 'request-password-secret', note: 'private-body-literal', 'access-alias': 'renamed-body-secret' }, private_id: 'request-id-secret' }) } },
        response: { status: 200, content: { mimeType: 'application/json', text: JSON.stringify({ nested: [{ access_token: 'response-token-secret', safe: 'shown' }] }) } },
      },
      {
        request: { method: 'POST', url: 'https://example.test/form', postData: { mimeType: 'application/x-www-form-urlencoded; charset=UTF-8', text: 'password=form-password-secret&access-alias=form-alias-secret&keep=hello+world' } },
        response: { status: 200, content: { mimeType: 'application/x-www-form-urlencoded', text: 'private_id=response-form-secret&keep=shown' } },
      },
      {
        request: { method: 'POST', url: 'https://example.test/encoded-form', postData: { mimeType: 'application/x-www-form-urlencoded', text: 'note=private%252Fsegment&other=password%253DVALUE_SECRET_9981&password=password%253DVALUE_SECRET_9999' } },
        response: { status: 200, content: {} },
      },
    ] } });
    const result = sanitizeHarWithPolicy(source, policy);
    const entries = JSON.parse(result.text).log.entries;
    const requestJson = JSON.parse(entries[0].request.postData.text);
    const responseJson = JSON.parse(entries[0].response.content.text);

    expect(requestJson).toEqual({ profile: { password: '[REDACTED]', note: '[LOCAL]', access_token: '[REDACTED]' }, private_id: '[REDACTED]' });
    expect(responseJson).toEqual({ nested: [{ access_token: '[REDACTED]', safe: 'shown' }] });
    expect(entries[1].request.postData.text).toContain('password=%5BREDACTED%5D');
    expect(entries[1].request.postData.text).toContain('access_token=%5BREDACTED%5D');
    expect(entries[1].request.postData.text).toContain('keep=hello+world');
    expect(entries[1].response.content.text).toContain('private_id=%5BREDACTED%5D');
    expect(entries[2].request.postData.text).toContain('note=%5BLOCAL%5D');
    expect(result.text).not.toMatch(/request-password-secret|request-id-secret|response-token-secret|form-password-secret|response-form-secret|form-alias-secret|renamed-body-secret|private-body-literal|private%252Fsegment|VALUE_SECRET_9981|VALUE_SECRET_9999/);
  });

  it('omits unsupported, base64, malformed, duplicate-key, and prototype-key bodies with reason counts', () => {
    const policy = validateRedactionPolicy({ ...DEFAULT_REDACTION_POLICY, bodyMode: 'supported' });
    const texts = [
      { mimeType: 'application/octet-stream', text: 'binary-secret-1' },
      { mimeType: 'application/json', encoding: 'base64', text: 'binary-secret-2' },
      { mimeType: 'application/json', text: '{invalid-json-secret' },
      { mimeType: 'application/json', text: '{"same":"first-secret","same":"second-secret"}' },
      { mimeType: 'application/json', text: '{"__proto__":{"polluted":"prototype-secret"}}' },
      { mimeType: 'application/x-www-form-urlencoded', text: 'bad=%GG&secret=bad-form-secret' },
    ];
    const source = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: texts.map((postData) => ({
      request: { method: 'POST', url: 'https://example.test/', postData },
      response: { status: 200, content: {} },
    })) } });
    const result = sanitizeHarWithPolicy(source, policy);
    const output = JSON.parse(result.text);

    expect(result.text).not.toMatch(/binary-secret|invalid-json-secret|first-secret|second-secret|prototype-secret|bad-form-secret/);
    expect(output.log.entries.every((entry: any) => !('postData' in entry.request))).toBe(true);
    expect(result.omissions.filter((item) => item.code.startsWith('body-')).map((item) => [item.code, item.count]).sort()).toEqual([
      ['body-binary', 1], ['body-invalid', 4], ['body-unsupported', 1],
    ]);
    expect(({} as { polluted?: string }).polluted).toBeUndefined();
  });

  it('bounds the number of URL-encoded body parameters and omits over-budget text', () => {
    const policy = validateRedactionPolicy({ ...DEFAULT_REDACTION_POLICY, bodyMode: 'supported' });
    const oversizedForm = '&'.repeat(LIMITS.jsonNodes + 1);
    const source = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{
      request: { method: 'POST', url: 'https://example.test/', postData: { mimeType: 'application/x-www-form-urlencoded', text: oversizedForm } },
      response: { status: 200, content: {} },
    }] } });

    const result = sanitizeHarWithPolicy(source, policy);
    const output = JSON.parse(result.text);

    expect(output.log.entries[0].request.postData).toBeUndefined();
    expect(result.omissions).toContainEqual(expect.objectContaining({ code: 'body-invalid', count: 1 }));
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

  it('applies literal rules as bounded literal text, never as user-supplied regular expressions', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: '(.+)+$', replacement: '[SAFE]' }],
    });
    const result = sanitizeLogWithPolicy('prefix (.+)+$ suffix', policy);
    expect(result.text).toBe('prefix [SAFE] suffix');
    expect(result.changes).toBe(1);
  });

  it('fails closed when adjacent replacements recreate a configured sensitive literal', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      literalRules: [
        { value: 'LONGSECRET', replacement: '[REMOVED]' },
        { value: 'x', replacement: 'LONG' },
      ],
    });

    expect(() => sanitizeLogWithPolicy('xSECRET', policy)).toThrow(/could not be removed safely/i);
  });

  it('never emits configured literals when a fixed redaction marker collides', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      bodyMode: 'supported',
      literalRules: [{ value: 'REDACTED', replacement: '[MASK]' }],
    });
    expect(() => sanitizeLogWithPolicy('token=private-credential', policy)).toThrow(/could not be removed safely/i);

    const har = JSON.stringify({ log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [{
      request: { method: 'POST', url: 'https://example.test/', postData: { mimeType: 'application/json', text: '{"token":"private-credential"}' } },
      response: { status: 200, content: {} },
    }] } });
    const result = sanitizeHarWithPolicy(har, policy);

    expect(result.text).not.toContain('private-credential');
    expect(result.text).not.toContain('REDACTED');
    expect(JSON.parse(result.text).log.entries[0].request.postData.text).toContain('[[MASK]]');
  });

  it('applies mandatory credential redaction to custom replacement text', () => {
    const policy = validateRedactionPolicy({
      ...DEFAULT_REDACTION_POLICY,
      sensitiveKeys: [...DEFAULT_REDACTION_POLICY.sensitiveKeys, 'private_id'],
      literalRules: [
        { value: 'placeholder-token', replacement: 'token=LEAKED-BASELINE-CREDENTIAL' },
        { value: 'placeholder-custom', replacement: 'private_id=LEAKED-CUSTOM-CREDENTIAL' },
      ],
    });
    const result = sanitizeLogWithPolicy('placeholder-token placeholder-custom', policy);

    expect(result.text).not.toMatch(/LEAKED-BASELINE-CREDENTIAL|LEAKED-CUSTOM-CREDENTIAL/);
    expect(result.text).toContain('token=[REDACTED]');
    expect(result.text).toContain('private_id=[REDACTED]');
  });
});
