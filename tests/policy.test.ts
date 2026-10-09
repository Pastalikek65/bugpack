import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';

async function policyApi() {
  try {
    return await import('../src/core/policy');
  } catch {
    throw new Error('The public redaction policy API is not implemented yet');
  }
}

describe('redaction policy contract', () => {
  it('exports a round-trippable default policy with mandatory credential keys', async () => {
    const api = await policyApi();
    const encoded = api.exportRedactionPolicy(api.DEFAULT_REDACTION_POLICY);
    const parsed = api.parseRedactionPolicy(encoded);

    expect(parsed).toEqual(api.DEFAULT_REDACTION_POLICY);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.bodyMode).toBe('omit');
    expect(parsed.sensitiveKeys).toContain('password');
    expect(parsed.sensitiveKeys).toContain('authorization');
    expect(parsed.literalRules).toEqual([]);
    expect(api.redactionPolicyFingerprint(parsed)).toBe(
      createHash('sha256').update(JSON.stringify(parsed), 'utf8').digest('hex'),
    );
  });

  it('rejects unknown policy versions and fields instead of silently ignoring them', async () => {
    const api = await policyApi();
    const base = api.DEFAULT_REDACTION_POLICY;
    expect(() => api.validateRedactionPolicy({ ...base, schemaVersion: 2 })).toThrow(/unsupported.*version/i);
    expect(() => api.validateRedactionPolicy({ ...base, allowUnsafe: true })).toThrow(/unknown|unsupported.*field/i);
    expect(() => api.validateRedactionPolicy({ ...base, bodyMode: 'anything' })).toThrow(/body mode/i);
  });

  it('rejects a policy that removes baseline credential keys', async () => {
    const api = await policyApi();
    const weakened = {
      ...api.DEFAULT_REDACTION_POLICY,
      sensitiveKeys: api.DEFAULT_REDACTION_POLICY.sensitiveKeys.filter((key) => key !== 'password'),
    };
    expect(() => api.validateRedactionPolicy(weakened)).toThrow(/mandatory|baseline|credential/i);
  });

  it('rejects duplicate keys, prototype fields, and malformed JSON rules', async () => {
    const api = await policyApi();
    const duplicate = '{"schemaVersion":1,"schemaVersion":1}';
    expect(() => api.parseRedactionPolicy(duplicate)).toThrow(/duplicate/i);
    expect(() => api.parseRedactionPolicy('{"schemaVersion":1,"__proto__":{}}')).toThrow(/prototype-sensitive/i);
    expect(() => api.validateRedactionPolicy({
      ...api.DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: 'secret', replacement: '[SAFE]', pattern: '.*' }],
    })).toThrow(/unknown|unsupported.*field/i);
  });

  it('bounds literal rules and treats regex-looking text as a literal value', async () => {
    const api = await policyApi();
    const policy = api.validateRedactionPolicy({
      ...api.DEFAULT_REDACTION_POLICY,
      literalRules: [{ value: '(.+)+$', replacement: '[SAFE]' }],
    });
    expect(policy.literalRules).toEqual([{ value: '(.+)+$', replacement: '[SAFE]' }]);
    expect(() => api.validateRedactionPolicy({
      ...api.DEFAULT_REDACTION_POLICY,
      literalRules: Array.from({ length: 129 }, (_, index) => ({ value: `value-${index}`, replacement: '[SAFE]' })),
    })).toThrow(/limit|too many/i);
  });

  it('canonicalizes Unicode literals by stable code-unit order', async () => {
    const api = await policyApi();
    const policy = api.validateRedactionPolicy({
      ...api.DEFAULT_REDACTION_POLICY,
      literalRules: [
        { value: 'a', replacement: '[LOWER]' },
        { value: 'Z', replacement: '[UPPER]' },
      ],
    });
    expect(policy.literalRules.map((rule) => rule.value)).toEqual(['Z', 'a']);
  });

  it('rejects sparse, accessor-backed, or augmented policy arrays', async () => {
    const api = await policyApi();
    const sparseRules = new Array(1);
    expect(() => api.validateRedactionPolicy({ ...api.DEFAULT_REDACTION_POLICY, literalRules: sparseRules })).toThrow(/holes|array/i);

    const accessorKeys = [...api.DEFAULT_REDACTION_POLICY.sensitiveKeys];
    Object.defineProperty(accessorKeys, '0', { get: () => 'password', configurable: true });
    expect(() => api.validateRedactionPolicy({ ...api.DEFAULT_REDACTION_POLICY, sensitiveKeys: accessorKeys })).toThrow(/accessors/i);

    const extraRules: unknown[] = [];
    Object.defineProperty(extraRules, 'extra', { value: 'ignored' });
    expect(() => api.validateRedactionPolicy({ ...api.DEFAULT_REDACTION_POLICY, literalRules: extraRules })).toThrow(/extra array properties/i);
  });
});
