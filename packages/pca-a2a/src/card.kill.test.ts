import { describe, expect, it } from 'vitest';
import { generateKeyPair } from 'jose';
import { PCA_A2A_EXTENSION_URI, extendedAgentCard, issueSignedAgentCard, jcsBytes, validateAgentCard1, verifyAgentCard } from './index';

const text = (v: unknown): string => new TextDecoder().decode(jcsBytes(v));
const throwsMsg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return `${(e as Error).name}: ${(e as Error).message}`;
  }
  return 'NO THROW';
};
const nest = (n: number, wrap: (inner: unknown) => unknown): unknown => {
  let v: unknown = 1;
  for (let i = 0; i < n; i++) v = wrap(v);
  return v;
};

describe('jcsBytes', () => {
  it('writes sorted members, minimal escapes and ECMAScript numbers', () => {
    expect(text({ b: [1, 2.5, -0, true, null], a: 'x"y' })).toBe('{"a":"x\\"y","b":[1,2.5,0,true,null]}');
  });
  it('refuses values with no JSON form, with exact messages', () => {
    expect(throwsMsg(() => jcsBytes(Number.NaN))).toBe('TypeError: jcs: non-finite number');
    expect(throwsMsg(() => jcsBytes(Infinity))).toBe('TypeError: jcs: non-finite number');
    expect(throwsMsg(() => jcsBytes('a\ud800'))).toBe('TypeError: jcs: lone surrogate in string');
    expect(throwsMsg(() => jcsBytes({ ['a\ud800']: 1 }))).toBe('TypeError: jcs: lone surrogate in key');
    expect(throwsMsg(() => jcsBytes(undefined))).toBe('TypeError: jcs: unsupported type undefined');
    expect(throwsMsg(() => jcsBytes(() => 1))).toBe('TypeError: jcs: unsupported type function');
    expect(throwsMsg(() => jcsBytes(1n))).toBe('TypeError: jcs: unsupported type bigint');
    expect(throwsMsg(() => jcsBytes(Symbol('s')))).toBe('TypeError: jcs: unsupported type symbol');
    expect(throwsMsg(() => jcsBytes(new Date(0)))).toBe('TypeError: jcs: non-plain object');
    expect(throwsMsg(() => jcsBytes(new Map()))).toBe('TypeError: jcs: non-plain object');
  });
  it('accepts null-prototype objects', () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.k = 1;
    expect(text(o)).toBe('{"k":1}');
  });
  it('nesting is bounded at 64 containers, for arrays and for objects', () => {
    const arr = (inner: unknown) => [inner];
    const obj = (inner: unknown) => ({ k: inner });
    expect(throwsMsg(() => jcsBytes(nest(64, arr)))).toBe('NO THROW');
    expect(throwsMsg(() => jcsBytes(nest(65, arr)))).toBe('TypeError: jcs: nesting too deep');
    expect(throwsMsg(() => jcsBytes(nest(64, obj)))).toBe('NO THROW');
    expect(throwsMsg(() => jcsBytes(nest(65, obj)))).toBe('TypeError: jcs: nesting too deep');
  });
  it('a shared (non-cyclic) reference is fine, a cycle is refused', () => {
    const shared = { x: 1 };
    expect(text({ a: shared, b: shared, c: [shared, shared] })).toBe('{"a":{"x":1},"b":{"x":1},"c":[{"x":1},{"x":1}]}');
    const cyc: Record<string, unknown> = {};
    cyc.self = cyc;
    expect(throwsMsg(() => jcsBytes(cyc))).toBe('TypeError: jcs: cycle');
  });
});

describe('validateAgentCard1', () => {
  const valid = (): Record<string, unknown> => ({
    name: 'n',
    description: 'd',
    version: '1',
    supportedInterfaces: [{ url: 'u', protocolBinding: 'b', protocolVersion: 'v' }],
    capabilities: {},
    defaultInputModes: ['text'],
    defaultOutputModes: ['text'],
    skills: [],
  });
  const probs = (over: Record<string, unknown>): string[] => validateAgentCard1({ ...valid(), ...over });
  it('a minimal card is valid, and so is one with every optional member empty', () => {
    expect(validateAgentCard1(valid())).toEqual([]);
    expect(probs({ capabilities: { extensions: [] }, signatures: [], securityRequirements: [], securitySchemes: {} })).toEqual([]);
    expect(probs({ skills: [{ id: 'i', name: 'n', description: 'd', tags: [], examples: [], inputModes: [], outputModes: [] }] })).toEqual([]);
  });
  it('required members and their messages', () => {
    expect(validateAgentCard1(null)).toEqual(['$: the agent card must be an object']);
    expect(validateAgentCard1([])).toEqual(['$: the agent card must be an object']);
    expect(probs({ name: '' })).toEqual(['$.name: required non-empty string']);
    expect(probs({ description: 5 })).toEqual(['$.description: required non-empty string']);
    expect(probs({ version: undefined })).toEqual(['$.version: required non-empty string']);
    expect(probs({ documentationUrl: 5 })).toEqual(['$.documentationUrl: must be a string']);
    expect(probs({ iconUrl: 5 })).toEqual(['$.iconUrl: must be a string']);
    expect(probs({ capabilities: undefined })).toEqual(['$.capabilities: required object']);
    expect(probs({ defaultInputModes: undefined })).toEqual(['$.defaultInputModes: required array of strings']);
    expect(probs({ defaultOutputModes: undefined })).toEqual(['$.defaultOutputModes: required array of strings']);
    expect(probs({ defaultInputModes: [] })).toEqual(['$.defaultInputModes: must not be empty']);
    expect(probs({ defaultOutputModes: [] })).toEqual(['$.defaultOutputModes: must not be empty']);
    expect(probs({ defaultOutputModes: ['a', 5] })).toEqual(['$.defaultOutputModes: must be an array of strings']);
    expect(probs({ defaultInputModes: 'x' })).toEqual(['$.defaultInputModes: must be an array of strings']);
    expect(probs({ skills: undefined })).toEqual(['$.skills: required array']);
  });
  it('supportedInterfaces', () => {
    expect(probs({ supportedInterfaces: undefined })).toEqual(['$.supportedInterfaces: required array']);
    expect(probs({ supportedInterfaces: 'x' })).toEqual(['$.supportedInterfaces: must be an array']);
    expect(probs({ supportedInterfaces: [] })).toEqual(['$.supportedInterfaces: must not be empty']);
    expect(probs({ supportedInterfaces: [5] })).toEqual(['$.supportedInterfaces[0]: must be an object']);
    expect(probs({ supportedInterfaces: [{ url: 'u', protocolBinding: 'b', protocolVersion: 'v', tenant: 5 }] })).toEqual(['$.supportedInterfaces[0].tenant: must be a string']);
    expect(probs({ supportedInterfaces: [{}] })).toEqual([
      '$.supportedInterfaces[0].url: required non-empty string',
      '$.supportedInterfaces[0].protocolBinding: required non-empty string',
      '$.supportedInterfaces[0].protocolVersion: required non-empty string',
    ]);
  });
  it('provider, capabilities, security members', () => {
    expect(probs({ provider: 5 })).toEqual(['$.provider: must be an object']);
    expect(probs({ provider: {} })).toEqual(['$.provider.url: required non-empty string', '$.provider.organization: required non-empty string']);
    expect(probs({ provider: { url: 'u', organization: 'o' } })).toEqual([]);
    expect(probs({ capabilities: { streaming: 'x' } })).toEqual(['$.capabilities.streaming: must be a boolean']);
    expect(probs({ capabilities: { pushNotifications: 'x' } })).toEqual(['$.capabilities.pushNotifications: must be a boolean']);
    expect(probs({ capabilities: { extendedAgentCard: 'x' } })).toEqual(['$.capabilities.extendedAgentCard: must be a boolean']);
    expect(probs({ capabilities: { extensions: 'x' } })).toEqual(['$.capabilities.extensions: must be an array']);
    expect(probs({ capabilities: { extensions: [5] } })).toEqual(['$.capabilities.extensions[0]: must be an object']);
    expect(probs({ capabilities: { extensions: [{ uri: 5, description: 5, required: 'x', params: 5 }] } })).toEqual([
      '$.capabilities.extensions[0].uri: must be a string',
      '$.capabilities.extensions[0].description: must be a string',
      '$.capabilities.extensions[0].required: must be a boolean',
      '$.capabilities.extensions[0].params: must be an object',
    ]);
    expect(probs({ capabilities: { extensions: [{ uri: 'u', params: { a: 1 } }] } })).toEqual([]);
    expect(probs({ securitySchemes: 5 })).toEqual(['$.securitySchemes: must be an object']);
    expect(probs({ securityRequirements: 'x' })).toEqual(['$.securityRequirements: must be an array']);
  });
  it('skills and signatures', () => {
    const skill = { id: 'i', name: 'n', description: 'd', tags: [] };
    expect(probs({ skills: 'x' })).toEqual(['$.skills: must be an array']);
    expect(probs({ skills: [5] })).toEqual(['$.skills[0]: must be an object']);
    expect(probs({ skills: [{}] })).toEqual([
      '$.skills[0].id: required non-empty string',
      '$.skills[0].name: required non-empty string',
      '$.skills[0].description: required non-empty string',
      '$.skills[0].tags: required array of strings',
    ]);
    expect(probs({ skills: [{ ...skill, tags: [5] }] })).toEqual(['$.skills[0].tags: must be an array of strings']);
    expect(probs({ skills: [{ ...skill, examples: 'x', inputModes: [5], outputModes: 5 }] })).toEqual([
      '$.skills[0].examples: must be an array of strings',
      '$.skills[0].inputModes: must be an array of strings',
      '$.skills[0].outputModes: must be an array of strings',
    ]);
    expect(probs({ skills: [{ ...skill, securityRequirements: 'x' }] })).toEqual(['$.skills[0].securityRequirements: must be an array']);
    expect(probs({ skills: [{ ...skill, securityRequirements: [] }] })).toEqual([]);
    expect(probs({ signatures: 'x' })).toEqual(['$.signatures: must be an array']);
    expect(probs({ signatures: [5] })).toEqual(['$.signatures[0]: must be an object']);
    expect(probs({ signatures: [{}] })).toEqual(['$.signatures[0].protected: required non-empty string', '$.signatures[0].signature: required non-empty string']);
    expect(probs({ signatures: [{ protected: 'p', signature: 's', header: 5 }] })).toEqual(['$.signatures[0].header: must be an object']);
    expect(probs({ signatures: [{ protected: 'p', signature: 's', header: {} }] })).toEqual([]);
  });
});

describe('signed card schema errors', () => {
  it('issue and verify report every schema problem, joined with "; "', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA');
    const card = { name: 'n' } as never;
    const problems = validateAgentCard1(card);
    expect(problems.length).toBeGreaterThan(1);
    let err = '';
    try {
      await issueSignedAgentCard(card, privateKey, { schema: 'a2a-1.0' });
    } catch (e) {
      err = (e as Error).message;
    }
    expect(err).toBe(`issueSignedAgentCard: the card does not match the A2A 1.0 schema: ${problems.join('; ')}`);
    const signed = await issueSignedAgentCard(card, privateKey);
    expect(await verifyAgentCard(signed, { key: publicKey, schema: 'a2a-1.0' })).toEqual({
      ok: false,
      reason: `agent card does not match the A2A 1.0 schema: ${validateAgentCard1(signed).join('; ')}`,
    });
  });
  it('the a2a-1.0 profile needs a non-empty kid', async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    for (const kid of [undefined, '']) {
      let err = '';
      try {
        await issueSignedAgentCard({ name: 'n' } as never, privateKey, { profile: 'a2a-1.0', ...(kid !== undefined ? { kid } : {}) });
      } catch (e) {
        err = (e as Error).message;
      }
      expect(err).toBe("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
    }
  });
  it('a protected header that is not JSON fails in the header check, not as a missing payload', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const bad = Buffer.from('notjson').toString('base64url');
    const sig = Buffer.alloc(64, 1).toString('base64url');
    const r = await verifyAgentCard({ name: 'n', signatures: [{ protected: bad, signature: sig }] } as never, { key: publicKey });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('signature 0 did not verify:');
    expect(r.reason).not.toContain('Payload missing');
  });
});

describe('extendedAgentCard', () => {
  const pub = (extra: Record<string, unknown> = {}) => ({
    name: 'n',
    capabilities: { extensions: [{ uri: PCA_A2A_EXTENSION_URI, params: { aud: 'a' } }, { uri: 'https://other.example/ext', params: { keep: 1 } }] },
    skills: [{ id: 'pub' }],
    signatures: [{ protected: 'p', signature: 's' }],
    ...extra,
  }) as never;
  const env = (verb: string, status: 'autonomous' | 'needs-approval' | 'denied', policyDigest = 'D') => ({ verb, status, policyDigest });
  const o = (over: Record<string, unknown> = {}) => ({ authenticated: true, hiddenSkills: [], envelopes: [], ...over }) as never;

  it('requires an authenticated caller and one policy', () => {
    expect(() => extendedAgentCard(pub(), o({ authenticated: false }))).toThrow('extendedAgentCard: the caller must be authenticated (A2A 13.3)');
    expect(() => extendedAgentCard(pub(), o({ authenticated: 1 }))).toThrow('extendedAgentCard: the caller must be authenticated (A2A 13.3)');
    expect(() => extendedAgentCard(pub(), o({ envelopes: [env('a', 'autonomous', 'D1'), env('b', 'autonomous', 'D2')] }))).toThrow(
      new RangeError('extendedAgentCard: envelopes were computed against different policies'),
    );
  });
  it('reveals autonomous and needs-approval skills with a status tag, keeps existing tags, and hides the rest', () => {
    const hidden = [
      { id: 's1', tags: ['pca-verb:read', 'x'] },
      { id: 's2', tags: ['pca-verb:write'] },
      { id: 's3', tags: ['pca-verb:nuke'] },
      { id: 's4', tags: ['pca-verb:ghost'] },
      { id: 's5', tags: [5, 'pca-verb:read'] },
      { id: 's6', tags: ['x', 'pca-verb:write'] },
      { id: 's7' },
    ];
    const out = extendedAgentCard(pub(), o({ hiddenSkills: hidden, envelopes: [env('read', 'autonomous'), env('write', 'needs-approval'), env('nuke', 'denied')] })) as unknown as { skills: unknown[]; signatures?: unknown };
    expect(out.skills).toEqual([
      { id: 'pub' },
      { id: 's1', tags: ['pca-verb:read', 'x', 'pca:autonomous'] },
      { id: 's2', tags: ['pca-verb:write', 'pca:needs-approval'] },
      { id: 's5', tags: [5, 'pca-verb:read', 'pca:autonomous'] },
      { id: 's6', tags: ['x', 'pca-verb:write', 'pca:needs-approval'] },
    ]);
    expect('signatures' in out).toBe(false);
  });
  it('a custom verb mapping can reveal a skill that has no tags, which then carries only the status tag', () => {
    const out = extendedAgentCard(pub(), o({ hiddenSkills: [{ id: 'q' }], envelopes: [env('v', 'autonomous')], verbOf: () => 'v' })) as unknown as { skills: unknown[] };
    expect(out.skills[1]).toEqual({ id: 'q', tags: ['pca:autonomous'] });
  });
  it('records the policy digest only on the PCA extension, and only when there is one', () => {
    const withEnv = extendedAgentCard(pub(), o({ envelopes: [env('a', 'autonomous', 'DIG')] })) as unknown as { capabilities: { extensions: Array<{ uri: string; params: Record<string, unknown> }> } };
    expect(withEnv.capabilities.extensions[0]!.params).toEqual({ aud: 'a', policy_digest: 'DIG' });
    expect(withEnv.capabilities.extensions[1]).toEqual({ uri: 'https://other.example/ext', params: { keep: 1 } });
    const none = extendedAgentCard(pub(), o()) as unknown as { capabilities: { extensions: Array<{ params: Record<string, unknown> }> } };
    expect(Object.keys(none.capabilities.extensions[0]!.params)).toEqual(['aud']);
  });
  it('a card without extensions or skills yields empty lists', () => {
    const out = extendedAgentCard({ name: 'n' } as never, o({ envelopes: [env('a', 'autonomous')] })) as unknown as { capabilities: { extensions: unknown[] }; skills: unknown[] };
    expect(out.capabilities.extensions).toEqual([]);
    expect(out.skills).toEqual([]);
  });
});
