import { describe, expect, it } from 'vitest';
import { generateKeyPair } from 'jose';
import { issueSignedAgentCard, jcsBytes, toRegistryEntry, validateAgentCard1, verifyAgentCard } from './index';

const text = (v: unknown): string => new TextDecoder().decode(jcsBytes(v));

function nest(levels: number, kind: 'array' | 'object'): unknown {
  let v: unknown = kind === 'array' ? [] : {};
  for (let i = 1; i < levels; i++) v = kind === 'array' ? [v] : { a: v };
  return v;
}

describe('jcs refusals carry their reason', () => {
  it('non-finite numbers', () => {
    expect(() => jcsBytes(Number.NaN)).toThrow('jcs: non-finite number');
    expect(() => jcsBytes([Number.POSITIVE_INFINITY])).toThrow('jcs: non-finite number');
  });
  it('lone surrogates in a string and in a key', () => {
    expect(() => jcsBytes('\uD800')).toThrow('jcs: lone surrogate in string');
    expect(() => jcsBytes({ '\uDC00': 1 })).toThrow('jcs: lone surrogate in key');
    expect(text('\u{1F600}')).toBe('"\u{1F600}"');
  });
  it('types with no JSON form', () => {
    expect(() => jcsBytes(undefined)).toThrow('jcs: unsupported type undefined');
    expect(() => jcsBytes(() => 1)).toThrow('jcs: unsupported type function');
    expect(() => jcsBytes(1n)).toThrow('jcs: unsupported type bigint');
    expect(() => jcsBytes(Symbol('s'))).toThrow('jcs: unsupported type symbol');
  });
  it('non-plain objects and cycles', () => {
    expect(() => jcsBytes(new Map())).toThrow('jcs: non-plain object');
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => jcsBytes(a)).toThrow('jcs: cycle');
  });
  it('a null-prototype object is plain', () => {
    expect(text(Object.assign(Object.create(null), { b: 1, a: 2 }))).toBe('{"a":2,"b":1}');
  });
  it('the same object may appear twice as siblings (it is not a cycle)', () => {
    const shared = { k: 1 };
    expect(text([shared, shared])).toBe('[{"k":1},{"k":1}]');
    expect(text({ x: shared, y: shared })).toBe('{"x":{"k":1},"y":{"k":1}}');
  });
  it('nesting: 64 levels pass, 65 throw (arrays and objects)', () => {
    expect(() => jcsBytes(nest(64, 'array'))).not.toThrow();
    expect(() => jcsBytes(nest(65, 'array'))).toThrow('jcs: nesting too deep');
    expect(() => jcsBytes(nest(64, 'object'))).not.toThrow();
    expect(() => jcsBytes(nest(65, 'object'))).toThrow('jcs: nesting too deep');
  });
});

function goodCard(): Record<string, unknown> {
  return {
    name: 'n',
    description: 'd',
    version: '1',
    supportedInterfaces: [{ url: 'https://a.example', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: {},
    defaultInputModes: ['text'],
    defaultOutputModes: ['text'],
    skills: [{ id: 's', name: 'sn', description: 'sd', tags: [] }],
  };
}
const withCard = (patch: (c: Record<string, any>) => void): string[] => {
  const c = goodCard() as Record<string, any>;
  patch(c);
  return validateAgentCard1(c);
};

describe('validateAgentCard1 exact problems', () => {
  it('a minimal card is valid, with empty optional arrays accepted', () => {
    expect(validateAgentCard1(goodCard())).toEqual([]);
    expect(withCard((c) => { c.capabilities = { extensions: [] }; c.signatures = []; c.skills[0] = { id: 's', name: 'n', description: 'd', tags: ['t'], examples: [], inputModes: [], outputModes: [] }; })).toEqual([]);
    expect(withCard((c) => { c.skills = []; })).toEqual([]);
  });
  it('optional strings', () => {
    expect(withCard((c) => { c.documentationUrl = 5; })).toEqual(['$.documentationUrl: must be a string']);
    expect(withCard((c) => { c.iconUrl = 5; })).toEqual(['$.iconUrl: must be a string']);
    expect(withCard((c) => { c.supportedInterfaces[0].tenant = 5; })).toEqual(['$.supportedInterfaces[0].tenant: must be a string']);
    expect(withCard((c) => { c.documentationUrl = 'u'; c.iconUrl = 'i'; c.supportedInterfaces[0].tenant = 't'; })).toEqual([]);
  });
  it('supportedInterfaces', () => {
    expect(withCard((c) => { delete c.supportedInterfaces; })).toEqual(['$.supportedInterfaces: required array']);
    expect(withCard((c) => { c.supportedInterfaces = []; })).toEqual(['$.supportedInterfaces: must not be empty']);
    expect(withCard((c) => { c.supportedInterfaces = 'x'; })).toEqual(['$.supportedInterfaces: must be an array']);
    expect(withCard((c) => { c.supportedInterfaces = [1]; })).toEqual(['$.supportedInterfaces[0]: must be an object']);
  });
  it('provider', () => {
    expect(withCard((c) => { c.provider = 5; })).toEqual(['$.provider: must be an object']);
    expect(withCard((c) => { c.provider = []; })).toEqual(['$.provider: must be an object']);
    expect(withCard((c) => { c.provider = {}; })).toEqual(['$.provider.url: required non-empty string', '$.provider.organization: required non-empty string']);
    expect(withCard((c) => { c.provider = { url: 'u', organization: 'o' }; })).toEqual([]);
  });
  it('capabilities', () => {
    expect(withCard((c) => { delete c.capabilities; })).toEqual(['$.capabilities: required object']);
    expect(withCard((c) => { c.capabilities = { streaming: 1 }; })).toEqual(['$.capabilities.streaming: must be a boolean']);
    expect(withCard((c) => { c.capabilities = { pushNotifications: 'y' }; })).toEqual(['$.capabilities.pushNotifications: must be a boolean']);
    expect(withCard((c) => { c.capabilities = { extendedAgentCard: 'y' }; })).toEqual(['$.capabilities.extendedAgentCard: must be a boolean']);
    expect(withCard((c) => { c.capabilities = { streaming: true, pushNotifications: false, extendedAgentCard: true }; })).toEqual([]);
    expect(withCard((c) => { c.capabilities = { extensions: 'x' }; })).toEqual(['$.capabilities.extensions: must be an array']);
    expect(withCard((c) => { c.capabilities = { extensions: [{ uri: 1, description: 2, required: 3, params: 4 }] }; })).toEqual([
      '$.capabilities.extensions[0].uri: must be a string',
      '$.capabilities.extensions[0].description: must be a string',
      '$.capabilities.extensions[0].required: must be a boolean',
      '$.capabilities.extensions[0].params: must be an object',
    ]);
    expect(withCard((c) => { c.capabilities = { extensions: [{ params: [] }] }; })).toEqual(['$.capabilities.extensions[0].params: must be an object']);
    expect(withCard((c) => { c.capabilities = { extensions: [{ uri: 'u', description: 'd', required: true, params: {} }] }; })).toEqual([]);
  });
  it('security members', () => {
    expect(withCard((c) => { c.securitySchemes = 5; })).toEqual(['$.securitySchemes: must be an object']);
    expect(withCard((c) => { c.securityRequirements = 'x'; })).toEqual(['$.securityRequirements: must be an array']);
    expect(withCard((c) => { c.securitySchemes = {}; c.securityRequirements = []; })).toEqual([]);
  });
  it('input and output modes', () => {
    expect(withCard((c) => { delete c.defaultInputModes; })).toEqual(['$.defaultInputModes: required array of strings']);
    expect(withCard((c) => { delete c.defaultOutputModes; })).toEqual(['$.defaultOutputModes: required array of strings']);
    expect(withCard((c) => { c.defaultInputModes = []; })).toEqual(['$.defaultInputModes: must not be empty']);
    expect(withCard((c) => { c.defaultOutputModes = []; })).toEqual(['$.defaultOutputModes: must not be empty']);
    expect(withCard((c) => { c.defaultOutputModes = [1]; })).toEqual(['$.defaultOutputModes: must be an array of strings']);
  });
  it('skills', () => {
    expect(withCard((c) => { delete c.skills; })).toEqual(['$.skills: required array']);
    expect(withCard((c) => { delete c.skills[0].tags; })).toEqual(['$.skills[0].tags: required array of strings']);
    expect(withCard((c) => { c.skills[0].tags = [1]; })).toEqual(['$.skills[0].tags: must be an array of strings']);
    expect(withCard((c) => { c.skills[0].examples = 'x'; })).toEqual(['$.skills[0].examples: must be an array of strings']);
    expect(withCard((c) => { c.skills[0].inputModes = [1]; })).toEqual(['$.skills[0].inputModes: must be an array of strings']);
    expect(withCard((c) => { c.skills[0].outputModes = {}; })).toEqual(['$.skills[0].outputModes: must be an array of strings']);
    expect(withCard((c) => { c.skills[0].securityRequirements = 'x'; })).toEqual(['$.skills[0].securityRequirements: must be an array']);
    expect(withCard((c) => { c.skills[0].securityRequirements = []; c.skills[0].examples = ['e']; })).toEqual([]);
  });
  it('signatures', () => {
    expect(withCard((c) => { c.signatures = [{}]; })).toEqual(['$.signatures[0].protected: required non-empty string', '$.signatures[0].signature: required non-empty string']);
    expect(withCard((c) => { c.signatures = [{ protected: 'p', signature: 's', header: 5 }]; })).toEqual(['$.signatures[0].header: must be an object']);
    expect(withCard((c) => { c.signatures = [{ protected: 'p', signature: 's', header: {} }]; })).toEqual([]);
  });
});

describe('agent card sign and verify guards', () => {
  it('issue joins every schema problem with "; "', async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    const card = { name: 'a' } as never;
    const problems = validateAgentCard1(card);
    expect(problems.length).toBeGreaterThan(1);
    await expect(issueSignedAgentCard(card, privateKey, { schema: 'a2a-1.0' })).rejects.toThrow(`issueSignedAgentCard: the card does not match the A2A 1.0 schema: ${problems.join('; ')}`);
  });
  it('verify joins every schema problem with "; "', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    const card = { name: 'a', signatures: [{ protected: 'p', signature: 's' }] } as never;
    const problems = validateAgentCard1(card);
    const r = await verifyAgentCard(card, { key: publicKey, schema: 'a2a-1.0' });
    expect(r).toEqual({ ok: false, reason: `agent card does not match the A2A 1.0 schema: ${problems.join('; ')}` });
  });
  it('an empty kid is refused under the a2a-1.0 profile', async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    await expect(issueSignedAgentCard({ name: 'a' }, privateKey, { profile: 'a2a-1.0', kid: '' })).rejects.toThrow("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
  });
  it('verify refuses a non-object card as "not an object"', async () => {
    const { publicKey } = await generateKeyPair('EdDSA');
    expect(await verifyAgentCard('x' as never, { key: publicKey })).toEqual({ ok: false, reason: 'agent card is not an object' });
    expect(await verifyAgentCard(null as never, { key: publicKey })).toEqual({ ok: false, reason: 'agent card is not an object' });
  });
});

describe('toRegistryEntry with an unparsable service url', () => {
  it('leaves agentCardUrl out', () => {
    const facts = { '@context': [], id: 'did:x', type: 'AgentFacts', selfAsserted: {}, attestations: [] } as never;
    const e = toRegistryEntry({ name: 'n', url: 'not a url' }, facts);
    expect('agentCardUrl' in e).toBe(false);
    expect(e.url).toBe('not a url');
    expect(toRegistryEntry({ name: 'n', url: 'https://h.example/base' }, facts).agentCardUrl).toBe('https://h.example/.well-known/agent-card.json');
  });
});
