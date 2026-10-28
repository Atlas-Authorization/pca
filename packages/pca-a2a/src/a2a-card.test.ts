import { describe, expect, it } from 'vitest';
import { compactVerify, generateKeyPair as joseGenerateKeyPair } from 'jose';
import { canonicalBytes } from '@atlasauth/pca';
import { jcsBytes, validateAgentCard1, issueSignedAgentCard, verifyAgentCard } from './index';

const text = (v: unknown): string => new TextDecoder().decode(jcsBytes(v));

/** An independent reference: sort keys by an explicit UTF-16 code unit comparison, serialize with JSON.stringify per value. */
function reference(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(reference).join(',')}]`;
  const o = v as Record<string, unknown>;
  const cmp = (a: string, b: string): number => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a.charCodeAt(i) !== b.charCodeAt(i)) return a.charCodeAt(i) - b.charCodeAt(i);
    return a.length - b.length;
  };
  return `{${Object.keys(o).sort(cmp).map((k) => `${JSON.stringify(k)}:${reference(o[k])}`).join(',')}}`;
}

describe('RFC 8785 (JCS)', () => {
  it('section 3.2.2: the published example', () => {
    const input = JSON.parse(String.raw`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000F\u000aA'B"\\\\"/","literals":[null,true,false]}`);
    const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
    expect(text(input)).toBe(expected);
  });
  it('section 3.2.3: members sort by UTF-16 code units (the emoji sorts before U+FB33)', () => {
    const input = JSON.parse(String.raw`{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}`);
    expect(Object.keys(JSON.parse(text(input)))).toEqual(['\r', '1', '\u0080', 'ö', '€', '\u{1F600}', 'דּ']);
  });
  it('PCA canonical JSON orders those keys by UTF-8 bytes instead, so it is NOT JCS for such keys (why cards use JCS)', () => {
    const o = { 'דּ': 1, '\u{1F600}': 2 };
    expect(Object.keys(JSON.parse(text(o)))).toEqual(['\u{1F600}', 'דּ']);
    expect(Object.keys(JSON.parse(new TextDecoder().decode(canonicalBytes(o))))).toEqual(['דּ', '\u{1F600}']);
  });
  it('agrees with an independent reference on a generated corpus', () => {
    let seed = 7;
    const rnd = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32);
    const alphabet = ['a', 'B', '0', 'é', '€', 'דּ', '￮', '\u{1F600}', '\u{10FFFF}', '"', '\\', '\n', '\u0000', '\u007f', ' '];
    const str = (): string => Array.from({ length: Math.floor(rnd() * 5) }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');
    const gen = (d: number): unknown => {
      const r = rnd();
      if (d > 3 || r < 0.2) return [str(), Math.floor(rnd() * 1e6) / 8, rnd() < 0.5, null, 1e21, 5e-7, -0][Math.floor(rnd() * 7)];
      if (r < 0.5) return Array.from({ length: Math.floor(rnd() * 4) }, () => gen(d + 1));
      return Object.fromEntries(Array.from({ length: Math.floor(rnd() * 5) }, () => [str(), gen(d + 1)]));
    };
    for (let i = 0; i < 300; i++) {
      const v = gen(0);
      expect(text(v), JSON.stringify(v)).toBe(reference(v));
    }
  });
  it('writes -0 as 0, large and small numbers in ECMAScript form, and keeps U+2028 and U+007F raw', () => {
    expect(text([-0, 1e21, 5e-7, 1.5, 100])).toBe('[0,1e+21,5e-7,1.5,100]');
    expect(text(' \u007f')).toBe('" \u007f"');
  });
  it.each([
    ['NaN', Number.NaN], ['Infinity', Infinity], ['undefined', undefined], ['a function', () => 1], ['a bigint', 1n], ['a symbol', Symbol('x')],
    ['a lone high surrogate', '\ud800'], ['a lone low surrogate', 'x\udc00'], ['a Date', new Date(0)], ['a Map', new Map()],
  ])('refuses %s', (_n, v) => {
    expect(() => jcsBytes({ v })).toThrow(TypeError);
  });
  it('refuses a lone surrogate in a key, a cycle and excess nesting', () => {
    expect(() => jcsBytes({ '\ud800': 1 })).toThrow('lone surrogate in key');
    const c: Record<string, unknown> = {};
    c.self = c;
    expect(() => jcsBytes(c)).toThrow('cycle');
    let deep: unknown = 1;
    for (let i = 0; i < 70; i++) deep = [deep];
    expect(() => jcsBytes(deep)).toThrow('nesting too deep');
    expect(() => jcsBytes(Object.create({ x: 1 }))).toThrow('non-plain object');
  });
});

const goodCard = () => ({
  name: 'Buyer', description: 'Buys things', version: '1.0.0',
  supportedInterfaces: [{ url: 'https://a.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true, extensions: [{ uri: 'https://x.example/ext', required: false, params: { a: 1 } }] },
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's1', name: 'Skill', description: 'does a thing', tags: ['t'] }],
});

describe('validateAgentCard1 (A2A 1.0 AgentCard message)', () => {
  it('accepts a complete card, with and without optional members and unknown extension members', () => {
    expect(validateAgentCard1(goodCard())).toEqual([]);
    expect(validateAgentCard1({ ...goodCard(), provider: { url: 'https://p.example', organization: 'P' }, documentationUrl: 'https://d', iconUrl: 'https://i', securitySchemes: {}, securityRequirements: [], pcaPassport: { id: 'pp' }, signatures: [{ protected: 'e30', signature: 'AA', header: {} }] })).toEqual([]);
  });
  it.each(['name', 'description', 'version', 'supportedInterfaces', 'capabilities', 'defaultInputModes', 'defaultOutputModes', 'skills'])('a missing %s is reported with its path', (k) => {
    const c = goodCard() as Record<string, unknown>;
    delete c[k];
    const p = validateAgentCard1(c);
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(new RegExp(`^\\$\\.${k}: required`));
  });
  it('reports each wrong type with its exact path', () => {
    const c = goodCard();
    const bad = { ...c, name: '', version: 1, supportedInterfaces: [{ url: 'u', protocolBinding: 'x' }], capabilities: { streaming: 'yes', extensions: [{ required: 1 }] }, defaultInputModes: [], skills: [{ id: 's', name: 'n', description: 'd', tags: 'x' }, 5], signatures: [{ protected: 'a' }] };
    expect(validateAgentCard1(bad).sort()).toEqual([
      '$.capabilities.extensions[0].required: must be a boolean',
      '$.capabilities.streaming: must be a boolean',
      '$.defaultInputModes: must not be empty',
      '$.name: required non-empty string',
      '$.signatures[0].signature: required non-empty string',
      '$.skills[0].tags: must be an array of strings',
      '$.skills[1]: must be an object',
      '$.supportedInterfaces[0].protocolVersion: required non-empty string',
      '$.version: required non-empty string',
    ].sort());
  });
  it('a non-object is refused', () => {
    for (const v of [null, [], 'x', 1, undefined]) expect(validateAgentCard1(v)).toEqual(['$: the agent card must be an object']);
  });
});

describe('the schema option', () => {
  it('issue refuses an invalid card under schema a2a-1.0 and signs a valid one; verify enforces it too', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    await expect(issueSignedAgentCard({ name: 'a' } as never, privateKey, { kid: 'k', profile: 'a2a-1.0', schema: 'a2a-1.0' })).rejects.toThrow(/does not match the A2A 1.0 schema: \$\.description/);
    const signed = await issueSignedAgentCard(goodCard() as never, privateKey, { kid: 'k', profile: 'a2a-1.0', schema: 'a2a-1.0' });
    expect((await verifyAgentCard(signed, { key: publicKey, schema: 'a2a-1.0' })).ok).toBe(true);
    const minimal = await issueSignedAgentCard({ name: 'a' } as never, privateKey, { kid: 'k', profile: 'a2a-1.0' });
    expect((await verifyAgentCard(minimal, { key: publicKey })).ok).toBe(true);
    const r = await verifyAgentCard(minimal, { key: publicKey, schema: 'a2a-1.0' });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^agent card does not match the A2A 1.0 schema: /);
  });
  it('a card whose keys differ in UTF-16 vs UTF-8 order signs over the JCS bytes (a JCS verifier would accept it)', async () => {
    const { publicKey, privateKey } = await joseGenerateKeyPair('EdDSA');
    const card = { ...goodCard(), 'דּ': 1, '\u{1F600}': 2 };
    const signed = await issueSignedAgentCard(card as never, privateKey, { kid: 'k', profile: 'a2a-1.0' });
    expect((await verifyAgentCard(signed, { key: publicKey })).ok).toBe(true);
    const { signatures, ...rest } = signed as unknown as { signatures: { protected: string; signature: string }[] };
    // an independent check: rebuild the JWS signing input by hand from the JCS bytes and verify with jose alone
    const sig = signatures[0]!;
    const compact = `${sig.protected}.${Buffer.from(jcsBytes(rest)).toString('base64url')}.${sig.signature}`;
    await expect(compactVerify(compact, publicKey)).resolves.toBeDefined();
    expect(JSON.parse(Buffer.from(sig.protected, 'base64url').toString('utf8')).typ).toBe('JOSE');
    const pcaOrder = `${sig.protected}.${Buffer.from(canonicalBytes(rest)).toString('base64url')}.${sig.signature}`;
    await expect(compactVerify(pcaOrder, publicKey)).rejects.toBeDefined();
  });
});
