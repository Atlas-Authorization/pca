/** Mutation kills for attributes.ts, bls.ts codecs, pca.ts reasons and aead/wire remainders. */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, type Capability, b64u, generateKeyPair, mintGrant } from '@atlasauth/pca';
import { Attr, capabilityAttributes } from './attributes';
import { decryptWithCapability, encryptToolPayload } from './pca';
import { encryptForPolicy, keygenForAttributes, setup } from './abe';
import { g1FromBytes, g1ToBytes, g2FromBytes, g2ToBytes, G1_BASE, G2_BASE, gtFromBytes, gtToBytes, pairing, hashAttrToG1, bytesToScalar, scalarToBytes, R } from './bls';
import { open, seal } from './aead';
import { isPosInt, unb64u } from './wire';

const Fp12 = bls12_381.fields.Fp12;

const P = generateKeyPair();
const mint = (preds: unknown[], caveats: unknown[] = [], holder = 'hold') =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder, goal: 'g', envelope: { predicates: preds as never, caveats: caveats as never, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const sorted = (s: Set<string>) => [...s].sort();

describe('capabilityAttributes', () => {
  it('single predicate yields act/verb/resource; several yield only act attributes', () => {
    const one = capabilityAttributes(mint([{ verb: 'read', resource: 'doc' }]));
    expect(sorted(one)).toEqual(sorted(new Set([Attr.holder('hold'), Attr.act('read', 'doc'), Attr.verb('read'), Attr.resource('doc')])));
    const two = capabilityAttributes(mint([{ verb: 'read', resource: 'a' }, { verb: ['w', 'x'], resource: 'b' }]));
    expect(sorted(two)).toEqual(sorted(new Set([Attr.holder('hold'), Attr.act('read', 'a'), Attr.act('w', 'b'), Attr.act('x', 'b')])));
  });
  it('verb forms and resource type', () => {
    expect(capabilityAttributes(mint([{ verb: ['r', 5], resource: 'd' }])).has(Attr.verb('r'))).toBe(true);
    expect(capabilityAttributes(mint([{ verb: ['r', 5], resource: 'd' }])).size).toBe(4);
    const noRes = capabilityAttributes(mint([{ verb: 'r', resource: 5 }]));
    expect(noRes.has(Attr.verb('r'))).toBe(true);
    expect([...noRes].some((a) => a.startsWith('resource:') || a.startsWith('act:'))).toBe(false);
    expect([...capabilityAttributes(mint([{ verb: 5, resource: 'd' }]))].some((a) => a.startsWith('verb:') || a.startsWith('act:'))).toBe(false);
    expect(capabilityAttributes(mint([null, 'x', { verb: 'r', resource: 'd' }] as never)).has(Attr.verb('r'))).toBe(true);
  });
  it('scope caveats on roots, including bad shapes', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    const withCv = { ...cap, caveats: [...cap.caveats, { type: 'scope', value: 's1' }, { type: 'scope', value: 5 }, { type: 'scopes', values: ['s2', 7] }, { type: 'scopes', values: 'x' }, { type: 'other', value: 's3' }] } as Capability;
    const a = capabilityAttributes(withCv);
    expect(a.has(Attr.scope('s1')) && a.has(Attr.scope('s2'))).toBe(true);
    expect([...a].filter((x) => x.startsWith('scope:')).length).toBe(2);
  });
  it('holder: absent or empty yields no holder attribute', () => {
    expect(capabilityAttributes({ ...mint([]), holder: '' } as Capability).has('holder:')).toBe(false);
    expect([...capabilityAttributes({ ...mint([]), holder: 5 } as never)].some((x) => x.startsWith('holder:'))).toBe(false);
  });
  it('a chain must end in the capability and verify', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    const ok = capabilityAttributes(cap, { chain: [cap], principal: b64u(P.publicKey) });
    expect(ok.has(Attr.verb('r'))).toBe(true);
    expect(capabilityAttributes(cap, { chain: [] }).size).toBe(0);
    expect(capabilityAttributes(cap, { chain: [{ ...cap, id: 'other' }] }).size).toBe(0);
    expect(capabilityAttributes(cap, { chain: [cap], principal: 'wrong' }).size).toBe(0);
  });
  it('a child capability without a chain contributes only its holder', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    const child = { ...cap, parent: 'p' } as Capability;
    expect(sorted(capabilityAttributes(child))).toEqual([Attr.holder('hold')]);
  });
});

describe('bls codecs', () => {
  it('points: canonical only; identity and garbage refused', () => {
    const g1 = g1ToBytes(G1_BASE), g2 = g2ToBytes(G2_BASE);
    expect(g1FromBytes(g1)).not.toBeNull(); expect(g2FromBytes(g2)).not.toBeNull();
    const ident1 = new Uint8Array(48); ident1[0] = 0xc0; const ident2 = new Uint8Array(96); ident2[0] = 0xc0;
    expect(g1FromBytes(ident1)).toBeNull(); expect(g2FromBytes(ident2)).toBeNull();
    expect(g1FromBytes(new Uint8Array(48).fill(1))).toBeNull(); expect(g2FromBytes(new Uint8Array(96).fill(1))).toBeNull();
    const uncompressed = G1_BASE.toRawBytes(false);
    expect(g1FromBytes(uncompressed)).toBeNull();
    expect(g1FromBytes(g1.subarray(0, 47))).toBeNull();
  });
  it('GT elements: length, identity, subgroup, canonical', () => {
    const e = pairing(G1_BASE, G2_BASE);
    const b = gtToBytes(e);
    expect(gtFromBytes(b)).not.toBeNull();
    expect(gtFromBytes(b.subarray(0, 575))).toBeNull();
    expect(gtFromBytes(new Uint8Array(577))).toBeNull();
    // Fp12 ONE serialises with the constant coefficient FIRST: a 1 in byte 47, zeros elsewhere. It is in the order-R
    // subgroup (ONE^R == ONE), so only the identity check refuses it.
    const one = new Uint8Array(576); one[47] = 1;
    expect(gtToBytes(Fp12.ONE as never)).toEqual(one);
    expect(gtFromBytes(one)).toBeNull();
    // a 1 in the LAST coefficient instead is a non-identity element outside the subgroup: refused by the R-th power check
    const last = new Uint8Array(576); last[575] = 1;
    expect(Fp12.eql(Fp12.pow(Fp12.fromBytes(last), R), Fp12.ONE)).toBe(false);
    expect(gtFromBytes(last)).toBeNull();
    expect(gtFromBytes(new Uint8Array(576).fill(2))).toBeNull();
    const notSub = gtToBytes(pairing(G1_BASE, G2_BASE)).slice(); notSub[10]! ^= 1;
    expect(gtFromBytes(notSub)).toBeNull();
  });
  it('scalars and attribute hashing', () => {
    expect(bytesToScalar(new Uint8Array(31))).toBeNull();
    expect(bytesToScalar(new Uint8Array(33))).toBeNull();
    expect(bytesToScalar(scalarToBytes(5n))).toBe(5n);
    expect(scalarToBytes(R + 5n)).toEqual(scalarToBytes(5n));
    expect(() => hashAttrToG1('a\ud800')).toThrow('attribute is not well-formed UTF-16');
    expect(() => hashAttrToG1('a😀')).not.toThrow();
  });
});

describe('pca.ts', () => {
  it('payload round trip and the exact refusal reasons', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptToolPayload(mpk, { attr: 'a' }, { x: 1 });
    expect(decryptWithCapability(keygenForAttributes(msk, ['a']), ciphertext)).toEqual({ ok: true, payload: { x: 1 } });
    expect(decryptWithCapability(keygenForAttributes(msk, ['b']), ciphertext)).toEqual({ ok: false, reason: 'capability does not satisfy the policy, or ciphertext is invalid' });
    const nonJson = encryptForPolicy(mpk, { attr: 'a' }, 'not json{').ciphertext;
    expect(decryptWithCapability(keygenForAttributes(msk, ['a']), nonJson)).toEqual({ ok: false, reason: 'decrypted payload is not valid JSON' });
    expect(decryptWithCapability(keygenForAttributes(msk, ['a']), encryptToolPayload(mpk, { attr: 'a' }, undefined).ciphertext)).toEqual({ ok: true, payload: null });
  });
});

describe('aead / wire remainders', () => {
  const key = new Uint8Array(32).fill(3), aad = new Uint8Array(0);
  it('open refuses each wrong length independently and a short tag cannot be forced', () => {
    const s = seal(key, new Uint8Array([1, 2, 3]), aad);
    expect(open(key, { ...s, tag: s.tag.subarray(0, 4) }, aad)).toBeNull();
    expect(open(key, { ...s, iv: new Uint8Array(16) }, aad)).toBeNull();
    expect(open(new Uint8Array(16), s, aad)).toBeNull();
    expect(open(key, s, aad)).toEqual(new Uint8Array([1, 2, 3]));
  });
  it('wire guards', () => {
    expect(unb64u(5)).toBeNull(); expect(unb64u('ab cd')).toBeNull(); expect(unb64u('ab\n')).toBeNull(); expect(unb64u('\nab')).toBeNull();
    expect(isPosInt('1')).toBe(false); expect(isPosInt(2)).toBe(true);
  });
});
