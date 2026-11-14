import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/abstract/utils';
import { createCipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, type Capability, b64u, generateKeyPair, mintGrant } from '@atlasauth/pca';
import {
  PcaEncryptionError,
  decrypt,
  decryptText,
  encryptForPolicy,
  keygenForAttributes,
  keygenForCapability,
  setup,
  type AbeCiphertext,
  type DecryptionKey,
  type MasterPublicKey,
  type MasterSecretKey,
} from './abe';
import { G1_BASE, G1_ZERO, G2_BASE, R, g1Mul, g1MulZ, gtFromBytes, gtToBytes, pairing } from './bls';
import { open } from './aead';
import { Attr, capabilityAttributes } from './attributes';
import { buildRows, fameDecrypt, fameEncrypt, fameKeygen, fameSetup, firstRepeatedAttribute, reconstructionWeights } from './fame';
import { MAX_POLICY_DEPTH, normalizePolicy, type ThresholdTree } from './policy';
import { unb64u } from './wire';

const errOf = (f: () => unknown): { name: string; message: string } => {
  try {
    f();
  } catch (e) {
    return { name: (e as Error).name, message: (e as Error).message };
  }
  return { name: 'NONE', message: 'did not throw' };
};
const zeros = (n: number): string => b64u(new Uint8Array(n));
const scalarBytes = (v: bigint): string => b64u(numberToBytesBE(v, 32));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const leaf = (attr: string): ThresholdTree => ({ kind: 'leaf', attr });

const P = generateKeyPair();
const mintCap = (preds: unknown[], caveats: unknown[] = [], holder = 'hold'): Capability =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder, goal: 'g', envelope: { predicates: preds as never, caveats: caveats as never, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;

describe('abe key material', () => {
  it('names the curve and the error class', () => {
    const { mpk, msk } = setup();
    expect(mpk.curve).toBe('bls12-381');
    expect(msk.curve).toBe('bls12-381');
    expect(keygenForAttributes(msk, ['a']).curve).toBe('bls12-381');
    expect(new PcaEncryptionError('x').name).toBe('PcaEncryptionError');
  });

  it('an invalid policy is reported with its reason, before the public key is read', () => {
    expect(errOf(() => encryptForPolicy({} as never, { attr: '' } as never, 'x'))).toEqual({
      name: 'PcaEncryptionError',
      message: "invalid policy: policy: 'attr' must be a non-empty string",
    });
  });

  it('keygen issues keys only for well-formed non-empty string attributes', () => {
    const { msk } = setup();
    const key = keygenForAttributes(msk, ['ok', '', 5 as never, '\ud800', 'ok', 'x\udc00']);
    expect(Object.keys(key.attrs)).toEqual(['ok']);
  });

  it('a malformed master secret key is refused with one error', () => {
    const { msk } = setup();
    const bad = (m: unknown) => errOf(() => keygenForAttributes(m as MasterSecretKey, ['a']));
    const want = { name: 'PcaEncryptionError', message: 'invalid master secret key' };
    const withA = (a: unknown) => ({ ...msk, a });
    const withB = (b: unknown) => ({ ...msk, b });
    const withG = (g: unknown) => ({ ...msk, g });
    const RBytes = scalarBytes(R);
    const cases: unknown[] = [
      null,
      { ...msk, v: 3 },
      withA('x'), withA([]), withA([msk.a[0]]), withA([...msk.a, msk.a[0]]), withA(['!', msk.a[1]]), withA([msk.a[0], '!']),
      withA([b64u(new Uint8Array(31)), msk.a[1]]), withA([zeros(32), msk.a[1]]), withA([RBytes, msk.a[1]]), withA([scalarBytes(R + 1n), msk.a[1]]),
      withB('x'), withB([]), withB([msk.b[0]]), withB([...msk.b, msk.b[0]]), withB(['!', msk.b[1]]), withB([msk.b[0], '!']), withB([msk.b[0], zeros(32)]),
      withG('x'), withG([msk.g[0], msk.g[1]]), withG([...msk.g, msk.g[0]]),
      withG([zeros(48), msk.g[1], msk.g[2]]), withG([msk.g[0], zeros(48), msk.g[2]]), withG([msk.g[0], msk.g[1], zeros(48)]), withG([msk.g[0], msk.g[1], '!']),
    ];
    for (const c of cases) expect(bad(c)).toEqual(want);
    expect(bad(msk)).toEqual({ name: 'NONE', message: 'did not throw' });
    expect(bad(withA([scalarBytes(R - 1n), msk.a[1]]))).toEqual({ name: 'NONE', message: 'did not throw' });
  });

  it('a malformed master public key is refused with one error', () => {
    const { mpk } = setup();
    const bad = (m: unknown) => errOf(() => encryptForPolicy(m as MasterPublicKey, { attr: 'a' }, 'x'));
    const want = { name: 'PcaEncryptionError', message: 'invalid master public key' };
    const cases: unknown[] = [
      null,
      { ...mpk, v: 3 },
      { ...mpk, h: 'x' }, { ...mpk, h: [mpk.h[0]] }, { ...mpk, h: [...mpk.h, mpk.h[0]] }, { ...mpk, h: [zeros(96), mpk.h[1]] }, { ...mpk, h: [mpk.h[0], zeros(96)] },
      { ...mpk, t: 'x' }, { ...mpk, t: [mpk.t[0]] }, { ...mpk, t: [...mpk.t, mpk.t[0]] }, { ...mpk, t: ['!', mpk.t[1]] }, { ...mpk, t: [mpk.t[0], '!'] },
      { ...mpk, t: [mpk.t[0], zeros(10)] }, { ...mpk, t: [zeros(10), mpk.t[1]] },
    ];
    for (const c of cases) expect(bad(c)).toEqual(want);
    expect(bad(mpk)).toEqual({ name: 'NONE', message: 'did not throw' });
  });
});

describe('abe decrypt fails closed on malformed key or ciphertext points', () => {
  const setupAll = () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { allOf: [{ attr: 'a' }, { attr: 'b' }] }, 'secret');
    const key = keygenForAttributes(msk, ['a', 'b']);
    return { ciphertext, key };
  };

  it('a good key decrypts; every structural defect in the key yields null', () => {
    const { ciphertext, key } = setupAll();
    expect(decryptText(key, ciphertext)).toBe('secret');
    const bad = (mut: (k: Record<string, unknown>) => void) => {
      const k = clone(key) as unknown as Record<string, unknown>;
      mut(k);
      return decrypt(k as unknown as DecryptionKey, ciphertext);
    };
    expect(bad((k) => { k.v = 3; })).toBeNull();
    expect(bad((k) => { k.attrs = null; })).toBeNull();
    expect(bad((k) => { k.attrs = []; })).toBeNull();
    expect(bad((k) => { k.k0 = 'x'; })).toBeNull();
    expect(bad((k) => { (k.k0 as string[]).push((k.k0 as string[])[0]!); })).toBeNull();
    expect(bad((k) => { (k.kp as string[]).push((k.kp as string[])[0]!); })).toBeNull();
    for (let i = 0; i < 3; i++) {
      expect(bad((k) => { (k.k0 as string[])[i] = zeros(96); })).toBeNull();
      expect(bad((k) => { (k.kp as string[])[i] = zeros(48); })).toBeNull();
    }
    expect(decrypt(null as never, ciphertext)).toBeNull();
  });

  it('a malformed attribute component counts as not held', () => {
    const { ciphertext, key } = setupAll();
    const attrs = key.attrs as Record<string, unknown>;
    for (const comp of [null, 5, {}, { k: 'x' }, { k: [zeros(48), zeros(48), zeros(48)] }, { k: [...key.attrs.a!.k, key.attrs.a!.k[0]] }]) {
      const k = { ...key, attrs: { ...attrs, a: comp } } as unknown as DecryptionKey;
      expect(decrypt(k, ciphertext)).toBeNull();
    }
  });

  it('a ciphertext whose points are not on the curve yields null', () => {
    const { ciphertext, key } = setupAll();
    for (let i = 0; i < 3; i++) {
      const c = clone(ciphertext) as AbeCiphertext;
      c.ct0[i] = zeros(96);
      expect(decrypt(key, c)).toBeNull();
      const r = clone(ciphertext) as AbeCiphertext;
      r.rows[0]![i] = zeros(48);
      expect(decrypt(key, r)).toBeNull();
      const r2 = clone(ciphertext) as AbeCiphertext;
      r2.rows[1]![i] = zeros(48);
      expect(decrypt(key, r2)).toBeNull();
    }
  });
});

describe('keygenForCapability', () => {
  it('issues exactly the capability attributes plus well-formed extras, and records the holder', () => {
    const { msk } = setup();
    const cap = mintCap([{ verb: 'read', resource: 'doc' }]);
    const key = keygenForCapability(msk, cap, [null as never, undefined as never, '', 5 as never, 'extra']);
    expect(Object.keys(key.attrs).sort()).toEqual([...capabilityAttributes(cap), 'extra'].sort());
    expect(key.holder).toBe('hold');
    expect(Object.keys(keygenForCapability(msk, cap).attrs).sort()).toEqual([...capabilityAttributes(cap)].sort());
  });
  it('a capability without a string holder leaves no holder on the key', () => {
    const { msk } = setup();
    const cap = { ...mintCap([{ verb: 'read', resource: 'doc' }]), holder: undefined } as unknown as Capability;
    const key = keygenForCapability(msk, cap);
    expect('holder' in key).toBe(false);
    expect(Object.keys(key.attrs).sort()).toEqual([Attr.act('read', 'doc'), Attr.resource('doc'), Attr.verb('read')].sort());
  });
});

describe('helpers', () => {
  it('unb64u refuses values that cannot even be coerced to text', () => {
    expect(unb64u(Symbol('x'))).toBeNull();
    expect(unb64u(Object.create(null))).toBeNull();
    expect(unb64u(['AA'])).toBeNull();
  });

  it('only a scopes caveat contributes a scopes list', () => {
    const cap = mintCap([{ verb: 'r', resource: 'd' }]);
    const withCv = { ...cap, caveats: [...cap.caveats, { type: 'other', values: ['sx'] }, { type: 'scopes', values: ['sy'] }] } as Capability;
    const got = [...capabilityAttributes(withCv)].filter((a) => a.startsWith('scope:'));
    expect(got).toEqual([Attr.scope('sy')]);
  });

  it('capabilityAttributes does not throw for a capability without a holder', () => {
    const cap = { ...mintCap([{ verb: 'r', resource: 'd' }]), holder: undefined } as unknown as Capability;
    expect([...capabilityAttributes(cap)].some((a) => a.startsWith('holder:'))).toBe(false);
  });

  it('an unknown policy node deep in the tree is reported as unknown, not as too deep', () => {
    let p: unknown = {};
    for (let i = 0; i < MAX_POLICY_DEPTH; i++) p = { allOf: [p] };
    const path = 'policy' + '.allOf[0]'.repeat(MAX_POLICY_DEPTH);
    expect(normalizePolicy(p)).toEqual({ ok: false, reason: `${path}: unknown policy node (expected attr/allOf/anyOf/threshold)` });
  });

  it('open refuses an IV that is not 12 bytes even when the sealed data authenticates under it', () => {
    const key = randomBytes(32);
    const iv = randomBytes(16);
    const c = createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from('aad'));
    const ct = Buffer.concat([c.update('hello'), c.final()]);
    const sealed = { iv: new Uint8Array(iv), ct: new Uint8Array(ct), tag: new Uint8Array(c.getAuthTag()) };
    expect(open(new Uint8Array(key), sealed, new TextEncoder().encode('aad'))).toBeNull();
  });
});

describe('bls codecs', () => {
  it('g1MulZ maps a scalar that is 0 mod r to the identity', () => {
    expect(g1MulZ(G1_BASE, 0n).equals(G1_ZERO)).toBe(true);
    expect(g1MulZ(G1_BASE, R).equals(G1_ZERO)).toBe(true);
    expect(g1MulZ(G1_BASE, 3n).equals(g1Mul(G1_BASE, 3n))).toBe(true);
  });
  it('a GT coordinate that is not reduced mod p is refused', () => {
    const p = bls12_381.fields.Fp.ORDER;
    const one = new Uint8Array(576);
    one[47] = 1;
    const unreduced = one.slice();
    unreduced.set(numberToBytesBE(1n + p, 48), 0);
    expect(bytesToNumberBE(unreduced.subarray(0, 48))).toBe(1n + p);
    expect(gtFromBytes(unreduced)).toBeNull();
    const e = gtToBytes(pairing(G1_BASE, G2_BASE));
    expect(gtFromBytes(e)).not.toBeNull();
    const shifted = e.slice();
    shifted.set(numberToBytesBE(bytesToNumberBE(e.subarray(0, 48)) + p, 48), 0);
    expect(gtFromBytes(shifted)).toBeNull();
  });
});

describe('fame internals', () => {
  it('buildRows lays out span-program columns across nested gates', () => {
    const tree: ThresholdTree = { kind: 'gate', t: 2, of: [leaf('a'), { kind: 'gate', t: 2, of: [leaf('b'), leaf('c')] }, leaf('d')] };
    const rows = buildRows(tree).map((r) => ({ attr: r.attr, vec: [...r.vec.entries()] }));
    expect(rows).toEqual([
      { attr: 'a', vec: [[0, 1n], [1, 1n]] },
      { attr: 'b', vec: [[0, 1n], [1, 2n], [2, 1n]] },
      { attr: 'c', vec: [[0, 1n], [1, 2n], [2, 2n]] },
      { attr: 'd', vec: [[0, 1n], [1, 3n]] },
    ]);
    const three: ThresholdTree = { kind: 'gate', t: 3, of: [leaf('a'), leaf('b'), leaf('c')] };
    expect(buildRows(three).map((r) => [...r.vec.entries()])).toEqual([
      [[0, 1n], [1, 1n], [2, 1n]],
      [[0, 1n], [1, 2n], [2, 4n]],
      [[0, 1n], [1, 3n], [2, 9n]],
    ]);
  });
  it('firstRepeatedAttribute reports the first repeat in depth-first order', () => {
    const t: ThresholdTree = { kind: 'gate', t: 1, of: [leaf('a'), leaf('a'), leaf('b'), leaf('b')] };
    expect(firstRepeatedAttribute(t)).toBe('a');
    expect(firstRepeatedAttribute({ kind: 'gate', t: 1, of: [leaf('a'), leaf('b')] })).toBeNull();
  });
  it('reconstructionWeights picks the first t satisfiable children and their Lagrange weights', () => {
    const all = () => true;
    const any: ThresholdTree = { kind: 'gate', t: 1, of: [leaf('a'), leaf('b')] };
    expect(reconstructionWeights(any, all)).toEqual(new Map([[0, 1n]]));
    const two: ThresholdTree = { kind: 'gate', t: 2, of: [leaf('a'), leaf('b'), leaf('c')] };
    expect(reconstructionWeights(two, all)).toEqual(new Map([[0, 2n], [1, R - 1n]]));
    expect(reconstructionWeights(two, (a) => a !== 'a')).toEqual(new Map([[1, 3n], [2, R - 2n]]));
    expect(reconstructionWeights(two, (a) => a === 'a')).toBeNull();
  });
  it('reconstructionWeights fails closed when the interpolation points are degenerate', () => {
    expect(reconstructionWeights({ kind: 'gate', t: 0, of: [] }, () => true)).toBeNull();
    expect(reconstructionWeights({ kind: 'gate', t: 1, of: [{ kind: 'gate', t: 0, of: [] }] }, () => true)).toBeNull();
  });

  const scheme = () => {
    const { mpk, msk } = fameSetup([2n, 3n], [5n, 7n], [11n, 13n, 17n]);
    const tree: ThresholdTree = { kind: 'gate', t: 2, of: [leaf('a'), leaf('b')] };
    const key = fameKeygen(msk, ['a', 'b'], [3n, 4n], [5n, 6n], 7n);
    const enc = fameEncrypt(mpk, tree, [8n, 9n]);
    return { mpk, msk, tree, key, enc };
  };
  it('fameKeygen needs one sigma per attribute', () => {
    const { msk } = scheme();
    expect(errOf(() => fameKeygen(msk, ['a', 'b'], [3n, 4n], [5n], 7n))).toEqual({ name: 'RangeError', message: 'fameKeygen: one sigma per attribute is required' });
  });
  it('fameDecrypt recovers the key, and refuses a ciphertext with a different number of rows', () => {
    const { tree, key, enc } = scheme();
    const k = fameDecrypt(key, tree, enc.ct);
    expect(k).not.toBeNull();
    expect(Buffer.from(gtToBytes(k!)).equals(Buffer.from(gtToBytes(enc.k)))).toBe(true);
    expect(fameDecrypt(key, tree, { ...enc.ct, rows: [...enc.ct.rows, enc.ct.rows[0]!] })).toBeNull();
    expect(fameDecrypt(key, tree, { ...enc.ct, rows: enc.ct.rows.slice(0, 1) })).toBeNull();
  });
  it('fameDecrypt returns null (not undefined) when the combined ciphertext point is the identity', () => {
    const { tree, key, enc } = scheme();
    const r0 = enc.ct.rows[0]!;
    const cancelled = { ...enc.ct, rows: [r0, [g1Mul(r0[0], 2n), g1Mul(r0[1], 2n), g1Mul(r0[2], 2n)] as typeof r0] };
    expect(fameDecrypt(key, tree, cancelled)).toBeNull();
  });
});
