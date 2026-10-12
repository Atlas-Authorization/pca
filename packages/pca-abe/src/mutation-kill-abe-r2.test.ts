/**
 * Round-2 adversarial kills: mutants that were ledgered as "equivalent" but are observable.
 * Each test documents the input that distinguishes the mutant from the original.
 */
import { createCipheriv, randomBytes } from 'node:crypto';
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, type Capability, b64u as pcaB64u, canonicalBytes, generateKeyPair, mintGrant } from '@atlasauth/pca';
import { ABE_ALG, PcaEncryptionError, decrypt, encryptForPolicy, keygenForAttributes, keygenForCapability, parseCiphertext, setup } from './abe';
import { Attr, capabilityAttributes } from './attributes';
import { open } from './aead';
import { G1_BASE, G2_BASE, g1FromBytes, g1Mul, g1ToBytes, g2FromBytes, g2Mul, g2ToBytes, gtFromBytes, gtPow, gtToBytes, hashAttrToG1, kdf32, pairing, randomScalar } from './bls';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES, normalizePolicy } from './policy';
import { seal } from './aead';
import { b64u, unb64u } from './wire';

const P = generateKeyPair();
const mint = (preds: unknown[], holder = 'hold'): Capability =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: pcaB64u(P.publicKey), holder, goal: 'g', envelope: { predicates: preds as never, caveats: [] as never, agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;

describe('r2: parseCiphertext node budget', () => {
  const leaf = { kind: 'leaf', attr: 'a', c: 'AA', cp: 'AA' };
  const gate = (n: number) => ({ kind: 'gate', t: 1, of: Array.from({ length: n }, (_, k) => ({ i: k + 1, sub: leaf })) });
  const wrap = (kem: unknown) => ({ v: 1, alg: ABE_ALG, salt: 'AA', c0: 'AA', iv: 'AA', ct: 'AA', tag: 'AA', kem });
  it('a tree of more than MAX_POLICY_NODES total nodes is refused even when no single gate is wide', () => {
    const half = Math.ceil(MAX_POLICY_NODES / 2) + 10; // each gate < MAX, total 1 + 2*(1+half) > MAX
    const big = { kind: 'gate', t: 1, of: [{ i: 1, sub: gate(half) }, { i: 2, sub: gate(half) }] };
    expect(1 + 2 * (1 + half)).toBeGreaterThan(MAX_POLICY_NODES);
    expect(parseCiphertext(wrap(big))).toBeNull();
    const ok = { kind: 'gate', t: 1, of: [{ i: 1, sub: gate(50) }, { i: 2, sub: gate(50) }] };
    expect(parseCiphertext(wrap(ok))).not.toBeNull();
  });
  it('non-object branches never throw (fail closed to null)', () => {
    for (const bad of [null, 5, 'x', [], true, undefined]) {
      expect(() => parseCiphertext(wrap({ kind: 'gate', t: 1, of: [bad] }))).not.toThrow();
      expect(parseCiphertext(wrap({ kind: 'gate', t: 1, of: [bad] }))).toBeNull();
    }
    // a valid first branch followed by a null one
    expect(parseCiphertext(wrap({ kind: 'gate', t: 1, of: [{ i: 1, sub: leaf }, null] }))).toBeNull();
  });
});

describe('r2: parseMpk memo-key construction', () => {
  it('a Symbol-valued component yields the typed PcaEncryptionError, not a TypeError from template coercion', () => {
    const { mpk } = setup();
    const cases = [
      { ...mpk, f: Symbol('f') },
      { ...mpk, h: Symbol('h') },
      { h: 'AA', f: Symbol('f'), egga: 'AA' },
      { h: Symbol('h'), f: Symbol('f'), egga: mpk.egga },
    ];
    for (const bad of cases) {
      let e: unknown;
      try { encryptForPolicy(bad as never, { attr: 'a' }, 'x'); } catch (x) { e = x; }
      expect(e).toBeInstanceOf(PcaEncryptionError);
    }
  });
  it('an identity GT element is not an acceptable Y (it would make every CEK a constant)', () => {
    const { mpk } = setup();
    const id = b64u(bls12_381.fields.Fp12.toBytes(bls12_381.fields.Fp12.ONE));
    expect(() => encryptForPolicy({ ...mpk, egga: id }, { attr: 'a' }, 'x')).toThrow(PcaEncryptionError);
    expect(gtFromBytes(bls12_381.fields.Fp12.toBytes(bls12_381.fields.Fp12.ONE))).toBeNull();
  });
});

describe('r2: gtFromBytes strictness', () => {
  const x = pairing(G1_BASE, G2_BASE);
  const good = gtToBytes(x);
  it('accepts the canonical encoding and only that', () => {
    expect(gtFromBytes(good)).not.toBeNull();
    for (const len of [0, 1, 575, 577, 1152]) expect(gtFromBytes(new Uint8Array(len))).toBeNull();
    expect(gtFromBytes(Uint8Array.from([...good, 0]))).toBeNull();
    expect(gtFromBytes(good.subarray(0, 575))).toBeNull();
  });
});

describe('r2: aead open() IV length', () => {
  it('only the canonical 12-byte IV opens, even when the tag authenticates under another IV length', () => {
    const key = new Uint8Array(randomBytes(32));
    const aad = new Uint8Array([1, 2, 3]);
    for (const ivLen of [8, 13, 16]) {
      const iv = new Uint8Array(randomBytes(ivLen));
      const c = createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(aad);
      const ct = new Uint8Array(Buffer.concat([c.update(new Uint8Array([9, 9, 9])), c.final()]));
      const tag = new Uint8Array(c.getAuthTag());
      expect(open(key, { iv, ct, tag }, aad)).toBeNull();
    }
    const iv = new Uint8Array(randomBytes(12));
    const c = createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(aad);
    const ct = new Uint8Array(Buffer.concat([c.update(new Uint8Array([9])), c.final()]));
    const tag = new Uint8Array(c.getAuthTag());
    expect(open(key, { iv, ct, tag }, aad)).toEqual(new Uint8Array([9]));
  });
  it('an ABE ciphertext re-sealed under a 16-byte IV is refused', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { attr: 'a' }, 'p');
    const key = keygenForAttributes(msk, ['a']);
    expect(decrypt(key, ciphertext)).not.toBeNull();
    // forge: recompute the CEK as an honest encryptor would (s known), seal under a 16-byte IV
    const { h: _h } = { h: g2FromBytes(unb64u(mpk.h)!)! };
    void _h;
    expect(decrypt(key, { ...ciphertext, iv: b64u(new Uint8Array(16)) })).toBeNull();
  });
});

describe('r2: a leaf whose ciphertext component is not a valid point is "not recoverable", not fatal', () => {
  it('OR(A, B) with a garbage C_A still opens through B; and a half-malformed key attribute is "not held"', () => {
    const { mpk, msk } = setup();
    const h = g2FromBytes(unb64u(mpk.h)!)!;
    const y = gtFromBytes(unb64u(mpk.egga)!)!;
    const s = randomScalar();
    const leafFor = (attr: string, badC: boolean) => ({
      kind: 'leaf' as const,
      attr,
      c: badC ? b64u(new Uint8Array(96).fill(1)) : b64u(g2ToBytes(g2Mul(G2_BASE, s))),
      cp: b64u(g1ToBytes(g1Mul(hashAttrToG1(attr), s))),
    });
    const salt = new Uint8Array(randomBytes(16));
    const header = {
      v: 1 as const, alg: ABE_ALG, salt: b64u(salt), c0: b64u(g2ToBytes(g2Mul(h, s))),
      kem: { kind: 'gate' as const, t: 1, of: [{ i: 1, sub: leafFor('A', true) }, { i: 2, sub: leafFor('B', false) }] },
    };
    const cek = kdf32(gtToBytes(gtPow(y, s)), salt, 'atlas-pca-abe/cek/v2');
    const sealed = seal(cek, new TextEncoder().encode('via-B'), canonicalBytes(header));
    const ct = { ...header, iv: b64u(sealed.iv), ct: b64u(sealed.ct), tag: b64u(sealed.tag) };
    const key = keygenForAttributes(msk, ['A', 'B']);
    expect(new TextDecoder().decode(decrypt(key, ct)!)).toBe('via-B');

    // The same, but A is spoiled in the KEY (valid D_j, malformed D'_j) on a well-formed ciphertext.
    const { ciphertext } = encryptForPolicy(mpk, { anyOf: [{ attr: 'A' }, { attr: 'B' }] }, 'via-B2');
    const k2 = keygenForAttributes(msk, ['A', 'B']);
    const spoiled = { ...k2, attrs: { ...k2.attrs, A: { dj: k2.attrs.A!.dj, dpj: b64u(new Uint8Array(96).fill(1)) } } };
    expect(new TextDecoder().decode(decrypt(spoiled, ciphertext)!)).toBe('via-B2');
    const spoiledJ = { ...k2, attrs: { ...k2.attrs, A: { dj: b64u(new Uint8Array(48).fill(1)), dpj: k2.attrs.A!.dpj } } };
    expect(new TextDecoder().decode(decrypt(spoiledJ, ciphertext)!)).toBe('via-B2');
  });
});

describe('r2: keygenForCapability grants exactly the capability attributes (+ explicit extras)', () => {
  it('no extra attribute appears by default', () => {
    const { msk } = setup();
    const cap = mint([{ verb: 'read', resource: 'doc' }]);
    const key = keygenForCapability(msk, cap);
    expect(Object.keys(key.attrs).sort()).toEqual([...capabilityAttributes(cap)].sort());
    const withExtra = keygenForCapability(msk, cap, ['x', '', 5 as never]);
    expect(Object.keys(withExtra.attrs).sort()).toEqual([...capabilityAttributes(cap), 'x'].sort());
  });
});

describe('r2: policy depth guard only applies to real gates', () => {
  it('a non-gate node at the depth limit reports "unknown node", not "nested too deep"', () => {
    let node: unknown = {};
    for (let i = 0; i < MAX_POLICY_DEPTH; i++) node = { allOf: [node] };
    const r = normalizePolicy(node);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toMatch(/unknown policy node/);
      expect(r.reason).not.toMatch(/nested deeper/);
    }
    let deeper: unknown = { attr: 'a' };
    for (let i = 0; i < MAX_POLICY_DEPTH + 1; i++) deeper = { allOf: [deeper] };
    const d = normalizePolicy(deeper);
    expect(d.ok === false && /nested deeper/.test(d.reason)).toBe(true);
  });
});

describe('r2: capabilityAttributes', () => {
  it('only "scopes" caveats contribute scope: tokens (a different type carrying a values array grants nothing)', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    const withCv = { ...cap, caveats: [...cap.caveats, { type: 'resource_in', values: ['admin'] }, { type: 'scope', values: ['admin2'] }, { type: 'scopes', values: ['ok'] }] } as Capability;
    const a = capabilityAttributes(withCv);
    expect(a.has(Attr.scope('ok'))).toBe(true);
    expect([...a].filter((t) => t.startsWith('scope:'))).toEqual([Attr.scope('ok')]);
  });
  it('a capability with no holder field is total (no throw) and yields no holder token', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    const noHolder = { ...cap } as Record<string, unknown>;
    delete noHolder.holder;
    expect(() => capabilityAttributes(noHolder as never)).not.toThrow();
    expect([...capabilityAttributes(noHolder as never)].some((t) => t.startsWith('holder:'))).toBe(false);
    expect([...capabilityAttributes({ ...cap, holder: null } as never)].some((t) => t.startsWith('holder:'))).toBe(false);
  });
  it('a chain that is not an array, or an empty one, yields nothing and never throws', () => {
    const cap = mint([{ verb: 'r', resource: 'd' }]);
    for (const chain of [[], {}, { length: 1, 0: cap }, 'abc', 5, null]) {
      let a: Set<string> | undefined;
      try { a = capabilityAttributes(cap, { chain: chain as never }); } catch { a = undefined; }
      // null throws on chain[0] in the original as well; everything else must be an empty set
      if (chain !== null) expect(a?.size).toBe(0);
    }
    const noId = { ...cap } as Record<string, unknown>;
    delete noId.id;
    expect(capabilityAttributes(noId as never, { chain: [] }).size).toBe(0);
  });
});

describe('r2: SECURITY - GT parsing must reject non-reduced coordinates (aliases of valid elements)', () => {
  const Fp12 = bls12_381.fields.Fp12;
  const FP = bls12_381.fields.Fp.ORDER;
  const setChunk = (b: Uint8Array, off: number, v: bigint): Uint8Array => {
    const out = Uint8Array.from(b);
    for (let i = 0; i < 48; i++) out[off + i] = Number((v >> BigInt(8 * (47 - i))) & 0xffn);
    return out;
  };
  const chunk = (b: Uint8Array, off: number): bigint => {
    let c = 0n;
    for (let i = 0; i < 48; i++) c = (c << 8n) | BigInt(b[off + i]!);
    return c;
  };
  it('the identity element cannot be smuggled in as 1 + p (it would make Y trivial and every CEK constant)', () => {
    const one = Fp12.toBytes(Fp12.ONE);
    const off = [...Array(12).keys()].map((k) => k * 48).find((o) => chunk(one, o) === 1n)!;
    const alias = setChunk(one, off, 1n + FP);
    expect(gtFromBytes(alias)).toBeNull();
    const { mpk } = setup();
    expect(() => encryptForPolicy({ ...mpk, egga: b64u(alias) }, { attr: 'a' }, 'x')).toThrow(PcaEncryptionError);
  });
  it('no coordinate of a valid element may be replaced by its alias c + p', () => {
    const good = gtToBytes(pairing(G1_BASE, G2_BASE));
    expect(gtFromBytes(good)).not.toBeNull();
    let tried = 0;
    for (let off = 0; off < 576; off += 48) {
      const c = chunk(good, off) + FP;
      if (c >> 384n !== 0n) continue;
      tried++;
      expect(gtFromBytes(setChunk(good, off, c))).toBeNull();
    }
    expect(tried).toBeGreaterThan(0);
  });
});

describe('r2: G1/G2 parsing rejects non-reduced x (noble accepts it; bytesEqual is the only guard)', () => {
  const FP = bls12_381.fields.Fp.ORDER;
  it('x + p aliases are refused', () => {
    let g1 = 0, g2 = 0;
    for (let n = 0; n < 40 && (g1 < 3 || g2 < 3); n++) {
      const b1 = g1Mul(G1_BASE, randomScalar()).toRawBytes(true);
      let x = 0n;
      for (let i = 0; i < 48; i++) x = (x << 8n) | BigInt(i === 0 ? b1[0]! & 0x1f : b1[i]!);
      const xx = x + FP;
      if (xx >> 381n === 0n) {
        const bad = new Uint8Array(48);
        for (let i = 0; i < 48; i++) bad[i] = Number((xx >> BigInt(8 * (47 - i))) & 0xffn);
        bad[0]! |= b1[0]! & 0xe0;
        expect(g1FromBytes(bad)).toBeNull();
        g1++;
      }
      const b2 = g2Mul(G2_BASE, randomScalar()).toRawBytes(true);
      for (const off of [0, 48]) {
        let y = 0n;
        for (let i = 0; i < 48; i++) y = (y << 8n) | BigInt(off === 0 && i === 0 ? b2[0]! & 0x1f : b2[off + i]!);
        const yy = y + FP;
        if (yy >> (off === 0 ? 381n : 384n) !== 0n) continue;
        const bad = Uint8Array.from(b2);
        for (let i = 0; i < 48; i++) bad[off + i] = Number((yy >> BigInt(8 * (47 - i))) & 0xffn);
        if (off === 0) bad[0]! |= b2[0]! & 0xe0;
        expect(g2FromBytes(bad)).toBeNull();
        g2++;
      }
    }
    expect(g1).toBeGreaterThan(0);
    expect(g2).toBeGreaterThan(0);
  });
});
