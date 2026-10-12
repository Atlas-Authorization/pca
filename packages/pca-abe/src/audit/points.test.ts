import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { numberToBytesBE } from '@noble/curves/abstract/utils';
import {
  type AttributeKey,
  type DecryptionKey,
  type MasterPublicKey,
  type MasterSecretKey,
  PcaEncryptionError,
  decrypt,
  encryptForPolicy,
  keygenForAttributes,
  setup,
} from '../index';
import { g1FromBytes, g2FromBytes, hashAttrToG1, R } from '../bls';
import { b64, clone, g1Infinity, g1OffSubgroup, g2Infinity, g2OffSubgroup, leaves } from './_helpers';

const PT = new TextEncoder().encode('points');
const Fp = bls.fields.Fp;

describe('G1 / G2 decoding: invalid-curve, wrong-subgroup, identity and malformed inputs', () => {
  it('rejects a G1 point on the curve but outside the prime-order subgroup', () => {
    expect(g1FromBytes(g1OffSubgroup())).toBeNull();
  });
  it('rejects a G2 point on the twist but outside the prime-order subgroup', () => {
    expect(g2FromBytes(g2OffSubgroup())).toBeNull();
  });
  it('rejects the point at infinity for both groups (an identity key / ephemeral / public key is never legitimate)', () => {
    expect(g1FromBytes(g1Infinity())).toBeNull();
    expect(g2FromBytes(g2Infinity())).toBeNull();
  });
  it('rejects x >= p (non-canonical field element), x not on the curve, wrong length, empty, wrong flags', () => {
    const bad: Uint8Array[] = [];
    const xplus = numberToBytesBE(Fp.ORDER + 4n, 48);
    xplus[0] = (xplus[0] ?? 0) | 0x80;
    bad.push(xplus);
    for (let x = 2n; x < 40n; x++) {
      const rhs = Fp.add(Fp.pow(x, 3n), 4n);
      try {
        Fp.sqrt(rhs);
        if (Fp.mul(Fp.sqrt(rhs), Fp.sqrt(rhs)) === rhs) continue;
      } catch {
        /* non-residue: good */
      }
      const o = numberToBytesBE(x, 48);
      o[0] = (o[0] ?? 0) | 0x80;
      bad.push(o);
      break;
    }
    bad.push(new Uint8Array(0), new Uint8Array(47), new Uint8Array(49), new Uint8Array(48), new Uint8Array(96).fill(0xff));
    const noFlag = bls.G1.ProjectivePoint.BASE.toRawBytes(true).slice();
    noFlag[0] = (noFlag[0] ?? 0) & 0x7f; // compression flag cleared in a 48-byte string
    bad.push(noFlag);
    const infWithData = g1Infinity();
    infWithData[47] = 1;
    bad.push(infWithData);
    for (const b of bad) expect(g1FromBytes(b)).toBeNull();
    expect(g2FromBytes(new Uint8Array(48))).toBeNull(); // a G1-length string is not a G2 point
    expect(g1FromBytes(bls.G2.ProjectivePoint.BASE.toRawBytes(true))).toBeNull(); // and vice versa
  });
  it('accepts exactly the canonical compressed encoding of valid points (round-trip)', () => {
    for (let i = 0; i < 5; i++) {
      const p = hashAttrToG1(`attr${i}`);
      const q = g1FromBytes(p.toRawBytes(true));
      expect(q?.equals(p)).toBe(true);
    }
  });
  it('the sign bit selects the other y: flipping it yields -P, never the same point', () => {
    const p = hashAttrToG1('sign');
    const enc = p.toRawBytes(true).slice();
    enc[0] = (enc[0] ?? 0) ^ 0x20;
    const q = g1FromBytes(enc);
    expect(q?.equals(p.negate())).toBe(true);
  });
});

describe('hostile points injected into protocol messages', () => {
  function setupAll() {
    const { mpk, msk } = setup();
    const key = keygenForAttributes(msk, ['a']);
    const { ciphertext } = encryptForPolicy(mpk, { attr: 'a' }, PT);
    return { mpk, msk, key, ciphertext };
  }
  const comp = (k: DecryptionKey, n: string) => k.attrs[n] as AttributeKey;

  it('encryptForPolicy refuses every degenerate master public key (identity h / f / Y, off-subgroup, inconsistent e(f,h) != e(g1,g2)) with PcaEncryptionError', () => {
    const { mpk } = setup();
    const other = setup().mpk;
    const bad: MasterPublicKey[] = [
      { ...mpk, h: b64(g2Infinity()) },
      { ...mpk, f: b64(g1Infinity()) },
      { ...mpk, egga: b64(new Uint8Array(576)) },
      { ...mpk, h: b64(g2OffSubgroup()) },
      { ...mpk, f: b64(g1OffSubgroup()) },
      { ...mpk, f: other.f }, // mixed keys: e(f,h) != e(g1,g2)
      { ...mpk, h: other.h },
    ];
    for (const m of bad) expect(() => encryptForPolicy(m, { attr: 'a' }, PT)).toThrow(PcaEncryptionError);
  });

  it('encryptForPolicy refuses garbage / wrong-length / missing master public key fields', () => {
    const { mpk } = setup();
    for (const h of [b64(new Uint8Array(96)), b64(new Uint8Array(10)), '', '!!', 'AAAA']) {
      expect(() => encryptForPolicy({ ...mpk, h }, { attr: 'a' }, PT)).toThrow(PcaEncryptionError);
    }
    expect(() => encryptForPolicy({ ...mpk, egga: b64(new Uint8Array(575)) }, { attr: 'a' }, PT)).toThrow(PcaEncryptionError);
    expect(() => encryptForPolicy(null as never, { attr: 'a' }, PT)).toThrow(PcaEncryptionError);
  });

  it('a key with an identity / off-subgroup / wrong-group / garbage point in D, D_j or D\'_j decrypts nothing and never throws', () => {
    const { key, ciphertext } = setupAll();
    const g1bad = [g1Infinity(), g1OffSubgroup(), g2Infinity(), new Uint8Array(48), bls.G2.ProjectivePoint.BASE.toRawBytes(true)];
    const g2bad = [g2Infinity(), g2OffSubgroup(), g1Infinity(), new Uint8Array(96), bls.G1.ProjectivePoint.BASE.toRawBytes(true)];
    for (const p of g1bad) {
      expect(decrypt({ ...key, d: b64(p) }, ciphertext)).toBeNull();
      expect(decrypt({ ...key, attrs: { a: { ...comp(key, 'a'), dj: b64(p) } } }, ciphertext)).toBeNull();
    }
    for (const p of g2bad) expect(decrypt({ ...key, attrs: { a: { ...comp(key, 'a'), dpj: b64(p) } } }, ciphertext)).toBeNull();
  });

  it('a ciphertext point C_0 / C_x / C\'_x that is the identity / off-subgroup / wrong-sized is refused without throwing', () => {
    const { key, ciphertext } = setupAll();
    for (const u of [g2Infinity(), g2OffSubgroup(), g1Infinity(), new Uint8Array(96)]) {
      const c0 = clone(ciphertext);
      c0.c0 = b64(u);
      const cx = clone(ciphertext);
      leaves(cx.kem)[0]!.c = b64(u);
      for (const c of [c0, cx]) {
        expect(() => decrypt(key, c)).not.toThrow();
        expect(decrypt(key, c)).toBeNull();
      }
    }
    for (const u of [g1Infinity(), g1OffSubgroup(), g2Infinity(), new Uint8Array(48)]) {
      const c = clone(ciphertext);
      leaves(c.kem)[0]!.cp = b64(u);
      expect(() => decrypt(key, c)).not.toThrow();
      expect(decrypt(key, c)).toBeNull();
    }
  });

  it('uncompressed (non-canonical) encodings are refused for keys and for ciphertext points: one encoding per element', () => {
    const { mpk, msk } = setupAll();
    const { ciphertext } = encryptForPolicy(mpk, { attr: 'a' }, PT);
    const k = keygenForAttributes(msk, ['a']);
    const unc1 = (s: string) => b64(bls.G1.ProjectivePoint.fromHex(Buffer.from(s, 'base64url')).toRawBytes(false));
    const unc2 = (s: string) => b64(bls.G2.ProjectivePoint.fromHex(Buffer.from(s, 'base64url')).toRawBytes(false));
    expect(decrypt(k, ciphertext)).toEqual(PT);
    expect(decrypt({ ...k, d: unc1(k.d) }, ciphertext)).toBeNull();
    expect(decrypt({ ...k, attrs: { a: { ...comp(k, 'a'), dj: unc1(comp(k, 'a').dj) } } }, ciphertext)).toBeNull();
    expect(decrypt({ ...k, attrs: { a: { ...comp(k, 'a'), dpj: unc2(comp(k, 'a').dpj) } } }, ciphertext)).toBeNull();
    const c = clone(ciphertext);
    c.c0 = unc2(c.c0);
    expect(decrypt(k, c)).toBeNull();
    const c2 = clone(ciphertext);
    leaves(c2.kem)[0]!.c = unc2(leaves(c2.kem)[0]!.c);
    expect(decrypt(k, c2)).toBeNull();
    const c3 = clone(ciphertext);
    leaves(c3.kem)[0]!.cp = unc1(leaves(c3.kem)[0]!.cp);
    expect(decrypt(k, c3)).toBeNull();
  });
});

describe('master secret key encoding', () => {
  it('rejects zero, wrong length, non-canonical (x + r) and garbage master scalars (alpha and beta)', () => {
    const { msk } = setup();
    const bads = [b64(new Uint8Array(32)), b64(numberToBytesBE(R, 32)), b64(new Uint8Array(31).fill(1)), '***', undefined];
    for (const x of bads) {
      expect(() => keygenForAttributes({ ...msk, alpha: x as string }, ['a'])).toThrow(PcaEncryptionError);
      expect(() => keygenForAttributes({ ...msk, beta: x as string }, ['a'])).toThrow(PcaEncryptionError);
    }
  });
  it('a non-canonical alias of a real master scalar (x + r) is refused, so each key has exactly one encoding', () => {
    const { msk } = setup();
    for (const f of ['alpha', 'beta'] as const) {
      const x = BigInt('0x' + Buffer.from(msk[f], 'base64url').toString('hex'));
      const alias: MasterSecretKey = { ...msk, [f]: b64(numberToBytesBE(x + R, 32)) };
      expect(() => keygenForAttributes(alias, ['a'])).toThrow(PcaEncryptionError);
    }
  });
});

describe('hash-to-curve domain properties', () => {
  it('distinct attributes map to distinct, non-identity, subgroup points; same attribute maps deterministically', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 40; i++) {
      const p = hashAttrToG1(`verb:${i}`);
      expect(p.equals(bls.G1.ProjectivePoint.ZERO)).toBe(false);
      expect(p.isTorsionFree()).toBe(true);
      seen.add(Buffer.from(p.toRawBytes(true)).toString('hex'));
    }
    expect(seen.size).toBe(40);
    expect(hashAttrToG1('x').equals(hashAttrToG1('x'))).toBe(true);
  });
  it('the attribute DST separates this scheme from the standard BLS-signature hash (a BLS signature is not a key component)', () => {
    const msg = new TextEncoder().encode('verb:read');
    const sigStyle = bls.G1.hashToCurve(msg, { DST: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_' });
    expect(hashAttrToG1('verb:read').equals(bls.G1.ProjectivePoint.fromAffine(sigStyle.toAffine()))).toBe(false);
  });
  it('rejects ill-formed UTF-16 attribute strings instead of aliasing them through U+FFFD', () => {
    expect(() => hashAttrToG1('\ud800')).toThrow();
    expect(() => hashAttrToG1('\ud801')).toThrow();
  });
});
