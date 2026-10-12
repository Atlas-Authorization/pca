/** Mutation kills for @atlasauth/pca-bbs: input limits and messages, reject reasons, index handling, and credential pinning. */
import { describe, expect, it } from 'vitest';
import { b64u, unb64u } from '@atlasauth/pca';
import {
  MAX_MESSAGES, R, createGenerators, generateKeyPair, keyGen, proofGen, proofVerifyDetailed, proofVerify, sign, skFromBytes, skToBytes, skToPk,
  verifyDetailed,
  type VerifyResult,
} from './bbs';

/** The rejection reason of a verify result (undefined when it verified). */
const why = (r: VerifyResult): string | undefined => (r.ok ? undefined : r.reason);
import {
  capabilityAttributes, issueCapabilityCredential, presentCredential, verifyCredential, verifyPresentation,
  type BBSPresentation,
} from './credential';

const te = new TextEncoder();
const msgs = (n: number) => Array.from({ length: n }, (_, i) => te.encode(`m${i}`));
const err = (f: () => unknown): Error => {
  try { f(); } catch (e) { return e as Error; }
  throw new Error('no throw');
};
const be32 = (v: bigint) => { const o = new Uint8Array(32); for (let i = 31, x = v; i >= 0; i--, x >>= 8n) o[i] = Number(x & 0xffn); return o; };
const { sk, pk } = generateKeyPair();
const H0 = new Uint8Array(0);
const sig = sign(sk, pk, H0, msgs(4));
const G1ZERO = (() => { const o = new Uint8Array(48); o[0] = 0xc0; return o; })();
const G2ZERO = (() => { const o = new Uint8Array(96); o[0] = 0xc0; return o; })();
const cat = (...p: Uint8Array[]) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };

describe('core limits and messages', () => {
  it('createGenerators bounds', () => {
    expect(createGenerators(0)).toEqual([]);
    for (const c of [-1, 1.5, NaN, Infinity]) expect(err(() => createGenerators(c)).message).toBe('bbs: generator count must be a non-negative integer');
    expect(err(() => createGenerators(MAX_MESSAGES + 2)).message).toBe(`bbs: at most ${MAX_MESSAGES} messages are supported`);
    expect(createGenerators(MAX_MESSAGES + 1)).toHaveLength(MAX_MESSAGES + 1);
  });
  it('keyGen / skFromBytes bounds', () => {
    expect(err(() => keyGen(new Uint8Array(31))).message).toBe('bbs: key material must be at least 32 octets');
    expect(() => keyGen(new Uint8Array(32).fill(1))).not.toThrow();
    expect(err(() => keyGen(new Uint8Array(32).fill(1), new Uint8Array(65536))).message).toBe('bbs: key info must be at most 65535 octets');
    expect(() => keyGen(new Uint8Array(32).fill(1), new Uint8Array(65535))).not.toThrow();
    expect(err(() => skFromBytes(new Uint8Array(31))).message).toBe('bbs: SK must be 32 octets');
    expect(err(() => skFromBytes(new Uint8Array(33))).message).toBe('bbs: SK must be 32 octets');
    expect(err(() => skFromBytes(new Uint8Array(32))).message).toBe('bbs: SK out of range');
    expect(err(() => skFromBytes(be32(R))).message).toBe('bbs: SK out of range');
    expect(skFromBytes(skToBytes(sk))).toBe(sk);
  });
  it('skToPk(0) is the group identity encoding (no throw)', () => {
    expect(skToPk(0n)).toEqual(G2ZERO);
  });
});

describe('signature parsing surfaces through proofGen and verifyDetailed', () => {
  const A = sig.subarray(0, 48);
  it('proofGen error messages', () => {
    expect(err(() => proofGen(pk, sig.subarray(0, 79), H0, H0, msgs(4), [0])).message).toBe('bbs: signature must be 80 octets');
    expect(err(() => proofGen(pk, cat(G1ZERO, be32(5n)), H0, H0, msgs(4), [0])).message).toBe('bbs: signature point A is the identity');
    expect(err(() => proofGen(pk, cat(A, be32(0n)), H0, H0, msgs(4), [0])).message).toBe('bbs: signature scalar e out of range');
    expect(err(() => proofGen(pk, cat(A, be32(R)), H0, H0, msgs(4), [0])).message).toBe('bbs: signature scalar e out of range');
    expect(err(() => proofGen(pk, sig, H0, H0, msgs(4), [4])).message).toBe('bbs: disclosed index 4 out of range [0, 4)');
    expect(err(() => proofGen(pk, sig, H0, H0, msgs(4), [-1])).message).toBe('bbs: disclosed index -1 out of range [0, 4)');
    expect(err(() => proofGen(pk, sig, H0, H0, msgs(4), [1.5])).message).toBe('bbs: disclosed index 1.5 out of range [0, 4)');
    expect(err(() => proofGen(pk, sig, H0, H0, msgs(4), [1, 1])).message).toBe('bbs: duplicate disclosed index 1');
  });
  it('verifyDetailed reasons', () => {
    expect(verifyDetailed(pk, sig, H0, msgs(4))).toEqual({ ok: true });
    expect(verifyDetailed(pk, sig.subarray(0, 79), H0, msgs(4))).toEqual({ ok: false, reason: 'malformed-signature' });
    expect(verifyDetailed(pk, cat(G1ZERO, be32(5n)), H0, msgs(4))).toEqual({ ok: false, reason: 'malformed-signature' });
    expect(verifyDetailed(pk, cat(A, be32(0n)), H0, msgs(4))).toEqual({ ok: false, reason: 'malformed-signature' });
    expect(verifyDetailed(new Uint8Array(96), sig, H0, msgs(4))).toEqual({ ok: false, reason: 'malformed-public-key' });
    expect(verifyDetailed(G2ZERO, sig, H0, msgs(4))).toEqual({ ok: false, reason: 'malformed-public-key' });
    expect(verifyDetailed(pk, sig, H0, msgs(3))).toEqual({ ok: false, reason: 'pairing-mismatch' });
  });
  it('message-count limit: 1024 is processed, 1025 is refused', () => {
    expect(verifyDetailed(pk, sig, H0, msgs(MAX_MESSAGES))).toEqual({ ok: false, reason: 'pairing-mismatch' });
    expect(verifyDetailed(pk, sig, H0, msgs(MAX_MESSAGES + 1))).toEqual({ ok: false, reason: 'disclosed-length-mismatch' });
  });
});

describe('proofs', () => {
  const all = [0, 1, 2, 3];
  const proof4 = proofGen(pk, sig, H0, H0, msgs(4), all); // U = 0: 272 octets
  const FIXED = 272;
  it('valid proof; wrong pk and mismatched lengths are named', () => {
    expect(proofVerifyDetailed(pk, proof4, H0, H0, msgs(4), all)).toEqual({ ok: true });
    expect(proofVerifyDetailed(pk, proof4, H0, H0, msgs(3), all)).toEqual({ ok: false, reason: 'disclosed-length-mismatch' });
    expect(proofVerifyDetailed(new Uint8Array(96), proof4, H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'malformed-public-key' });
    expect(proofVerifyDetailed(G2ZERO, proof4, H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'malformed-public-key' });
    expect(proofVerifyDetailed(pk, proof4, H0, H0, msgs(4), [0, 1, 2, 2])).toEqual({ ok: false, reason: 'invalid-disclosed-indexes' });
    expect(proofVerifyDetailed(pk, proof4, H0, H0, msgs(4), [0, 1, 2, 4])).toEqual({ ok: false, reason: 'invalid-disclosed-indexes' });
  });
  it('proof length / scalar / identity parsing is malformed-proof', () => {
    expect(why(proofVerifyDetailed(pk, proof4.subarray(0, FIXED - 32), H0, H0, msgs(4), all))).toBe('malformed-proof');
    expect(why(proofVerifyDetailed(pk, proof4.subarray(0, FIXED - 1), H0, H0, msgs(4), all))).toBe('malformed-proof');
    expect(why(proofVerifyDetailed(pk, cat(proof4, new Uint8Array(1)), H0, H0, msgs(4), all))).toBe('malformed-proof');
    const withC = (c: bigint) => cat(proof4.subarray(0, FIXED - 32), be32(c));
    expect(proofVerifyDetailed(pk, withC(R), H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'malformed-proof' });
    expect(proofVerifyDetailed(pk, withC(R - 1n), H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'challenge-mismatch' });
    // a zero challenge scalar is a legal encoding: the multiplication by zero must not throw
    expect(proofVerifyDetailed(pk, withC(0n), H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'challenge-mismatch' });
    expect(why(proofVerifyDetailed(pk, cat(G1ZERO, proof4.subarray(48)), H0, H0, msgs(4), all))).toBe('malformed-proof');
    expect(why(proofVerifyDetailed(pk, cat(proof4.subarray(0, 48), G1ZERO, proof4.subarray(96)), H0, H0, msgs(4), all))).toBe('malformed-proof');
    expect(why(proofVerifyDetailed(pk, cat(proof4.subarray(0, 96), G1ZERO, proof4.subarray(144)), H0, H0, msgs(4), all))).toBe('malformed-proof');
  });
  it('zero response scalars do not throw', () => {
    const z = (off: number) => { const p = proof4.slice(); p.set(new Uint8Array(32), off); return p; };
    for (const off of [144, 176, 208]) expect(proofVerifyDetailed(pk, z(off), H0, H0, msgs(4), all)).toEqual({ ok: false, reason: 'challenge-mismatch' });
  });
  it('1024 total messages are parsed, 1025 are malformed-proof', () => {
    const big = (u: number) => cat(proof4.subarray(0, FIXED - 32), new Uint8Array(32 * u), proof4.subarray(FIXED - 32));
    expect(why(proofVerifyDetailed(pk, big(MAX_MESSAGES), H0, H0, [], []))).toBe('challenge-mismatch');
    expect(proofVerifyDetailed(pk, big(MAX_MESSAGES + 1), H0, H0, [], [])).toEqual({ ok: false, reason: 'malformed-proof' });
  });
  it('a proof over a bogus signature passes the challenge but fails the pairing', () => {
    const bogus = cat(sig.subarray(0, 48), be32(7n));
    const p = proofGen(pk, bogus, H0, H0, msgs(4), [0]);
    expect(proofVerifyDetailed(pk, p, H0, H0, [msgs(4)[0]!], [0])).toEqual({ ok: false, reason: 'pairing-mismatch' });
  });
  it('disclosed indexes are canonicalised: any order, numeric (not lexicographic) sort', () => {
    const m = msgs(12);
    const s12 = sign(sk, pk, H0, m);
    const idx = [10, 2, 1, 9, 0];
    const p = proofGen(pk, s12, H0, H0, m, idx);
    expect(proofVerify(pk, p, H0, H0, idx.map((i) => m[i]!), idx)).toBe(true);
    const sorted = [0, 1, 2, 9, 10];
    expect(proofVerify(pk, p, H0, H0, sorted.map((i) => m[i]!), sorted)).toBe(true);
    const p2 = proofGen(pk, s12, H0, H0, m, [2, 0]);
    expect(proofVerify(pk, p2, H0, H0, [m[2]!, m[0]!], [2, 0])).toBe(true);
  });
});

describe('credential layer', () => {
  const cap = { issuer: 'iss-key', holder: 'holder-key', caveats: [{ type: 'scope', actions: ['a'] }] };
  const kp = generateKeyPair();
  const cred = issueCapabilityCredential(cap as never, { sk: kp.sk, pk: kp.pk });
  const ph = te.encode('ctx');
  const pres = presentCredential(cred, { disclose: ['iss', 'sub'], presentationHeader: ph });
  const clone = (): BBSPresentation => JSON.parse(JSON.stringify(pres));
  it('capability without a caveat array has only issuer and holder', () => {
    expect(capabilityAttributes({ issuer: 'i', holder: 'h', caveats: undefined as never })).toEqual([
      { index: 0, name: 'iss', value: 'i' }, { index: 1, name: 'sub', value: 'h' },
    ]);
  });
  it('attribute encoding refuses non-strings and NUL names with exact messages', () => {
    expect(err(() => issueCapabilityCredential({ issuer: 5 as never, holder: 'h', caveats: [] }, { sk: kp.sk, pk: kp.pk })).message).toBe('attribute name and value must be strings');
    const bad = JSON.parse(JSON.stringify(cred));
    bad.attributes[0].name = 5;
    expect(err(() => presentCredential(bad, { disclose: ['sub'] })).message).toBe('attribute name and value must be strings');
    bad.attributes[0].name = 'a\0b';
    bad.attributes[0].value = 'x';
    expect(err(() => presentCredential(bad, { disclose: ['sub'] })).message).toBe('attribute name must not contain NUL');
    const badv = JSON.parse(JSON.stringify(cred));
    badv.attributes[1].value = 9;
    expect(err(() => presentCredential(badv, { disclose: ['iss'] })).message).toBe('attribute name and value must be strings');
    expect(verifyCredential(badv)).toBe(false);
  });
  it('verifyCredential never throws on undecodable fields', () => {
    for (const f of ['issuerPublicKey', 'header', 'signature'] as const) expect(verifyCredential({ ...cred, [f]: '!!!' })).toBe(false);
    expect(verifyCredential({ ...cred, attributes: null as never })).toBe(false);
    expect(verifyCredential(cred)).toBe(true);
  });
  it('presentCredential names every unknown attribute, joined by ", "', () => {
    expect(err(() => presentCredential(cred, { disclose: ['iss', 'nope'] })).message).toBe('presentCredential: unknown attribute(s): nope');
    expect(err(() => presentCredential(cred, { disclose: ['x', 'y'] })).message).toBe('presentCredential: unknown attribute(s): x, y');
  });
  it('pinned issuer key must equal the key the presentation claims', () => {
    expect(verifyPresentation(pres, { pk: kp.pk, presentationHeader: ph })).toBe(true);
    const t = clone();
    t.issuerPublicKey = b64u(generateKeyPair().pk);
    expect(verifyPresentation(t, { pk: kp.pk, presentationHeader: ph })).toBe(false);
  });
  it('pinned presentation header is authoritative and the echoed field must match it when non-empty', () => {
    const t = clone();
    t.presentationHeader = 'AAAA';
    expect(verifyPresentation(t, { presentationHeader: ph })).toBe(false);
    expect(verifyPresentation(pres, { presentationHeader: ph })).toBe(true);
    const noph = presentCredential(cred, { disclose: ['iss'] });
    const t2 = JSON.parse(JSON.stringify(noph));
    t2.presentationHeader = 'AAAA';
    expect(verifyPresentation(t2, { presentationHeader: new Uint8Array(0) })).toBe(true);
    expect(verifyPresentation(t2)).toBe(false);
  });
  it('an undecodable presentationHeader field fails closed', () => {
    const t = clone();
    t.presentationHeader = '!!!';
    expect(verifyPresentation(t)).toBe(false);
    const u = clone();
    u.issuerPublicKey = '!!!';
    expect(verifyPresentation(u)).toBe(false);
  });
  it('malformed presentation structure fails closed', () => {
    for (const mut of [(t: Record<string, unknown>) => { t.disclosed = null; }, (t: Record<string, unknown>) => { t.disclosed = [{ index: 0 }]; }]) {
      const t = clone() as unknown as Record<string, unknown>;
      mut(t);
      expect(verifyPresentation(t as never)).toBe(false);
    }
  });
  it('asserted disclosure must equal the shown one (order-insensitive, exact)', () => {
    const [a, b] = pres.disclosed as [typeof pres.disclosed[number], typeof pres.disclosed[number]];
    expect(verifyPresentation(pres, { disclosed: [a, b] })).toBe(true);
    expect(verifyPresentation(pres, { disclosed: [b, a] })).toBe(true);
    expect(verifyPresentation(pres, { disclosed: [a] })).toBe(false);
    expect(verifyPresentation(pres, { disclosed: [a, b, a] })).toBe(false);
    expect(verifyPresentation(pres, { disclosed: [a, { ...b, value: 'other' }] })).toBe(false);
    expect(verifyPresentation(pres, { disclosed: [a, { ...b, name: 'other' }] })).toBe(false);
    expect(verifyPresentation(pres, { disclosed: [a, { ...b, index: 7 }] })).toBe(false);
    // shown values tampered while the verifier asserts the true ones
    const t = clone();
    t.disclosed[1] = { ...t.disclosed[1]!, value: 'tampered' };
    expect(verifyPresentation(t, { disclosed: [a, b] })).toBe(false);
    expect(verifyPresentation(t)).toBe(false);
    // sort stability of the comparison key: two entries sharing a prefix
    const x = { index: 0, name: 'a', value: 'b' };
    const y = { index: 0, name: 'a', value: 'bb' };
    expect(verifyPresentation({ ...pres, disclosed: [x, y] }, { disclosed: [y, x] })).toBe(false); // verification fails, never throws
  });
  it('a disclosed index must be below the stated message count', () => {
    const t = clone();
    t.messageCount = 1;
    expect(verifyPresentation(t)).toBe(false);
    const u = clone();
    u.messageCount = 2;
    expect(verifyPresentation(u)).toBe(true);
    expect(verifyPresentation(pres)).toBe(true);
  });
  it('unb64u import is used for round trips', () => {
    expect(unb64u(b64u(Uint8Array.of(1, 2, 3)))).toEqual(Uint8Array.of(1, 2, 3));
  });
});
