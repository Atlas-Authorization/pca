/** Mutation kills for @atlasauth/pca-aggsig: registered keys, raw BLS guards, aggregated-chain reasons, witness quorum. */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, unb64u } from '@atlasauth/pca';
import {
  KeyRegistry, RegisteredKey, aggregate, aggregateVerify, checkRegistered, fastAggregateVerify, isRegisteredKey, popProve, registerKey, keyGen, sign,
} from './bls';
import { aggregatePublicKeys, isCompressed, keyValidate, popVerify, verify, aggregateVerify as rawAggregateVerify, fastAggregateVerify as rawFast } from './core';
import {
  BLS_SUITE, MAX_CHAIN_DEPTH, aggregateChainSignatures, blsAttenuate, blsDelegate, blsPublicKey, capHash, mintBlsRoot, verifyAggregatedChain,
  type BlsCapability,
} from './chain';
import { aggregateWitnessCosignatures, cosignTreeHead, verifyAggregatedWitnessCosignatures, verifyWitnessCosignature } from './witness';

const te = new TextEncoder();
const err = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const kp = () => keyGen();
const G1ZERO = (() => { const o = new Uint8Array(48); o[0] = 0xc0; return o; })();
const G2ZERO = (() => { const o = new Uint8Array(96); o[0] = 0xc0; return o; })();
const regKey = (k: { publicKey: Uint8Array; secretKey: Uint8Array }) => {
  const r = registerKey(k.publicKey, popProve(k.secretKey));
  if (!r.ok) throw new Error(r.reason);
  return r.key;
};

describe('registered keys', () => {
  const k = kp();
  it('construction is private and instances are frozen', () => {
    expect(err(() => new RegisteredKey(Symbol('x'), k.publicKey)).message).toBe('RegisteredKey cannot be constructed directly; use registerKey(publicKey, pop)');
    const rk = regKey(k);
    expect(Object.isFrozen(rk)).toBe(true);
    expect(rk.bytes).toEqual(k.publicKey);
    expect(rk.bytes).not.toBe(rk.bytes);
  });
  it('registerKey reasons', () => {
    const pop = popProve(k.secretKey);
    expect(registerKey('x' as never, pop)).toEqual({ ok: false, reason: 'public key and proof of possession must be Uint8Arrays' });
    expect(registerKey(k.publicKey, 'x' as never)).toEqual({ ok: false, reason: 'public key and proof of possession must be Uint8Arrays' });
    expect(registerKey(G1ZERO, pop).ok).toBe(false);
    expect((registerKey(G1ZERO, pop) as { reason: string }).reason).toMatch(/fails KeyValidate/);
    expect(registerKey(k.publicKey, pop.subarray(0, 95))).toEqual({ ok: false, reason: 'proof of possession is not a 96-byte compressed G2 signature' });
    expect(registerKey(k.publicKey, popProve(kp().secretKey))).toEqual({ ok: false, reason: 'proof of possession does not verify for this key' });
    expect(registerKey(k.publicKey, pop).ok).toBe(true);
  });
  it('isRegisteredKey / checkRegistered / aggregateVerify only trust genuine registered keys', () => {
    const rk = regKey(k);
    expect(isRegisteredKey(rk)).toBe(true);
    for (const x of [null, 5, 'x', {}, { bytes: k.publicKey }, undefined]) expect(isRegisteredKey(x)).toBe(false);
    expect(checkRegistered(5)).toBe('keys must be an array of RegisteredKey');
    expect(checkRegistered([])).toBe('no keys');
    expect(checkRegistered([rk, {}])).toBe('key 1 is not a registered key: it was not admitted through registerKey (proof of possession)');
    expect(checkRegistered([rk])).toBeNull();
    const msg = te.encode('m');
    const s = sign(k.secretKey, msg);
    expect(aggregateVerify([rk], [msg], s)).toBe(true);
    // a look-alike object carrying valid key bytes is refused although the maths would pass
    expect(aggregateVerify([{ bytes: k.publicKey } as never], [msg], s)).toBe(false);
    expect(fastAggregateVerify([{ bytes: k.publicKey } as never], msg, s)).toBe(false);
    expect(aggregateVerify([], [], s)).toBe(false);
  });
  it('KeyRegistry lookups are type-safe and idempotent', () => {
    const reg = new KeyRegistry();
    expect(reg.size).toBe(0);
    expect(reg.register(k.publicKey, popProve(k.secretKey)).ok).toBe(true);
    expect(reg.register(k.publicKey, popProve(k.secretKey)).ok).toBe(true);
    expect(reg.register(kp().publicKey, new Uint8Array(96)).ok).toBe(false);
    expect(reg.size).toBe(1);
    expect(reg.has(k.publicKey)).toBe(true);
    expect(reg.has(kp().publicKey)).toBe(false);
    expect(reg.get(k.publicKey)).toBeDefined();
    expect(reg.get({ length: 48 } as never)).toBeUndefined();
    expect(reg.get(5 as never)).toBeUndefined();
    expect(reg.get(k.publicKey.subarray(0, 47))).toBeUndefined();
  });
});

describe('raw BLS guards', () => {
  const k = kp();
  const msg = te.encode('hello');
  const sig = sign(k.secretKey, msg);
  it('isCompressed demands a real Uint8Array of the right length with the flag bit', () => {
    expect(isCompressed(sig, 96)).toBe(true);
    expect(isCompressed(Array.from(sig), 96)).toBe(false);
    expect(isCompressed('x'.repeat(96), 96)).toBe(false);
    expect(isCompressed(sig.subarray(0, 95), 96)).toBe(false);
    expect(isCompressed(new Uint8Array(96), 96)).toBe(false);
    const cleared = sig.slice(); cleared[0]! &= 0x7f;
    expect(isCompressed(cleared, 96)).toBe(false);
    expect(isCompressed(new Uint8Array(97).fill(0x80), 96)).toBe(false);
  });
  it('aggregate / aggregatePublicKeys messages', () => {
    expect(err(() => aggregate([])).message).toBe('aggregate: need at least one signature');
    expect(err(() => aggregate([sig, new Uint8Array(96)])).message).toBe('aggregate: every signature must be a 96-byte compressed G2 point');
    expect(err(() => aggregatePublicKeys([])).message).toBe('aggregatePublicKeys: need at least one key');
  });
  it('verify family rejects malformed inputs without throwing', () => {
    const cleared = sig.slice(); cleared[0]! &= 0x7f;
    expect(verify(k.publicKey, msg, sig)).toBe(true);
    expect(verify(k.publicKey, msg, cleared)).toBe(false);
    expect(verify(G1ZERO, msg, G2ZERO)).toBe(false);
    expect(verify(k.publicKey.subarray(0, 47), msg, sig)).toBe(false);
    expect(rawAggregateVerify([k.publicKey], [msg], sig)).toBe(true);
    expect(rawAggregateVerify([], [], sig)).toBe(false);
    expect(rawAggregateVerify([k.publicKey], [], sig)).toBe(false);
    expect(rawAggregateVerify([k.publicKey, kp().publicKey], [msg], sig)).toBe(false);
    expect(rawAggregateVerify([G1ZERO], [msg], G2ZERO)).toBe(false);
    expect(rawAggregateVerify([k.publicKey], [msg], cleared)).toBe(false);
    expect(rawFast([], msg, sig)).toBe(false);
    expect(rawFast([k.publicKey], msg, sig)).toBe(true);
    expect(rawFast([G1ZERO], msg, G2ZERO)).toBe(false);
    // {P, -P}: each key validates, the aggregate is the identity
    const P = bls12_381.G1.ProjectivePoint.fromHex(k.publicKey);
    const neg = P.negate().toRawBytes(true);
    expect(keyValidate(k.publicKey) && keyValidate(neg)).toBe(true);
    expect(rawFast([k.publicKey, neg], msg, G2ZERO)).toBe(false);
    expect(popVerify(k.publicKey, new Uint8Array(96).fill(0xff))).toBe(false);
    expect(popVerify(k.publicKey, popProve(k.secretKey))).toBe(true);
    expect(keyValidate(k.publicKey.subarray(0, 47))).toBe(false);
    expect(keyValidate(G1ZERO)).toBe(false);
    expect(keyValidate(new Uint8Array(48).fill(0xff))).toBe(false);
  });
});

describe('aggregated capability chains: every refusal has its own reason', () => {
  const k0 = kp(), k1 = kp(), k2 = kp();
  const reg = new KeyRegistry();
  for (const k of [k0, k1, k2]) reg.register(k.publicKey, popProve(k.secretKey));
  const pub = (k: { secretKey: Uint8Array }) => blsPublicKey(k.secretKey);
  const root = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: pub(k0), holder: pub(k1), caveats: [{ type: 'a' }, { type: 'b' }] });
  const c1 = blsDelegate(root, pub(k2), [{ type: 'c' }], k1.secretKey);
  const chain = [root, c1];
  const agg = aggregateChainSignatures(chain);
  const V = (c: unknown[], a = agg, r: unknown = reg, exp?: string) => verifyAggregatedChain(c as never, a, r as never, exp);
  const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));
  // re-seal helper replicating the internal sealing so structurally-valid but dishonest hops can be built
  const forge = (body: { issuer: string; holder: string; caveats: unknown[]; parent?: string }, secret: Uint8Array): BlsCapability => {
    const digest = hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent ?? null });
    const d = unb64u(digest);
    const p = te.encode('atlas-pca/cap-bls/v1\0');
    const m = new Uint8Array(p.length + d.length); m.set(p); m.set(d, p.length);
    const cap: BlsCapability = { id: digest, issuer: body.issuer, holder: body.holder, caveats: body.caveats as never, body_digest: digest, sig: b64u(sign(secret, m)), suite: BLS_SUITE };
    if (body.parent !== undefined) cap.parent = body.parent;
    return cap;
  };

  it('accepts the honest chain and the 16-hop maximum, refuses 17', () => {
    expect(V(chain)).toEqual({ ok: true });
    expect(V(chain, agg, reg, pub(k0))).toEqual({ ok: true });
    let cur = c1;
    // hops 2.. delegate k2 -> k2 repeatedly
    const long = [root, c1];
    while (long.length < MAX_CHAIN_DEPTH) { cur = blsAttenuate(cur, [{ type: 'x' }], k2.secretKey); long.push(cur); }
    expect(V(long, aggregateChainSignatures(long))).toEqual({ ok: true });
    long.push(blsAttenuate(cur, [{ type: 'x' }], k2.secretKey));
    expect(V(long, aggregateChainSignatures(long))).toEqual({ ok: false, reason: 'chain too long (max 16 hops)' });
  });
  it('registry and shape', () => {
    for (const bad of [null, 5, {}, { get: 1 }]) expect(V(chain, agg, bad)).toEqual({ ok: false, reason: 'a KeyRegistry of proof-of-possession-verified keys is required' });
    expect(V([])).toEqual({ ok: false, reason: 'empty chain' });
    expect(V(null as never)).toEqual({ ok: false, reason: 'empty chain' });
    expect(err(() => aggregateChainSignatures([])).message).toBe('aggregateChainSignatures: empty chain');
    expect(err(() => aggregateChainSignatures(null as never)).message).toBe('aggregateChainSignatures: empty chain');
    expect(blsAttenuate(root, [], k1.secretKey).holder).toBe(root.holder);
  });
  it.each([
    ['null hop', (c: any[]) => { c[1] = null; }],
    ['string hop', (c: any[]) => { c[1] = 'x'; }],
    ['id', (c: any[]) => { c[1].id = 5; }],
    ['issuer', (c: any[]) => { c[1].issuer = 5; }],
    ['holder', (c: any[]) => { c[1].holder = 5; }],
    ['body_digest', (c: any[]) => { c[1].body_digest = 5; }],
    ['sig', (c: any[]) => { c[1].sig = 5; }],
    ['suite', (c: any[]) => { c[1].suite = 'ed25519'; }],
    ['parent', (c: any[]) => { c[1].parent = 5; }],
    ['caveats', (c: any[]) => { c[1].caveats = 'x'; }],
    ['caveat null', (c: any[]) => { c[1].caveats = [null]; }],
    ['caveat string', (c: any[]) => { c[1].caveats = ['x']; }],
    ['caveat array', (c: any[]) => { c[1].caveats = [[]]; }],
    ['caveat type', (c: any[]) => { c[1].caveats = [{ type: 5 }]; }],
    ['one bad caveat among good', (c: any[]) => { c[1].caveats = [{ type: 'a' }, { type: 5 }]; }],
  ])('malformed capability: %s', (_n, mut) => {
    const c = clone(chain) as any[];
    mut(c);
    expect(V(c)).toEqual({ ok: false, reason: 'hop 1: malformed capability' });
  });
  it('root rules', () => {
    expect(V([c1], aggregateChainSignatures([c1]))).toEqual({ ok: false, reason: 'hop 0: root must not have a parent' });
    expect(V(chain, agg, reg, pub(k2))).toEqual({ ok: false, reason: 'hop 0: root issuer is not the expected principal' });
  });
  it('body digest and id are bound', () => {
    const t = clone(chain) as any[];
    t[1].caveats = [...t[1].caveats, { type: 'z' }];
    expect(V(t)).toEqual({ ok: false, reason: 'hop 1: body digest mismatch' });
    const u = clone(chain) as any[];
    u[0].id = u[1].id;
    expect(V(u)).toEqual({ ok: false, reason: 'hop 0: body digest mismatch' });
    const w = clone(chain) as any[];
    w[0].body_digest = w[1].body_digest;
    expect(V(w)).toEqual({ ok: false, reason: 'hop 0: body digest mismatch' });
  });
  it('an unhashable body is "malformed body"', () => {
    const t = clone(root) as any;
    t.caveats = [{ type: 'a', n: Number.NaN }];
    expect(V([t], aggregateChainSignatures([root]))).toEqual({ ok: false, reason: 'hop 0: malformed body' });
  });
  it('issuer keys must be registered', () => {
    const r2 = new KeyRegistry();
    r2.register(k0.publicKey, popProve(k0.secretKey));
    expect(V(chain, agg, r2)).toEqual({ ok: false, reason: 'hop 1: issuer key has no verified proof of possession (not in the registry)' });
    const emptyReg = new KeyRegistry();
    expect(V(chain, agg, emptyReg)).toEqual({ ok: false, reason: 'hop 0: issuer key has no verified proof of possession (not in the registry)' });
  });
  it('malformed issuer key text', () => {
    const r = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: '!!!', holder: pub(k1), caveats: [] });
    expect(V([r], aggregateChainSignatures([r]))).toEqual({ ok: false, reason: 'hop 0: malformed issuer key' });
  });
  it('parent link, caveat prefix, and holder continuity', () => {
    const otherRoot = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: pub(k0), holder: pub(k1), caveats: [{ type: 'a' }, { type: 'q' }] });
    const grafted = blsDelegate(otherRoot, pub(k2), [{ type: 'c' }], k1.secretKey);
    expect(V([root, grafted], aggregateChainSignatures([root, grafted]))).toEqual({ ok: false, reason: 'hop 1: broken parent link' });
    const dropped = forge({ issuer: root.holder, holder: pub(k2), caveats: [{ type: 'a' }], parent: capHash(root) }, k1.secretKey);
    expect(V([root, dropped], aggregateChainSignatures([root, dropped]))).toEqual({ ok: false, reason: 'hop 1: drops parent caveat(s)' });
    const equalLen = forge({ issuer: root.holder, holder: pub(k2), caveats: [{ type: 'a' }, { type: 'b' }], parent: capHash(root) }, k1.secretKey);
    expect(V([root, equalLen], aggregateChainSignatures([root, equalLen]))).toEqual({ ok: true });
    const altered = forge({ issuer: root.holder, holder: pub(k2), caveats: [{ type: 'a' }, { type: 'B' }], parent: capHash(root) }, k1.secretKey);
    expect(V([root, altered], aggregateChainSignatures([root, altered]))).toEqual({ ok: false, reason: 'hop 1: caveat 1 altered or reordered' });
    const reordered = forge({ issuer: root.holder, holder: pub(k2), caveats: [{ type: 'b' }, { type: 'a' }], parent: capHash(root) }, k1.secretKey);
    expect(V([root, reordered], aggregateChainSignatures([root, reordered]))).toEqual({ ok: false, reason: 'hop 1: caveat 0 altered or reordered' });
    // an issuer that is not the parent's holder: sign as k2 though the link and registry are fine
    const wrongIssuer = forge({ issuer: pub(k2), holder: pub(k0), caveats: [{ type: 'a' }, { type: 'b' }], parent: capHash(root) }, k2.secretKey);
    expect(V([root, wrongIssuer], aggregateChainSignatures([root, wrongIssuer]))).toEqual({ ok: false, reason: "hop 1: issuer is not the parent's bound holder" });
  });
  it('the per-hop sig fields must be canonical and sum to the aggregate', () => {
    expect(V(chain, aggregateChainSignatures([root]))).toEqual({ ok: false, reason: 'hop sig fields do not sum to the aggregate signature' });
    expect(V(chain, agg.subarray(0, 95))).toEqual({ ok: false, reason: 'hop sig fields do not sum to the aggregate signature' });
    expect(V(chain, Uint8Array.from([...agg, 0]))).toEqual({ ok: false, reason: 'hop sig fields do not sum to the aggregate signature' });
    const flipped = agg.slice(); flipped[95]! ^= 1;
    expect(V(chain, flipped)).toEqual({ ok: false, reason: 'hop sig fields do not sum to the aggregate signature' });
    const t = clone(chain) as any[];
    t[1].sig = b64u(new Uint8Array(96));
    expect(V(t)).toEqual({ ok: false, reason: 'malformed hop sig' });
    const u = clone(chain) as any[];
    u[0].sig = '!!!';
    expect(V(u)).toEqual({ ok: false, reason: 'malformed hop sig' });
    // The standard-alphabet spelling is an alias only when the random signature's base64url text contains a
    // '-' or '_' (about 98% of draws); otherwise it IS the canonical text and must verify, so it is not an alias.
    const sig0 = chain[0]!.sig;
    const std = sig0.replace(/-/g, '+').replace(/_/g, '/');
    const aliases = [sig0 + '=', ...(std !== sig0 ? [std] : [])];
    for (const alias of aliases) {
      const v = clone(chain) as any[];
      v[0].sig = alias;
      const r = V(v);
      expect(r.ok).toBe(false);
    }
  });
  it('a valid-looking aggregate signed by the wrong key does not verify', () => {
    const forgedChild = forge({ issuer: root.holder, holder: pub(k2), caveats: [...root.caveats, { type: 'c' }], parent: capHash(root) }, k2.secretKey);
    expect(V([root, forgedChild], aggregateChainSignatures([root, forgedChild]))).toEqual({ ok: false, reason: 'aggregate signature does not verify over all hops' });
  });
});

describe('witness cosignatures', () => {
  const st = { size: 10, root: 'cm9vdA==', prev_root: 'cHJldg==', guardian_epoch: 1 };
  const w1 = kp(), w2 = kp();
  const c1 = cosignTreeHead(st, w1.secretKey), c2 = cosignTreeHead(st, w2.secretKey);
  it('single cosignature checks', () => {
    expect(verifyWitnessCosignature(st, c1)).toBe(true);
    for (const bad of [null, 5, 'x', { ...c1, suite: 'x' }, { ...c1, sig: '!!!' }, undefined]) expect(verifyWitnessCosignature(st, bad as never)).toBe(false);
    expect(verifyWitnessCosignature({ ...st, size: 11 }, c1)).toBe(false);
    expect(verifyWitnessCosignature({ size: 10, root: st.root, prev_root: st.prev_root }, cosignTreeHead({ size: 10, root: st.root, prev_root: st.prev_root, guardian_epoch: 0 }, w1.secretKey))).toBe(true);
  });
  it('aggregate refuses an empty or non-array set with its own message', () => {
    expect(err(() => aggregateWitnessCosignatures([])).message).toBe('aggregateWitnessCosignatures: empty set');
    expect(err(() => aggregateWitnessCosignatures(null as never)).message).toBe('aggregateWitnessCosignatures: empty set');
  });
  it('quorum verification: distinct registered witnesses only, never throws', () => {
    const k1 = regKey(w1), k2 = regKey(w2);
    const agg = aggregateWitnessCosignatures([c1, c2]);
    expect(verifyAggregatedWitnessCosignatures(st, [k1, k2], agg)).toBe(true);
    expect(verifyAggregatedWitnessCosignatures(st, [k2, k1], agg)).toBe(true);
    expect(verifyAggregatedWitnessCosignatures(st, [], agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, null as never, agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(st, [k1], agg)).toBe(false);
    // one witness aggregated with itself must not pass as two distinct witnesses
    const dup = aggregateWitnessCosignatures([c1, c1]);
    expect(verifyAggregatedWitnessCosignatures(st, [k1, k1], dup)).toBe(false);
    // statement that cannot be canonicalised fails closed
    expect(verifyAggregatedWitnessCosignatures({ ...st, size: Number.NaN }, [k1, k2], agg)).toBe(false);
    expect(verifyAggregatedWitnessCosignatures(null as never, [k1, k2], agg)).toBe(false);
  });
});
