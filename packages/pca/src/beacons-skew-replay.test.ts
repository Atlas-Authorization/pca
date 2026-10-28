// Liveness beacons: clock skew and replay, with exact outcomes. Every boundary is asserted on both sides, the order of the
// checks is pinned (the first failing check names the reason), and replay protection is exercised through restarts and a
// failing store.
import { describe, expect, it } from 'vitest';
import {
  BEACON_CLOCK_SKEW_MS,
  BEACON_EPOCH_MS,
  BEACON_MAX_VALIDITY_MS,
  GLOBAL_SCOPE,
  type LivenessBeacon,
  acceptBeacon,
  createBeaconAcceptor,
  isFrozenLiveness,
  issueLivenessBeacon,
  livenessBeaconMessage,
  verifyLivenessBeacon,
} from './beacons';
import { b64u } from './hash';
import { createMemoryDurableKv, openDurableState, type DurableKv } from './durable-state';
import { encodeKey, generateKeyPair, sign } from './keys';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const I = generateKeyPair();
const issuer = encodeKey(I.publicKey);
const T0 = 1_800_000_000_000; // divisible by BEACON_EPOCH_MS, so epochs are easy to reason about
const chk = (now: number, o: Record<string, unknown> = {}) => ({ issuers: [issuer], now, instance: 'ins', ...o });
const mk = (o: Partial<Parameters<typeof issueLivenessBeacon>[0]> = {}) => issueLivenessBeacon({ issuerSecret: I.secretKey, instance: 'ins', seq: 1, issuedAt: T0, ...o });
/** Sign an arbitrary body (the issuer function refuses out-of-range windows; a hostile or buggy issuer would not). */
function forge(over: Partial<Omit<LivenessBeacon, 'sig'>>): LivenessBeacon {
  const body = { v: 2 as const, instance: 'ins', scope: GLOBAL_SCOPE, epoch: Math.floor(T0 / BEACON_EPOCH_MS), seq: 1, issued_at: T0, not_after: T0 + 300_000, issuer, ...over };
  return { ...body, sig: b64u(sign(I.secretKey, livenessBeaconMessage(body))) };
}

describe('beacon clock skew: both sides of every boundary', () => {
  it('the future-skew allowance is exactly 30 000 ms', () => {
    expect(BEACON_CLOCK_SKEW_MS).toBe(30_000);
    const b = mk();
    expect(verifyLivenessBeacon(b, chk(T0 - 30_000))).toEqual({ ok: true });
    expect(verifyLivenessBeacon(b, chk(T0 - 30_001))).toEqual({ ok: false, reason: 'not yet valid' });
  });
  it('a beacon is valid through not_after inclusive and expired one millisecond later', () => {
    const b = mk({ validityMs: 60_000 });
    expect(verifyLivenessBeacon(b, chk(T0 + 60_000))).toEqual({ ok: true });
    expect(verifyLivenessBeacon(b, chk(T0 + 60_001))).toEqual({ ok: false, reason: 'expired' });
  });
  it('the hard validity cap is exactly one hour: the issuer refuses more, a forged longer one is refused by the verifier', () => {
    expect(BEACON_MAX_VALIDITY_MS).toBe(3_600_000);
    const atCap = mk({ validityMs: BEACON_MAX_VALIDITY_MS });
    expect(atCap.not_after - atCap.issued_at).toBe(3_600_000);
    expect(verifyLivenessBeacon(atCap, chk(T0 + 3_600_000))).toEqual({ ok: true });
    expect(() => mk({ validityMs: BEACON_MAX_VALIDITY_MS + 1 })).toThrow(RangeError);
    expect(() => mk({ validityMs: 0 })).toThrow(RangeError);
    expect(() => mk({ validityMs: -5 })).toThrow(RangeError);
    expect(() => mk({ validityMs: 1.5 })).toThrow(RangeError);
    expect(verifyLivenessBeacon(forge({ not_after: T0 + 3_600_001 }), chk(T0))).toEqual({ ok: false, reason: 'validity exceeds the hard maximum' });
    expect(verifyLivenessBeacon(forge({ not_after: T0 }), chk(T0))).toEqual({ ok: false, reason: 'validity exceeds the hard maximum' }); // zero length
    expect(verifyLivenessBeacon(forge({ not_after: T0 - 1 }), chk(T0))).toEqual({ ok: false, reason: 'validity exceeds the hard maximum' });
  });
  it('the epoch is floor(issued_at / 60 000): one millisecond across the boundary changes it', () => {
    expect(mk({ issuedAt: T0 + BEACON_EPOCH_MS - 1 }).epoch).toBe(T0 / BEACON_EPOCH_MS);
    expect(mk({ issuedAt: T0 + BEACON_EPOCH_MS }).epoch).toBe(T0 / BEACON_EPOCH_MS + 1);
    expect(verifyLivenessBeacon(forge({ epoch: T0 / BEACON_EPOCH_MS + 1 }), chk(T0))).toEqual({ ok: false, reason: 'epoch does not match issued_at' });
    expect(verifyLivenessBeacon(forge({ epoch: T0 / BEACON_EPOCH_MS - 1 }), chk(T0))).toEqual({ ok: false, reason: 'epoch does not match issued_at' });
  });
  it('a clock that runs fast (skew inside the allowance) accepts a beacon that is not yet issued; one that runs slow expires early', () => {
    const b = mk({ validityMs: 120_000 });
    expect(verifyLivenessBeacon(b, chk(T0 - 29_999)).ok).toBe(true); // verifier 29.999 s behind the issuer
    expect(verifyLivenessBeacon(b, chk(T0 + 120_000)).ok).toBe(true);
    expect(verifyLivenessBeacon(b, chk(T0 + 120_001)).ok).toBe(false); // verifier ahead of the issuer by 1 ms past not_after
  });
  it('liveness freezes exactly when the last valid beacon lapses and thaws on a fresh one', () => {
    const b1 = mk({ validityMs: 60_000, seq: 1 });
    const b2 = mk({ validityMs: 60_000, seq: 2, issuedAt: T0 + 60_000 });
    expect(isFrozenLiveness([b1], chk(T0 + 60_000))).toBe(false);
    expect(isFrozenLiveness([b1], chk(T0 + 60_001))).toBe(true);
    expect(isFrozenLiveness([b1, b2], chk(T0 + 60_001))).toBe(false);
    expect(isFrozenLiveness([b1, b2], chk(T0 + 120_001))).toBe(true);
    expect(isFrozenLiveness([b2], chk(T0 + 29_999))).toBe(true); // b2 is not valid until 30 s before its issue time... which is T0 + 30 000
    expect(isFrozenLiveness([b2], chk(T0 + 30_000))).toBe(false);
  });
});

describe('beacon verification: the order of checks names the first failure', () => {
  const good = mk({ scope: 'g1', validityMs: 60_000 });
  it('instance, issuer pin, signature, window shape, validity, epoch, not-yet-valid, expiry, scope: in this order', () => {
    const wrongEverything = forge({ instance: 'other', issuer: encodeKey(generateKeyPair().publicKey), seq: -1, not_after: T0, epoch: 0, scope: 'g9' });
    expect(verifyLivenessBeacon(wrongEverything, chk(T0 + 10_000_000, { scope: 'g1' }))).toEqual({ ok: false, reason: 'wrong instance' });
    expect(verifyLivenessBeacon({ ...wrongEverything, instance: 'ins' }, chk(T0 + 10_000_000, { scope: 'g1' }))).toEqual({ ok: false, reason: 'issuer not pinned' });
    expect(verifyLivenessBeacon({ ...good, sig: good.sig.replace(/^./, (x) => (x === 'A' ? 'B' : 'A')) }, chk(T0 + 10_000_000, { scope: 'g2' }))).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyLivenessBeacon(forge({ seq: -1 }), chk(T0))).toEqual({ ok: false, reason: 'malformed window' });
    for (const bad of [{ seq: 1.5 }, { issued_at: T0 + 0.5 }, { epoch: 1.5 }, { not_after: T0 + 1.5 }] as const) {
      expect(verifyLivenessBeacon(forge(bad as never), chk(T0)), JSON.stringify(bad)).toEqual({ ok: false, reason: 'malformed window' });
    }
    expect(verifyLivenessBeacon(forge({ not_after: T0 + 4_000_000, epoch: 5 }), chk(T0 + 99_000_000, { scope: 'g2' }))).toEqual({ ok: false, reason: 'validity exceeds the hard maximum' });
    expect(verifyLivenessBeacon(forge({ epoch: 5 }), chk(T0 + 99_000_000, { scope: 'g2' }))).toEqual({ ok: false, reason: 'epoch does not match issued_at' });
    expect(verifyLivenessBeacon(good, chk(T0 - 31_000, { scope: 'g2' }))).toEqual({ ok: false, reason: 'not yet valid' });
    expect(verifyLivenessBeacon(good, chk(T0 + 99_000, { scope: 'g2' }))).toEqual({ ok: false, reason: 'expired' });
    expect(verifyLivenessBeacon(good, chk(T0 + 1, { scope: 'g2' }))).toEqual({ ok: false, reason: 'scope not covered' });
    expect(verifyLivenessBeacon(good, chk(T0 + 1, { scope: 'g1' }))).toEqual({ ok: true });
  });
  it('scope: a global beacon covers every grant, a scoped one only its own, an unscoped check accepts any scope', () => {
    const global = mk({ validityMs: 60_000 });
    const scoped = mk({ scope: 'g1', validityMs: 60_000 });
    expect(global.scope).toBe('*');
    expect(verifyLivenessBeacon(global, chk(T0, { scope: 'anything' }))).toEqual({ ok: true });
    expect(verifyLivenessBeacon(scoped, chk(T0, { scope: 'g1' }))).toEqual({ ok: true });
    expect(verifyLivenessBeacon(scoped, chk(T0, { scope: 'g2' }))).toEqual({ ok: false, reason: 'scope not covered' });
    expect(verifyLivenessBeacon(scoped, chk(T0))).toEqual({ ok: true });
  });
  it('hostile input never throws and is reported as malformed', () => {
    for (const bad of [null, undefined, 'b', 7, [], {}, { v: 1 }, { ...good, v: 3 }, { ...good, alg: 'bogus' }]) {
      expect(verifyLivenessBeacon(bad as never, chk(T0)), JSON.stringify(bad)).toEqual({ ok: false, reason: 'malformed beacon' });
    }
    expect(() => verifyLivenessBeacon(good, null as never)).not.toThrow();
    expect(verifyLivenessBeacon(good, null as never)).toEqual({ ok: false, reason: 'malformed beacon' });
  });
  it('an unpinned issuer set freezes everything; two issuers: either one keeps the agents live', () => {
    const other = generateKeyPair();
    const a = mk({ validityMs: 60_000 });
    const bBeacon = issueLivenessBeacon({ issuerSecret: other.secretKey, instance: 'ins', seq: 1, issuedAt: T0, validityMs: 60_000 });
    expect(isFrozenLiveness([a], chk(T0, { issuers: [] }))).toBe(true);
    expect(isFrozenLiveness([a], chk(T0, { issuers: [encodeKey(other.publicKey)] }))).toBe(true);
    expect(isFrozenLiveness([a, bBeacon], chk(T0, { issuers: [issuer, encodeKey(other.publicKey)] }))).toBe(false);
    expect(isFrozenLiveness([bBeacon], chk(T0, { issuers: [issuer, encodeKey(other.publicKey)] }))).toBe(false);
  });
  it('a beacon of another instance never keeps this instance live (cross-instance replay)', () => {
    const foreign = mk({ validityMs: 60_000 });
    expect(isFrozenLiveness([foreign], chk(T0 + 1, { instance: 'ins-2' }))).toBe(true);
    expect(isFrozenLiveness([foreign], chk(T0 + 1))).toBe(false);
  });
});

describe('beacon replay: acceptBeacon (pure comparison)', () => {
  it('only a strictly higher seq replaces the stored beacon', () => {
    const b5 = mk({ seq: 5 });
    expect(acceptBeacon(null, b5)).toEqual({ ok: true });
    expect(acceptBeacon(undefined, b5)).toEqual({ ok: true });
    expect(acceptBeacon({ seq: 4 }, b5)).toEqual({ ok: true });
    expect(acceptBeacon({ seq: 5 }, b5)).toEqual({ ok: false, reason: 'replayed beacon: seq 5 <= 5' });
    expect(acceptBeacon({ seq: 6 }, b5)).toEqual({ ok: false, reason: 'replayed beacon: seq 5 <= 6' });
    expect(acceptBeacon({ seq: 0 }, mk({ seq: 0 }))).toEqual({ ok: false, reason: 'replayed beacon: seq 0 <= 0' });
    expect(acceptBeacon(null, mk({ seq: 0 }))).toEqual({ ok: true });
  });
  it('a malformed candidate is refused, never a TypeError', () => {
    for (const bad of [null, undefined, 'x', 3, {}, { seq: -1 }, { seq: 1.5 }, { seq: '2' }, { seq: Number.NaN }, { seq: 2 ** 53 }]) {
      expect(acceptBeacon({ seq: 1 }, bad as never), JSON.stringify(bad)).toEqual({ ok: false, reason: 'malformed beacon' });
    }
  });
});

describe('beacon replay: durable acceptor (survives restarts, fails closed)', () => {
  const issue = (seq: number, o: Partial<Parameters<typeof issueLivenessBeacon>[0]> = {}) => mk({ seq, validityMs: 120_000, ...o });
  it('accepts a fresh seq, refuses an equal or lower one, per (instance, scope, issuer)', async () => {
    const acc = createBeaconAcceptor(createMemoryDurableKv());
    const c = chk(T0 + 1);
    expect(await acc.accept(issue(3), c)).toEqual({ ok: true });
    expect(await acc.accept(issue(3), c)).toEqual({ ok: false, reason: 'replayed beacon: seq 3 <= 3' });
    expect(await acc.accept(issue(2), c)).toEqual({ ok: false, reason: 'replayed beacon: seq 2 <= 3' });
    expect(await acc.accept(issue(4), c)).toEqual({ ok: true });
    // other tuples are independent
    expect(await acc.accept(issue(1, { scope: 'g1' }), c)).toEqual({ ok: true });
    expect(await acc.accept(issue(1, { instance: 'ins-2' }), chk(T0 + 1, { instance: 'ins-2' }))).toEqual({ ok: true });
    const second = generateKeyPair();
    expect(await acc.accept(issueLivenessBeacon({ issuerSecret: second.secretKey, instance: 'ins', seq: 1, issuedAt: T0, validityMs: 120_000 }), chk(T0 + 1, { issuers: [encodeKey(second.publicKey)] }))).toEqual({ ok: true });
    expect(await acc.accept(issue(2, { scope: 'g1' }), c)).toEqual({ ok: true });
    expect(await acc.accept(issue(2, { scope: 'g1' }), c)).toEqual({ ok: false, reason: 'replayed beacon: seq 2 <= 2' });
  });
  it('a beacon that fails verification is refused with its own reason and records nothing', async () => {
    const kv = createMemoryDurableKv();
    const acc = createBeaconAcceptor(kv);
    expect(await acc.accept(issue(9), chk(T0 + 999_999))).toEqual({ ok: false, reason: 'expired' });
    expect(await acc.accept(issue(9), chk(T0 - 40_000))).toEqual({ ok: false, reason: 'not yet valid' });
    expect(await kv.keys()).toEqual([]);
    expect(await acc.accept(issue(1), chk(T0 + 1))).toEqual({ ok: true }); // seq 9 was never recorded
  });
  it('keys with separators cannot collide: instance "a|b" scope "c" differs from instance "a" scope "b|c"', async () => {
    const acc = createBeaconAcceptor(createMemoryDurableKv());
    const x = issueLivenessBeacon({ issuerSecret: I.secretKey, instance: 'a|b', scope: 'c', seq: 1, issuedAt: T0, validityMs: 60_000 });
    const y = issueLivenessBeacon({ issuerSecret: I.secretKey, instance: 'a', scope: 'b|c', seq: 1, issuedAt: T0, validityMs: 60_000 });
    expect(await acc.accept(x, chk(T0, { instance: 'a|b' }))).toEqual({ ok: true });
    expect(await acc.accept(y, chk(T0, { instance: 'a' }))).toEqual({ ok: true });
  });
  it('a restart does not forget: the highest accepted seq is on disk', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-beacon-'));
    try {
      const first = createBeaconAcceptor(await openDurableState({ dir }));
      expect(await first.accept(issue(7), chk(T0 + 1))).toEqual({ ok: true });
      const second = createBeaconAcceptor(await openDurableState({ dir })); // the process restarted
      expect(await second.accept(issue(7), chk(T0 + 1))).toEqual({ ok: false, reason: 'replayed beacon: seq 7 <= 7' });
      expect(await second.accept(issue(6), chk(T0 + 1))).toEqual({ ok: false, reason: 'replayed beacon: seq 6 <= 7' });
      expect(await second.accept(issue(8), chk(T0 + 1))).toEqual({ ok: true });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('racing acceptors on one store: exactly one of two identical beacons is accepted', async () => {
    const kv = createMemoryDurableKv();
    const a = createBeaconAcceptor(kv);
    const b = createBeaconAcceptor(kv);
    const r = await Promise.all([a.accept(issue(5), chk(T0 + 1)), b.accept(issue(5), chk(T0 + 1)), a.accept(issue(5), chk(T0 + 1)), b.accept(issue(5), chk(T0 + 1))]);
    expect(r.filter((x) => x.ok)).toHaveLength(1);
    expect(r.filter((x) => !x.ok).every((x) => x.reason === 'replayed beacon: seq 5 <= 5')).toBe(true);
  });
  it('fails closed when the store cannot decide: an error, an unreachable store or a malformed stored value refuses the beacon', async () => {
    const kv = createMemoryDurableKv();
    const down: DurableKv = { ...kv, get: kv.get, set: kv.set, keys: kv.keys, update: () => Promise.reject(new Error('store down')) };
    expect(await createBeaconAcceptor(down).accept(issue(1), chk(T0 + 1))).toEqual({ ok: false, reason: 'beacon state unavailable' });
    for (const junk of ['7', -1, 1.5, null, { seq: 3 }]) {
      const k2 = createMemoryDurableKv();
      await k2.set(`beacon-seq/v1/${JSON.stringify(['ins', '*', issuer])}`, junk);
      expect(await createBeaconAcceptor(k2).accept(issue(10), chk(T0 + 1)), JSON.stringify(junk)).toEqual({ ok: false, reason: 'beacon state unavailable' });
    }
    expect(() => createBeaconAcceptor(undefined as never)).toThrow(TypeError);
    expect(() => createBeaconAcceptor({} as never)).toThrow(TypeError);
  });
});
