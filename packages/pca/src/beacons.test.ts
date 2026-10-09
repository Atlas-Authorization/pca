import { describe, expect, it } from 'vitest';
import {
  acceptBeacon,
  BEACON_EPOCH_MS,
  BEACON_MAX_VALIDITY_MS,
  beaconRef,
  GLOBAL_SCOPE,
  isFrozenLiveness,
  issueLivenessBeacon,
  verifyLivenessBeacon,
} from './beacons';
import { encodeKey, generateKeyPair } from './keys';

describe('liveness beacons v2', () => {
  const P = generateKeyPair();
  const pub = encodeKey(P.publicKey);
  const T0 = 1_000_000_000_000;
  const mk = (over: Partial<Parameters<typeof issueLivenessBeacon>[0]> = {}) =>
    issueLivenessBeacon({ issuerSecret: P.secretKey, instance: 'ins_1', scope: 'g1', seq: 1, issuedAt: T0, ...over });
  const chk = (now: number, extra = {}) => ({ issuers: [pub], now, instance: 'ins_1', scope: 'g1', ...extra });

  it('verifies inside the window and binds epoch to issued_at', () => {
    const b = mk();
    expect(b.epoch).toBe(Math.floor(T0 / BEACON_EPOCH_MS));
    expect(verifyLivenessBeacon(b, chk(T0 + 1000)).ok).toBe(true);
    expect(beaconRef(b)).toBe(beaconRef({ ...b }));
  });
  it('fails closed: stale, absent, wrong issuer/instance/scope, tampered', () => {
    const b = mk({ validityMs: 60_000 });
    expect(verifyLivenessBeacon(b, chk(T0 + 61_000))).toEqual({ ok: false, reason: 'expired' });
    expect(isFrozenLiveness([], chk(T0))).toBe(true);
    expect(isFrozenLiveness([b], chk(T0 + 61_000))).toBe(true);
    expect(isFrozenLiveness([b], chk(T0 + 10))).toBe(false);
    expect(verifyLivenessBeacon(b, chk(T0, { issuers: [encodeKey(generateKeyPair().publicKey)] })).reason).toBe('issuer not pinned');
    expect(verifyLivenessBeacon(b, chk(T0, { instance: 'ins_2' })).reason).toBe('wrong instance');
    expect(verifyLivenessBeacon(b, chk(T0, { scope: 'g2' })).reason).toBe('scope not covered');
    expect(verifyLivenessBeacon({ ...b, not_after: b.not_after + 5 }, chk(T0)).ok).toBe(false);
    expect(verifyLivenessBeacon({ ...b, seq: 9 }, chk(T0)).ok).toBe(false);
    expect(verifyLivenessBeacon({ ...b, issued_at: T0 + 10 * BEACON_EPOCH_MS, epoch: b.epoch }, chk(T0)).ok).toBe(false);
  });
  it('a global beacon covers every scope', () => {
    const g = mk({ scope: GLOBAL_SCOPE });
    expect(verifyLivenessBeacon(g, chk(T0, { scope: 'anything' })).ok).toBe(true);
  });
  it('enforces the HARD max validity at issue and at verify', () => {
    expect(() => mk({ validityMs: BEACON_MAX_VALIDITY_MS + 1 })).toThrow();
    expect(() => mk({ validityMs: 0 })).toThrow();
    expect(mk({ validityMs: BEACON_MAX_VALIDITY_MS }).not_after - T0).toBe(BEACON_MAX_VALIDITY_MS);
    // a hand-forged over-long beacon (validly signed by a pinned issuer) is still refused
    const body = { ...mk(), not_after: T0 + BEACON_MAX_VALIDITY_MS + 1 };
    expect(verifyLivenessBeacon(body, chk(T0)).ok).toBe(false);
  });
  it('rejects a replayed older (or equal) seq, accepts a strictly newer one', () => {
    const b1 = mk({ seq: 5 });
    expect(acceptBeacon(null, b1).ok).toBe(true);
    expect(acceptBeacon(b1, mk({ seq: 4 })).ok).toBe(false);
    expect(acceptBeacon(b1, mk({ seq: 5 })).ok).toBe(false);
    expect(acceptBeacon(b1, mk({ seq: 6 })).ok).toBe(true);
  });
  it('a principal that stops issuing halts the grant (dead-man)', () => {
    const bs = [0, 1, 2].map((i) => mk({ seq: i, issuedAt: T0 + i * 60_000, validityMs: 60_000 }));
    expect(isFrozenLiveness(bs, chk(T0 + 2 * 60_000 + 30_000))).toBe(false);
    expect(isFrozenLiveness(bs, chk(T0 + 3 * 60_000 + 1))).toBe(true);
  });
});
