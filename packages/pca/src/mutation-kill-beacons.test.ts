/**
 * Mutation-kill tests for beacons.ts: every field-level guard of verifyLivenessBeacon is reached with a beacon whose
 * SIGNATURE IS VALID (re-signed over the tampered body), so each guard fires on its own with its own reason; exact
 * boundaries; the signed message layout; the issue-side argument checks with their messages.
 */
import { describe, expect, it } from 'vitest';
import {
  acceptBeacon,
  BEACON_CLOCK_SKEW_MS,
  BEACON_EPOCH_MS,
  BEACON_MAX_VALIDITY_MS,
  beaconRef,
  GLOBAL_SCOPE,
  issueLivenessBeacon,
  livenessBeaconMessage,
  verifyLivenessBeacon,
  type LivenessBeacon,
} from './beacons';
import { b64u, canonicalBytes, sha256, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';

const P = generateKeyPair();
const pub = encodeKey(P.publicKey);
const T0 = 1_000_000_020_000; // a multiple of BEACON_EPOCH_MS is not required; epoch is derived
const base = (): Omit<LivenessBeacon, 'sig'> => ({
  v: 2,
  instance: 'ins_1',
  scope: 'g1',
  epoch: Math.floor(T0 / BEACON_EPOCH_MS),
  seq: 1,
  issued_at: T0,
  not_after: T0 + 60_000,
  issuer: pub,
});
/** A beacon with an arbitrary (even malformed) body and a VALID signature over it. */
const signed = (over: Record<string, unknown>): LivenessBeacon => {
  const body = { ...base(), ...over } as Omit<LivenessBeacon, 'sig'>;
  return { ...body, sig: b64u(sign(P.secretKey, livenessBeaconMessage(body))) } as LivenessBeacon;
};
const chk = (now: number, extra: Record<string, unknown> = {}) => ({ issuers: [pub], now, instance: 'ins_1', scope: 'g1', ...extra });
const v = (b: unknown, now = T0, extra: Record<string, unknown> = {}) => verifyLivenessBeacon(b as LivenessBeacon, chk(now, extra));
const bad = (reason: string) => ({ ok: false, reason });

describe('the signed message', () => {
  it('is the domain prefix followed by the canonical body', () => {
    const b = base();
    const m = livenessBeaconMessage(b);
    const prefix = utf8('atlas-pca/beacon/v2\0');
    expect(Array.from(m.slice(0, prefix.length))).toEqual(Array.from(prefix));
    const body = canonicalBytes({ v: 2, instance: b.instance, scope: b.scope, epoch: b.epoch, seq: b.seq, issued_at: b.issued_at, not_after: b.not_after, issuer: b.issuer });
    expect(m.length).toBe(prefix.length + body.length);
    expect(Array.from(m.slice(prefix.length))).toEqual(Array.from(body));
  });
  it('a signature over the bare body (no domain prefix) does not verify', () => {
    const b = base();
    const body = canonicalBytes({ v: 2, instance: b.instance, scope: b.scope, epoch: b.epoch, seq: b.seq, issued_at: b.issued_at, not_after: b.not_after, issuer: b.issuer });
    const forged = { ...b, sig: b64u(sign(P.secretKey, body)) };
    expect(v(forged)).toEqual(bad('bad signature'));
  });
  it('beaconRef is sha256 of the canonical beacon and differs per beacon', () => {
    const b = signed({});
    expect(beaconRef(b)).toBe(b64u(sha256(canonicalBytes({ ...b }))));
    expect(beaconRef(b)).not.toBe(beaconRef(signed({ seq: 2 })));
  });
});

describe('issueLivenessBeacon argument checks', () => {
  const issue = (o: Record<string, unknown>) => issueLivenessBeacon({ issuerSecret: P.secretKey, instance: 'i', seq: 1, issuedAt: T0, ...o } as never);
  it('seq must be a non-negative integer', () => {
    for (const seq of [-1, 1.5, NaN]) expect(() => issue({ seq })).toThrow(new RangeError('issueLivenessBeacon: seq must be a non-negative integer'));
    expect(issue({ seq: 0 }).seq).toBe(0);
  });
  it('issuedAt must be a non-negative integer', () => {
    for (const issuedAt of [-1, 0.5, NaN]) expect(() => issue({ issuedAt })).toThrow(new RangeError('issueLivenessBeacon: issuedAt must be an integer'));
    expect(issue({ issuedAt: 0 }).issued_at).toBe(0);
  });
  it('validity must be an integer in (0, max]', () => {
    for (const validityMs of [0, -1, 1.5, BEACON_MAX_VALIDITY_MS + 1]) {
      expect(() => issue({ validityMs })).toThrow(new RangeError(`issueLivenessBeacon: validity must be in (0, ${BEACON_MAX_VALIDITY_MS}] ms`));
    }
    expect(issue({ validityMs: BEACON_MAX_VALIDITY_MS }).not_after - T0).toBe(BEACON_MAX_VALIDITY_MS);
    expect(issue({ validityMs: 1 }).not_after - T0).toBe(1);
    expect(issue({}).not_after - T0).toBe(5 * BEACON_EPOCH_MS);
    expect(issue({}).scope).toBe(GLOBAL_SCOPE);
  });
});

describe('verifyLivenessBeacon: each guard on its own', () => {
  it('a well-formed beacon verifies', () => {
    expect(v(signed({}))).toEqual({ ok: true });
  });
  it('malformed beacon: null, wrong version, unknown suite', () => {
    expect(v(null)).toEqual(bad('malformed beacon'));
    expect(v(signed({ v: 1 }))).toEqual(bad('malformed beacon'));
    expect(v(signed({ v: 3 }))).toEqual(bad('malformed beacon'));
    expect(v(signed({ alg: 'rot13' }))).toEqual(bad('malformed beacon'));
  });
  it('malformed window: each numeric field must be an integer, seq non-negative', () => {
    for (const over of [{ epoch: '5' }, { seq: '1' }, { issued_at: '5' }, { not_after: '5' }, { seq: -1 }]) {
      expect(v(signed(over)), JSON.stringify(over)).toEqual(bad('malformed window'));
    }
  });
  it('validity: not_after must be strictly after issued_at and within the hard maximum (inclusive)', () => {
    expect(v(signed({ not_after: T0 }))).toEqual(bad('validity exceeds the hard maximum'));
    expect(v(signed({ not_after: T0 - 1 }))).toEqual(bad('validity exceeds the hard maximum'));
    expect(v(signed({ not_after: T0 + 1 }))).toEqual({ ok: true });
    expect(v(signed({ not_after: T0 + BEACON_MAX_VALIDITY_MS }))).toEqual({ ok: true });
    expect(v(signed({ not_after: T0 + BEACON_MAX_VALIDITY_MS + 1 }))).toEqual(bad('validity exceeds the hard maximum'));
  });
  it('epoch must equal floor(issued_at / epoch length)', () => {
    expect(v(signed({ epoch: Math.floor(T0 / BEACON_EPOCH_MS) + 1 }))).toEqual(bad('epoch does not match issued_at'));
    expect(v(signed({ epoch: Math.floor(T0 / BEACON_EPOCH_MS) - 1 }))).toEqual(bad('epoch does not match issued_at'));
  });
  it('not yet valid: tolerated skew is exact', () => {
    expect(v(signed({}), T0 - BEACON_CLOCK_SKEW_MS)).toEqual({ ok: true });
    expect(v(signed({}), T0 - BEACON_CLOCK_SKEW_MS - 1)).toEqual(bad('not yet valid'));
  });
  it('expired: valid up to and including not_after', () => {
    expect(v(signed({}), T0 + 60_000)).toEqual({ ok: true });
    expect(v(signed({}), T0 + 60_001)).toEqual(bad('expired'));
  });
  it('scope: global covers everything, an equal scope is covered, a different one is not, none requested is not checked', () => {
    expect(v(signed({ scope: GLOBAL_SCOPE }), T0, { scope: 'other' })).toEqual({ ok: true });
    expect(v(signed({}), T0, { scope: 'g1' })).toEqual({ ok: true });
    expect(v(signed({}), T0, { scope: 'g2' })).toEqual(bad('scope not covered'));
    expect(v(signed({}), T0, { scope: undefined })).toEqual({ ok: true });
  });
});

describe('verifyLivenessBeacon never throws', () => {
  it('a broken verifier configuration is a malformed-beacon verdict', () => {
    expect(verifyLivenessBeacon(signed({}), { issuers: undefined, now: T0, instance: 'ins_1' } as never)).toEqual(bad('malformed beacon'));
    expect(verifyLivenessBeacon(signed({}), null as never)).toEqual(bad('malformed beacon'));
  });
});

describe('acceptBeacon', () => {
  const b = (seq: unknown) => ({ seq }) as never;
  it('refuses non-objects, including a function carrying an integer seq', () => {
    const fn = Object.assign(() => 0, { seq: 5 });
    for (const x of [null, undefined, 5, 'x', fn, b(-1), b(1.5), b(2 ** 53)]) expect(acceptBeacon(null, x as never)).toEqual(bad('malformed beacon'));
  });
  it('requires a strictly higher seq, with the exact replay message', () => {
    expect(acceptBeacon(null, b(0))).toEqual({ ok: true });
    expect(acceptBeacon({ seq: 4 }, b(5))).toEqual({ ok: true });
    expect(acceptBeacon({ seq: 5 }, b(5))).toEqual(bad('replayed beacon: seq 5 <= 5'));
    expect(acceptBeacon({ seq: 6 }, b(5))).toEqual(bad('replayed beacon: seq 5 <= 6'));
  });
});
