import { describe, expect, it } from 'vitest';
import { isFrozenLiveness, issueLivenessBeacon, verifyLivenessBeacon } from './beacons';
import { encodeKey, generateKeyPair } from './keys';

const P = generateKeyPair();
const pub = encodeKey(P.publicKey);
const T0 = 1_000_000_000_000;
const beacon = () => issueLivenessBeacon({ issuerSecret: P.secretKey, instance: 'ins_1', scope: 'g1', seq: 1, issuedAt: T0, validityMs: 60_000 });
const chk = (now: number) => ({ issuers: [pub], now, instance: 'ins_1', scope: 'g1' });

describe('a non-finite clock never admits (liveness beacons)', () => {
  it('a finite clock inside the window verifies', () => {
    expect(verifyLivenessBeacon(beacon(), chk(T0 + 1000)).ok).toBe(true);
  });
  // old check `now > not_after` was false for NaN (and the not-yet-valid check too), so a NaN clock counted as fresh
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a clock of %s refuses and reads as frozen', (now) => {
    const b = beacon();
    expect(verifyLivenessBeacon(b, chk(now)).ok).toBe(false);
    expect(isFrozenLiveness([b], chk(now))).toBe(true);
  });
});
