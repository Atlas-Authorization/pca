import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  MIN_PRODUCTION_MODULUS_BITS,
  RSA_2048_CHALLENGE_MODULUS,
  checkProductionModulus,
  insecureDevSetup,
  vdf,
  vdfVerifyDetailed,
} from './vdf';
import * as api from './index';
import { deriveTimelockInput, proveTimelockElapsed, requireTimelock, verifyTimelock } from './timelock';

const N = RSA_2048_CHALLENGE_MODULUS;

describe('insecureDevSetup cannot be mistaken for a production setup', () => {
  it('the generator is only exported under its explicit INSECURE name, and the old name is gone', () => {
    expect(typeof api.insecureDevSetup).toBe('function');
    expect('setup' in api).toBe(false);
    expect('setup' in vdf).toBe(false);
    expect('insecureDevSetup' in vdf).toBe(true);
  });

  it('its result is branded and carries the trapdoor', () => {
    const s = insecureDevSetup({ bits: 256 });
    expect(s.insecureDevOnly).toBe(true);
    expect(s.p * s.q).toBe(s.N);
  });

  it('a 2048-bit self-generated modulus is refused by the timelock layer (registry), with a reason that names the cause', () => {
    const s = insecureDevSetup({ bits: MIN_PRODUCTION_MODULUS_BITS });
    expect(s.bits).toBeGreaterThanOrEqual(MIN_PRODUCTION_MODULUS_BITS - 1);
    // size alone would let it through (>= 2048 bits); the in-process registry is what stops it
    const check = checkProductionModulus(s.N);
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toMatch(/insecureDevSetup/);
    expect(() => requireTimelock('a', { steps: 10, N: s.N })).toThrow(/factors are known/);
    expect(() => proveTimelockElapsed('a', 10, s.N)).toThrow(/factors are known/);
    const proof = proveTimelockElapsed('a', 10, s.N, { allowInsecureDevModulus: true });
    expect(verifyTimelock('a', proof, { steps: 10, N: s.N })).toBe(false); // fails closed, does not throw
    expect(verifyTimelock('a', proof, { steps: 10, N: s.N, allowInsecureDevModulus: true })).toBe(true);
  });

  it('small moduli are refused on the production path even when they did not come from this process', () => {
    const s = insecureDevSetup({ bits: 256 });
    const foreign = BigInt(s.N.toString()); // same value, as if received from another process
    expect(checkProductionModulus(foreign)).toEqual({ ok: false, reason: expect.stringMatching(/insecureDevSetup|below 2048/) });
    const other = ((1n << 521n) - 1n) * ((1n << 607n) - 1n); // product of two Mersenne primes: 1127 bits
    expect(checkProductionModulus(other)).toEqual({ ok: false, reason: `modulus is below ${MIN_PRODUCTION_MODULUS_BITS} bits` });
  });

  it('structurally weak 2048-bit-plus moduli are refused with the specific reason', () => {
    const m2203 = (1n << 2203n) - 1n; // a Mersenne PRIME: group order N-1 would be public
    expect(checkProductionModulus(m2203)).toEqual({ ok: false, reason: 'modulus is prime (group order N-1 is public)' });
    expect(checkProductionModulus(N * N)).toEqual({ ok: false, reason: 'modulus is a perfect square' });
    expect(checkProductionModulus(N * 3n)).toEqual({ ok: false, reason: 'modulus has the small prime factor 3' });
    expect(checkProductionModulus(N + 1n)).toEqual({ ok: false, reason: 'modulus is even' });
    expect(checkProductionModulus(N)).toEqual({ ok: true });
  });

  it('the production default (RSA-2048) is accepted end to end', () => {
    const req = requireTimelock('prod-action', { steps: 50, N });
    expect(req.N).toBe(N);
    const proof = proveTimelockElapsed('prod-action', 50, N);
    expect(verifyTimelock('prod-action', proof, { steps: 50, N })).toBe(true);
  });
});

describe('REGRESSION: zero-work forgery (y = pi = 0 used to verify for any input)', () => {
  it('vdfVerify / verifyTimelock refuse y = pi = 0, y = pi = N and other non-canonical encodings', () => {
    const steps = 1_000_000_000; // a "cooling-off" of a billion squarings, forged with no work
    const forged = { kind: 'vdf-timelock-proof' as const, y: 0n, pi: 0n, steps };
    expect(verifyTimelock('irreversible-wire-transfer', forged, { steps, N })).toBe(false);
    expect(vdfVerifyDetailed(123456789n, 0n, 0n, steps, N)).toEqual({ ok: false, reason: 'non-canonical-y' });
    expect(vdfVerifyDetailed(123456789n, N, N, steps, N)).toEqual({ ok: false, reason: 'non-canonical-y' });
    expect(vdfVerifyDetailed(123456789n, 5n, 0n, steps, N)).toEqual({ ok: false, reason: 'non-canonical-pi' });
    expect(vdfVerifyDetailed(123456789n, -5n, 7n, steps, N)).toEqual({ ok: false, reason: 'non-canonical-y' });
  });

  it('a genuine proof still verifies after the fix', () => {
    const proof = proveTimelockElapsed('genuine', 300, N);
    expect(verifyTimelock('genuine', proof, { steps: 300, N })).toBe(true);
  });
});

describe('timelock input derivation matches an independent re-computation (node:crypto)', () => {
  it('x = sha256(domain || digest) mod N, nudged into [2, N)', () => {
    for (const digest of ['a', 'digest-of-the-irreversible-action', 'é中文', '']) {
      const h = createHash('sha256').update('atlas-pca/vdf/timelock/input/v1\0' + digest, 'utf8').digest('hex');
      let want = BigInt('0x' + h) % N;
      if (want <= 1n) want += 2n;
      expect(deriveTimelockInput(digest, N)).toBe(want);
    }
  });
});
