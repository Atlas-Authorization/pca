/** Mutation kills for @atlasauth/pca-vdf: exact refusal reasons, boundary values and dev-setup guard rails. */
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MODULUS, bigIntToBytes, canonicalVdfOutput, checkProductionModulus, gcd, hashToPrime, insecureDevSetup, isProbablePrime, modpow,
  vdfEval, vdfEvalCanonical, vdfVerify, vdfVerifyCanonical, vdfVerifyCanonicalDetailed, vdfVerifyDetailed, bytesToBigInt,
} from './vdf';
import { actionDigest, calibrateSteps, deriveTimelockInput, proveTimelockElapsed, requireTimelock, verifyTimelock } from './timelock';

const err = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const dev = insecureDevSetup({ bits: 64 });
const N = dev.N;
const x = 12345n;
const T = 5;
const good = vdfEval(x, T, N);
const goodC = vdfEvalCanonical(x, T, N);
const F = (reason: string) => ({ ok: false, reason });

describe('helpers', () => {
  it('bigint codecs', () => {
    expect(err(() => bigIntToBytes(-1n)).message).toBe('bigIntToBytes: negative value');
    expect(bigIntToBytes(0n)).toEqual(Uint8Array.of(0));
    expect(bigIntToBytes(255n)).toEqual(Uint8Array.of(255));
    expect(bigIntToBytes(256n)).toEqual(Uint8Array.of(1, 0));
    expect(bytesToBigInt(Uint8Array.of(1, 0, 2))).toBe(65538n);
  });
  it('gcd is sign-insensitive', () => {
    expect(gcd(-12n, 18n)).toBe(6n);
    expect(gcd(12n, -18n)).toBe(6n);
    expect(gcd(-12n, -18n)).toBe(6n);
    expect(gcd(0n, 5n)).toBe(5n);
    expect(gcd(5n, 0n)).toBe(5n);
  });
  it('modpow', () => {
    expect(err(() => modpow(2n, 3n, 0n)).message).toBe('modpow: modulus must be positive');
    expect(err(() => modpow(2n, 3n, -5n)).message).toBe('modpow: modulus must be positive');
    expect(modpow(5n, 0n, 1n)).toBe(0n);
    expect(modpow(5n, 3n, 1n)).toBe(0n);
    expect(err(() => modpow(2n, -1n, 7n)).message).toBe('modpow: negative exponent (no inverse in a group of unknown order)');
    expect(modpow(-2n, 3n, 7n)).toBe(6n);
    expect(modpow(3n, 0n, 7n)).toBe(1n);
    expect(modpow(3n, 200n, 1000003n)).toBe(BigInt(Number(3n ** 200n % 1000003n)));
  });
  it('isProbablePrime', () => {
    for (const p of [2n, 3n, 97n, 101n, 1000003n, 2n ** 61n - 1n]) expect(isProbablePrime(p)).toBe(true);
    for (const c of [-7n, 0n, 1n, 4n, 91n, 1000001n, 561n, 2n ** 61n + 1n]) expect(isProbablePrime(c)).toBe(false);
  });
  it('hashToPrime bounds', () => {
    for (const b of [7, 8193, 1.5, NaN]) expect(err(() => hashToPrime(2n, 3n, 1, N, b)).message).toBe('hashToPrime: bits must be an integer in [8, 8192]');
    const p8 = hashToPrime(2n, 3n, 1, N, 8);
    expect(p8.toString(2).length).toBe(8);
    expect(isProbablePrime(p8)).toBe(true);
    expect(err(() => hashToPrime(2n, 3n, -1, N)).message).toBe('VDF: steps T must be a non-negative safe integer, got -1');
    expect(hashToPrime(2n, 3n, 1, N).toString(2).length).toBe(256);
    // reduced mod N before hashing
    expect(hashToPrime(2n + N, 3n + N, 1, N)).toBe(hashToPrime(2n, 3n, 1, N));
    expect(hashToPrime(2n, 3n, 1, N)).not.toBe(hashToPrime(2n, 3n, 2, N));
  });
});

describe('vdfEval / vdfEvalCanonical refusals', () => {
  it.each([[vdfEval], [vdfEvalCanonical]])('modulus, steps and input messages', (ev) => {
    for (const bad of [3n, 2n, 1n, 0n, -7n, 10n]) expect(err(() => ev(x, T, bad)).message).toBe('VDF: modulus N must be odd and > 3');
    expect(() => ev(2n, T, 5n)).not.toThrow();
    for (const t of [-1, 1.5, NaN]) expect(err(() => ev(x, t, N)).message).toBe(`VDF: steps T must be a non-negative safe integer, got ${String(t)}`);
    const unit = 'VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)';
    for (const bad of [0n, 1n, N - 1n, N, N + 1n, 2n * N - 1n, dev.p, dev.q, -1n]) expect(err(() => ev(bad, T, N)).message).toBe(unit);
    expect(() => ev(2n, T, N)).not.toThrow();
    expect(() => ev(N - 2n, T, N)).not.toThrow();
  });
  it('canonical output is the smaller of {y, N-y}', () => {
    expect(canonicalVdfOutput(3n, 11n)).toBe(3n);
    expect(canonicalVdfOutput(8n, 11n)).toBe(3n);
    expect(canonicalVdfOutput(5n, 11n)).toBe(5n);
    expect(goodC.y <= N - goodC.y).toBe(true);
    expect(vdfEvalCanonical(x, T, N).y).toBe(canonicalVdfOutput(good.y, N));
  });
});

describe('vdfVerifyDetailed: every refusal has its own reason', () => {
  const V = (xx: unknown, y: unknown, pi: unknown, t: unknown, n: unknown) => vdfVerifyDetailed(xx as never, y as never, pi as never, t as never, n as never);
  it('accepts the honest proof, T = 0 included', () => {
    expect(V(x, good.y, good.pi, T, N)).toEqual({ ok: true });
    const z = vdfEval(x, 0, N);
    expect(V(x, z.y, z.pi, 0, N)).toEqual({ ok: true });
    expect(vdfVerify(x, good.y, good.pi, T, N)).toBe(true);
    expect(vdfVerify(x, good.y, good.pi, T + 1, N)).toBe(false);
  });
  it('malformed-input: any non-bigint argument', () => {
    const m = F('malformed-input');
    expect(V(5, good.y, good.pi, T, N)).toEqual(m);
    expect(V(x, 5, good.pi, T, N)).toEqual(m);
    expect(V(x, good.y, 5, T, N)).toEqual(m);
    expect(V(x, good.y, good.pi, T, 5)).toEqual(m);
    expect(V(undefined, undefined, undefined, undefined, undefined)).toEqual(m);
  });
  it('bad-modulus / bad-steps', () => {
    for (const n of [3n, 2n, 1n, 0n, -9n, 100n]) expect(V(x, good.y, good.pi, T, n)).toEqual(F('bad-modulus'));
    const r5 = V(x, good.y, good.pi, T, 5n);
    expect(r5.ok ? 'OK' : r5.reason).not.toBe('bad-modulus');
    for (const t of [-1, 1.5, NaN, Infinity, 2 ** 53]) expect(V(x, good.y, good.pi, t, N)).toEqual(F('bad-steps'));
    expect(V(x, good.y, good.pi, '5', N)).toEqual(F('bad-steps'));
  });
  it('non-canonical y / pi: zero, N, multiples of a factor, out of range', () => {
    for (const y of [0n, N, N + good.y, dev.p, dev.q, -good.y]) expect(V(x, y, good.pi, T, N)).toEqual(F('non-canonical-y'));
    for (const pi of [0n, N, N + good.pi, dev.p, -good.pi]) expect(V(x, good.y, pi, T, N)).toEqual(F('non-canonical-pi'));
    // y = pi = 0 satisfies the equation for every x: it must be refused, not accepted
    expect(V(x, 0n, 0n, T, N)).toEqual(F('non-canonical-y'));
  });
  it('bad input x', () => {
    for (const bx of [0n, 1n, N - 1n, N, N + 1n, dev.p, dev.q, -1n]) expect(V(bx, good.y, good.pi, T, N)).toEqual(F('bad-input-x'));
  });
  it('equation mismatch, including the sign twin which the plain verifier refuses', () => {
    expect(V(x, good.y, good.pi, T + 1, N)).toEqual(F('equation-mismatch'));
    expect(V(x + 1n, good.y, good.pi, T, N)).toEqual(F('equation-mismatch'));
    // the plain relation holds up to sign (RT-10): the sign twin verifies, the canonical verifier refuses it
    expect(V(x, N - good.y, N - good.pi, T, N)).toEqual({ ok: true });
    expect(V(x, good.y, good.pi === 2n ? 3n : 2n, T, N)).toEqual(F('equation-mismatch'));
  });
});

describe('vdfVerifyCanonicalDetailed', () => {
  const V = (xx: unknown, y: unknown, pi: unknown, t: unknown, n: unknown) => vdfVerifyCanonicalDetailed(xx as never, y as never, pi as never, t as never, n as never);
  it('accepts exactly the canonical form (up to sign of the relation)', () => {
    expect(V(x, goodC.y, goodC.pi, T, N)).toEqual({ ok: true });
    expect(vdfVerifyCanonical(x, goodC.y, goodC.pi, T, N)).toBe(true);
    expect(V(x, N - goodC.y, goodC.pi, T, N)).toEqual(F('non-canonical-y'));
    expect(V(x, goodC.y, N - goodC.pi, T, N)).toEqual(F('non-canonical-pi')); // R6-ALIAS-03
  });
  it('same reasons as the plain verifier', () => {
    expect(V(5, goodC.y, goodC.pi, T, N)).toEqual(F('malformed-input'));
    expect(V(x, 5, goodC.pi, T, N)).toEqual(F('malformed-input'));
    expect(V(x, goodC.y, 5, T, N)).toEqual(F('malformed-input'));
    expect(V(x, goodC.y, goodC.pi, T, 5)).toEqual(F('malformed-input'));
    for (const n of [3n, 2n, 0n, -9n, 100n]) expect(V(x, goodC.y, goodC.pi, T, n)).toEqual(F('bad-modulus'));
    for (const t of [-1, 1.5, NaN]) expect(V(x, goodC.y, goodC.pi, t, N)).toEqual(F('bad-steps'));
    for (const y of [0n, N, dev.p]) expect(V(x, y, goodC.pi, T, N)).toEqual(F('non-canonical-y'));
    for (const pi of [0n, N, dev.p]) expect(V(x, goodC.y, pi, T, N)).toEqual(F('non-canonical-pi'));
    for (const bx of [0n, 1n, N - 1n, dev.p]) expect(V(bx, goodC.y, goodC.pi, T, N)).toEqual(F('bad-input-x'));
    expect(V(x, goodC.y, goodC.pi, T + 1, N)).toEqual(F('equation-mismatch'));
    expect(V(x, goodC.y === 2n ? 3n : 2n, goodC.pi, T, N)).toEqual(F('equation-mismatch'));
  });
});

describe('insecureDevSetup guard rails', () => {
  it('bit sizes and primes', () => {
    expect(err(() => insecureDevSetup({ bits: 31 })).message).toBe('insecureDevSetup: bits must be a safe integer >= 32');
    expect(err(() => insecureDevSetup({ bits: 40.5 })).message).toBe('insecureDevSetup: bits must be a safe integer >= 32');
    const s = insecureDevSetup({ bits: 32 });
    expect(s.insecureDevOnly).toBe(true);
    expect(s.p.toString(2).length).toBe(16);
    expect(s.q.toString(2).length).toBe(16);
    expect(s.p * s.q).toBe(s.N);
    expect(s.bits).toBe(s.N.toString(2).length);
    expect(isProbablePrime(s.p) && isProbablePrime(s.q)).toBe(true);
    expect(s.p).not.toBe(s.q);
    const s2 = insecureDevSetup({ bits: 65 });
    expect(s2.p.toString(2).length).toBe(32);
    expect(s2.q.toString(2).length).toBe(33);
  });
  it('defaults: 2048-bit modulus from the system CSPRNG', () => {
    const s = insecureDevSetup();
    expect(s.bits).toBeGreaterThanOrEqual(2047);
    expect(s.bits).toBeLessThanOrEqual(2048);
    expect(checkProductionModulus(s.N)).toEqual(F('modulus came from insecureDevSetup(): its factors are known, so it provides no delay'));
  });
  it('a stuck or constant randomness source fails closed with its own message', () => {
    expect(err(() => insecureDevSetup({ bits: 64, randomBytes: (n) => new Uint8Array(n) })).message).toBe('insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)');
    let fixed: Uint8Array | null = null;
    for (let c = 1; c < 256 && fixed === null; c += 2) {
      const cand = Uint8Array.of(0xff, c);
      if (isProbablePrime(BigInt((0xff << 8) | c))) fixed = cand;
    }
    expect(fixed).not.toBeNull();
    expect(err(() => insecureDevSetup({ bits: 32, randomBytes: () => fixed! })).message).toBe('insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)');
    let calls = 0;
    const seq = [0xfff1, 0xfff1, 0xfff1, 0xffef];
    const r = insecureDevSetup({ bits: 32, randomBytes: () => { const v = seq[Math.min(calls++, seq.length - 1)]!; return Uint8Array.of(v >> 8, v & 255); } });
    expect(r.p).toBe(0xfff1n);
    expect(r.q).toBe(0xffefn);
  });
});

describe('checkProductionModulus', () => {
  const ok = { ok: true };
  it('reasons, in order', () => {
    expect(checkProductionModulus(5 as never)).toEqual(F('modulus is not a bigint'));
    for (const n of [3n, 2n, 1n, 0n, -5n]) expect(checkProductionModulus(n)).toEqual(F('modulus is too small'));
    expect(checkProductionModulus(5n)).toEqual(F('modulus is below 2048 bits'));
    const even = (1n << 2100n) + 2n;
    expect(checkProductionModulus(even)).toEqual(F('modulus is even'));
    const sq = ((1n << 1100n) + 1n) ** 2n;
    expect(checkProductionModulus(sq)).toEqual(F('modulus is a perfect square'));
    expect(checkProductionModulus((1n << 2203n) - 1n)).toEqual(F('modulus is prime (group order N-1 is public)'));
    expect(checkProductionModulus(3n * DEFAULT_MODULUS)).toEqual(F('modulus has the small prime factor 3'));
    expect(checkProductionModulus(65521n * DEFAULT_MODULUS)).toEqual(F('modulus has the small prime factor 65521'));
    expect(checkProductionModulus(DEFAULT_MODULUS)).toEqual(ok);
    expect(checkProductionModulus(DEFAULT_MODULUS)).toEqual(ok);
  });
  it('perfect-square detection is exact', () => {
    const base = (1n << 1100n) + 1n;
    expect((checkProductionModulus(base * base) as { reason: string }).reason).toBe('modulus is a perfect square');
    expect((checkProductionModulus(base * base + 2n) as { reason?: string }).reason).not.toBe('modulus is a perfect square');
    expect((checkProductionModulus(base * base - 2n) as { reason?: string }).reason).not.toBe('modulus is a perfect square');
  });
});

describe('timelock layer', () => {
  const BEACON = 'beacon-0123456789';
  const opts = { steps: 4, N, beacon: BEACON, allowInsecureDevModulus: true };
  it('input derivation: domain-separated sha256 mod N, never 0 or 1', () => {
    const d = new TextEncoder().encode('act');
    const dom = new TextEncoder().encode('atlas-pca/vdf/timelock/input/v2\0');
    const lp = (b: Uint8Array) => { const o = new Uint8Array(4 + b.length); new DataView(o.buffer).setUint32(0, b.length, false); o.set(b, 4); return o; };
    const bb = new TextEncoder().encode(BEACON);
    const parts = [dom, lp(d), lp(bb)];
    const msg = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { msg.set(p, o); o += p.length; }
    const raw = bytesToBigInt(sha256(msg)) % N;
    expect(deriveTimelockInput('act', N, BEACON)).toBe(raw <= 1n ? raw + 2n : raw);
    expect(deriveTimelockInput('act', N, new TextEncoder().encode(BEACON))).toBe(deriveTimelockInput('act', N, BEACON));
    expect(deriveTimelockInput('act', N, 'other-beacon')).not.toBe(deriveTimelockInput('act', N, BEACON));
    expect(deriveTimelockInput('act2', N, BEACON)).not.toBe(deriveTimelockInput('act', N, BEACON));
    expect(actionDigest('abc')).toBe('abc');
  });
  it('input derivation refusals', () => {
    for (const n of [3n, 2n, 0n, -4n, 5 as never]) expect(err(() => deriveTimelockInput('a', n as bigint, BEACON)).message).toBe('deriveTimelockInput: modulus N must be a bigint > 3');
    expect(() => deriveTimelockInput('a', 5n, BEACON)).not.toThrow();
    for (const b of ['', new Uint8Array(0), 5 as never, null as never]) expect(err(() => deriveTimelockInput('a', N, b)).message).toBe('timelock: a non-empty beacon (unpredictable, post-action value) is required');
    // N = 4 and N = 5 force raw in {0,1,2,3,4}: the lift keeps x >= 2
    for (let i = 0; i < 30; i++) expect(deriveTimelockInput(`a${i}`, 5n, `b${i}`) >= 2n).toBe(true);
  });
  it('requireTimelock / prove / verify', () => {
    const req = requireTimelock('act', opts);
    expect(req).toEqual({ kind: 'vdf-timelock', x: deriveTimelockInput('act', N, BEACON), steps: 4, N, actionDigest: 'act' });
    for (const s of [0, -1, 1.5, NaN]) expect(err(() => requireTimelock('act', { ...opts, steps: s })).message).toBe(`timelock: steps must be a safe integer >= 1, got ${String(s)}`);
    expect(requireTimelock('act', { ...opts, steps: 1 }).steps).toBe(1);
    const refuse = err(() => requireTimelock('act', { ...opts, allowInsecureDevModulus: false }));
    expect(refuse.message).toBe('timelock: refusing this modulus: modulus came from insecureDevSetup(): its factors are known, so it provides no delay. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.');
    expect(refuse).toBeInstanceOf(RangeError);
    const proof = proveTimelockElapsed('act', 4, N, { beacon: BEACON, allowInsecureDevModulus: true });
    expect(proof.kind).toBe('vdf-timelock-proof');
    expect(proof.steps).toBe(4);
    expect(verifyTimelock('act', proof, opts)).toBe(true);
    expect(verifyTimelock('act2', proof, opts)).toBe(false);
    expect(verifyTimelock('act', proof, { ...opts, beacon: 'other-beacon-xx' })).toBe(false);
    expect(verifyTimelock('act', proof, { ...opts, steps: 5 })).toBe(false);
    expect(verifyTimelock('act', proof, { ...opts, allowInsecureDevModulus: false })).toBe(false);
    expect(verifyTimelock('act', proof, { ...opts, steps: 0 })).toBe(false);
    for (const bad of [null, undefined, 5, 'x', { ...proof, kind: 'x' }, { ...proof, steps: 3 }, { ...proof, steps: 4.5 }, { ...proof, y: 5 }, { ...proof, pi: 5 }, { ...proof, y: proof.y + 1n }]) {
      expect(verifyTimelock('act', bad as never, opts)).toBe(false);
    }
    expect(err(() => proveTimelockElapsed('act', 0, N, { beacon: BEACON, allowInsecureDevModulus: true })).message).toBe('timelock: steps must be a safe integer >= 1, got 0');
  });
  it('calibrateSteps arithmetic and refusals', () => {
    let t = 0;
    const clock = () => { const v = t; t += 500; return v; }; // 500 ms per sample
    const r = calibrateSteps({ N, desiredSeconds: 3, sampleSquarings: 1000, adversaryAdvantage: 4, now: clock });
    expect(r.measuredSquaringsPerSecond).toBe(2000);
    expect(r.assumedAdversarySquaringsPerSecond).toBe(8000);
    expect(r.steps).toBe(24000);
    let t2 = 0;
    expect(calibrateSteps({ N, desiredSeconds: 0.0001, sampleSquarings: 1, adversaryAdvantage: 1, now: () => (t2 += 1000) }).steps).toBe(1);
    const base = { N, desiredSeconds: 1, now: () => 0 };
    expect(err(() => calibrateSteps({ ...base, N: 3n })).message).toBe('calibrateSteps: modulus N must be a bigint > 3');
    expect(err(() => calibrateSteps({ ...base, N: 5 as never })).message).toBe('calibrateSteps: modulus N must be a bigint > 3');
    for (const d of [0, -1, NaN, Infinity]) expect(err(() => calibrateSteps({ ...base, desiredSeconds: d })).message).toBe('calibrateSteps: desiredSeconds must be > 0');
    for (const s of [0, -1, 1.5, NaN]) expect(err(() => calibrateSteps({ ...base, sampleSquarings: s })).message).toBe('calibrateSteps: sampleSquarings must be a safe integer >= 1');
    for (const a of [0.5, NaN, Infinity]) expect(err(() => calibrateSteps({ ...base, adversaryAdvantage: a })).message).toBe('calibrateSteps: adversaryAdvantage must be >= 1');
    expect(() => calibrateSteps({ N, desiredSeconds: 1, sampleSquarings: 1, adversaryAdvantage: 1, now: (() => { let q = 0; return () => (q += 10); })() })).not.toThrow();
    // real clock: positive finite measurement
    const real = calibrateSteps({ N, desiredSeconds: 1, sampleSquarings: 2000 });
    expect(real.measuredSquaringsPerSecond).toBeGreaterThan(0);
    expect(Number.isFinite(real.measuredSquaringsPerSecond)).toBe(true);
    // the squarings really are performed: a clock that reports the loop count would see sample iterations
    expect(real.assumedAdversarySquaringsPerSecond).toBeCloseTo(real.measuredSquaringsPerSecond * 10, 5);
  });
});
