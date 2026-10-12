import { describe, expect, it } from 'vitest';
import {
  canonicalVdfOutput,
  hashToPrime,
  insecureDevSetup,
  vdfEval,
  vdfEvalCanonical,
  vdfVerify,
  vdfVerifyCanonical,
  vdfVerifyCanonicalDetailed,
} from './vdf';
import { deriveTimelockInput, proveTimelockElapsed, requireTimelock, verifyTimelock } from './timelock';

const { N } = insecureDevSetup({ bits: 256 });
const dev = { allowInsecureDevModulus: true } as const;

describe('RT-10: beacon binding (precompute)', () => {
  it('a proof computed against a PREDICTED beacon does not release the action under the real beacon', () => {
    const digest = 'predicted-action-digest';
    const early = proveTimelockElapsed(digest, 200, N, { beacon: 'guess-1', ...dev });
    expect(verifyTimelock(digest, early, { steps: 200, N, beacon: 'guess-1', ...dev })).toBe(true);
    expect(verifyTimelock(digest, early, { steps: 200, N, beacon: 'drand-round-9000001', ...dev })).toBe(false);
  });
  it('x depends on the beacon, unambiguously (length-prefixed)', () => {
    const a = deriveTimelockInput('ab', N, 'c');
    expect(deriveTimelockInput('a', N, 'bc')).not.toBe(a);
    expect(deriveTimelockInput('ab', N, 'd')).not.toBe(a);
    expect(deriveTimelockInput('ab', N, new TextEncoder().encode('c'))).toBe(a);
  });
  it('an empty beacon is refused everywhere', () => {
    expect(() => deriveTimelockInput('a', N, '')).toThrow(RangeError);
    expect(() => requireTimelock('a', { steps: 5, N, beacon: '', ...dev })).toThrow(RangeError);
    expect(() => proveTimelockElapsed('a', 5, N, { beacon: new Uint8Array(0), ...dev })).toThrow(RangeError);
    const p = proveTimelockElapsed('a', 5, N, { beacon: 'b', ...dev });
    expect(verifyTimelock('a', p, { steps: 5, N, beacon: '', ...dev })).toBe(false);
  });
});

describe('RT-10: output uniqueness', () => {
  it('the plain verifier accepts (N-y, N-pi\'\') - the malleability being closed', () => {
    const x = 123456789n, T = 300;
    const { y, pi } = vdfEval(x, T, N);
    const y2 = N - y;
    const l2 = hashToPrime(x, y2, T, N);
    let q = 1n, r = 1n % l2;
    for (let i = 0; i < T; i++) { const t = r * 2n; const b = t / l2; r = t % l2; q = (q * q) % N; if (b) q = (q * x) % N; }
    const pi2 = (N - q) % N;
    expect(vdfVerify(x, y2, pi2, T, N)).toBe(true); // raw primitive: documented sign ambiguity
    // the canonical verifier admits exactly one of the two (pi in its canonical form, R6-ALIAS-03)
    const ok = [ [y, pi], [y2, pi2] ].filter(([a, b]) => vdfVerifyCanonical(x, a!, canonicalVdfOutput(b!, N), T, N));
    expect(ok.length).toBe(1);
    expect(ok[0]![0]).toBe(canonicalVdfOutput(y, N));
  });
  it('vdfEvalCanonical output is <= N/2, verifies, and its flipped twin is rejected as non-canonical', () => {
    for (const x of [3n, 5n, 7n, 11n, 13n, 17n]) {
      const { y, pi } = vdfEvalCanonical(x, 100, N);
      expect(y <= N - y).toBe(true);
      expect(vdfVerifyCanonical(x, y, pi, 100, N)).toBe(true);
      expect(vdfVerifyCanonicalDetailed(x, N - y, pi, 100, N)).toEqual({ ok: false, reason: 'non-canonical-y' });
      expect(vdfVerifyCanonical(x, y, pi + 1n, 100, N)).toBe(false);
    }
  });
  it('timelock: the y/N-y twin of a valid proof is rejected', () => {
    const o = { steps: 150, N, beacon: 'bcn', ...dev } as const;
    const p = proveTimelockElapsed('act', 150, N, { beacon: 'bcn', ...dev });
    expect(verifyTimelock('act', p, o)).toBe(true);
    expect(verifyTimelock('act', { ...p, y: N - p.y }, o)).toBe(false);
    expect(verifyTimelock('act', { ...p, y: N - p.y, pi: N - p.pi }, o)).toBe(false);
  });
});

describe('R6-ALIAS-03: the proof element has one encoding', () => {
  it('vdfEvalCanonical emits pi <= N/2 and the canonical verifier refuses N-pi', () => {
    for (const x of [3n, 5n, 7n, 11n, 13n, 17n, 123456789012345678901234567890n]) {
      const { y, pi } = vdfEvalCanonical(x, 120, N);
      expect(pi <= N - pi).toBe(true);
      expect(vdfVerifyCanonical(x, y, pi, 120, N)).toBe(true);
      expect(vdfVerifyCanonicalDetailed(x, y, N - pi, 120, N)).toEqual({ ok: false, reason: 'non-canonical-pi' });
    }
  });
  it('timelock: the pi/N-pi twin of a valid proof is rejected', () => {
    const o = { steps: 150, N, beacon: 'bcn', ...dev } as const;
    const p = proveTimelockElapsed('act', 150, N, { beacon: 'bcn', ...dev });
    expect(verifyTimelock('act', p, o)).toBe(true);
    expect(verifyTimelock('act', { ...p, pi: N - p.pi }, o)).toBe(false);
  });
});
