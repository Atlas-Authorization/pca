/** Round 2: canonical verifier at T=0, the sequentialSquare modulus floor, and a clock that does not start at zero. */
import { describe, expect, it } from 'vitest';
import { insecureDevSetup, sequentialSquare, vdfEvalCanonical, vdfVerifyCanonicalDetailed } from './vdf';
import { calibrateSteps } from './timelock';

const dev = insecureDevSetup({ bits: 64 });
describe('round 2', () => {
  it('canonical verifier accepts T=0', () => {
    const p = vdfEvalCanonical(12345n, 0, dev.N);
    expect(vdfVerifyCanonicalDetailed(12345n, p.y, p.pi, 0, dev.N)).toEqual({ ok: true });
  });
  it('sequentialSquare refuses N <= 1 and works for N = 2', () => {
    for (const n of [1n, 0n, -3n]) expect(() => sequentialSquare(2n, 1, n)).toThrow('VDF: modulus N must be > 1');
    expect(sequentialSquare(1n, 3, 2n)).toBe(1n);
  });
  it('calibration uses the elapsed time, not the end timestamp', () => {
    const ts = [1000, 1500];
    const r = calibrateSteps({ N: dev.N, desiredSeconds: 1, sampleSquarings: 100, adversaryAdvantage: 1, now: () => ts.shift()! });
    expect(r.measuredSquaringsPerSecond).toBe(200);
  });
});
