/**
 * dudect-style timing checks for the secret-scalar paths of pca-bbs.
 *
 * Method (after Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?"): two input classes, here a
 * scalar of Hamming weight 1 ("sparse") and one of Hamming weight 253 ("dense"); randomly interleaved
 * measurements; outliers above the pooled 80th percentile cropped; Welch's t statistic on the class means.
 * A variable-time double-and-add shows a huge |t| on exactly this split, which is the positive control.
 *
 * STATED THRESHOLD: the test fails if |t| >= T_FAIL (10) AND the class medians differ by more than 5%.
 * (dudect's own bounds: |t| > 10 "definitely leaky", > 4.5 "probably".) Requiring both keeps a noisy shared
 * machine from producing false alarms while still failing on a real Hamming-weight dependence, which the
 * control shows is a >30% effect with |t| in the hundreds.
 *
 * WHAT THIS IS NOT: a proof. JavaScript gives no constant-time guarantee (BigInt arithmetic, JIT and GC all
 * have data-dependent timing, and the library's window method indexes a table by secret digits). A pass means
 * "no first-order Hamming-weight dependence of this size is visible on this machine in this run".
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bls12_381 } from '@noble/curves/bls12-381';
import { keyGen, proofGen, sign, skToPk, R } from './bbs';

const T_FAIL = 10;
const MEDIAN_BAND = 0.05;

const SPARSE = 1n << 200n; // Hamming weight 1
const DENSE = (1n << 253n) - 1n; // Hamming weight 253, below the group order
if (DENSE >= R) throw new Error('test setup: dense scalar must be below the group order');

function welch(a: number[], b: number[]): number {
  const mean = (x: number[]) => x.reduce((s, v) => s + v, 0) / x.length;
  const varr = (x: number[], m: number) => x.reduce((s, v) => s + (v - m) ** 2, 0) / (x.length - 1);
  const ma = mean(a);
  const mb = mean(b);
  return (ma - mb) / Math.sqrt(varr(a, ma) / a.length + varr(b, mb) / b.length);
}
const q = (x: number[], p: number): number => [...x].sort((u, v) => u - v)[Math.floor(p * (x.length - 1))] as number;

interface Result {
  t: number;
  medianRatio: number;
}

/** Interleaved (random order) measurement of `fn(classScalar)` for the sparse and dense class. */
function dudect(fn: (s: bigint) => unknown, samples: number): Result {
  for (let i = 0; i < 6; i++) {
    fn(SPARSE);
    fn(DENSE);
  }
  const t: [number[], number[]] = [[], []];
  const order: number[] = [];
  for (let i = 0; i < samples; i++) order.push(0, 1);
  // Fisher-Yates with a fixed LCG so a run is reproducible
  let st = 0x9e3779b9;
  for (let i = order.length - 1; i > 0; i--) {
    st = (Math.imul(st, 1664525) + 1013904223) >>> 0;
    const j = st % (i + 1);
    [order[i], order[j]] = [order[j] as number, order[i] as number];
  }
  for (const c of order) {
    const t0 = performance.now();
    fn(c === 0 ? SPARSE : DENSE);
    (t[c] as number[]).push(performance.now() - t0);
  }
  const cut = q([...t[0], ...t[1]], 0.8);
  const a = t[0].filter((v) => v <= cut);
  const b = t[1].filter((v) => v <= cut);
  return { t: welch(a, b), medianRatio: q(t[1], 0.5) / q(t[0], 0.5) };
}

const leaks = (r: Result): boolean => Math.abs(r.t) >= T_FAIL && Math.abs(r.medianRatio - 1) > MEDIAN_BAND;

describe('timing (dudect-style): secret-scalar multiplication does not depend on the scalar Hamming weight', () => {
  const G2 = bls12_381.G2.ProjectivePoint;
  const G1 = bls12_381.G1.ProjectivePoint;

  it('positive control: the library variable-time multiply IS detected by this harness', () => {
    const r = dudect((s) => G2.BASE.multiplyUnsafe(s), 120);
    expect(leaks(r)).toBe(true);
  }, 120_000);

  it('skToPk (secret key times the G2 generator): no Hamming-weight dependence', () => {
    const r = dudect((s) => skToPk(s), 120);
    expect(leaks(r)).toBe(false);
  }, 120_000);

  it('proofGen with prover blinding scalars r1,r2 of weight 1 vs 253: no Hamming-weight dependence', () => {
    const sk = keyGen(new Uint8Array(32).fill(7));
    const pk = skToPk(sk);
    const header = new Uint8Array([1]);
    const msgs = [new Uint8Array([1])];
    const sig = sign(sk, pk, header, msgs);
    // fixedRandomScalars = [r1, r2, eTilde, r1Tilde, r3Tilde, mTilde]: all five blinds take the class scalar
    const r = dudect((s) => proofGen(pk, sig, header, new Uint8Array(0), msgs, [], [s, s, s, s, s, s]), 60);
    expect(leaks(r)).toBe(false);
  }, 120_000);

  it('G1 secret multiply path used by sign/proofGen (library multiply) vs the control on the same points', () => {
    const P = G1.BASE.multiply(12345n);
    const ctl = dudect((s) => P.multiplyUnsafe(s), 200);
    const ct = dudect((s) => P.multiply(s), 200);
    expect(leaks(ctl)).toBe(true);
    expect(leaks(ct)).toBe(false);
  }, 120_000);
});

describe('static guard: no variable-time multiply or Euclid inversion on a secret path', () => {
  const src = readFileSync(join(__dirname, 'bbs.ts'), 'utf8');
  const body = (name: string): string => {
    const i = src.indexOf(`function ${name}(`);
    if (i < 0) throw new Error(`test setup: ${name} not found`);
    const j = src.indexOf('\n}\n', i);
    return src.slice(i, j);
  };

  it('sign, proofGen, skToPk and the B commitment use only the secret-scalar multiply and Fermat inversion', () => {
    for (const f of ['sign', 'proofGen', 'skToPk', 'computeB']) {
      expect(body(f), f).not.toMatch(/\bg[12]mul\(/);
      expect(body(f), f).not.toMatch(/multiplyUnsafe/);
      expect(body(f), f).not.toMatch(/Fr\.inv\(/);
    }
  });

  it('multiplyUnsafe is confined to the two public-scalar helpers', () => {
    expect([...src.matchAll(/multiplyUnsafe\(/g)].length).toBe(2);
    expect(src).not.toMatch(/Fr\.inv\(/);
  });
});
