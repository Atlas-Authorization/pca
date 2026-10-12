/**
 * dudect-style timing checks for the secret-scalar paths of pca-oprf.
 *
 * Method (after Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?"): two input classes, here a
 * scalar of Hamming weight 1 ("sparse") and one of Hamming weight 252 ("dense"); randomly interleaved
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
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RistrettoPoint } from '@noble/curves/ed25519';
import { blind, blindEvaluate, deriveKeyPair, serializeScalar } from './oprf';

const T_FAIL = 10;
const MEDIAN_BAND = 0.05;

const SPARSE = 1n << 200n; // Hamming weight 1
const ORDER = 2n ** 252n + 27742317777372353535851937790883648493n; // ristretto255 group order (RFC 9496)
const DENSE = (1n << 252n) - 1n; // Hamming weight 252, below the group order
if (DENSE >= ORDER) throw new Error('test setup: dense scalar must be below the group order');

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


const x = new TextEncoder().encode('timing input');

describe('timing (dudect-style): the server key multiply and the client blind do not depend on the scalar Hamming weight', () => {
  const blinded = blind(x).blindedElement;

  it('positive control: the library variable-time multiply IS detected by this harness', () => {
    const P = RistrettoPoint.BASE.multiply(987654321n);
    const r = dudect((s) => P.multiplyUnsafe(s), 400);
    expect(leaks(r)).toBe(true);
  }, 120_000);

  it('blindEvaluate (OPRF): sparse vs dense server secret key shows no Hamming-weight dependence', () => {
    const r = dudect((s) => blindEvaluate(serializeScalar(s), blinded, 'oprf'), 400);
    expect(leaks(r)).toBe(false);
  }, 120_000);

  it('blindEvaluate (VOPRF, incl. the DLEQ proof that multiplies by the key): no Hamming-weight dependence', () => {
    const r = dudect((s) => blindEvaluate(serializeScalar(s), blinded, 'voprf'), 150);
    expect(leaks(r)).toBe(false);
  }, 120_000);

  it('blind with a sparse vs dense client blind scalar: no Hamming-weight dependence', () => {
    const r = dudect((s) => blind(x, 'oprf', serializeScalar(s)), 300);
    expect(leaks(r)).toBe(false);
  }, 120_000);

  it('deriveKeyPair is deterministic (sanity for the harness inputs)', () => {
    const seed = new Uint8Array(32).fill(3);
    expect(Buffer.from(deriveKeyPair(seed, new Uint8Array(0), 'oprf').secretKey).toString('hex')).toBe(Buffer.from(deriveKeyPair(seed, new Uint8Array(0), 'oprf').secretKey).toString('hex'));
  });
});

describe('static guard: no variable-time multiply or Euclid inversion on a secret path', () => {
  const src = readFileSync(join(__dirname, 'oprf.ts'), 'utf8');
  const body = (name: string): string => {
    const i = src.indexOf(`function ${name}(`);
    if (i < 0) throw new Error(`test setup: ${name} not found`);
    const j = src.indexOf('\n}\n', i);
    return src.slice(i, j);
  };
  const secretPaths = ['scalarBaseMult', 'scalarInvert', 'blind', 'blindEvaluate', 'evaluate', 'blindEvaluatePoprf', 'evaluatePoprf', 'finalize', 'finalizePoprf', 'generateProof', 'computeCompositesFast'];

  it('secret-handling functions never call invert() (extended Euclid)', () => {
    for (const f of secretPaths) expect(body(f), f).not.toMatch(/\binvert\(/);
    expect(src).not.toMatch(/import \{[^}]*\binvert\b[^}]*\} from/);
  });

  it('multiplyUnsafe appears only where the scalar is a public transcript value (composites coefficient, proof verification)', () => {
    const uses = [...src.matchAll(/multiplyUnsafe\(/g)].length;
    // computeComposites: 2, computeCompositesFast: 1, verifyProof: 4
    expect(uses).toBe(7);
    for (const f of secretPaths.filter((n) => n !== 'computeCompositesFast')) expect(body(f), f).not.toMatch(/multiplyUnsafe\(/);
  });
});
