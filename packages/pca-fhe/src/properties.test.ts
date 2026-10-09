import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { DEFAULT_RISK_POLICY, type RiskInputs, type RiskPolicy, cost, riskScore } from '@atlasauth/pca';
import {
  DEFAULT_SCALE,
  RISK_DIM,
  SIGNED_BOUND,
  type EvalKeys,
  type FheKeyset,
  type FheRiskPolicy,
  decryptVerdict,
  encryptRiskInputs,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
  quantizeRiskInputs,
  transformedInputs,
} from './index';

const TIMEOUT = 600_000;

// ---------------------------------------------------------------------------------------------
// Generators. Inputs deliberately include out-of-range, negative, NaN and +/-Infinity values,
// because risk.ts maps every one of those to a defined (fail-closed) value.
// ---------------------------------------------------------------------------------------------
const rawInput: fc.Arbitrary<number> = fc.oneof(
  { weight: 6, arbitrary: fc.double({ min: 0, max: 1, noNaN: true }) },
  { weight: 1, arbitrary: fc.constantFrom(0, 1, 0.5, 0.0005, 0.9995, 0.0004999, 0.0005001) },
  { weight: 1, arbitrary: fc.double({ min: -5, max: 5, noNaN: true }) },
  { weight: 1, arbitrary: fc.constantFrom(Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0) },
);

const riskInputs: fc.Arbitrary<RiskInputs> = fc.record({
  semanticDistance: rawInput,
  reversibility: rawInput,
  blastRadius: rawInput,
  taint: rawInput,
  confidence: rawInput,
  age: rawInput,
});

/** Policies whose weights sum to at most 1 (the regime where the linear circuit equals the plaintext gate). */
const corePolicy: fc.Arbitrary<RiskPolicy> = fc
  .record({
    w: fc.array(fc.double({ min: 0, max: 1, noNaN: true }), { minLength: 6, maxLength: 6 }),
    kappa: fc.double({ min: 0.01, max: 1, noNaN: true }),
    budget: fc.double({ min: 0, max: 1, noNaN: true }),
  })
  .map(({ w, kappa }) => {
    const total = w.reduce((a, b) => a + b, 0);
    const norm = total > 1 ? total : 1; // scale down only when the sum exceeds 1
    const [alpha = 0, beta = 0, gamma = 0, delta = 0, epsilon = 0, zeta = 0] = w.map((v) => v / norm);
    return { ...DEFAULT_RISK_POLICY, weights: { alpha, beta, gamma, delta, epsilon, zeta }, kappa };
  });

const budgetArb = fc.double({ min: 0, max: 1, noNaN: true });

// ---------------------------------------------------------------------------------------------
// The integer circuit, written out in plain BigInt: exactly what the encrypted evaluation computes
// (mod t, centered). Used as the oracle for the ciphertext path and to bound divergence from risk.ts.
// ---------------------------------------------------------------------------------------------
function emulate(x: number[], p: FheRiskPolicy): { riskRaw: number; slack: number } {
  let r = 0n;
  let kr = 0n;
  for (let i = 0; i < RISK_DIM; i++) {
    const xi = BigInt(x[i] ?? 0);
    r += BigInt(p.weightsScaled[i] ?? 0) * xi;
    kr += BigInt(p.kappaWeightsScaled[i] ?? 0) * xi;
  }
  return { riskRaw: Number(r), slack: Number(BigInt(p.budgetScaled) - kr) };
}

/** Rounding-error bound of the fixed-point pipeline on r (and on kappa*r), derived term by term. */
function errBound(sumW: number, S: number): number {
  return (sumW + RISK_DIM) / (2 * S) + RISK_DIM / (4 * S * S) + 1e-9;
}

describe('fixed-point pipeline vs plaintext risk.ts (property-based, no encryption)', () => {
  it('quantized inputs are integers in [0,S] for any raw input, including NaN/Inf/out-of-range', () => {
    fc.assert(
      fc.property(riskInputs, fc.constantFrom(1, 10, 100, DEFAULT_SCALE), (inp, S) => {
        const q = quantizeRiskInputs(inp, S);
        expect(q).toHaveLength(RISK_DIM);
        for (const v of q) {
          expect(Number.isInteger(v)).toBe(true);
          expect(v).toBeGreaterThanOrEqual(0);
          expect(v).toBeLessThanOrEqual(S);
        }
      }),
      { numRuns: 500 },
    );
  });

  it('transformedInputs is the vector risk.ts weights: dot with the weights equals riskScore (pre-clamp)', () => {
    fc.assert(
      fc.property(riskInputs, corePolicy, (inp, core) => {
        const t = transformedInputs(inp);
        const w = core.weights;
        const dot = w.alpha * t[0]! + w.beta * t[1]! + w.gamma * t[2]! + w.delta * t[3]! + w.epsilon * t[4]! + w.zeta * t[5]!;
        // Weights sum <= 1 and every term in [0,1] => the clamp in riskScore is inactive.
        expect(riskScore(inp, w)).toBeCloseTo(Math.min(1, Math.max(0, dot)), 12);
      }),
      { numRuns: 500 },
    );
  });

  it('integer circuit stays within the derived rounding bound of riskScore, and agrees on admit outside that band', () => {
    fc.assert(
      fc.property(riskInputs, corePolicy, budgetArb, (inp, core, budget) => {
        const S = DEFAULT_SCALE;
        const pol = fheRiskPolicy(core, budget, S);
        const x = quantizeRiskInputs(inp, S);
        const { riskRaw, slack } = emulate(x, pol);
        const sumW = Object.values(core.weights).reduce((a, b) => a + b, 0);
        const r = riskScore(inp, core.weights);
        expect(Math.abs(riskRaw / (S * S) - r)).toBeLessThanOrEqual(errBound(sumW, S));

        // admit: slack >= 0 <=> kappa*r <= B up to the same bound (+ budget rounding).
        const band = errBound(core.kappa * sumW, S) + 1 / (2 * S * S);
        const ref = cost(r, core.kappa) <= budget;
        if (Math.abs(core.kappa * r - budget) > band) {
          expect(slack >= 0).toBe(ref);
        }
      }),
      { numRuns: 1000 },
    );
  });

  it('fheRiskPolicy either throws or guarantees every intermediate stays below the signed bound', () => {
    const wide = fc.record({
      w: fc.array(fc.double({ min: 0, max: 50, noNaN: true }), { minLength: 6, maxLength: 6 }),
      kappa: fc.double({ min: 0.01, max: 50, noNaN: true }),
      budget: fc.double({ min: 0, max: 1000, noNaN: true }),
      S: fc.constantFrom(10, 100, 1000, 5000, 20000),
    });
    let accepted = 0;
    let rejected = 0;
    fc.assert(
      fc.property(wide, ({ w, kappa, budget, S }) => {
        const [alpha = 0, beta = 0, gamma = 0, delta = 0, epsilon = 0, zeta = 0] = w;
        const core: RiskPolicy = { ...DEFAULT_RISK_POLICY, weights: { alpha, beta, gamma, delta, epsilon, zeta }, kappa };
        let pol: FheRiskPolicy;
        try {
          pol = fheRiskPolicy(core, budget, S);
        } catch (e) {
          rejected++;
          expect(String(e)).toMatch(/overflow the plain modulus/);
          return;
        }
        accepted++;
        const worst = emulate(new Array<number>(RISK_DIM).fill(S), pol);
        expect(Math.abs(worst.riskRaw)).toBeLessThan(SIGNED_BOUND);
        expect(Math.abs(worst.slack)).toBeLessThan(SIGNED_BOUND);
        expect(pol.budgetScaled).toBeLessThan(SIGNED_BOUND);
      }),
      { numRuns: 800 },
    );
    expect(accepted).toBeGreaterThan(0);
    expect(rejected).toBeGreaterThan(0);
  });

  it('boundary cases: all-zero, all-worst, NaN fail-closed, and the exact slack == 0 edge', () => {
    const S = DEFAULT_SCALE;
    const best: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
    const worst: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
    const nan: RiskInputs = {
      semanticDistance: Number.NaN,
      reversibility: Number.NaN,
      blastRadius: Number.NaN,
      taint: Number.NaN,
      confidence: Number.NaN,
      age: Number.NaN,
    };
    expect(quantizeRiskInputs(best, S)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(quantizeRiskInputs(worst, S)).toEqual([S, S, S, S, S, S]);
    expect(quantizeRiskInputs(nan, S)).toEqual([S, S, S, S, S, S]); // fail-closed == worst case

    const atBudget = fheRiskPolicy(DEFAULT_RISK_POLICY, 1, S);
    expect(emulate(quantizeRiskInputs(worst, S), atBudget)).toEqual({ riskRaw: S * S, slack: 0 }); // slack 0 => admit
    const justUnder = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.999999, S);
    expect(emulate(quantizeRiskInputs(worst, S), justUnder).slack).toBe(-1); // one unit short => deny
    const zeroBudget = fheRiskPolicy(DEFAULT_RISK_POLICY, 0, S);
    expect(emulate(quantizeRiskInputs(best, S), zeroBudget)).toEqual({ riskRaw: 0, slack: 0 }); // r = 0, B = 0 => admit
  });
});

describe('encrypted evaluation equals the integer oracle across random inputs (property-based, real BFV)', () => {
  let keys: FheKeyset;
  let evalKeys: EvalKeys;

  beforeAll(async () => {
    keys = await keygen();
    evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };
  }, TIMEOUT);

  async function roundTrip(x: number[], pol: FheRiskPolicy) {
    const enc = await encryptRiskInputs(keys.publicKey, x);
    const gate = await evalRiskGate(evalKeys, enc, pol);
    return decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, pol);
  }

  it(
    'random in-range vectors and policies: decrypted riskRaw/slack/admit match the BigInt oracle exactly',
    async () => {
      await fc.assert(
        fc.asyncProperty(
          riskInputs,
          corePolicy,
          budgetArb,
          async (inp, core, budget) => {
            const pol = fheRiskPolicy(core, budget, DEFAULT_SCALE);
            const x = quantizeRiskInputs(inp, DEFAULT_SCALE);
            const want = emulate(x, pol);
            const got = await roundTrip(x, pol);
            const cap = DEFAULT_SCALE * DEFAULT_SCALE;
            expect(got.rScaled).toBe(Math.min(cap, Math.max(0, want.riskRaw)));
            expect(got.slack).toBe(want.slack);
            expect(got.admit).toBe(want.slack >= 0);
            // ...and the plaintext risk.ts reference within the derived bound.
            const sumW = Object.values(core.weights).reduce((a, b) => a + b, 0);
            expect(Math.abs(got.rScaled / cap - riskScore(inp, core.weights))).toBeLessThanOrEqual(errBound(sumW, DEFAULT_SCALE));
          },
        ),
        { numRuns: 12 },
      );
    },
    TIMEOUT,
  );

  it(
    'boundary vectors under encryption: all-zero, all-worst, and the exact slack == 0 / -1 edge',
    async () => {
      const S = DEFAULT_SCALE;
      const zeros = new Array<number>(RISK_DIM).fill(0);
      const worst = new Array<number>(RISK_DIM).fill(S);

      const v0 = await roundTrip(zeros, fheRiskPolicy(DEFAULT_RISK_POLICY, 0, S));
      expect(v0).toEqual({ rScaled: 0, slack: 0, admit: true });

      const vEdge = await roundTrip(worst, fheRiskPolicy(DEFAULT_RISK_POLICY, 1, S));
      expect(vEdge).toEqual({ rScaled: S * S, slack: 0, admit: true });

      const vDeny = await roundTrip(worst, fheRiskPolicy(DEFAULT_RISK_POLICY, 0.999999, S));
      expect(vDeny).toEqual({ rScaled: S * S, slack: -1, admit: false });
    },
    TIMEOUT,
  );

  it(
    'a larger plaintext-weight policy near the signed bound still decrypts exactly (no silent wrap)',
    async () => {
      // Largest admissible weight total at S = 1000: exercises values close to SIGNED_BOUND.
      const S = DEFAULT_SCALE;
      const core: RiskPolicy = {
        ...DEFAULT_RISK_POLICY,
        weights: { alpha: 80, beta: 80, gamma: 80, delta: 80, epsilon: 80, zeta: 80 },
        kappa: 1,
      };
      const pol = fheRiskPolicy(core, 100, S);
      const x = [S, S, S, S, S, S];
      const want = emulate(x, pol);
      expect(Math.abs(want.riskRaw)).toBeLessThan(SIGNED_BOUND);
      const got = await roundTrip(x, pol);
      expect(got.slack).toBe(want.slack);
      expect(got.admit).toBe(false);
    },
    TIMEOUT,
  );
});
