/**
 * Adversarial / audit-style tests for @atlasauth/pca-fhe (complements the BFV round-trip, parameter and
 * serialization suites; does not repeat them): untrusted-policy validation, malformed / swapped /
 * truncated SEAL objects, wrong-key and garbage-ciphertext behaviour, the (documented) lack of
 * evaluator integrity, IND-CPA sanity, property tests and bounded fuzzing of the parse entries.
 * Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import {
  RISK_DIM,
  SIGNED_BOUND,
  decryptVerdict,
  encryptRiskInputs,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
  quantizeRiskInputs,
  type EvalKeys,
  type FheKeyset,
  type FheRiskPolicy,
} from './index';

const TIMEOUT = 600_000;
const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
const inputs = [100, 900, 100, 100, 100, 100];

let ks: FheKeyset;
let other: FheKeyset;
let ev: EvalKeys;
let enc: string;
let gate: { encRiskRaw: string; encSlack: string };

beforeAll(async () => {
  ks = await keygen();
  other = await keygen();
  ev = { publicKey: ks.publicKey, relinKeys: ks.relinKeys, galoisKeys: ks.galoisKeys };
  enc = await encryptRiskInputs(ks.publicKey, inputs);
  gate = await evalRiskGate(ev, enc, policy);
}, TIMEOUT);

const bad = (over: Partial<FheRiskPolicy>): FheRiskPolicy => ({ ...policy, ...over });

describe('untrusted policy: every coefficient is validated (a truncated / wrapped value would silently be a different circuit)', () => {
  it('evalRiskGate and decryptVerdict refuse NaN, fractional, infinite, out-of-range and mistyped coefficients before touching any key', async () => {
    const w = (i: number, v: number) => policy.weightsScaled.map((x, k) => (k === i ? v : x));
    const cases: FheRiskPolicy[] = [
      bad({ weightsScaled: w(0, Number.NaN) }),
      bad({ weightsScaled: w(1, 0.5) }),
      bad({ weightsScaled: w(2, Infinity) }),
      bad({ weightsScaled: w(3, 2 ** 32 + 5) }), // would wrap through Int32Array to a small number
      bad({ weightsScaled: w(4, SIGNED_BOUND) }),
      bad({ kappaWeightsScaled: policy.kappaWeightsScaled.map(() => -SIGNED_BOUND) }),
      bad({ budgetScaled: Number.NaN }),
      bad({ budgetScaled: 2 ** 40 }),
      bad({ scale: 0 }),
      bad({ scale: -1000 }),
      bad({ scale: 1.5 }),
      bad({ scale: Number.NaN }),
      bad({ dim: 5 }),
      bad({ weightsScaled: policy.weightsScaled.slice(1) }),
      bad({ kappaWeightsScaled: [...policy.kappaWeightsScaled, 1] }),
      bad({ weightsScaled: ['1', 2, 3, 4, 5, 6] as never }),
      null as never,
      undefined as never,
    ];
    for (const p of cases) {
      await expect(evalRiskGate(ev, enc, p)).rejects.toThrow();
      await expect(decryptVerdict(ks.secretKey, gate.encRiskRaw, gate.encSlack, p)).rejects.toThrow();
    }
  });

  it('fheRiskPolicy itself rejects overflowing scale / budget / kappa / non-positive scale', () => {
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, 1e9)).toThrow();
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, -1)).toThrow();
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, Number.NaN)).toThrow();
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, 1, 0)).toThrow();
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, 1, 1e7)).toThrow(/overflow/);
    expect(() => fheRiskPolicy({ ...DEFAULT_RISK_POLICY, kappa: 0 }, 1)).toThrow();
    expect(() => fheRiskPolicy({ ...DEFAULT_RISK_POLICY, kappa: Number.NaN }, 1)).toThrow();
  });

  it('encryptRiskInputs refuses wrong arity, negative, fractional, NaN and over-bound inputs (before any key is parsed)', async () => {
    for (const v of [[], [1, 2, 3], [...inputs, 1], [-1, 0, 0, 0, 0, 0], [0.5, 0, 0, 0, 0, 0], [Number.NaN, 0, 0, 0, 0, 0], [SIGNED_BOUND, 0, 0, 0, 0, 0], [Infinity, 0, 0, 0, 0, 0]]) {
      await expect(encryptRiskInputs(ks.publicKey, v)).rejects.toThrow();
    }
    expect(() => quantizeRiskInputs({} as never, 0)).toThrow();
  });
});

describe('malformed, swapped and truncated SEAL objects', () => {
  it('non-strings, empty, short, non-base64, bad header, truncated and padded blobs are rejected with a typed error', async () => {
    const blobs: unknown[] = [undefined, null, 5, {}, [], '', 'AAAA', '!!!!'.repeat(10), 'A'.repeat(100), enc.slice(0, enc.length - 8), enc.slice(0, 40), enc + 'AAAA', enc.replace(/^..../, 'AAAA')];
    for (const b of blobs) {
      await expect(evalRiskGate(ev, b as string, policy)).rejects.toThrow();
      await expect(encryptRiskInputs(b as string, inputs)).rejects.toThrow();
      await expect(decryptVerdict(b as string, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow();
      await expect(decryptVerdict(ks.secretKey, b as string, gate.encSlack, policy)).rejects.toThrow();
    }
  });

  it('an object of the wrong KIND (public key where a ciphertext is expected, ciphertext where a key is expected) is rejected', async () => {
    await expect(evalRiskGate(ev, ks.publicKey, policy)).rejects.toThrow();
    await expect(evalRiskGate({ ...ev, galoisKeys: ks.publicKey }, enc, policy)).rejects.toThrow();
    await expect(evalRiskGate({ ...ev, publicKey: enc }, enc, policy)).rejects.toThrow();
    await expect(decryptVerdict(enc, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow();
    await expect(decryptVerdict(ks.secretKey, ks.publicKey, gate.encSlack, policy)).rejects.toThrow();
    await expect(encryptRiskInputs(enc, inputs)).rejects.toThrow();
  });
});

describe('decryption fails closed on anything that is not a gate output under THIS key', () => {
  it('honest round-trip: raw = sum(w*x), slack = budget - kappa*raw', async () => {
    const v = await decryptVerdict(ks.secretKey, gate.encRiskRaw, gate.encSlack, policy);
    const raw = inputs.reduce((a, x, i) => a + x * (policy.weightsScaled[i] ?? 0), 0);
    const kraw = inputs.reduce((a, x, i) => a + x * (policy.kappaWeightsScaled[i] ?? 0), 0);
    expect(v.rScaled).toBe(raw);
    expect(v.slack).toBe(policy.budgetScaled - kraw);
    expect(v.admit).toBe(v.slack >= 0);
  }, TIMEOUT);

  it('a gate output decrypted with a DIFFERENT secret key throws (it would otherwise be random garbage that "admits" half the time)', async () => {
    await expect(decryptVerdict(other.secretKey, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow(/noise budget/);
    await expect(decryptVerdict(other.secretKey, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow();
  }, TIMEOUT);

  it('inputs encrypted under another key evaluate to garbage that is rejected at decryption, not silently admitted', async () => {
    const foreign = await encryptRiskInputs(other.publicKey, inputs);
    const g = await evalRiskGate(ev, foreign, policy); // the evaluator cannot tell
    await expect(decryptVerdict(ks.secretKey, g.encRiskRaw, g.encSlack, policy)).rejects.toThrow(/noise budget/);
  }, TIMEOUT);

  it('DOCUMENTED LIMIT (confidentiality, not integrity): anyone holding the public key can mint a ciphertext that decrypts to an arbitrary "slack" and is accepted', async () => {
    // Slot 0 of a freshly encrypted vector is what decryptVerdict reads for both outputs.
    const forged = await encryptRiskInputs(ks.publicKey, [123456, 0, 0, 0, 0, 0]);
    const v = await decryptVerdict(ks.secretKey, forged, forged, policy);
    expect(v.slack).toBe(123456);
    expect(v.admit).toBe(true);
  }, TIMEOUT);

  it('the rScaled output is clamped at scale^2 and never negative', async () => {
    const huge = await encryptRiskInputs(ks.publicKey, [SIGNED_BOUND - 1, 0, 0, 0, 0, 0]);
    const v = await decryptVerdict(ks.secretKey, huge, huge, policy);
    expect(v.rScaled).toBeLessThanOrEqual(policy.scale * policy.scale);
    expect(v.rScaled).toBeGreaterThanOrEqual(0);
  }, TIMEOUT);
});

describe('IND-CPA sanity and key independence', () => {
  it('encrypting the same plaintext twice gives different ciphertexts; two keygens give different keys', async () => {
    const again = await encryptRiskInputs(ks.publicKey, inputs);
    expect(again).not.toBe(enc);
    expect(other.secretKey).not.toBe(ks.secretKey);
    expect(other.publicKey).not.toBe(ks.publicKey);
  }, TIMEOUT);

  it('the evaluator output does not contain the plaintext inputs in the clear', () => {
    const blob = Buffer.from(gate.encRiskRaw, 'base64');
    for (const v of [260000, 100, 900]) {
      const le = Buffer.alloc(4);
      le.writeUInt32LE(v);
      expect(blob.includes(le)).toBe(false);
    }
  });
});

describe('property tests (fast-check)', () => {
  it('quantizeRiskInputs is total: any numbers (incl. NaN/inf/huge) yield integers in [0, scale]', () => {
    fc.assert(
      fc.property(fc.array(fc.oneof(fc.double({ noNaN: false }), fc.constantFrom(Infinity, -Infinity, Number.NaN)), { minLength: 6, maxLength: 6 }), fc.integer({ min: 1, max: 5000 }), (xs, scale) => {
        const [semanticDistance, reversibility, blastRadius, taint, confidence, age] = xs as [number, number, number, number, number, number];
        const q = quantizeRiskInputs({ semanticDistance, reversibility, blastRadius, taint, confidence, age } as never, scale);
        return q.length === RISK_DIM && q.every((v) => Number.isInteger(v) && v >= 0 && v <= scale);
      }),
      { numRuns: 300 },
    );
  });

  it('encrypted gate equals the integer oracle for random in-range inputs (a few full BFV round-trips)', async () => {
    const draws = fc.sample(fc.array(fc.integer({ min: 0, max: 1000 }), { minLength: 6, maxLength: 6 }), 3);
    for (const xs of draws) {
      const e = await encryptRiskInputs(ks.publicKey, xs);
      const g = await evalRiskGate(ev, e, policy);
      const v = await decryptVerdict(ks.secretKey, g.encRiskRaw, g.encSlack, policy);
      const raw = xs.reduce((a, x, i) => a + x * (policy.weightsScaled[i] ?? 0), 0);
      const kraw = xs.reduce((a, x, i) => a + x * (policy.kappaWeightsScaled[i] ?? 0), 0);
      expect(v.rScaled).toBe(Math.min(raw, policy.scale * policy.scale));
      expect(v.slack).toBe(policy.budgetScaled - kraw);
    }
  }, TIMEOUT);
});

describe('bounded fuzzing of every parse entry (typed errors only, no hang)', () => {
  it('random and structurally-mutated blobs through every entry reject quickly with an Error', async () => {
    const deadline = Date.now() + FUZZ_MS;
    const decoded = Buffer.from(enc, 'base64');
    let n = 0;
    while (Date.now() < deadline) {
      n++;
      const m = Buffer.from(decoded);
      const flips = 1 + (n % 4);
      for (let i = 0; i < flips; i++) {
        // keep the 16-byte SEAL header intact on odd rounds so deeper validation is reached
        const lo = n % 2 ? 16 : 0;
        const at = lo + Math.floor(Math.random() * (m.length - lo));
        m[at] = (m[at] ?? 0) ^ (1 << Math.floor(Math.random() * 8));
      }
      const mutated = m.toString('base64');
      const t0 = performance.now();
      for (const run of [() => evalRiskGate(ev, mutated, policy), () => decryptVerdict(ks.secretKey, mutated, mutated, policy)]) {
        try {
          const r = await run();
          // A mutated ciphertext may still decode (low-order noise flips are harmless in BFV); it must
          // never produce a verdict that disagrees silently with a throw: just require a well-formed result.
          expect(r).toBeDefined();
        } catch (e) {
          expect(e instanceof Error).toBe(true);
          expect((e as Error).message).not.toMatch(/Cannot read propert|is not a function|undefined is not/);
        }
      }
      expect(performance.now() - t0, 'one parse took > 20s').toBeLessThan(20_000);
    }
    expect(n).toBeGreaterThan(0);
  }, TIMEOUT);

  it('arbitrary strings and shapes for keys, policies and inputs never produce an untyped failure', async () => {
    await fc.assert(
      fc.asyncProperty(fc.anything(), fc.anything(), fc.string({ maxLength: 120 }), async (a, b, s) => {
        for (const run of [
          () => evalRiskGate(a as never, s, b as never),
          () => decryptVerdict(s, s, s, b as never),
          () => encryptRiskInputs(s, a as never),
        ]) {
          try {
            await run();
            return false; // garbage must never succeed
          } catch (e) {
            if (!(e instanceof Error) || /Cannot read propert|is not a function|undefined is not/.test(e.message)) return false;
          }
        }
        return true;
      }),
      { numRuns: 100000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false },
    );
    void fuzzOpts;
  }, TIMEOUT);
});
