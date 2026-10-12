/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Mutation-kill tests for index.ts: exact validation messages, blob envelope checks (each header byte), the
 * fail-closed noise-budget check per ciphertext, signed decode of a negative risk, and that EVERY WASM-side
 * object a call creates is deleted on every exit path (node-seal is wrapped so each object's delete() is counted).
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';

const live = new Set<object>();
const seen = new WeakSet<object>();
let created = 0;
function track<T>(o: T): T {
  if (o === null || typeof o !== 'object' || seen.has(o as object)) return o;
  const obj = o as any;
  if (typeof obj.delete !== 'function') return o;
  seen.add(obj);
  live.add(obj);
  created++;
  for (const k of Object.keys(obj)) {
    const f = obj[k];
    if (typeof f !== 'function') continue;
    obj[k] =
      k === 'delete'
        ? (...a: unknown[]) => {
            live.delete(obj);
            return f.apply(obj, a);
          }
        : (...a: unknown[]) => track(f.apply(obj, a));
  }
  return o;
}
vi.mock('node-seal', async (importOriginal) => {
  const real: any = await importOriginal();
  const SEAL = real.default ?? real;
  return {
    default: async () => {
      const seal = await SEAL();
      const wrapped: any = { ...seal };
      for (const k of Object.keys(seal)) {
        if (typeof seal[k] === 'function') wrapped[k] = (...a: unknown[]) => track(seal[k](...a));
      }
      wrapped.PlainModulus = { ...seal.PlainModulus, Batching: (...a: unknown[]) => track(seal.PlainModulus.Batching(...a)) };
      return wrapped;
    },
  };
});

import { DEFAULT_RISK_POLICY, type PCActn } from '@atlasauth/pca';
import {
  SIGNED_BOUND,
  bindingFromPCActn,
  decryptVerdict,
  encryptRiskInputs,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
  quantizeRiskInputs,
  riskInputsFromPCActn,
  weightVector,
  type EvalKeys,
  type FheKeyset,
} from './index';

const TIMEOUT = 120_000;
const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
const inputs = [500, 0, 250, 0, 1000, 0];

let keys: FheKeyset;
let other: FheKeyset;
let evalKeys: EvalKeys;
let enc: string;
let gate: { encRiskRaw: string; encSlack: string };

const rejects = async (p: Promise<unknown>, msg: string) => {
  await expect(p).rejects.toThrow(msg);
  await p.catch((e: Error) => expect(e.message).toBe(msg));
};
/** Re-encode a valid blob with byte `i` changed (keeps the declared size equal to the length). */
const patch = (blob: string, i: number, v: number) => {
  const bin = Buffer.from(blob, 'base64');
  bin[i] = v;
  return bin.toString('base64');
};

beforeAll(async () => {
  keys = await keygen();
  other = await keygen();
  evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };
  enc = await encryptRiskInputs(keys.publicKey, inputs);
  gate = await evalRiskGate(evalKeys, enc, policy);
}, TIMEOUT * 2);

describe('WASM objects are released on every path', () => {
  it('keygen / encrypt / evaluate / decrypt leave no live SEAL object', async () => {
    expect(live.size).toBe(0);
    const before = created;
    await keygen();
    expect(created - before).toBeGreaterThanOrEqual(9); // params, modulus, context, encoder, keygen + 4 keys: the wrapper really sees them
    expect(live.size).toBe(0);
    await encryptRiskInputs(keys.publicKey, inputs);
    expect(live.size).toBe(0);
    await evalRiskGate(evalKeys, enc, policy);
    expect(live.size).toBe(0);
    // an all-zero policy takes the encrypt-zero branch
    const zeroPol = fheRiskPolicy({ ...DEFAULT_RISK_POLICY, weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } }, 0.6);
    await evalRiskGate(evalKeys, enc, zeroPol);
    expect(live.size).toBe(0);
    await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
    expect(live.size).toBe(0);
  }, TIMEOUT);
  it('...including when SEAL throws mid-call', async () => {
    // a well-formed envelope that does not belong to this kind of object makes SEAL's loader throw after objects exist
    await expect(encryptRiskInputs(keys.secretKey, inputs)).rejects.toThrow();
    expect(live.size).toBe(0);
    await expect(evalRiskGate({ ...evalKeys, galoisKeys: keys.publicKey }, enc, policy)).rejects.toThrow();
    expect(live.size).toBe(0);
    await expect(decryptVerdict(keys.publicKey, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow();
    expect(live.size).toBe(0);
    await expect(decryptVerdict(other.secretKey, gate.encRiskRaw, gate.encSlack, policy)).rejects.toThrow();
    expect(live.size).toBe(0);
  }, TIMEOUT);
});

describe('validation messages', () => {
  it('quantize / policy builder', () => {
    expect(() => quantizeRiskInputs({} as any, 0)).toThrow(new Error('scale must be a positive integer'));
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, 0.5, 1.5)).toThrow(new Error('scale must be a positive integer'));
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, -1)).toThrow(new Error('budget must be finite and >= 0'));
    expect(() => fheRiskPolicy({ ...DEFAULT_RISK_POLICY, kappa: 0 }, 1)).toThrow(new Error('policy.kappa must be finite and > 0'));
    const zeroW = { ...DEFAULT_RISK_POLICY, kappa: 1, weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } };
    expect(() => fheRiskPolicy(zeroW, SIGNED_BOUND, 1)).toThrow(
      new Error(`policy/scale overflow the plain modulus: max |value| ${SIGNED_BOUND} must be < SIGNED_BOUND ${SIGNED_BOUND}. Lower the scale or the weights/budget.`),
    );
    expect(fheRiskPolicy(zeroW, SIGNED_BOUND - 1, 1).budgetScaled).toBe(SIGNED_BOUND - 1);
  });
  it('weight clamp: negative and non-finite weights are 0, zero stays 0', () => {
    expect(weightVector({ alpha: -1, beta: Number.POSITIVE_INFINITY, gamma: Number.NaN, delta: 0, epsilon: 0.5, zeta: -0.1 })).toEqual([0, 0, 0, 0, 0.5, 0]);
  });
  it('policy object checks (an evaluator receives the policy as JSON)', async () => {
    await rejects(evalRiskGate(evalKeys, enc, null as any), 'policy must be an object');
    await rejects(evalRiskGate(evalKeys, enc, { ...policy, scale: 0 }), 'policy.scale must be a positive integer');
    await rejects(evalRiskGate(evalKeys, enc, { ...policy, budgetScaled: 0.5 }), 'policy coefficients must be integers with |value| < SIGNED_BOUND');
    await rejects(evalRiskGate(evalKeys, enc, { ...policy, dim: 5 } as any), 'policy.dim must be 6');
    await rejects(evalRiskGate(evalKeys, enc, { ...policy, weightsScaled: [1, 2] }), 'policy weight vectors must have length 6');
    // a missing vector is not "a bad coefficient": it fails on the length read
    for (const k of ['weightsScaled', 'kappaWeightsScaled'] as const) {
      const p: any = { ...policy };
      delete p[k];
      await expect(evalRiskGate(evalKeys, enc, p)).rejects.toThrow(TypeError);
    }
  });
  it('argument checks and blob labels', async () => {
    await rejects(encryptRiskInputs(keys.publicKey, 'x' as any), 'inputsScaled must be an array');
    for (const k of [null, 'str', 5]) await rejects(evalRiskGate(k as any, enc, policy), 'evalKeys must be an object');
    await rejects(evalRiskGate({ ...evalKeys, publicKey: 'bad' }, enc, policy), 'publicKey: not a serialized SEAL object (bad encoding)');
    await rejects(evalRiskGate(evalKeys, 'bad', policy), 'encInputs: not a serialized SEAL object (bad encoding)');
    await rejects(decryptVerdict(keys.secretKey, 'bad', gate.encSlack, policy), 'encRiskRaw: not a serialized SEAL object (bad encoding)');
    await rejects(decryptVerdict(keys.secretKey, gate.encRiskRaw, 'bad', policy), 'encSlack: not a serialized SEAL object (bad encoding)');
  });
});

describe('SEAL blob envelope', () => {
  it('non-strings and lengths that are not a multiple of 4 are bad encodings', async () => {
    const fake = { length: 24, toString: () => keys.publicKey };
    await rejects(encryptRiskInputs(fake as any, inputs), 'publicKey: not a serialized SEAL object (bad encoding)');
    await rejects(encryptRiskInputs('A'.repeat(26), inputs), 'publicKey: not a serialized SEAL object (bad encoding)');
    await rejects(encryptRiskInputs('A'.repeat(27), inputs), 'publicKey: not a serialized SEAL object (bad encoding)');
  });
  it('each header byte is checked', async () => {
    for (const [i, v] of [[0, 0x5f], [1, 0xa0], [2, 15], [5, 3], [6, 1], [7, 1]] as const) {
      await rejects(encryptRiskInputs(patch(keys.publicKey, i, v), inputs), 'publicKey: not a serialized SEAL object (bad header)');
    }
    expect(live.size).toBe(0);
  });
});

describe('decryptVerdict', () => {
  it('fails closed when EITHER ciphertext has no noise budget (foreign key)', async () => {
    const foreign = await evalRiskGate({ publicKey: other.publicKey, relinKeys: other.relinKeys, galoisKeys: other.galoisKeys }, await encryptRiskInputs(other.publicKey, inputs), policy);
    const msg = 'decryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)';
    await rejects(decryptVerdict(keys.secretKey, foreign.encRiskRaw, gate.encSlack, policy), msg);
    await rejects(decryptVerdict(keys.secretKey, gate.encRiskRaw, foreign.encSlack, policy), msg);
    const ok = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
    expect(ok.admit).toBe(ok.slack >= 0);
  }, TIMEOUT);
  it('a negative raw risk (hand-made policy with negative weights) decodes signed and clamps to 0', async () => {
    const neg = { ...policy, weightsScaled: policy.weightsScaled.map((w) => -w) };
    const g = await evalRiskGate(evalKeys, enc, neg);
    const v = await decryptVerdict(keys.secretKey, g.encRiskRaw, g.encSlack, neg);
    expect(v.rScaled).toBe(0);
    const pos = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
    const expected = policy.weightsScaled.reduce((a, w, i) => a + w * inputs[i]!, 0);
    expect(pos.rScaled).toBe(expected);
  }, TIMEOUT);
});

describe('PCActn helpers', () => {
  it('non-numeric risk inputs read as NaN; nonce is copied only when present', () => {
    const p = {
      aud: 'a', counter: 3, action: { params_digest: 'pd' },
      risk_claim: { inputs: { semanticDistance: 0.5, reversibility: '1', blastRadius: null, taint: undefined, confidence: 1, age: {} } },
    } as unknown as PCActn;
    const r = riskInputsFromPCActn(p);
    expect(r.semanticDistance).toBe(0.5);
    expect(r.confidence).toBe(1);
    for (const k of ['reversibility', 'blastRadius', 'taint', 'age'] as const) expect(Number.isNaN(r[k])).toBe(true);
    const b = bindingFromPCActn(p);
    expect(b).toEqual({ aud: 'a', actionRef: 'pd', counter: 3 });
    expect('nonce' in b).toBe(false);
    expect(bindingFromPCActn({ ...p, nonce: 'n' } as PCActn).nonce).toBe('n');
  });
});
