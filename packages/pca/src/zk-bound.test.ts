/**
 * Risk-bound Policy-VM circuit ('pca-policyvm-v2'): the TypeScript side. snarkjs is replaced by a recording fake that
 * accepts whatever reaches it, so every guard in front of it is observable on its own (the real proofs for this circuit
 * are built and checked by the circuit CI job, see zk-circuits-ci.test.ts).
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const st = { calls: [] as unknown[][], result: true };
  const api = {
    verify: async (...args: unknown[]) => {
      st.calls.push(args);
      return st.result;
    },
  };
  return { st, api };
});
vi.mock('snarkjs', () => ({ groth16: h.api }));

import { assuranceLabelOf } from './assurance';
import type { VerifyContext } from './pcactn';
import {
  POLICYVM_BOUND_PUBLIC_SIGNAL,
  POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
  POLICYVM_BOUND_VKEY_PATH,
  POLICYVM_PUBLIC_SIGNAL,
  createPolicyVmBoundSnarkBackend,
  createPolicyVmSnarkBackend,
  decodePolicyVmBoundPublic,
  policyVmRiskHash,
  policyVmStructHash,
  verifyPolicyVmProof,
} from './zk';

const CIRC = `${__dirname}/../circuits`;
const v1 = JSON.parse(readFileSync(`${CIRC}/policyvm_sample_proof.json`, 'utf8')) as { system: string; circuit: string; proof: object; publicSignals: string[] };
const KEY = { fake: 'vkey' };
const RISK: [number, number, number, number, number] = [1_000_000, 0, 1_000_000, 0, 0];
const risk = policyVmRiskHash(RISK);
const action = { hi: '11', lo: '12' };
const policy = { hi: '21', lo: '22' };
const plan = { hi: '31', lo: '32' };
const ctx = {} as VerifyContext;

/** A v2 envelope: the canonical v1 proof elements (shape is all the canonical gate looks at) with the 17 v2 signals. */
function v2Env(over: Partial<Record<keyof typeof POLICYVM_BOUND_PUBLIC_SIGNAL, string>> = {}) {
  const P = POLICYVM_BOUND_PUBLIC_SIGNAL;
  const vals: Record<string, string> = {
    actionHi: action.hi, actionLo: action.lo, policyHi: policy.hi, policyLo: policy.lo, planHi: plan.hi, planLo: plan.lo,
    r: '65000', t: '1', admit: '1', riskHi: risk.hi, riskLo: risk.lo,
    allow: '1', now: '1000000000', blast: '0', delegationDepth: '0', recentCount: '0', allocChild: '500000', ...over,
  };
  const ps = new Array<string>(POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT);
  for (const [k, i] of Object.entries(P)) ps[i] = vals[k]!;
  return { system: 'groth16-bn254', circuit: 'pca-policyvm-v2', proof: JSON.parse(JSON.stringify(v1.proof)), publicSignals: ps };
}
const allPins = { expectActionHash: action, expectPolicyHash: policy, expectPlanHash: plan, expectRiskHash: risk, verificationKey: KEY };
const verifyBackend = (b: { verify(i: never): unknown }, proof: unknown) => b.verify({ proof, publicInputs: {}, ctx } as never);

const tmp = mkdtempSync(join(tmpdir(), 'zk-bound-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
beforeEach(() => {
  h.st.calls = [];
  h.st.result = true;
});

describe('policyVmRiskHash', () => {
  it('is the sha256 of the five uint64 big-endian fields, split into two 128-bit halves', () => {
    const bytes = Buffer.alloc(40);
    RISK.forEach((v, i) => bytes.writeBigUInt64BE(BigInt(v), i * 8));
    const d = createHash('sha256').update(bytes).digest();
    expect(risk).toEqual({ hi: BigInt('0x' + d.subarray(0, 16).toString('hex')).toString(), lo: BigInt('0x' + d.subarray(16).toString('hex')).toString() });
    expect(risk).toEqual(policyVmStructHash(RISK));
  });
  it('changes when any one risk field changes', () => {
    for (let i = 0; i < 5; i++) {
      const f = [...RISK] as typeof RISK;
      f[i] += 1;
      expect(policyVmRiskHash(f)).not.toEqual(risk);
    }
  });
  it('refuses a wrong field count and out-of-range fields', () => {
    expect(() => policyVmRiskHash([1, 2, 3, 4] as never)).toThrow('need exactly 5 risk fields');
    expect(() => policyVmRiskHash([1, 2, 3, 4, 5, 6] as never)).toThrow('need exactly 5 risk fields');
    expect(() => policyVmRiskHash([1, 2, 3, 4, -1])).toThrow('out of uint64 range');
    expect(() => policyVmRiskHash([1, 2, 3, 4, 1n << 64n])).toThrow('out of uint64 range');
  });
});

describe('v2 public-signal layout', () => {
  it('keeps the nine v1 outputs at the same indices and appends the risk halves before the public inputs', () => {
    for (const k of ['actionHi', 'actionLo', 'policyHi', 'policyLo', 'planHi', 'planLo', 'r', 't', 'admit'] as const) {
      expect(POLICYVM_BOUND_PUBLIC_SIGNAL[k]).toBe(POLICYVM_PUBLIC_SIGNAL[k]);
    }
    expect([POLICYVM_BOUND_PUBLIC_SIGNAL.riskHi, POLICYVM_BOUND_PUBLIC_SIGNAL.riskLo, POLICYVM_BOUND_PUBLIC_SIGNAL.allow, POLICYVM_BOUND_PUBLIC_SIGNAL.allocChild]).toEqual([9, 10, 11, 16]);
    expect(POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT).toBe(17);
    expect(Object.keys(POLICYVM_BOUND_PUBLIC_SIGNAL)).toHaveLength(17);
  });
  it('decodes every signal from its own index', () => {
    const d = decodePolicyVmBoundPublic(v2Env({ blast: '7', recentCount: '9' }).publicSignals);
    expect(d).toEqual({
      actionHash: action, policyHash: policy, planHash: plan, riskHash: risk,
      r: '65000', t: '1', admit: '1', allow: '1', now: '1000000000', blast: '7', delegationDepth: '0', recentCount: '9', allocChild: '500000',
    });
  });
  it('the default verifying-key location is the one the dev setup writes', () => {
    expect(POLICYVM_BOUND_VKEY_PATH().endsWith('/src/../circuits/build/policyvm_bound_vkey.json')).toBe(true);
  });
});

describe('verifyPolicyVmProof on the risk-bound circuit', () => {
  it('passes the exact vkey, signals and proof to snarkjs (control)', async () => {
    const env = v2Env();
    expect(await verifyPolicyVmProof(env, { verificationKey: KEY })).toBe(true);
    expect(h.st.calls).toEqual([[KEY, env.publicSignals, env.proof]]);
  });
  it('reads the verifying key from verificationKeyPath when no key object is given', async () => {
    const f = join(tmp, 'vk.json');
    writeFileSync(f, JSON.stringify({ from: 'file' }));
    expect(await verifyPolicyVmProof(v2Env(), { verificationKeyPath: f })).toBe(true);
    expect(h.st.calls[0]![0]).toEqual({ from: 'file' });
  });
  it('refuses wrong signal counts (15 = the v1 count, 16, 18)', async () => {
    for (const n of [15, 16, 18]) {
      const env = v2Env();
      env.publicSignals = n < 17 ? env.publicSignals.slice(0, n) : [...env.publicSignals, '0'];
      expect(await verifyPolicyVmProof(env, { verificationKey: KEY }), `n=${n}`).toBe(false);
    }
    expect(h.st.calls).toEqual([]);
  });
  it('refuses a released-allow bit that is not 1 (read at index 11, not the v1 index 9)', async () => {
    expect(await verifyPolicyVmProof(v2Env({ allow: '0' }), { verificationKey: KEY })).toBe(false);
    const env = v2Env();
    env.publicSignals[POLICYVM_PUBLIC_SIGNAL.allow] = '0'; // index 9 is riskHi in v2: not the allow bit
    expect(await verifyPolicyVmProof(env, { verificationKey: KEY })).toBe(true);
  });
  it('is BN254 only: a BLS12-381 v2 envelope is refused', async () => {
    expect(await verifyPolicyVmProof({ ...v2Env(), system: 'groth16-bls12-381' }, { verificationKey: KEY })).toBe(false);
    expect(h.st.calls).toEqual([]);
  });
  it('pins the context at the v2 indices', async () => {
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY, expect: { now: 1_000_000_000, requireAdmit: true, requireTier1: true, r: 65000 } })).toBe(true);
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY, expect: { now: 1 } })).toBe(false);
    expect(await verifyPolicyVmProof(v2Env({ admit: '0' }), { verificationKey: KEY, expect: { requireAdmit: true } })).toBe(false);
    expect(await verifyPolicyVmProof(v2Env({ allocChild: '2' }), { verificationKey: KEY, expect: { allocChild: 3 } })).toBe(false);
  });
  it('refuses a field-negative (non-canonical, >= 2^64) context signal', async () => {
    expect(await verifyPolicyVmProof(v2Env({ now: (1n << 64n).toString() }), { verificationKey: KEY })).toBe(false);
  });
  it('enforces the risk pin: equal halves pass; a different hi, a different lo, or a missing commitment fail', async () => {
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY, expectRiskHash: risk })).toBe(true);
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY, expectRiskHash: { hi: '1', lo: risk.lo } })).toBe(false);
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY, expectRiskHash: { hi: risk.hi, lo: '1' } })).toBe(false);
    // a proof of the same statement made from other risk magnitudes carries another commitment
    const other = policyVmRiskHash([0, 1, 0, 0, 0]);
    expect(await verifyPolicyVmProof(v2Env({ riskHi: other.hi, riskLo: other.lo }), { verificationKey: KEY, expectRiskHash: risk })).toBe(false);
  });
  it('a v1 proof has no risk commitment: a risk pin refuses it, and without the pin it still verifies (v1 unchanged)', async () => {
    expect(await verifyPolicyVmProof(v1, { verificationKey: KEY })).toBe(true);
    expect(h.st.calls).toHaveLength(1);
    expect(await verifyPolicyVmProof(v1, { verificationKey: KEY, expectRiskHash: risk })).toBe(false);
    expect(h.st.calls).toHaveLength(1);
  });
  it('refuses an unknown circuit id', async () => {
    expect(await verifyPolicyVmProof({ ...v2Env(), circuit: 'pca-policyvm-v3' }, { verificationKey: KEY })).toBe(false);
  });
  it('returns false when snarkjs says no', async () => {
    h.st.result = false;
    expect(await verifyPolicyVmProof(v2Env(), { verificationKey: KEY })).toBe(false);
  });
});

describe('backends keep the two circuits apart', () => {
  it('the v1 backend refuses a v2 envelope and the v2 backend refuses a v1 envelope, before snarkjs', async () => {
    expect(await verifyBackend(createPolicyVmSnarkBackend({ verificationKey: KEY }), v2Env())).toBe(false);
    expect(await verifyBackend(createPolicyVmBoundSnarkBackend({ verificationKey: KEY }), v1)).toBe(false);
    expect(h.st.calls).toEqual([]);
    expect(await verifyBackend(createPolicyVmSnarkBackend({ verificationKey: KEY }), v1)).toBe(true);
  });
  it('the v2 backend binds each of the four commitments (a wrong half in any one refuses)', async () => {
    const b = createPolicyVmBoundSnarkBackend(allPins);
    expect(await verifyBackend(b, v2Env())).toBe(true);
    for (const over of [{ actionHi: '0' }, { actionLo: '0' }, { policyHi: '0' }, { policyLo: '0' }, { planHi: '0' }, { planLo: '0' }, { riskHi: '0' }, { riskLo: '0' }]) {
      expect(await verifyBackend(b, v2Env(over)), JSON.stringify(over)).toBe(false);
    }
  });
  it('is labelled policyvm_snark only when action, policy, plan and risk are all pinned', () => {
    expect(assuranceLabelOf(createPolicyVmBoundSnarkBackend(allPins))).toEqual({ level: 'policyvm_snark', ceremony: 'single-party' });
    for (const drop of ['expectActionHash', 'expectPolicyHash', 'expectPlanHash', 'expectRiskHash'] as const) {
      const pins: Record<string, unknown> = { ...allPins };
      delete pins[drop];
      expect(assuranceLabelOf(createPolicyVmBoundSnarkBackend(pins)), drop).toEqual({ level: 'unknown', vendor: 'policyvm-unbound', ceremony: 'single-party' });
    }
  });
  it('rejects a non-object / missing envelope', async () => {
    const b = createPolicyVmBoundSnarkBackend(allPins);
    for (const bad of [null, undefined, 'x', {}, { circuit: 'pca-policyvm-v2' }]) expect(await verifyBackend(b, bad)).toBe(false);
  });
});
