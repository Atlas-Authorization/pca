import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { useSingleThreadSnarkCurvesInWorkerThreads } from './test-support/snarkjs-single-thread';
import {
  DEFAULT_WASM_PATH,
  DEFAULT_ZKEY_PATH,
  DEFAULT_VKEY_PATH,
  POLICYVM_BLS12381_SAMPLE_PROOF_PATH,
  POLICYVM_BLS12381_VKEY_PATH,
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  POLICYVM_WASM_PATH,
  POLICYVM_ZKEY_PATH,
  proveGroth16Compliance,
  provePolicyVmCompliance,
  verifyPolicyVmProof,
} from './zk';
import { vkId } from './zk-ceremony';

beforeAll(useSingleThreadSnarkCurvesInWorkerThreads);

// Circuit-constraint tests (audit-readiness): every PUBLIC signal of each circuit is bound by the verification equation,
// so changing any one of them must fail verification; and perturbing any private witness input must either make proving
// impossible or change a public signal (a witness change that leaves every public signal the same and still proves is
// an under-constrained signal). The committed fixtures need no circom; the witness tests need the generated wasm + zkey
// (`PCA_DEV_SETUP=1 bash circuits/policyvm.setup.sh`) and are skipped, visibly, without them.

type G16 = { verify(vk: object, ps: string[], proof: object): Promise<boolean> };
const g16 = async (): Promise<G16> => ((await import('snarkjs' as string)) as { groth16: G16 }).groth16;
const R_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const R_BLS12381 = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;

const FIXTURES = [
  { name: 'bn254', vk: POLICYVM_VKEY_PATH, proof: POLICYVM_SAMPLE_PROOF_PATH, r: R_BN254 },
  { name: 'bls12-381', vk: POLICYVM_BLS12381_VKEY_PATH, proof: POLICYVM_BLS12381_SAMPLE_PROOF_PATH, r: R_BLS12381 },
];
const names = Object.entries(POLICYVM_PUBLIC_SIGNAL);

describe.each(FIXTURES)('Policy-VM circuit, $name: public signals are all bound', ({ vk, proof, r }) => {
  const vkey = JSON.parse(readFileSync(vk(), 'utf8')) as object;
  const env = JSON.parse(readFileSync(proof(), 'utf8')) as { proof: object; publicSignals: string[] };

  it('the untouched fixture verifies (the control for every case below)', async () => {
    expect(await (await g16()).verify(vkey, env.publicSignals, env.proof)).toBe(true);
  });

  it.each(names)('changing public signal %s (index %i) fails verification', async (_n, i) => {
    const g = await g16();
    for (const next of [(BigInt(env.publicSignals[i]!) + 1n).toString(), BigInt(env.publicSignals[i]!) === 0n ? '2' : '0']) {
      const ps = [...env.publicSignals];
      ps[i] = next;
      expect(await g.verify(vkey, ps, env.proof), `signal ${i} -> ${next}`).toBe(false);
    }
  });

  it.each(names)('replacing public signal %s with its value + the field order fails (non-canonical)', async (_n, i) => {
    const ps = [...env.publicSignals];
    ps[i] = (BigInt(ps[i]!) + r).toString();
    // the package verifier is canonical-only; raw snarkjs may reduce, so assert the package path
    expect(await verifyPolicyVmProof({ ...(env as object), system: vk === POLICYVM_VKEY_PATH ? 'groth16-bn254' : 'groth16-bls12-381', circuit: 'pca-policyvm-v1', publicSignals: ps } as never, { verificationKey: vkey })).toBe(false);
  });

  it('swapping two signals, dropping one or adding one fails', async () => {
    const g = await g16();
    const p = env.publicSignals;
    const sw = [...p];
    [sw[POLICYVM_PUBLIC_SIGNAL.r], sw[POLICYVM_PUBLIC_SIGNAL.now]] = [sw[POLICYVM_PUBLIC_SIGNAL.now]!, sw[POLICYVM_PUBLIC_SIGNAL.r]!];
    expect(await g.verify(vkey, sw, env.proof)).toBe(false);
    for (const bad of [p.slice(1), [...p, '1']]) expect(await g.verify(vkey, bad, env.proof).catch(() => false)).toBe(false);
  });

  it('the verifying key has exactly one input commitment per public signal', () => {
    expect((vkey as { IC: unknown[] }).IC).toHaveLength(env.publicSignals.length + 1);
    expect((vkey as { nPublic: number }).nPublic).toBe(env.publicSignals.length);
  });
});

describe('circuit versioning: the verifying key id', () => {
  it('differs between curves and is stable for one key', () => {
    const a = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8'));
    const b = JSON.parse(readFileSync(POLICYVM_BLS12381_VKEY_PATH(), 'utf8'));
    expect(vkId(a)).toBe(vkId(JSON.parse(JSON.stringify(a))));
    expect(vkId(a)).not.toBe(vkId(b));
    expect(vkId(a)).toMatch(/^vk_[0-9a-f]{64}$/);
  });
});

// the fixtures come from circuits/ensure-build.sh (vitest globalSetup), so this suite always runs
describe('compliance circuit (generated fixtures): public signals bound, witness perturbation', () => {
  const W = { verb: 7, resource: 42, planVerb: 7, policySalt: 111, planSalt: 222, actionSalt: 333, risk: 3, budget: 10 };
  const commit = (n: number) => Buffer.alloc(32, n).toString('base64url');
  const C = { action_commit: commit(1), policy_commit: commit(2), plan_commit: commit(3) };
  it('every public signal is bound', async () => {
    const vkey = JSON.parse(readFileSync(DEFAULT_VKEY_PATH(), 'utf8'));
    const p = await proveGroth16Compliance({ ...C, ...W });
    const g = await g16();
    expect(await g.verify(vkey, p.publicSignals, p.proof as object)).toBe(true);
    for (let i = 0; i < p.publicSignals.length; i++) {
      const ps = [...p.publicSignals];
      ps[i] = (BigInt(ps[i]!) + 1n).toString();
      expect(await g.verify(vkey, ps, p.proof as object), `signal ${i}`).toBe(false);
    }
  }, 120_000);
  // risk and budget are private and only constrained by risk <= budget, so +1 stays satisfiable: push them across the bound
  const PERTURBED: Record<string, number> = { ...W, risk: W.budget + 1, budget: W.risk - 1 };
  it.each(Object.keys(W))('perturbing witness %s: proving fails or a public signal changes', async (k) => {
    const base = await proveGroth16Compliance({ ...C, ...W });
    let after: string[] | undefined;
    try {
      after = (await proveGroth16Compliance({ ...C, ...W, [k]: k === 'risk' || k === 'budget' ? PERTURBED[k]! : (W as Record<string, number>)[k]! + 1 })).publicSignals;
    } catch {
      return; // unsatisfiable: good
    }
    expect(after).not.toEqual(base.publicSignals);
  }, 120_000);
});

const havePolicyVm = existsSync(POLICYVM_WASM_PATH()) && existsSync(POLICYVM_ZKEY_PATH());
describe.skipIf(!havePolicyVm)('Policy-VM circuit (needs the generated fixtures): witness perturbation', () => {
  const input = JSON.parse(readFileSync(join(__dirname, '..', 'circuits', 'policyvm_sample_input.json'), 'utf8')) as Record<string, string>;
  it.each(Object.keys(input))('perturbing witness input %s: proving fails or a public signal changes', async (k) => {
    const base = await provePolicyVmCompliance(input);
    let after: string[] | undefined;
    try {
      after = (await provePolicyVmCompliance({ ...input, [k]: (BigInt(input[k]!) + 1n).toString() })).publicSignals;
    } catch {
      return;
    }
    expect(after, `input ${k} is not constrained: changing it leaves every public signal unchanged`).not.toEqual(base.publicSignals);
  }, 600_000);
});
