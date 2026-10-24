/**
 * r13 g1: zk.ts guards in front of snarkjs, with snarkjs replaced by a recording fake (vi.mock). With the real verifier
 * almost every structural guard is shadowed (snarkjs also rejects the malformed proof), so a mutant that drops a guard
 * survives; with a fake that ACCEPTS whatever reaches it, each guard is observable on its own. Also pins exactly what
 * reaches snarkjs (vkey, signals, proof, witness, wasm/zkey paths) and the lazy loader's fallback / missing-API paths.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  type Call = { fn: 'verify' | 'fullProve'; args: unknown[] };
  const st = {
    calls: [] as Call[],
    verifyResult: true as boolean | 'throw',
    proveResult: { proof: { p: 1 }, publicSignals: ['9'] } as { proof: unknown; publicSignals: string[] },
    shape: 'named' as 'named' | 'default' | 'none',
  };
  const api = {
    verify: async (...args: unknown[]) => {
      st.calls.push({ fn: 'verify', args });
      if (st.verifyResult === 'throw') throw new Error('snark boom');
      return st.verifyResult;
    },
    fullProve: async (...args: unknown[]) => {
      st.calls.push({ fn: 'fullProve', args });
      return st.proveResult;
    },
  };
  return { st, api };
});

vi.mock('snarkjs', () => ({
  get groth16() {
    return h.st.shape === 'named' ? h.api : undefined;
  },
  get default() {
    return h.st.shape === 'default' ? { groth16: h.api } : undefined;
  },
}));

import {
  DEFAULT_VKEY_PATH,
  DEFAULT_WASM_PATH,
  DEFAULT_ZKEY_PATH,
  POLICYVM_BLS12381_SAMPLE_PROOF_PATH,
  POLICYVM_BLS12381_VKEY_PATH,
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  POLICYVM_WASM_PATH,
  POLICYVM_ZKEY_PATH,
  commitmentField,
  createGroth16SnarkBackend,
  createPolicyVmSnarkBackend,
  createPolicyVmSnarkBackendBls12381,
  policyVmStructHash,
  provePolicyVmCompliance,
  proveGroth16Compliance,
  verifyPolicyVmProof,
} from './zk';
import type { VerifyContext } from './pcactn';

// Outcome capture: a mutant that throws where a value is expected (or returns where a refusal is expected) fails an
// explicit toEqual assertion instead of an uncaught error.
type Outcome = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const caught = (e: unknown): Outcome => ({
  ok: false,
  error: e instanceof Error ? { name: e.constructor.name, message: e.message } : { name: typeof e, message: String(e) },
});
const settle = (f: () => unknown): Outcome => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return caught(e);
  }
};
const settleAsync = async (f: () => unknown): Promise<Outcome> => {
  try {
    return { ok: true, value: await f() };
  } catch (e) {
    return caught(e);
  }
};
const ok = (value: unknown): Outcome => ({ ok: true, value });
const refused = (message: string, name = 'Error'): Outcome => ({ ok: false, error: { name, message } });

// fixtures read by literal path (not via the zk.ts path helpers, which are mutated too)
const CIRC = `${__dirname}/../circuits`;
const FIX = {
  vkey: `${CIRC}/build/verification_key.json`,
  wasm: `${CIRC}/build/compliance_js/compliance.wasm`,
  zkey: `${CIRC}/build/compliance_final.zkey`,
  pvVkey: `${CIRC}/policyvm_vkey.json`,
  pvSample: `${CIRC}/policyvm_sample_proof.json`,
  pvWasm: `${CIRC}/build/policyvm_js/policyvm.wasm`,
  pvZkey: `${CIRC}/build/policyvm_final.zkey`,
  blsVkey: `${CIRC}/policyvm_bls12381_vkey.json`,
  blsSample: `${CIRC}/policyvm_bls12381_sample_proof.json`,
};
const sample = JSON.parse(readFileSync(FIX.pvSample, 'utf8')) as { system: string; circuit: string; proof: Record<string, unknown>; publicSignals: string[] };
const bnVkey = JSON.parse(readFileSync(FIX.pvVkey, 'utf8')) as object;
const blsVkey = JSON.parse(readFileSync(FIX.blsVkey, 'utf8')) as object;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const ctx = {} as VerifyContext;
const tmp = mkdtempSync(join(tmpdir(), 'zk-r13-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

beforeEach(() => {
  h.st.calls = [];
  h.st.verifyResult = true;
  h.st.shape = 'named';
  h.st.proveResult = { proof: { p: 1 }, publicSignals: ['9'] };
});

describe('fixture paths', () => {
  it('are exactly the package-relative locations, and the helpers load the same fixtures', () => {
    expect(settle(() => [DEFAULT_VKEY_PATH(), DEFAULT_WASM_PATH(), DEFAULT_ZKEY_PATH(), POLICYVM_VKEY_PATH(), POLICYVM_SAMPLE_PROOF_PATH(), POLICYVM_WASM_PATH(), POLICYVM_ZKEY_PATH(), POLICYVM_BLS12381_VKEY_PATH(), POLICYVM_BLS12381_SAMPLE_PROOF_PATH()])).toEqual(
      ok([FIX.vkey, FIX.wasm, FIX.zkey, FIX.pvVkey, FIX.pvSample, FIX.pvWasm, FIX.pvZkey, FIX.blsVkey, FIX.blsSample]),
    );
    const digest = (f: () => string) => settle(() => createHash('sha256').update(readFileSync(f())).digest('hex'));
    for (const [helper, lit] of [[DEFAULT_VKEY_PATH, FIX.vkey], [DEFAULT_WASM_PATH, FIX.wasm], [POLICYVM_VKEY_PATH, FIX.pvVkey], [POLICYVM_SAMPLE_PROOF_PATH, FIX.pvSample], [POLICYVM_BLS12381_VKEY_PATH, FIX.blsVkey], [POLICYVM_BLS12381_SAMPLE_PROOF_PATH, FIX.blsSample]] as const) {
      expect(digest(helper)).toEqual(ok(createHash('sha256').update(readFileSync(lit)).digest('hex')));
    }
  });

  it('are the documented package-relative locations', () => {
    expect(DEFAULT_VKEY_PATH().endsWith('/src/../circuits/build/verification_key.json')).toBe(true);
    expect(DEFAULT_WASM_PATH().endsWith('/src/../circuits/build/compliance_js/compliance.wasm')).toBe(true);
    expect(DEFAULT_ZKEY_PATH().endsWith('/src/../circuits/build/compliance_final.zkey')).toBe(true);
    expect(POLICYVM_VKEY_PATH().endsWith('/src/../circuits/policyvm_vkey.json')).toBe(true);
    expect(POLICYVM_SAMPLE_PROOF_PATH().endsWith('/src/../circuits/policyvm_sample_proof.json')).toBe(true);
    expect(POLICYVM_WASM_PATH().endsWith('/src/../circuits/build/policyvm_js/policyvm.wasm')).toBe(true);
    expect(POLICYVM_ZKEY_PATH().endsWith('/src/../circuits/build/policyvm_final.zkey')).toBe(true);
    expect(POLICYVM_BLS12381_VKEY_PATH().endsWith('/src/../circuits/policyvm_bls12381_vkey.json')).toBe(true);
    expect(POLICYVM_WASM_PATH().startsWith(__dirname)).toBe(true);
  });
});

describe('lazy snarkjs loader', () => {
  it('falls back to the default export when there is no named groth16', async () => {
    h.st.shape = 'default';
    expect(await settleAsync(() => verifyPolicyVmProof(sample, { verificationKey: bnVkey }))).toEqual(ok(true));
    expect(h.st.calls).toHaveLength(1);
  });

  it('with neither, proving throws the exact install hint and verification fails closed', async () => {
    h.st.shape = 'none';
    await expect(proveGroth16Compliance({ action_commit: 'AA', policy_commit: 'AA', plan_commit: 'AA', verb: 1, resource: 1, planVerb: 1, policySalt: 1, planSalt: 1, actionSalt: 1, risk: 1, budget: 1 })).rejects.toThrow(
      new Error('snarkjs groth16 API not available (install the optional dependency "snarkjs")'),
    );
    await expect(provePolicyVmCompliance({ a: 1 })).rejects.toThrow(new Error('snarkjs groth16 API not available (install the optional dependency "snarkjs")'));
    expect(await settleAsync(() => verifyPolicyVmProof(sample, { verificationKey: bnVkey }))).toEqual(ok(false));
  });
});

describe('proveGroth16Compliance: exact witness and fixtures handed to snarkjs', () => {
  const inp = { action_commit: 'AAEC', policy_commit: '__8', plan_commit: 'BAUG', verb: 7n, resource: '42', planVerb: 7, policySalt: 1, planSalt: 2, actionSalt: 3, risk: 4, budget: 5 };
  it('default fixtures', async () => {
    h.st.proveResult = { proof: { q: 2 }, publicSignals: ['1', '2'] };
    const out = await proveGroth16Compliance(inp);
    expect(out).toEqual({ system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof: { q: 2 }, publicSignals: ['1', '2'] });
    expect(h.st.calls).toEqual([
      {
        fn: 'fullProve',
        args: [
          {
            verb: '7', resource: '42', planVerb: '7', policySalt: '1', planSalt: '2', actionSalt: '3', risk: '4', budget: '5',
            shaPolicy: commitmentField('__8'), shaPlan: commitmentField('BAUG'), shaAction: commitmentField('AAEC'), allow: '1',
          },
          FIX.wasm,
          FIX.zkey,
        ],
      },
    ]);
  });
  it('explicit fixtures', async () => {
    await proveGroth16Compliance(inp, { wasmPath: '/w.wasm', zkeyPath: '/k.zkey' });
    expect(h.st.calls[0]!.args.slice(1)).toEqual(['/w.wasm', '/k.zkey']);
  });
});

describe('provePolicyVmCompliance: exact witness and fixtures handed to snarkjs', () => {
  it('stringifies every witness value; default and explicit fixtures', async () => {
    h.st.proveResult = { proof: { z: 1 }, publicSignals: ['3'] };
    const out = await provePolicyVmCompliance({ a: 1, b: 2n, c: 'x' });
    expect(out).toEqual({ system: 'groth16-bn254', circuit: 'pca-policyvm-v1', proof: { z: 1 }, publicSignals: ['3'] });
    expect(h.st.calls).toEqual([{ fn: 'fullProve', args: [{ a: '1', b: '2', c: 'x' }, FIX.pvWasm, FIX.pvZkey] }]);
    await provePolicyVmCompliance({}, { wasmPath: '/a', zkeyPath: '/b' });
    expect(h.st.calls[1]!.args).toEqual([{}, '/a', '/b']);
  });
});

// ---- createGroth16SnarkBackend: every guard before snarkjs -------------------------------------------------------------
describe('createGroth16SnarkBackend guards (snarkjs fake accepts)', () => {
  const pub = { action_commit: 'AAEC', policy_commit: 'AQID', plan_commit: 'BAUG' };
  const good = () => ({
    system: 'groth16-bn254',
    circuit: 'pca-compliance-v1',
    proof: clone(sample.proof),
    publicSignals: ['11', '12', '13', commitmentField(pub.policy_commit), commitmentField(pub.plan_commit), commitmentField(pub.action_commit), '1'],
  });
  const vkey = { vk: 1 };
  const run = (proof: unknown, b = createGroth16SnarkBackend({ verificationKey: vkey })) => b.verify({ proof, publicInputs: pub, ctx });

  it('a well-formed bound envelope reaches snarkjs with the vkey, the signals and the proof', async () => {
    const g = good();
    expect(await settleAsync(() => run(g))).toEqual(ok(true));
    expect(h.st.calls).toEqual([{ fn: 'verify', args: [vkey, g.publicSignals, g.proof] }]);
    h.st.verifyResult = false;
    expect(await settleAsync(() => run(good()))).toEqual(ok(false));
  });

  it('rejects non-objects and null without throwing', async () => {
    for (const p of [null, undefined, 'x', 7]) expect(await settleAsync(() => run(p))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('rejects a wrong system or circuit tag', async () => {
    expect(await settleAsync(() => run({ ...good(), system: 'groth16-bls12-381' }))).toEqual(ok(false));
    expect(await settleAsync(() => run({ ...good(), circuit: 'pca-policyvm-v1' }))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('rejects public signals that are not exactly 7, and a missing proof', async () => {
    expect(await settleAsync(() => run({ ...good(), publicSignals: [...good().publicSignals, '0'] }))).toEqual(ok(false));
    expect(await settleAsync(() => run({ ...good(), publicSignals: good().publicSignals.slice(0, 6) }))).toEqual(ok(false));
    expect(await settleAsync(() => run({ ...good(), publicSignals: Object.assign({}, good().publicSignals, { length: 7 }) }))).toEqual(ok(false));
    expect(await settleAsync(() => run({ ...good(), proof: null }))).toEqual(ok(false));
    expect(await settleAsync(() => run({ ...good(), proof: undefined }))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('requires allow == "1"', async () => {
    const g = good();
    g.publicSignals[6] = '0';
    expect(await settleAsync(() => run(g))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('binds each sha tag to the RS commitment', async () => {
    for (const i of [3, 4, 5]) {
      const g = good();
      g.publicSignals[i] = '5';
      expect(await settleAsync(() => run(g))).toEqual(ok(false));
    }
    expect(h.st.calls).toEqual([]);
  });

  it('only the canonical encoding reaches snarkjs', async () => {
    const g = good();
    g.publicSignals[0] = '011';
    expect(await settleAsync(() => run(g))).toEqual(ok(false));
    const g2 = good();
    (g2.proof as { pi_a: string[] }).pi_a[2] = '01';
    expect(await settleAsync(() => run(g2))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('loads the verifying key from verificationKeyPath once, else from the default path', async () => {
    const p = join(tmp, 'vk.json');
    writeFileSync(p, JSON.stringify({ from: 'file' }));
    const b = createGroth16SnarkBackend({ verificationKeyPath: p });
    expect(await settleAsync(() => run(good(), b))).toEqual(ok(true));
    rmSync(p);
    expect(await settleAsync(() => run(good(), b))).toEqual(ok(true)); // cached: the file is gone
    expect(h.st.calls.map((c) => c.args[0])).toEqual([{ from: 'file' }, { from: 'file' }]);
    h.st.calls = [];
    expect(await settleAsync(() => run(good(), createGroth16SnarkBackend()))).toEqual(ok(true));
    expect(h.st.calls[0]!.args[0]).toEqual(JSON.parse(readFileSync(FIX.vkey, 'utf8')));
  });
});

// ---- verifyPolicyVmProof: every guard before snarkjs ------------------------------------------------------------------
describe('verifyPolicyVmProof guards (snarkjs fake accepts)', () => {
  const good = () => clone(sample);
  const v = (e: unknown, o: Parameters<typeof verifyPolicyVmProof>[1] = { verificationKey: bnVkey }) => verifyPolicyVmProof(e, o);

  it('a well-formed envelope reaches snarkjs exactly once with the vkey, signals and proof', async () => {
    const g = good();
    expect(await settleAsync(() => v(g))).toEqual(ok(true));
    expect(h.st.calls).toEqual([{ fn: 'verify', args: [bnVkey, g.publicSignals, g.proof] }]);
  });

  it('snarkjs throwing or rejecting is false', async () => {
    h.st.verifyResult = 'throw';
    expect(await settleAsync(() => v(good()))).toEqual(ok(false));
    h.st.verifyResult = false;
    expect(await settleAsync(() => v(good()))).toEqual(ok(false));
  });

  it('rejects non-objects without throwing', async () => {
    for (const e of [null, undefined, 'x', 3, true]) expect(await settleAsync(() => v(e))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('rejects a wrong circuit or an unknown system', async () => {
    expect(await settleAsync(() => v({ ...good(), circuit: 'pca-compliance-v1' }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), system: 'groth16-bn255' }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), system: undefined }))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('rejects public signals that are not exactly 15, and a missing proof', async () => {
    expect(await settleAsync(() => v({ ...good(), publicSignals: [...good().publicSignals, '0'] }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), publicSignals: good().publicSignals.slice(0, 14) }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), publicSignals: Object.assign({}, good().publicSignals, { length: 15 }) }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), proof: null }))).toEqual(ok(false));
    expect(await settleAsync(() => v({ ...good(), proof: undefined }))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
  });

  it('requires allow == "1", the canonical encoding and the pinned context', async () => {
    const a = good();
    a.publicSignals[POLICYVM_PUBLIC_SIGNAL.allow] = '0';
    expect(await settleAsync(() => v(a))).toEqual(ok(false));
    const c = good();
    c.publicSignals[0] = '0' + c.publicSignals[0];
    expect(await settleAsync(() => v(c))).toEqual(ok(false));
    expect(await settleAsync(() => v(good(), { verificationKey: bnVkey, expect: { now: 5 } }))).toEqual(ok(false));
    const n = good();
    n.publicSignals[POLICYVM_PUBLIC_SIGNAL.now] = (1n << 64n).toString();
    expect(await settleAsync(() => v(n))).toEqual(ok(false));
    expect(h.st.calls).toEqual([]);
    expect(await settleAsync(() => v(good(), { verificationKey: bnVkey, expect: { now: 1_000_000_000 } }))).toEqual(ok(true));
  });

  it('a BLS12-381 envelope is checked as BLS and defaults to the BLS vkey; BN254 to the BN254 vkey; a path overrides', async () => {
    const bls = JSON.parse(readFileSync(FIX.blsSample, 'utf8')) as typeof sample;
    expect(await settleAsync(() => verifyPolicyVmProof(bls))).toEqual(ok(true));
    expect(h.st.calls[0]!.args[0]).toEqual(blsVkey);
    expect(await settleAsync(() => verifyPolicyVmProof(good()))).toEqual(ok(true));
    expect(h.st.calls[1]!.args[0]).toEqual(bnVkey);
    const p = join(tmp, 'pv.json');
    writeFileSync(p, JSON.stringify({ custom: true }));
    expect(await settleAsync(() => verifyPolicyVmProof(good(), { verificationKeyPath: p }))).toEqual(ok(true));
    expect(h.st.calls[2]!.args[0]).toEqual({ custom: true });
    // a BN254 envelope mislabelled as BLS fails the BLS canonical gate (curve tag 'bn128')
    expect(await settleAsync(() => verifyPolicyVmProof({ ...good(), system: 'groth16-bls12-381' }))).toEqual(ok(false));
    // and a BLS envelope labelled BN254 fails the BN254 gate
    expect(await settleAsync(() => verifyPolicyVmProof({ ...bls, system: 'groth16-bn254' }))).toEqual(ok(false));
    expect(h.st.calls).toHaveLength(3);
  });
});

// ---- the Policy-VM backends: struct-hash binding + forwarding --------------------------------------------------------
describe('createPolicyVmSnarkBackend / Bls12381 (snarkjs fake accepts)', () => {
  const bls = JSON.parse(readFileSync(FIX.blsSample, 'utf8')) as typeof sample;
  const P = POLICYVM_PUBLIC_SIGNAL;
  const ps = sample.publicSignals;
  const halves = (hi: number, lo: number) => ({ hi: ps[hi]!, lo: ps[lo]! });
  const A = halves(P.actionHi, P.actionLo);
  const POL = halves(P.policyHi, P.policyLo);
  const PLAN = halves(P.planHi, P.planLo);

  for (const [name, make, env, defVkey] of [
    ['bn254', createPolicyVmSnarkBackend, sample, bnVkey],
    ['bls12-381', createPolicyVmSnarkBackendBls12381, bls, blsVkey],
  ] as const) {
    const run = (b: ReturnType<typeof make>, proof: unknown = clone(env)) => b.verify({ proof, publicInputs: { action_commit: '', policy_commit: '', plan_commit: '' }, ctx });

    it(`${name}: matching halves verify; each half of each hash is checked`, async () => {
      expect(await settleAsync(() => run(make({ verificationKey: { k: 1 }, expectActionHash: A, expectPolicyHash: POL, expectPlanHash: PLAN })))).toEqual(ok(true));
      for (const want of [
        { expectActionHash: { ...A, hi: '1' } },
        { expectActionHash: { ...A, lo: '1' } },
        { expectPolicyHash: { ...POL, hi: '1' } },
        { expectPolicyHash: { ...POL, lo: '1' } },
        { expectPlanHash: { ...PLAN, hi: '1' } },
        { expectPlanHash: { ...PLAN, lo: '1' } },
        { expectActionHash: POL },
        { expectPlanHash: A },
      ]) {
        expect(await settleAsync(() => run(make({ verificationKey: { k: 1 }, ...want })))).toEqual(ok(false));
      }
      expect(h.st.calls).toHaveLength(1);
    });

    it(`${name}: forwards the vkey and the expectation; defaults the vkey to its curve fixture`, async () => {
      expect(await settleAsync(() => run(make({ verificationKey: { k: 2 } })))).toEqual(ok(true));
      expect(h.st.calls[0]!.args[0]).toEqual({ k: 2 });
      expect(await settleAsync(() => run(make({ verificationKey: { k: 2 }, expect: { now: 7 } })))).toEqual(ok(false));
      expect(await settleAsync(() => run(make({ verificationKey: { k: 2 }, expect: () => ({ requireAdmit: true, now: 1_000_000_000 }) })))).toEqual(ok(true));
      expect(await run(make()))
        .toBe(true);
      expect(h.st.calls[2]!.args[0]).toEqual(defVkey);
    });

    it(`${name}: a missing or signal-less proof is false, never a throw`, async () => {
      const b = make({ verificationKey: { k: 3 }, expectActionHash: A });
      expect(await settleAsync(() => run(b, null))).toEqual(ok(false));
      expect(await b.verify({ proof: undefined, publicInputs: { action_commit: '', policy_commit: '', plan_commit: '' }, ctx })).toBe(false);
      expect(await settleAsync(() => run(b, { ...clone(env), publicSignals: undefined }))).toEqual(ok(false));
      expect(await settleAsync(() => run(make({ verificationKey: { k: 3 } }), null))).toEqual(ok(false));
      expect(h.st.calls).toEqual([]);
    });
  }

  it('the halves are compared against the right indices', () => {
    // sanity for the fixture: a struct hash recomputed from the sample's action struct equals the action halves
    expect(settle(() => policyVmStructHash([7, 42, 0, 100]))).toEqual(ok(A));
  });
});
