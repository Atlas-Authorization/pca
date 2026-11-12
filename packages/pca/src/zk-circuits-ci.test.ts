/**
 * Witness-level audit of the three circuits, run against the real compiled witness calculators (no proving key needed).
 * For every private input: perturb it; either the circuit refuses the witness or at least one public signal changes.
 * A perturbation that is accepted and leaves every public signal unchanged is an under-constrained input.
 *
 * Artifacts come from the circuit CI job (circom --wasm into circuits/build). Locally they may be absent and the suite
 * is skipped; with PCA_REQUIRE_CIRCUITS=1 (the CI job) a missing artifact FAILS the suite instead.
 * CI shards the perturbation cases: PCA_ZK_CIRCUIT=<circuit> PCA_ZK_SHARD=k/n (see test-support/zk-shard.ts; zk-shard.test.ts proves
 * the shards partition every private input). The control cases run in the job that owns shard 1 of policyvm_bound.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { myShard, runsControls } from './test-support/zk-shard';
import { commitmentField, policyVmRiskHash, policyVmStructHash, POLICYVM_BOUND_PUBLIC_SIGNAL, POLICYVM_PUBLIC_SIGNAL } from './zk';

const CIRC = join(__dirname, '..', 'circuits');
const BUILD = join(CIRC, 'build');
const REQUIRE = process.env.PCA_REQUIRE_CIRCUITS === '1';
const WASM = {
  compliance: join(BUILD, 'compliance_js', 'compliance.wasm'),
  v1: join(BUILD, 'policyvm_js', 'policyvm.wasm'),
  v2: join(BUILD, 'policyvm_bound_js', 'policyvm_bound.wasm'),
};
const present = Object.values(WASM).every((f) => existsSync(f));
const tmp = mkdtempSync(join(tmpdir(), 'zk-wit-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Input = Record<string, string>;
let n = 0;
/** Witness public signals (decimal strings), or null when the circuit refuses the witness. */
async function witness(wasm: string, input: Input, nPublic: number): Promise<string[] | null> {
  const spec: string = 'snarkjs';
  const sj = (await import(spec)) as { wtns: { calculate(i: Input, w: string, o: string): Promise<void>; exportJson(f: string): Promise<bigint[]> } };
  const out = join(tmp, `w${n++}.wtns`);
  try {
    await sj.wtns.calculate(input, wasm, out);
  } catch {
    return null;
  }
  return (await sj.wtns.exportJson(out)).slice(1, 1 + nPublic).map(String);
}

if (REQUIRE) {
  describe('circuit artifacts', () => {
    it('are all built (PCA_REQUIRE_CIRCUITS=1: a missing artifact fails, never skips)', () => {
      expect(Object.entries(WASM).filter(([, f]) => !existsSync(f)).map(([k]) => k)).toEqual([]);
    });
  });
}

const D = !present && !REQUIRE ? describe.skip : describe;
const S = 1_000_000n;
const POLICY_PUBLIC = ['allow', 'now', 'blast', 'delegationDepth', 'recentCount', 'allocChild'];
const sample = JSON.parse(readFileSync(join(CIRC, 'policyvm_sample_input.json'), 'utf8')) as Input;
const POLICY_PRIVATE = Object.keys(sample).filter((k) => !POLICY_PUBLIC.includes(k));
const RISK = ['revScore', 'taint', 'conf', 'age', 'rFloorIn'];

/** Recompute the four division witnesses the way the circuit proves them (rQ/rRem, costQ/costRem). */
function withDivisions(i: Input): Input {
  const b = (k: string) => BigInt(i[k]!);
  const rNum = b('wAlpha') * b('semanticDist') + b('wBeta') * (S - b('revScore')) + b('wGamma') * b('blast') + b('wDelta') * b('taint') + b('wEpsilon') * (S - b('conf')) + b('wZeta') * b('age');
  const rQ = rNum / S;
  const clamped = rQ <= S ? rQ : S;
  const rFinal = b('rFloorIn') <= clamped ? clamped : b('rFloorIn');
  const costNum = b('kappa') * rFinal;
  return { ...i, rQ: String(rQ), rRem: String(rNum % S), costQ: String(costNum / S), costRem: String(costNum % S) };
}

// shard-gated on purpose (they need v1 and v2 and run once); missing artifacts still fail via the check above
(runsControls() ? D : describe.skip)('Policy-VM circuits: control cases', () => {
  it('v1: the sample witness is accepted and its public signals carry the sha256 of the sample structs', async () => {
    const ps = (await witness(WASM.v1, sample, 15))!;
    expect(ps).not.toBeNull();
    const P = POLICYVM_PUBLIC_SIGNAL;
    const fields = (ks: string[]) => ks.map((k) => sample[k]!);
    const action = policyVmStructHash(fields(['verb', 'resource', 'reversibility', 'paramScalar']));
    expect([ps[P.actionHi], ps[P.actionLo]]).toEqual([action.hi, action.lo]);
    expect([ps[P.allow], ps[P.t], ps[P.admit]]).toEqual(['1', '1', '1']);
  }, 600_000);

  it('v2: the same sample gives the v1 signals at indices 0-8, the risk commitment at 9-10 and the v1 inputs at 11-16', async () => {
    const v1 = (await witness(WASM.v1, sample, 15))!;
    const v2 = (await witness(WASM.v2, sample, 17))!;
    const P = POLICYVM_BOUND_PUBLIC_SIGNAL;
    expect(v2.slice(0, 9)).toEqual(v1.slice(0, 9));
    expect(v2.slice(11)).toEqual(v1.slice(9));
    const risk = policyVmRiskHash(RISK.map((k) => sample[k]!) as never);
    expect([v2[P.riskHi], v2[P.riskLo]]).toEqual([risk.hi, risk.lo]);
  }, 600_000);

  it('v2: changing a risk magnitude to another valid value changes the commitment to exactly the new digest, and r with it', async () => {
    const base = (await witness(WASM.v2, withDivisions(sample), 17))!;
    for (const [k, v] of [['revScore', '900000'], ['taint', '100000'], ['conf', '900000'], ['age', '100000'], ['rFloorIn', '50000']] as const) {
      const input = withDivisions({ ...sample, [k]: v });
      const ps = (await witness(WASM.v2, input, 17))!;
      expect(ps, k).not.toBeNull();
      const want = policyVmRiskHash(RISK.map((x) => input[x]!) as never);
      expect([ps[9], ps[10]], k).toEqual([want.hi, want.lo]);
      expect([ps[9], ps[10]], k).not.toEqual([base[9], base[10]]);
    }
  }, 900_000);

  it('a deny witness is refused (verb mismatch, risk over threshold budget, expired, over-deep delegation)', async () => {
    for (const over of [{ planVerb: '8' }, { verb: '8' }, { now: '9000000000001' }, { delegationDepth: '17' }, { allocChild: '1000001' }, { recentCount: '100' }, { allow: '0' }]) {
      expect(await witness(WASM.v1, { ...sample, ...over }, 15), JSON.stringify(over)).toBeNull();
      expect(await witness(WASM.v2, { ...sample, ...over }, 17), JSON.stringify(over)).toBeNull();
    }
  }, 900_000);
});

// Cost: one witness calculation of the 151k-constraint circuit is seconds to a minute on a CI runner; each case does two (base + perturbed),
// so 600 s per case is a conservative ceiling and a 7-input shard stays far inside its job timeout. The base witness is computed once per file.
const bases = new Map<string, Promise<string[]>>();
const baseOf = (wasm: string, nPublic: number) => {
  if (!bases.has(wasm)) bases.set(wasm, witness(wasm, sample, nPublic).then((r) => r!));
  return bases.get(wasm)!;
};
for (const { name, circuit, wasm, nPublic } of [
  { name: 'v1 (pca-policyvm-v1)', circuit: 'policyvm', wasm: WASM.v1, nPublic: 15 },
  { name: 'v2 (pca-policyvm-v2)', circuit: 'policyvm_bound', wasm: WASM.v2, nPublic: 17 },
] as const) {
  const mine = myShard(circuit, POLICY_PRIVATE);
  if (mine.length === 0) continue;
  D(`Policy-VM ${name}: witness perturbation`, () => {
    it.each(mine)('perturbing private input %s: the witness is refused or a public signal changes', async (k) => {
      const base = await baseOf(wasm, nPublic);
      const after = await witness(wasm, { ...sample, [k]: (BigInt(sample[k]!) + 1n).toString() }, nPublic);
      if (after === null) return;
      expect(after, `input ${k} is under-constrained: changing it leaves every public signal unchanged`).not.toEqual(base);
    }, 600_000);
  });
}

// compliance.circom: public signals [policyCommit, planCommit, actionCommit, shaPolicy, shaPlan, shaAction, allow]
const complianceMine = myShard('compliance', ['verb', 'resource', 'planVerb', 'policySalt', 'planSalt', 'actionSalt', 'risk', 'budget']);
(complianceMine.length ? D : describe.skip)('compliance circuit: witness perturbation', () => {
  const W: Input = { verb: '7', resource: '42', planVerb: '7', policySalt: '111', planSalt: '222', actionSalt: '333', risk: '3', budget: '10' };
  const commit = (b: number) => commitmentField(Buffer.alloc(32, b).toString('base64url'));
  const base: Input = { ...W, shaPolicy: commit(2), shaPlan: commit(3), shaAction: commit(1), allow: '1' };
  it('the control witness is accepted and the binding tags appear unchanged as public signals', async () => {
    const ps = (await witness(WASM.compliance, base, 7))!;
    expect(ps.slice(3)).toEqual([base.shaPolicy, base.shaPlan, base.shaAction, '1']);
  });
  // risk and budget are only constrained by risk <= budget, so +1 stays satisfiable: push them across the bound
  const PERT: Record<string, string> = { risk: '11', budget: '2' };
  it.each(complianceMine)('perturbing private input %s: the witness is refused or a public signal changes', async (k) => {
    const b = (await witness(WASM.compliance, base, 7))!;
    const after = await witness(WASM.compliance, { ...base, [k]: PERT[k] ?? String(BigInt(W[k]!) + 1n) }, 7);
    if (after === null) return;
    expect(after, `input ${k} is under-constrained`).not.toEqual(b);
  }, 120_000);
});
