import { afterEach, describe, expect, it, vi } from 'vitest';
import { type PlanNode, type TrustBudget, encodeKey, generateKeyPair, hashCanonical, mintRoot, paramsDigest } from '@atlasauth/pca';
import { type Candidate, Harness } from './harness';

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: pub(principal), holder: pub(agentKp), caveats: [] });
const plan: PlanNode[] = [
  { id: 'n1', verb: 'read', resource: 'doc:1' },
  { id: 'n2', verb: 'summarize', resource: 'doc:1' },
];
const T0 = 1_700_000_000_000;
const budgetOf = (B: number): TrustBudget => ({ B, tau: T0, asOf: T0 });
const mk = (over: Partial<ConstructorParameters<typeof Harness>[0]> = {}) =>
  new Harness({ grant, agentSecret: agentKp.secretKey, plan, audience: 'ins_kill', budget: budgetOf(1), now: () => T0, ...over });
const cand: Candidate = { verb: 'read', resource: 'doc:1', nodeId: 'n1' };
// semanticDistance 1, reversibility 0, blastRadius 1 => r = 0.65 > theta2 (0.6) => t = 3
const HIGH = { semanticDistance: 1, reversibility: 0, blastRadius: 1 };

afterEach(() => vi.restoreAllMocks());

describe('Harness.step shape and wiring', () => {
  it('the default nonce is 32 zero-padded hex characters', async () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((a: Uint8Array) => {
      a.fill(1);
      return a;
    }) as never);
    const h = new Harness({ grant, agentSecret: agentKp.secretKey, plan, audience: 'ins_kill', budget: budgetOf(1), now: () => T0 });
    const r = await h.step(() => cand);
    if (!r.ok) throw new Error(r.detail);
    expect(r.pcactn.nonce).toBe('01'.repeat(16));
  });
  it('an oracle throwing null or undefined is a refusal with the unknown-error detail', async () => {
    for (const thrown of [null, undefined]) {
      expect(
        await mk().step(() => {
          throw thrown;
        }),
      ).toEqual({ ok: false, reason: 'bad_candidate', detail: 'oracle failed: unknown error' });
    }
  });
  it('an unknown node is refused with the exact outcome', async () => {
    const h = mk();
    expect(await h.step(() => ({ ...cand, nodeId: 'zz' }))).toEqual({ ok: false, reason: 'out_of_plan', detail: "node 'zz' is not in the committed plan" });
    expect(h.counter).toBe(0);
  });
  it('the returned inclusion proof is the one stamped into the action', async () => {
    const r = await mk().step(() => cand);
    if (!r.ok) throw new Error(r.detail);
    expect(r.inclusionProof).toBeDefined();
    expect(r.inclusionProof).toEqual(r.pcactn.plan.inclusion_proof);
  });
  it('base risk overrides are applied on top of the defaults', async () => {
    const r = await mk({ baseRisk: { semanticDistance: 0.5 } }).step(() => cand);
    if (!r.ok) throw new Error(r.detail);
    expect(r.risk.inputs).toEqual({ semanticDistance: 0.5, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 });
  });
  it('the signed lifetime is the configured ttl', async () => {
    const r = await mk({ ttlMs: 5000 }).step(() => cand);
    if (!r.ok) throw new Error(r.detail);
    expect(r.pcactn.exp - r.pcactn.iat).toBe(5000);
  });
  it('params that do not match the committed digest are a bad_candidate naming the build failure', async () => {
    const guarded: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1', params_digest: paramsDigest({ a: 1 }) }];
    const h = mk({ plan: guarded });
    const r = await h.step(() => ({ ...cand, params: { a: 2 } }));
    expect(r).toMatchObject({ ok: false, reason: 'bad_candidate' });
    if (r.ok) throw new Error('unreachable');
    expect(r.detail).toMatch(/^could not build PCActn: .*params/);
    expect(h.counter).toBe(0);
    expect(h.budget.B).toBe(1);
  });
});

describe('Harness.step input lineage', () => {
  const causal = async (inputs: unknown[]) => {
    const r = await mk().step(() => ({ ...cand, inputs: inputs as never }));
    if (!r.ok) throw new Error(r.detail);
    return r;
  };
  it('records trusted inputs with their ref and provenance', async () => {
    const r = await causal([{ ref: 'brief', provenance: 'trusted' }]);
    expect(r.pcactn.provenance.causal_hash).toBe(hashCanonical([{ ref: 'brief', provenance: 'trusted' }]));
    expect(r.pcactn.provenance.trusted_refs).toEqual(['brief']);
  });
  it('keeps the ref of an untrusted input and blanks a missing one', async () => {
    const r = await causal([{ ref: 'evil', provenance: 'untrusted' }, { provenance: 'untrusted' }, 'junk']);
    expect(r.pcactn.provenance.causal_hash).toBe(
      hashCanonical([
        { ref: 'evil', provenance: 'untrusted' },
        { ref: '', provenance: 'untrusted' },
        { ref: '', provenance: 'untrusted' },
      ]),
    );
  });
  it('a function carrying a trusted label is not a trusted input', async () => {
    const fake = Object.assign(() => 0, { ref: 'a', provenance: 'trusted' });
    const r = await causal([fake]);
    expect(r.risk.taint).toBe(1);
    expect(r.pcactn.provenance.trusted_refs).toEqual([]);
    expect(r.pcactn.provenance.causal_hash).toBe(hashCanonical([{ ref: 'a', provenance: 'untrusted' }]));
  });
});

describe('Harness.step budget metering', () => {
  it('a t=3 action is never metered: it signs with an empty budget and leaves the budget untouched', async () => {
    for (const B of [0, 1]) {
      const h = mk({ baseRisk: HIGH, budget: budgetOf(B) });
      const r = await h.step(() => cand);
      if (!r.ok) throw new Error(r.detail);
      expect(r.risk.t).toBe(3);
      expect(r.budget.B).toBe(B);
      expect(h.budget.B).toBe(B);
      expect(h.counter).toBe(1);
    }
  });
  it('a t=1 action debits exactly its cost', async () => {
    const r = await mk().step(() => cand);
    if (!r.ok) throw new Error(r.detail);
    expect(r.risk.t).toBe(1);
    expect(r.budget.B).toBeCloseTo(1 - r.risk.r, 12);
  });
  it('a budget exactly equal to the cost is enough; one hair less is not', async () => {
    const probe = await mk().step(() => cand);
    if (!probe.ok) throw new Error(probe.detail);
    const exact = await mk({ budget: budgetOf(probe.risk.r) }).step(() => cand);
    expect(exact.ok).toBe(true);
    const short = await mk({ budget: budgetOf(probe.risk.r - 1e-9) }).step(() => cand);
    expect(short).toMatchObject({ ok: false, reason: 'over_budget', requiredT: 3 });
  });
});
