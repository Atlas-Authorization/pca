import { describe, expect, it } from 'vitest';
import {
  type PlanNode,
  type TrustBudget,
  DEFAULT_RISK_POLICY,
  encodeKey,
  generateKeyPair,
  mintRoot,
  verifyPCActnCore,
} from '@atlasauth/pca';
import { type Candidate, ENFORCED_CHECKS, Harness, computeHarnessMeasurement } from './harness';

// --- fixtures ---------------------------------------------------------------------------------

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

const grant = mintRoot({
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  holder: pub(agentKp),
  caveats: [],
});

// The principal-authorised plan: the only actions the harness may ever emit.
const plan: PlanNode[] = [
  { id: 'n1', verb: 'read', resource: 'doc:1' },
  { id: 'n2', verb: 'summarize', resource: 'doc:1' },
];

const AUD = 'ins_harness_test';

const fullBudget = (): TrustBudget => {
  const now = Date.now();
  return { B: 1, tau: now, asOf: now };
};

const mkHarness = (over: Partial<ConstructorParameters<typeof Harness>[0]> = {}) =>
  new Harness({
    grant,
    agentSecret: agentKp.secretKey,
    plan,
    audience: AUD,
    budget: fullBudget(),
    ...over,
  });

/** Wrap a fixed candidate as the untrusted oracle. */
const oracle = (c: Candidate) => () => c;

describe('B1 harness — attest the mediator, not the weights', () => {
  it('blocks an injected OUT-OF-PLAN action ("wire the money") and never produces a PCActn', async () => {
    const h = mkHarness();
    // A prompt-injected oracle tries to act outside the committed plan.
    const res = await h.step(
      oracle({ verb: 'transfer', resource: 'bank:acct-999', nodeId: 'wire', params: { amount: 1_000_000 } }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('unreachable');
    expect(res.reason).toBe('out_of_plan');
    expect('pcactn' in res).toBe(false); // nothing was signed
    expect(h.counter).toBe(0); // no action emitted
    // Budget untouched — the refusal happened before any metering.
    expect(h.budget.B).toBe(1);
  });

  it('blocks a verb-swap smuggled under a REAL node id (same node, different action)', async () => {
    const h = mkHarness();
    const res = await h.step(oracle({ verb: 'transfer', resource: 'doc:1', nodeId: 'n1' }));
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('unreachable');
    expect(res.reason).toBe('out_of_plan');
    expect(h.counter).toBe(0);
  });

  it('emits a valid PCActn for an in-plan action that verifyPCActnCore accepts', async () => {
    const h = mkHarness();
    const res = await h.step(
      oracle({ verb: 'read', resource: 'doc:1', nodeId: 'n1', inputs: [{ ref: 'task-brief', provenance: 'trusted' }] }),
    );
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error(res.detail);
    // The signed action carries the committed plan root and an inclusion proof.
    expect(res.pcactn.plan.root).toBe(h.planRoot);
    expect(res.pcactn.plan.node_id).toBe('n1');
    const v = await verifyPCActnCore(res.pcactn, { grant, audience: AUD });
    expect(v.allow).toBe(true);
    expect(v.checks.plan_inclusion).toBe('pass');
    expect(v.checks.leaf_signature).toBe('pass');
    // A verifier at a different audience rejects it (freshness binding).
    expect((await verifyPCActnCore(res.pcactn, { grant, audience: 'ins_other' })).checks.audience).toBe('fail');
    expect(h.counter).toBe(1);
  });

  it('forces a step-up / refusal under budget exhaustion, even for a low-risk in-plan action', async () => {
    const now = Date.now();
    const h = mkHarness({ budget: { B: 0.001, tau: now, asOf: now } }); // near-depleted
    const res = await h.step(
      oracle({ verb: 'read', resource: 'doc:1', nodeId: 'n1', inputs: [{ ref: 'task-brief', provenance: 'trusted' }] }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('unreachable');
    expect(res.reason).toBe('over_budget');
    expect(res.requiredT).toBe(3); // must escalate to a human co-sign
    expect('pcactn' in res).toBe(false);
    expect(h.counter).toBe(0); // no action emitted
  });

  it('raises the risk inputs for UNTRUSTED input provenance vs the same action with TRUSTED inputs', async () => {
    const h = mkHarness(); // B=1 covers both steps
    const trusted = await h.step(
      oracle({ verb: 'read', resource: 'doc:1', nodeId: 'n1', inputs: [{ ref: 'task-brief', provenance: 'trusted' }] }),
    );
    const untrusted = await h.step(
      oracle({ verb: 'summarize', resource: 'doc:1', nodeId: 'n2', inputs: [{ ref: 'https://evil.example/page', provenance: 'untrusted' }] }),
    );
    expect(trusted.ok && untrusted.ok).toBe(true);
    if (!trusted.ok || !untrusted.ok) throw new Error('both steps should succeed');

    // Taint label is derived from provenance and folded into the risk inputs.
    expect(trusted.risk.taint).toBe(0);
    expect(untrusted.risk.taint).toBe(1);
    expect(trusted.risk.inputs.taint).toBe(0);
    expect(untrusted.risk.inputs.taint).toBe(1);
    // Untrusted lineage strictly raises r.
    expect(untrusted.risk.r).toBeGreaterThan(trusted.risk.r);
    // The raised risk and taint level are reflected in the SIGNED PCActn.
    expect(untrusted.pcactn.risk_claim.r).toBe(untrusted.risk.r);
    expect(untrusted.pcactn.provenance.taint_level).toBe(1);
    expect(trusted.pcactn.provenance.taint_level).toBe(0);
    // The untrusted ref is NOT recorded as a trusted ref.
    expect(untrusted.pcactn.provenance.trusted_refs).toEqual([]);
    expect(trusted.pcactn.provenance.trusted_refs).toEqual(['task-brief']);
  });

  it('harnessMeasurement() is stable and changes when the enforced-checks manifest changes', async () => {
    const h = mkHarness();
    const m1 = h.harnessMeasurement();
    const m2 = h.harnessMeasurement();
    expect(m1).toBe(m2); // stable across calls

    // A second harness with the SAME policy surface measures identically.
    const same = mkHarness();
    expect(same.harnessMeasurement()).toBe(m1);

    // Changing what the mediator enforces changes its measurement.
    const changed = mkHarness({ measurementManifest: [...ENFORCED_CHECKS, 'semantic_judge_cosign'] });
    expect(changed.harnessMeasurement()).not.toBe(m1);

    // Measurement is a 32-byte digest (b64u, 43 chars, unpadded).
    expect(m1).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // And it is exactly the pure-function digest over the manifest (what an attestation would cover).
    expect(h.harnessMeasurement()).toBe(computeHarnessMeasurement('0.1.0', ENFORCED_CHECKS, DEFAULT_RISK_POLICY));
  });
});
