import { describe, expect, it } from 'vitest';
import {
  type Envelope,
  type PCActn,
  type PlanNode,
  DEFAULT_RISK_POLICY,
  b64u,
  budgetAllocCaveat,
  buildPCActn,
  decide,
  delegate,
  generateKeyPair,
  mintGrant,
  paramsDigest,
  readEnvelope,
  verifyPCActnCore,
} from '@atlasauth/pca';
import { explainChain, explainDecision, explainVerification } from './index';

const AUD = 'ins_test';
const NOW = 1_000_000;

interface Fixture {
  principal: ReturnType<typeof generateKeyPair>;
  holder: ReturnType<typeof generateKeyPair>;
  grant: ReturnType<typeof mintGrant>['grant'];
  envelope: Envelope;
  plan: PlanNode[];
}

/** Mint a real grant (envelope with a refund predicate + two caveats) and a one-node plan. */
function fixture(caveats: Envelope['caveats'] = [{ type: 'expires', at: NOW + 60_000 }, { type: 'max_blast_radius', max: 0.5 }]): Fixture {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const env: Omit<Envelope, 'goal_commit'> = {
    predicates: [{ verb: 'stripe.refund', resource: 'charge:*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }],
    caveats,
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  };
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: b64u(principal.publicKey),
    holder: b64u(holder.publicKey),
    goal: 'reconcile refunds for October',
    envelope: env,
  });
  const envelope = readEnvelope(grant);
  if (!envelope) throw new Error('fixture: envelope did not read back');
  const plan: PlanNode[] = [{ id: 'n0', verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible' }];
  return { principal, holder, grant, envelope, plan };
}

function buildActn(f: Fixture, params: Record<string, unknown>, r: number, chainHolderSecret?: Uint8Array, chain = [f.grant]): PCActn {
  const base = f.plan[0];
  if (!base) throw new Error('buildActn: fixture plan is empty');
  // The committed plan node must carry the SAME params_digest the action does, or plan-inclusion fails
  // (exactly what the facade's act() does).
  const plan: PlanNode[] = [{ ...base, params_digest: paramsDigest(params) }];
  return buildPCActn({
    grant: f.grant,
    chain,
    plan,
    nodeId: 'n0',
    params,
    counter: 1,
    signerSecret: chainHolderSecret ?? f.holder.secretKey,
    aud: AUD,
    now: NOW,
    riskClaim: { r, inputs: {} },
  });
}

describe('explainVerification', () => {
  it('ALLOW: names the passing checks with concrete detail', async () => {
    const f = fixture();
    const p = buildActn(f, { amount: 100 }, 0.1);
    const vr = await verifyPCActnCore(p, { grant: f.grant, nowEpoch: NOW, audience: AUD });
    expect(vr.allow).toBe(true);

    const ex = explainVerification(p, vr, { now: NOW });
    expect(ex.verdict).toBe('allow');
    expect(ex.passed).toEqual(expect.arrayContaining(['wire', 'version', 'audience', 'validity', 'cap_chain', 'plan_inclusion', 'leaf_signature', 'counter']));
    expect(ex.decisive).toBeUndefined();

    const text = ex.toText();
    expect(text).toContain('ALLOW');
    expect(text).toContain(`aud "${AUD}" matches`);
    expect(text).toMatch(/leaf signature|leaf holder/);
  });

  it('DENY (broken signature): pinpoints the leaf hop with a remedy', async () => {
    const f = fixture();
    // 2-hop chain: grant -> sub-agent. The leaf (acting) holder is the sub-agent.
    const sub = generateKeyPair();
    const child = delegate(f.grant, b64u(sub.publicKey), [], f.holder.secretKey);
    const chain = [f.grant, child];
    const p = buildActn(f, { amount: 100 }, 0.1, sub.secretKey, chain);
    // Tamper the leaf signature.
    const tampered: PCActn = { ...p, sig: b64u(new Uint8Array(64)) };

    const vr = await verifyPCActnCore(tampered, { grant: f.grant, nowEpoch: NOW, audience: AUD });
    expect(vr.allow).toBe(false);

    const ex = explainVerification(tampered, vr, { now: NOW });
    expect(ex.verdict).toBe('deny');
    expect(ex.decisive?.name).toBe('leaf_signature');
    expect(ex.decisive?.hop).toBe(1); // the sub-agent leaf
    expect(ex.decisive?.remedy).toMatch(/leaf holder/i);
    expect(ex.toText()).toContain('DECISIVE');
  });

  it('DENY (audience mismatch): pinpoints aud + gives a remedy', async () => {
    const f = fixture();
    const p = buildActn(f, { amount: 100 }, 0.1);
    const vr = await verifyPCActnCore(p, { grant: f.grant, nowEpoch: NOW, audience: 'ins_other' });
    expect(vr.allow).toBe(false);

    const ex = explainVerification(p, vr, { now: NOW });
    expect(ex.decisive?.name).toBe('audience');
    expect(ex.decisive?.detail).toMatch(/does not match/);
    expect(ex.decisive?.remedy).toMatch(/aud/);
  });

  it('DENY (expired): validity pinpoint distinguishes expiry using now', async () => {
    const f = fixture();
    const p = buildActn(f, { amount: 100 }, 0.1); // iat=NOW, exp=NOW+20min
    const later = NOW + 60 * 60_000; // an hour later -> expired
    const vr = await verifyPCActnCore(p, { grant: f.grant, nowEpoch: later, audience: AUD });
    expect(vr.allow).toBe(false);

    const ex = explainVerification(p, vr, { now: later });
    expect(ex.decisive?.name).toBe('validity');
    expect(ex.decisive?.detail).toMatch(/expired/);
  });
});

describe('explainDecision', () => {
  function actionCtx(amount: number) {
    return { action: { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount }, reversibility_class: 'reversible' } };
  }

  it('ALLOW: names the granting predicate, the satisfied caveats, and r/tier/budget', () => {
    const f = fixture();
    const p = buildActn(f, { amount: 100 }, 0.1);
    const action = actionCtx(100);
    const caveat = { now: NOW, blastRadius: 0.1, reversibilityClass: 'reversible', delegationDepth: 0 };
    const dec = decide({
      grant: f.grant,
      chain: [f.grant],
      action,
      plan: f.plan,
      risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 },
      budget: { B: 1, tau: NOW, asOf: NOW },
      now: NOW,
      caveatContext: { blastRadius: 0.1, delegationDepth: 0 },
    });
    expect(dec.admit).toBe(true);

    const ex = explainDecision(p, dec, { envelope: f.envelope, context: { action, caveat, chain: [f.grant] } });
    expect(ex.verdict).toBe('allow');
    expect(ex.disposition).toBe('auto-admit');

    // the granting capability + predicate
    expect(ex.grant.granted).toBe(true);
    expect(ex.grant.predicateIndex).toBe(0);
    expect(ex.grant.predicate?.verb).toBe('stripe.refund');
    expect(ex.grant.where).toContain('action.params.amount lte 500');

    // satisfied caveats
    expect(ex.caveats.map((c) => c.type)).toEqual(['expires', 'max_blast_radius']);
    expect(ex.caveats.every((c) => c.satisfied)).toBe(true);

    // r / tier / budget
    expect(ex.risk.tier).toBe(1);
    expect(ex.risk.r).toBeCloseTo(0.02, 5);
    expect(ex.admission.admit).toBe(true);
    expect(ex.admission.cost).toBeCloseTo(0.02, 5);

    const text = ex.toText();
    expect(text).toContain('predicate #0');
    expect(text).toContain('expires');
    expect(text).toContain('max_blast_radius');
    expect(text).toMatch(/claim band \(t=1\)/);
  });

  it('DENY (failed caveat): names the caveat, its offending value, and a remedy', () => {
    const f = fixture([{ type: 'max_blast_radius', max: 0.2 }]);
    const p = buildActn(f, { amount: 100 }, 0.8);
    const action = actionCtx(100);
    const caveat = { now: NOW, blastRadius: 0.8, reversibilityClass: 'reversible', delegationDepth: 0 };
    const dec = decide({
      grant: f.grant,
      chain: [f.grant],
      action,
      plan: f.plan,
      risk: { semanticDistance: 0.5, reversibility: 1, blastRadius: 0.8, taint: 0, confidence: 1, age: 0 },
      budget: { B: 1, tau: NOW, asOf: NOW },
      now: NOW,
      caveatContext: { blastRadius: 0.8, delegationDepth: 0 },
    });
    expect(dec.releaseGuardianShare).toBe(false);

    const ex = explainDecision(p, dec, { envelope: f.envelope, context: { action, caveat, chain: [f.grant] } });
    expect(ex.verdict).toBe('deny');
    expect(ex.disposition).toBe('denied');

    const failed = ex.caveats.find((c) => !c.satisfied);
    expect(failed?.type).toBe('max_blast_radius');
    expect(failed?.value).toEqual({ max: 0.2 });
    expect(failed?.remedy).toMatch(/blast radius/i);

    expect(ex.decisive?.reason).toMatch(/max_blast_radius/);
    expect(ex.decisive?.remedy).toMatch(/max_blast_radius|narrow/i);
    expect(ex.toText()).toContain('DECISIVE');
  });

  it('STEP-UP: a permitted action over the auto threshold needs a co-signature (names the tier)', () => {
    const f = fixture([]); // no caveats to fail
    const p = buildActn(f, { amount: 100 }, 0.9);
    const action = actionCtx(100);
    const caveat = { now: NOW, blastRadius: 0.9, reversibilityClass: 'reversible', delegationDepth: 0 };
    const dec = decide({
      grant: f.grant,
      chain: [f.grant],
      action,
      plan: f.plan,
      risk: { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 }, // worst -> high r
      budget: { B: 1, tau: NOW, asOf: NOW },
      now: NOW,
      caveatContext: { blastRadius: 0.9, delegationDepth: 0 },
    });
    expect(dec.releaseGuardianShare).toBe(true);
    expect(dec.needStepUp).toBe(true);

    const ex = explainDecision(p, dec, { envelope: f.envelope, context: { action, caveat, chain: [f.grant] } });
    expect(ex.verdict).toBe('deny');
    expect(ex.disposition).toBe('step-up');
    expect(ex.grant.granted).toBe(true);
    expect(ex.decisive?.reason).toMatch(/step-up|budget/i);
  });
});

describe('explainChain', () => {
  it('renders attenuation across >=2 hops: issuer->holder and what each hop narrowed', () => {
    const f = fixture();
    const sub = generateKeyPair();
    const child = delegate(f.grant, b64u(sub.publicKey), [budgetAllocCaveat(5), { type: 'rate', max: 3, per_secs: 60 }], f.holder.secretKey);
    const chain = [f.grant, child];

    const ex = explainChain(chain);
    expect(ex.depth).toBe(2);
    expect(ex.hops).toHaveLength(2);

    // hop 0 = root grant (carries the envelope)
    expect(ex.hops[0]?.isRoot).toBe(true);
    expect(ex.hops[0]?.issuer).toBe(b64u(f.principal.publicKey));
    expect(ex.hops[0]?.holder).toBe(b64u(f.holder.publicKey));
    expect(ex.hops[0]?.narrowed).toMatch(/envelope/);

    // hop 1 = delegation to the sub-agent, adding two caveats incl. a budget sub-allocation
    expect(ex.hops[1]?.isRoot).toBe(false);
    expect(ex.hops[1]?.issuer).toBe(b64u(f.holder.publicKey)); // issued by the parent's holder
    expect(ex.hops[1]?.holder).toBe(b64u(sub.publicKey));
    expect(ex.hops[1]?.addedCaveatTypes).toEqual(['budget_alloc', 'rate']);
    expect(ex.hops[1]?.budgetAlloc).toBe(5);
    expect(ex.hops[1]?.narrowed).toMatch(/narrows:/);

    // budget subtree surfaced
    expect(ex.budgetNodes.length).toBeGreaterThanOrEqual(1);

    const text = ex.toText();
    expect(text).toContain('2 hop(s)');
    expect(text).toContain('──▶');
    expect(text).toContain('budget_alloc(B_sub=5)');
    expect(text).toContain('budget subtree');
  });

  it('empty chain degrades gracefully', () => {
    const ex = explainChain([]);
    expect(ex.depth).toBe(0);
    expect(ex.hops).toHaveLength(0);
    expect(ex.toText()).toContain('empty chain');
  });
});
