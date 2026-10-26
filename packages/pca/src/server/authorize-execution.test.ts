// 0.5 (T5): `authorizeExecution`, the full-policy engine of the gateway and the agent-framework execution guards.
import { describe, expect, it } from 'vitest';
import { delegate, mintRoot, type Capability, type Caveat } from '../capability';
import { mintGrant } from '../envelope';
import { agent } from '../facade';
import { hashCanonical } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { commitPlan, conditionsDigest, type PlanNode } from '../merkle';
import { PCACTN_VERSION, signPCActn, verifyPCActnCore, type PCActn } from '../pcactn';
import { DEFAULT_RISK_POLICY } from '../risk';
import { amountRisk, authorizeExecution, EXECUTION_REQUIRED_CHECKS, missingExecutionComponents, type AuthorizeExecutionOptions } from './authorize-execution';
import { atomicMemoryPcaStore, memoryPcaStore, type PcaStateStore } from './require-pca';

const AUD = 'rs-t5';
const VERB = 'stripe.refund';

/** A grant with a $100 per-refund limit (`amount <= 100` predicate), as `agent({ limits })` mints it. */
function refundWorld() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD });
  const revoked = { v: false };
  const opts: AuthorizeExecutionOptions = { audience: AUD, grant: a.grant, state: memoryPcaStore(), isRevoked: () => revoked.v };
  const sign = (amount: number) => {
    const params = { charge: 'ch_1', amount };
    return { params, pcactn: a.act(VERB, 'charge:ch_1', params).pcactn };
  };
  return { a, opts, revoked, sign };
}

describe('authorizeExecution: the reviewer acceptance test', () => {
  it('a validly signed $400 refund under a $100 grant: genuine to the core verifier, refused by the full policy', async () => {
    const { a, opts, sign } = refundWorld();
    const { params, pcactn } = sign(400);
    // the signature-only verifier the guards used to run accepts it
    expect((await verifyPCActnCore(pcactn, { grant: a.grant, audience: AUD })).allow).toBe(true);
    const d = await authorizeExecution(pcactn, { verb: VERB, resource: 'charge:ch_1', params }, opts);
    expect(d.allow === false && { kind: d.kind, status: d.status, reason: d.reason, policy: d.checks?.['policy'] }).toEqual({
      kind: 'policy',
      status: 403,
      reason: 'policy: amount <= 100 not satisfied for stripe.refund on charge:ch_1',
      policy: 'fail',
    });
  });

  it('a $50 refund is allowed once; the replayed proof is refused', async () => {
    const { opts, sign } = refundWorld();
    const { params, pcactn } = sign(50);
    const first = await authorizeExecution(pcactn, { verb: VERB, resource: 'charge:ch_1', params }, opts);
    expect(first.allow).toBe(true);
    const again = await authorizeExecution(pcactn, { verb: VERB, resource: 'charge:ch_1', params }, opts);
    expect(again.allow === false && { kind: again.kind, status: again.status, counter: again.checks?.['replay'] }).toEqual({ kind: 'replay', status: 403, counter: 'fail' });
    expect(again.allow === false && again.reason).toBe(`replay: ${pcactn.counter} is not greater than last seen ${pcactn.counter} (replay)`);
  });

  it('by default the server prices a refund from the verified amount (amountRisk): two $50 refunds fit a $100 budget', async () => {
    const { opts, sign } = refundWorld();
    const one = sign(50);
    const first = await authorizeExecution(one.pcactn, { verb: VERB, params: one.params }, opts);
    expect(first.allow && { r: first.verdict.r, B: first.verdict.budget?.B, reasons: first.verdict.reasons }).toEqual({
      r: 0.5,
      B: 50,
      reasons: ['policy: risk input(s) missing, assumed worst case: reversibility, taint, confidence'],
    });
    const two = sign(50);
    expect((await authorizeExecution(two.pcactn, { verb: VERB, params: two.params }, opts)).allow).toBe(true);
    // without server-side pricing the first refund is priced at the worst case and spends the whole budget
    const unpriced = refundWorld();
    const u = unpriced.sign(50);
    const d = await authorizeExecution(u.pcactn, { verb: VERB, params: u.params }, { ...unpriced.opts, risk: () => undefined });
    expect(d.allow && { r: d.verdict.r, B: d.verdict.budget?.B }).toEqual({ r: 1, B: 0 });
  });

  it('a revoked grant is refused', async () => {
    const { opts, revoked, sign } = refundWorld();
    revoked.v = true;
    const { params, pcactn } = sign(50);
    const d = await authorizeExecution(pcactn, { verb: VERB, params }, opts);
    expect(d.allow === false && { kind: d.kind, status: d.status, revocation: d.checks?.['revocation'] }).toEqual({ kind: 'revoked', status: 403, revocation: 'fail' });
  });

  it('isRevoked receives the grant and the PCActn', async () => {
    const { a, opts, sign } = refundWorld();
    const seen: [Capability, PCActn][] = [];
    const { params, pcactn } = sign(50);
    expect((await authorizeExecution(pcactn, { verb: VERB, params }, { ...opts, isRevoked: (g, p) => (seen.push([g, p]), false) })).allow).toBe(true);
    expect(seen).toEqual([[a.grant, pcactn]]);
  });
});

describe('authorizeExecution: binding to the operation', () => {
  it('params that differ from the signed ones are refused (params_digest), and the proof is not spent', async () => {
    const { opts, sign } = refundWorld();
    const { params, pcactn } = sign(50);
    const d = await authorizeExecution(pcactn, { verb: VERB, params: { ...params, amount: 5 } }, opts);
    expect(d.allow === false && { kind: d.kind, digest: d.checks?.['params_digest'], reason: d.reason }).toEqual({
      kind: 'policy',
      digest: 'fail',
      reason: 'params_digest: supplied params do not hash to action.params_digest',
    });
    expect((await authorizeExecution(pcactn, { verb: VERB, params }, opts)).allow).toBe(true);
  });

  it('another verb or another resource is refused before any state is touched', async () => {
    const { opts, sign } = refundWorld();
    const { params, pcactn } = sign(50);
    const reads: string[] = [];
    const state: PcaStateStore = { get: async (k) => (reads.push(k), undefined), put: async () => undefined };
    const verb = await authorizeExecution(pcactn, { verb: 'stripe.delete_customer', params }, { ...opts, state });
    expect(verb).toEqual({ allow: false, kind: 'binding', status: 403, reason: 'the proof is for stripe.refund on charge:ch_1, but this call is stripe.delete_customer' });
    const res = await authorizeExecution(pcactn, { verb: VERB, resource: 'charge:ch_2', params }, { ...opts, state });
    expect(res).toEqual({ allow: false, kind: 'binding', status: 403, reason: 'the proof is for stripe.refund on charge:ch_1, but this call is stripe.refund on charge:ch_2' });
    expect(reads).toEqual([]);
  });

  it('another audience is refused as authentication (401)', async () => {
    const { opts, sign } = refundWorld();
    const { params, pcactn } = sign(50);
    const d = await authorizeExecution(pcactn, { verb: VERB, params }, { ...opts, audience: 'rs-other' });
    expect(d.allow === false && { kind: d.kind, status: d.status, audience: d.checks?.['audience'] }).toEqual({ kind: 'authn', status: 401, audience: 'fail' });
  });
});

describe('authorizeExecution fails closed on a missing component', () => {
  const cases: [string, Partial<AuthorizeExecutionOptions>, string][] = [
    ['state', { state: undefined }, 'state'],
    ['isRevoked', { isRevoked: undefined }, 'isRevoked'],
    ['grant source', { grant: undefined, resolveGrant: undefined }, 'grant or resolveGrant'],
    ['audience', { audience: '' }, 'audience'],
  ];
  for (const [name, patch, label] of cases) {
    it(`no ${name}: denied with a named reason, the store and grant source are never consulted`, async () => {
      const { opts, sign } = refundWorld();
      const { params, pcactn } = sign(50);
      const touched: string[] = [];
      const state: PcaStateStore = { get: async () => (touched.push('state'), undefined), put: async () => void touched.push('state') };
      const o = { ...opts, state, resolveGrant: () => (touched.push('grant'), null), ...patch } as AuthorizeExecutionOptions;
      expect(await authorizeExecution(pcactn, { verb: VERB, params }, o)).toEqual({ allow: false, kind: 'config', status: 403, reason: `full policy mode is missing ${label} (fail closed)` });
      expect(touched).toEqual([]);
    });
  }

  it('missingExecutionComponents lists every gap, and none for a complete configuration', () => {
    expect(missingExecutionComponents(undefined)).toEqual(['audience', 'grant or resolveGrant', 'state', 'isRevoked']);
    expect(missingExecutionComponents({ audience: AUD, resolveGrant: () => null, state: { get: async () => undefined } as unknown as PcaStateStore, isRevoked: () => false })).toEqual(['state']);
    expect(missingExecutionComponents(refundWorld().opts)).toEqual([]);
  });

  it('a throwing revocation check denies (fail closed)', async () => {
    const { opts, sign } = refundWorld();
    const { params, pcactn } = sign(50);
    const d = await authorizeExecution(pcactn, { verb: VERB, params }, { ...opts, isRevoked: () => { throw new Error('revocation list unavailable'); } });
    expect(d.allow).toBe(false);
  });

  it('the required checks are the requirePCA profile plus params_digest and policy', () => {
    expect(EXECUTION_REQUIRED_CHECKS).toEqual(['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound', 'params_digest', 'policy']);
  });
});

describe('authorizeExecution evaluates ROOT caveats (a max_spend outside the envelope)', () => {
  const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
  const lowRisk = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0, age: 0 };

  function world(rootExtra: Caveat[]) {
    const principal = generateKeyPair();
    const pPub = encodeKey(principal.publicKey);
    const { grant: g0 } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: pPub,
      holder: pPub,
      goal: 'pay invoices',
      envelope: { predicates: [{ verb: 'pay', resource: 'invoice:*' }], caveats: [{ type: 'expires', at: NOW + 3_600_000 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    });
    const grant: Capability = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: pPub, caveats: [...g0.caveats, ...rootExtra] });
    const ag = generateKeyPair();
    const chain = [grant, delegate(grant, encodeKey(ag.publicKey), [], principal.secretKey)];
    let counter = 0;
    const mk = (params: Record<string, unknown>): PCActn => {
      const plan: PlanNode[] = [{ id: 'n1', verb: 'pay', resource: 'invoice:42', params_digest: hashCanonical(params), reversibility_class: 'reversible' }];
      const c = commitPlan(plan);
      return signPCActn(
        {
          ver: PCACTN_VERSION,
          action: { verb: 'pay', resource: 'invoice:42', params_digest: hashCanonical(params), reversibility_class: 'reversible' },
          grant_ref: grant.id,
          cap_chain: chain,
          plan: { root: c.root, inclusion_proof: c.proofFor('n1'), node_id: 'n1', conditions_digest: conditionsDigest(undefined, undefined) },
          attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
          provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
          freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
          counter: ++counter,
          risk_claim: { r: 0, inputs: {} },
          aud: AUD,
          iat: NOW,
          exp: NOW + 600_000,
        } as never,
        ag.secretKey,
      );
    };
    const opts: AuthorizeExecutionOptions = { audience: AUD, grant, state: memoryPcaStore(), isRevoked: () => false, now: () => NOW, risk: () => lowRisk };
    return { mk, opts };
  }

  it('$400 under a root max_spend of $100 is refused; $50 is allowed', async () => {
    const { mk, opts } = world([{ type: 'max_spend', usd: 100 }]);
    const over = { amount: 400, currency: 'usd' };
    const d = await authorizeExecution(mk(over), { verb: 'pay', resource: 'invoice:42', params: over }, opts);
    expect(d.allow === false && { kind: d.kind, policy: d.checks?.['policy'] }).toEqual({ kind: 'policy', policy: 'fail' });
    const ok = { amount: 50, currency: 'usd' };
    expect((await authorizeExecution(mk(ok), { verb: 'pay', resource: 'invoice:42', params: ok }, opts)).allow).toBe(true);
  });

  it('without the root caveat the same $400 is allowed (the denial above is the caveat)', async () => {
    const { mk, opts } = world([]);
    const over = { amount: 400, currency: 'usd' };
    expect((await authorizeExecution(mk(over), { verb: 'pay', resource: 'invoice:42', params: over }, opts)).allow).toBe(true);
  });
});

describe('amountRisk', () => {
  it('prices amount / kappa, clamped to [0, 1]; no amount or no kappa is undefined', () => {
    const { a } = refundWorld();
    const kappa = 100;
    expect(amountRisk(a.grant, { amount: 25 })).toEqual({ blastRadius: 25 / kappa });
    expect(amountRisk(a.grant, { amount: 250 })).toEqual({ blastRadius: 1 });
    expect(amountRisk(a.grant, { amount: -5 })).toEqual({ blastRadius: 0 });
    expect(amountRisk(a.grant, { total: 25 }, { amountField: 'total' })).toEqual({ blastRadius: 25 / kappa });
    expect(amountRisk(a.grant, { amount: '25' })).toBeUndefined();
    expect(amountRisk(a.grant, { amount: Number.NaN })).toBeUndefined();
    expect(amountRisk(a.grant, {})).toBeUndefined();
  });
});

describe('authorizeExecution runs on the atomic claim path of the one pipeline', () => {
  it('an atomic store is used through claim: $50 allowed once, the replay and a concurrent duplicate refused', async () => {
    const { opts, sign } = refundWorld();
    const base = atomicMemoryPcaStore();
    const claims: number[] = [];
    const state = { ...base, claim: async (k: string, c: Parameters<typeof base.claim>[1]) => (claims.push(c.counter), base.claim(k, c)) };
    const { params, pcactn } = sign(50);
    const op = { verb: VERB, resource: 'charge:ch_1', params };
    const [x, y] = await Promise.all([authorizeExecution(pcactn, op, { ...opts, state }), authorizeExecution(pcactn, op, { ...opts, state })]);
    expect([x.allow, y.allow].sort()).toEqual([false, true]);
    const lost = x.allow ? y : x;
    expect(lost.allow === false && { kind: lost.kind, counter: lost.checks?.['replay'] }).toEqual({ kind: 'replay', counter: 'fail' });
    const again = await authorizeExecution(pcactn, op, { ...opts, state });
    expect(again.allow === false && { kind: again.kind, reason: again.reason }).toEqual({
      kind: 'replay',
      reason: `replay: ${pcactn.counter} is not greater than last seen ${pcactn.counter} (replay)`,
    });
    // admission went through claim (no get -> put under a lock): the two concurrent calls each claimed once; the third
    // was refused by the stored counter before reaching the claim
    expect(claims).toEqual([pcactn.counter, pcactn.counter]);
  });
});
