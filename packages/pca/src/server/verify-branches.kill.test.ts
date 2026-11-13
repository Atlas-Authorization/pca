/**
 * Exact-outcome tests for server/verify.ts: the legacy `counter` requirement, the assurance report of an early refusal, when
 * the v2 pipeline runs for the grant's model rules, options and PCActn members read once (getters), the `operation` check,
 * revocation epoch vs the core freshness gate, required risk inputs, K1 input to the Policy VM, delegated-caveat reasons,
 * the unsupported-feature refusal, and the budget an escalation keeps.
 */
import { describe, expect, it } from 'vitest';
import { mintRoot, type Capability } from '../capability';
import { decisionOf } from '../decision';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, type PCActn } from '../pcactn';
import { RevocationSet, signRevocationEpoch } from '../revocation';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from '../risk';
import { AUD, NOW, setup } from './fixture.test-util';
import { enforceRequired, verifyPCActn, type VerifyPCActnOptions } from './verify';

const base = (s: ReturnType<typeof setup>) => ({ grant: s.grant, now: NOW, audience: AUD, require: [] as string[], insecureSkipPlanRootCheck: true });
const okCtx = (s: ReturnType<typeof setup>) => ({ plan: s.plan, risk: s.lowRisk, params: {}, budget: { B: 1, tau: NOW, asOf: NOW } });
const isVerifierError = (v: { reasons: string[] }) => v.reasons.some((r) => r.startsWith('verifier error'));

/** A grant whose envelope carries `extra` members, with optional extra ROOT caveats, and a PCActn for it. */
function grantWith(extra: Record<string, unknown>, rootCaveats: Record<string, unknown>[] = []) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const hPub = encodeKey(holder.publicKey);
  const env = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: hPub,
    goal: 'tidy sessions',
    envelope: { predicates: [{ verb: 'list_sessions', resource: 'session:*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant.caveats[0]!;
  const grant: Capability = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: hPub, caveats: [{ ...env, ...extra }, ...rootCaveats] as never });
  const plan: PlanNode[] = [{ id: 'n1', verb: 'list_sessions', resource: 'session:*', params_digest: paramsDigest({}), reversibility_class: 'reversible' }];
  const actn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n1', counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  return { grant, actn, plan };
}

function epochFor(grantId: string, issuedAt = NOW - 120_000) {
  const G = generateKeyPair();
  const set = new RevocationSet();
  const epoch = signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: grantId, epoch: 0, set_size: set.size, root: set.root, issued_at: issuedAt, not_after: issuedAt + 300_000 });
  return { epoch, guardianPublic: encodeKey(G.publicKey) };
}

describe('enforceRequired: the legacy "counter" name', () => {
  it('resolves to counter_format statelessly', () => {
    const v = enforceRequired({ allow: true, r: 0, requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: false }, checks: { counter_format: 'pass' }, reasons: [] }, ['counter']);
    expect(v.allow).toBe(true);
    expect(v.reasons).toEqual([]);
  });
});

describe('verifyPCActn: an early refusal still reports assurance when a requirement is set', () => {
  it('undecodable input with requireAssurance', async () => {
    const s = setup();
    const v = await verifyPCActn('%%%', { grant: s.grant, requireAssurance: { signature: 'pq' } });
    expect(v.checks).toEqual({ malformed: 'fail' });
    expect(v.assurance).toEqual({ malformed: { outcome: 'fail' } });
  });
});

describe('verifyPCActn: the v2 pipeline runs exactly when the grant carries a model rule', () => {
  const schemaReason = 'schema: malformed v2 context: env must be an object';
  const run = (g: ReturnType<typeof grantWith>, o: Partial<VerifyPCActnOptions> = {}) =>
    verifyPCActn(g.actn, { grant: g.grant, now: NOW, audience: AUD, require: [], insecureSkipPlanRootCheck: true, context: { env: [] as never }, ...o });
  it('a grant without units / tighten / model_polarity / actions / model-derived where: no v2 context', async () => {
    const v = await run(grantWith({}));
    expect(v.checks.schema).toBeUndefined();
    expect(v.reasons.filter((r) => r.startsWith('schema:'))).toEqual([]);
  });
  for (const [name, extra] of [
    ['units', { units: { 'action.params.amount': { kind: 'money' } } }],
    ['model_polarity', { model_polarity: 'legacy' }],
    ['actions', { actions: {} }],
  ] as const) {
    it(`a grant carrying only ${name}: the host env reaches the v2 context`, async () => {
      const v = await run(grantWith(extra));
      expect(v.checks.schema).toBe('fail');
      expect(v.reasons).toContain(schemaReason);
    });
  }
  it('without intent_session or model rules the core keeps only its first v2 reason', async () => {
    const v = await run(grantWith({}), { context: {}, intentV2: { env: [] as never } });
    expect(v.checks.schema).toBe('fail');
    expect(v.checks.intent_session).toBe('fail');
    expect(v.reasons).toContain(schemaReason);
    expect(v.reasons.filter((r) => r.startsWith('intent_session:'))).toEqual([]);
  });
});

describe('verifyPCActn: options read once', () => {
  it('freshAt and enforce are taken as they were when tested', async () => {
    const s = setup();
    let n = 0;
    const fa = await verifyPCActn(s.mk(s.plan[0]!), {
      ...base(s),
      context: okCtx(s),
      get freshAt() {
        return n++ === 0 ? { signer: 'x', scope: 's', local: {} as never, require: true } : undefined;
      },
    });
    expect(fa.checks.fresh_at).toBeUndefined();
    let m = 0;
    const en = await verifyPCActn(s.mk(s.plan[0]!), {
      ...base(s),
      context: okCtx(s),
      get enforce() {
        return m++ === 0 ? { freshness: { maxAgeMs: 1000 } } : undefined;
      },
    });
    expect(en.checks.freshness).toBe('not-enforced');
  });
  it('the revocation epoch maxAgeMs is taken as it was when tested', async () => {
    const s = setup();
    const e = epochFor(s.grant.id);
    let n = 0;
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      ...base(s),
      context: {
        ...okCtx(s),
        revocationEpoch: {
          ...e,
          get maxAgeMs() {
            return n++ === 0 ? 1 : undefined;
          },
        },
      },
    });
    expect(v.checks.freshness).toBe('pass');
  });
});

describe('verifyPCActn: the operation check', () => {
  const op = { verb: 'list_sessions', resource: 'session:*' };
  /** A PCActn whose `action` reads as the signed one, except the reads listed `false` after `arm()`. */
  function flaky(pc: PCActn, schedule: boolean[]) {
    const real = pc.action;
    let armed = false;
    let i = 0;
    const p = { ...pc } as PCActn;
    Object.defineProperty(p, 'action', {
      enumerable: true,
      configurable: true,
      get: () => (!armed || (schedule[i++] ?? true) ? real : undefined),
    });
    return { p, arm: () => (armed = true) };
  }
  const runFlaky = (schedule: boolean[], o: { verb: string; resource: string; params?: Record<string, unknown> }) => {
    const s = setup();
    const f = flaky(s.mk(s.plan[0]!), schedule);
    // pqPins is first read right before the operation check: the action then reads per the schedule
    return verifyPCActn(f.p, {
      ...base(s),
      operation: o,
      get pqPins() {
        f.arm();
        return undefined;
      },
    });
  };
  it('an action that reads as absent is compared, never dereferenced', async () => {
    expect((await runFlaky([false], op)).checks.operation).toBe('pass');
    expect((await runFlaky([true, false], op)).checks.operation).toBe('pass');
    const mismatch = 'operation: the proof is for list_sessions on session:*, but this operation is list_sessions on session:*';
    const a = await runFlaky([true, true, false], op);
    expect(a.checks.operation).toBe('fail');
    expect(a.reasons).toContain(mismatch);
    const b = await runFlaky([true, true, true, false], op);
    expect(b.checks.operation).toBe('fail');
    expect(b.reasons).toContain(mismatch);
    const c = await runFlaky([true, true, true, true, false], { ...op, params: {} });
    expect(c.checks.operation).toBe('fail');
    expect(c.reasons).toContain("operation: the proof's params_digest does not match the params of this list_sessions operation");
    for (const v of [a, b, c]) expect(isVerifierError(v)).toBe(false);
  });
  it('a server operation without a string verb or resource fails closed', async () => {
    const s = setup();
    const why = 'operation: the server operation has no verb / resource (fail closed)';
    for (const o of [{ verb: 5, resource: 'session:*' }, { verb: 'list_sessions', resource: 5 }]) {
      const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), operation: o as never });
      expect(v.checks.operation).toBe('fail');
      expect(v.reasons).toContain(why);
    }
  });
  it('context.params must equal the operation params; without operation params they are not compared', async () => {
    const s = setup();
    const differ = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), operation: { ...op, params: {} }, context: { params: { x: 1 } } });
    expect(differ.checks.operation).toBe('fail');
    expect(differ.reasons).toContain('operation: context.params differ from the operation params');
    const noOpParams = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), operation: op, context: { params: {} } });
    expect(noOpParams.checks.operation).toBe('pass');
  });
});

describe('verifyPCActn: plan root opt-out, freshness, risk inputs', () => {
  it('the opt-out reports plan_root_authorized as not-enforced under its own name', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), base(s));
    expect(v.checks.plan_root_authorized).toBe('not-enforced');
    expect('' in v.checks).toBe(false);
  });
  it('a valid revocation epoch never overwrites a failed core freshness gate', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), enforce: { freshness: { maxAgeMs: 1000 } }, context: { ...okCtx(s), revocationEpoch: epochFor(s.grant.id) } });
    expect(v.checks.freshness).toBe('fail');
    const ok = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), context: { ...okCtx(s), revocationEpoch: epochFor(s.grant.id) } });
    expect(ok.checks.freshness).toBe('pass');
  });
  it('semanticDistance counts as supplied only with a plan; missing inputs are listed comma-separated', async () => {
    const s = setup();
    const noPlan = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), requireRiskInputs: ['semanticDistance'], context: { params: {} } });
    expect(noPlan.checks.risk_inputs).toBe('fail');
    expect(noPlan.reasons).toContain('risk_inputs: required risk input(s) not supplied by the server: semanticDistance');
    const withPlan = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), requireRiskInputs: ['semanticDistance'], context: { plan: s.plan, params: {} } });
    expect(withPlan.checks.risk_inputs).toBe('pass');
    const two = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), requireRiskInputs: ['blastRadius', 'taint'], context: { params: {} } });
    expect(two.reasons).toContain('risk_inputs: required risk input(s) not supplied by the server: blastRadius, taint');
  });
});

describe('verifyPCActn: K1 input handed to the Policy VM', () => {
  const lowRisk = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };
  const run = (g: ReturnType<typeof grantWith>, k1?: VerifyPCActnOptions['k1']) =>
    verifyPCActn(g.actn, { grant: g.grant, now: NOW, audience: AUD, require: [], insecureSkipPlanRootCheck: true, context: { plan: g.plan, risk: lowRisk, params: {} }, ...(k1 !== undefined ? { k1 } : {}) });
  it('a root max_uses caveat: refused without k1, evaluated with it', async () => {
    const g = grantWith({}, [{ type: 'max_uses', id: 'u', n: 2, until: NOW + 600_000 }]);
    const why = 'policy: caveat language: max_uses: the caveat language is not configured (no k1 input)';
    expect((await run(g)).reasons).toContain(why);
    expect((await run(g, {})).reasons).not.toContain(why);
  });
  it('a root spiffe_bound caveat sees the configured SPIFFE ID', async () => {
    const g = grantWith({}, [{ type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x' }]);
    const why = 'policy: caveat language: spiffe_bound: the presenting workload does not carry the required SPIFFE ID';
    expect((await run(g, { spiffe_id: 'spiffe://a.test/x' })).reasons).not.toContain(why);
    expect((await run(g, { spiffe_id: 'spiffe://a.test/y' })).reasons).toContain(why);
  });
});

describe('verifyPCActn: delegated caveats', () => {
  it('without a K1 caveat the caveat language does not run (a fractional clock is not its business)', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...base(s), now: NOW + 0.5, context: okCtx(s) });
    expect(v.checks.delegated_caveats).toBe('pass');
  });
  it('the failure reason: the list alone, or the list and the K1 reasons joined by "; "', async () => {
    const one = setup({ taskCaveats: [{ type: 'made_up_a' }] });
    const a = await verifyPCActn(one.mk(one.plan[0]!), { ...base(one), context: okCtx(one) });
    expect(a.reasons).toContain('delegated_caveats: delegation caveat(s) not satisfied: made_up_a');
    const k1 = setup({ taskCaveats: [{ type: 'sealed' }, { type: 'max_uses', id: 'u', n: 1, until: NOW + 1000 }] });
    const b = await verifyPCActn(k1.mk(k1.plan[0]!), { ...base(k1), context: okCtx(k1) });
    const nc = 'the caveat language is not configured (no k1 input)';
    expect(b.reasons).toContain(`delegated_caveats: delegation caveat(s) not satisfied: sealed, max_uses (${nc}; ${nc})`);
  });
});

describe('verifyPCActn: a PCActn carrying an unsupported feature', () => {
  it('the refusal still applies the required checks and reports assurance only when asked', async () => {
    const s = setup();
    const pc = s.mk(s.plan[0]!, { extra: { bond_ref: 'b1' } });
    const v = await verifyPCActn(pc, { ...base(s), require: ['bond'], context: okCtx(s) });
    expect(v.allow).toBe(false);
    expect(v.reasons).toContain('bond: required check is unsupported (default-deny: not enforced by this resource server)');
    expect(v.assurance).toBeUndefined();
    const w = await verifyPCActn(pc, { ...base(s), assurance: true, context: okCtx(s) });
    expect(w.allow).toBe(false);
    expect(w.assurance?.leaf_signature?.suites).toEqual(['ed25519']);
  });
});

describe('verifyPCActn: an escalation keeps the post-decision budget, nothing else does', () => {
  const VERB = 'payments.send';
  const SPEND: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
  function esc() {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const pPub = encodeKey(principal.publicKey);
    const grant = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: pPub,
      holder: encodeKey(holder.publicKey),
      goal: 'pay invoices',
      envelope: {
        predicates: [{ verb: [VERB], resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }],
        caveats: [],
        agent_binding: {},
        risk_policy: SPEND,
        tighten: [{ id: 'big_payment', when: { field: 'action.params.amount', op: 'gt', value: 50 }, signal: 'escalate' }],
      },
    }).grant;
    return async (amount: number, withBudget: boolean) => {
      const params = { payee: 'acme', amount };
      const node: PlanNode = { id: 'n1', verb: VERB, resource: 'payments', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
      const p = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
      return verifyPCActn(p, {
        grant,
        now: NOW,
        audience: AUD,
        require: [],
        context: { plan: [node], planAuthorized: true, params, risk: { blastRadius: 0, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }, ...(withBudget ? { budget: { B: 1_000_000, tau: NOW, asOf: NOW } } : {}) },
      });
    };
  }
  it('escalate with a budget carries it; escalate without one, and a deny with one, carry none', async () => {
    const run = esc();
    const e = await run(70, true);
    expect(e.allow).toBe(false);
    expect(decisionOf(e)).toBe('escalate');
    expect(e.budget).toEqual(expect.objectContaining({ B: expect.any(Number), tau: expect.any(Number), asOf: expect.any(Number) }));
    const bare = await run(70, false);
    expect(decisionOf(bare)).toBe('escalate');
    expect(bare.budget).toBeUndefined();
    const d = await run(400, true);
    expect(decisionOf(d)).toBe('deny');
    expect(d.budget).toBeUndefined();
  });
});

describe('verifyPCActn: an intent_session that appears after the v2 decision', () => {
  it('the predicate env falls back to the host env, never a crash', async () => {
    const s = setup();
    const pc = s.mk(s.plan[0]!);
    let armed = false;
    Object.defineProperty(pc, 'intent_session', { enumerable: false, configurable: true, get: () => (armed ? {} : undefined) });
    // requireRiskInputs is first read after the v2 decision and before the predicate env is built
    const v = await verifyPCActn(pc, {
      ...base(s),
      context: okCtx(s),
      get requireRiskInputs() {
        armed = true;
        return undefined;
      },
    });
    expect(v.checks.malformed).toBeUndefined();
    expect(isVerifierError(v)).toBe(false);
  });
});
