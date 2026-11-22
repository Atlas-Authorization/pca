import {
  DEFAULT_RISK_POLICY,
  type Agent,
  type PlanNode,
  agent,
  buildPCActn,
  encodeKey,
  encodePCActn,
  generateKeyPair,
  hashCanonical,
  mintGrant,
  mintRoot,
  paramsDigest,
  readEnvelope,
} from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  type AccessEvaluationRequest,
  type AccessEvaluationResponse,
  type AuthzenPdpConfig,
  COAZ_TOOL_PATH,
  EVALUATIONS_PATH,
  EVALUATION_PATH,
  PCA_ACTION_KEY,
  PCA_APPROVAL_KEY,
  type PdpDecisionContext,
  approvalOf,
  authzenHandler,
  authzenPdp,
  defaultToAction,
  isAccessEvaluationRequest,
  isAuthzenAction,
  isAuthzenResource,
  isAuthzenSubject,
  isCoazToolAuthorizationRequest,
} from './index';

const AUD = 'rs_kill';
const stripe = (): Agent => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500' }, aud: AUD });
const gmail = (): Agent => agent({ principal: generateKeyPair(), goal: 'send october summaries', permissions: { gmail: ['send'] }, aud: AUD });
const ctxOf = (a: Agent, over: Partial<PdpDecisionContext> = {}): PdpDecisionContext => ({ grant: a.grant, chain: a.chain, policy: a.policy, budget: a.budget, ...over });
const pdpFor = (a: Agent, config: Partial<AuthzenPdpConfig> = {}, ctx: Partial<PdpDecisionContext> = {}) =>
  authzenPdp({ audience: AUD, insecureSkipPlanRootCheck: true, requireAuthorizer: false, resolve: () => ctxOf(a, ctx), ...config });
const DENY = (reason: string, status?: number) => ({
  decision: false,
  context: { ...(status ? { error: { status, message: reason } } : {}), reason_admin: { denied: true, reason }, reason_user: { message: reason } },
});
const subject = { type: 'agent', id: 'a1' };
const refundReq = (id = 'ch_1', context?: Record<string, unknown>): AccessEvaluationRequest => ({
  subject,
  action: { name: 'stripe.refund', properties: { amount: 42, currency: 'usd', reversibility_class: 'reversible' } },
  resource: { type: 'charge', id },
  ...(context !== undefined ? { context } : {}),
});
const LOW = { blastRadius: 42 / 500 };

describe('approvalOf: reading a pending reference', () => {
  const resp = (pending: unknown): AccessEvaluationResponse => ({ decision: false, context: { [PCA_APPROVAL_KEY]: pending } });
  const good = { approval_required: true, auth_req_id: 'id1' };
  it('absent context or reference is null', () => {
    expect(approvalOf({ decision: false })).toBeNull();
    expect(approvalOf({ decision: false, context: {} })).toBeNull();
  });
  it('approval_required must be exactly true and auth_req_id a string', () => {
    for (const bad of [{ ...good, approval_required: false }, { ...good, approval_required: 'true' }, { auth_req_id: 'id1' }, { ...good, auth_req_id: 5 }, { approval_required: true }, 'x', [], null]) {
      expect(approvalOf(resp(bad))).toBeNull();
    }
  });
  it('defaults follow the tier: 3 is a strong human threshold, anything else a standard guardian one', () => {
    expect(approvalOf(resp({ ...good, tier: 3 }))).toEqual({
      approval_required: true, auth_req_id: 'id1', tier: 3, required_threshold: { t: 3, proof: 'strong', optimisticAllowed: false }, goal_commit: '', risk: 1, reason: 'approval required', requested_at: 0,
    });
    expect(approvalOf(resp({ ...good, tier: 2 }))).toMatchObject({ tier: 2, required_threshold: { t: 2, proof: 'standard', optimisticAllowed: false } });
    expect(approvalOf(resp({ ...good, tier: 7 }))).toMatchObject({ tier: 2, required_threshold: { t: 2, proof: 'standard', optimisticAllowed: false } });
    expect(approvalOf(resp(good))).toMatchObject({ tier: 2 });
  });
  it('a well-formed threshold is kept, a malformed one replaced by the tier default', () => {
    for (const t of [1, 2, 3]) {
      const rt = { t, proof: 'claim', optimisticAllowed: true };
      expect(approvalOf(resp({ ...good, tier: 3, required_threshold: rt }))?.required_threshold).toEqual(rt);
    }
    const fallback = { t: 3, proof: 'strong', optimisticAllowed: false };
    const ok = { t: 2, proof: 'standard', optimisticAllowed: false };
    for (const bad of [null, 'x', [], 5, { ...ok, t: 4 }, { ...ok, t: 0 }, { ...ok, t: '2' }, { t: 2, optimisticAllowed: false }, { ...ok, proof: 5 }, { t: 2, proof: 'standard' }, { ...ok, optimisticAllowed: 'no' }]) {
      expect(approvalOf(resp({ ...good, tier: 3, required_threshold: bad }))?.required_threshold).toEqual(fallback);
    }
  });
  it('goal_commit, risk, reason and requested_at are read only when of the right type', () => {
    expect(approvalOf(resp({ ...good, goal_commit: 'g', risk: 0.5, reason: 'why', requested_at: 9 }))).toMatchObject({ goal_commit: 'g', risk: 0.5, reason: 'why', requested_at: 9 });
    expect(approvalOf(resp({ ...good, goal_commit: 5, risk: '0.5', reason: 7, requested_at: '9' }))).toMatchObject({ goal_commit: '', risk: 1, reason: 'approval required', requested_at: 0 });
    expect(approvalOf(resp({ ...good, risk: 0, requested_at: 0 }))).toMatchObject({ risk: 0, requested_at: 0 });
  });
});

describe('request guards', () => {
  it('subject, action and resource need string members', () => {
    expect(isAuthzenSubject({ type: 'a', id: 'b' })).toBe(true);
    for (const bad of [null, 'x', [], {}, { type: 'a' }, { id: 'b' }, { type: 5, id: 'b' }, { type: 'a', id: 5 }]) {
      expect(isAuthzenSubject(bad)).toBe(false);
      expect(isAuthzenResource(bad)).toBe(false);
    }
    expect(isAuthzenResource({ type: 'a', id: 'b' })).toBe(true);
    expect(isAuthzenAction({ name: 'x' })).toBe(true);
    for (const bad of [null, 'x', [], {}, { name: 5 }]) expect(isAuthzenAction(bad)).toBe(false);
  });
  it('an access evaluation request needs all three entities and a record context', () => {
    const ok = { subject, action: { name: 'x' }, resource: { type: 't', id: 'i' } };
    expect(isAccessEvaluationRequest(ok)).toBe(true);
    expect(isAccessEvaluationRequest({ ...ok, context: {} })).toBe(true);
    for (const bad of [null, {}, { ...ok, subject: {} }, { ...ok, action: {} }, { ...ok, resource: {} }, { ...ok, context: [] }, { ...ok, context: 'x' }]) expect(isAccessEvaluationRequest(bad)).toBe(false);
  });
  it('a COAZ request needs a subject and a tool with a string name', () => {
    expect(isCoazToolAuthorizationRequest({ subject, tool: { name: 't' } })).toBe(true);
    for (const bad of [null, 'x', {}, { subject }, { subject: {}, tool: { name: 't' } }, { subject, tool: 'x' }, { subject, tool: [] }, { subject, tool: {} }, { subject, tool: { name: 5 } }]) {
      expect(isCoazToolAuthorizationRequest(bad)).toBe(false);
    }
  });
});

describe('defaultToAction', () => {
  const base: AccessEvaluationRequest = { subject, action: { name: 'x.y' }, resource: { type: 'doc', id: '1' } };
  it('the bare mapping carries only verb, resource and params', () => {
    expect(defaultToAction(base)).toStrictEqual({ verb: 'x.y', resource: 'doc:1', params: {} });
  });
  it('an empty resource id leaves just the type', () => {
    expect(defaultToAction({ ...base, resource: { type: 'doc', id: '' } }).resource).toBe('doc');
  });
  it('params merge resource then action properties, ignoring non-records', () => {
    const r = defaultToAction({ ...base, resource: { type: 'doc', id: '1', properties: { a: 1, b: 1 } }, action: { name: 'x.y', properties: { b: 2 } } });
    expect(r.params).toEqual({ a: 1, b: 2 });
    const odd = defaultToAction({ ...base, resource: { type: 'doc', id: '1', properties: [1] as never }, action: { name: 'x.y', properties: 'x' as never } });
    expect(odd.params).toEqual({});
  });
  it('reversibility is read from the action first, then the context, only as a string', () => {
    const rc = (action: AccessEvaluationRequest['action'], context?: Record<string, unknown>) => defaultToAction({ ...base, action, ...(context ? { context } : {}) });
    expect(rc({ name: 'x', properties: { reversibility_class: 'irreversible' } }, { reversibility_class: 'reversible' }).reversibilityClass).toBe('irreversible');
    expect(rc({ name: 'x', properties: { reversibility_class: 5 } }, { reversibility_class: 'reversible' }).reversibilityClass).toBe('reversible');
    expect(rc({ name: 'x', properties: {} }, { reversibility_class: 'reversible' }).reversibilityClass).toBe('reversible');
    expect(rc({ name: 'x' }, { reversibility_class: 'reversible' }).reversibilityClass).toBe('reversible');
    expect(rc({ name: 'x' }, { reversibility_class: 3 })).not.toHaveProperty('reversibilityClass');
    expect(rc({ name: 'x' }, { other: 'x' })).not.toHaveProperty('reversibilityClass');
    expect(rc({ name: 'x' })).not.toHaveProperty('reversibilityClass');
  });
  it('subject properties become the subject witness only when they are a record', () => {
    expect(defaultToAction({ ...base, subject: { ...subject, properties: { role: 'admin' } } }).subject).toEqual({ role: 'admin' });
    expect(defaultToAction({ ...base, subject: { ...subject, properties: [1] as never } })).not.toHaveProperty('subject');
    expect(defaultToAction(base)).not.toHaveProperty('subject');
  });
  it('the env witness is the context minus the PCA-private keys, and absent when nothing is left', () => {
    expect(defaultToAction({ ...base, context: { [PCA_ACTION_KEY]: 'x', [PCA_APPROVAL_KEY]: {}, foo: 1, bar: 'b' } }).env).toEqual({ foo: 1, bar: 'b' });
    expect(defaultToAction({ ...base, context: { foo: 1 } }).env).toEqual({ foo: 1 });
    expect(defaultToAction({ ...base, context: { [PCA_ACTION_KEY]: 'x' } })).not.toHaveProperty('env');
    expect(defaultToAction({ ...base, context: { [PCA_APPROVAL_KEY]: {} } })).not.toHaveProperty('env');
    expect(defaultToAction({ ...base, context: {} })).not.toHaveProperty('env');
    expect(defaultToAction({ ...base, context: 'x' as never })).not.toHaveProperty('env');
    expect(defaultToAction(base)).not.toHaveProperty('env');
  });
});

describe('static admission and refusals: exact responses', () => {
  const a = stripe();
  const pdp = pdpFor(a, { requireProof: false });
  it('a statically admissible request is a bare permit with its reason', async () => {
    expect(await pdp.evaluate(refundReq())).toStrictEqual({ decision: true, context: { reason_admin: { reason: 'statically admissible under the declared authority' } } });
  });
  it('an inadmissible request is a bare deny with its reason and no id member', async () => {
    const r = await pdp.evaluate({ ...refundReq(), action: { name: 'stripe.void', properties: { reversibility_class: 'reversible' } } });
    expect(r).toStrictEqual(DENY('action is not admissible under the declared authority'));
    expect(Object.keys(r.context ?? {})).toEqual(['reason_admin', 'reason_user']);
  });
  it('a missing or null pca_action means no proof (static path); a non-string one is malformed', async () => {
    const permit = { decision: true, context: { reason_admin: { reason: 'statically admissible under the declared authority' } } };
    expect(await pdp.evaluate(refundReq('ch_1', { other: 1 }))).toStrictEqual(permit);
    expect(await pdp.evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: null }))).toStrictEqual(permit);
    expect(await pdp.evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: undefined }))).toStrictEqual(permit);
    for (const bad of [5, true, {}, []]) expect(await pdp.evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: bad }))).toStrictEqual(DENY('context carries a malformed PCActn'));
  });
  it('a throwing resolver that throws a non-Error is reported as unknown', async () => {
    const r = await authzenPdp({ resolve: () => { throw 'boom'; } }).evaluate(refundReq());
    expect(r).toStrictEqual(DENY('evaluation error (fail closed): unknown', 500));
  });
});

describe('proof path', () => {
  it('without a budget in the context a fresh one at the grant bMax is used', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const r = await pdpFor(a, {}, { budget: undefined, risk: LOW }).evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }));
    expect(r.decision).toBe(true);
  });
  it('a budget in the context is the one metered against', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const now = Date.now();
    const r = await pdpFor(a, {}, { budget: { B: 0, tau: now, asOf: now }, risk: LOW }).evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }));
    expect(r.decision).toBe(false);
  });
  it('the context chain is the one evaluated, not the proof chain', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const r = await pdpFor(a, {}, { chain: [], risk: LOW }).evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }));
    expect(r.decision).toBe(false);
    expect(r.context?.reason_admin).toMatchObject({ denied: true, stage: 'policy', reasons: expect.arrayContaining(['delegation chain is empty or malformed']) });
  });
  it('a context plan is passed to the risk model (semantic distance is then not assumed worst-case)', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const run = async (plan?: PlanNode[]) => {
      const r = await pdpFor(a, {}, { risk: {}, ...(plan !== undefined ? { plan } : {}) }).evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }));
      const reasons = (r.context?.reason_admin as { reasons: string[] }).reasons;
      return reasons.find((x) => x.startsWith('risk input(s) missing')) ?? '';
    };
    expect(await run()).toContain('semanticDistance');
    expect(await run([])).not.toContain('semanticDistance');
    expect(await run([])).toContain('risk input(s) missing, assumed worst case:');
  });
  it('an enforcement gate in the context is applied by the verifier, with its real reason', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const r = await pdpFor(a, {}, { risk: LOW, enforce: { freshness: { maxAgeMs: -1 } } }).evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }));
    expect(r).toEqual({
      decision: false,
      context: {
        reason_admin: { denied: true, stage: 'verify', checks: expect.objectContaining({ freshness: 'fail' }), reason: expect.stringContaining('freshness gate misconfigured') },
        reason_user: { message: 'the proof-carrying action did not verify' },
      },
    });
  });
  it('a grant without an envelope is denied without an evaluation error', async () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), caveats: [] });
    const node: PlanNode = { id: 'n', verb: 'v.x', resource: 'r:1', params_digest: paramsDigest({}), reversibility_class: 'reversible' };
    const NOW = Date.UTC(2026, 9, 25, 12);
    const p = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: {}, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
    const pdp = authzenPdp({
      audience: AUD,
      insecureSkipPlanRootCheck: true,
      requireAuthorizer: false,
      now: () => NOW,
      resolve: () => ({ grant, chain: [grant], policy: { predicates: [], caveats: [] } as never, risk: {} }),
    });
    const r = await pdp.evaluate({ subject, action: { name: 'v.x' }, resource: { type: 'r', id: '1' }, context: { [PCA_ACTION_KEY]: encodePCActn(p) } });
    expect(r.decision).toBe(false);
    expect(r.context).not.toHaveProperty('error');
  });
  it('subject and env witnesses reach the predicate conditions', async () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: encodeKey(principal.publicKey),
      holder: encodeKey(holder.publicKey),
      goal: 'docs',
      envelope: {
        predicates: [{ verb: 'doc.read', where: [{ field: 'subject.role', op: 'eq', value: 'admin' }, { field: 'env.region', op: 'eq', value: 'eu' }] }],
        caveats: [],
        agent_binding: {},
        risk_policy: DEFAULT_RISK_POLICY,
      },
    });
    const node: PlanNode = { id: 'n', verb: 'doc.read', resource: 'doc:1', params_digest: paramsDigest({}), reversibility_class: 'reversible' };
    const NOW = Date.UTC(2026, 9, 25, 12);
    const p = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: {}, counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
    const risk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
    const run = (sub?: Record<string, unknown>, env?: Record<string, unknown>) =>
      authzenPdp({
        audience: AUD,
        insecureSkipPlanRootCheck: true,
        requireAuthorizer: false,
        now: () => NOW,
        resolve: () => ({ grant, chain: [grant], policy: { predicates: [], caveats: [] } as never, risk, toAction: () => ({ verb: 'doc.read', resource: 'doc:1', params: {}, reversibilityClass: 'reversible', ...(sub ? { subject: sub } : {}), ...(env ? { env } : {}) }) }),
      }).evaluate({ subject, action: { name: 'doc.read' }, resource: { type: 'doc', id: '1' }, context: { [PCA_ACTION_KEY]: encodePCActn(p) } });
    expect((await run({ role: 'admin' }, { region: 'eu' })).decision).toBe(true);
    expect((await run({ role: 'user' }, { region: 'eu' })).decision).toBe(false);
    expect((await run({ role: 'admin' }, { region: 'us' })).decision).toBe(false);
    expect((await run(undefined, { region: 'eu' })).decision).toBe(false);
    expect((await run({ role: 'admin' }, undefined)).decision).toBe(false);
  });
  it('the authorizer receives the operation and proof, and the provenance only when present', async () => {
    const a = stripe();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd', reversibility_class: 'reversible' });
    const seen: Array<Record<string, unknown>> = [];
    const authorizer = (async (input: Record<string, unknown>) => (seen.push(input), { allow: true })) as never;
    const pdp = pdpFor(a, { authorizer, requireAuthorizer: true }, { risk: LOW });
    expect((await pdp.evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded }))).decision).toBe(true);
    expect(seen[0]).not.toHaveProperty('provenance');
    expect(seen[0]).toMatchObject({ operation: { verb: 'stripe.refund', resource: 'charge:ch_1' } });
    const prov = { receipts: ['x'] };
    await pdp.evaluate(refundReq('ch_1', { [PCA_ACTION_KEY]: encoded, pca_provenance: prov }));
    expect(seen[1]!.provenance).toEqual(prov);
  });
});

describe('approval required (step-up) responses', () => {
  const stepUp = async (risk: PdpDecisionContext['risk']) => {
    const a = gmail();
    const { encoded, pcactn } = a.act('gmail.send', 'thread:re_1', { subject: 'October summary' });
    const resp = await pdpFor(a, {}, { risk }).evaluate({ subject, action: { name: 'gmail.send', properties: { subject: 'October summary' } }, resource: { type: 'thread', id: 're_1' }, context: { [PCA_ACTION_KEY]: encoded } });
    return { a, resp, pcactn };
  };
  it('a mid-risk action needs a tier-2 guardian co-sign', async () => {
    const { a, resp, pcactn } = await stepUp({ semanticDistance: 0.5, reversibility: 0, blastRadius: 0.5, taint: 0, confidence: 1 });
    const pending = approvalOf(resp)!;
    expect(pending.tier).toBe(2);
    expect(pending.required_threshold.t).toBe(2);
    expect(pending.goal_commit).toBe(readEnvelope(a.grant)!.goal_commit);
    expect(pending.goal_commit.length).toBeGreaterThan(0);
    const reasons = (resp.context!.reason_admin as { reasons: string[] }).reasons;
    expect(reasons.length).toBeGreaterThan(0);
    expect(pending.reason).toBe(reasons[0]);
    expect(pending.auth_req_id).toBe(hashCanonical({ d: 'atlas-pca/authzen/aarp/v1', verb: 'gmail.send', resource: 'thread:re_1', params_digest: pcactn.action.params_digest, counter: pcactn.counter, at: pending.requested_at }));
    expect(resp.context!.id).toBe(pending.auth_req_id);
    expect(resp).toEqual({
      decision: false,
      context: {
        id: pending.auth_req_id,
        reason_admin: { stage: 'step_up', risk: pending.risk, threshold: pending.required_threshold, reasons },
        reason_user: { message: 'approval required before this action can proceed' },
        [PCA_APPROVAL_KEY]: pending,
      },
    });
  });
  it('a high-risk action needs a tier-3 human co-sign', async () => {
    const { resp } = await stepUp({ semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0 });
    expect(approvalOf(resp)).toMatchObject({ tier: 3, required_threshold: { t: 3 } });
  });
});

describe('Access Evaluations: defaults, semantics and ordering', () => {
  const permitItem = { resource: { type: 'charge', id: 'ch_1' } };
  const denyItem = { action: { name: 'stripe.void', properties: { reversibility_class: 'reversible' } } };
  const base = { subject, action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } }, resource: { type: 'charge', id: 'ch_0' } };
  const decisions = async (items: unknown[], semantic?: string) => {
    const a = stripe();
    const r = await pdpFor(a, { requireProof: false }).evaluations({ ...base, evaluations: items as never, ...(semantic ? { options: { evaluations_semantic: semantic as never } } : {}) });
    return r.evaluations.map((e) => e.decision);
  };
  it('execute_all answers every item; the short-circuit modes stop at the first matching decision', async () => {
    expect(await decisions([permitItem, denyItem, permitItem])).toEqual([true, false, true]);
    expect(await decisions([permitItem, denyItem, permitItem], 'execute_all')).toEqual([true, false, true]);
    expect(await decisions([permitItem, denyItem, permitItem], 'deny_on_first_deny')).toEqual([true, false]);
    expect(await decisions([permitItem, permitItem, permitItem], 'deny_on_first_deny')).toEqual([true, true, true]);
    expect(await decisions([denyItem, permitItem, denyItem], 'permit_on_first_permit')).toEqual([false, true]);
    expect(await decisions([denyItem, denyItem], 'permit_on_first_permit')).toEqual([false, false]);
  });
  it('an item missing a required entity is a 400 deny in every mode', async () => {
    const a = stripe();
    const pdp = pdpFor(a, { requireProof: false });
    const incomplete = DENY('incomplete evaluation (missing subject/action/resource)', 400);
    const noResource = { subject, action: { name: 'stripe.refund' } };
    for (const semantic of [undefined, 'execute_all', 'deny_on_first_deny', 'permit_on_first_permit'] as const) {
      const r = await pdp.evaluations({ ...noResource, evaluations: [{}], ...(semantic ? { options: { evaluations_semantic: semantic } } : {}) } as never);
      expect(r.evaluations).toEqual([incomplete]);
    }
  });
  it('execute_all runs the items concurrently, the short-circuit modes one after another', async () => {
    const a = stripe();
    const p1 = a.act('stripe.refund', 'charge:ch_1', { amount: 42, reversibility_class: 'reversible' }).encoded;
    const p2 = a.act('stripe.refund', 'charge:ch_2', { amount: 42, reversibility_class: 'reversible' }).encoded;
    const run = async (semantic: string) => {
      const log: string[] = [];
      const pdp = authzenPdp({
        audience: AUD,
        insecureSkipPlanRootCheck: true,
        requireAuthorizer: true,
        authorizer: (async () => (await Promise.resolve(), log.push('auth'), { allow: true })) as never,
        resolve: () => (log.push('resolve'), ctxOf(a, { risk: LOW })),
      });
      await pdp.evaluations({
        ...base,
        options: { evaluations_semantic: semantic as never },
        evaluations: [
          { resource: { type: 'charge', id: 'ch_1' }, context: { [PCA_ACTION_KEY]: p1 } },
          { resource: { type: 'charge', id: 'ch_2' }, context: { [PCA_ACTION_KEY]: p2 } },
        ],
      });
      return log;
    };
    expect(await run('execute_all')).toEqual(['resolve', 'resolve', 'auth', 'auth']);
    expect(await run('deny_on_first_deny')).toEqual(['resolve', 'auth', 'resolve', 'auth']);
  });
  it('the boxcar default context applies to items without their own, and an item context replaces it', async () => {
    const a = stripe();
    const seen: Array<AccessEvaluationRequest> = [];
    const pdp = authzenPdp({ requireProof: false, resolve: (r) => (seen.push(r), ctxOf(a)) });
    await pdp.evaluations({ ...base, context: { d: 1 }, evaluations: [{}, { context: { own: 2 } }] });
    expect(seen[0]!.context).toEqual({ d: 1 });
    expect(seen[1]!.context).toEqual({ own: 2 });
    seen.length = 0;
    await pdp.evaluations({ ...base, evaluations: [{}] });
    expect(seen[0]).not.toHaveProperty('context');
  });
});

describe('evaluateTool', () => {
  const a = stripe();
  const capture = (extra: Partial<AuthzenPdpConfig> = {}) => {
    const seen: AccessEvaluationRequest[] = [];
    const pdp = authzenPdp({ requireProof: false, resolve: (r) => (seen.push(r), ctxOf(a)), ...extra });
    return { seen, pdp };
  };
  it('maps the tool to a request on an mcp_tool resource', async () => {
    const { seen, pdp } = capture();
    const out = await pdp.evaluateTool({ subject, tool: { name: 'stripe.refund', arguments: { amount: 42, reversibility_class: 'reversible' } }, context: { c: 1 } });
    expect(seen[0]).toEqual({ subject, action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } }, resource: { type: 'mcp_tool', id: 'stripe.refund' }, context: { c: 1 } });
    expect(out).toStrictEqual({ decision: true, tool: 'stripe.refund', required_capability: 'stripe.refund', context: { reason_admin: { reason: 'statically admissible under the declared authority' } } });
  });
  it('arguments and context are optional and are not invented', async () => {
    const { seen, pdp } = capture();
    await pdp.evaluateTool({ subject, tool: { name: 'stripe.refund' } });
    expect(seen[0]!.action).toStrictEqual({ name: 'stripe.refund' });
    expect(seen[0]).not.toHaveProperty('context');
  });
  it('a tool-capability mapper that throws is a 500 deny naming the cause', async () => {
    const r1 = await capture({ toolCapability: () => { throw new Error('no mapping'); } }).pdp.evaluateTool({ subject, tool: { name: 't' } });
    expect(r1).toStrictEqual({ decision: false, tool: 't', required_capability: '', context: DENY('evaluation error (fail closed): no mapping', 500).context });
    const r2 = await capture({ toolCapability: () => { throw 'x'; } }).pdp.evaluateTool({ subject, tool: { name: 't' } });
    expect(r2.context).toStrictEqual(DENY('evaluation error (fail closed): unknown', 500).context);
  });
});

describe('authzenHandler routing and bodies', () => {
  const a = stripe();
  const pdp = pdpFor(a, { requireProof: false });
  const h = authzenHandler(pdp);
  const ok = refundReq();
  it('each path answers its own kind of request', async () => {
    const single = await h({ path: EVALUATION_PATH, body: ok });
    expect(single).toEqual({ status: 200, body: { decision: true, context: { reason_admin: { reason: 'statically admissible under the declared authority' } } } });
    const boxcar = await h({ path: EVALUATIONS_PATH, body: { ...ok, evaluations: [{}, {}] } });
    expect(boxcar.status).toBe(200);
    expect((boxcar.body as { evaluations: unknown[] }).evaluations).toHaveLength(2);
    const tool = await h({ path: COAZ_TOOL_PATH, body: { subject, tool: { name: 'stripe.refund', arguments: { amount: 1, reversibility_class: 'reversible' } } } });
    expect(tool).toMatchObject({ status: 200, body: { decision: true, tool: 'stripe.refund', required_capability: 'stripe.refund' } });
  });
  it('invalid bodies are 400 with the exact message for their endpoint', async () => {
    expect(await h({ path: EVALUATION_PATH, body: {} })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluation request' } });
    expect(await h({ path: EVALUATION_PATH, body: null })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluation request' } });
    expect(await h({ path: EVALUATIONS_PATH, body: { evaluations: 'x' } })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } });
    expect(await h({ path: EVALUATIONS_PATH, body: { evaluations: [] } })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } });
    expect(await h({ path: COAZ_TOOL_PATH, body: {} })).toEqual({ status: 400, body: { error: 'invalid COAZ MCP-tool authorization request' } });
  });
  it('an evaluations request with no or an empty list is one plain evaluation', async () => {
    for (const body of [ok, { ...ok, evaluations: [] }]) {
      expect(await h({ path: EVALUATIONS_PATH, body })).toMatchObject({ status: 200, body: { decision: true } });
    }
  });
  it('an unknown path is a 404 naming it, and a failing PDP is a generic 500', async () => {
    expect(await h({ path: '/nope', body: ok })).toEqual({ status: 404, body: { error: 'unknown AuthZEN path: /nope' } });
    const broken = authzenHandler({ evaluate: async () => { throw new Error('secret detail'); }, evaluations: async () => ({ evaluations: [] }), evaluateTool: async () => { throw new Error('x'); } });
    expect(await broken({ path: EVALUATION_PATH, body: ok })).toEqual({ status: 500, body: { error: 'internal error' } });
  });
});
