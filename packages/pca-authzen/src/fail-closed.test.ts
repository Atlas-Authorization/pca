import { describe, expect, it } from 'vitest';
import { type Agent, agent, createAuthorizer, generateKeyPair, memoryPcaStore } from '@atlasauth/pca';
import {
  type AccessEvaluationRequest,
  COAZ_TOOL_PATH,
  EVALUATIONS_PATH,
  EVALUATION_PATH,
  type AuthzenPdpConfig,
  type PdpDecisionContext,
  PCA_ACTION_KEY,
  DEFAULT_MAX_EVALUATIONS,
  authzenHandler,
  authzenPdp,
} from './index';

const AUD = 'rs_test';

function stripeAgent(): Agent {
  return agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500' }, aud: AUD });
}
const authority = (a: Agent, risk: PdpDecisionContext['risk'] = { blastRadius: 0.1 }): PdpDecisionContext => ({
  grant: a.grant, chain: a.chain, policy: a.policy, budget: a.budget, risk,
});
const pdpFor = (a: Agent, extra: Partial<AuthzenPdpConfig> = {}) => authzenPdp({ audience: AUD, insecureSkipPlanRootCheck: true, resolve: () => authority(a), requireProof: false, requireAuthorizer: false, ...extra });

const req = (encoded?: string, amount = 42, id = 'ch_1'): AccessEvaluationRequest => ({
  subject: { type: 'agent', id: 'a1' },
  action: { name: 'stripe.refund', properties: { amount, currency: 'usd' } },
  resource: { type: 'charge', id },
  ...(encoded !== undefined ? { context: { [PCA_ACTION_KEY]: encoded } } : {}),
});

const DENY = (reason: string, _id?: undefined, status?: number) => ({
  decision: false,
  context: { ...(status ? { error: { status, message: reason } } : {}), reason_admin: { denied: true, reason }, reason_user: { message: reason } },
});

describe('Access Evaluation: whole-response rows', () => {
  it('permit with a verified, under-cap proof', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    expect(await pdpFor(a).evaluate(req(encoded))).toEqual({
      decision: true,
      context: { reason_admin: { stage: 'policy', risk: expect.any(Number), threshold: expect.anything() } },
    });
  });
  it('rows that deny', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const pdp = pdpFor(a);
    // no authority resolved
    expect(await authzenPdp({ resolve: () => null }).evaluate(req())).toEqual(DENY('no PCA authority resolved for this request'));
    expect(await authzenPdp({ resolve: () => undefined }).evaluate(req())).toEqual(DENY('no PCA authority resolved for this request'));
    // resolver throws
    expect(await authzenPdp({ resolve: () => { throw new Error('db down'); } }).evaluate(req())).toEqual(
      DENY('evaluation error (fail closed): db down', undefined, 500),
    );
    // malformed carried proof: wrong type and undecodable string
    for (const bad of [123, 'not-a-pcactn', {}]) {
      expect(await pdp.evaluate({ ...req(), context: { [PCA_ACTION_KEY]: bad } })).toEqual(DENY('context carries a malformed PCActn'));
    }
    // proof for a different verb / resource / params
    expect(await pdp.evaluate({ ...req(encoded), action: { name: 'stripe.void', properties: { amount: 42, currency: 'usd' } } })).toEqual(
      DENY('the PCActn authorizes stripe.refund on charge:ch_1, not the requested stripe.void on charge:ch_1'),
    );
    expect(await pdp.evaluate(req(encoded, 42, 'ch_other'))).toEqual(
      DENY('the PCActn authorizes stripe.refund on charge:ch_1, not the requested stripe.refund on charge:ch_other'),
    );
    expect(await pdp.evaluate(req(encoded, 43))).toEqual(DENY("the request attributes do not match the PCActn's signed params_digest"));
  });
  it('wrong audience (PDP audience differs, or omitted) fails closed at verify', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    for (const audience of ['someone_else', undefined]) {
      const r = await authzenPdp({ audience, insecureSkipPlanRootCheck: true, resolve: () => authority(a), requireAuthorizer: false }).evaluate(req(encoded));
      expect(r).toEqual({
        decision: false,
        context: {
          reason_admin: { denied: true, stage: 'verify', checks: expect.objectContaining({ audience: 'fail' }), reason: expect.any(String) },
          reason_user: { message: 'the proof-carrying action did not verify' },
        },
      });
    }
  });
  it('a proof signed under a different grant does not verify', async () => {
    const a = stripeAgent();
    const other = stripeAgent();
    const { encoded } = other.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const r = await pdpFor(a).evaluate(req(encoded));
    expect(r.decision).toBe(false);
    expect(r.context?.reason_admin).toMatchObject({ denied: true, stage: 'verify' });
  });
  it('over-cap is a policy deny with the exact stage', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_2', { amount: 5000, currency: 'usd' });
    const r = await pdpFor(a).evaluate(req(encoded, 5000, 'ch_2'));
    expect(r).toEqual({
      decision: false,
      context: {
        reason_admin: { denied: true, stage: 'policy', reasons: expect.any(Array), risk: expect.any(Number) },
        reason_user: { message: 'the policy does not permit this action' },
      },
    });
  });
});

describe('requireProof (default true since 0.5)', () => {
  it('a request without a proof is denied by default; requireProof: false opts into static admission', async () => {
    const a = stripeAgent();
    const body: AccessEvaluationRequest = { ...req(), action: { name: 'stripe.refund', properties: { amount: 42, reversibility_class: 'reversible' } } };
    const bare = (extra: Partial<AuthzenPdpConfig>) => authzenPdp({ audience: AUD, insecureSkipPlanRootCheck: true, resolve: () => authority(a), ...extra });
    expect(await bare({}).evaluate(body)).toEqual(DENY('a signed PCActn is required (requireProof)'));
    expect(await bare({ requireProof: true }).evaluate(body)).toEqual(DENY('a signed PCActn is required (requireProof)'));
    expect((await bare({ requireProof: false }).evaluate(body)).decision).toBe(true);
    // a request WITH a proof is unaffected
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    expect((await pdpFor(a, { requireProof: true }).evaluate(req(encoded))).decision).toBe(true);
  });
});

describe('Core authorizer hook: replay and revocation', () => {
  function authorizerFor(a: Agent, revoked = false) {
    return createAuthorizer({
      audience: AUD,
      resolveGrant: async (ref) => (ref === a.grant.id ? a.grant : null),
      budgetStore: memoryPcaStore(),
      hooks: { revocation: () => (revoked ? { enforced: true, ok: false, detail: 'revoked' } : { enforced: true, ok: true }) },
      plan: 'single-step',
      risk: () => ({ blastRadius: 0.1, semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }),
    });
  }
  it('a replayed PCActn is permitted once and then denied', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a, { authorizer: authorizerFor(a), requireAuthorizer: true });
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    expect((await pdp.evaluate(req(encoded))).decision).toBe(true);
    const second = await pdp.evaluate(req(encoded));
    expect(second).toEqual({
      decision: false,
      context: {
        reason_admin: { denied: true, stage: 'authorize', reason: expect.any(String) },
        reason_user: { message: 'the proof-carrying action was not authorized' },
      },
    });
  });
  it('a revoked grant is denied', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a, { authorizer: authorizerFor(a, true) });
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const r = await pdp.evaluate(req(encoded));
    expect(r.decision).toBe(false);
    expect(r.context?.reason_admin).toMatchObject({ stage: 'authorize' });
  });
  it('without the hook a proof is denied by default (0.5); requireAuthorizer: false opts into the stateless PDP, where a replay is permitted', async () => {
    const a = stripeAgent();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const plain = pdpFor(a);
    expect((await plain.evaluate(req(encoded))).decision).toBe(true);
    expect((await plain.evaluate(req(encoded))).decision).toBe(true);
    const strict = authzenPdp({ audience: AUD, insecureSkipPlanRootCheck: true, resolve: () => authority(a), requireProof: false });
    expect(await strict.evaluate(req(encoded))).toEqual(DENY('no replay/revocation authorizer is configured (requireAuthorizer)'));
    expect(await pdpFor(a, { requireAuthorizer: true }).evaluate(req(encoded))).toEqual(
      DENY('no replay/revocation authorizer is configured (requireAuthorizer)'),
    );
    // a request without a proof is not a PCActn request, so requireAuthorizer alone does not change it
    expect((await pdpFor(a, { requireAuthorizer: true }).evaluate(req())).decision).toBe(false);
  });
  it('a thrown authorizer fails closed', async () => {
    const a = stripeAgent();
    const pdp = pdpFor(a, { authorizer: async () => { throw new Error('store down'); } });
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    expect(await pdp.evaluate(req(encoded))).toEqual(DENY('evaluation error (fail closed): store down', undefined, 500));
  });
});

describe('Access Evaluations (boxcar) conformance rows', () => {
  const sub = { type: 'agent', id: 'a1' };
  const res = { type: 'charge', id: 'ch_x' };
  const act = (amount: number) => ({ action: { name: 'stripe.refund', properties: { amount, reversibility_class: 'reversible' } } });
  it('missing pieces: an item left without subject/action/resource is denied with a 400 error member, a complete one is not', async () => {
    const pdp = pdpFor(stripeAgent());
    const r = await pdp.evaluations({ subject: sub, evaluations: [act(42), { resource: res }] });
    expect(r.evaluations).toEqual([
      DENY('incomplete evaluation (missing subject/action/resource)', undefined, 400),
      DENY('incomplete evaluation (missing subject/action/resource)', undefined, 400),
    ]);
    const ok = await pdp.evaluations({ subject: sub, resource: res, evaluations: [act(42), { resource: undefined as never }] });
    expect(ok.evaluations[0]!.decision).toBe(true);
    expect(ok.evaluations[1]).toEqual(DENY('incomplete evaluation (missing subject/action/resource)', undefined, 400));
  });
  it('semantics: execute_all keeps order; deny_on_first_deny stops after the deny; permit_on_first_permit stops at the permit', async () => {
    const pdp = pdpFor(stripeAgent());
    const items = [act(5000), act(42), act(5000)];
    const run = async (evaluations_semantic?: 'execute_all' | 'deny_on_first_deny' | 'permit_on_first_permit') =>
      (await pdp.evaluations({ subject: sub, resource: res, ...(evaluations_semantic ? { options: { evaluations_semantic } } : {}), evaluations: items })).evaluations.map((e) => e.decision);
    expect(await run()).toEqual([false, true, false]);
    expect(await run('execute_all')).toEqual([false, true, false]);
    expect(await run('deny_on_first_deny')).toEqual([false]);
    expect(await run('permit_on_first_permit')).toEqual([false, true]);
  });
  it('an unsupported semantic denies every item', async () => {
    const pdp = pdpFor(stripeAgent());
    const r = await pdp.evaluations({ subject: sub, resource: res, options: { evaluations_semantic: 'permit_all' as never }, evaluations: [act(42), act(42)] });
    expect(r.evaluations).toEqual([DENY('unsupported evaluations_semantic', undefined, 400), DENY('unsupported evaluations_semantic', undefined, 400)]);
  });
  it('maxEvaluations refuses an oversize boxcar', async () => {
    const pdp = pdpFor(stripeAgent(), { maxEvaluations: 2 });
    const r = await pdp.evaluations({ subject: sub, resource: res, evaluations: [act(42), act(42), act(42)] });
    expect(r.evaluations).toEqual(Array(3).fill(DENY('too many evaluations (limit 2)', undefined, 400)));
    expect((await pdp.evaluations({ subject: sub, resource: res, evaluations: [act(42), act(42)] })).evaluations).toHaveLength(2);
  });
  it('the default bound is 100 items: 100 are evaluated, 101 are refused', async () => {
    expect(DEFAULT_MAX_EVALUATIONS).toBe(100);
    const pdp = pdpFor(stripeAgent());
    const n = (k: number) => pdp.evaluations({ subject: sub, resource: res, evaluations: Array.from({ length: k }, () => act(42)) });
    expect((await n(100)).evaluations).toHaveLength(100);
    expect((await n(100)).evaluations.every((e) => e.decision)).toBe(true);
    expect((await n(101)).evaluations).toEqual(Array(101).fill(DENY('too many evaluations (limit 100)', undefined, 400)));
  });
  it('maxEvaluations: Infinity removes the bound; a smaller value replaces it', async () => {
    const pdp = pdpFor(stripeAgent(), { maxEvaluations: Number.POSITIVE_INFINITY });
    expect((await pdp.evaluations({ subject: sub, resource: res, evaluations: Array.from({ length: 101 }, () => act(42)) })).evaluations).toHaveLength(101);
  });
  it('non-array evaluations: empty result (never a permit)', async () => {
    expect(await pdpFor(stripeAgent()).evaluations({ evaluations: 'x' as never })).toEqual({ evaluations: [] });
  });
});

describe('HTTP handler conformance rows', () => {
  // The AuthZEN 1.0 request example shape: subject/resource/action(+properties)/context.
  const spec = {
    subject: { type: 'user', id: 'alice@example.com' },
    resource: { type: 'account', id: '123' },
    action: { name: 'can_read', properties: { method: 'GET' } },
    context: { time: '1985-10-26T01:22-07:00' },
  };
  it('the AuthZEN example request is accepted and answered with only a boolean decision (denied: nothing resolves it)', async () => {
    const h = authzenHandler(authzenPdp({ resolve: () => null }));
    const r = await h({ path: EVALUATION_PATH, body: spec });
    expect(r.status).toBe(200);
    expect((r.body as { decision: boolean }).decision).toBe(false);
  });
  it('absent or empty evaluations is a single Access Evaluation (section 7)', async () => {
    const h = authzenHandler(authzenPdp({ resolve: () => null }));
    for (const body of [spec, { ...spec, evaluations: [] }]) {
      const r = await h({ path: EVALUATIONS_PATH, body });
      expect(r).toEqual({ status: 200, body: DENY('no PCA authority resolved for this request') });
    }
    expect(await h({ path: EVALUATIONS_PATH, body: { evaluations: [] } })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } });
    expect(await h({ path: EVALUATIONS_PATH, body: {} })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } });
    expect(await h({ path: EVALUATIONS_PATH, body: { evaluations: 'x' } })).toEqual({ status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } });
  });
  it('malformed bodies are 400; unknown paths (including the search APIs) are 404', async () => {
    const h = authzenHandler(authzenPdp({ resolve: () => null }));
    for (const body of [null, 'x', 5, [], { subject: spec.subject }, { ...spec, subject: { type: 'user' } }, { ...spec, context: 'x' }]) {
      expect((await h({ path: EVALUATION_PATH, body })).status).toBe(400);
    }
    expect((await h({ path: COAZ_TOOL_PATH, body: { subject: spec.subject, tool: {} } })).status).toBe(400);
    for (const path of ['/access/v1/search/subject', '/access/v1/search/resource', '/access/v1/search/action', '/nope']) {
      expect((await h({ path, body: spec })).status).toBe(404);
    }
  });
  it('a PDP that throws becomes a 500 (a PEP treats it as deny), not an unhandled rejection', async () => {
    const h = authzenHandler({
      evaluate: async () => { throw new Error('boom'); },
      evaluations: async () => { throw new Error('boom'); },
      evaluateTool: async () => { throw new Error('boom'); },
    });
    expect(await h({ path: EVALUATION_PATH, body: spec })).toEqual({ status: 500, body: { error: 'internal error' } });
  });
  it('COAZ: a throwing toolCapability denies', async () => {
    const pdp = authzenPdp({ resolve: () => null, toolCapability: () => { throw new Error('map failed'); } });
    const r = await pdp.evaluateTool({ subject: spec.subject, tool: { name: 't' } });
    expect(r).toEqual({ ...DENY('evaluation error (fail closed): map failed', undefined, 500), tool: 't', required_capability: '' });
  });
});
