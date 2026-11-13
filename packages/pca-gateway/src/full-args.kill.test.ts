/** pca-gateway: what the full-policy pipeline hands to the core and how it maps the core's decision, with the core's decision controlled. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { authorize, bindParams, createGateway, memoryPcaStore, requestBinding, type GatewayFullPolicy, type GatewayOptions, type GatewayRequest } from './index';

const st = vi.hoisted(() => ({ calls: [] as unknown[][], decision: undefined as unknown }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return { ...actual, authorizeExecution: async (...a: unknown[]) => (st.calls.push(a), st.decision) };
});

const RATE_LIMITED_REFUND = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_args_gw';
const VERB = 'stripe.refund';
const PATH = '/refunds/ch_1';
const refund = { charge: 'ch_1', amount: 50 };
const allowVerdict = { allow: true, checks: { policy: 'pass' }, reasons: [] };

function world(o: { policy?: Partial<GatewayFullPolicy>; gw?: Partial<GatewayOptions> } = {}) {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$1000/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const roots: string[] = [];
  const clock = { t: Date.now() };
  const policy: GatewayFullPolicy = { mode: 'full', params: 'body', state: memoryPcaStore(), isRevoked: () => false, provenanceLog: false, ...o.policy };
  const opts: GatewayOptions = {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB } }],
    resolveGrant: (r) => (r === a.grant.id ? a.grant : null),
    authorizedPlanRoots: roots,
    now: () => clock.t,
    policy,
    ...o.gw,
  };
  const { encoded, pcactn } = a.act(VERB, 'charge:ch_1', bindParams(refund, requestBinding({ method: 'POST', path: PATH, headers: {} }, { body: false })));
  roots.push(pcactn.plan.root);
  clock.t = pcactn.iat;
  const req: GatewayRequest = { method: 'POST', path: PATH, headers: { 'pca-action': pcaHeaders(encoded)[PCA_HEADER]! }, body: JSON.stringify(refund) };
  return { a, opts, policy, req, pcactn, clock };
}
const bound = { ...refund, binding: { v: 2, method: 'POST', path: PATH, query: '' } };

describe('arguments handed to authorizeExecution', () => {
  beforeEach(() => { st.calls.length = 0; st.decision = { allow: true, verdict: allowVerdict }; });

  it('the operation and options carry exactly what was configured', async () => {
    const w = world();
    const d = await authorize(w.req, w.opts);
    expect(d).toMatchObject({ allow: true, code: 'allow', reason: 'proof-carrying action authorized (full policy)', policyVerdict: allowVerdict });
    const [p, op, o] = st.calls[0] as [unknown, Record<string, unknown>, Record<string, unknown>];
    expect(p).toEqual(w.pcactn);
    expect(op).toStrictEqual({ verb: VERB, params: bound });
    for (const k of ['k1', 'hooks', 'usesStore']) expect(Object.keys(o)).not.toContain(k);
    expect(o.audience).toBe(AUD);
    expect(o.grant).toBe(w.a.grant);
    expect((o.now as () => number)()).toBe(w.pcactn.iat);
    expect(o.state).toBe(w.policy.state);
  });
  it('a route resource and an unrouted proof shape the operation', async () => {
    const w = world({ gw: { routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB, resource: 'charge:ch_1' } }] } });
    await authorize(w.req, w.opts);
    expect(st.calls[0]![1]).toStrictEqual({ verb: VERB, resource: 'charge:ch_1', params: bound });
    st.calls.length = 0;
    const u = world({ gw: { routes: [], unmatchedRoute: 'require-proof' } });
    await authorize(u.req, u.opts);
    expect(st.calls[0]![1]).toStrictEqual({ verb: VERB, params: bound });
  });
  it('hooks go through minus the revocation hook; k1 only when configured', async () => {
    const attestation = () => ({ enforced: false as const });
    const w = world({ gw: { hooks: { revocation: () => ({ enforced: true as const, ok: true }), attestation } as never } });
    await authorize(w.req, w.opts);
    expect((st.calls[0]![2] as { hooks: unknown }).hooks).toStrictEqual({ attestation });
    expect(Object.keys(st.calls[0]![2] as object)).not.toContain('k1');
    st.calls.length = 0;
    const k = world({ policy: { k1: { pins: [] } } });
    await authorize(k.req, k.opts);
    const o = st.calls[0]![2] as Record<string, unknown>;
    expect(o.k1).toStrictEqual({ pins: [] });
    expect(Object.keys(o)).not.toContain('hooks');
  });
  it('the caller\'s state and usesStore stay the caller\'s objects through createGateway', async () => {
    const inner = memoryPcaStore();
    const state = { data: [] as string[], get: (k: string) => inner.get(k), put: (k: string, s: Parameters<typeof inner.put>[1]) => inner.put(k, s) };
    const usesStore = { claim: async () => true };
    const w = world({ policy: { state: state as never, usesStore: usesStore as never } });
    await createGateway(w.opts)(w.req);
    const o = st.calls[0]![2] as Record<string, unknown>;
    expect(o.state).toBe(state);
    expect(o.usesStore).toBe(usesStore);
  });
});

describe('mapping the core decision', () => {
  beforeEach(() => { st.calls.length = 0; });
  it('maps each denial kind to a gateway code and keeps the status and policy verdict', async () => {
    const v = { allow: false, checks: { policy: 'fail' }, reasons: ['r'] };
    for (const [kind, status, code] of [
      ['replay', 403, 'replayed-proof'],
      ['binding', 403, 'insufficient-capability'],
      ['authn', 401, 'verify-failed'],
      ['policy', 403, 'proof-rejected'],
      ['revoked', 403, 'proof-rejected'],
      ['config', 403, 'proof-rejected'],
    ] as const) {
      st.decision = { allow: false, kind, status, reason: `why ${kind}`, verdict: v };
      const w = world();
      const d = await authorize(w.req, w.opts);
      expect({ allow: d.allow, status: d.status, code: d.code, reason: d.reason, policyVerdict: d.policyVerdict }).toEqual({ allow: false, status, code, reason: `why ${kind}`, policyVerdict: v });
      expect(d.pcactn).toBeDefined();
      expect(d.verdict).toBeDefined();
    }
    st.decision = { allow: false, kind: 'policy', status: 403, reason: 'no verdict' };
    const w = world();
    expect('policyVerdict' in (await authorize(w.req, w.opts))).toBe(false);
  });
});
