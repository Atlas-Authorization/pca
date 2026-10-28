// 0.5 (T5): full-policy mode (`policy: { mode: 'full', ... }`). The reviewer acceptance test against the gateway core and
// its Envoy (HTTP, gRPC), Cloudflare Worker and Lambda shims: a validly signed $400 refund under a $100 grant, a replayed
// proof and a revoked grant are each refused, and the upstream never runs.
import { describe, expect, it } from 'vitest';
import { agent, createProvenanceRecorder, principalDirectProvenance, type PcaOperation, generateKeyPair, pcaHeaders, PCA_HEADER, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import {
  authorize,
  bindParams,
  cloudflareWorker,
  createGateway,
  envoyExtAuthz,
  envoyGrpcExtAuthz,
  lambdaAuthorizer,
  memoryPcaStore,
  requestBinding,
  type GatewayOptions,
  type GatewayFullPolicy,
  type GatewayPolicy,
  type GatewayRequest,
  type WorkerLikeRequest,
} from './index';

// Provenance by default: these tests are about the gateway's other checks, so every operation is presented as coming straight
// from the principal (a principal-direct bundle under a pinned harness key; the session log is off). The gateway's own provenance
// handling is tested in provenance.test.ts.
const provRec = () => createProvenanceRecorder({ mediator: 'test-harness', kid: 'k1', secretKey: new Uint8Array(32).fill(1) });
const PROV = {
  provenance: { mediators: [provRec().pin], bundle: (_r: unknown, _p: unknown, o: PcaOperation) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} }) },
  provenanceLog: false as const,
};

// 0.5: the built-in stripe.refund is irreversible (never auto-approved, even within a cap); these tests exercise the within-cap
// allow path, so they grant the pre-0.5 rate_limited refund instead.
const RATE_LIMITED_REFUND = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_t5_gw';
const VERB = 'stripe.refund';
const PATH = '/refunds/ch_1';

function world(o: { params?: GatewayFullPolicy['params'] } = {}) {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const revoked = { v: false };
  /** The plan roots the principal authorized: every proof `sign` mints registers its root (a gateway built by `createGateway` snapshots this, so mint first). */
  const roots: string[] = [];
  const policy: GatewayFullPolicy = { mode: 'full', params: o.params ?? 'body', state: memoryPcaStore(), isRevoked: () => revoked.v, ...PROV };
  const opts: GatewayOptions = {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB } }],
    resolveGrant: (ref) => (ref === a.grant.id ? a.grant : null),
    authorizedPlanRoots: roots,
    policy,
  };
  /** The agent side: sign the real params plus the request binding. */
  const sign = (params: Record<string, unknown>, query = '') => {
    const binding = requestBinding({ method: 'POST', path: PATH, query, headers: {} }, { body: false });
    const { encoded, pcactn } = a.act(VERB, 'charge:ch_1', bindParams(params, binding));
    roots.push(pcactn.plan.root);
    return { header: pcaHeaders(encoded)[PCA_HEADER]!, pcactn };
  };
  const req = (header: string, body: string, extra: Partial<GatewayRequest> = {}): GatewayRequest => ({ method: 'POST', path: PATH, headers: { 'pca-action': header }, body, ...extra });
  return { a, revoked, roots, policy, opts, sign, req };
}

const refund = (amount: number) => ({ charge: 'ch_1', amount });
const json = (v: unknown) => JSON.stringify(v);

describe('pca-gateway full-policy mode: reviewer acceptance (core)', () => {
  it('a validly signed $400 refund under a $100 grant is refused', async () => {
    const w = world();
    const { header } = w.sign(refund(400));
    const d = await authorize(w.req(header, json(refund(400))), w.opts);
    expect({ allow: d.allow, status: d.status, code: d.code, reason: d.reason, policy: d.policyVerdict?.checks['policy'] }).toEqual({
      allow: false,
      status: 403,
      code: 'proof-rejected',
      reason: 'policy: amount <= 100 not satisfied for stripe.refund on charge:ch_1',
      policy: 'fail',
    });
  });

  it('signature-only mode (explicit since 0.5) admits a $400 body (the agent signs only the binding): the gap full mode closes', async () => {
    const w = world();
    const legacy: GatewayOptions = { ...w.opts, insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard: { claim: async () => true }, requireChecks: [] };
    const binding = requestBinding({ method: 'POST', path: PATH, headers: {} });
    const { encoded } = w.a.act(VERB, 'charge:ch_1', binding);
    const d = await authorize(w.req(pcaHeaders(encoded)[PCA_HEADER]!, json(refund(400))), legacy);
    expect({ allow: d.allow, code: d.code, policyVerdict: d.policyVerdict }).toEqual({ allow: true, code: 'allow', policyVerdict: undefined });
  });

  it('a $50 refund is allowed once; the replayed proof is refused', async () => {
    const w = world();
    const { header, pcactn } = w.sign(refund(50));
    const ok = await authorize(w.req(header, json(refund(50))), w.opts);
    expect({ allow: ok.allow, code: ok.code, reason: ok.reason, policy: ok.policyVerdict?.checks['policy'] }).toEqual({
      allow: true,
      code: 'allow',
      reason: 'proof-carrying action authorized (full policy)',
      policy: 'pass',
    });
    const again = await authorize(w.req(header, json(refund(50))), w.opts);
    expect({ allow: again.allow, status: again.status, code: again.code, reason: again.reason }).toEqual({
      allow: false,
      status: 403,
      code: 'replayed-proof',
      reason: `replay: ${pcactn.counter} is not greater than last seen ${pcactn.counter} (replay)`,
    });
  });

  it('a revoked grant is refused', async () => {
    const w = world();
    w.revoked.v = true;
    const { header } = w.sign(refund(50));
    const d = await authorize(w.req(header, json(refund(50))), w.opts);
    expect({ allow: d.allow, status: d.status, code: d.code, revocation: d.policyVerdict?.checks['revocation'] }).toEqual({ allow: false, status: 403, code: 'proof-rejected', revocation: 'fail' });
  });
});

describe('pca-gateway full-policy mode: plan_root_authorized is enforced (not waived)', () => {
  it('a full-mode gateway with no authorizedPlanRoots denies with plan_root_authorized', async () => {
    const w = world();
    const { header } = w.sign(refund(50));
    const { authorizedPlanRoots: _r, ...noRoots } = w.opts;
    const d = await authorize(w.req(header, json(refund(50))), noRoots);
    expect({ allow: d.allow, code: d.code, check: d.verdict?.checks['plan_root_authorized'] }).toEqual({ allow: false, code: 'verify-failed', check: 'fail' });
    const other = await authorize(w.req(header, json(refund(50))), { ...w.opts, authorizedPlanRoots: ['not-this-root'] });
    expect({ allow: other.allow, code: other.code, check: other.verdict?.checks['plan_root_authorized'] }).toEqual({ allow: false, code: 'verify-failed', check: 'fail' });
  });
});

describe('pca-gateway full-policy mode: binding the real params', () => {
  it('a body that differs from the signed params, or another path, is a request mismatch (and does not spend the proof)', async () => {
    const w = world();
    const { header } = w.sign(refund(50));
    const mismatch = { allow: false, status: 403, code: 'request-mismatch', reason: 'the proof is not bound to this request (params/method/path/query/authority)' };
    const pick = (d: { allow: boolean; status: number; code: string; reason: string }) => ({ allow: d.allow, status: d.status, code: d.code, reason: d.reason });
    expect(pick(await authorize(w.req(header, json(refund(90))), w.opts))).toEqual(mismatch);
    expect(pick(await authorize(w.req(header, json(refund(50)), { path: '/refunds/ch_2' }), w.opts))).toEqual(mismatch);
    expect(pick(await authorize(w.req(header, json(refund(50)), { query: 'x=1' }), w.opts))).toEqual(mismatch);
    expect((await authorize(w.req(header, json(refund(50))), w.opts)).allow).toBe(true);
  });

  it('no body, a non-object body, non-strict JSON, or a body that carries `binding` is refused', async () => {
    const w = world();
    const { header } = w.sign(refund(50));
    const reasonOf = async (r: GatewayRequest) => {
      const d = await authorize(r, w.opts);
      return [d.code, d.reason];
    };
    const { body: _b, ...noBody } = w.req(header, '');
    expect(await reasonOf(noBody)).toEqual(['request-mismatch', 'full policy mode reads the params from the body, and the request carries none']);
    expect(await reasonOf(w.req(header, '[1]'))).toEqual(['request-mismatch', 'the request params are not a JSON object']);
    expect(await reasonOf(w.req(header, '{"amount":1,"amount":2}'))).toMatchObject(['request-mismatch', expect.stringMatching(/^the body is not strict JSON: /)]);
    expect(await reasonOf(w.req(header, json({ ...refund(50), binding: {} })))).toEqual(['request-mismatch', "the request params carry a 'binding' member (reserved for the request binding)"]);
  });

  it('bindParams refuses params that already carry `binding`, and passes params through with no binding', () => {
    expect(() => bindParams({ binding: 1 }, { v: 2, method: 'POST', path: '/', query: '' })).toThrow("params already have a 'binding' member");
    const p = { amount: 1 };
    expect(bindParams(p)).toBe(p);
  });

  it('with bindRequest: false the agent signs only the params', async () => {
    const w = world();
    const { encoded, pcactn } = w.a.act(VERB, 'charge:ch_1', refund(50));
    w.roots.push(pcactn.plan.root);
    const d = await authorize(w.req(pcaHeaders(encoded)[PCA_HEADER]!, json(refund(50))), { ...w.opts, bindRequest: false });
    expect(d.allow).toBe(true);
  });
});

describe('pca-gateway full-policy mode fails closed on a missing component', () => {
  const cases: [string, Partial<GatewayPolicy>, string][] = [
    ['state', { state: undefined as never }, 'state'],
    ['isRevoked', { isRevoked: undefined as never }, 'isRevoked'],
    ['params', { params: undefined as never }, "params ('body' or a function)"],
    ['mode', { mode: 'partial' as never }, "a known policy mode (got 'partial')"],
  ];
  for (const [name, patch, label] of cases) {
    it(`no ${name}: createGateway throws, authorize denies every request`, async () => {
      const w = world();
      const { header } = w.sign(refund(50));
      const opts = { ...w.opts, policy: { ...w.policy, ...patch } as GatewayPolicy };
      expect(() => createGateway(opts)).toThrow(new TypeError(`pca-gateway: full policy mode is missing ${label}`));
      const d = await authorize(w.req(header, json(refund(50))), opts);
      expect({ allow: d.allow, status: d.status, code: d.code, reason: d.reason }).toEqual({ allow: false, status: 403, code: 'proof-rejected', reason: `full policy mode is missing ${label} (fail closed)` });
    });
  }
});

describe('pca-gateway full-policy mode: the reviewer acceptance test on every shim', () => {
  it('Envoy HTTP ext_authz: $400 403, $50 200 once, replay 403, revoked 403', async () => {
    const w = world();
    const [overH, ok, rvH] = [w.sign(refund(400)).header, w.sign(refund(50)).header, w.sign(refund(50)).header];
    const check = envoyExtAuthz(w.opts);
    const send = (header: string, amount: number) => check({ method: 'POST', path: PATH, headers: { 'pca-action': header }, body: json(refund(amount)) });
    const over = await send(overH, 400);
    expect([over.status, JSON.parse(over.body)]).toEqual([403, { error: 'proof-rejected', reason: 'policy: amount <= 100 not satisfied for stripe.refund on charge:ch_1' }]);
    expect((await send(ok, 50)).status).toBe(200);
    expect([(await send(ok, 50)).status, JSON.parse((await send(ok, 50)).body).error]).toEqual([403, 'replayed-proof']);
    w.revoked.v = true;
    const rv = await send(rvH, 50);
    expect([rv.status, JSON.parse(rv.body).error]).toEqual([403, 'proof-rejected']);
  });

  it('Envoy gRPC ext_authz: the body rides on attributes.request.http.body', async () => {
    const w = world();
    const [overH, ok] = [w.sign(refund(400)).header, w.sign(refund(50)).header];
    const check = envoyGrpcExtAuthz(w.opts);
    const send = (header: string, amount: number) => check({ attributes: { request: { http: { method: 'POST', path: PATH, headers: { 'pca-action': header }, body: json(refund(amount)) } } } });
    const over = await send(overH, 400);
    expect([over.status.code, over.deniedResponse?.status.code]).toEqual([7, 403]);
    expect((await send(ok, 50)).status.code).toBe(0);
    const again = await send(ok, 50);
    expect([again.status.code, JSON.parse(again.deniedResponse!.body).error]).toEqual([7, 'replayed-proof']);
  });

  it('Cloudflare Worker: the body is read from a clone; next never runs on a denial', async () => {
    const w = world();
    const [overH, ok, rvH, ncH] = [w.sign(refund(400)).header, w.sign(refund(50)).header, w.sign(refund(50)).header, w.sign(refund(50)).header];
    const forwarded: number[] = [];
    const mw = cloudflareWorker<WorkerLikeRequest & { amount: number }, { status: number; body: string }>({
      ...w.opts,
      next: (r) => (forwarded.push(r.amount), { status: 200, body: 'upstream' }),
      respond: (body, init) => ({ status: init.status, body }),
    });
    const request = (header: string, amount: number) => ({
      method: 'POST',
      url: `https://api.example.com${PATH}`,
      headers: { get: (n: string) => (n.toLowerCase() === 'pca-action' ? header : null) },
      clone: () => ({ text: async () => json(refund(amount)) }),
      amount,
    });
    const over = await mw(request(overH, 400));
    expect([over.status, JSON.parse(over.body).error]).toEqual([403, 'proof-rejected']);
    expect(await mw(request(ok, 50))).toEqual({ status: 200, body: 'upstream' });
    expect([(await mw(request(ok, 50))).status]).toEqual([403]);
    w.revoked.v = true;
    expect((await mw(request(rvH, 50))).status).toBe(403);
    expect(forwarded).toEqual([50]);
    // a Worker request without clone() has no body: full mode with body params fails closed
    const { clone: _c, ...noClone } = request(ncH, 50);
    expect(JSON.parse((await mw(noClone)).body).error).toBe('request-mismatch');
  });

  it('Lambda REQUEST authorizer: no body reaches it, so params come from the query (`params` function)', async () => {
    const fromQuery = (r: GatewayRequest) => {
      const q = new URLSearchParams(r.query ?? '');
      return { charge: r.path.split('/').pop(), amount: Number(q.get('amount')) };
    };
    const w = world({ params: fromQuery });
    const [overH, ok, rvH] = [w.sign(refund(400), 'amount=400').header, w.sign(refund(50), 'amount=50').header, w.sign(refund(50), 'amount=50').header];
    const auth = lambdaAuthorizer(w.opts);
    const send = (header: string, amount: number) =>
      auth({ httpMethod: 'POST', path: PATH, methodArn: 'arn:aws:execute-api:us-east-1:1:api/prod/POST/refunds/ch_1', queryStringParameters: { amount: String(amount) }, headers: { 'pca-action': header } });
    const effect = async (header: string, amount: number) => {
      const r = await send(header, amount);
      return [r.policyDocument.Statement[0]!.Effect, r.context['pcaCode']];
    };
    expect(await effect(overH, 400)).toEqual(['Deny', 'proof-rejected']);
    expect(await effect(ok, 50)).toEqual(['Allow', undefined]);
    expect(await effect(ok, 50)).toEqual(['Deny', 'replayed-proof']);
    w.revoked.v = true;
    expect(await effect(rvH, 50)).toEqual(['Deny', 'proof-rejected']);
    // with body params a Lambda authorizer never sees the body: denied, not downgraded
    const body = world();
    const bodyH = body.sign(refund(50)).header;
    expect((await lambdaAuthorizer(body.opts)({ httpMethod: 'POST', path: PATH, headers: { 'pca-action': bodyH } })).context['pcaCode']).toBe('request-mismatch');
  });
});
