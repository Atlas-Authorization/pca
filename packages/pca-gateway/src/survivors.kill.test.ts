import { describe, expect, it } from 'vitest';
import { agent, createProvenanceRecorder, principalDirectProvenance, type PcaOperation, generateKeyPair, missingExecutionComponents, pcaHeaders, PCA_HEADER, PROV_HEADER, type Agent } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import {
  authorize,
  bindParams,
  cloudflareWorker,
  createGateway,
  envoyGrpcExtAuthz,
  memoryPcaStore,
  memoryProvenanceLog,
  presentedArtifacts,
  presentedProvenance,
  requestBinding,
  type BindRequestOptions,
  type GatewayFullPolicy,
  type GatewayOptions,
  type GatewayRequest,
  type WorkerLikeRequest,
} from './index';

const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
const rq = (o: Partial<GatewayRequest> = {}): GatewayRequest => ({ method: 'POST', path: '/p', headers: {}, ...o });
const policyOf = (params: GatewayFullPolicy['params'] = 'body'): GatewayFullPolicy => ({ mode: 'full', params, state: memoryPcaStore(), isRevoked: () => false });

describe('memoryProvenanceLog', () => {
  it('dedupes on origin and source together and returns copies', async () => {
    const l = memoryProvenanceLog();
    expect(await l.seen('s')).toEqual([]);
    await l.add('s', { origin: 'tool', source: 'a' });
    await l.add('s', { origin: 'tool', source: 'a' });
    await l.add('s', { origin: 'retrieval' as never, source: 'a' });
    await l.add('s', { origin: 'tool', source: 'b' });
    const seen = [...(await l.seen('s'))];
    expect(seen).toEqual([{ origin: 'tool', source: 'a' }, { origin: 'retrieval', source: 'a' }, { origin: 'tool', source: 'b' }]);
    (await l.seen('s') as unknown[]).length = 0;
    expect(await l.seen('s')).toHaveLength(3);
  });
  it('drops the least recently used session, and keeps maxSessions of them', async () => {
    const l = memoryProvenanceLog(2);
    await l.add('s1', { origin: 'tool', source: 'x' });
    await l.add('s2', { origin: 'tool', source: 'x' });
    expect(await l.seen('s1')).toHaveLength(1);
    expect(await l.seen('s2')).toHaveLength(1);
    await l.add('s1', { origin: 'tool', source: 'y' });
    await l.add('s3', { origin: 'tool', source: 'x' });
    expect(await l.seen('s2')).toEqual([]);
    expect(await l.seen('s1')).toHaveLength(2);
    expect(await l.seen('s3')).toHaveLength(1);
  });
});

describe('presentedProvenance', () => {
  const body = (b: unknown) => JSON.stringify(b);
  it('reads a strict header and prefers it to the body', () => {
    const p = policyOf(() => ({}));
    expect(presentedProvenance(rq({ headers: { 'PCA-Provenance': enc({ a: 1 }) }, body: body({ pca_provenance: { b: 2 } }) }), p)).toEqual({ a: 1 });
  });
  it('an unreadable header is null, an empty one is no header', () => {
    expect(presentedProvenance(rq({ headers: { 'pca-provenance': '%%%' } }), policyOf())).toBeNull();
    expect(presentedProvenance(rq({ headers: { 'pca-provenance': '' } }), policyOf())).toBeUndefined();
  });
  it('the body member counts only when the params are not the body', () => {
    const b = body({ pca_provenance: { c: 3 } });
    expect(presentedProvenance(rq({ body: b }), policyOf(() => ({})))).toEqual({ c: 3 });
    expect(presentedProvenance(rq({ body: b }), policyOf('body'))).toBeUndefined();
    expect(presentedProvenance(rq({ body: body({ pca_provenance: null }) }), policyOf(() => ({})))).toBeNull();
  });
  it('anything else in the body is no provenance', () => {
    const p = policyOf(() => ({}));
    for (const b of [undefined, '', 'null', '5', '[1]', '{"x":1}', 'not json']) expect(presentedProvenance(rq({ ...(b === undefined ? {} : { body: b }) }), p)).toBeUndefined();
  });
  it('a body that is an array, a number, a string or a boolean has no member, even one its prototype carries', () => {
    const p = policyOf(() => ({}));
    const protos = [Array.prototype, Number.prototype, String.prototype, Boolean.prototype] as unknown as Array<Record<string, unknown>>;
    for (const proto of protos) proto.pca_provenance = { inherited: true };
    try {
      for (const b of ['[1]', '5', '"s"', 'true']) expect(presentedProvenance(rq({ body: b }), p), b).toBeUndefined();
    } finally {
      for (const proto of protos) delete proto.pca_provenance;
    }
  });
});

describe('presentedArtifacts', () => {
  const fn = policyOf(() => ({}));
  it('reads the discharge array and the narrow block from headers', () => {
    expect(presentedArtifacts(rq({ headers: { 'PCA-Discharges': enc([1, 2]), 'pca-narrow': enc({ n: 1 }) } }), policyOf())).toStrictEqual({ discharges: [1, 2], narrow: { n: 1 } });
  });
  it('ignores a discharge header that is not an array, and empty or unreadable headers', () => {
    expect(presentedArtifacts(rq({ headers: { 'pca-discharges': enc({ a: 1 }) } }), policyOf())).toStrictEqual({});
    expect(presentedArtifacts(rq({ headers: { 'pca-discharges': '', 'pca-narrow': '' } }), policyOf())).toStrictEqual({});
    expect(presentedArtifacts(rq({ headers: { 'pca-discharges': '!!!', 'pca-narrow': '!!!' } }), policyOf())).toStrictEqual({});
  });
  it('falls back to body members only when the params are not the body', () => {
    const b = JSON.stringify({ pca_discharges: ['d'], pca_narrow: { n: 2 } });
    expect(presentedArtifacts(rq({ body: b }), fn)).toStrictEqual({ discharges: ['d'], narrow: { n: 2 } });
    expect(presentedArtifacts(rq({ body: b }), policyOf('body'))).toStrictEqual({});
  });
  it('headers win over the body, and body members of the wrong shape are ignored', () => {
    const b = JSON.stringify({ pca_discharges: ['body'], pca_narrow: { n: 'body' } });
    expect(presentedArtifacts(rq({ headers: { 'pca-discharges': enc(['hdr']), 'pca-narrow': enc({ n: 'hdr' }) }, body: b }), fn)).toStrictEqual({ discharges: ['hdr'], narrow: { n: 'hdr' } });
    expect(presentedArtifacts(rq({ body: JSON.stringify({ pca_discharges: 'x' }) }), fn)).toStrictEqual({});
    expect(presentedArtifacts(rq({ body: JSON.stringify({ other: 1 }) }), fn)).toStrictEqual({});
    for (const x of [undefined, '', 'null', '5', '[1]', 'not json']) expect(presentedArtifacts(rq({ ...(x === undefined ? {} : { body: x }) }), fn)).toStrictEqual({});
  });
});

// ---- the full-policy pipeline ----------------------------------------------------------------------------------------

const provRec = () => createProvenanceRecorder({ mediator: 'test-harness', kid: 'k1', secretKey: new Uint8Array(32).fill(1) });
const PROV = {
  provenance: { mediators: [provRec().pin], bundle: (_r: unknown, _p: unknown, o: PcaOperation) => principalDirectProvenance(provRec(), { verb: o.verb, resource: o.resource, params: o.params ?? {} }) },
  provenanceLog: false as const,
};
const RATE_LIMITED_REFUND = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' })]);
const AUD = 'ins_kill_gw';
const VERB = 'stripe.refund';
const PATH = '/refunds/ch_1';
const refund = { charge: 'ch_1', amount: 50 };

function world(o: { params?: GatewayFullPolicy['params']; policy?: Partial<GatewayFullPolicy>; gw?: Partial<GatewayOptions>; noProv?: boolean } = {}) {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$1000/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const roots: string[] = [];
  const policy: GatewayFullPolicy = { mode: 'full', params: o.params ?? 'body', state: memoryPcaStore(), isRevoked: () => false, ...(o.noProv ? {} : PROV), ...o.policy };
  const opts: GatewayOptions = {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB } }],
    resolveGrant: (r) => (r === a.grant.id ? a.grant : null),
    authorizedPlanRoots: roots,
    policy,
    ...o.gw,
  };
  const sign = (params: Record<string, unknown> = refund, bindingReq: GatewayRequest = { method: 'POST', path: PATH, headers: {} }, bind: BindRequestOptions = { body: false }) => {
    const { encoded, pcactn } = a.act(VERB, 'charge:ch_1', bindParams(params, requestBinding(bindingReq, bind)));
    roots.push(pcactn.plan.root);
    return { header: pcaHeaders(encoded)[PCA_HEADER]!, pcactn };
  };
  const req = (header: string, extra: Partial<GatewayRequest> = {}): GatewayRequest => ({ method: 'POST', path: PATH, headers: { 'pca-action': header }, body: JSON.stringify(refund), ...extra });
  return { a, opts, policy, sign, req };
}
const brief = (d: Awaited<ReturnType<typeof authorize>>) => ({ allow: d.allow, status: d.status, code: d.code, reason: d.reason });

describe('full policy: request params and binding', () => {
  it('refuses params that are not a JSON object', async () => {
    for (const v of [undefined, null, 5, [1], 'x']) {
      const w = world({ params: () => v as never });
      const { header } = w.sign();
      expect(brief(await authorize(w.req(header), w.opts))).toEqual({ allow: false, status: 403, code: 'request-mismatch', reason: 'the request params are not a JSON object' });
    }
  });
  it('refuses a request that lacks the attribute the proof must bind', async () => {
    const msg = 'request lacks an attribute the proof must bind (authority / body hash)';
    for (const bindRequest of [{ authority: true }, { body: true }, { authority: true, body: true }]) {
      const w = world({ gw: { bindRequest } });
      const { header } = w.sign();
      const d = await authorize(w.req(header), w.opts);
      expect(brief(d)).toEqual({ allow: false, status: 403, code: 'request-mismatch', reason: msg });
      expect(d.pcactn).toBeDefined();
      expect(d.verdict).toBeDefined();
    }
    const w = world({ gw: { bindRequest: { authority: true } } });
    expect((await authorize(w.req(w.sign().header, { authority: 'x' }), w.opts)).reason).not.toBe(msg);
    const v = world({ gw: { bindRequest: { body: true } } });
    expect((await authorize(v.req(v.sign().header, { bodySha256: 'ab' }), v.opts)).reason).not.toBe(msg);
  });
  it('binds the authority and the body hash when asked, and only then', async () => {
    const both = world({ gw: { bindRequest: { authority: true, body: true } } });
    const r: GatewayRequest = { method: 'POST', path: PATH, headers: {}, authority: 'API.Example', bodySha256: 'ABCDEF' };
    expect(brief(await authorize(both.req(both.sign(refund, r, { authority: true, body: true }).header, { authority: 'API.Example', bodySha256: 'ABCDEF' }), both.opts))).toMatchObject({ allow: true, code: 'allow' });
    const auth = world({ gw: { bindRequest: { authority: true } } });
    expect((await authorize(auth.req(auth.sign(refund, r, { authority: true, body: false }).header, { authority: 'API.Example', bodySha256: 'ABCDEF' }), auth.opts)).allow).toBe(true);
    const none = world();
    expect((await authorize(none.req(none.sign(refund, r, { body: false }).header, { authority: 'API.Example', bodySha256: 'ABCDEF' }), none.opts)).allow).toBe(true);
    const wrong = world({ gw: { bindRequest: { authority: true } } });
    expect((await authorize(wrong.req(wrong.sign(refund, r, { body: false }).header, { authority: 'API.Example' }), wrong.opts)).code).toBe('request-mismatch');
  });
  it('turns an ambiguous query into a request-mismatch with the reason', async () => {
    const w = world();
    const d = await authorize(w.req(w.sign().header, { query: 'a=1&a=2' }), w.opts);
    expect(brief(d)).toEqual({ allow: false, status: 403, code: 'request-mismatch', reason: "the request cannot be bound: duplicate query parameter 'a'" });
    expect(d.pcactn).toBeDefined();
  });
  it('an unmapped route under require-proof still runs the full pipeline', async () => {
    const w = world({ gw: { routes: [], unmatchedRoute: 'require-proof' } });
    expect(brief(await authorize(w.req(w.sign().header), w.opts))).toMatchObject({ allow: true, code: 'allow', reason: 'proof-carrying action authorized (full policy)' });
  });
  it('a route with a resource runs the full pipeline for that resource', async () => {
    const w = world({ gw: { routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: VERB, resource: 'charge:ch_1' } }] } });
    expect((await authorize(w.req(w.sign().header), w.opts)).allow).toBe(true);
  });
  it('uses the gateway clock for the full pipeline', async () => {
    const w = world();
    const { header, pcactn } = w.sign();
    expect((await authorize(w.req(header), { ...w.opts, now: () => pcactn.iat })).allow).toBe(true);
    const w2 = world();
    const s2 = w2.sign();
    expect((await authorize(w2.req(s2.header), { ...w2.opts, now: () => s2.pcactn.exp + 3_600_000 })).allow).toBe(false);
  });
});

describe('full policy: denials carry the proof', () => {
  it('unknown grant', async () => {
    const w = world();
    const d = await authorize(w.req(w.sign().header), { ...w.opts, resolveGrant: () => null });
    expect(brief(d).code).toBe('unknown-grant');
    expect(d.pcactn).toBeDefined();
    expect(d.verdict).toBeUndefined();
  });
  it('checkProof refusals and failures', async () => {
    const cases: Array<[GatewayOptions['checkProof'], string]> = [
      [() => false, 'rejected by checkProof'],
      [() => ({ allow: false }), 'rejected by checkProof'],
      [() => ({ allow: false, reason: 'nope' }), 'nope'],
      [() => { throw new Error('bad hook'); }, 'checkProof failed: bad hook'],
    ];
    for (const [checkProof, reason] of cases) {
      const w = world({ gw: { checkProof } });
      const d = await authorize(w.req(w.sign().header), w.opts);
      expect(brief(d)).toEqual({ allow: false, status: 403, code: 'proof-rejected', reason });
      expect(d.pcactn).toBeDefined();
      expect(d.verdict).toBeDefined();
    }
    const ok = world({ gw: { checkProof: () => ({ allow: true }) } });
    expect((await authorize(ok.req(ok.sign().header), ok.opts)).allow).toBe(true);
  });
  it('a failing k1 input is a fail-closed refusal', async () => {
    const w = world({ policy: { k1: () => { throw new Error('boom'); } } });
    const d = await authorize(w.req(w.sign().header), w.opts);
    expect(brief(d)).toEqual({ allow: false, status: 403, code: 'proof-rejected', reason: 'k1 input failed: boom (fail closed)' });
    expect(d.pcactn).toBeDefined();
    expect(d.verdict).toBeDefined();
  });
  it('a configuration with several missing components names them all', () => {
    const opts: GatewayOptions = { audience: AUD, routes: [], resolveGrant: () => null, policy: { mode: 'full', params: 'body' } as never };
    const expected = missingExecutionComponents({ mode: 'full', params: 'body', audience: AUD, resolveGrant: opts.resolveGrant } as never);
    expect(expected.length).toBeGreaterThan(1);
    expect(() => createGateway(opts)).toThrow(new TypeError(`pca-gateway: full policy mode is missing ${expected.join(', ')}`));
  });
});

describe('full policy: the gateway keeps the caller\'s log by identity and writes to it', () => {
  it('records each allowed call in the configured provenance log', async () => {
    const rows: Array<[string, unknown]> = [];
    const log = { rows, seen() { return []; }, add(s: string, o: unknown) { this.rows.push([s, o]); } };
    const w = world({ policy: { provenanceLog: log } });
    const { header, pcactn } = w.sign(); // sign first: the gateway snapshots authorizedPlanRoots when it is created
    const gw = createGateway(w.opts);
    const d = await gw(w.req(header));
    expect(d.allow).toBe(true);
    expect(rows).toHaveLength(1);
    expect(rows[0]![0]).toBe(`${pcactn.grant_ref}\n${pcactn.cap_chain[pcactn.cap_chain.length - 1]!.holder}\n-`);
    expect(rows[0]![1]).toEqual({ origin: 'tool', source: VERB });
  });
  it('a plain-object state store stays the caller\'s object', async () => {
    const inner = memoryPcaStore();
    const store = { scope: 'process' as const, puts: [] as string[], get: (k: string) => inner.get(k), async put(k: string, s: Parameters<typeof inner.put>[1]) { this.puts.push(k); return inner.put(k, s); } };
    const w = world({ policy: { state: store as never } });
    const { header } = w.sign(); // sign first: the gateway snapshots authorizedPlanRoots when it is created
    const gw = createGateway(w.opts);
    expect((await gw(w.req(header))).allow).toBe(true);
    expect(store.puts.length).toBeGreaterThan(0);
  });
});

describe('adapters', () => {
  it('the worker adapter forwards the discharge and narrow headers to the gateway', async () => {
    const seen: GatewayRequest[] = [];
    const w = world({ params: () => ({}), policy: { k1: (r) => (seen.push(r), {}) } });
    const { header } = w.sign({});
    const h = new Map([['pca-action', header], ['pca-discharges', enc(['d'])], ['pca-narrow', enc({ n: 1 })]]);
    const request: WorkerLikeRequest = { method: 'POST', url: `https://api.example${PATH}`, headers: { get: (n) => h.get(n.toLowerCase()) ?? null } };
    await cloudflareWorker({ ...w.opts, next: () => 'next', respond: (b) => b })(request);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers).toEqual({ 'pca-action': header, 'pca-discharges': enc(['d']), 'pca-narrow': enc({ n: 1 }) });
  });
  it('the worker adapter reads a body only for body params, from a clone', async () => {
    const reads: string[] = [];
    const mk = (params: GatewayFullPolicy['params']) => {
      const w = world({ params });
      const { header } = w.sign(params === 'body' ? refund : {});
      const request: WorkerLikeRequest = { method: 'POST', url: `https://api.example${PATH}`, headers: { get: (n) => (n.toLowerCase() === 'pca-action' ? header : null) }, clone: () => ({ text: async () => (reads.push('r'), JSON.stringify(refund)) }) };
      return { w, request };
    };
    const a = mk('body');
    expect(await cloudflareWorker({ ...a.w.opts, next: () => 'next', respond: (b) => b })(a.request)).toBe('next');
    expect(reads).toEqual(['r']);
    const b = mk(() => ({}));
    await cloudflareWorker({ ...b.w.opts, next: () => 'next', respond: (x) => x })(b.request);
    expect(reads).toEqual(['r']);
  });
  it('the worker adapter forwards only the headers that are present and reads no body in signature-only mode', async () => {
    const seen: GatewayRequest[] = [];
    const w = world({ params: () => ({}), policy: { k1: (r) => (seen.push(r), {}) } });
    const { header } = w.sign({});
    const request: WorkerLikeRequest = { method: 'POST', url: `https://api.example${PATH}`, headers: { get: (n) => (n.toLowerCase() === 'pca-action' ? header : null) } };
    await cloudflareWorker({ ...w.opts, next: () => 'next', respond: (b) => b })(request);
    expect(seen[0]!.headers).toEqual({ 'pca-action': header });
    let reads = 0;
    const sig = world();
    const sigReq: WorkerLikeRequest = { method: 'GET', url: 'https://api.example/x', headers: { get: () => null }, clone: () => ({ text: async () => (reads++, '') }) };
    await cloudflareWorker({ ...sig.opts, policy: { mode: 'signature-only' }, replayGuard: { claim: async () => true }, requireChecks: [], next: () => 'next', respond: (b) => b })(sigReq);
    expect(reads).toBe(0);
  });
  it('the gRPC adapter hands the body to the gateway', async () => {
    const w = world();
    const { header } = w.sign();
    const check = envoyGrpcExtAuthz(w.opts);
    const ok = await check({ attributes: { request: { http: { method: 'POST', path: PATH, headers: { 'pca-action': header }, body: JSON.stringify(refund) } } } } as never);
    expect(ok.status?.code).toBe(0);
    const w2 = world();
    const s2 = w2.sign();
    const nobody = await envoyGrpcExtAuthz(w2.opts)({ attributes: { request: { http: { method: 'POST', path: PATH, headers: { 'pca-action': s2.header } } } } } as never);
    expect(nobody.status?.code).not.toBe(0);
    expect(nobody.deniedResponse?.body).toContain('request-mismatch');
  });
});

describe('full policy: session key', () => {
  it('keys the log by the session of the presented provenance bundle', async () => {
    const rows: string[] = [];
    const log = { seen: () => [] as never[], add: (k: string) => { rows.push(k); } };
    const w = world({ noProv: true, policy: { provenanceLog: log } });
    w.a.provenance!.principal('Refund 50 on charge ch_1');
    const binding = requestBinding({ method: 'POST', path: PATH, headers: {} }, { body: false });
    const r = w.a.act(VERB, 'charge:ch_1', bindParams(refund, binding));
    const h = pcaHeaders(r.encoded, r.provenance);
    const request = w.req(h[PCA_HEADER]!, { headers: { 'pca-action': h[PCA_HEADER]!, 'pca-provenance': h[PROV_HEADER]! } });
    const bundle = presentedProvenance(request, w.policy) as { receipts: Array<{ session: string }> };
    await createGateway({ ...w.opts, authorizedPlanRoots: [r.pcactn.plan.root] })(request);
    expect(typeof bundle.receipts[0]!.session).toBe('string');
    expect(rows).toEqual([`${r.pcactn.grant_ref}\n${r.pcactn.cap_chain[r.pcactn.cap_chain.length - 1]!.holder}\n${bundle.receipts[0]!.session}`]);
  });
});
