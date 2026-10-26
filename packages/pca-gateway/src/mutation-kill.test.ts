/**
 * Mutation-kill tests for the gateway core and its Envoy / Worker / Lambda adapters: exact reasons, status codes,
 * header sets, request shapes handed to hooks, boundary values of the replay guard and path matcher.
 */
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import {
  ambiguousPathReason,
  canonicalQuery,
  authorize,
  cloudflareWorker,
  envoyExtAuthz,
  envoyGrpcExtAuthz,
  lambdaAuthorizer,
  lambdaSimpleAuthorizer,
  memoryReplayGuard,
  requestBinding,
  type GatewayOptions,
  type GatewayRequest,
  type ProofCheckContext,
} from './index';

/** Signature-only on purpose (0.5: an explicit mode): these tests are about routing, adapters and binding; full mode is in full-policy.test.ts. */
const SIG_ONLY = { policy: { mode: 'signature-only' as const }, replayGuard: { claim: async () => true }, requireChecks: [] as string[] };

const AUD = 'ins_mk';
type Minted = { encoded: string; grant: Capability; ref: string; header: string; sig: string; exp: number };
function mint(params: unknown = { amount: 20 }, resource = 'charge:ch_1'): Minted {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  const { encoded, pcactn } = a.act('stripe.refund', resource, params as Record<string, unknown>, { counter: 1 });
  return { encoded, grant: a.grant as Capability, ref: pcactn.grant_ref, header: pcaHeaders(encoded)[PCA_HEADER] as string, sig: pcactn.sig, exp: pcactn.exp };
}
const base = (m: Minted, o: Partial<GatewayOptions> = {}): GatewayOptions => ({
  audience: AUD,
  routes: [],
  bindRequest: false, // these tests are about routing/adapters; binding is covered in bind.test.ts
  unmatchedRoute: 'require-proof',
  resolveGrant: async (r) => (r === m.ref ? m.grant : null),
  ...SIG_ONLY,
  ...o,
});
const H = (m: Minted) => ({ 'pca-action': m.header });

describe('requestBinding', () => {
  it('upper-cases the method, lower-cases authority and body hash, and only includes what is asked for', () => {
    const r: GatewayRequest = { method: 'post', path: '/p', authority: 'API.Example', bodySha256: 'ABCDEF', headers: {} };
    expect(requestBinding(r, { body: false })).toStrictEqual({ v: 2, method: 'POST', path: '/p', query: '' });
    expect(requestBinding(r, { body: false, authority: true })).toStrictEqual({ v: 2, method: 'POST', path: '/p', query: '', authority: 'api.example' });
    expect(requestBinding(r, { body: true })).toStrictEqual({ v: 2, method: 'POST', path: '/p', query: '', body_sha256: 'abcdef' });
    // default: the body hash is bound whenever the request carries one
    expect(requestBinding(r)).toStrictEqual({ v: 2, method: 'POST', path: '/p', query: '', body_sha256: 'abcdef' });
    expect(requestBinding({ method: 'get', path: '/', headers: {} }, { authority: true, body: true })).toStrictEqual({
      v: 2, method: 'GET', path: '/', query: '', authority: '', body_sha256: '',
    });
    // the query is bound, sorted
    expect(requestBinding({ method: 'get', path: '/', query: '?b=2&a=1&', headers: {} }).query).toBe('a=1&b=2');
  });
});

describe('memoryReplayGuard', () => {
  it('claims once; a claim is live through exp inclusive', () => {
    const g = memoryReplayGuard(10, () => 0);
    expect(g.claim('k', 10, 0)).toBe(true);
    expect(g.claim('k', 10, 10)).toBe(false);
    expect(g.claim('k', 10, 11)).toBe(true);
  });
  it('uses its own clock when no nowMs is given', () => {
    let t = 0;
    const g = memoryReplayGuard(10, () => t);
    expect(g.claim('k', 5)).toBe(true);
    expect(g.claim('k', 5)).toBe(false);
    t = 6;
    expect(g.claim('k', 9)).toBe(true);
  });
  it('does not prune while below the cap', () => {
    const g = memoryReplayGuard(3, () => 0);
    expect(g.claim('a', 10, 0)).toBe(true);
    expect(g.claim('b', 100, 50)); // would prune 'a' if pruning ran below the cap
    expect(g.claim('a', 10, 5)).toBe(false);
  });
  it('at the cap: prunes only strictly-expired claims, fails closed when none are, with a specific message', () => {
    const g = memoryReplayGuard(1, () => 0);
    expect(g.claim('a', 50, 0)).toBe(true);
    expect(() => g.claim('b', 100, 50)).toThrow('replay guard full'); // exp == now is still live
    expect(g.claim('b', 100, 51)).toBe(true); // a pruned (50 < 51), room made
    expect(() => g.claim('c', 200, 60)).toThrow(/^replay guard full$/);
  });
  it('prunes just enough room: after pruning one expired entry below the cap the claim succeeds', () => {
    const g = memoryReplayGuard(2, () => 0);
    g.claim('a', 10, 0);
    g.claim('b', 100, 0);
    expect(g.claim('c', 100, 20)).toBe(true);
    expect(() => g.claim('d', 100, 20)).toThrow('replay guard full');
  });
});

describe('header extraction', () => {
  it('takes the first value of an array header, matches names case-insensitively, and rejects empty values', async () => {
    const m = mint();
    expect((await authorize({ method: 'GET', path: '/x', headers: { 'PCA-Action': [m.header, 'garbage'] } }, base(m))).allow).toBe(true);
    const empty = await authorize({ method: 'GET', path: '/x', headers: { 'pca-action': [] } }, base(m));
    expect([empty.code, empty.status]).toEqual(['no-proof', 401]);
    const blank = await authorize({ method: 'GET', path: '/x', headers: { 'pca-action': '' } }, base(m));
    expect(blank.code).toBe('no-proof');
    expect(blank.reason).toBe(`no ${PCA_HEADER} header`);
    const und = await authorize({ method: 'GET', path: '/x', headers: { 'pca-action': undefined } }, base(m));
    expect(und.code).toBe('no-proof');
  });
  it('an undecodable header names the header and carries the decoder error', async () => {
    const d = await authorize({ method: 'GET', path: '/x', headers: { 'pca-action': '!!!' } }, base(mint()));
    expect(d.code).toBe('invalid-proof');
    expect(d.reason.startsWith(`undecodable ${PCA_HEADER} header: `)).toBe(true);
    expect(d.reason.length).toBeGreaterThan(`undecodable ${PCA_HEADER} header: `.length);
  });
});

/** True when (method, path) matched a route (a proofless request then fails with no-proof rather than unmapped-route). */
async function routed(rule: { method?: string; path: string }, method: string, path: string): Promise<boolean> {
  const m = mint();
  const d = await authorize({ method, path, headers: {} }, base(m, { unmatchedRoute: 'deny', routes: [{ ...rule, capability: { verb: 'stripe.refund' } }] }));
  return d.code === 'no-proof';
}

describe('route matching', () => {
  it('methods: undefined, *, ANY (any case) match everything; otherwise case-insensitive equality', async () => {
    expect(await routed({ path: '/a' }, 'DELETE', '/a')).toBe(true);
    expect(await routed({ method: '*', path: '/a' }, 'DELETE', '/a')).toBe(true);
    expect(await routed({ method: 'ANY', path: '/a' }, 'DELETE', '/a')).toBe(true);
    expect(await routed({ method: 'any', path: '/a' }, 'DELETE', '/a')).toBe(true);
    expect(await routed({ method: 'post', path: '/a' }, 'POST', '/a')).toBe(true);
    expect(await routed({ method: 'POST', path: '/a' }, 'post', '/a')).toBe(true);
    expect(await routed({ method: 'GET', path: '/a' }, 'POST', '/a')).toBe(false);
  });
  it('paths: exact, "/x/*" directory, "/x*" prefix, "/*" and "*" everything', async () => {
    expect(await routed({ path: '/a' }, 'GET', '/a')).toBe(true);
    expect(await routed({ path: '/a' }, 'GET', '/ab')).toBe(false);
    expect(await routed({ path: '/a' }, 'GET', '/')).toBe(false);
    expect(await routed({ path: '/api/*' }, 'GET', '/api')).toBe(true);
    expect(await routed({ path: '/api/*' }, 'GET', '/api/x/y')).toBe(true);
    expect(await routed({ path: '/api/*' }, 'GET', '/apix')).toBe(false);
    expect(await routed({ path: '/api/*' }, 'GET', '/ap')).toBe(false);
    expect(await routed({ path: '/api*' }, 'GET', '/apix')).toBe(true);
    expect(await routed({ path: '/api*' }, 'GET', '/api')).toBe(true);
    expect(await routed({ path: '/api*' }, 'GET', '/ap')).toBe(false);
    expect(await routed({ path: '/api*' }, 'GET', '/xapi')).toBe(false);
    expect(await routed({ path: '/*' }, 'GET', '/anything/at/all')).toBe(true);
    expect(await routed({ path: '/*' }, 'GET', 'no-leading-slash')).toBe(true);
    expect(await routed({ path: '*' }, 'GET', '/anything')).toBe(true);
    expect(await routed({ path: '*' }, 'GET', 'no-leading-slash')).toBe(true);
    expect(await routed({ path: '/pre/*x' }, 'GET', '/pre/zzx')).toBe(false);
  });
  it('unmapped routes: deny by default with a specific reason; allow carries a specific allow reason', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/nope', headers: {} }, base(m, { unmatchedRoute: 'deny' }));
    expect([d.code, d.status, d.reason]).toEqual(['unmapped-route', 403, 'no capability mapping for GET /nope (deny-by-default)']);
    const dflt = await authorize({ method: 'GET', path: '/nope', headers: {} }, { ...base(m), unmatchedRoute: undefined });
    expect(dflt.code).toBe('unmapped-route');
    const a = await authorize({ method: 'GET', path: '/nope', headers: {} }, base(m, { unmatchedRoute: 'allow' }));
    expect(a.allow).toBe(true);
    expect(a.reason).toBe('route GET /nope is unmapped (unmatchedRoute=allow)');
    expect(a.headers).toStrictEqual({});
    expect(a.verdict).toBeUndefined();
  });
});

describe('ambiguousPathReason', () => {
  it.each([
    ['/a\u0001b', 'control character or backslash in path'],
    ['/a\\b', 'control character or backslash in path'],
    ['/a\u007fb', 'control character or backslash in path'],
    ['/a//b', 'repeated slash in path'],
    ['/a;x=1', 'path parameter (;) in path'],
    ['/a/../b', 'dot segment in path'],
    ['/a/./b', 'dot segment in path'],
    ['/a%00b', 'percent-encoded control character in path'],
    ['/a%1fb', 'percent-encoded control character in path'],
    ['/a%7fb', 'percent-encoded control character in path'],
    ['/a%2fb', 'percent-encoded slash in path'],
    ['/a%5Cb', 'percent-encoded slash in path'],
    ['/a%3Bb', 'percent-encoded path parameter delimiter in path'],
    ['/a%41b', 'non-canonical percent-encoding in path'],
    ['/a%7ab', 'non-canonical percent-encoding in path'],
    ['/a%2db', 'non-canonical percent-encoding in path'],
    ['/a%2Eb', 'non-canonical percent-encoding in path'],
    ['/a%5fb', 'non-canonical percent-encoding in path'],
    ['/a%7eb', 'non-canonical percent-encoding in path'],
    ['/a%39b', 'non-canonical percent-encoding in path'],
    ['/a%4g', 'malformed percent-encoding in path'],
    ['/a%', 'malformed percent-encoding in path'],
    ['/a%zz', 'malformed percent-encoding in path'],
  ])('%j -> %s', (p, why) => {
    expect(ambiguousPathReason(p)).toBe(why);
  });
  it.each(['/a%20b', '/a%C3%A9', '/ok/path-1_2.3~', '/', '/a%7B'])('%j is unambiguous', (p) => {
    expect(ambiguousPathReason(p)).toBeUndefined();
  });
  it('control chars at the boundaries 0x00 / 0x1f / 0x20', () => {
    expect(ambiguousPathReason('/\u0000')).toBeDefined();
    expect(ambiguousPathReason('/\u001f')).toBeDefined();
    expect(ambiguousPathReason('/ ')).toBeUndefined();
    expect(ambiguousPathReason('/a%1f')).toBe('percent-encoded control character in path');
    expect(ambiguousPathReason('/a%20')).toBeUndefined();
    expect(ambiguousPathReason('/a%7E')).toBe('non-canonical percent-encoding in path');
  });
});

describe('authorize decisions carry exact reasons and evidence', () => {
  it('unknown grant', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { resolveGrant: async () => undefined }));
    expect([d.code, d.status, d.reason]).toEqual(['unknown-grant', 401, `unknown grant_ref ${m.ref}`]);
    expect(d.pcactn?.grant_ref).toBe(m.ref);
    expect(d.headers['www-authenticate']).toBe(`PCA realm="${AUD}", error="invalid_proof"`);
  });
  it('realm override', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/x', headers: {} }, base(m, { realm: 'r1' }));
    expect(d.headers['www-authenticate']).toBe('PCA realm="r1", error="missing_proof"');
  });
  it('verify failure with evidence; wrong audience is 403', async () => {
    const m = mint();
    const wa = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { audience: 'other' }));
    expect([wa.code, wa.status]).toEqual(['wrong-audience', 403]);
    expect(wa.verdict?.allow).toBe(false);
    expect(wa.pcactn?.grant_ref).toBe(m.ref);
    expect(wa.reason).toBe(wa.verdict?.reason);
    expect(wa.reason).not.toBe('PCActn verification failed');
    expect(wa.reason.length).toBeGreaterThan(0);
    const exp = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { now: () => m.exp + 10 * 60_000 }));
    expect([exp.code, exp.status]).toEqual(['verify-failed', 401]);
    expect(exp.verdict?.allow).toBe(false);
    expect(exp.headers['www-authenticate']).toContain('invalid_proof');
  });
  it('capability enforcement: verb and resource, with matched evidence', async () => {
    const m = mint();
    const o = (cap: { verb: string; resource?: string }) => base(m, { unmatchedRoute: 'deny', routes: [{ path: '/x', capability: cap }] });
    const req = { method: 'GET', path: '/x', headers: H(m) };
    const v = await authorize(req, o({ verb: 'stripe.payout' }));
    expect([v.code, v.status]).toEqual(['insufficient-capability', 403]);
    expect(v.reason).toBe("route requires capability 'stripe.payout' but the proof authorizes 'stripe.refund'");
    expect(v.matched).toEqual({ verb: 'stripe.payout' });
    expect(v.verdict?.allow).toBe(true);
    expect(v.pcactn?.grant_ref).toBe(m.ref);
    const r = await authorize(req, o({ verb: 'stripe.refund', resource: 'charge:other' }));
    expect(r.code).toBe('insufficient-capability');
    expect(r.reason).toBe("route is bound to resource 'charge:other' but the proof targets 'charge:ch_1'");
    expect(r.matched).toEqual({ verb: 'stripe.refund', resource: 'charge:other' });
    expect(r.verdict?.allow).toBe(true);
    expect(r.pcactn?.grant_ref).toBe(m.ref);
    const ok = await authorize(req, o({ verb: 'stripe.refund', resource: 'charge:ch_1' }));
    expect(ok.allow).toBe(true);
    expect(ok.matched).toEqual({ verb: 'stripe.refund', resource: 'charge:ch_1' });
    expect(ok.reason).toBe('proof-carrying action verified');
    expect(JSON.parse(ok.headers['x-pca-verdict'] as string).allow).toBe(true);
  });
  it('require-proof without a rule: allow decision has no matched capability', async () => {
    const m = mint();
    const ok = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m));
    expect(ok.allow).toBe(true);
    expect('matched' in ok).toBe(false);
    expect(ok.verdict?.allow).toBe(true);
    expect(ok.pcactn?.grant_ref).toBe(m.ref);
  });
});

describe('request binding (RT-09) reasons', () => {
  const LACKS = 'request lacks an attribute the proof must bind (authority / body hash)';
  const MISMATCH = 'the proof is not bound to this request (method/path/query/authority/body)';
  it('missing authority, missing body, and mismatches each report their own reason, with evidence', async () => {
    const full: GatewayRequest = { method: 'POST', path: '/p', authority: 'a.example', bodySha256: 'ab', headers: {} };
    const m = mint(requestBinding(full, { authority: true, body: true }));
    const req = (over: Partial<GatewayRequest>): GatewayRequest => ({ ...full, ...over, headers: H(m) });
    const both = base(m, { bindRequest: { authority: true, body: true } });
    const a = await authorize(req({ authority: undefined }), both);
    expect([a.code, a.status, a.reason]).toEqual(['request-mismatch', 403, LACKS]);
    expect(a.verdict?.allow).toBe(true);
    expect(a.pcactn?.grant_ref).toBe(m.ref);
    expect((await authorize(req({ bodySha256: undefined }), both)).reason).toBe(LACKS);
    expect((await authorize(req({ authority: '' }), both)).reason).toBe(LACKS);
    // authority-only binding: a missing body hash is NOT a "lacks" error, a missing authority is
    const onlyAuth = base(m, { bindRequest: { authority: true } });
    expect((await authorize(req({ authority: undefined }), onlyAuth)).reason).toBe(LACKS);
    expect((await authorize(req({ authority: 'x.example' }), onlyAuth)).reason).toBe(MISMATCH);
    // body-only binding: a missing authority is not a "lacks" error
    const onlyBody = base(m, { bindRequest: { body: true } });
    expect((await authorize(req({ bodySha256: undefined }), onlyBody)).reason).toBe(LACKS);
    expect((await authorize(req({ authority: undefined, bodySha256: 'cd' }), onlyBody)).reason).toBe(MISMATCH);
    const mm = await authorize(req({ path: '/other' }), both);
    expect([mm.code, mm.reason]).toEqual(['request-mismatch', MISMATCH]);
    expect(mm.verdict?.allow).toBe(true);
    expect(mm.pcactn?.grant_ref).toBe(m.ref);
    expect((await authorize(req({}), both)).allow).toBe(true);
    // case-insensitive authority / hash
    expect((await authorize(req({ authority: 'A.EXAMPLE', bodySha256: 'AB' }), both)).allow).toBe(true);
  });
});

describe('requireChecks / checkProof / replayGuard', () => {
  it('requireChecks: a failing or absent check is named in the reason', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { requireChecks: ['no_such_check'] }));
    expect([d.code, d.status, d.reason]).toEqual(['proof-rejected', 403, "required check 'no_such_check' is absent"]);
    expect(d.verdict?.allow).toBe(true);
    expect(d.pcactn?.grant_ref).toBe(m.ref);
    const ok = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { requireChecks: ['audience'] }));
    expect(ok.allow).toBe(true);
    const ok0 = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { requireChecks: [] }));
    expect(ok0.allow).toBe(true);
    const probe = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m));
    const notPass = Object.entries(probe.verdict?.checks ?? {}).find(([, v]) => v !== 'pass');
    if (notPass) {
      const nd = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { requireChecks: [notPass[0]] }));
      expect(nd.reason).toBe(`required check '${notPass[0]}' is ${notPass[1]}`);
    }
  });
  it('checkProof receives the full context; the required capability only when a route matched', async () => {
    const m = mint();
    let ctx: ProofCheckContext | undefined;
    const spy = (c: ProofCheckContext): boolean => ((ctx = c), true);
    const req = { method: 'GET', path: '/x', headers: H(m) };
    await authorize(req, base(m, { checkProof: spy }));
    expect(ctx?.pcactn.grant_ref).toBe(m.ref);
    expect(ctx?.grant).toBe(m.grant);
    expect(ctx?.verdict.allow).toBe(true);
    expect(ctx?.request).toBe(req);
    expect(ctx && 'required' in ctx).toBe(false);
    await authorize(req, base(m, { checkProof: spy, unmatchedRoute: 'deny', routes: [{ path: '/x', capability: { verb: 'stripe.refund' } }] }));
    expect(ctx?.required).toEqual({ verb: 'stripe.refund' });
  });
  it('checkProof results: boolean, object with/without reason, and throws', async () => {
    const m = mint();
    const run = (r: () => unknown) => authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { checkProof: r as never }));
    const f = await run(() => false);
    expect([f.code, f.status, f.reason]).toEqual(['proof-rejected', 403, 'rejected by checkProof']);
    expect(f.verdict?.allow).toBe(true);
    expect(f.pcactn?.grant_ref).toBe(m.ref);
    expect((await run(() => ({ allow: false }))).reason).toBe('rejected by checkProof');
    expect((await run(() => ({ allow: false, reason: '' }))).reason).toBe('rejected by checkProof');
    expect((await run(() => ({ allow: false, reason: 'budget' }))).reason).toBe('budget');
    expect((await run(() => ({ allow: true, reason: 'x' }))).allow).toBe(true);
    expect((await run(() => true)).allow).toBe(true);
    expect((await run(async () => ({ allow: true }))).allow).toBe(true);
    const t = await run(() => { throw new Error('boom'); });
    expect([t.code, t.status, t.reason]).toEqual(['proof-rejected', 403, 'checkProof failed: boom']);
    expect(t.verdict?.allow).toBe(true);
    expect(t.pcactn?.grant_ref).toBe(m.ref);
    expect((await run(() => Promise.reject(new Error('late')))).reason).toBe('checkProof failed: late');
  });
  it('replayGuard: claims `grant:sig` with exp and the gateway clock; unavailability is 503; replays are 403', async () => {
    const m = mint();
    const calls: unknown[][] = [];
    const guard = { claim: (...a: unknown[]) => (calls.push(a), true) };
    const now = () => m.exp - 1000;
    const ok = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { replayGuard: guard as never, now }));
    expect(ok.allow).toBe(true);
    expect(calls).toEqual([[`${m.ref}:${m.sig}`, m.exp, m.exp - 1000]]);
    const down = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { replayGuard: { claim: () => { throw new Error('redis down'); } } }));
    expect([down.code, down.status, down.reason]).toEqual(['replay-guard-unavailable', 503, 'replay guard unavailable: redis down']);
    expect(down.verdict?.allow).toBe(true);
    expect(down.pcactn?.grant_ref).toBe(m.ref);
    expect(down.headers['www-authenticate']).toContain('temporarily_unavailable');
    const rg = memoryReplayGuard();
    await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { replayGuard: rg }));
    const again = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { replayGuard: rg }));
    expect([again.code, again.status, again.reason]).toEqual(['replayed-proof', 403, 'this proof has already been used']);
    expect(again.verdict?.allow).toBe(true);
    expect(again.pcactn?.grant_ref).toBe(m.ref);
  });
  it('pathPolicy: strict (default) refuses ambiguous paths with the reason; off lets them through to routing', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/a//b', headers: H(m) }, base(m));
    expect([d.code, d.status, d.reason]).toEqual(['invalid-path', 400, 'repeated slash in path']);
    expect((await authorize({ method: 'GET', path: '/a//b', headers: H(m) }, base(m, { pathPolicy: 'strict' }))).code).toBe('invalid-path');
    expect((await authorize({ method: 'GET', path: '/a//b', headers: H(m) }, base(m, { pathPolicy: 'off' }))).allow).toBe(true);
  });
});

describe('Envoy HTTP ext_authz', () => {
  const seen = (m: Minted) => {
    const box: { req?: GatewayRequest } = {};
    const o = base(m, { checkProof: (c) => ((box.req = c.request), true) });
    return { box, o };
  };
  it('request shape: method/path/authority sources, query and fragment stripped, defaults', async () => {
    const m = mint();
    const { box, o } = seen(m);
    const fn = envoyExtAuthz(o);
    const h = { 'pca-action': m.header };
    await fn({ method: 'POST', path: '/refunds?x=1', authority: 'a.example', headers: h });
    expect(box.req).toStrictEqual({ method: 'POST', path: '/refunds', query: 'x=1', authority: 'a.example', headers: h });
    await fn({ path: '/r#frag', headers: { ...h, ':method': 'PUT', ':authority': 'b.example' } });
    expect(box.req?.method).toBe('PUT');
    expect(box.req?.path).toBe('/r');
    expect(box.req?.authority).toBe('b.example');
    await fn({ headers: { ...h, ':path': '/viaheader' } });
    expect(box.req?.path).toBe('/viaheader');
    expect(box.req?.method).toBe('*');
    expect('authority' in (box.req as object)).toBe(false);
    await fn({ headers: h });
    expect(box.req?.path).toBe('/');
    await fn({ path: '?only=query', headers: h });
    expect(box.req?.path).toBe('/');
    await fn({ path: '', headers: h });
    expect(box.req?.path).toBe('/');
    await fn({ path: '/q?', headers: h });
    expect(box.req?.path).toBe('/q');
    await fn({ method: 'GET', path: '/p', authority: 'x', headers: { ...h, ':method': 'PUT', ':path': '/z', ':authority': 'y' } });
    expect([box.req?.method, box.req?.path, box.req?.authority]).toEqual(['GET', '/p', 'x']);
  });
  it('allow overwrites every injected header (blank when unset) with an empty body; deny is JSON with the challenge', async () => {
    const m = mint();
    const allowU = await envoyExtAuthz(base(m, { unmatchedRoute: 'allow' }))({ method: 'GET', path: '/x', headers: {} });
    expect(allowU).toStrictEqual({ status: 200, headers: { 'x-pca-verdict': '', 'x-pca-verb': '', 'x-pca-grant': '' }, body: '' });
    const ok = await envoyExtAuthz(base(m))({ method: 'GET', path: '/x', headers: { 'pca-action': m.header } });
    expect(ok.status).toBe(200);
    expect(ok.body).toBe('');
    expect(ok.headers['x-pca-verb']).toBe('stripe.refund');
    expect(ok.headers['x-pca-grant']).toBe(m.ref);
    expect(JSON.parse(ok.headers['x-pca-verdict'] as string).allow).toBe(true);
    const no = await envoyExtAuthz(base(m))({ method: 'GET', path: '/x', headers: {} });
    expect(no.status).toBe(401);
    expect(no.headers['content-type']).toBe('application/json');
    expect(no.headers['www-authenticate']).toBe(`PCA realm="${AUD}", error="missing_proof"`);
    expect(JSON.parse(no.body)).toStrictEqual({ error: 'no-proof', reason: `no ${PCA_HEADER} header` });
  });
});

describe('Envoy gRPC ext_authz', () => {
  it('no HTTP attributes fails closed with the exact response', async () => {
    const fn = envoyGrpcExtAuthz(base(mint()));
    for (const c of [{}, { attributes: {} }, { attributes: { request: {} } }]) {
      expect(await fn(c as never)).toStrictEqual({
        status: { code: 7, message: 'no http request attributes' },
        deniedResponse: {
          status: { code: 403 },
          headers: [],
          body: JSON.stringify({ error: 'invalid-request', reason: 'CheckRequest carried no HTTP attributes' }),
        },
      });
    }
  });
  it('request fields come from http.* then the pseudo-headers', async () => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    const fn = envoyGrpcExtAuthz(base(m, { checkProof: (c) => ((box.req = c.request), true) }));
    const h = { 'pca-action': m.header };
    await fn({ attributes: { request: { http: { method: 'POST', path: '/a?q', host: 'h.example', headers: { ...h, ':method': 'X', ':path': '/z', ':authority': 'z' } } } } });
    expect([box.req?.method, box.req?.path, box.req?.authority]).toEqual(['POST', '/a', 'h.example']);
    await fn({ attributes: { request: { http: { headers: { ...h, ':method': 'PUT', ':path': '/b', ':authority': 'p.example' } } } } });
    expect([box.req?.method, box.req?.path, box.req?.authority]).toEqual(['PUT', '/b', 'p.example']);
    await fn({ attributes: { request: { http: { headers: h } } } });
    expect([box.req?.method, box.req?.path]).toEqual(['*', '/']);
    expect('authority' in (box.req as object)).toBe(false);
    await fn({ attributes: { request: { http: { method: 'GET', path: '/n' } } } });
  });
  it('allow and deny envelopes, incl. gRPC status mapping 401 -> 16, 503 -> 14, else 7', async () => {
    const m = mint();
    const h = { 'pca-action': m.header };
    const call = (o: GatewayOptions, headers: Record<string, string>) =>
      envoyGrpcExtAuthz(o)({ attributes: { request: { http: { method: 'GET', path: '/x', headers } } } });
    const ok = await call(base(m), h);
    expect(ok.status).toStrictEqual({ code: 0, message: '' });
    const hk = ok.okResponse?.headers.map((x) => x.header.key);
    expect(hk).toEqual(['x-pca-verdict', 'x-pca-verb', 'x-pca-grant']);
    expect(ok.okResponse?.headersToRemove).toEqual([]);
    const un = await call(base(m, { unmatchedRoute: 'allow' }), {});
    expect(un.okResponse?.headers).toEqual([]);
    expect(un.okResponse?.headersToRemove).toEqual(['x-pca-verdict', 'x-pca-verb', 'x-pca-grant']);
    const d401 = await call(base(m), {});
    expect(d401.status.code).toBe(16);
    expect(d401.status.message).toBe(`no ${PCA_HEADER} header`);
    expect(d401.deniedResponse?.status).toStrictEqual({ code: 401 });
    expect(JSON.parse(d401.deniedResponse?.body as string)).toStrictEqual({ error: 'no-proof', reason: `no ${PCA_HEADER} header` });
    const keys = d401.deniedResponse?.headers.map((x) => [x.header.key, x.header.value]);
    expect(keys).toEqual([['content-type', 'application/json'], ['www-authenticate', `PCA realm="${AUD}", error="missing_proof"`]]);
    const d403 = await call(base(m, { unmatchedRoute: 'deny' }), {});
    expect(d403.status.code).toBe(7);
    expect(d403.deniedResponse?.status).toStrictEqual({ code: 403 });
    const d503 = await call(base(m, { replayGuard: { claim: () => { throw new Error('x'); } } }), h);
    expect(d503.status.code).toBe(14);
    expect(d503.deniedResponse?.status).toStrictEqual({ code: 503 });
  });
});

describe('Cloudflare Worker adapter', () => {
  const mkReq = (url: string, headers: Record<string, string>, method = 'GET') => new Request(url, { method, headers });
  it('path and authority come from the URL; query/fragment dropped; "/" default; no scheme means no authority', async () => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    const w = cloudflareWorker<Request, string>({ ...base(m, { checkProof: (c) => ((box.req = c.request), true) }), next: () => 'next', respond: (b) => b });
    const h = { 'pca-action': m.header };
    expect(await w(mkReq('https://h.example/refunds?x=1', h))).toBe('next');
    expect([box.req?.method, box.req?.path, box.req?.authority]).toEqual(['GET', '/refunds', 'h.example:'.slice(0, -1)]);
    const fake = (url: string, extra: Record<string, string> = {}) => ({ method: 'GET', url, headers: new Headers({ ...h, ...extra }) });
    const w2 = cloudflareWorker({ ...base(m, { checkProof: (c) => ((box.req = c.request), true) }), next: () => 'n', respond: (b: string) => b });
    await w2(fake('https://h.example'));
    expect([box.req?.path, box.req?.authority]).toEqual(['/', 'h.example']);
    await w2(fake('https://h.example/'));
    expect([box.req?.path, box.req?.authority]).toEqual(['/', 'h.example']);
    await w2(fake('/just/a/path#f'));
    expect([box.req?.path, box.req?.authority]).toEqual(['/just/a/path', '']);
    await w2(fake('/?q'));
    expect(box.req?.path).toBe('/');
    await w2(fake('https://h.example/a/b?x'));
    expect([box.req?.path, box.req?.authority]).toEqual(['/a/b', 'h.example']);
    await w2(fake(''));
    expect(box.req?.path).toBe('/');
  });
  it('only the PCA header is forwarded to the gateway; absent means no-proof', async () => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    const w = cloudflareWorker({ ...base(m, { checkProof: (c) => ((box.req = c.request), true) }), next: () => 'n', respond: (b: string, i) => `${i.status}:${b}` });
    await w({ method: 'GET', url: 'https://h/x', headers: new Headers({ 'pca-action': m.header, cookie: 'secret' }) });
    expect(box.req?.headers).toStrictEqual({ 'pca-action': m.header });
    const out = await w({ method: 'GET', url: 'https://h/x', headers: new Headers() });
    expect(out.startsWith('401:')).toBe(true);
    expect(JSON.parse(out.slice(4)).error).toBe('no-proof');
  });
  it('deny: respond gets JSON body, status, content-type and challenge', async () => {
    const m = mint();
    let got: { body: string; init: { status: number; headers: Record<string, string> } } | undefined;
    const w = cloudflareWorker({ ...base(m), next: () => 'n', respond: (body: string, init) => ((got = { body, init }), 'r') });
    await w({ method: 'GET', url: 'https://h/x', headers: new Headers() });
    expect(got?.init.status).toBe(401);
    expect(got?.init.headers).toStrictEqual({ 'content-type': 'application/json', 'www-authenticate': `PCA realm="${AUD}", error="missing_proof"` });
    expect(JSON.parse(got?.body as string)).toStrictEqual({ error: 'no-proof', reason: `no ${PCA_HEADER} header` });
  });
  it('allowed request without forged headers is passed through untouched', async () => {
    const m = mint();
    const req = mkReq('https://h/x', { 'pca-action': m.header, 'x-keep': '1' });
    let passed: unknown;
    const w = cloudflareWorker<Request, string>({ ...base(m), next: (r) => ((passed = r), 'ok'), respond: (b) => b });
    expect(await w(req)).toBe('ok');
    expect(passed).toBe(req);
  });
  it('forged x-pca-* headers are stripped by the default rewrite; other headers survive', async () => {
    const m = mint();
    let passed: Request | undefined;
    const w = cloudflareWorker<Request, string>({ ...base(m), next: (r) => ((passed = r), 'ok'), respond: (b) => b });
    expect(await w(mkReq('https://h/x', { 'pca-action': m.header, 'x-pca-verb': 'forged', 'X-PCA-Custom': '1', 'x-keep': '1' }))).toBe('ok');
    expect(passed?.headers.get('x-pca-verb')).toBeNull();
    expect(passed?.headers.get('x-pca-custom')).toBeNull();
    expect(passed?.headers.get('x-keep')).toBe('1');
    expect(passed?.headers.get('pca-action')).toBe(m.header);
  });
  it('rewriteRequest hook receives the exact list; null or undefined result refuses with 400 and a JSON body', async () => {
    const m = mint();
    let drop: readonly string[] = [];
    const w = cloudflareWorker<Request, string>({
      ...base(m),
      next: (r) => `next:${r.url}`,
      rewriteRequest: (r, d) => ((drop = d), new Request('https://rewritten/x', { headers: r.headers })),
      respond: (b) => b,
    });
    expect(await w(mkReq('https://h/x', { 'pca-action': m.header, 'x-pca-verb': 'a', 'x-pca-Grant': 'b' }))).toBe('next:https://rewritten/x');
    expect([...drop].sort()).toEqual(['x-pca-grant', 'x-pca-verb']);
    for (const rewriteRequest of [null, undefined as never]) {
      let got: { body: string; init: { status: number; headers: Record<string, string> } } | undefined;
      const w2 = cloudflareWorker<WLike, string>({
        ...base(m),
        next: () => 'NEXT',
        ...(rewriteRequest === null ? { rewriteRequest: null } : { rewriteRequest: () => undefined as never }),
        respond: (body, init) => ((got = { body, init }), 'resp'),
      });
      expect(await w2({ method: 'GET', url: 'https://h/x', headers: new Headers({ 'pca-action': m.header, 'x-pca-verb': 'a' }) })).toBe('resp');
      expect(got?.init).toStrictEqual({ status: 400, headers: { 'content-type': 'application/json' } });
      expect(JSON.parse(got?.body as string)).toStrictEqual({ error: 'forged-pca-header', reason: 'inbound x-pca-* header cannot be removed' });
    }
  });
  it('headers object without forEach: injected names are found by get(); default rewrite cannot clean it and refuses', async () => {
    const m = mint();
    const mkNoEach = (forged: string[]) => ({
      method: 'GET',
      url: 'https://h/x',
      headers: { get: (n: string) => (n.toLowerCase() === 'pca-action' ? m.header : forged.includes(n) ? 'v' : null) },
    });
    let status = 0;
    let drop: readonly string[] = [];
    const w = cloudflareWorker({ ...base(m), next: () => 'NEXT', rewriteRequest: (r: WLike, d) => ((drop = d), r), respond: (_b: string, i) => ((status = i.status), 'resp') });
    expect(await w(mkNoEach(['x-pca-verdict', 'x-pca-grant']))).toBe('NEXT');
    expect([...drop].sort()).toEqual(['x-pca-grant', 'x-pca-verdict']);
    const w2 = cloudflareWorker({ ...base(m), next: () => 'NEXT', respond: (_b: string, i) => ((status = i.status), 'resp') });
    expect(await w2(mkNoEach(['x-pca-verb']))).toBe('resp');
    expect(status).toBe(400);
    expect(await w2(mkNoEach([]))).toBe('NEXT');
  });
  it('without a global Request the default rewrite cannot clean and refuses', async () => {
    const m = mint();
    const saved = (globalThis as { Request?: unknown }).Request;
    let status = 0;
    try {
      (globalThis as { Request?: unknown }).Request = undefined;
      const w = cloudflareWorker({ ...base(m), next: () => 'NEXT', respond: (_b: string, i) => ((status = i.status), 'resp') });
      const r = { method: 'GET', url: 'https://h/x', headers: new Headers({ 'pca-action': m.header, 'x-pca-verb': 'a' }) };
      expect(await w(r)).toBe('resp');
      expect(status).toBe(400);
    } finally {
      (globalThis as { Request?: unknown }).Request = saved;
    }
  });
});
type WLike = { method: string; url: string; headers: Headers | { get(n: string): string | null; forEach?: (cb: (v: string, k: string) => void) => void } };

describe('Lambda authorizers', () => {
  const ARN = 'arn:aws:execute-api:us-east-1:123456789012:abcdef/prod/POST/refunds/ch_1';
  const run = async (event: Record<string, unknown>, extra: Partial<GatewayOptions> = {}) => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    const fn = lambdaAuthorizer(base(m, { checkProof: (c) => ((box.req = c.request), true), ...extra }));
    const res = await fn({ headers: { 'pca-action': m.header }, ...event } as never);
    return { box, res, m };
  };
  it('method/path precedence: requestContext.http, httpMethod/path/rawPath, ARN fallback', async () => {
    let r = await run({ requestContext: { http: { method: 'PATCH', path: '/ctx' } }, httpMethod: 'GET', path: '/p', rawPath: '/raw' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['PATCH', '/raw']);
    r = await run({ httpMethod: 'GET', path: '/p' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/p']);
    r = await run({ httpMethod: 'GET', requestContext: { http: { path: '/ctxpath' } } });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/ctxpath']);
    r = await run({ requestContext: { http: { method: 'PUT' } }, rawPath: '/r' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['PUT', '/r']);
    r = await run({ methodArn: ARN });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['POST', '/refunds/ch_1']);
    r = await run({ routeArn: 'arn:aws:execute-api:us-east-1:123:abcdef/$default/GET /orders' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/orders']);
    r = await run({ methodArn: ARN, httpMethod: 'DELETE' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['DELETE', '/refunds/ch_1']);
    r = await run({ methodArn: ARN, path: '/explicit' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['POST', '/explicit']);
    r = await run({ methodArn: 'arn:aws:execute-api:r:a:id/stage' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['*', '/']);
    r = await run({ methodArn: 'arn:aws:execute-api:r:a:id/stage/GET/x/y' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/x/y']);
    r = await run({});
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['*', '/']);
    r = await run({ httpMethod: 'GET' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/']);
    r = await run({ path: '/only-path' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['*', '/only-path']);
  });
  it('the ARN tail keeps embedded colons', async () => {
    const r = await run({ methodArn: 'arn:aws:execute-api:r:a:id/st:age/GET/a:b' });
    expect([r.box.req?.method, r.box.req?.path]).toEqual(['GET', '/a:b']);
  });
  it('allow and deny policies, principal, resource and context', async () => {
    const ok = await run({ methodArn: ARN, httpMethod: 'POST', path: '/x' });
    expect(ok.res.principalId).toBe(ok.m.ref);
    expect(ok.res.policyDocument).toStrictEqual({ Version: '2012-10-17', Statement: [{ Action: 'execute-api:Invoke', Effect: 'Allow', Resource: ARN }] });
    expect(JSON.parse(ok.res.context.pcaVerdict as string).allow).toBe(true);
    expect(Object.keys(ok.res.context)).toEqual(['pcaVerdict']);
    const route = await run({ routeArn: 'arn:r', httpMethod: 'GET', path: '/x' });
    expect(route.res.policyDocument.Statement[0]?.Resource).toBe('arn:r');
    const star = await run({ httpMethod: 'GET', path: '/x' });
    expect(star.res.policyDocument.Statement[0]?.Resource).toBe('*');
    const both = await run({ methodArn: 'M', routeArn: 'R', httpMethod: 'GET', path: '/x' });
    expect(both.res.policyDocument.Statement[0]?.Resource).toBe('M');
    const anon = await run({ httpMethod: 'GET', path: '/x', headers: {} });
    expect(anon.res.principalId).toBe('anonymous');
    expect(anon.res.policyDocument.Statement[0]?.Effect).toBe('Deny');
    expect(anon.res.context).toStrictEqual({ pcaDenied: 'true', pcaCode: 'no-proof', pcaReason: `no ${PCA_HEADER} header`, pcaStatus: '401' });
    const denied = await run({ httpMethod: 'GET', path: '/x' }, { checkProof: () => false });
    expect(denied.res.principalId).toBe(denied.m.ref);
    expect(denied.res.context.pcaStatus).toBe('403');
  });
  it('allow without a verdict (unmapped route allowed) has an empty context; headers default to {}', async () => {
    const m = mint();
    const fn = lambdaAuthorizer(base(m, { unmatchedRoute: 'allow' }));
    const r = await fn({ httpMethod: 'GET', path: '/x' } as never);
    expect(r.context).toStrictEqual({});
    expect(r.principalId).toBe('anonymous');
    expect(r.policyDocument.Statement[0]?.Effect).toBe('Allow');
  });
  it('simple authorizer', async () => {
    const m = mint();
    const fn = lambdaSimpleAuthorizer(base(m));
    const ok = await fn({ httpMethod: 'GET', path: '/x', headers: { 'pca-action': m.header } } as never);
    expect(ok.isAuthorized).toBe(true);
    expect(Object.keys(ok.context)).toEqual(['pcaVerdict']);
    const no = await fn({ httpMethod: 'GET', path: '/x' } as never);
    expect(no).toStrictEqual({ isAuthorized: false, context: { pcaDenied: 'true', pcaCode: 'no-proof', pcaReason: `no ${PCA_HEADER} header`, pcaStatus: '401' } });
  });
});

describe('remaining boundaries', () => {
  it('enforcement gates are forwarded to the verifier', async () => {
    const m = mint();
    const d = await authorize({ method: 'GET', path: '/x', headers: H(m) }, base(m, { enforce: { freshness: { maxAgeMs: 1 } } }));
    expect(d.verdict?.checks.freshness).toMatch(/^(pass|fail)$/);
  });
  it('worker URL parsing at index zero', async () => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    const w = cloudflareWorker({ ...base(m, { checkProof: (c) => ((box.req = c.request), true) }), next: () => 'n', respond: (b: string) => b });
    const h = new Headers({ 'pca-action': m.header });
    await w({ method: 'GET', url: '://h.example/x', headers: h });
    expect([box.req?.path, box.req?.authority]).toEqual(['/x', 'h.example']);
    await w({ method: 'GET', url: 'https:///x', headers: h });
    expect([box.req?.path, box.req?.authority]).toEqual(['/x', '']);
    await w({ method: 'GET', url: '?q', headers: h });
    expect(box.req?.path).toBe('/');
  });
  it('a requestContext without an http object does not throw', async () => {
    const m = mint();
    const fn = lambdaAuthorizer(base(m, { unmatchedRoute: 'allow' }));
    const r = await fn({ requestContext: {}, httpMethod: 'GET' } as never);
    expect(r.policyDocument.Statement[0]?.Effect).toBe('Allow');
  });
});

describe('query handling (R2-11)', () => {
  it('canonicalQuery: strips one leading ?, drops empty pairs, sorts, joins with &', () => {
    expect(canonicalQuery(undefined)).toBe('');
    expect(canonicalQuery('')).toBe('');
    expect(canonicalQuery('a=1')).toBe('a=1');
    expect(canonicalQuery('?a=1')).toBe('a=1');
    expect(canonicalQuery('??a=1')).toBe('?a=1');
    expect(canonicalQuery('b=2&&a=1&')).toBe('a=1&b=2');
    expect(canonicalQuery('b=%20&a=%2F')).toBe('a=%2F&b=%20');
  });
  const seen = async (cfg: (m: Minted) => GatewayOptions, call: (o: GatewayOptions, m: Minted) => Promise<unknown>) => {
    const m = mint();
    const box: { req?: GatewayRequest } = {};
    await call({ ...cfg(m), checkProof: (c) => ((box.req = c.request), true) }, m);
    return box.req;
  };
  it('Envoy: the query is taken from the target up to the fragment', async () => {
    const q = async (path?: string) => (await seen(base, (o, m) => envoyExtAuthz(o)({ ...(path === undefined ? {} : { path }), headers: { 'pca-action': m.header } })))?.query;
    expect(await q('/p')).toBe('');
    expect(await q('/p?a=1')).toBe('a=1');
    expect(await q('?a=1')).toBe('a=1');
    expect(await q('/p?a=1#frag')).toBe('a=1');
    expect(await q('/p?#frag')).toBe('');
    expect(await q('/p#frag?notquery')).toBe('notquery'); // first ? wins, fragment cut only after it
    expect(await q()).toBe('');
  });
  it('Worker: the query comes from the URL', async () => {
    const q = async (url: string) =>
      (await seen(base, (o, m) => cloudflareWorker({ ...o, next: () => 'n', respond: (b: string) => b })({ method: 'GET', url, headers: new Headers({ 'pca-action': m.header }) })))?.query;
    expect(await q('https://h.example/p?x=1&y=2#f')).toBe('x=1&y=2');
    expect(await q('https://h.example/p')).toBe('');
    expect(await q('https://h.example/p?')).toBe('');
  });
  it('Lambda: rawQueryString wins (even when empty); else multi-value, else single-value; encoded and & joined', async () => {
    const q = async (e: Record<string, unknown>) =>
      (await seen(base, (o, m) => lambdaAuthorizer(o)({ httpMethod: 'GET', path: '/p', headers: { 'pca-action': m.header }, ...e } as never)))?.query;
    expect(await q({ rawQueryString: 'a=1&b=2', queryStringParameters: { z: '9' } })).toBe('a=1&b=2');
    expect(await q({ rawQueryString: '', queryStringParameters: { z: '9' } })).toBe('');
    expect(await q({ rawQueryString: 5 as never, queryStringParameters: { z: '9' } })).toBe('z=9');
    expect(await q({ multiValueQueryStringParameters: { a: ['1', '2'], 'b c': ['x y'] }, queryStringParameters: { z: '9' } })).toBe('a=1&a=2&b%20c=x%20y');
    expect(await q({ multiValueQueryStringParameters: { a: null, b: ['1'] } })).toBe('b=1');
    expect(await q({ queryStringParameters: { a: '1', u: undefined, 'k&': 'v=' } })).toBe('a=1&k%26=v%3D');
    expect(await q({ queryStringParameters: null })).toBe('');
    expect(await q({})).toBe('');
    expect(await q({ queryStringParameters: { only: '1' } })).toBe('only=1');
  });
  it('the proof binds the query: a different query is a request mismatch, an order change is not', async () => {
    const bind = (query: string) => requestBinding({ method: 'GET', path: '/p', query, headers: {} });
    const m = mint(bind('a=1&b=2'));
    const run = (query: string) => authorize({ method: 'GET', path: '/p', query, headers: H(m) }, base(m, { bindRequest: {} }));
    expect((await run('b=2&a=1')).allow).toBe(true);
    expect((await run('a=1&b=3')).code).toBe('request-mismatch');
  });
});
