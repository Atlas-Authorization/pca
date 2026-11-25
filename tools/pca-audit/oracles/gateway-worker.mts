// Oracle: @atlasauth/pca-gateway cloudflareWorker (fetch-style middleware: decide, strip inbound x-pca-*, deny JSON, forged-header 400).
// One corpus for the php and ruby lanes. Runtime-free: the reference runs over a real Fetch Request here; natives model a request as
// {method, url, headers} and next/respond as injected callables. Deterministic: seeded keys (labels only), fixed clock.
// PORTING: workerScenario(spec) -> native cloudflare_worker(opts, next, respond[, rewrite_request]) over spec.events[0] = {method, url, headers, rewrite?: 'default'|'null'};
//   result {forwarded:{method,url,headers(lower-cased names)}} when next ran, else {status, headers, body (parsed JSON)}.
import * as G0 from '@atlasauth/pca-gateway';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const G: any = (G0 as any).default ?? G0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('gateway-worker', 'tools/pca-audit/oracles/gateway-worker.mts', 'TS-reference oracle for the PCA gateway Cloudflare Worker adapter.');
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, name, ref, args);

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'gw_acme';
const VERB = 'stripe.refund';
const ZERO = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1000 };
const prSk = seed('gwworker/principal'), agSk = seed('gwworker/agent');
const pPub = P.b64u(P.publicKeyOf(prSk)), aPub = P.b64u(P.publicKeyOf(agSk));
const SALT = P.b64u(seed('gwworker/salt').slice(0, 16));
const grant = P.mintGrant({ principalSecret: prSk, principalPublic: pPub, holder: aPub, goal: 'refunds', salt: SALT, envelope: { predicates: [{ verb: [VERB, 'stripe.payout'], resource: 'charge:*' }], caveats: [], agent_binding: {}, risk_policy: ZERO } }).grant;
const bindOf = (req: any, bo: any = {}) => G.requestBinding({ headers: {}, ...req }, bo);
function sign(params: any, x: any = {}) {
  const node = { id: 'n1', verb: x.verb ?? VERB, resource: x.resource ?? 'charge:ch_1', params_digest: P.paramsDigest(params), reversibility_class: 'irreversible' };
  const pc = P.buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: x.counter ?? 1, signerSecret: agSk, aud: x.aud ?? AUD, now: x.now ?? NOW });
  return { header: P.pcaHeaders(JSON.stringify(pc))['PCA-Action'], pc };
}
const POST = { method: 'POST', path: '/refunds' };
const P1 = sign(bindOf(POST));
const ROUTES = [{ method: 'POST', path: '/refunds', capability: { verb: VERB } }, { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } }, { method: 'GET', path: '/charges/*', capability: { verb: VERB, resource: 'charge:ch_1' } }];
const req = (h: string | undefined, over: any = {}) => ({ ...POST, headers: h === undefined ? {} : { 'pca-action': h }, ...over });
const tamper = (h: string) => h.slice(0, -4) + (h.endsWith('AAAA') ? 'BBBB' : 'AAAA');

const base = (over: any = {}) => ({ audience: AUD, routes: ROUTES, grants: { [grant.id]: grant }, bindRequest: undefined, replay: 'always', revocation: 'ok', policy: 'sig', skipPlan: true, now: NOW, requests: [], ...over });
const P2 = sign(bindOf({ ...POST, query: 'x=1' }), { counter: 2 });
const P3 = sign(bindOf({ method: 'GET', path: '/charges/ch_1' }), { counter: 3 });
function mask(s: any): any {
  if (typeof s === 'string') return s.replace(/undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*/g, 'undecodable PCA-Action header: <json>');
  if (Array.isArray(s)) return s.map(mask);
  if (s && typeof s === 'object') {
    const out: any = {};
    for (const [k, v] of Object.entries(s)) {
      if ((k === 'x-pca-verdict' || k === 'pcaVerdict') && typeof v === 'string' && v !== '') out[k] = '<verdict>';
      else out[k] = mask(v);
    }
    if (out.header && out.header.key === 'x-pca-verdict' && out.header.value !== '') out.header = { ...out.header, value: '<verdict>' };
    return out;
  }
  return s;
}
function buildOpts(spec: any) {
  const clockNow = spec.now;
  const opts: any = { audience: spec.audience, routes: spec.routes, resolveGrant: (ref: any) => spec.grants[ref] ?? null, now: () => clockNow };
  if (spec.bindRequest === 'off') opts.bindRequest = false; else if (spec.bindRequest !== undefined) opts.bindRequest = spec.bindRequest;
  if (spec.unmatched !== undefined) opts.unmatchedRoute = spec.unmatched;
  if (spec.pathPolicy !== undefined) opts.pathPolicy = spec.pathPolicy;
  if (spec.requireChecks !== undefined) opts.requireChecks = spec.requireChecks;
  if (spec.realm !== undefined) opts.realm = spec.realm;
  if (spec.skipPlan) opts.insecureSkipPlanRootCheck = true;
  if (spec.planRoots !== undefined) opts.authorizedPlanRoots = spec.planRoots;
  const rg: any = { always: { claim: () => true }, false: { claim: () => false }, throws: { claim: () => { throw new Error('store down'); } }, memory: G.memoryReplayGuard(100_000, () => clockNow), 'memory-full': G.memoryReplayGuard(1, () => clockNow) };
  if (spec.replay !== 'none') opts.replayGuard = rg[spec.replay];
  const rv: any = { ok: () => ({ enforced: true, ok: true }), revoked: () => ({ enforced: true, ok: false, reason: 'grant revoked' }), 'revoked-noreason': () => ({ enforced: true, ok: false }), notEnforced: () => ({ enforced: false }), throws: () => { throw new Error('rev down'); } };
  if (spec.revocation !== 'none') opts.hooks = { revocation: rv[spec.revocation] };
  const cp: any = { true: () => true, false: () => false, 'obj-true': () => ({ allow: true }), 'obj-false': () => ({ allow: false }), 'obj-false-reason': () => ({ allow: false, reason: 'over limit' }), throws: () => { throw new Error('policy down'); } };
  if (spec.checkProof) opts.checkProof = cp[spec.checkProof];
  if (spec.policy === 'sig') opts.policy = { mode: 'signature-only' };
  else if (spec.policy === 'bogus') opts.policy = { mode: 'bogus' };
  else if (spec.policy === 'full-missing') opts.policy = { mode: 'full', params: 'body' };
  return opts;
}

// A scenario: spec fields as in the gateway oracle, events[0] a Fetch-style request. rewrite: 'default' (reference default) | 'null' (opt out) | 'custom' (drops the names, tags the request).
function worker(spec: any) {
  const ev = spec.events[0];
  const opts: any = buildOpts(spec);
  const view = (r: Request) => ({ method: r.method, url: r.url, headers: Object.fromEntries([...r.headers.entries()].sort()) });
  opts.next = async (r: Request) => ({ forwarded: view(r) });
  opts.respond = (body: string, init: any) => ({ status: init.status, headers: init.headers, body: JSON.parse(body) });
  if (ev.rewrite === 'null') opts.rewriteRequest = null;
  if (ev.rewrite === 'custom') opts.rewriteRequest = (r: Request, drop: string[]) => { const h = new Headers(r.headers); for (const n of drop) h.delete(n); h.set('x-rewritten', drop.join(',')); return new Request(r, { headers: h }); };
  let w: any;
  try { w = G.cloudflareWorker(opts); } catch (e: any) { return { create: e.message }; }
  return Promise.resolve(w(new Request(ev.url, { method: ev.method, headers: ev.headers }))).then((x: any) => mask(x), (e: any) => ({ threw: e.message }));
}
const ev = (h: Record<string, string>, over: any = {}) => ({ method: 'POST', url: 'https://api.example.com/refunds', headers: h, ...over });
const S = (label: string, events: any[], over: any = {}) => add('workerScenario', label, worker, [base({ ...over, events })]);
const H1 = { 'pca-action': P1.header };
await S('allow', [ev(H1)]);
await S('allow query bound', [ev({ 'pca-action': P2.header }, { url: 'https://api.example.com/refunds?x=1' })]);
await S('allow fragment', [ev(H1, { url: 'https://api.example.com/refunds#frag' })]);
await S('allow extra headers', [ev({ ...H1, accept: 'text/plain', 'x-trace': 'abc' })]);
await S('allow GET route', [ev({ 'pca-action': P3.header }, { method: 'GET', url: 'https://api.example.com/charges/ch_1' })]);
await S('allow root path no slash', [ev(H1, { url: 'https://api.example.com' })], { routes: [{ method: 'POST', path: '/', capability: { verb: VERB } }] });
await S('no proof', [ev({})]);
await S('tampered', [ev({ 'pca-action': tamper(P1.header) })]);
await S('undecodable', [ev({ 'pca-action': '!!!' })]);
await S('unmapped route deny', [ev(H1, { url: 'https://api.example.com/nope' })]);
await S('unmapped route allow', [ev({}, { method: 'DELETE', url: 'https://api.example.com/x' })], { unmatched: 'allow' });
await S('wrong audience', [ev(H1)], { audience: 'other' });
await S('replay false', [ev(H1)], { replay: 'false' });
await S('revoked', [ev(H1)], { revocation: 'revoked' });
await S('realm', [ev({})], { realm: 'my realm' });
await S('forged verdict header stripped', [ev({ ...H1, 'x-pca-verdict': 'forged' })]);
await S('forged all injected', [ev({ ...H1, 'x-pca-verdict': 'a', 'x-pca-verb': 'b', 'x-pca-grant': 'c', 'X-PCA-Other': 'd', accept: '*/*' })]);
await S('forged headers, rewrite opt-out', [ev({ ...H1, 'x-pca-verb': 'b' }, { rewrite: 'null' })]);
await S('forged headers, custom rewrite', [ev({ ...H1, 'x-pca-verb': 'b', 'x-pca-other': 'd' }, { rewrite: 'custom' })]);
await S('no forged headers, rewrite opt-out', [ev(H1, { rewrite: 'null' })]);
await S('denied with forged header', [ev({ 'x-pca-verdict': 'forged' })]);
await S('misconfigured', [ev(H1)], { policy: 'none' });
refWrite(o, 'gateway-worker');
