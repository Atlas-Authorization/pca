// Oracle: @atlasauth/pca-gateway (canonicalQuery, requestBinding, bindParams, ambiguousPathReason, memoryReplayGuard, memoryProvenanceLog, presentedProvenance,
// presentedArtifacts, authorize / createGateway in signature-only mode over real signed proofs, the Envoy HTTP / gRPC ext_authz shapes and the Lambda authorizers).
// Deterministic: seeded keys, fixed clock. Proofs are minted here (principal + agent from seeds) and cross as header values.
// Compared after masking: the verdict objects are not compared (the native verdict lists its own check names), x-pca-verdict / pcaVerdict print "<verdict>", and the
// strict-JSON parser's own message in "undecodable PCA-Action header: <message>" prints "<json>" (the header-level messages are compared).
// Not generated: full-policy mode (it needs an authorizer state store, revocation, the provenance gate and a catalog; the native delegates it to the core authorize),
// the Cloudflare Worker adapter (n-a: runs JavaScript), hooks other than revocation, enforcement gates.
// PORTING (fn(args) -> native entry point, compared by JSON value; a throw requires the native to throw):
//   canonicalQuery(q)                Gateway.canonicalQuery(q)
//   requestBinding(req, opts)        Gateway.requestBinding(GatewayRequest{method,path,query?,authority?,bodySha256?}, BindRequestOptions{authority, body: true | false | null})
//   bindParams(params, binding)      Gateway.bindParams(params, binding)
//   ambiguousPathReason(path)        Gateway.ambiguousPathReason(path)   (null when canonical)
//   replayScenario(spec)             Gateway.memoryReplayGuard(max, clock) then claim ops; {max, clock, ops:[{key, exp, now?}]} -> [true|false|{threw}]
//   provenanceLogScenario(spec)      Gateway.memoryProvenanceLog(max); ops add / seen
//   presentedProvenance(req, kind)   Gateway.presentedProvenance(req, FullPolicy{paramsFromBody: kind==='body', paramsFn}); GatewayRequest.ABSENT -> {undef:true}
//   presentedArtifacts(req, kind)    Gateway.presentedArtifacts(...)
//   authorizeScenario(spec)          Gateway.createGateway(opts) then authorize per request; spec fields documented at the top of the case builder below; {create: <msg>} when it throws
//   envoyScenario / grpcScenario / lambdaScenario / lambdaSimpleScenario(spec)   Gateway.envoyExtAuthz / envoyGrpcExtAuthz / lambdaAuthorizer / lambdaSimpleAuthorizer over spec.events
import * as G0 from '@atlasauth/pca-gateway';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const G: any = (G0 as any).default ?? G0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('gateway', 'tools/pca-audit/oracles/gateway.mts', 'TS-reference oracle for the PCA gateway.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

// ---- pure functions ---------------------------------------------------------------------------------------------------------------------
const QUERIES: (string | undefined)[] = [
  undefined, '', '?', 'a=1', '?a=1', '??a=1', 'b=2&a=1', 'a=1&&b=2&', '&', 'a', 'a=', '=1', 'B=1&b=2', 'a=1&A=2', 'a%20b=1&a+b=2', 'a+b=1&a%20b=2', 'a%2Bb=1&a+b=2', 'q=1;r=2', ';', '%3B=1',
  'a=%', 'a%=1', '%zz=1', '%e9=1', '%c3%a9=1&%C3%A9=2', '%C3%A9=1', '%c0%80=1', '%ed%a0%80=1', '%f0%9f%98%80=1', '%f8%80%80%80%80=1', '%f4%90%80%80=1', '%e0%80%80=1', '%c3=1', '%c3%28=1', '%80=1', '%',
  'z=1&y=2&x=3', 'x=%41&x=2', 'Ab=1&aB=2', 'a=1&b=%zz', 'a=1=2', 'k=v&k2=v2&k3=v3', 'é=1', 'é=1&É=2', 'İ=1&i%CC%87=2', 'a b=1', 'a=1#frag', '+=1&%20=2', 'a%2B=1', 'long=' + 'x'.repeat(500),
];
for (const q of QUERIES) await add('canonicalQuery', String(q).slice(0, 40), G.canonicalQuery, [q]);

const REQS: any[] = [
  { method: 'post', path: '/refunds' }, { method: 'POST', path: '/refunds', query: 'b=2&a=1' }, { method: 'get', path: '/a/b', query: '?x=1', authority: 'API.Example.COM' }, { method: 'PUT', path: '/p', bodySha256: 'ABCDEF01' },
  { method: 'POST', path: '/p', authority: 'Host', bodySha256: 'AbC' }, { method: 'POST', path: '/p', query: 'a=1&a=2' }, { method: 'POST', path: '/p', query: 'q=1;2' }, { method: 'POST', path: '/p' }, { method: 'é', path: '/é' },
];
const BOPTS: any[] = [undefined, {}, { authority: true }, { body: true }, { body: false }, { authority: true, body: true }, { authority: false, body: false }];
for (const r of REQS) for (const b of BOPTS) await add('requestBinding', `${JSON.stringify(r)}/${JSON.stringify(b)}`, (rq: any, op: any) => G.requestBinding({ ...rq, headers: {} }, op ?? undefined), [r, b]);

const PARAMS: any[] = [{}, { a: 1 }, { binding: 1 }, { b: { c: [1, 2] } }];
const BINDS: any[] = [undefined, null, { v: 2, method: 'POST' }, {}];
for (const p of PARAMS) for (const b of BINDS) await add('bindParams', `${JSON.stringify(p)}/${JSON.stringify(b)}`, (x: any, y: any) => G.bindParams(x, y ?? undefined), [p, b]);

const PATHS = [
  '/', '/a/b', '/refunds/ch_1', '/a//b', '//', '/a/./b', '/a/../b', '/.', '/..', '/a/.', '/a/..', '/a\\b', '/a\u0000b', '/a\u001fb', '/a\u007fb', '/a b', '/a;x=1', '/public/..;/admin', '/a%2Fb', '/a%2fb', '/a%5Cb', '/a%5cb',
  '/a%3Bb', '/a%3bb', '/a%00b', '/a%1Fb', '/a%7Fb', '/a%41b', '/a%61b', '/a%30', '/a%2D', '/a%2d', '/a%2E', '/a%5F', '/a%7E', '/a%7e', '/a%20b', '/a%C3%A9', '/a%80', '/a%FF', '/a%', '/a%4', '/a%zz', '/a%%41', '/a%41%', '/%', '/a%2',
  '/é', '/a%7Fb%2F', '/a%20%00', '/ok/%E2%82%AC', '', 'rel/path', '/a/b/', '/a/%2e%2e/b', '/a/%2E', '/a%25b', '/a%25', '/a%2525',
];
for (const p of PATHS) await add('ambiguousPathReason', JSON.stringify(p), (x: string) => G.ambiguousPathReason(x) ?? null, [p]);

// ---- replay guard, provenance log ---------------------------------------------------------------------------------------------------------
function replay(spec: any) {
  let clock = spec.clock ?? 0;
  const g = G.memoryReplayGuard(spec.max, () => clock);
  const out: any[] = [];
  for (const op of spec.ops) {
    if (op.setClock !== undefined) { clock = op.setClock; continue; }
    try { out.push(g.claim(op.key, op.exp, op.now)); } catch (e: any) { out.push({ threw: e.message }); }
  }
  return out;
}
const RS: any[] = [
  { max: 10, clock: 100, ops: [{ key: 'a', exp: 200 }, { key: 'a', exp: 200 }, { key: 'b', exp: 300 }, { key: 'a', exp: 200, now: 201 }, { key: 'a', exp: 400, now: 201 }] },
  { max: 10, clock: 100, ops: [{ key: 'a', exp: 100 }, { key: 'a', exp: 100 }, { key: 'a', exp: 100, now: 101 }, { key: 'a', exp: 100, now: 100 }] },
  { max: 2, clock: 0, ops: [{ key: 'a', exp: 10 }, { key: 'b', exp: 20 }, { key: 'c', exp: 30 }, { setClock: 15 }, { key: 'c', exp: 30 }, { key: 'd', exp: 40 }, { key: 'd', exp: 40 }, { key: 'e', exp: 50, now: 100 }] },
  { max: 1, clock: 0, ops: [{ key: 'a', exp: 10 }, { key: 'a', exp: 10 }, { key: 'b', exp: 10, now: 11 }, { key: 'a', exp: 10, now: 11 }] },
  { max: 0, clock: 0, ops: [{ key: 'a', exp: 10 }] },
  { max: 3, clock: 5, ops: [{ key: 'a', exp: 5 }, { key: 'b', exp: 4 }, { key: 'c', exp: 6 }, { key: 'd', exp: 7 }, { key: 'e', exp: 8 }] },
];
for (const [i, sp] of RS.entries()) await add('replayScenario', `${i}`, replay, [sp]);

function provLog(spec: any) {
  const l = G.memoryProvenanceLog(spec.max);
  const out: any[] = [];
  for (const op of spec.ops) {
    if (op.add) { l.add(op.session, op.o); out.push('added'); } else out.push(l.seen(op.session));
  }
  return out;
}
const OB = (origin: any, source: any) => ({ origin, source });
const PS: any[] = [
  { max: 10, ops: [{ add: 1, session: 's', o: OB('tool', 'x') }, { add: 1, session: 's', o: OB('tool', 'x') }, { add: 1, session: 's', o: OB('tool', 'y') }, { session: 's' }, { session: 't' }] },
  { max: 2, ops: [{ add: 1, session: 'a', o: OB('t', 1) }, { add: 1, session: 'b', o: OB('t', 1) }, { add: 1, session: 'c', o: OB('t', 1) }, { session: 'a' }, { session: 'b' }, { add: 1, session: 'b', o: OB('t', 2) }, { add: 1, session: 'd', o: OB('t', 1) }, { session: 'c' }, { session: 'b' }] },
  { max: 5, ops: [{ add: 1, session: 's', o: { origin: 'o' } }, { add: 1, session: 's', o: { origin: 'o' } }, { add: 1, session: 's', o: { origin: 'o', source: null } }, { add: 1, session: 's', o: { source: 1 } }, { add: 1, session: 's', o: {} }, { add: 1, session: 's', o: { origin: 1, source: 1.0 } }, { add: 1, session: 's', o: { origin: '1', source: 1 } }, { session: 's' }] },
  { max: 0, ops: [{ add: 1, session: 's', o: OB('a', 'b') }, { session: 's' }] },
  { max: 3, ops: [...Array.from({ length: 300 }, (_, i) => ({ add: 1, session: 's', o: OB('tool', `v${i}`) })), { session: 's' }] },
];
for (const [i, sp] of PS.entries()) await add('provenanceLogScenario', `${i}`, provLog, [sp]);

// ---- presented artifacts ------------------------------------------------------------------------------------------------------------------
const hb = (v: any) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
const PR_REQS: any[] = [
  { headers: {} }, { headers: { 'pca-provenance': hb({ receipts: [{ session: 's1' }] }) } }, { headers: { 'PCA-Provenance': hb('null') } }, { headers: { 'pca-provenance': '' } }, { headers: { 'pca-provenance': '!!' } }, { headers: { 'pca-provenance': hb('{bad') } },
  { headers: { 'pca-provenance': [hb({ a: 1 }), hb({ b: 2 })] } }, { headers: { 'pca-provenance': [] } }, { headers: {}, body: '{"pca_provenance":{"x":1}}' }, { headers: {}, body: '{"pca_provenance":null}' }, { headers: {}, body: '{"other":1}' }, { headers: {}, body: '[1]' },
  { headers: {}, body: 'not json' }, { headers: {}, body: '' }, { headers: { 'pca-provenance': hb({ h: 1 }) }, body: '{"pca_provenance":{"x":1}}' }, { headers: { 'pca-provenance': '' }, body: '{"pca_provenance":{"x":1}}' },
  { headers: { 'pca-discharges': hb([1, 2]) } }, { headers: { 'pca-discharges': hb({ a: 1 }) } }, { headers: { 'pca-discharges': '!!' } }, { headers: { 'pca-narrow': hb({ n: 1 }) } }, { headers: { 'pca-narrow': hb('null') } }, { headers: { 'pca-narrow': '%%' } },
  { headers: { 'pca-discharges': hb([1]), 'pca-narrow': hb({ n: 1 }) }, body: '{"pca_discharges":[9],"pca_narrow":{"z":1}}' }, { headers: {}, body: '{"pca_discharges":[9],"pca_narrow":{"z":1}}' }, { headers: {}, body: '{"pca_discharges":"no","pca_narrow":null}' },
  { headers: { 'pca-narrow': hb('null') }, body: '{"pca_narrow":{"z":1}}' }, { headers: { 'pca-discharges': hb({ a: 1 }) }, body: '{"pca_discharges":[9]}' },
];
for (const [i, r] of PR_REQS.entries()) for (const kind of ['body', 'fn']) {
  const pol = (k: string) => (k === 'body' ? { params: 'body' } : { params: () => ({}) });
  await add('presentedProvenance', `${i}/${kind}`, (rq: any, k: string) => { const v = G.presentedProvenance({ method: 'POST', path: '/', ...rq }, pol(k)); return v === undefined ? { undef: true } : v; }, [r, kind]);
  await add('presentedArtifacts', `${i}/${kind}`, (rq: any, k: string) => G.presentedArtifacts({ method: 'POST', path: '/', ...rq }, pol(k)), [r, kind]);
}

// ---- signed proofs -----------------------------------------------------------------------------------------------------------------------
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'gw_acme';
const VERB = 'stripe.refund';
const ZERO = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1000 };
const prSk = seed('refgw/principal'), agSk = seed('refgw/agent');
const pPub = P.b64u(P.publicKeyOf(prSk)), aPub = P.b64u(P.publicKeyOf(agSk));
const SALT = P.b64u(seed('refgw/salt').slice(0, 16));
const grant = P.mintGrant({ principalSecret: prSk, principalPublic: pPub, holder: aPub, goal: 'refunds', salt: SALT, envelope: { predicates: [{ verb: [VERB, 'stripe.payout'], resource: 'charge:*' }], caveats: [], agent_binding: {}, risk_policy: ZERO } }).grant;
const bindOf = (req: any, bo: any = {}) => G.requestBinding({ headers: {}, ...req }, bo);
function sign(params: any, x: any = {}) {
  const node = { id: 'n1', verb: x.verb ?? VERB, resource: x.resource ?? 'charge:ch_1', params_digest: P.paramsDigest(params), reversibility_class: 'irreversible' };
  const pc = P.buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: x.counter ?? 1, signerSecret: agSk, aud: x.aud ?? AUD, now: x.now ?? NOW });
  return { header: P.pcaHeaders(JSON.stringify(pc))['PCA-Action'], pc };
}
const POST = { method: 'POST', path: '/refunds' };
const P1 = sign(bindOf(POST));
const P2 = sign(bindOf({ ...POST, query: 'x=1' }), { counter: 2 });
const P3 = sign({ amount: 1 }, { counter: 3 });
const P4 = sign(bindOf(POST), { aud: 'other_gw', counter: 4 });
const P5 = sign(bindOf(POST), { verb: 'stripe.payout', counter: 5 });
const P6 = sign(bindOf(POST), { resource: 'charge:ch_2', counter: 6 });
const P7 = sign(bindOf(POST), { now: NOW - 4 * 3600_000, counter: 7 });
const P8 = sign(bindOf(POST, { authority: true }, ), { counter: 8 });
const P8b = sign(bindOf({ ...POST, authority: 'api.example.com' }, { authority: true }), { counter: 8 });
const P9 = sign(bindOf({ ...POST, bodySha256: 'ab'.repeat(32) }, { body: true }), { counter: 9 });
const P10 = sign(bindOf({ method: 'POST', path: '/other' }), { counter: 10 });
const P11 = sign(bindOf({ method: 'GET', path: '/refunds' }), { counter: 11 });
const ROUTES = [{ method: 'POST', path: '/refunds', capability: { verb: VERB } }, { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } }, { method: 'GET', path: '/charges/*', capability: { verb: VERB, resource: 'charge:ch_1' } }];
const req = (h: string | undefined, over: any = {}) => ({ ...POST, headers: h === undefined ? {} : { 'pca-action': h }, ...over });
const tamper = (h: string) => h.slice(0, -4) + (h.endsWith('AAAA') ? 'BBBB' : 'AAAA');

const base = (over: any = {}) => ({ audience: AUD, routes: ROUTES, grants: { [grant.id]: grant }, bindRequest: undefined, replay: 'always', revocation: 'ok', policy: 'sig', skipPlan: true, now: NOW, requests: [], ...over });
const CASES: [string, any][] = [];
const C = (label: string, over: any, requests: any[]) => CASES.push([label, base({ ...over, requests })]);
C('allow bound', {}, [req(P1.header)]);
C('allow bound twice memory', { replay: 'memory' }, [req(P1.header), req(P1.header), req(P2.header, { query: 'x=1' })]);
C('allow query bound', {}, [req(P2.header, { query: 'x=1' }), req(P2.header, { query: 'x=2' }), req(P2.header)]);
C('query ambiguous', {}, [req(P1.header, { query: 'a=1&a=2' }), req(P1.header, { query: 'a=1;b=2' }), req(P1.header, { query: 'a%zz=1' })]);
C('unbound proof', {}, [req(P3.header)]);
C('unbound proof, binding off', { bindRequest: 'off' }, [req(P3.header)]);
C('other path proof', {}, [req(P10.header), req(P11.header)]);
C('wrong audience', {}, [req(P4.header)]);
C('wrong verb', {}, [req(P5.header)]);
C('expired', {}, [req(P7.header)]);
C('resource bound route', {}, [{ method: 'GET', path: '/charges/ch_1', headers: { 'pca-action': P11.header } }, { method: 'GET', path: '/charges/ch_1', headers: { 'pca-action': P6.header } }]);
C('authority binding', { bindRequest: { authority: true } }, [req(P8b.header, { authority: 'api.example.com' }), req(P8b.header, { authority: 'API.EXAMPLE.COM' }), req(P8b.header), req(P8b.header, { authority: 'other' }), req(P1.header, { authority: 'x' })]);
C('body binding', { bindRequest: { body: true } }, [req(P9.header, { bodySha256: 'ab'.repeat(32) }), req(P9.header, { bodySha256: 'AB'.repeat(32) }), req(P9.header), req(P9.header, { bodySha256: 'cd'.repeat(32) })]);
C('body binding implicit', {}, [req(P9.header, { bodySha256: 'ab'.repeat(32) }), req(P1.header, { bodySha256: 'ab'.repeat(32) })]);
C('body binding off', { bindRequest: { body: false } }, [req(P1.header, { bodySha256: 'ab'.repeat(32) })]);
C('no proof', {}, [req(undefined), { ...POST, headers: { 'pca-action': '' } }, { ...POST, headers: { 'PCA-ACTION': '' } }, { ...POST, headers: { 'pca-action': [] } }]);
C('header forms', {}, [{ ...POST, headers: { 'PCA-Action': P1.header } }, { ...POST, headers: { 'pca-action': [P1.header, 'junk'] } }, { ...POST, headers: { 'x-other': 'y', 'Pca-Action': P1.header } }]);
C('undecodable header', {}, [req('!!!'), req('abc='), req('A'), req(Buffer.from([0xff, 0xfe]).toString('base64url')), req(hb('[]')), req(hb('"x"')), req(hb('null')), req(hb('{bad')), req(hb('{"a":1,"a":2}')), req(hb('{"a":1e5}')), req(hb('x'.repeat(10))), req(P1.header + '=')]);
C('oversize', {}, [req(hb('{"a":"' + 'x'.repeat(600_000) + '"}'))]);
C('tampered proof', {}, [req(tamper(P1.header))]);
C('no wire fields', {}, [req(hb({})), req(hb({ grant_ref: 'x' })), req(hb({ grant_ref: grant.id }))]);
C('unknown grant', { grants: {} }, [req(P1.header)]);
C('unmapped route deny', {}, [{ method: 'DELETE', path: '/refunds', headers: { 'pca-action': P1.header } }, { method: 'POST', path: '/nope', headers: {} }]);
C('unmapped route allow', { unmatched: 'allow' }, [{ method: 'DELETE', path: '/x', headers: {} }, { method: 'DELETE', path: '/x', headers: { 'pca-action': 'evil' } }]);
C('unmapped route require-proof', { unmatched: 'require-proof' }, [{ method: 'POST', path: '/other', headers: { 'pca-action': P10.header } }, { method: 'POST', path: '/other', headers: {} }]);
C('unmatched bogus', { unmatched: 'bogus' }, [{ method: 'POST', path: '/other', headers: { 'pca-action': P10.header } }]);
C('invalid path', {}, [req(P1.header, { path: '/refunds/../x' }), req(P1.header, { path: '/a//b' }), req(P1.header, { path: '/a%2Fb' })]);
C('invalid path, policy off', { pathPolicy: 'off' }, [req(P1.header, { path: '/refunds/../x' })]);
C('route methods', { routes: [{ method: 'ANY', path: '/refunds', capability: { verb: VERB } }] }, [req(P1.header), { method: 'get', path: '/refunds', headers: { 'pca-action': P11.header } }]);
C('route no method', { routes: [{ path: '/refunds', capability: { verb: VERB } }] }, [req(P1.header)]);
C('route star', { routes: [{ method: '*', path: '*', capability: { verb: VERB } }] }, [req(P1.header), req(P10.header, { path: '/other' })]);
C('route prefix', { routes: [{ path: '/re*', capability: { verb: VERB } }, { path: '/x/*', capability: { verb: 'z' } }] }, [req(P1.header), { method: 'POST', path: '/x', headers: {} }, { method: 'POST', path: '/xy', headers: {} }]);
C('replay false', { replay: 'false' }, [req(P1.header)]);
C('replay throws', { replay: 'throws' }, [req(P1.header)]);
C('replay full', { replay: 'memory-full' }, [req(P1.header), req(P2.header, { query: 'x=1' })]);
C('revoked', { revocation: 'revoked' }, [req(P1.header)]);
C('revoked no reason', { revocation: 'revoked-noreason' }, [req(P1.header)]);
C('revocation not enforced', { revocation: 'notEnforced' }, [req(P1.header)]);
C('revocation not enforced waived', { revocation: 'notEnforced', requireChecks: [] }, [req(P1.header)]);
C('revocation throws', { revocation: 'throws' }, [req(P1.header)]);
C('revocation none waived', { revocation: 'none', requireChecks: [] }, [req(P1.header)]);
C('revocation none default', { revocation: 'none' }, [req(P1.header)]);
C('require other checks', { requireChecks: ['revocation', 'leaf_signature', 'taint_gate', 'attestation', 'nonexistent'] }, [req(P1.header)]);
C('require audience', { requireChecks: ['audience', 'wire'] }, [req(P1.header)]);
for (const cp of ['true', 'false', 'obj-true', 'obj-false', 'obj-false-reason', 'throws']) C(`checkProof ${cp}`, { checkProof: cp }, [req(P1.header)]);
C('plan roots listed', { skipPlan: false, planRoots: [P1.pc.plan.root] }, [req(P1.header), req(P2.header, { query: 'x=1' })]);
C('plan roots empty', { skipPlan: false, planRoots: [] }, [req(P1.header)]);
C('plan roots none', { skipPlan: false }, [req(P1.header)]);
C('plan roots win over skip', { skipPlan: true, planRoots: [] }, [req(P1.header)]);
C('realm', { realm: 'my realm' }, [req(undefined)]);
C('now late', { now: NOW + 10_000_000 }, [req(P1.header)]);
C('no policy', { policy: 'none' }, [req(P1.header)]);
C('bogus policy', { policy: 'bogus' }, [req(P1.header)]);
C('full missing parts', { policy: 'full-missing' }, [req(P1.header)]);
C('sig only without replay guard', { replay: 'none' }, [req(P1.header)]);
C('sig only without replay guard waived', { replay: 'none', revocation: 'ok' }, [req(P1.header)]);
const caseKey = (s: any) => JSON.stringify([s.policy, s.replay, s.revocation]);
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
const proj = (d: any) => mask({ allow: d.allow, status: d.status, code: d.code, reason: d.reason, headers: d.headers, matched: d.matched, grant: d.pcactn?.grant_ref, verdictAllow: d.verdict?.allow });
async function authorizeScenario(spec: any) {
  let gw: any;
  try { gw = G.createGateway(buildOpts(spec)); } catch (e: any) { return { create: e.message }; }
  const out: any[] = [];
  for (const r of spec.requests) { try { out.push(proj(await gw(r))); } catch (e: any) { out.push({ threw: e.message }); } }
  return out;
}
for (const [label, sp] of CASES) await add('authorizeScenario', label, authorizeScenario, [sp]);

// ---- adapters ------------------------------------------------------------------------------------------------------------------------
const aspec = (events: any[], over: any = {}) => base({ ...over, events });
const H1 = { 'pca-action': P1.header };
const ENVOY: any[] = [
  { method: 'POST', path: '/refunds', headers: H1 }, { method: 'POST', path: '/refunds?x=1', headers: { 'pca-action': P2.header } }, { method: 'POST', path: '/refunds#frag', headers: H1 }, { headers: { ':method': 'POST', ':path': '/refunds', 'pca-action': P1.header } },
  { method: 'POST', headers: H1 }, { path: '/refunds', headers: H1 }, { method: 'POST', path: '', headers: H1 }, { method: 'POST', path: '?x=1', headers: H1 }, {}, { headers: {} }, { method: 'POST', path: '/refunds', authority: 'a.example', headers: H1 },
  { method: 'POST', path: '/refunds', headers: { ':authority': 'b.example', 'pca-action': P1.header } }, { method: 'POST', path: '/refunds', body: '{"a":1}', headers: H1 }, { method: 'POST', path: '/refunds', headers: { 'pca-action': '!!' } },
  { method: 'POST', path: '/nope', headers: H1 }, { method: 'POST', path: '/x//y', headers: H1 }, { method: 'POST', path: '/refunds?a=1&a=2', headers: H1 },
];
for (const [i, ev] of ENVOY.entries()) await add('envoyScenario', `${i}`, async (s: any) => mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])), [aspec([ev])]);
await add('envoyScenario', 'unmapped allow', async (s: any) => mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])), [aspec([{ method: 'DELETE', path: '/x', headers: { 'x-pca-verdict': 'forged' } }], { unmatched: 'allow' })]);
await add('envoyScenario', 'revoked', async (s: any) => mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])), [aspec([ENVOY[0]], { revocation: 'revoked' })]);
await add('envoyScenario', 'replay', async (s: any) => mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])), [aspec([ENVOY[0]], { replay: 'false' })]);
await add('envoyScenario', 'replay unavailable', async (s: any) => mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])), [aspec([ENVOY[0]], { replay: 'throws' })]);
await add('envoyScenario', 'misconfigured', async (s: any) => { try { return mask(await G.envoyExtAuthz(buildOpts(s))(s.events[0])); } catch (e: any) { return { create: e.message }; } }, [aspec([ENVOY[0]], { policy: 'none' })]);

const GRPC = (http: any) => ({ attributes: { request: { http } } });
const GR: any[] = [
  GRPC({ method: 'POST', path: '/refunds', headers: H1 }), GRPC({ method: 'POST', path: '/refunds?x=1', host: 'h.example', headers: { 'pca-action': P2.header } }), GRPC({ headers: { ':method': 'POST', ':path': '/refunds', ':authority': 'h', 'pca-action': P1.header } }),
  GRPC({ method: 'POST', path: '/refunds', body: '{}', headers: {} }), GRPC({ method: 'POST', path: '/refunds', headers: { 'pca-action': '!!' } }), {}, { attributes: {} }, { attributes: { request: {} } }, GRPC({ method: 'POST', path: '/nope', headers: H1 }),
  GRPC({ method: 'POST', path: '/refunds' }),
];
for (const [i, ev] of GR.entries()) await add('grpcScenario', `${i}`, async (s: any) => mask(await G.envoyGrpcExtAuthz(buildOpts(s))(s.events[0])), [aspec([ev])]);
await add('grpcScenario', 'unmapped allow', async (s: any) => mask(await G.envoyGrpcExtAuthz(buildOpts(s))(s.events[0])), [aspec([GRPC({ method: 'DELETE', path: '/x', headers: {} })], { unmatched: 'allow' })]);
await add('grpcScenario', 'unavailable', async (s: any) => mask(await G.envoyGrpcExtAuthz(buildOpts(s))(s.events[0])), [aspec([GR[0]], { replay: 'throws' })]);
await add('grpcScenario', 'replayed', async (s: any) => mask(await G.envoyGrpcExtAuthz(buildOpts(s))(s.events[0])), [aspec([GR[0]], { replay: 'false' })]);

const ARN = 'arn:aws:execute-api:us-east-1:123456789012:abcdef/prod/POST/refunds';
const LAM: any[] = [
  { methodArn: ARN, httpMethod: 'POST', path: '/refunds', headers: H1 }, { methodArn: ARN, headers: H1 }, { routeArn: 'arn:aws:execute-api:us-east-1:123:abc/$default/POST/refunds', requestContext: { http: { method: 'POST', path: '/refunds' } }, rawPath: '/refunds', rawQueryString: '', headers: H1 },
  { routeArn: ARN, requestContext: { http: { method: 'POST' } }, headers: H1 }, { httpMethod: 'POST', rawPath: '/refunds', headers: H1 }, { httpMethod: 'POST', path: '/refunds', rawQueryString: 'x=1', headers: { 'pca-action': P2.header } },
  { httpMethod: 'POST', path: '/refunds', queryStringParameters: { x: '1' }, headers: { 'pca-action': P2.header } }, { httpMethod: 'POST', path: '/refunds', multiValueQueryStringParameters: { x: ['1'] }, queryStringParameters: { x: 'zzz' }, headers: { 'pca-action': P2.header } },
  { httpMethod: 'POST', path: '/refunds', queryStringParameters: { 'a b': 'é&=', c: null }, headers: H1 }, { httpMethod: 'POST', path: '/refunds', multiValueQueryStringParameters: { k: ['1', '2'], 'é': ['x y'] }, headers: H1 },
  { httpMethod: 'POST', path: '/refunds', queryStringParameters: null, multiValueQueryStringParameters: null, headers: H1 }, { httpMethod: 'POST', path: '/refunds', multiValueQueryStringParameters: {}, queryStringParameters: { x: '1' }, headers: H1 },
  { methodArn: 'arn:aws:execute-api:r:a:id/stage', headers: H1 }, { methodArn: 'short', headers: H1 }, { methodArn: 'a:b:c:d:e:f/s/GET path/x/y', headers: H1 }, { methodArn: 'a:b:c:d:e:f:g/s/POST/refunds/deep', headers: H1 }, { headers: H1 }, {}, { httpMethod: 'POST', path: '/refunds' },
  { httpMethod: 'POST', path: '/refunds', headers: { 'pca-action': '!!' } }, { httpMethod: 'POST', path: '/nope', headers: H1, methodArn: ARN }, { httpMethod: 'POST', path: '/refunds', rawQueryString: 'a=1&a=2', headers: H1 },
];
for (const [i, ev] of LAM.entries()) {
  await add('lambdaScenario', `${i}`, async (s: any) => mask(await G.lambdaAuthorizer(buildOpts(s))(s.events[0])), [aspec([ev])]);
  await add('lambdaSimpleScenario', `${i}`, async (s: any) => mask(await G.lambdaSimpleAuthorizer(buildOpts(s))(s.events[0])), [aspec([ev])]);
}
await add('lambdaScenario', 'revoked', async (s: any) => mask(await G.lambdaAuthorizer(buildOpts(s))(s.events[0])), [aspec([LAM[0]], { revocation: 'revoked' })]);
await add('lambdaScenario', 'lone surrogate query', async (s: any) => { try { return mask(await G.lambdaAuthorizer(buildOpts(s))(s.events[0])); } catch (e: any) { return { threw: e.message }; } }, [aspec([{ httpMethod: 'POST', path: '/refunds', queryStringParameters: { k: '\ud800' }, headers: H1 }])]);

refWrite(o, 'gateway');
