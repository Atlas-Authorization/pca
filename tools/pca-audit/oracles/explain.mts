// Oracle: @atlasauth/pca-explain (self-explaining PCA decisions): cleanText, explainVerification, explainDecision, explainChain and
// the toText renderers. Deterministic: seeded Ed25519 keys (signatures are deterministic), fixed clocks, no randomness.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, a throw requires the native to refuse; the explanation
// class instances are compared as their JSON (own members; undefined members absent)):
//   cleanText(text)                          Explain.cleanText(text)                      exact string (a non-string argument is String()-ed)
//   explainVerification(pcactn, result, opts)  Explain.explainVerification(...)           opts = {now?}; always passed as an object
//   explainVerificationText(...)             Explain.verificationToText(Explain.explainVerification(...))
//   explainDecision(pcactn, decision, opts)  Explain.explainDecision(...)                 opts = {envelope?, context?: {action?, caveat?, chain?}}
//   explainDecisionText(...)                 Explain.decisionToText(Explain.explainDecision(...))
//   explainChain(chain, opts)                Explain.explainChain(chain, opts)            opts = {verify?, expectedRootIssuer?}; always an object
//   explainChainText(...)                    Explain.chainToText(Explain.explainChain(...))
//   consts                                   VERIFY_CHECK_ORDER
// The native caveat evaluation maps the context {now, blastRadius, reversibilityClass, delegationDepth, recentActionTimes} onto the
// evaluator's own context keys.
import * as Ex from '@atlasauth/pca-explain';
import * as Core from '@atlasauth/pca';
import { Oracle, refWrite, rng, seed, reparse, paths, getAt, setAt, DEL } from './lib.mjs';

const X: any = (Ex as any).default ?? Ex;
const C: any = (Core as any).default ?? Core;
const o = new Oracle('explain', 'tools/pca-audit/oracles/explain.mts', 'TS-reference oracle for the PCA explainer.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const run = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);
const NOW = 1_800_000_000_000;
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const key = (l: string) => { const sk = seed('explain/' + l); return { sk, pk: b64(C.publicKeyOf(sk)) }; };
const K = { p: key('principal'), h: key('holder'), s: key('sub'), t: key('third') };

// ---- chains -------------------------------------------------------------------------------------------------------------------------
const budget = (l: number) => C.budgetAllocCaveat(l);
const env = (): any => ({ type: 'envelope', goal_commit: 'g', predicates: [{ verb: 'a', resource: '*' }, { verb: 'b', resource: '*' }], caveats: [{ type: 'expires', at: NOW }], agent_binding: {}, risk_policy: {} });
const root0 = C.mintRoot({ principalSecret: K.p.sk, principalPublic: K.p.pk, holder: K.h.pk, caveats: [] });
const root1 = C.mintRoot({ principalSecret: K.p.sk, principalPublic: K.p.pk, holder: K.h.pk, caveats: [{ type: 'expires', at: NOW + 60000 }, { type: 'max_blast_radius', max: 0.5 }] });
const root2 = C.mintRoot({ principalSecret: K.p.sk, principalPublic: K.p.pk, holder: K.h.pk, caveats: [budget(100), { type: 'rate', max: 3, per_secs: 60 }] });
const rootE = C.mintRoot({ principalSecret: K.p.sk, principalPublic: K.p.pk, holder: K.h.pk, caveats: [env()] });
const d1 = C.delegate(root1, K.s.pk, [budget(50)], K.h.sk);
const d2 = C.delegate(d1, K.t.pk, [{ type: 'delegation_depth', max: 2 }, budget(20), { type: 'x'.repeat(3), a: { b: [1, 2] }, c: 1.23456789, d: 'v' }], K.s.sk);
const d3 = C.delegate(root2, K.s.pk, [budget(100), budget(40), { type: 'reversibility_max', class: 'rate_limited' }], K.h.sk);
const dE = C.delegate(rootE, K.s.pk, [{ type: 'expires', at: NOW }], K.h.sk);
const dRebind = C.delegate(root0, K.s.pk, [], K.h.sk);
const CHAINS: any[][] = [[root0], [root1], [root1, d1], [root1, d1, d2], [root2], [root2, d3], [rootE], [rootE, dE], [root0, dRebind]];
const tamper = (ch: any[], i: number, f: (c: any) => void) => { const c = reparse(ch); f(c[i]); return c; };
const BADCHAINS: any[] = [
  tamper([root1, d1], 1, (c) => { c.sig = 'A'.repeat(c.sig.length); }),
  tamper([root1, d1], 0, (c) => { c.sig = 'A'.repeat(c.sig.length); }),
  tamper([root1, d1], 1, (c) => { c.caveats = []; }),
  tamper([root1, d1, d2], 2, (c) => { c.caveats = c.caveats.slice(0, 2); }),
  tamper([root1, d1], 1, (c) => { c.caveats[2].limit = 5000; }),
  tamper([root1, d1, d2], 2, (c) => { c.caveats[3].limit = 900; }),
  tamper([root1, d1], 1, (c) => { c.parent = root0.id; }),
  tamper([root1, d1], 1, (c) => { c.issuer = K.t.pk; }),
  [root1, d3], [d1], [d1, root1], [], [null], [root1, null], [root1, 5, d1], 'x', null, {}, [{}], [{ caveats: 'x' }],
  [root1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1, d1],
  [{ caveats: [{ type: 'budget_alloc', limit: -1 }, { type: 'budget_alloc', limit: 'x' }, null, 5, { type: 5 }, [], { '0': 1, type: 'k', b: 1 }] }],
];
const allChains = [...CHAINS, ...BADCHAINS];

// ---- explainChain -----------------------------------------------------------------------------------------------------------------------
for (const [i, ch] of allChains.entries()) {
  for (const [j, opts] of [{}, { verify: true }, { verify: false }, { verify: true, expectedRootIssuer: K.p.pk }, { verify: true, expectedRootIssuer: K.t.pk }, { verify: 'yes' }].entries()) {
    await run('explainChain', `c${i}/o${j}`, X.explainChain, [ch, opts]);
    if (j < 4) await run('explainChainText', `c${i}/o${j}`, (c: any, op: any) => X.explainChain(c, op).toText(), [ch, opts]);
  }
}
{
  // sampled structural edits of a delegated chain
  const seedC = reparse([root1, d1, d2]);
  const ps = paths(seedC, 4);
  const stride = Math.max(1, Math.ceil(ps.length / 40));
  const HOST = [null, 0, -0, 1.5, '', 'x', [], {}, true, 1e21];
  for (const [i, p] of ps.entries()) {
    if (i % stride !== 0 || p.length === 0) continue;
    const at = '/' + p.join('/');
    for (const [j, v] of [['del', DEL], ...HOST.map((h, k) => [`h${k}`, h])] as any[]) {
      const c = setAt(seedC, p, () => v);
      await run('explainChain', `${at} ${j}`, X.explainChain, [c, { verify: j === 'del' || j === 'h0' }]);
    }
  }
}

// ---- cleanText ----------------------------------------------------------------------------------------------------------------------------
{
  const r = rng(77);
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const T = [
    jwt, `a ${jwt} b`, 'eyJ12345.12345.', 'eyJ1234.12345.abc', 'xeyJ12345.12345.abc', '_eyJ12345.12345.abc', 'éeyJ12345.12345.abc',
    'Bearer abcdef', 'bearer abcdef', 'BEARER abc', 'Bearer abcdefghij1234', 'Basic dXNlcjpwYXNz', 'Token t0k3nvalue', 'xBearer abcdef', 'Bearer\u00a0abcdef', 'Bearer\u2003abcdef', 'Bearer\u200babcdef', 'Bearer \tabcdef==',
    'https://user:pass@host/x', 'HTTP://u:p@h', 'ftp://a:b@c:80/d', 'https://host/x@y', 'https://user@host', 'git+ssh://u:p@h', '1http://u:p@h', 'x://:@y', 'https://u:p\u00a0q@h',
    'token=abc', 'Token: abc', 'password = "p w d"', "secret='s e'", 'api_key=abc123', 'api-key: z', 'apikey=q', 'x-api-key=1', 'key=v', 'monkey=v', 'KEY=V', 'signature=abc,def', 'sig:  abc; next', 'credential="a"', 'authorization: Bearer abc', 'auth=ok&x=1',
    'token"=abc', 'token\u00a0=\u00a0abc', 'token=', 'token=""', 'passwd=a b', 'pwd:\n x', 'éToken=abc', '1token=abc', 'a_token=abc', 'secret_key=abc',
    'a'.repeat(39), 'a'.repeat(40), 'a'.repeat(41), 'a-'.repeat(25), 'é' + 'a'.repeat(45), 'a'.repeat(39) + 'é' + 'a'.repeat(45), 'x '.repeat(10) + 'a'.repeat(60),
    '', ' ', 'plain text with no secrets', 'x'.repeat(400), 'x'.repeat(401), 'x'.repeat(399) + 'é', 'x'.repeat(399) + '😀', 'x'.repeat(500), 'é'.repeat(450), '😀'.repeat(250), '\ud800'.repeat(5),
    'line1\nline2 token=abc\nline3', 'tab\ttoken=abc', 'k=v token=abc',
  ];
  for (let i = 0; i < 120; i++) {
    const parts = ['token=', 'Bearer ', 'secret: ', 'https://u:p@', 'eyJ' + 'a'.repeat(r.int(3, 9)) + '.' + 'b'.repeat(r.int(3, 9)) + '.', 'a'.repeat(r.int(30, 50)), ' ', '\u00a0', 'é', '_', '-', '"', "'", '&', ';', 'x', 'KEY=', 'Auth=', 'sig:'];
    T.push(Array.from({ length: r.int(1, 9) }, () => r.pick(parts)).join(''));
  }
  for (const [i, t] of T.entries()) await run('cleanText', `t${i}`, X.cleanText, [t]);
  for (const v of [null, 5, true, 1.5, -0, [], ['a', 'token=b'], {}, { a: 1 }]) await run('cleanText', `nonstring/${JSON.stringify(v)}`, X.cleanText, [v]);
}

// ---- explainVerification ----------------------------------------------------------------------------------------------------------------------
const pc = (over: any = {}): any => ({
  ver: 2, aud: 'ins_test', iat: NOW, exp: NOW + 30_000, counter: 7, grant_ref: root1.id, cap_chain: [root1, d1],
  action: { verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible', params_digest: 'pd' }, plan: { root: 'R'.repeat(43), node_id: 'n0' }, ...over,
});
const ALL = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
const passAll = () => Object.fromEntries(ALL.map((k) => [k, 'pass']));
const res = (checks: any, extra: any = {}) => ({ allow: false, checks, ...extra });
const RESULTS: any[] = [
  { allow: true, checks: passAll() },
  { allow: true, checks: { ...passAll(), replay: 'pass', taint_gate: 'not-enforced', attestation: 'unsupported' } },
  { allow: true, checks: { ...passAll(), validity: 'fail' } },
  { allow: true }, { allow: true, checks: [] }, { allow: 'true', checks: passAll() }, { allow: 1, checks: passAll() }, { allow: false, checks: passAll() }, { checks: passAll() },
  { allow: false, checks: {}, reason: 'weird' }, { allow: false, checks: {} }, { allow: false }, { allow: false, reason: 5 },
  ...ALL.map((k) => res({ ...passAll(), [k]: 'fail' }, { reason: `${k}: custom tail for ${k}` })),
  ...ALL.map((k) => res({ ...passAll(), [k]: 'fail' })),
  ...ALL.map((k) => res({ ...passAll(), [k]: 'fail' }, { reason: `${k}: ` })),
  ...ALL.map((k) => res({ ...passAll(), [k]: 'fail' }, { reason: `other: ${k}` })),
  res({ ...passAll(), wire: 'fail', version: 'fail', leaf_signature: 'fail' }),
  res({ wire: 'pass', version: 'fail' }), res({ replay: 'fail' }), res({ plan_root_authorized: 'fail', malformed: 'fail' }, { reason: 'malformed: token=abc123' }),
  res({ counter: 'fail' }), res({ counter_format: 'fail', counter: 'fail' }), res({ taint_gate: 'fail', attestation: 'fail', threshold: 'fail', revocation: 'fail', zk_compliance: 'fail', bond: 'fail' }),
  res({ wire: 'weird', version: 5, audience: null, validity: true, cap_chain: 'skipped' }), res({ wire: 'not-enforced', version: 'unsupported' }),
  res({ ...passAll(), audience: 'fail' }, { reason: 'audience: aud Bearer abcdefghij does not match' }),
  res({ ...passAll(), version: 'fail' }, { reason: 'version: ' + 'x'.repeat(500) }),
  res(['pass', 'fail', 'weird']), res('abc'), res(5), res(null), res(null, { allow: true }),
];
const PCS: any[] = [
  pc(), pc({ ver: 1 }), pc({ ver: undefined }), pc({ aud: undefined }), pc({ aud: 5 }), pc({ aud: 'a"b' }), pc({ counter: -1 }), pc({ counter: 1.5 }), pc({ counter: undefined }),
  pc({ grant_ref: 'G'.repeat(43) }), pc({ grant_ref: '' }), pc({ grant_ref: 5 }), pc({ plan: undefined }), pc({ plan: { node_id: 3 } }), pc({ action: undefined }),
  pc({ cap_chain: [] }), pc({ cap_chain: undefined }), pc({ cap_chain: 'x' }), pc({ cap_chain: [root1, d1, d2] }), pc({ cap_chain: [d1, root1] }), pc({ cap_chain: [null] }), pc({ cap_chain: tamper([root1, d1], 1, (c) => { c.sig = 'A'.repeat(c.sig.length); }) }),
  pc({ cap_chain: tamper([root1, d1], 1, (c) => { c.caveats[2].limit = 5000; }) }), pc({ cap_chain: tamper([root1, d1], 1, (c) => { c.caveats = []; }) }), pc({ cap_chain: [root1, d3] }),
  pc({ alg: 'ml-dsa-65' }), pc({ alg: null }), pc({ exp: NOW }), pc({ exp: NOW - 1 }), pc({ exp: NOW + 7_200_000 }), pc({ exp: undefined }), pc({ iat: undefined }), pc({ exp: 'x', iat: 'y' }), pc({ exp: '2', iat: '10' }),
  {}, [], null, 5, 'x', pc({ plan: { root: 'short', node_id: 'n' } }), pc({ plan: { root: '', node_id: '' } }),
];
for (const [i, p] of PCS.entries()) {
  for (const [j, r] of RESULTS.entries()) {
    if ((i > 8 && j % 13 !== i % 13) || (i <= 8 && j % 3 !== i % 3 && j > 12)) continue; // thin the cross product
    await run('explainVerification', `p${i}/r${j}`, X.explainVerification, [p, r, {}]);
    if ((i + j) % 3 === 0) await run('explainVerificationText', `p${i}/r${j}`, (a: any, b: any, c: any) => X.explainVerification(a, b, c).toText(), [p, r, {}]);
  }
}
for (const nowV of [0, NOW - 100_000, NOW, NOW + 29_999, NOW + 30_001, NOW + 60_000, NOW - 59_999, NOW - 60_001, NOW + 1e9, -0, 1.5, null, 'x', true]) {
  for (const p of [pc({ cap_chain: [] }), pc({ exp: NOW, cap_chain: [] }), pc({ exp: NOW - 5, cap_chain: [] }), pc({ exp: NOW + 7_200_000, cap_chain: [] }), pc({ iat: NOW + 500_000, exp: NOW + 530_000, cap_chain: [] }), pc({ exp: undefined, cap_chain: [] })]) {
    await run('explainVerification', `now/${String(nowV)}/${p.exp}`, X.explainVerification, [p, res({ ...passAll(), validity: 'fail' }), { now: nowV }]);
    await run('explainVerification', `nowtail/${String(nowV)}/${p.exp}`, X.explainVerification, [p, res({ ...passAll(), validity: 'fail' }, { reason: 'validity: from the tail' }), { now: nowV }]);
  }
}
for (const [i, opts] of [{}, { now: undefined }, { foo: 1 }, null, 5].entries()) await run('explainVerification', `opts${i}`, X.explainVerification, [pc(), res({ ...passAll(), validity: 'fail' }), opts]);

// ---- explainDecision --------------------------------------------------------------------------------------------------------------------------
const RP = { weights: { alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1 }, theta1: 0.3, theta2: 0.7, kappa: 2, lambda: 0.1, rho: 0.5, bMax: 10 };
const ENVC: any[] = [{ type: 'expires', at: NOW + 60_000 }, { type: 'max_blast_radius', max: 0.5 }, { type: 'rate', max: 3, per_secs: 60 }, { type: 'reversibility_max', class: 'rate_limited' }, { type: 'delegation_depth', max: 2 }, { type: 'not_before', at: NOW - 1000 }];
const envelope = (over: any = {}): any => ({
  goal_commit: 'g', predicates: [{ verb: 'stripe.refund', resource: 'charge:*', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }] }, { verb: ['a', 'b'], resource: '*' }],
  caveats: ENVC, agent_binding: {}, risk_policy: RP, ...over,
});
const aCtx = (amount = 100, verb = 'stripe.refund', resource = 'charge:ch_1', rc: any = 'reversible'): any => ({ action: { verb, resource, params: { amount }, ...(rc === undefined ? {} : { reversibility_class: rc }) } });
const cCtx = (over: any = {}): any => ({ now: NOW, blastRadius: 0.2, reversibilityClass: 'reversible', delegationDepth: 1, recentActionTimes: [NOW - 5000], ...over });
const capsRoot = { ...root1, caveats: [{ type: 'expires', at: NOW + 60_000 }] };
const leafCaps = { ...root1, caveats: [{ type: 'expires', at: NOW + 60_000 }, { type: 'max_blast_radius', max: 0.1 }, { type: 'delegation_depth', max: 0 }, { type: 'zzz', q: [1] }] };
const dec = (over: any = {}): any => ({ admit: true, needStepUp: false, releaseGuardianShare: true, r: 0.12, requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: true }, budget: { B: 5, tau: 1000, asOf: 1000 }, reasons: [], ...over });
const DECS: any[] = [
  dec(), dec({ r: 0.123456789 }), dec({ r: 0.5, requiredThreshold: { t: 2, proof: 'guardian', optimisticAllowed: false } }), dec({ r: 0.9, requiredThreshold: { t: 3, proof: 'human', optimisticAllowed: false } }),
  dec({ admit: false, needStepUp: true, r: 0.5, requiredThreshold: { t: 2, proof: 'guardian', optimisticAllowed: false } }),
  dec({ admit: false, needStepUp: true, r: 0.9, requiredThreshold: { t: 3, proof: 'human', optimisticAllowed: false }, reasons: ['budget depleted: B=0.1 < cost 1.8'] }),
  dec({ admit: false, needStepUp: true, requiredThreshold: { t: 3, proof: 'human', optimisticAllowed: false }, reasons: ['budget depleted'] }),
  dec({ admit: false, releaseGuardianShare: false, reasons: ['action not permitted by predicate', 'caveat(s) not satisfied: expires, rate'] }),
  dec({ admit: false, releaseGuardianShare: false, reasons: ['caveat(s) not satisfied: max_blast_radius,delegation_depth, ,zzz'] }),
  dec({ admit: false, releaseGuardianShare: false, reasons: [] }), dec({ admit: false, releaseGuardianShare: false, reasons: ['nothing relevant'] }),
  dec({ admit: false, releaseGuardianShare: true, reasons: ['caveat(s) not satisfied: expires'] }),
  dec({ admit: 'yes' }), dec({ admit: 1, releaseGuardianShare: 'true' }), dec({ releaseGuardianShare: undefined }), dec({ reasons: undefined }), dec({ reasons: 'x' }), dec({ reasons: [1] }), dec({ reasons: ['token=abc123 not permitted'] }),
  dec({ budget: undefined }), dec({ r: undefined }), dec({ r: 'x' }), dec({ r: null }), dec({ r: 2 }), dec({ r: -1 }), dec({ requiredThreshold: { t: 4, proof: 'x', optimisticAllowed: 'maybe' } }), dec({ requiredThreshold: {} }),
  dec({ requiredThreshold: null }), dec({ requiredThreshold: 'x' }), dec({ requiredThreshold: [] }), null, 'x', 5, [], {}, dec({ needStepUp: undefined }),
];
const CONTEXTS: any[] = [
  {}, { envelope: envelope() }, { envelope: envelope(), context: {} },
  { envelope: envelope(), context: { action: aCtx() } }, { envelope: envelope(), context: { action: aCtx(), caveat: cCtx() } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx(), chain: [capsRoot] } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx(), chain: [capsRoot, leafCaps] } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ now: NOW + 100_000 }), chain: [capsRoot, leafCaps] } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ blastRadius: 0.9 }) } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ reversibilityClass: 'irreversible' }) } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ delegationDepth: 5 }) } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ recentActionTimes: [NOW - 1, NOW - 2, NOW - 3] }) } },
  { envelope: envelope(), context: { action: aCtx(), caveat: cCtx({ recentActionTimes: undefined }) } },
  { envelope: envelope(), context: { action: aCtx(900), caveat: cCtx() } },
  { envelope: envelope(), context: { action: aCtx(100, 'other.verb'), caveat: cCtx() } },
  { envelope: envelope(), context: { action: aCtx(100, 'a', 'x'), caveat: cCtx() } },
  { envelope: envelope(), context: { action: aCtx(100, 'stripe.refund', 'nope'), caveat: cCtx() } },
  { envelope: envelope(), context: { action: aCtx(100, 'stripe.refund', 'charge:1', undefined), caveat: cCtx() } },
  { envelope: envelope({ predicates: [] }), context: { action: aCtx(), caveat: cCtx() } },
  { envelope: envelope({ caveats: [] }), context: { action: aCtx(), caveat: cCtx() } },
  { envelope: envelope({ caveats: [{ type: 'max_spend', usd: 50 }] }), context: { action: aCtx(40), caveat: cCtx() } },
  { envelope: envelope({ caveats: [{ type: 'max_spend', usd: 50 }, { type: 'zzz', deep: { a: [1, { b: 2 }] }, n: 1.23456789 }] }), context: { action: aCtx(99), caveat: cCtx() } },
  { envelope: envelope({ risk_policy: { ...RP, theta1: 0.1, theta2: 0.12 } }), context: { action: aCtx(), caveat: cCtx() } },
  { envelope: envelope({ risk_policy: { ...RP, kappa: 0 } }) }, { envelope: envelope({ risk_policy: { ...RP, kappa: 'x' } }) }, { envelope: envelope({ risk_policy: { ...RP, kappa: 0.123456 } }) },
  { envelope: envelope({ risk_policy: undefined }) }, { envelope: envelope({ risk_policy: { kappa: 1 } }) }, { envelope: envelope({ predicates: undefined }), context: { action: aCtx() } },
  { envelope: envelope({ caveats: undefined }) }, { envelope: envelope({ caveats: 'x' }) },
  { context: { action: aCtx(), caveat: cCtx(), chain: [capsRoot, leafCaps] } },
  { envelope: envelope(), context: { chain: [capsRoot, leafCaps] } }, { envelope: envelope(), context: { chain: [{ id: 'x' }] } }, { envelope: envelope(), context: { chain: [{ id: 'x', caveats: [] }, { caveats: [{ type: 'expires', at: 1 }] }] } },
  { envelope: envelope(), context: { chain: [] } },
];
const PCS_DEC = pc({ cap_chain: [] });
for (const [i, d] of DECS.entries()) {
  for (const [j, op] of CONTEXTS.entries()) {
    if (i > 7 && j % 9 !== i % 9) continue;
    await run('explainDecision', `d${i}/c${j}`, X.explainDecision, [PCS_DEC, d, op]);
    if ((i + j) % 3 === 0) await run('explainDecisionText', `d${i}/c${j}`, (a: any, b: any, c: any) => X.explainDecision(a, b, c).toText(), [PCS_DEC, d, op]);
  }
}
o.add('consts', 'all', [], { VERIFY_CHECK_ORDER: X.VERIFY_CHECK_ORDER, MAX_TEXT: 400 });
{ const sz: any = {}; for (const c of (o as any).cases) sz[c.fn] = (sz[c.fn] ?? 0) + JSON.stringify(c).length; console.log(JSON.stringify(sz)); }
refWrite(o, 'explain');
