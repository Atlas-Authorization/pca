// Oracle: @atlasauth/pca-gnap (GNAP RFC 9635 bridge: access rights <-> predicates, grant request -> capability chain, action authorization,
// bound tokens, jwsd detached-JWS proofs, continuation / step-up, interaction modes). Deterministic (Ed25519 is). Writes out/ref-gnap.json.gz.
// Args are the TS argument lists as JSON. Secrets are the 32-byte seed as base64url text (a string wherever TS takes a Uint8Array).
// Compare by JSON value; a throw only requires the native to refuse (the message is not part of the contract), except InteractionError,
// whose stable `code` must match.
// PORTING (fn -> native entry point, comparison rule)
//   gnapActionResource(type, loc)             string concat "gnap:<type>:<loc>"                          exact
//   normalizeAccess(items) / accessToPredicates(a) / accessContains(g, r) / accessWithin(G, r) / clampAccess(G, req)   same names           JSON equality
//   grantedAccessOf(chain) / holderJwk(holder)                                                           JSON equality
//   resolveHolder(req[, override])            second arg absent -> no override (an explicit null is an override and is refused)     exact string | throw
//   grantRequestToCapability(req, opts)       opts.issuerSecret is the seed; opts.salt is always set for a root grant (else random)   JSON equality of
//                                             {grant, chain, holder, grantedAccess, droppedAccess, provenance}
//   authorizeGnapAction(chain, action, opts)  {allowed, reason?} exact reasons (chain / predicate reasons come from the core verifiers)
//   encodeBoundToken(chain)                   base64url(JSON.stringify(chain)): member order of the input is the output
//   capabilityToGrantResponse(chain, opts)    JSON equality;  verifyGnapToken(value, opts)  {ok, ...} exact reasons
//   gnapContentDigest(body)                   {"$bytes": ..} body -> raw bytes; gnapContentDigestAbsent() -> the digest of no content (empty bytes)
//   signGnapRequest(args)                     args.key = {secretKey, publicKey} as base64url; args.body {"$bytes"} -> bytes; JSON equality of the result
//   verifyGnapRequest(args)                   -> {result, seen}: seen = the [proofId, expiresSec] pairs the replay store was called with. args.seenProofMode:
//                                             none | fresh (returns false) | replayed (true) | throws | undefined (returns nothing: replayed) | no replayCheck
//                                             (args.replayCheck absent and no store: throws). A bad-json detail is cut to "bad-json" in the reason.
//   gnapRequestRequiresStepUp(req, opts) / beginGnapContinuation(args) / gnapStepUpShare(body, role, seed, signerSet, t) /
//   completeGnapContinuation(args)            args.agentLeafSecret and cosignSecrets[].secret are seeds; JSON equality
//   constants()                               {GNAP_GRANT_CAVEAT, GNAP_ACCESS_CAVEAT, MAX_DETACHED_JWS_CHARS, START_MODES, FINISH_METHODS, HASH_METHODS: [names]}
//   AGENT_GNAP_PROFILE()                      the profile object
//   callbackUriOk(uri) / validateInteractRequest(r) / interactionHash(a) / verifyInteractionHash(received, a) / accessToNeeds(access) / acceptFinish(cb, ctx)
//                                             same names in the native Interaction class; throws: InteractionError code must match
//   newUserCode(len)                          only the refusals (len outside 6..12) are recorded (the output is random)
//   interactionScenario(s)                    {opts, steps}: runs the AS state machine; every random value (id, user code, ref, AS nonce, hash) is replaced by
//                                             a token in the trace (see the runner in the test). Compare the trace by JSON equality.
import * as G0 from '@atlasauth/pca-gnap';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, rng, seed, variants } from './lib.mjs';

const M: any = (G0 as any).default ?? G0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('gnap', 'tools/pca-audit/oracles/gnap.mts', 'TS-reference oracle for the GNAP bridge (access rights, grant requests, chains, jwsd proofs, step-up, interaction).');

const B = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const D = (l: string) => P.b64u(seed(`ref-gnap/${l}`));
const PUB = (sk: string) => P.b64u(P.publicKeyOf(B(sk)));
const T0 = 1_800_000_000_000;
const SK = { principal: D('principal'), a1: D('agent1'), a2: D('agent2'), a3: D('agent3'), g: D('guardian'), pr: D('principal-device') };
const PK: Record<string, string> = Object.fromEntries(Object.entries(SK).map(([k, v]) => [k, PUB(v)]));
const unbytes = (x: any) => (x !== null && typeof x === 'object' && !Array.isArray(x) && Object.keys(x).length === 1 && typeof x.$bytes === 'string' ? B(x.$bytes) : x);
const run = (fn: string, name: string, ref: any, args: any[]) => o.run(fn, name, ref, args);

// ---- constants -------------------------------------------------------------------------------------------------------------------
await run('constants', 'all', () => ({ GNAP_GRANT_CAVEAT: M.GNAP_GRANT_CAVEAT, GNAP_ACCESS_CAVEAT: M.GNAP_ACCESS_CAVEAT, MAX_DETACHED_JWS_CHARS: M.MAX_DETACHED_JWS_CHARS,
  START_MODES: [...M.START_MODES], FINISH_METHODS: [...M.FINISH_METHODS], HASH_METHODS: Object.keys(M.HASH_METHODS) }), []);
await run('AGENT_GNAP_PROFILE', 'all', () => M.AGENT_GNAP_PROFILE, []);

// ---- access rights ---------------------------------------------------------------------------------------------------------------
for (const [t, l] of [['files', 'https://x/a'], ['', ''], ['a:b', 'c:d'], ['db', '*'], ['é', '\u2603']]) await run('gnapActionResource', `${t}|${l}`, M.gnapActionResource, [t, l]);

const RAW: any[] = [
  'files', '', { type: 'files' }, { type: '' }, { type: 5 }, { type: 'files', actions: ['read', 'write'], locations: ['https://x/a'], datatypes: ['doc'], identifier: 'id1', privileges: ['p'] },
  { type: 'files', actions: [], locations: [], datatypes: [], privileges: [] }, { type: 'files', actions: ['read', 1, null, 'write'] }, { type: 'files', actions: 'read' },
  { type: 'files', locations: ['*', 7] }, { type: 'files', identifier: '' }, { type: 'files', identifier: 5 }, { type: 'files', extra: 1, actions: ['a'] },
  null, 7, true, [], ['files'], {}, { type: 'x', datatypes: ['a', 'b'] }, { type: 'x', privileges: ['a'] },
];
await run('normalizeAccess', 'empty', M.normalizeAccess, [[]]);
await run('normalizeAccess', 'not-array-string', M.normalizeAccess, ['files']);
await run('normalizeAccess', 'not-array-obj', M.normalizeAccess, [{ type: 'files' }]);
await run('normalizeAccess', 'not-array-null', M.normalizeAccess, [null]);
for (const [i, r] of RAW.entries()) await run('normalizeAccess', `one${i}`, M.normalizeAccess, [[r]]);
await run('normalizeAccess', 'many', M.normalizeAccess, [[RAW[0], RAW[2], RAW[5], RAW[9]]]);
await run('normalizeAccess', 'many-with-bad', M.normalizeAccess, [[RAW[0], RAW[4], RAW[5]]]);

const AC: any[] = [
  { type: 'files' }, { type: 'files', actions: ['read'] }, { type: 'files', actions: ['read', 'write'], locations: ['https://x/a'] },
  { type: 'files', actions: ['read'], locations: ['https://x/*'] }, { type: 'files', locations: ['*'] }, { type: 'files', datatypes: ['a', 'b'] },
  { type: 'files', identifier: 'id1' }, { type: 'files', identifier: '' },
  { type: 'db', actions: ['read'], locations: ['s3://b/k*'], datatypes: ['x'], identifier: 'q', privileges: ['p'] }, { type: 'files', actions: ['*'] },
  { type: 'files', actions: ['read'], locations: ['https://x/a/b', 'https://y/'], datatypes: ['a'] }, { type: 'files', locations: ['https://x/a/b'] },
  { type: 'files', actions: ['read'], locations: ['*'], identifier: 'id2' }, { type: 'files', locations: ['a*'] }, { type: 'files', locations: ['ab'] },
];
for (const [i, a] of AC.entries()) await run('accessToPredicates', `a${i}`, M.accessToPredicates, [a]);
for (const [i, g] of AC.entries()) for (const [j, r] of AC.entries()) await run('accessContains', `g${i}r${j}`, M.accessContains, [g, r]);
for (const [i, r] of AC.entries()) {
  await run('accessWithin', `empty r${i}`, M.accessWithin, [[], r]);
  await run('accessWithin', `two r${i}`, M.accessWithin, [[AC[2], AC[3]], r]);
  await run('accessWithin', `any r${i}`, M.accessWithin, [[AC[0], AC[8]], r]);
}
await run('clampAccess', 'none', M.clampAccess, [[], AC]);
await run('clampAccess', 'all', M.clampAccess, [[AC[0], AC[8]], AC]);
await run('clampAccess', 'narrow', M.clampAccess, [[AC[3], AC[8]], AC]);
await run('clampAccess', 'issuer-wild', M.clampAccess, [[AC[4]], AC]);
await run('clampAccess', 'no-request', M.clampAccess, [AC, []]);

// ---- holders ---------------------------------------------------------------------------------------------------------------------
const jwk = (x: string) => ({ kty: 'OKP', crv: 'Ed25519', x });
const reqOf = (access: any[], over: any = {}) => ({ access_token: { access }, client: { key: { proof: 'jwsd', jwk: jwk(PK.a1) } }, ...over });
const HR: any[] = [
  reqOf([]), reqOf([], { client: PK.a1 }), reqOf([], { client: { key: PK.a1 } }), reqOf([], { client: { key: { proof: 'httpsig', jwk: jwk(PK.a1) } } }),
  reqOf([], { client: { key: { proof: 'mtls' } } }), reqOf([], { client: { key: { jwk: jwk(PK.a1) } } }), reqOf([], { client: { key: { proof: { method: 'jwsd' }, jwk: jwk(PK.a1) } } }),
  reqOf([], { client: { key: { proof: { method: 'httpsig' }, jwk: jwk(PK.a1) } } }), reqOf([], { client: { key: { proof: { method: 5 } } } }), reqOf([], { client: { key: { proof: 5 } } }),
  reqOf([], { client: { key: { proof: 'jwsd' } } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: { kty: 'RSA', crv: 'Ed25519', x: PK.a1 } } } }),
  reqOf([], { client: { key: { proof: 'jwsd', jwk: { kty: 'OKP', crv: 'X25519', x: PK.a1 } } } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: jwk('short') } } }),
  reqOf([], { client: { key: { proof: 'jwsd', jwk: jwk(PK.a1 + 'A') } } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: jwk(PK.a1.slice(0, -1) + 'B') } } }),
  reqOf([], { client: { key: { proof: 'jwsd', jwk: jwk(5) } } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: 'x' } } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: null } } }),
  reqOf([], { client: [] }), reqOf([], { client: null }), reqOf([], { client: {} }), reqOf([], { client: { key: [] } }), reqOf([], { client: { key: { proof: 'jwsd', jwk: [jwk(PK.a1)] } } }),
  { access_token: { access: [] } }, null, 5, 'x', [],
];
for (const [i, r] of HR.entries()) {
  await run('resolveHolder', `r${i}`, M.resolveHolder, [r]);
  for (const [j, h] of [PK.a2, 'short', '', null, 5, PK.a2 + '=', PK.a2.slice(0, -1) + 'B'].entries()) await run('resolveHolder', `r${i}o${j}`, M.resolveHolder, [r, h]);
}
for (const h of [PK.a1, '', 'x', 'é']) await run('holderJwk', h || 'empty', M.holderJwk, [h]);

// ---- grant request -> capability -------------------------------------------------------------------------------------------------
const FILES = { type: 'files', actions: ['read', 'write'], locations: ['https://files.example/*'], datatypes: ['doc', 'img'] };
const DB = { type: 'db', actions: ['read'], locations: ['db://main/users'] };
const mintOpts = (over: any = {}) => ({ issuerSecret: SK.principal, issuerPublic: PK.principal, now: T0, salt: 'c2FsdC1nbmFw', ...over });
const dec = (opts: any) => (opts && typeof opts.issuerSecret === 'string' ? { ...opts, issuerSecret: B(opts.issuerSecret) } : opts);
const g2c = (req: any, opts: any) => M.grantRequestToCapability(req, dec(opts));
const G2C = (name: string, req: any, opts: any) => run('grantRequestToCapability', name, g2c, [req, opts]);

const REQ_ROOT = reqOf([FILES, DB], { interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://c.example/cb', nonce: 'nonce-12345678' } } });
await G2C('root', REQ_ROOT, mintOpts());
await G2C('root-no-interact', reqOf([FILES, DB]), mintOpts());
await G2C('root-interacted', reqOf([FILES, DB]), mintOpts({ interacted: true }));
await G2C('root-goal', reqOf([FILES]), mintOpts({ goal: 'plan the trip' }));
await G2C('root-agent-binding', reqOf([FILES]), mintOpts({ agentBinding: { min_measurement: '' } }));
await G2C('root-risk', reqOf([FILES]), mintOpts({ riskPolicy: P.DEFAULT_RISK_POLICY }));
await G2C('root-bad-risk', reqOf([FILES]), mintOpts({ riskPolicy: { theta1: 2 } }));
await G2C('root-holder-override', reqOf([FILES]), mintOpts({ holder: PK.a2 }));
await G2C('root-holder-override-bad', reqOf([FILES]), mintOpts({ holder: 'nope' }));
await G2C('root-now-fraction', reqOf([FILES]), mintOpts({ now: T0 + 0.7 }));
await G2C('root-other-salt', reqOf([FILES]), mintOpts({ salt: 'b3RoZXI' }));
await G2C('root-string-access', reqOf(['files', FILES]), mintOpts());
await G2C('root-empty-access', reqOf([]), mintOpts());
await G2C('root-bad-access-item', reqOf([FILES, { type: '' }]), mintOpts());
await G2C('root-access-not-array', { ...reqOf([]), access_token: { access: 'files' } }, mintOpts());
await G2C('root-no-access-token', { client: reqOf([]).client }, mintOpts());
await G2C('root-httpsig', reqOf([FILES], { client: { key: { proof: 'httpsig', jwk: jwk(PK.a1) } } }), mintOpts());
await G2C('root-no-secret', reqOf([FILES]), { issuerPublic: PK.principal, now: T0, salt: 'c2FsdA' });
await G2C('root-short-secret', reqOf([FILES]), mintOpts({ issuerSecret: P.b64u(new Uint8Array(31)) }));
await G2C('root-no-holder-key', reqOf([FILES], { client: { key: { proof: 'jwsd' } } }), mintOpts());
await G2C('root-parent-null', reqOf([FILES]), mintOpts({ parent: null }));
await G2C('root-parent-false', reqOf([FILES]), mintOpts({ parent: false, interacted: 'yes' }));
for (const [n, v] of variants(REQ_ROOT, { hostile: [null, '', 'x', 0, 1.5, [], {}, true], maxPaths: 40 })) await G2C('variant ' + n, v, mintOpts());

const ROOT = g2c(reqOf([FILES, DB]), mintOpts());
const ROOT_CHAIN = ROOT.chain;
const delOpts = (parent: any, chain: any, secret: string, over: any = {}) => ({ issuerSecret: secret, parent, issuerChain: chain, now: T0 + 1000, ...over });
const REQ_A2 = (access: any[]) => reqOf(access, { client: { key: { proof: 'jwsd', jwk: jwk(PK.a2) } } });
const REQ_A3 = (access: any[]) => reqOf(access, { client: { key: { proof: 'jwsd', jwk: jwk(PK.a3) } } });
const H1ACC = [{ type: 'files', actions: ['read'], locations: ['https://files.example/a/*'], datatypes: ['doc'] }, { type: 'db', actions: ['read', 'write'], locations: ['db://main/users'] }];
await G2C('del-narrow', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
await G2C('del-default-chain', REQ_A2(H1ACC), delOpts(ROOT.grant, undefined, SK.a1));
await G2C('del-noclamp', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1, { clampToIssuer: false }));
await G2C('del-clamp-true', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1, { clampToIssuer: true }));
await G2C('del-clamp-null', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1, { clampToIssuer: null }));
await G2C('del-all-dropped', REQ_A2([{ type: 'mail', actions: ['send'], locations: ['*'] }]), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
await G2C('del-wide', REQ_A2([{ type: 'files' }]), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
await G2C('del-interact', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
await G2C('del-holder-override', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1, { holder: PK.a3 }));
await G2C('del-wrong-signer', REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a3));
await G2C('del-no-secret', REQ_A2(H1ACC), { parent: ROOT.grant, issuerChain: ROOT_CHAIN, now: T0 });
await G2C('del-bad-access', REQ_A2([7]), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
const H1 = g2c(REQ_A2(H1ACC), delOpts(ROOT.grant, ROOT_CHAIN, SK.a1));
const H2ACC = [{ type: 'files', actions: ['read'], locations: ['https://files.example/a/b/*'], datatypes: ['doc'] }, { type: 'db', actions: ['read'], locations: ['db://main/users'] }, { type: 'files', actions: ['write'], locations: ['https://files.example/a/b/*'] }];
await G2C('del2', REQ_A3(H2ACC), delOpts(H1.grant, H1.chain, SK.a2, { now: T0 + 2000 }));
await G2C('del2-default-chain', REQ_A3(H2ACC), delOpts(H1.grant, undefined, SK.a2, { now: T0 + 2000 }));
await G2C('del2-noclamp', REQ_A3(H2ACC), delOpts(H1.grant, H1.chain, SK.a2, { clampToIssuer: false, now: T0 + 2000 }));
const H2 = g2c(REQ_A3(H2ACC), delOpts(H1.grant, H1.chain, SK.a2, { now: T0 + 2000 }));
await G2C('del-parent-not-object', REQ_A2(H1ACC), delOpts('x', ROOT_CHAIN, SK.a1));
const CHAINS: Record<string, any[]> = { root: ROOT_CHAIN, h1: H1.chain, h2: H2.chain };

// ---- granted access of a chain ---------------------------------------------------------------------------------------------------
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const mutate = (chain: any[], f: (c: any[]) => void) => { const c = clone(chain); f(c); return c; };
const lastCav = (c: any[]) => c[c.length - 1].caveats;
const TAMPER: [string, (c: any[]) => void][] = [
  ['sig flipped', (c) => { c[c.length - 1].sig = c[c.length - 1].sig.slice(0, -2) + 'AA'; }],
  ['root sig flipped', (c) => { c[0].sig = c[0].sig.slice(0, -2) + 'AA'; }],
  ['body_digest', (c) => { c[c.length - 1].body_digest = c[0].body_digest; }],
  ['holder swapped', (c) => { c[c.length - 1].holder = PK.a3; }],
  ['caveats emptied', (c) => { c[c.length - 1].caveats = []; }],
  ['caveats not array', (c) => { c[c.length - 1].caveats = 'x'; }],
  ['first caveat removed', (c) => { c[0].caveats.shift(); }],
  ['access caveat widened', (c) => { const cv = lastCav(c).find((x: any) => x.type === 'gnap_access'); if (cv) cv.access = [{ type: 'files' }]; else c[0].caveats[0].predicates = [{ verb: '*', resource: '*' }]; }],
  ['access caveat malformed', (c) => { const cv = lastCav(c).find((x: any) => x.type === 'gnap_access'); if (cv) cv.access = [7, { type: '' }, { type: 'files', actions: ['read'] }]; else c[0].caveats[0].granted_access = 7; }],
  ['access caveat missing', (c) => { const cv = lastCav(c).find((x: any) => x.type === 'gnap_access'); if (cv) delete cv.access; else delete c[0].caveats[0].granted_access; }],
  ['grant caveat client_id removed', (c) => { const e = c[0].caveats[0]; const g = e.caveats.find((x: any) => x.type === 'gnap_grant'); if (g) delete g.client_id; }],
  ['grant caveat request_digest num', (c) => { const e = c[0].caveats[0]; const g = e.caveats.find((x: any) => x.type === 'gnap_grant'); if (g) g.request_digest = 5; }],
  ['extra access caveat appended', (c) => { lastCav(c).push({ type: 'gnap_access', access: [{ type: 'files', actions: ['read'], locations: ['https://files.example/z'] }] }); }],
  ['hop dropped', (c) => { if (c.length > 1) c.splice(1, 1); }],
  ['hop duplicated', (c) => { c.push(clone(c[c.length - 1])); }],
  ['reversed', (c) => { c.reverse(); }],
  ['root parent set', (c) => { c[0].parent = 'x'; }],
  ['alg unknown', (c) => { c[0].alg = 'rot13'; }],
  ['alg number', (c) => { c[0].alg = 5; }],
  ['id removed', (c) => { delete c[0].id; }],
  ['non-object hop', (c) => { c.push(5); }],
  ['null hop', (c) => { c.push(null); }],
];
for (const [k, ch] of Object.entries(CHAINS)) await run('grantedAccessOf', k, M.grantedAccessOf, [ch]);
for (const [i, v] of [[], null, 'x', {}, 5, [null], [5], [{}], [{ caveats: 'x' }], [{ caveats: [null, 5, { type: 'gnap_access', access: [{ type: 'q' }] }] }]].entries()) await run('grantedAccessOf', `junk${i}`, M.grantedAccessOf, [v]);
for (const [k, ch] of Object.entries(CHAINS)) for (const [n, f] of TAMPER) await run('grantedAccessOf', `${k} ${n}`, M.grantedAccessOf, [mutate(ch, f)]);

// ---- action authorization --------------------------------------------------------------------------------------------------------
const R = (p: string) => `gnap:files:https://files.example/${p}`;
const ACTIONS: any[] = [
  { verb: 'read', resource: R('a/x'), params: { datatype: 'doc' } }, { verb: 'read', resource: R('a/x'), params: { datatype: 'img' } },
  { verb: 'write', resource: R('a/x'), params: { datatype: 'doc' } }, { verb: 'read', resource: R('b/x'), params: { datatype: 'doc' } },
  { verb: 'read', resource: R('a/b/c'), params: { datatype: 'doc' } }, { verb: 'write', resource: R('a/b/c') }, { verb: 'read', resource: R('a/x') },
  { verb: 'read', resource: 'gnap:db:db://main/users' }, { verb: 'write', resource: 'gnap:db:db://main/users' }, { verb: 'read', resource: 'gnap:db:db://main/other' },
  { verb: 'send', resource: 'gnap:mail:*' }, { verb: 'read', resource: R('a/x'), params: { datatype: 'doc' }, reversibility_class: 'reversible' },
  { verb: '', resource: '' }, { verb: 5, resource: null }, { verb: 'read', resource: R('a/x'), params: null },
];
for (const [k, ch] of Object.entries(CHAINS)) {
  for (const [i, a] of ACTIONS.entries()) {
    await run('authorizeGnapAction', `${k} a${i}`, M.authorizeGnapAction, [ch, a]);
    await run('authorizeGnapAction', `${k} a${i} issuer-ok`, M.authorizeGnapAction, [ch, a, { expectedRootIssuer: PK.principal }]);
  }
  await run('authorizeGnapAction', `${k} issuer-wrong`, M.authorizeGnapAction, [ch, ACTIONS[0], { expectedRootIssuer: PK.a1 }]);
  await run('authorizeGnapAction', `${k} issuer-null`, M.authorizeGnapAction, [ch, ACTIONS[0], { expectedRootIssuer: null }]);
  await run('authorizeGnapAction', `${k} pqpins`, M.authorizeGnapAction, [ch, ACTIONS[0], { pqPins: { [PK.principal]: 'x' } }]);
}
for (const [n, f] of TAMPER) for (const k of ['root', 'h2']) for (const i of [0, 3, 7]) await run('authorizeGnapAction', `${k} ${n} a${i}`, M.authorizeGnapAction, [mutate(CHAINS[k], f), ACTIONS[i]]);
for (const [i, v] of [[], null, 'x', {}, 5].entries()) await run('authorizeGnapAction', `junk${i}`, M.authorizeGnapAction, [v, ACTIONS[0]]);
// a chain whose root has no envelope (a bare capability)
{
  const holder = PK.a1;
  const bare = P.mintRoot({ principalSecret: B(SK.principal), principalPublic: PK.principal, holder, caveats: [] });
  await run('authorizeGnapAction', 'no envelope', M.authorizeGnapAction, [[bare], ACTIONS[0]]);
  await run('grantedAccessOf', 'no envelope', M.grantedAccessOf, [[bare]]);
}

// ---- bound tokens ----------------------------------------------------------------------------------------------------------------
for (const [k, ch] of Object.entries(CHAINS)) await run('encodeBoundToken', k, M.encodeBoundToken, [ch]);
await run('encodeBoundToken', 'empty', M.encodeBoundToken, [[]]);
await run('encodeBoundToken', 'strings', M.encodeBoundToken, [[{ a: 'q"\\\n\u0001\u007f\u2028\ud800é', b: [1.5, -1, 0, true, null], c: {} }]]);
await run('encodeBoundToken', 'order', M.encodeBoundToken, [[{ z: 1, a: 2, m: { y: 1, b: 2 } }]]);
for (const [k, ch] of Object.entries(CHAINS)) {
  await run('capabilityToGrantResponse', k, M.capabilityToGrantResponse, [ch]);
  await run('capabilityToGrantResponse', `${k} bearer`, M.capabilityToGrantResponse, [ch, { bearer: true }]);
  await run('capabilityToGrantResponse', `${k} bearer-false`, M.capabilityToGrantResponse, [ch, { bearer: false }]);
  await run('capabilityToGrantResponse', `${k} all`, M.capabilityToGrantResponse, [ch, { expiresIn: 3600, manageUri: 'https://as.example/m', instanceId: 'inst1',
    continue: { uri: 'https://as.example/c', access_token: { value: 'tok', bound: true }, wait: 5 } }]);
  await run('capabilityToGrantResponse', `${k} expiresIn-zero`, M.capabilityToGrantResponse, [ch, { expiresIn: 0, instanceId: '', manageUri: '' }]);
  await run('capabilityToGrantResponse', `${k} nulls`, M.capabilityToGrantResponse, [ch, { expiresIn: null, manageUri: null, instanceId: null, continue: null }]);
}
await run('capabilityToGrantResponse', 'empty', M.capabilityToGrantResponse, [[]]);
await run('capabilityToGrantResponse', 'not-array', M.capabilityToGrantResponse, ['x']);

const tok = (chain: any) => M.encodeBoundToken(chain);
const V = (name: string, value: any, opts?: any) => run('verifyGnapToken', name, M.verifyGnapToken, opts === undefined ? [value] : [value, opts]);
for (const [k, ch] of Object.entries(CHAINS)) {
  await V(k, tok(ch));
  await V(`${k} issuer-ok`, tok(ch), { expectedRootIssuer: PK.principal });
  await V(`${k} issuer-wrong`, tok(ch), { expectedRootIssuer: PK.a1 });
  await V(`${k} pqpins`, tok(ch), { pqPins: { [PK.principal]: 'x' } });
  for (const [n, f] of TAMPER) await V(`${k} ${n}`, tok(mutate(ch, f)));
}
const raw64 = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const rootJson = JSON.stringify(ROOT_CHAIN);
for (const [n, v] of Object.entries<any>({
  empty: '', 'not-b64': '!!!', padded: tok(ROOT_CHAIN) + '=', 'std-alphabet': tok(ROOT_CHAIN).replace(/-/g, '+'), 'len1mod4': 'A', 'trailing-bits': 'QR', number: 5, null: null,
  'not-json': raw64('nope'), 'json-object': raw64('{}'), 'json-empty-array': raw64('[]'), 'json-string': raw64('"x"'), 'dup-keys': raw64('[{"id":"a","id":"b"}]'),
  bom: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(rootJson)]).toString('base64url'), 'bad-utf8': Buffer.from([0x5b, 0xff, 0x5d]).toString('base64url'),
  'chain-in-array': raw64(JSON.stringify([ROOT_CHAIN])), 'hop-not-object': raw64('[1]'), 'hop-missing-fields': raw64('[{"id":"a"}]'),
  'trailing-space': raw64(rootJson + ' '), 'leading-space': raw64(' ' + rootJson), 'negative-zero': raw64(rootJson.replace('"ts":1800000000000', '"ts":-0')),
  exponent: raw64(rootJson.replace('"ts":1800000000000', '"ts":1e3')), 'lone-surrogate': raw64(rootJson.replace('gnap_grant', 'gnap\\ud800grant')),
  deep: raw64('['.repeat(40) + ']'.repeat(40)), 'parent-number': raw64(JSON.stringify([{ ...ROOT_CHAIN[0], parent: 5 }])), 'alg-null': raw64(JSON.stringify([{ ...ROOT_CHAIN[0], alg: null }])),
  'pq-sig-number': raw64(JSON.stringify([{ ...ROOT_CHAIN[0], pq_sig: 1 }])), 'caveats-object': raw64(JSON.stringify([{ ...ROOT_CHAIN[0], caveats: {} }])),
})) await V(n, v);

// ---- jwsd: content digest, sign, verify ------------------------------------------------------------------------------------------
const CD: [string, any][] = [['string', 'hello'], ['empty-string', ''], ['unicode', 'h\u00e9llo \u2603 \ud83d\ude00'], ['lone-surrogate', 'a\ud800b'],
  ['bytes', { $bytes: Buffer.from('hello').toString('base64url') }], ['empty-bytes', { $bytes: '' }], ['object', { b: 1, a: [true, null, 'x'] }], ['object-unsorted', { z: 1, a: { y: 2, b: 1 } }],
  ['array', [3, 2, 1]], ['number', 5], ['neg-zero', -0], ['float', 1.5], ['null', null], ['true', true], ['nested-neg-zero', { a: -0 }], ['large', 2 ** 53], ['too-large', 1e21],
  ['tiny', 1e-7], ['precise', 0.1234567890123456], ['deep', JSON.parse('['.repeat(33) + ']'.repeat(33))], ['bytes-lookalike', { $bytes: 'AA', x: 1 }], ['unicode-key', { 'é': 1 }]];
for (const [n, b] of CD) await run('gnapContentDigest', n, (x: any) => M.gnapContentDigest(unbytes(x)), [b]);
await run('gnapContentDigestAbsent', 'absent', () => M.gnapContentDigest(undefined), []);

const KEY = { secretKey: SK.a1, publicKey: PK.a1 };
const BODY = { access_token: { access: [FILES] }, client: { key: { proof: 'jwsd', jwk: jwk(PK.a1) } } };
const signArgs = (a: any) => ({ ...a, key: a.key ? { secretKey: B(a.key.secretKey), publicKey: B(a.key.publicKey) } : a.key, body: unbytes(a.body) });
const S = (name: string, a: any) => run('signGnapRequest', name, (x: any) => M.signGnapRequest(signArgs(x)), [a]);
const base = { body: BODY, key: KEY, htm: 'post', uri: 'https://as.example/gnap', created: T0 / 1000 };
await S('base', base);
await S('upper-htm', { ...base, htm: 'POST' });
await S('kid', { ...base, kid: 'k1' });
await S('ath', { ...base, accessTokenValue: 'access-token-1' });
await S('ath-empty', { ...base, accessTokenValue: '' });
await S('no-body', { ...base, body: undefined });
await S('string-body', { ...base, body: '{"raw":true}' });
await S('bytes-body', { ...base, body: { $bytes: Buffer.from('raw bytes').toString('base64url') } });
await S('other-key', { ...base, key: { secretKey: SK.a2, publicKey: PK.a2 } });
await S('created-fraction', { ...base, created: 1800000000.5 });
await S('created-zero', { ...base, created: 0 });
await S('unicode-uri', { ...base, uri: 'https://as.example/g\u00e9?q="x"' });
await S('all', { ...base, kid: 'k1', accessTokenValue: 'tok', htm: 'get' });
await S('short-secret', { ...base, key: { secretKey: P.b64u(new Uint8Array(31)), publicKey: PK.a1 } });
await S('bad-body', { ...base, body: 1e21 });
await S('htm-missing', { ...base, htm: undefined });

// verify: take real proofs and break them one at a time
const sign = (a: any) => M.signGnapRequest(signArgs(a));
const NOW = T0;
const PROOF0 = await sign(base);
const PROOF_ATH = await sign({ ...base, accessTokenValue: 'tok', kid: 'k9' });
const verifyArgs = (a: any, seen: string[][]) => {
  const { seenProofMode, ...rest } = a;
  const args: any = { ...rest, body: unbytes(a.body) };
  if (seenProofMode === 'fresh') args.seenProof = (id: string, exp: number) => { seen.push([id, exp] as any); return false; };
  else if (seenProofMode === 'replayed') args.seenProof = (id: string, exp: number) => { seen.push([id, exp] as any); return true; };
  else if (seenProofMode === 'throws') args.seenProof = (id: string, exp: number) => { seen.push([id, exp] as any); throw new Error('store down'); };
  else if (seenProofMode === 'undefined') args.seenProof = (id: string, exp: number) => { seen.push([id, exp] as any); return undefined; };
  return args;
};
const cutJson = (r: any) => (r && typeof r.reason === 'string' ? { ...r, reason: r.reason.replace(/(bad-json) \(.*\)$/s, '$1') } : r);
const VR = (name: string, a: any) => run('verifyGnapRequest', name, async (x: any) => { const seen: any[] = []; const result = cutJson(await M.verifyGnapRequest(verifyArgs(x, seen))); return { result, seen }; }, [a]);
const vbase = { detachedJws: PROOF0.detachedJws, body: BODY, holder: PK.a1, htm: 'POST', uri: 'https://as.example/gnap', now: NOW, replayCheck: 'unchecked' };
await VR('ok', vbase);
await VR('ok-fresh', { ...vbase, replayCheck: undefined, seenProofMode: 'fresh' });
await VR('ok-fresh-maxage', { ...vbase, replayCheck: undefined, seenProofMode: 'fresh', maxAgeSec: 1000 });
await VR('replayed', { ...vbase, replayCheck: undefined, seenProofMode: 'replayed' });
await VR('store-throws', { ...vbase, replayCheck: undefined, seenProofMode: 'throws' });
await VR('store-undefined', { ...vbase, replayCheck: undefined, seenProofMode: 'undefined' });
await VR('store-and-unchecked', { ...vbase, seenProofMode: 'fresh' });
await VR('no-replay-config', { ...vbase, replayCheck: undefined });
await VR('replay-check-other', { ...vbase, replayCheck: 'checked' });
await VR('htm-lower', { ...vbase, htm: 'post' });
await VR('htm-wrong', { ...vbase, htm: 'GET' });
await VR('uri-wrong', { ...vbase, uri: 'https://as.example/other' });
await VR('uri-case', { ...vbase, uri: 'https://AS.example/gnap' });
await VR('body-tampered', { ...vbase, body: { ...BODY, extra: 1 } });
await VR('body-key-order', { ...vbase, body: { client: BODY.client, access_token: BODY.access_token } });
await VR('body-absent', { ...vbase, body: undefined });
await VR('holder-other', { ...vbase, holder: PK.a2 });
await VR('holder-bad', { ...vbase, holder: 'x' });
await VR('holder-padded', { ...vbase, holder: PK.a1 + '=' });
await VR('holder-null', { ...vbase, holder: null });
await VR('holder-small-order', { ...vbase, holder: P.b64u(new Uint8Array(32)) });
for (const dn of [-100, -1, 0, 1, 59, 60, 61, 299, 300, 301, 302, 400, 3600])
  for (const dm of [undefined, 1000]) await VR(`clock ${dn}${dm ? ' max' + dm : ''}`, { ...vbase, now: NOW + dn * 1000, ...(dm ? { maxAgeSec: dm } : {}) });
await VR('clock-ms-floor', { ...vbase, now: NOW + 300999 });
await VR('clock-ms-floor2', { ...vbase, now: NOW + 301000 });
await VR('maxage-zero', { ...vbase, maxAgeSec: 0 });
await VR('maxage-zero-later', { ...vbase, maxAgeSec: 0, now: NOW + 1000 });
await VR('ath-ok', { ...vbase, detachedJws: PROOF_ATH.detachedJws, accessTokenValue: 'tok' });
await VR('ath-wrong', { ...vbase, detachedJws: PROOF_ATH.detachedJws, accessTokenValue: 'other' });
await VR('ath-missing-in-proof', { ...vbase, accessTokenValue: 'tok' });
await VR('ath-not-demanded', { ...vbase, detachedJws: PROOF_ATH.detachedJws });
await VR('ath-null', { ...vbase, detachedJws: PROOF_ATH.detachedJws, accessTokenValue: null });
const [h64, , s64] = PROOF0.detachedJws.split('.');
const digestB64 = Buffer.from(M.gnapContentDigest(BODY)).toString('base64url');
const hdr = JSON.parse(Buffer.from(h64, 'base64url').toString());
const reSign = async (header: any, key = KEY, payloadBody: any = BODY, raw?: string) => {
  const h = raw ?? Buffer.from(JSON.stringify(header)).toString('base64url');
  const payload = Buffer.from(M.gnapContentDigest(payloadBody)).toString('base64url');
  const sig = P.b64u(P.sign(B(key.secretKey), new TextEncoder().encode(`${h}.${payload}`)));
  return `${h}..${sig}`;
};
const mid = (jws: string, m: string) => { const [a, , c] = jws.split('.'); return `${a}.${m}.${c}`; };
const variantsJws: [string, string][] = [
  ['digest-spelled-out', mid(PROOF0.detachedJws, digestB64)], ['wrong-mid', mid(PROOF0.detachedJws, 'AAAA')], ['two-parts', `${h64}.${s64}`], ['four-parts', PROOF0.detachedJws + '.x'],
  ['empty', ''], ['no-dots', 'abc'], ['sig-flipped', `${h64}..${s64.slice(0, -2)}AA`], ['sig-short', `${h64}..${s64.slice(0, -4)}`], ['sig-empty', `${h64}..`], ['header-empty', `..${s64}`],
  ['sig-nonzero-trailing', `${h64}..${s64.slice(0, -1)}${s64.slice(-1) === 'A' ? 'B' : 'A'}`], ['sig-padded', `${h64}..${s64}=`], ['sig-std-alphabet', `${h64}..${s64.replace(/-/g, '+').replace(/_/g, '/')}x`],
  ['header-nonzero-trailing', `${h64.slice(0, -1)}${h64.slice(-1) === 'A' ? 'B' : 'A'}..${s64}`], ['header-len1mod4', `${h64.slice(0, 5)}..${s64}`], ['header-bad-char', `${h64}!..${s64}`],
  ['header-space', ` ${h64}..${s64}`], ['header-not-json', `${raw64('nope')}..${s64}`], ['header-array', `${raw64('[]')}..${s64}`], ['header-string', `${raw64('"x"')}..${s64}`],
  ['header-dup-key', `${raw64('{"alg":"EdDSA","alg":"EdDSA"}')}..${s64}`], ['header-bom', `${Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(hdr))]).toString('base64url')}..${s64}`],
  ['header-bad-utf8', `${Buffer.from([0x7b, 0xff, 0x7d]).toString('base64url')}..${s64}`], ['header-neg-zero', `${raw64(JSON.stringify(hdr).replace(String(hdr.created), '-0'))}..${s64}`],
  ['header-exponent', `${raw64(JSON.stringify(hdr).replace(String(hdr.created), '1e9'))}..${s64}`], ['signed-by-other-header-tampered', `${raw64(JSON.stringify({ ...hdr, uri: 'https://evil' }))}..${s64}`],
  ['long', 'a'.repeat(8193)], ['long-ok-size', 'a'.repeat(8192)], ['unicode', '\u00e9..\u00e9'],
];
for (const [n, j] of variantsJws) await VR('jws ' + n, { ...vbase, detachedJws: j });
const SIGNED: [string, any][] = [
  ['typ-wrong', { ...hdr, typ: 'JWT' }], ['typ-missing', (() => { const h = { ...hdr }; delete h.typ; return h; })()], ['alg-none', { ...hdr, alg: 'none' }], ['alg-missing', (() => { const h = { ...hdr }; delete h.alg; return h; })()],
  ['htm-lower', { ...hdr, htm: 'post' }], ['htm-number', { ...hdr, htm: 5 }], ['htm-missing', (() => { const h = { ...hdr }; delete h.htm; return h; })()], ['uri-number', { ...hdr, uri: 5 }],
  ['created-string', { ...hdr, created: String(hdr.created) }], ['created-missing', (() => { const h = { ...hdr }; delete h.created; return h; })()], ['created-fraction', { ...hdr, created: hdr.created + 0.5 }],
  ['created-future', { ...hdr, created: hdr.created + 100 }], ['created-old', { ...hdr, created: hdr.created - 1000 }], ['created-null', { ...hdr, created: null }], ['created-neg', { ...hdr, created: -5 }],
  ['kid-number', { ...hdr, kid: 5 }], ['kid-string', { ...hdr, kid: 'abc' }], ['ath-number', { ...hdr, ath: 5 }], ['ath-extra', { ...hdr, ath: 'x' }], ['extra-member', { ...hdr, zz: 1 }],
  ['crit-b64', { ...hdr, crit: ['b64'], b64: true }], ['crit-b64-false', { ...hdr, crit: ['b64'], b64: false }], ['crit-b64-missing', { ...hdr, crit: ['b64'] }], ['crit-other', { ...hdr, crit: ['exp'], exp: 1 }],
  ['crit-empty', { ...hdr, crit: [] }], ['crit-string', { ...hdr, crit: 'b64', b64: true }], ['crit-b64-string', { ...hdr, crit: ['b64'], b64: 'true' }], ['crit-dup', { ...hdr, crit: ['b64', 'b64'], b64: true }],
  ['alg-es256', { ...hdr, alg: 'ES256' }], ['alg-lower', { ...hdr, alg: 'eddsa' }], ['alg-number', { ...hdr, alg: 5 }],
];
for (const [n, h] of SIGNED) await VR('signed ' + n, { ...vbase, detachedJws: await reSign(h) });
await VR('signed-other-key', { ...vbase, detachedJws: await reSign(hdr, { secretKey: SK.a2, publicKey: PK.a2 }) });
await VR('signed-other-body', { ...vbase, detachedJws: await reSign(hdr, KEY, { other: 1 }) });
await VR('signed-ok-again', { ...vbase, detachedJws: await reSign(hdr) });
await VR('signed-pretty-header', { ...vbase, detachedJws: await reSign(null, KEY, BODY, Buffer.from(JSON.stringify(hdr, null, 2)).toString('base64url')) });
await VR('detached-arg-number', { ...vbase, detachedJws: 5 });
await VR('detached-arg-null', { ...vbase, detachedJws: null });
await VR('htm-arg-number', { ...vbase, htm: 5 });
await VR('uri-arg-number', { ...vbase, uri: 5 });
await VR('now-fraction', { ...vbase, now: NOW + 0.5 });
await VR('body-neg-zero', { ...vbase, body: { a: -0 } });
await VR('body-too-large-number', { ...vbase, body: 1e21 });
for (const [n, b] of CD.slice(0, 9)) {
  const s = await sign({ ...base, body: b });
  await VR('body ' + n, { ...vbase, detachedJws: s.detachedJws, body: b });
}

// ---- step-up ---------------------------------------------------------------------------------------------------------------------
const SS = [{ role: 'agent', publicKey: PK.a1 }, { role: 'guardian', publicKey: PK.g }, { role: 'principal', publicKey: PK.pr }];
const RQ = (a: any[], over: any = {}) => reqOf(a, over);
const SU = (name: string, req: any, opts?: any) => run('gnapRequestRequiresStepUp', name, M.gnapRequestRequiresStepUp, opts === undefined ? [req] : [req, opts]);
await SU('plain', RQ([FILES]));
await SU('interact', RQ([FILES], { interact: { start: ['redirect'] } }));
await SU('interact-empty-start', RQ([FILES], { interact: { start: [] } }));
await SU('interact-null', RQ([FILES], { interact: null }));
await SU('interact-string', RQ([FILES], { interact: 'x' }));
await SU('interact-start-string', RQ([FILES], { interact: { start: 'redirect' } }));
await SU('interact-array', RQ([FILES], { interact: [] }));
await SU('tier-2', RQ([FILES]), { tier: 2 });
await SU('tier-3', RQ([FILES]), { tier: 3 });
await SU('tier-1', RQ([FILES]), { tier: 1 });
await SU('tier-null', RQ([FILES]), { tier: null });
await SU('tier-3-interact', RQ([FILES], { interact: { start: ['app'] } }), { tier: 3 });
await SU('empty-opts', RQ([FILES]), {});
await SU('chain-within', RQ([H1ACC[0]]), { issuerChain: ROOT_CHAIN });
await SU('chain-beyond', RQ([{ type: 'mail' }, H1ACC[0]]), { issuerChain: ROOT_CHAIN });
await SU('chain-beyond-tier2', RQ([{ type: 'mail' }]), { issuerChain: ROOT_CHAIN, tier: 2 });
await SU('chain-beyond-interact', RQ([{ type: 'mail' }], { interact: { start: ['redirect'] } }), { issuerChain: ROOT_CHAIN });
await SU('chain-h2-wide', RQ([FILES]), { issuerChain: H2.chain });
await SU('chain-bad-access', RQ([7]), { issuerChain: ROOT_CHAIN });
await SU('chain-no-access', { client: RQ([]).client }, { issuerChain: ROOT_CHAIN });
await SU('chain-empty', RQ([FILES]), { issuerChain: [] });
await SU('no-chain-bad-access', RQ([7]));
await SU('req-null', null);
await SU('req-null-chain', null, { issuerChain: ROOT_CHAIN });

const BG = (name: string, a: any) => run('beginGnapContinuation', name, M.beginGnapContinuation, [a]);
await BG('base', { signerSet: SS, t: 2, tier: 2, continueUri: 'https://as.example/continue/1', continueToken: 'ct-1' });
await BG('wait', { signerSet: SS, t: 3, tier: 3, continueUri: 'https://as.example/continue/2', continueToken: 'ct-2', wait: 30 });
await BG('wait-zero', { signerSet: SS, t: 3, tier: 3, continueUri: 'u', continueToken: 't', wait: 0 });
await BG('wait-null', { signerSet: SS, t: 3, tier: 3, continueUri: 'u', continueToken: 't', wait: null });
await BG('reason', { signerSet: SS, t: 2, tier: 2, continueUri: 'u', continueToken: 't', reason: 'because' });
await BG('reason-empty', { signerSet: SS, t: 2, tier: 2, continueUri: 'u', continueToken: 't', reason: '' });
await BG('reason-null', { signerSet: SS, t: 2, tier: 3, continueUri: 'u', continueToken: 't', reason: null });

// threshold shares and the folded continuation
const NODE = { id: 'n1', verb: 'read', resource: R('a/x') };
const PLAN = [NODE, { id: 'n2', verb: 'write', resource: R('a/y'), reversibility_class: 'irreversible' }];
const ACTN_BODY = P.buildPCActn({ grant: H1.grant, chain: H1.chain, plan: PLAN, nodeId: 'n1', counter: 1, signerSecret: B(SK.a2), aud: 'rs.example', now: NOW, params: { datatype: 'doc' } });
const SHARE = (name: string, body: any, role: string, sk: string, set: any, t: any) => run('gnapStepUpShare', name, (b: any, r: string, s: string, ss: any, tt: any) => M.gnapStepUpShare(b, r, B(s), ss, tt), [body, role, sk, set, t]);
await SHARE('guardian-t2', ACTN_BODY, 'guardian', SK.g, SS, 2);
await SHARE('principal-t3', ACTN_BODY, 'principal', SK.pr, SS, 3);
await SHARE('agent-t1', ACTN_BODY, 'agent', SK.a1, SS, 1);
await SHARE('t0', ACTN_BODY, 'guardian', SK.g, SS, 0);
await SHARE('t4', ACTN_BODY, 'guardian', SK.g, SS, 4);
await SHARE('t-string', ACTN_BODY, 'guardian', SK.g, SS, '2');
await SHARE('t-fraction', ACTN_BODY, 'guardian', SK.g, SS, 2.5);
await SHARE('other-order', ACTN_BODY, 'guardian', SK.g, [SS[2], SS[0], SS[1]], 2);
await SHARE('other-set', ACTN_BODY, 'guardian', SK.g, [SS[0], SS[1]], 2);
await SHARE('role-other', ACTN_BODY, 'admin', SK.g, SS, 2);
await SHARE('set-pq', ACTN_BODY, 'guardian', SK.g, [SS[0], { ...SS[1], pq_pk: 'AAAA' }, SS[2]], 2);
await SHARE('short-secret', ACTN_BODY, 'guardian', P.b64u(new Uint8Array(5)), SS, 2);
await SHARE('body-signed', { ...ACTN_BODY, sig: 'x', threshold: { shares: [] }, pq_sig: 'y' }, 'guardian', SK.g, SS, 2);
await SHARE('body-other', { ...ACTN_BODY, counter: 2 }, 'guardian', SK.g, SS, 2);
await SHARE('set-empty', ACTN_BODY, 'guardian', SK.g, [], 2);
await SHARE('set-not-array', ACTN_BODY, 'guardian', SK.g, 'x', 2);
await SHARE('set-null', ACTN_BODY, 'guardian', SK.g, null, 2);

const CC = (name: string, a: any) => run('completeGnapContinuation', name, (x: any) => M.completeGnapContinuation({ ...x, agentLeafSecret: B(x.agentLeafSecret), cosignSecrets: x.cosignSecrets?.map((c: any) => ({ ...c, secret: B(c.secret) })) }), [a]);
const cbase = { grant: H1.grant, chain: H1.chain, plan: PLAN, nodeId: 'n1', params: { datatype: 'doc' }, counter: 7, aud: 'rs.example', now: NOW, ttlMs: 60000,
  agentLeafSecret: SK.a2, signerSet: [{ role: 'agent', publicKey: PK.a2 }, { role: 'guardian', publicKey: PK.g }, { role: 'principal', publicKey: PK.pr }], t: 2,
  cosignSecrets: [{ role: 'guardian', secret: SK.g }] };
const SSX = cbase.signerSet;
await CC('t2-guardian', cbase);
await CC('t3-both', { ...cbase, t: 3, cosignSecrets: [{ role: 'guardian', secret: SK.g }, { role: 'principal', secret: SK.pr }] });
await CC('t3-one', { ...cbase, t: 3 });
await CC('t1-agent-only', { ...cbase, t: 1, cosignSecrets: [] });
await CC('t1-no-cosign-field', { ...cbase, t: 1, cosignSecrets: undefined });
await CC('t2-no-cosign', { ...cbase, cosignSecrets: [] });
await CC('t2-principal', { ...cbase, cosignSecrets: [{ role: 'principal', secret: SK.pr }] });
await CC('t2-wrong-key', { ...cbase, cosignSecrets: [{ role: 'guardian', secret: SK.a3 }] });
await CC('t2-role-unknown', { ...cbase, cosignSecrets: [{ role: 'admin', secret: SK.g }] });
await CC('t2-role-lies', { ...cbase, cosignSecrets: [{ role: 'principal', secret: SK.g }] });
await CC('t2-dup-guardian', { ...cbase, cosignSecrets: [{ role: 'guardian', secret: SK.g }, { role: 'guardian', secret: SK.g }] });
await CC('t3-dup-then-principal', { ...cbase, t: 3, cosignSecrets: [{ role: 'guardian', secret: SK.g }, { role: 'guardian', secret: SK.g }, { role: 'principal', secret: SK.pr }] });
await CC('t2-agent-key-not-registered', { ...cbase, agentLeafSecret: SK.a3 });
await CC('t2-agent-cosign', { ...cbase, cosignSecrets: [{ role: 'agent', secret: SK.a2 }] });
await CC('set-two-keys-for-role', { ...cbase, signerSet: [...SSX, { role: 'guardian', publicKey: PK.a3 }] });
await CC('set-one-key-two-roles', { ...cbase, signerSet: [...SSX, { role: 'principal', publicKey: PK.g }] });
await CC('set-duplicate-entry', { ...cbase, signerSet: [...SSX, SSX[1]] });
await CC('set-bad-role', { ...cbase, signerSet: [...SSX, { role: 'root', publicKey: PK.a3 }] });
await CC('set-bad-key', { ...cbase, signerSet: [...SSX, { role: 'guardian', publicKey: 'x' }] });
await CC('set-pq-valid-length-agent', { ...cbase, signerSet: [{ ...SSX[0], pq_pk: Buffer.alloc(1952, 7).toString('base64url') }, SSX[1], SSX[2]] });
await CC('set-pq-valid-length-guardian', { ...cbase, signerSet: [SSX[0], { ...SSX[1], pq_pk: Buffer.alloc(1952, 7).toString('base64url') }, SSX[2]] });
await CC('set-pq-bad-length', { ...cbase, signerSet: [SSX[0], { ...SSX[1], pq_pk: 'AAAA' }, SSX[2]] });
await CC('set-pq-null', { ...cbase, signerSet: [SSX[0], { ...SSX[1], pq_pk: null }, SSX[2]] });
await CC('set-pq-dup-conflict', { ...cbase, signerSet: [...SSX, { ...SSX[1], pq_pk: Buffer.alloc(1952, 7).toString('base64url') }] });
await CC('set-empty', { ...cbase, signerSet: [] });
await CC('set-order', { ...cbase, signerSet: [SSX[2], SSX[1], SSX[0]] });
await CC('set-guardian-only', { ...cbase, signerSet: [SSX[1]], cosignSecrets: [] });
await CC('t0', { ...cbase, t: 0 });
await CC('t4', { ...cbase, t: 4 });
await CC('no-params', { ...cbase, params: undefined, nodeId: 'n1' });
await CC('params-mismatch-pin', { ...cbase, plan: [{ ...NODE, params_digest: P.paramsDigest({ datatype: 'img' }) }, PLAN[1]] });
await CC('params-match-pin', { ...cbase, plan: [{ ...NODE, params_digest: P.paramsDigest({ datatype: 'doc' }) }, PLAN[1]] });
await CC('node-2', { ...cbase, nodeId: 'n2', params: undefined });
await CC('node-unknown', { ...cbase, nodeId: 'zz' });
await CC('no-aud', { ...cbase, aud: '' });
await CC('empty-chain', { ...cbase, chain: [] });
await CC('ttl', { ...cbase, ttlMs: 1000 });
await CC('no-ttl', { ...cbase, ttlMs: undefined });
await CC('counter-0', { ...cbase, counter: 0 });
await CC('pre-post-plan', { ...cbase, plan: [{ ...NODE, pre: [{ field: 'a', op: 'eq', value: 1 }], post: [] }, PLAN[1]] });
await CC('root-chain', { ...cbase, grant: ROOT.grant, chain: ROOT_CHAIN, agentLeafSecret: SK.a1, signerSet: [{ role: 'agent', publicKey: PK.a1 }, SSX[1], SSX[2]] });

// ---- interaction -----------------------------------------------------------------------------------------------------------------
const URIS: string[] = [
  'https://client.example/cb', 'https://client.example', 'https://client.example/', 'https://client.example/cb?x=1', 'https://client.example/cb?x=1&y=a%20b', 'https://CLIENT.Example/Cb',
  'https://client.example:8443/cb', 'https://client.example:443/cb', 'https://client.example:/cb', 'https://client.example:99999/cb', 'https://client.example:abc/cb', 'https://user:pw@client.example/cb',
  'https://client.example/cb#frag', 'https://client.example/cb#', 'https://client.example/a/b/c', 'https://sub.client.example/cb', 'https://client_x.example/cb', 'https://-client.example/cb',
  'http://client.example/cb', 'http://localhost/cb', 'http://localhost:8080/cb', 'http://LOCALHOST/cb', 'http://127.0.0.1/cb', 'http://127.0.0.1:3000/cb', 'http://[::1]/cb', 'http://[::1]:3000/cb',
  'http://localhost.example/cb', 'http://127.0.0.2/cb', 'http://localhost./cb', 'https://1.2.3.4/cb', 'https://1.2.3.256/cb', 'https://client.example.1/cb', 'https://exa mple.com/cb', 'https://exa<mple.com/cb',
  'https://', 'https://:80/cb', 'https://user@/cb', 'https://[::1/cb',
  'com.example.app:/oauth2redirect', 'com.example.app:/cb?x=1', 'myapp://callback', 'myapp://callback/path', 'myapp:', 'myapp:cb', 'myapp://host:99/cb', 'myapp://host:x/cb', 'MYAPP://cb',
  'javascript:alert(1)', 'JavaScript:alert(1)', 'data:text/html,hi', 'file:///etc/passwd', 'blob:https://x/y', 'ftp://files.example/x', 'ws://x.example/y', 'wss://x.example/y',
  '', ' ', '/cb', 'cb', '//client.example/cb', ':foo', '1abc:foo', 'a b:c', 'c:\\foo', '\u00e9://x', 'https://client.example/\u00e9', 'https://client.example/cb\n', '  https://client.example/cb  ',
  'https://cli\tent.example/cb', 'https://client.example/' + 'a'.repeat(2025), 'https://client.example/' + 'a'.repeat(2026), 'x:' + 'a'.repeat(2046), 'x:' + 'a'.repeat(2047),
];
for (const [i, u] of URIS.entries()) await run('callbackUriOk', `u${i}`, M.callbackUriOk, [u]);
for (const [i, u] of [null, 5, true, [], {}, ['https://x/']].entries()) await run('callbackUriOk', `nonstring${i}`, M.callbackUriOk, [u]);

const IV = { start: ['redirect', 'user_code'], finish: { method: 'redirect', uri: 'https://client.example/cb', nonce: 'nonce-1234567890' }, hints: { ui_locales: ['en'] } };
await run('validateInteractRequest', 'valid', M.validateInteractRequest, [IV]);
for (const [n, v] of variants(IV, { lens: [0, 1, 7, 8, 9, 255, 256, 257], hostile: [null, '', 'x', 0, 1.5, [], {}, true, 'push', 'sha-256', 'toString', 'constructor'], maxPaths: 40 })) await run('validateInteractRequest', n, M.validateInteractRequest, [v]);
for (const [n, v] of Object.entries<any>({
  'start-17': { start: Array(17).fill('redirect') }, 'start-16': { start: Array(16).fill('redirect') }, 'start-objects': { start: [{ mode: 'redirect' }, { mode: 5 }, {}, null, 7, [], { mode: 'x', extra: 1 }] },
  'start-unknown': { start: ['carrier-pigeon'] }, 'finish-array': { start: ['app'], finish: [] }, 'finish-null': { start: ['app'], finish: null }, 'finish-string': { start: ['app'], finish: 'x' },
  'finish-undefined-members': { start: ['app'], finish: {} }, 'hash-proto': { start: ['app'], finish: { ...IV.finish, hash_method: 'hasOwnProperty' } }, 'hash-proto2': { start: ['app'], finish: { ...IV.finish, hash_method: '__proto__' } },
  'hash-sha3': { start: ['app'], finish: { ...IV.finish, hash_method: 'sha3-512' } }, 'hash-upper': { start: ['app'], finish: { ...IV.finish, hash_method: 'SHA-256' } },
  'hash-number': { start: ['app'], finish: { ...IV.finish, hash_method: 5 } }, 'hash-null': { start: ['app'], finish: { ...IV.finish, hash_method: null } }, 'hash-array': { start: ['app'], finish: { ...IV.finish, hash_method: ['sha-256'] } },
  'hash-object': { start: ['app'], finish: { ...IV.finish, hash_method: {} } }, 'nonce-printable': { start: ['app'], finish: { ...IV.finish, nonce: '!~!~!~!~' } }, 'nonce-space': { start: ['app'], finish: { ...IV.finish, nonce: 'aaaa bbbb' } },
  'nonce-newline': { start: ['app'], finish: { ...IV.finish, nonce: 'aaaabbbb\n' } }, 'nonce-unicode': { start: ['app'], finish: { ...IV.finish, nonce: 'aaaabbb\u00e9' } }, 'nonce-8': { start: ['app'], finish: { ...IV.finish, nonce: 'a'.repeat(8) } },
  'nonce-7': { start: ['app'], finish: { ...IV.finish, nonce: 'a'.repeat(7) } }, 'nonce-256': { start: ['app'], finish: { ...IV.finish, nonce: 'a'.repeat(256) } }, 'nonce-257': { start: ['app'], finish: { ...IV.finish, nonce: 'a'.repeat(257) } },
  'method-push': { start: ['app'], finish: { ...IV.finish, method: 'push' } }, 'method-upper': { start: ['app'], finish: { ...IV.finish, method: 'PUSH' } }, 'method-array': { start: ['app'], finish: { ...IV.finish, method: ['push'] } },
  'uri-bad': { start: ['app'], finish: { ...IV.finish, uri: 'http://remote.example/cb' } }, 'uri-loopback': { start: ['app'], finish: { ...IV.finish, uri: 'http://localhost:1/cb' } },
  'all-bad': { start: [], finish: { method: 'x', uri: 5, nonce: 5, hash_method: 'x' } }, 'extra': { start: ['app'], zz: 1 },
  array: [], string: 'x', number: 5, null: null, true: true, empty: {},
})) await run('validateInteractRequest', n, M.validateInteractRequest, [v]);

const HA = { clientNonce: 'KBMRTQ1ABCDEF', asNonce: 'VJLO6A4CAYLBXHTR0KRO', interactRef: 'VJLO6A4CAYLBXHTR0KRO-x', grantEndpoint: 'https://server.example.com/tx' };
// RFC 9635 4.2.3 example inputs
const RFC = { clientNonce: 'VJLO6A4CAYLBXHTR0KRO', asNonce: 'MBDOFXG4Y5CVJCX821LH', interactRef: '4IFWWIKYBC2PQ6U56NL1', grantEndpoint: 'https://server.example.com/tx' };
for (const [n, a] of Object.entries<any>({ rfc: RFC, base: HA, empty: { clientNonce: '', asNonce: '', interactRef: '', grantEndpoint: '' }, unicode: { ...HA, clientNonce: 'n\u00e9\u0101\u2603' }, 'newline-in-nonce': { ...HA, clientNonce: 'a\nb' } }))
  for (const m of [undefined, 'sha-256', 'sha-384', 'sha-512', 'sha3-256', 'sha3-512', 'SHA-256', 'md5', '', null, 5, 'toString', 'constructor', '__proto__']) {
    await run('interactionHash', `${n} ${String(m)}`, M.interactionHash, [m === undefined ? a : { ...a, hashMethod: m }]);
  }
await run('interactionHash', 'missing-nonce', M.interactionHash, [{ asNonce: 'a', interactRef: 'b', grantEndpoint: 'c' }]);
{
  const good = M.interactionHash(RFC);
  for (const [n, rec] of Object.entries<any>({ good, wrong: 'x' + good.slice(1), short: good.slice(0, -1), long: good + 'A', empty: '', number: 5, null: null, array: [good], 'other-case': good.toUpperCase(), unicode: good.slice(0, -1) + '\u00e9' }))
    for (const m of [undefined, 'sha-512', 'bogus']) await run('verifyInteractionHash', `${n} ${String(m)}`, M.verifyInteractionHash, [rec, m === undefined ? RFC : { ...RFC, hashMethod: m }]);
  const cb = (hash: any, ref: any) => ({ hash, interact_ref: ref });
  const ctx = { clientNonce: RFC.clientNonce, asNonce: RFC.asNonce, grantEndpoint: RFC.grantEndpoint };
  const bad = (m: string) => ({ ...ctx, hashMethod: m });
  for (const [n, a, c] of [['ok', cb(good, RFC.interactRef), ctx], ['wrong-hash', cb('x', RFC.interactRef), ctx], ['wrong-ref', cb(good, 'other'), ctx], ['no-ref', { hash: good }, ctx], ['empty-ref', cb(good, ''), ctx],
    ['no-hash', { interact_ref: RFC.interactRef }, ctx], ['hash-number', cb(5, RFC.interactRef), ctx], ['ref-number', cb(good, 5), ctx], ['empty-cb', {}, ctx], ['bad-method', cb(good, RFC.interactRef), bad('md5')],
    ['sha512', cb(M.interactionHash({ ...RFC, hashMethod: 'sha-512' }), RFC.interactRef), bad('sha-512')], ['extra', { ...cb(good, RFC.interactRef), zz: 1 }, ctx]] as any[])
    await run('acceptFinish', n, M.acceptFinish, [a, c]);
}
for (const len of [5, 13, 0, -1, 100]) await run('newUserCode', `len${len}`, M.newUserCode, [len]);

const AN: [string, any][] = [
  ['ok', [{ type: 'files', actions: ['read', 'write'], locations: ['a', 'b'] }]], ['one', [{ type: 'db', actions: ['r'], locations: ['x'] }]], ['empty', []],
  ['no-actions', [{ type: 'files', locations: ['a'] }]], ['no-locations', [{ type: 'files', actions: ['a'] }]], ['empty-actions', [{ type: 'files', actions: [], locations: ['a'] }]],
  ['empty-locations', [{ type: 'files', actions: ['a'], locations: [] }]], ['two', [{ type: 'a', actions: ['x'], locations: ['l'] }, { type: 'b', actions: ['y', 'z'], locations: ['m'] }]],
  ['second-bad', [{ type: 'a', actions: ['x'], locations: ['l'] }, { type: 'b' }]], ['null-entry', [null]], ['wildcard', [{ type: 'a', actions: ['*'], locations: ['*'] }]],
  ['extra', [{ type: 'a', actions: ['x'], locations: ['l'], datatypes: ['d'] }]],
];
for (const [n, a] of AN) await run('accessToNeeds', n, M.accessToNeeds, [a]);

// ---- the interaction server, as scripted scenarios --------------------------------------------------------------------------------
const redact = (v: any, map: [string, string][]): any => {
  if (typeof v === 'string') { let s = v; for (const [k, t] of map) if (k) s = s.split(k).join(t); return s; }
  if (Array.isArray(v)) return v.map((x) => redact(x, map));
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => [k, redact(x, map)]));
  return v;
};
const runScenario = (s: any) => {
  let clock = 1000;
  const GE = s.opts.grantEndpoint ?? 'https://as.example/tx';
  const srv = new M.InteractionServer({ grantEndpoint: GE, supports: s.opts.supports, redirectUri: (id: string) => `https://as.example/i/${id}`, ...(s.opts.app ? { appUri: (id: string) => `app://as/${id}` } : {}),
    ...(s.opts.userCodeUri ? { userCodeUri: s.opts.userCodeUri } : {}), ...(s.opts.ttlSec !== undefined ? { ttlSec: s.opts.ttlSec } : {}), now: () => clock });
  const v: Record<string, string> = {};
  let lastReq: any;
  const trace: any[] = [];
  const sub = (x: any) => (typeof x === 'string' && x.startsWith('$') ? (x === '$code:lower' ? (v.code ?? '').toLowerCase() : x === '$code:spaced' ? ((v.code ?? '').slice(0, 4) + ' - ' + (v.code ?? '').slice(4)) : v[x.slice(1)] ?? x) : x);
  // every started interaction's random id, user code and AS nonce is redacted, not only the latest: the latest keeps <ID>/<CODE>/<ASNONCE>,
  // an earlier one (start number n, from 0) is <ID:n>/<CODE:n>/<ASNONCE:n>
  const started: { id: string; code: string; asnonce: string }[] = [];
  const tokens = (): [string, string][] => [[v.ref, '<REF>'], [v.hash, '<HASH>'], [v.asnonce, '<ASNONCE>'], [v.id, '<ID>'], [v.code, '<CODE>'],
    ...started.slice(0, -1).flatMap((a, n): [string, string][] => [[a.id, `<ID:${n}>`], [a.code, `<CODE:${n}>`], [a.asnonce, `<ASNONCE:${n}>`]])];
  for (const st of s.steps) {
    try {
      let value: any;
      if (st.op === 'start') {
        lastReq = st.req;
        const r = srv.start(st.req);
        v.id = r.interaction.id; v.code = r.interaction.userCode ?? ''; v.asnonce = r.interaction.finish?.asNonce ?? '';
        started.push({ id: v.id, code: v.code, asnonce: v.asnonce });
        value = { interaction: r.interaction, response: r.response };
      } else if (st.op === 'lookup') value = srv.lookupUserCode(sub(st.code)) ?? null;
      else if (st.op === 'approve') {
        const r = srv.approve(sub(st.id));
        v.ref = r.interactRef;
        const it = srv.get(v.id);
        const m = r.finish?.method === 'push' ? r.finish.body.hash : r.finish?.url ? /[?&]hash=([^&]+)/.exec(r.finish.url)?.[1] : undefined;
        v.hash = m ?? '';
        const expected = it?.finish ? M.interactionHash({ clientNonce: it.finish.clientNonce, asNonce: it.finish.asNonce, interactRef: r.interactRef, grantEndpoint: it.grantEndpoint, hashMethod: it.finish.hashMethod }) : undefined;
        value = { result: r, hashOk: m === expected };
      } else if (st.op === 'consume') value = srv.consume(sub(st.ref));
      else if (st.op === 'finalize') value = srv.finalize(sub(st.id)) ?? null;
      else if (st.op === 'get') value = srv.get(sub(st.id)) ?? null;
      else if (st.op === 'advance') { clock += st.sec; value = clock; }
      else if (st.op === 'accept') {
        const ctx = { clientNonce: lastReq.finish.nonce, asNonce: v.asnonce, grantEndpoint: GE, ...(lastReq.finish.hash_method ? { hashMethod: lastReq.finish.hash_method } : {}) };
        value = M.acceptFinish({ hash: sub(st.hash), interact_ref: sub(st.ref) }, ctx);
      }
      trace.push({ op: st.op, ok: true, value: redact(JSON.parse(JSON.stringify(value ?? null)), tokens()) });
    } catch (e: any) {
      trace.push({ op: st.op, ok: false, code: e instanceof M.InteractionError ? e.code : 'other' });
    }
  }
  return trace;
};
const FIN = (method: string, extra: any = {}) => ({ method, uri: 'https://client.example/cb?x=1', nonce: 'client-nonce-12345', ...extra });
const SC: [string, any][] = [
  ['redirect-happy', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: FIN('redirect') } }, { op: 'get', id: '$id' }, { op: 'approve', id: '$id' }, { op: 'accept', hash: '$hash', ref: '$ref' }, { op: 'consume', ref: '$ref' }, { op: 'consume', ref: '$ref' }, { op: 'get', id: '$id' }] }],
  ['push-happy', { opts: { supports: ['redirect', 'app'], app: true }, steps: [{ op: 'start', req: { start: ['redirect', 'app'], finish: FIN('push', { hash_method: 'sha3-256' }) } }, { op: 'approve', id: '$id' }, { op: 'accept', hash: '$hash', ref: '$ref' }, { op: 'consume', ref: '$ref' }] }],
  ['user-code', { opts: { supports: ['user_code', 'redirect'] }, steps: [{ op: 'start', req: { start: ['user_code'] } }, { op: 'lookup', code: '$code' }, { op: 'lookup', code: '$code:lower' }, { op: 'lookup', code: '$code:spaced' }, { op: 'lookup', code: 'ZZZZZZZZ' }, { op: 'approve', id: '$id' }, { op: 'lookup', code: '$code' }, { op: 'consume', ref: '$ref' }] }],
  ['user-code-uri', { opts: { supports: ['user_code_uri'], userCodeUri: 'https://as.example/device' }, steps: [{ op: 'start', req: { start: [{ mode: 'user_code_uri' }] } }, { op: 'lookup', code: '$code' }] }],
  ['user-code-uri-unsupported', { opts: { supports: ['user_code_uri'] }, steps: [{ op: 'start', req: { start: ['user_code_uri'] } }] }],
  ['app-unsupported', { opts: { supports: ['app'] }, steps: [{ op: 'start', req: { start: ['app'] } }] }],
  ['app-unsupported-with-finish', { opts: { supports: ['app'] }, steps: [{ op: 'start', req: { start: ['app'], finish: FIN('redirect') } }, { op: 'approve', id: '$id' }] }],
  ['both-codes', { opts: { supports: ['user_code', 'user_code_uri', 'redirect'], userCodeUri: 'https://as.example/device' }, steps: [{ op: 'start', req: { start: ['user_code', 'user_code_uri', 'redirect'] } }] }],
  ['not-asked', { opts: { supports: ['redirect', 'app'], app: true }, steps: [{ op: 'start', req: { start: ['redirect'] } }] }],
  ['no-mode-supported', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['carrier-pigeon'] } }] }],
  ['invalid-request', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: [] } }, { op: 'start', req: { start: ['redirect'], finish: { method: 'x' } } }] }],
  ['no-finish-approve', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'consume', ref: '$ref' }, { op: 'approve', id: '$id' }, { op: 'approve', id: '$id' }, { op: 'consume', ref: '$ref' }, { op: 'finalize', id: '$id' }, { op: 'consume', ref: '$ref' }] }],
  ['consume-pending', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'consume', ref: 'nope' }] }],
  ['approve-unknown', { opts: { supports: ['redirect'] }, steps: [{ op: 'approve', id: 'nope' }] }],
  ['expiry-approve', { opts: { supports: ['redirect'], ttlSec: 10 }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'advance', sec: 10 }, { op: 'approve', id: '$id' }] }],
  ['expiry-approve-late', { opts: { supports: ['redirect'], ttlSec: 10 }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'advance', sec: 11 }, { op: 'approve', id: '$id' }] }],
  ['expiry-consume', { opts: { supports: ['redirect'], ttlSec: 10 }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'approve', id: '$id' }, { op: 'advance', sec: 11 }, { op: 'consume', ref: '$ref' }] }],
  ['expiry-lookup', { opts: { supports: ['user_code'], ttlSec: 10 }, steps: [{ op: 'start', req: { start: ['user_code'] } }, { op: 'advance', sec: 10 }, { op: 'lookup', code: '$code' }, { op: 'advance', sec: 1 }, { op: 'lookup', code: '$code' }] }],
  ['ttl-zero', { opts: { supports: ['redirect'], ttlSec: 0 }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'approve', id: '$id' }, { op: 'advance', sec: 1 }, { op: 'approve', id: '$id' }] }],
  ['accept-wrong-hash', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: FIN('redirect') } }, { op: 'approve', id: '$id' }, { op: 'accept', hash: 'x', ref: '$ref' }] }],
  ['redirect-existing-params', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: { ...FIN('redirect'), uri: 'https://Client.Example:443/cb?hash=old&x=a+b&interact_ref=old&y=%20z&x=2' } } }, { op: 'approve', id: '$id' }] }],
  ['redirect-no-path', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: { ...FIN('redirect'), uri: 'https://client.example' } } }, { op: 'approve', id: '$id' }] }],
  ['redirect-port', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: { ...FIN('redirect'), uri: 'http://localhost:8080/cb' } } }, { op: 'approve', id: '$id' }] }],
  ['redirect-app-scheme', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: { ...FIN('redirect'), uri: 'com.example.app:/cb' } } }, { op: 'approve', id: '$id' }] }],
  ['sha512-redirect', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: FIN('redirect', { hash_method: 'sha-512' }) } }, { op: 'approve', id: '$id' }, { op: 'accept', hash: '$hash', ref: '$ref' }] }],
  ['proto-hash-method', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'], finish: FIN('redirect', { hash_method: 'valueOf' }) } }, { op: 'approve', id: '$id' }] }],
  ['two-interactions', { opts: { supports: ['redirect'] }, steps: [{ op: 'start', req: { start: ['redirect'] } }, { op: 'approve', id: '$id' }, { op: 'start', req: { start: ['redirect'] } }, { op: 'consume', ref: '$ref' }] }],
];
for (const [n, s] of SC) await run('interactionScenario', n, runScenario, [s]);

refWrite(o, 'gnap');
