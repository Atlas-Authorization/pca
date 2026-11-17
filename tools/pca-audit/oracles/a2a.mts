// Oracle: @atlasauth/pca-a2a (proof-carrying A2A tasks, signed Agent Cards, AP2 payment mandate envelope, AUTH_REQUIRED mapping, extension
// declaration, per-hop delegation, push tokens, signed task-update receipts, extended Agent Card, RFC 8785 JCS, A2A 1.0 card schema).
// Deterministic: Ed25519 keys from seeds (EdDSA is deterministic, so signed cards compare byte for byte), fixed clocks (T0).
// What is NOT covered: a PCActn that reaches the full verifier (its verdict wording is the verifier's, not this adapter's) and a
// human-present mandate backed by real threshold shares; every verify* case here is refused BEFORE the verifier (no proof, missing chain,
// wrong root issuer, mandate binding errors).
// Reasons that quote the JOSE library ("signature N did not verify: ...", "could not resolve verification key: ...") are compared up to the
// first colon (norm() below; the native replay applies the same rule).
// PORTING (fn(args) -> native entry point, comparison rule; "A2aPca" = net.atlasauth.pca.a2a.A2aPca, JSON by value):
//   constants()                                   {PCA_A2A_EXTENSION_URI, TASK_STATE_AUTH_REQUIRED, TASK_STATE_INPUT_REQUIRED, A2A_AP2_CONTEXT, A2A_RECEIPT_DOMAIN, RECEIPT_KEY}
//   jcsBytes(v)                                   A2aPca.jcsBytes; bytes exact, a throw must throw
//   validateAgentCard1(card)                      A2aPca.validateAgentCard1; list exact
//   attachPcaToA2ATask / attachPcaToA2AMessage / extractPca / extractPcaFromMessage    same names; null where the reference returns undefined
//   issueSignedAgentCard(card, jwk, opts?)        A2aPca.issueSignedAgentCard (opts alg, passport, kid, profile, schema); the card with signatures, bytes exact
//   verifyAgentCard(card, opts)                   A2aPca.verifyAgentCard (opts jwks, key, alg, schema); result by value after norm()
//   verifyA2ATask(task, o) / middleware(task, o) / resumeAuthRequired(task, answer, o) / verifyA2ADelegation(hops)
//                                                 o = {aud, expectedRootIssuer?, grant?, require?}; require=false is the middleware's `require` option
//   a2aPaymentMandateFromPca(pcActn, opts)        opts as JSON (amount, paymentMethod, merchant, humanPresent, humanSignerSet, issuerPublic, now)
//   pcaBindingFromA2APaymentMandate(m)            same name
//   verifyA2APaymentMandate(m, pcActn, o)         o = {aud, expectedRootIssuer?, context?: <the params object context>, humanSignerSet?}; "malformed payment mandate or PCActn: ..." compared up to the colon
//   pcaExtensionDeclaration(params, required?) / readPcaExtension(card) / clientOptsIntoPca(h) / isAuthRequired(s) / authRequiredStatus(need, o) /
//   readAuthRequiredNeed(task) / answerMessage(need, pcActn, id) / resumeGate(o) / chainExtends(a, b) / checkChainExtension(chains) /
//   pcaPushToken(id, ids, salt) / checkPushNotification(expected, delivered) / uniformTaskNotFound()      same names
//   signTaskReceipt(label, o)                     the secret is the 32-byte seed sha256("atlas-pca-conformance/" + label); o = {taskId, state, chainIds, issuedAt, prev?}
//   verifyTaskReceipt / receiptDigest / checkReceiptChain(receipts, o) / mayTriggerNext(receipts, o) / attachReceipt / receiptOfPayload   same names
//   extendedAgentCard(card, o)                    o = {authenticated, hiddenSkills, envelopes} (default pca-verb:<verb> tag mapping)
import { createPrivateKey, sign as edSign } from 'node:crypto';
import { Oracle, HOSTILE, refWrite, seed, variants } from './lib.mjs';

const M: any = await import('../../../packages/pca-a2a/src/index.ts');
const core: any = await import('../../../packages/pca/src/index.ts');
const o = new Oracle('a2a', 'tools/pca-audit/oracles/a2a.mts', 'TS-reference oracle for the A2A adapter (tasks, cards, mandate, AUTH_REQUIRED, delegation, push, receipts, extended card).');

const T0 = 1_800_000_000_000;
const URI = M.PCA_A2A_EXTENSION_URI;
const b64u = (u: Uint8Array | Buffer) => Buffer.from(u).toString('base64url');

// ---- keys ------------------------------------------------------------------------------------------------------------
const PK8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyOf(label: string) {
  const ko = createPrivateKey({ key: Buffer.concat([PK8, Buffer.from(seed(label))]), format: 'der', type: 'pkcs8' });
  const priv: any = ko.export({ format: 'jwk' });
  const { d: _d, ...pub } = priv;
  return { ko, priv, pub };
}
const K1 = keyOf('a2a/key1');
const K2 = keyOf('a2a/key2');
const signerOf = (label: string) => b64u(core.publicKeyOf(seed(label)));

// the reasons that quote the JOSE library are compared up to the first colon
const norm = (r: any): any => {
  if (r && typeof r === 'object' && typeof r.reason === 'string') {
    const m = /^(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): /.exec(r.reason);
    if (m) return { ...r, reason: m[1] };
  }
  return r;
};

// ---- fixtures --------------------------------------------------------------------------------------------------------
const CARD = {
  name: 'Pay Agent', description: 'pays things', version: '1.0.0',
  supportedInterfaces: [{ url: 'https://a.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true, extensions: [{ uri: URI, description: 'd', required: true, params: { aud: 'https://a.example' } }] },
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's1', name: 'pay', description: 'pay', tags: ['pca-verb:pay'] }],
};
const PCA = {
  ver: 2, aud: 'rs-1', grant_ref: 'g1', iat: T0, exp: T0 + 60_000, counter: 1, sig: 'AAAA',
  action: { verb: 'pay', resource: 'merchant/1', params_digest: 'dd' },
  cap_chain: [{ id: 'g1', issuer: 'ROOT', holder: 'H1' }, { id: 'g2', issuer: 'H1', holder: 'H2' }],
};
const NEED = { v: 1, kind: 'scope', verb: 'pay', resource: 'merchant/1', scopes: ['pay:write'], limits: { 'money.usd': 40 } };
const TASK = { id: 't1', status: { state: 'TASK_STATE_WORKING' }, metadata: { x: 1 } };
const MSG = { role: 'user', messageId: 'm1', parts: [{ kind: 'text', text: 'hi' }] };

// ---- constants -------------------------------------------------------------------------------------------------------
await o.run('constants', 'all', () => ({
  PCA_A2A_EXTENSION_URI: M.PCA_A2A_EXTENSION_URI, TASK_STATE_AUTH_REQUIRED: M.TASK_STATE_AUTH_REQUIRED, TASK_STATE_INPUT_REQUIRED: M.TASK_STATE_INPUT_REQUIRED,
  A2A_AP2_CONTEXT: M.A2A_AP2_CONTEXT, A2A_RECEIPT_DOMAIN: M.A2A_RECEIPT_DOMAIN, RECEIPT_KEY: M.RECEIPT_KEY,
}), []);

// ---- jcsBytes ----------------------------------------------------------------------------------------------------------
const jcsVals: any[] = [...HOSTILE, { b: 1, a: [1, 2, { z: null, y: 'é' }] }, { '': 1, '😀': 2, a: 3 }, { '10': 1, '9': 2, '': 3 }, [[[]]], 'a b\u007f\u001f"\\/',
  { a: 1e-7, b: 123456789012345680000, c: 0.1, d: 1e21, e: -1e-7, f: 5e-324, g: 1.7976931348623157e308 }, { nested: { a: { b: { c: 1 } } } },
  { 'a\ud800': 1 }, [-0, 0], 1e300, -1e300, 4.35, 100, 1e5, 123456.789];
for (const [i, v] of jcsVals.entries()) await o.run('jcsBytes', `v${i}`, M.jcsBytes, [v]);
let deep: any = 1;
for (let i = 0; i < 70; i++) deep = [deep];
for (const n of [63, 64, 65, 70]) { let d: any = 1; for (let i = 0; i < n; i++) d = { a: d }; await o.run('jcsBytes', `deep${n}`, M.jcsBytes, [d]); }
await o.run('jcsBytes', 'deepArr', M.jcsBytes, [deep]);
for (const [i, v] of jcsVals.entries()) await o.run('jcsBytes', `obj${i}`, M.jcsBytes, [{ k: v }]);

// ---- validateAgentCard1 ---------------------------------------------------------------------------------------------
await o.run('validateAgentCard1', 'seed', M.validateAgentCard1, [CARD]);
for (const [hi, h] of HOSTILE.entries()) await o.run('validateAgentCard1', `top${hi}`, M.validateAgentCard1, [h]);
const FULL = { ...CARD, documentationUrl: 'https://d', iconUrl: 'https://i', provider: { url: 'https://p', organization: 'P' }, securitySchemes: { a: {} }, securityRequirements: [],
  signatures: [{ protected: 'AA', signature: 'BB', header: {} }],
  skills: [{ id: 's1', name: 'n', description: 'd', tags: [], examples: ['e'], inputModes: ['i'], outputModes: ['o'], securityRequirements: [] }] };
await o.run('validateAgentCard1', 'full', M.validateAgentCard1, [FULL]);
for (const [label, v] of variants(FULL, { depth: 4, maxPaths: 140 })) await o.run('validateAgentCard1', label, M.validateAgentCard1, [v]);

// ---- attach / extract ------------------------------------------------------------------------------------------------
const carriers: any[] = [TASK, MSG, {}, null, 5, 'abc', [], ['x'], { metadata: null }, { metadata: 'ab' }, { metadata: 5 }, { metadata: [1] }, { metadata: { [URI]: { old: 1 }, k: 2 } }, { metadata: false }, { id: 'z', metadata: { a: 1 }, status: { state: 'x' } }];
for (const [i, c] of carriers.entries()) {
  await o.run('attachPcaToA2ATask', `c${i}`, M.attachPcaToA2ATask, [c, PCA]);
  await o.run('attachPcaToA2AMessage', `c${i}`, M.attachPcaToA2AMessage, [c, PCA]);
  await o.run('extractPcaFromMessage', `c${i}`, (x: any) => M.extractPcaFromMessage(x) ?? null, [c]);
}
const P = { id: 'p' };
const ext: any[] = [
  { id: 't', metadata: { [URI]: P } }, { id: 't', status: { state: 's', message: { metadata: { [URI]: P } } } }, { id: 't', history: [{ metadata: { [URI]: { n: 1 } } }, { metadata: { [URI]: { n: 2 } } }, { x: 1 }] },
  { id: 't', metadata: { [URI]: [] } }, { id: 't', metadata: { [URI]: 'x' } }, { id: 't', metadata: { [URI]: null } }, { id: 't', status: null, history: null }, { id: 't', status: 'x' },
  { id: 't', status: [], history: {} }, { id: 't', history: [null, 5, 'x', { metadata: { [URI]: P } }] }, { id: 't', history: { length: 1e9 } }, { id: 't', status: { message: null } },
  { id: 't', metadata: { [URI]: P }, status: { message: { metadata: { [URI]: { other: 1 } } } } }, null, 5, 'x', [], {},
  { id: 't', status: { state: 's', message: { metadata: { [URI]: { s: 1 } } } }, history: [{ metadata: { [URI]: { h: 1 } } }] },
];
for (const [i, t] of ext.entries()) await o.run('extractPca', `t${i}`, (x: any) => M.extractPca(x) ?? null, [t]);

// ---- verification refused before the verifier ------------------------------------------------------------------------
const wrapO = (x: any) => (x === undefined ? undefined : { ...x });
const mkOpts = (x: any) => { const { require: _r, ...rest } = x ?? {}; return rest; };
const PRE = /^(no proof-carrying|proof-carrying action required|PCActn is not|PCActn carries no|chain root issuer|payment mandate|context\.params|the PCActn params|malformed payment mandate)/;
const keepRefused = async (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => {
  const a = JSON.parse(JSON.stringify(args));
  let r: any;
  try { r = await ref(...a); } catch { r = { $throws: true }; }
  const reason = r?.reason ?? r?.chains !== undefined ? r?.reason : undefined;
  const ok = r && r.$throws ? true : r?.ok === true && !r?.result ? true : typeof r?.reason === 'string' && (PRE.test(r.reason) || r.reason === 'no_hops' || /^(task_not_auth_required|no_valid_need|answer_not_bound_to_need|no_proof|action_mismatch)$/.test(r.reason));
  void reason;
  if (!ok) return false;
  return o.run(fn, name, ref, args);
};
const AUTH_OPTS = [{ aud: 'rs-1', expectedRootIssuer: 'ROOT', now: T0 }, { aud: 'rs-1', expectedRootIssuer: 'OTHER', now: T0 }, { aud: 'rs-1', now: T0 }, { aud: 'rs-1', expectedRootIssuer: '', now: T0 }, { aud: 'rs-1', grant: { id: 'g1' }, now: T0 }];
const tasksV: any[] = [
  TASK, { ...TASK, metadata: { [URI]: PCA } }, { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: [] } } }, { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: undefined } } },
  { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: ['x'] } } }, { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: [null] } } }, { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: [{ id: 'g1' }] } } },
  null, {}, { id: 't', history: [{ metadata: { [URI]: PCA } }] }, { id: 't', status: { message: { metadata: { [URI]: PCA } } } },
];
for (const [i, t] of tasksV.entries()) for (const [j, op] of AUTH_OPTS.entries()) {
  await keepRefused('verifyA2ATask', `t${i}o${j}`, (task: any, x: any) => M.verifyA2ATask(task, mkOpts(x)), [t, op]);
  await keepRefused('middleware', `t${i}o${j}`, (task: any, x: any) => M.pcaA2AMiddleware({ ...mkOpts(x), ...(x.require === false ? { require: false } : {}) })(task), [t, op]);
  await keepRefused('middleware', `t${i}o${j}r0`, (task: any, x: any) => M.pcaA2AMiddleware({ ...mkOpts(x), ...(x.require === false ? { require: false } : {}) })(task), [t, { ...op, require: false }]);
}
await o.run('verifyA2ATask', 'noauthority', (t: any) => M.verifyA2ATask(t, { aud: 'rs-1' }), [TASK]);
await o.run('verifyA2ATask', 'noauthority2', (t: any) => M.verifyA2ATask(t, { aud: 'rs-1', expectedRootIssuer: '' }), [{ ...TASK, metadata: { [URI]: PCA } }]);
await o.run('middleware', 'noauthority', (t: any) => M.pcaA2AMiddleware({ aud: 'rs-1' })(t), [TASK]);

// ---- AUTH_REQUIRED ---------------------------------------------------------------------------------------------------------
const needs: any[] = [NEED, { v: 1, kind: 'escalate', verb: 'v', resource: 'r', tier: 3, discharges: [{ issuer: 'https://i', claim: 'kyc' }] }, { ...NEED, v: 2 }, { ...NEED, scopes: ['a b'] }, null, 5, {}, { ...NEED, extra: 1 },
  { v: 1, kind: 'grant', verb: 'v', resource: 'r', grant_ref: 'g' }, { v: 1, kind: 'discharge', verb: 'v', resource: 'r', policy_digest: 'p' }, { ...NEED, resource: 'x'.repeat(2000) }];
for (const [i, n] of needs.entries()) {
  for (const [j, op] of [{ messageId: 'm1', now: T0 }, { messageId: 'm2', now: T0, text: 'custom text' }, { messageId: 'm3', now: NaN }, { messageId: 'm4', now: 8.64e15 + 1 }, { messageId: 'm5', now: -1 }, { messageId: 'm6', now: 253402300800000 }, { messageId: 'm7', now: 1.5 }].entries()) {
    await o.run('authRequiredStatus', `n${i}o${j}`, M.authRequiredStatus, [n, Number.isNaN(op.now) ? { ...op, now: 'x' } : op]);
  }
  await o.run('answerMessage', `n${i}`, (nn: any, p: any, id: any) => M.answerMessage(nn, p, id), [n, PCA, 'm9']);
}
const statuses: any[] = [];
for (const n of needs.slice(0, 2)) statuses.push({ id: 't', status: M.authRequiredStatus(n, { messageId: 'm', now: T0 }) });
const parkedMd = (v: any) => ({ id: 't', status: { state: 'TASK_STATE_AUTH_REQUIRED', message: { metadata: { [M.PCA_A2A_EXTENSION_URI + '#need']: v } } } });
const encNeed = core.encodePcaNeed(NEED);
for (const s of [...statuses, parkedMd(encNeed), parkedMd('###'), parkedMd(''), parkedMd(5), parkedMd(null), parkedMd(encNeed + '='), parkedMd('A'.repeat(2049)), TASK, null, {}, { status: 5 }, { status: { message: 5 } }, { status: { message: { metadata: 5 } } }])
  await o.run('readAuthRequiredNeed', 'x' + o.cases.length, (t: any) => M.readAuthRequiredNeed(t) ?? null, [s]);
for (const [i, s] of [TASK.status.state, 'TASK_STATE_AUTH_REQUIRED', 'auth-required', 'TASK_STATE_INPUT_REQUIRED', null, 5, '', 'AUTH-REQUIRED'].entries()) await o.run('isAuthRequired', `s${i}`, M.isAuthRequired, [s]);

const digest = core.pcaNeedDigest(NEED);
const gateCases: any[] = [];
for (const state of ['TASK_STATE_AUTH_REQUIRED', 'auth-required', 'TASK_STATE_INPUT_REQUIRED', null, 5])
  for (const needEncoded of [encNeed, undefined, '', 'x', 5, null, encNeed + '=', b64u(Buffer.from('{}'))])
    for (const answerNeedDigest of [digest, undefined, 'x', null, 5])
      for (const proofAction of [undefined, { verb: 'pay', resource: 'merchant/1' }, { verb: 'pay', resource: 'other' }, { verb: 'x', resource: 'merchant/1' }, {}, { verb: 5, resource: 'merchant/1' }, 'str', 5, null, { verb: 'pay' }])
        gateCases.push({ state, needEncoded, answerNeedDigest, proofAction });
for (const [i, g] of gateCases.entries()) await o.run('resumeGate', `g${i}`, (x: any) => M.resumeGate(x), [g]);

// resume flow: the full path up to (not into) the verifier
const parked = { id: 't1', status: { state: 'TASK_STATE_AUTH_REQUIRED', message: { metadata: { [URI + '#need']: encNeed } } } };
const answer = (p: any, d: any) => ({ role: 'user', messageId: 'a', metadata: { [URI]: p, [URI + '#need']: d } });
const pAct = { ...PCA, action: { verb: 'pay', resource: 'merchant/1', params_digest: 'dd' } };
const resumes: any[] = [
  [parked, answer(pAct, digest)], [parked, answer(pAct, 'wrong')], [parked, answer({ ...pAct, action: { verb: 'x', resource: 'merchant/1' } }, digest)], [parked, answer(undefined, digest)],
  [{ ...parked, status: { state: 'TASK_STATE_INPUT_REQUIRED', message: parked.status.message } }, answer(pAct, digest)], [{ id: 't' }, answer(pAct, digest)], [null, answer(pAct, digest)], [parked, null], [parked, 'x'],
  [parked, answer({ ...pAct, cap_chain: [] }, digest)], [parked, { metadata: null }], [parked, answer({ ...pAct, action: null }, digest)], [parked, answer({ ...pAct, action: 'str' }, digest)],
  [{ ...parked, status: { state: 'auth-required', message: parked.status.message } }, answer(pAct, digest)],
];
for (const [i, r] of resumes.entries()) for (const [j, op] of AUTH_OPTS.entries()) {
  await keepRefused('resumeAuthRequired', `r${i}o${j}`, (t: any, a: any, x: any) => M.resumeAuthRequired(t, a, mkOpts(x)), [r[0], r[1], op]);
}

// ---- extension declaration ---------------------------------------------------------------------------------------------
const params: any[] = [{ aud: 'https://a.example' }, { aud: 'a', suites: ['ed25519'], policy_digest: 'p' }];
for (const [i, p] of params.entries()) { await o.run('pcaExtensionDeclaration', `p${i}`, M.pcaExtensionDeclaration, [p]); await o.run('pcaExtensionDeclaration', `p${i}f`, M.pcaExtensionDeclaration, [p, false]); }
const decl = (p: any, extra: any = {}) => ({ capabilities: { extensions: [{ uri: URI, description: 'd', required: true, params: p, ...extra }] } });
const grantDetail = { type: 'pca_grant', chain_digest: core.pcaChainDigest(['c1']), chain_len: 1 };
const declCards: any[] = [
  CARD, decl({ aud: 'a' }), decl({ aud: 'a', suites: ['x'] }), decl({ aud: 'a', suites: [] }), decl({ aud: 'a', suites: [''] }), decl({ aud: 'a', suites: [1] }), decl({ aud: 'a', suites: Array.from({ length: 17 }, () => 's') }),
  decl({ aud: 'a', suites: ['s'.repeat(65)] }), decl({ aud: '' }), decl({ aud: 'a'.repeat(513) }), decl({ aud: 'a'.repeat(512) }), decl({}), decl(null), decl('x'), decl([]), decl({ aud: 'a', extra: 1 }),
  decl({ aud: 'a', policy_digest: '' }), decl({ aud: 'a', policy_digest: 'p'.repeat(129) }), decl({ aud: 'a', policy_digest: 5 }), decl({ aud: 'a', grants: [grantDetail] }), decl({ aud: 'a', grants: [] }),
  decl({ aud: 'a', grants: 'x' }), decl({ aud: 'a', grants: [{ type: 'pca_grant' }] }), decl({ aud: 'a', grants: [{ type: 'other' }, grantDetail] }), decl({ aud: 'a', grants: null }),
  decl({ aud: 'a' }, { required: 'yes' }), decl({ aud: 'a' }, { required: false }), decl({ aud: 'a' }, { required: null }),
  { capabilities: { extensions: [] } }, { capabilities: {} }, { capabilities: null }, {}, null, 5, [],
  { capabilities: { extensions: [{ uri: 'other', params: { aud: 'a' } }] } }, { capabilities: { extensions: [null, 5, { uri: URI, params: { aud: 'a' } }] } },
  { capabilities: { extensions: [{ uri: URI, params: { aud: 'a' } }, { uri: URI, params: { aud: 'b' } }] } }, { capabilities: { extensions: 'x' } },
];
for (const [i, c] of declCards.entries()) await o.run('readPcaExtension', `c${i}`, M.readPcaExtension, [c]);
const hdrs: any[] = [URI, `a, ${URI}`, `${URI},b`, ` ${URI} `, `\t${URI} `, `${URI}x`, '', 5, null, [URI], `x,,${URI}`, `${URI.toUpperCase()}`, ` ${URI}﻿`, `\u0085${URI}`, `${URI}/`];
for (const [i, h] of hdrs.entries()) await o.run('clientOptsIntoPca', `h${i}`, M.clientOptsIntoPca, [h]);

// ---- chain extension -------------------------------------------------------------------------------------------------------
const chainSets: any[] = [[['a'], ['a', 'b']], [['a', 'b'], ['a', 'b']], [['a'], ['a', 'b'], ['a', 'b', 'c']], [['a']], [['a', 'b'], ['x', 'b', 'c']], [['a', 'b'], ['a']], [[]], [['a'], []], [], [['a'], 'x'], [['a'], null],
  [[1], [1, 2]], [[1], ['1', 2]], [['a'], ['a', 'b'], ['a']], [[null], [null, 'x']], 'x', null, [5], [['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd']]];
for (const [i, c] of chainSets.entries()) await o.run('checkChainExtension', `c${i}`, M.checkChainExtension, [c]);
for (const [i, [a, b]] of [[['a'], ['a', 'b']], [['a', 'b'], ['a']], [[], []], [[], ['a']], [['a'], ['b']], [[1], [1]], [[1], ['1']]].entries()) await o.run('chainExtends', `e${i}`, M.chainExtends, [a, b]);

// ---- delegation (refused before the verifier) ---------------------------------------------------------------------------------
const hopSets: any[] = [[], [{ task: TASK, opts: AUTH_OPTS[0] }], [{ task: { ...TASK, metadata: { [URI]: PCA } }, opts: AUTH_OPTS[1] }], [{ task: TASK, opts: AUTH_OPTS[1] }, { task: TASK, opts: AUTH_OPTS[0] }],
  [{ task: { ...TASK, metadata: { [URI]: { ...PCA, cap_chain: [] } } }, opts: AUTH_OPTS[0] }]];
for (const [i, h] of hopSets.entries()) await keepRefused('verifyA2ADelegation', `h${i}`, (hops: any[]) => M.verifyA2ADelegation(hops.map((x) => ({ task: x.task, opts: mkOpts(x.opts) }))), [h]);
await o.run('verifyA2ADelegation', 'noauth', (hops: any[]) => M.verifyA2ADelegation(hops), [[{ task: TASK, opts: { aud: 'x' } }]]);

// ---- push --------------------------------------------------------------------------------------------------------------------------
const SALT = 'a-secret-salt-16+chars';
for (const [i, [id, ids, salt]] of ([['t1', ['capA', 'capB'], SALT], ['t1', ['capA'], SALT], ['t2', ['capA', 'capB'], SALT], ['t1', [], SALT], ['', ['x'], SALT], ['t1', ['x'], ''], ['t1', ['x'], 'short'], ['t1', ['x'], 'fifteen-chars!!'], ['t1', ['x'], 'sixteen-chars!!!!'], ['t1', ['x'], 5], ['t1', ['x'], null], [5, ['x'], SALT], ['é', ['é'], 'é'.repeat(16)]] as any[]).entries())
  await o.run('pcaPushToken', `t${i}`, M.pcaPushToken, [id, ids, salt]);
const tok = M.pcaPushToken('t1', ['capA', 'capB'], SALT);
const upd = (id: string) => ({ statusUpdate: { taskId: id, status: { state: 'TASK_STATE_COMPLETED' } } });
const exp = { taskId: 't1', chainIds: ['capA', 'capB'], salt: SALT };
const pushCases: any[] = [
  [exp, { token: tok, payload: upd('t1') }], [exp, { token: tok, payload: { task: { id: 't1' } } }], [exp, { token: tok, payload: { artifactUpdate: { taskId: 't1' } } }], [exp, { token: undefined, payload: upd('t1') }], [exp, { token: '', payload: upd('t1') }],
  [exp, { token: M.pcaPushToken('t2', ['capA', 'capB'], SALT), payload: upd('t1') }], [exp, { token: M.pcaPushToken('t1', ['capA'], SALT), payload: upd('t1') }], [exp, { token: tok, payload: upd('t2') }], [exp, { token: tok, payload: 'x' }],
  [exp, { token: tok, payload: {} }], [exp, { token: tok, payload: null }], [exp, { token: tok, payload: { task: null, statusUpdate: upd('t1').statusUpdate } }], [exp, { token: tok, payload: { task: { id: null }, statusUpdate: { taskId: 't1' } } }],
  [exp, { token: tok, payload: { task: 5, artifactUpdate: { taskId: 't1' } } }], [exp, { token: 5, payload: upd('t1') }], [exp, { token: tok + 'x', payload: upd('t1') }], [{ ...exp, salt: 'short' }, { token: tok, payload: upd('t1') }], [{ ...exp, salt: 'short' }, { token: '', payload: upd('t1') }],
  [exp, { payload: upd('t1') }], [exp, { token: tok, payload: { task: { id: 't1' }, statusUpdate: { taskId: 't2' } } }], [exp, { token: tok, payload: { task: { id: 5 } } }],
];
for (const [i, c] of pushCases.entries()) await o.run('checkPushNotification', `c${i}`, M.checkPushNotification, c);
await o.run('uniformTaskNotFound', 'x', M.uniformTaskNotFound, []);

// ---- receipts ----------------------------------------------------------------------------------------------------------------------
const IDS = ['capA', 'capB'];
const signR = (label: string, x: any) => M.signTaskReceipt(seed(label), x);
await o.run('signTaskReceipt', 'warm', (l: string, x: any) => signR(l, x), ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }]);
const r0 = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_SUBMITTED', chainIds: IDS, issuedAt: T0 });
const r1 = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 + 1, prev: r0 });
const r2 = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_COMPLETED', chainIds: IDS, issuedAt: T0 + 2, prev: r1 });
const rF = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_FAILED', chainIds: IDS, issuedAt: T0 + 2, prev: r1 });
const signCases: any[] = [
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_SUBMITTED', chainIds: IDS, issuedAt: T0 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 + 1, prev: r0 }],
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_COMPLETED', chainIds: IDS, issuedAt: T0 + 2, prev: r1 }], ['a2a/r2', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }],
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0, prev: r2 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0, prev: rF }],
  ['a2a/r1', { taskId: 't2', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0, prev: r0 }], ['a2a/r1', { taskId: '', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }],
  ['a2a/r1', { taskId: 'x'.repeat(256), state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }], ['a2a/r1', { taskId: 'x'.repeat(257), state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }],
  ['a2a/r1', { taskId: 't1', state: 'BOGUS', chainIds: IDS, issuedAt: T0 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: [], issuedAt: T0 }],
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: -1 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: 1.5 }],
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: 2 ** 53 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: 0 }],
  ['a2a/r1', { taskId: 5, state: 'TASK_STATE_WORKING', chainIds: IDS, issuedAt: T0 }], ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_AUTH_REQUIRED', chainIds: ['a'], issuedAt: T0 }],
  ['a2a/r1', { taskId: 't1', state: 'TASK_STATE_INPUT_REQUIRED', chainIds: ['é'], issuedAt: T0 }],
];
for (const [i, c] of signCases.entries()) await o.run('signTaskReceipt', `c${i}`, (l: string, x: any) => signR(l, x), c);

const SIGNER = signerOf('a2a/r1');
const mut = (r: any, k: string, v: any) => ({ ...r, [k]: v });
const rcpts: any[] = [r0, r1, r2, rF, mut(r0, 'sig', 'A'.repeat(86)), mut(r0, 'v', 2), mut(r0, 'signer', signerOf('a2a/r2')), mut(r0, 'task_id', 'x'), mut(r0, 'state', 'BOGUS'), mut(r0, 'seq', 1), mut(r1, 'seq', 0), mut(r1, 'prev', null),
  mut(r0, 'prev', r0.chain), mut(r0, 'chain', 'short'), mut(r0, 'issued_at', -1), mut(r0, 'issued_at', 1.5), mut(r0, 'task_id', ''), mut(r0, 'task_id', 'x'.repeat(4097)), mut(r0, 'sig', 5), mut(r0, 'sig', undefined),
  { ...r0, extra: 1 }, null, 5, 'x', [], {}, mut(r0, 'seq', -0), mut(r0, 'state', 5), (() => { const { sig, ...rest } = r0; return rest; })()];
for (const [i, r] of rcpts.entries()) {
  await o.run('verifyTaskReceipt', `r${i}`, M.verifyTaskReceipt, [r, SIGNER]);
  await o.run('receiptDigest', `r${i}`, (x: any) => M.receiptDigest(x), [r]);
}
await o.run('verifyTaskReceipt', 'wrongsigner', M.verifyTaskReceipt, [r0, signerOf('a2a/r2')]);
const copt = { signer: SIGNER, taskId: 't1', chainIds: IDS };
const chainsR: any[] = [[r0, r1, r2], [r0, r1], [r0], [r0, r1, rF], [], [r1], [r0, r2], [r0, r0], [r0, r1, r2, r1], [r2], [rF], [r0, mut(r1, 'sig', 'A'.repeat(86))], [r0, 'x'], null, 'x', [r0, r1, mut(r2, 'chain', r0.prev ?? r0.chain)],
  (() => { const o2 = signR('a2a/r1', { taskId: 't9', state: 'TASK_STATE_SUBMITTED', chainIds: IDS, issuedAt: T0 }); return [o2]; })(),
  (() => { const o2 = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_SUBMITTED', chainIds: ['other'], issuedAt: T0 }); return [o2]; })(),
  (() => { const done = signR('a2a/r1', { taskId: 't1', state: 'TASK_STATE_COMPLETED', chainIds: IDS, issuedAt: T0 }); return [done]; })()];
for (const [i, c] of chainsR.entries()) {
  await o.run('checkReceiptChain', `c${i}`, M.checkReceiptChain, [c, copt]);
  await o.run('mayTriggerNext', `c${i}`, M.mayTriggerNext, [c, copt]);
  await o.run('checkReceiptChain', `c${i}w`, M.checkReceiptChain, [c, { ...copt, taskId: 'other' }]);
  await o.run('checkReceiptChain', `c${i}x`, M.checkReceiptChain, [c, { ...copt, chainIds: ['zzz'] }]);
}
for (const [i, c] of [TASK, MSG, null, 5, {}, { metadata: null }, { metadata: { a: 1 } }].entries()) await o.run('attachReceipt', `c${i}`, M.attachReceipt, [c, r0]);
const RK = M.RECEIPT_KEY;
const pays: any[] = [{ statusUpdate: { metadata: { [RK]: r0 } } }, { task: { metadata: { [RK]: r1 } } }, { message: { metadata: { [RK]: r2 } } }, { statusUpdate: { metadata: {} }, task: { metadata: { [RK]: r1 } } }, { statusUpdate: { metadata: { [RK]: null } } },
  {}, null, 5, 'x', [], { statusUpdate: 5 }, { statusUpdate: { metadata: 5 } }, { statusUpdate: { metadata: { [RK]: 'x' } }, task: { metadata: { [RK]: r1 } } }];
for (const [i, p] of pays.entries()) await o.run('receiptOfPayload', `p${i}`, (x: any) => M.receiptOfPayload(x) ?? null, [p]);

// ---- extended card ----------------------------------------------------------------------------------------------------------------
const env = (verb: string, status: string, policyDigest = 'pd1') => ({ verb, status, policyDigest });
const hidden = [{ id: 'h1', tags: ['pca-verb:pay'] }, { id: 'h2', tags: ['pca-verb:wire', 'x'] }, { id: 'h3', tags: ['other'] }, { id: 'h4' }, { id: 'h5', tags: ['pca-verb:none'] }, { id: 'h6', tags: [5, 'pca-verb:pay'] }];
const exCases: any[] = [
  { authenticated: true, hiddenSkills: hidden, envelopes: [env('pay', 'autonomous'), env('wire', 'needs-approval')] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [env('pay', 'denied'), env('wire', 'needs-approval')] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [env('pay', 'weird')] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [] }, { authenticated: true, hiddenSkills: [], envelopes: [env('pay', 'autonomous')] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [env('pay', 'autonomous', 'a'), env('wire', 'autonomous', 'b')] },
  { authenticated: false, hiddenSkills: hidden, envelopes: [] }, { authenticated: 'yes', hiddenSkills: [], envelopes: [] }, { hiddenSkills: [], envelopes: [] },
  { authenticated: true, hiddenSkills: [{ id: 'x', tags: 'pca-verb:pay' }], envelopes: [env('pay', 'autonomous')] }, { authenticated: true, hiddenSkills: [{ id: 'x', tags: null }], envelopes: [env('pay', 'autonomous')] },
  { authenticated: true, hiddenSkills: [null], envelopes: [env('pay', 'autonomous')] }, { authenticated: true, hiddenSkills: ['str', 5], envelopes: [env('pay', 'autonomous')] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [null] }, { authenticated: true, hiddenSkills: hidden, envelopes: [{ verb: 'pay', status: 'autonomous' }] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [env('pay', 'autonomous'), env('pay', 'denied')] }, { authenticated: true, hiddenSkills: hidden, envelopes: [{ verb: 'pay', status: 'autonomous', policyDigest: null }] },
  { authenticated: true, hiddenSkills: hidden, envelopes: [{ verb: 5, status: 'autonomous', policyDigest: 'p' }] },
];
const publicCards: any[] = [CARD, { ...CARD, signatures: [{ protected: 'a', signature: 'b' }] }, { ...CARD, capabilities: { extensions: [{ uri: URI, params: { aud: 'a', old: 1 } }, { uri: 'other' }] } },
  { ...CARD, capabilities: { extensions: [{ uri: URI }] } }, { ...CARD, capabilities: null }, { ...CARD, capabilities: 'x' }, { ...CARD, capabilities: { extensions: 'x' } }, { ...CARD, skills: undefined },
  { ...CARD, skills: 'x' }, { name: 'bare' }, {}, { ...CARD, capabilities: { extensions: [null] } }, { ...CARD, capabilities: { extensions: [5, { uri: URI, params: 'p' }] } }, { ...CARD, capabilities: { other: 1, extensions: [{ uri: URI, params: null }] } }];
for (const [i, c] of exCases.entries()) for (const [j, pc] of publicCards.entries()) await o.run('extendedAgentCard', `e${i}c${j}`, M.extendedAgentCard, [pc, c]);
await o.run('extendedAgentCard', 'nullcard', M.extendedAgentCard, [null, exCases[0]]);

// ---- signed agent cards -----------------------------------------------------------------------------------------------------------
const issueOpts: any[] = [];
for (const profile of [undefined, 'pca-detached', 'a2a-1.0']) for (const kid of [undefined, 'k1', '']) for (const passport of [undefined, { id: 'p1' }, { id: 'p1', uri: 'https://p.example/p1' }, { id: 'p1', uri: undefined }, {}]) for (const schema of [undefined, 'a2a-1.0'])
  issueOpts.push({ ...(profile ? { profile } : {}), ...(kid !== undefined ? { kid } : {}), ...(passport ? { passport } : {}), ...(schema ? { schema } : {}) });
const issueCards: any[] = [CARD, { ...CARD, pcaPassport: { id: 'pc' } }, { ...CARD, pcaPassport: { id: 'pc', uri: 'https://u' } }, { ...CARD, pcaPassport: 'weird' }, { ...CARD, description: undefined }, { name: 'n' }, { ...CARD, extra: { b: 2, a: 1 } },
  { ...CARD, signatures: [{ protected: 'a', signature: 'b' }] }, { ...CARD, signatures: 'ab' }, { ...CARD, signatures: 5 }, { ...CARD, signatures: null }, { ...CARD, name: 'é ' }, { ...CARD, big: 1e21 }, { ...CARD, bad: '\ud800' }, { ...CARD, f: 0.1 }];
for (const [ci, c] of issueCards.entries()) for (const [oi, op] of issueOpts.entries()) {
  if (ci > 1 && oi % 3 !== 0) continue; // keep the corpus small
  await o.run('issueSignedAgentCard', `c${ci}o${oi}`, (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [c, K1.priv, op]);
}
await o.run('issueSignedAgentCard', 'noopts', (card: any, k: any) => M.issueSignedAgentCard(card, k), [CARD, K1.priv]);
await o.run('issueSignedAgentCard', 'es256', (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [CARD, K1.priv, { alg: 'ES256' }]);
await o.run('issueSignedAgentCard', 'eddsa', (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [CARD, K1.priv, { alg: 'EdDSA' }]);
await o.run('issueSignedAgentCard', 'pubkey', (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [CARD, K1.pub, {}]);
await o.run('issueSignedAgentCard', 'algmismatch', (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [CARD, { ...K1.priv, alg: 'ES256' }, {}]);
await o.run('issueSignedAgentCard', 'algmatch', (card: any, k: any, x: any) => M.issueSignedAgentCard(card, k, x), [CARD, { ...K1.priv, alg: 'EdDSA' }, {}]);

// verification: cards signed by us (TS) and hand-built signatures
const issued: Record<string, any> = {};
for (const profile of ['pca-detached', 'a2a-1.0']) issued[profile] = await M.issueSignedAgentCard(CARD, K1.priv, { profile, kid: 'k1', passport: { id: 'p1', uri: 'https://p' } });
issued.plain = await M.issueSignedAgentCard(CARD, K1.priv, {});
const two = await M.issueSignedAgentCard(issued.plain, K2.priv, { kid: 'k2' });
const jwks = (...ks: any[]) => ({ keys: ks });
const withKid = (k: any, kid: string) => ({ ...k, kid });
const vopts: any[] = [{ key: K1.pub }, { key: K2.pub }, { jwks: jwks(withKid(K1.pub, 'k1')) }, { jwks: jwks(withKid(K1.pub, 'k1'), withKid(K2.pub, 'k2')) }, { jwks: jwks(K1.pub) }, { jwks: jwks(K1.pub, K2.pub) }, { jwks: jwks(withKid(K2.pub, 'k2')) },
  {}, { key: K1.pub, alg: 'EdDSA' }, { key: K1.pub, alg: 'ES256' }, { key: K1.pub, schema: 'a2a-1.0' }, { jwks: { keys: 'x' } }, { jwks: {} }, { jwks: { keys: [5] } }, { key: { kty: 'oct', k: 'AAAA' } }, { key: { kty: 'OKP', crv: 'Ed25519', x: 'AA' } },
  { key: K1.priv }, { jwks: jwks({ ...K1.pub, alg: 'ES256' }) }, { jwks: jwks({ ...K1.pub, use: 'enc' }) }, { jwks: jwks({ ...K1.pub, use: 'sig' }) }, { jwks: jwks({ ...K1.pub, key_ops: ['sign'] }) }, { jwks: jwks({ ...K1.pub, key_ops: ['verify'] }) },
  { key: K1.pub, jwks: jwks(K2.pub) }, { key: 'x' }, { key: K1.pub, alg: 'none' }, { jwks: jwks({ ...K1.pub, alg: 'EdDSA' }) }];
const vcards: any[] = [issued['pca-detached'], issued['a2a-1.0'], issued.plain, two, CARD, { ...issued.plain, name: 'tampered' }, { ...issued.plain, signatures: [] }, { ...issued.plain, signatures: [null] }, { ...issued.plain, signatures: [{}] },
  { ...issued.plain, signatures: [{ protected: 5, signature: 'x' }] }, { ...issued.plain, signatures: [issued.plain.signatures[0], issued.plain.signatures[0]] }, { ...issued.plain, signatures: [issued.plain.signatures[0], { protected: 'A', signature: 'A' }] },
  { ...issued.plain, signatures: [{ ...issued.plain.signatures[0], signature: issued.plain.signatures[0].signature + '=' }] }, { ...issued.plain, signatures: [{ ...issued.plain.signatures[0], signature: issued.plain.signatures[0].signature.slice(0, -2) }] },
  { ...issued.plain, signatures: [{ ...issued.plain.signatures[0], protected: issued.plain.signatures[0].protected + '=' }] }, { ...issued.plain, signatures: [{ ...issued.plain.signatures[0], header: { a: 1 } }] }, { ...issued.plain, bad: '\ud800' },
  { ...issued.plain, big: 1e21 }, { ...issued.plain, pcaPassport: { id: 'p9' } }, { ...issued['a2a-1.0'], pcaPassport: undefined }, { ...issued.plain, signatures: 'x' }, { ...issued.plain, signatures: {} }, null, 5, 'x', [], {}, { ...issued.plain, signatures: [{ protected: '', signature: '' }] }];
for (const [ci, c] of vcards.entries()) for (const [oi, op] of vopts.entries()) {
  if (ci > 4 && oi > 12) continue;
  await o.run('verifyAgentCard', `c${ci}o${oi}`, async (card: any, x: any) => norm(await M.verifyAgentCard(card, x)), [c, op]);
}
// hand-built protected headers (the JOSE rules)
const payload = Buffer.from(M.jcsBytes((({ signatures: _s, ...rest }: any) => rest)(CARD)));
const hdrs2: any[] = [{ alg: 'EdDSA' }, { alg: 'EdDSA', b64: false }, { alg: 'EdDSA', b64: false, crit: ['b64'] }, { alg: 'EdDSA', crit: ['b64'] }, { alg: 'EdDSA', crit: ['b64'], b64: true }, { alg: 'EdDSA', crit: ['b64'], b64: 'x' }, { alg: 'EdDSA', crit: ['foo'], foo: 1 },
  { alg: 'EdDSA', crit: [] }, { alg: 'EdDSA', crit: 'b64', b64: false }, { alg: 'EdDSA', crit: [''], b64: false }, { alg: 'EdDSA', crit: [5], b64: false }, { alg: '' }, {}, { alg: 5 }, { alg: 'ES256' }, { alg: 'none' }, { alg: 'HS256' }, { alg: 'EdDSA', typ: 'JOSE', kid: 'k1' },
  { alg: 'EdDSA', kid: 'k2' }, { alg: 'EdDSA', kid: 5 }, { alg: 'EdDSA', pca_passport: 'p1', b64: false, crit: ['b64'] }, { alg: 'EdDSA', crit: ['b64', 'b64'], b64: false }, { alg: 'EdDSA', crit: ['b64', 'foo'], b64: false, foo: 1 }, { alg: 'EdDSA', b64: null, crit: ['b64'] }];
function manual(h: any, b64: boolean | undefined, signWith = K1.ko) {
  const prot = Buffer.from(JSON.stringify(h)).toString('base64url');
  const body = b64 === false ? payload : Buffer.from(b64u(payload));
  const sig = edSign(null, Buffer.concat([Buffer.from(prot + '.'), body]), signWith);
  return { protected: prot, signature: b64u(sig) };
}
for (const [hi, h] of hdrs2.entries()) for (const [bi, bb] of ([false, true] as const).entries()) {
  const card = { ...CARD, signatures: [manual(h, bb)] };
  for (const [oi, op] of [{ key: K1.pub }, { jwks: jwks(withKid(K1.pub, 'k1')) }, { jwks: jwks(withKid(K1.pub, 'k1'), withKid(K2.pub, 'k2')) }].entries()) await o.run('verifyAgentCard', `h${hi}b${bi}o${oi}`, async (c: any, x: any) => norm(await M.verifyAgentCard(c, x)), [card, op]);
}
for (const [i, raw] of ['{"alg":"EdDSA","alg":"EdDSA"}', '[]', '5', 'null', '{"alg":"EdDSA"} ', '﻿{"alg":"EdDSA"}', '{"alg":"EdDSA"'].entries()) {
  const prot = Buffer.from(raw).toString('base64url');
  const sig = edSign(null, Buffer.concat([Buffer.from(prot + '.'), Buffer.from(b64u(payload))]), K1.ko);
  await o.run('verifyAgentCard', `raw${i}`, async (c: any, x: any) => norm(await M.verifyAgentCard(c, x)), [{ ...CARD, signatures: [{ protected: prot, signature: b64u(sig) }] }, { key: K1.pub }]);
}
const ws = manual({ alg: 'EdDSA' }, true, K2.ko);
await o.run('verifyAgentCard', 'wrongkeysig', async (c: any, x: any) => norm(await M.verifyAgentCard(c, x)), [{ ...CARD, signatures: [ws] }, { key: K1.pub }]);

// ---- payment mandate ---------------------------------------------------------------------------------------------------------------
const PAYPCA = { ...PCA, action: { verb: 'pay', resource: 'merchant/1', params_digest: 'dd' } };
const mopts: any[] = [
  { amount: { currency: 'USD', value: 1200 }, paymentMethod: { type: 'card', display: '**** 4242' }, now: T0 }, { amount: { currency: 'USD', value: 0 }, paymentMethod: { type: 'card' }, merchant: 'm1', now: T0 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanPresent: true, now: T0 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanPresent: false, now: T0 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, issuerPublic: 'ISS', now: T0 }, { amount: { currency: 'USD', value: -1 }, paymentMethod: { type: 'card' }, now: T0 },
  { amount: { currency: 'USD', value: 1.5 }, paymentMethod: { type: 'card' }, now: T0 }, { amount: { currency: 'USD', value: 2 ** 53 }, paymentMethod: { type: 'card' }, now: T0 }, { amount: { currency: 'USD', value: '5' }, paymentMethod: { type: 'card' }, now: T0 },
  { amount: { currency: 'USD', value: -0 }, paymentMethod: { type: 'card' }, now: T0 }, { amount: { currency: 'USD', value: 5 }, now: T0 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: NaN === 1 ? 0 : 8.64e15 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: 8.64e15 + 1 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: 253402300799999 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: 253402300800000 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: -62198755200000 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: -1 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, now: 1.9 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanSignerSet: [], now: T0 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanSignerSet: [{ role: 'agent', publicKey: 'H2' }], now: T0 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanSignerSet: 'x', now: T0 }, { paymentMethod: { type: 'card' }, now: T0 }, { amount: null, now: T0 }, { amount: { currency: 'USD', value: 5, extra: 1 }, paymentMethod: { type: 'card', token: 't' }, merchant: '', now: T0 },
  { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanPresent: 'yes', now: T0 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: { type: 'card' }, humanPresent: null, now: T0 }, { amount: { currency: 'USD', value: 5 }, paymentMethod: null, now: T0 },
];
const mpcas: any[] = [PAYPCA, { ...PAYPCA, cap_chain: [] }, { ...PAYPCA, cap_chain: undefined }, { ...PAYPCA, action: undefined }, { ...PAYPCA, action: { verb: 'pay' } }, { ...PAYPCA, aud: undefined }, { ...PAYPCA, cap_chain: [{ id: 'g', issuer: 'i', holder: null }] }, { ...PAYPCA, cap_chain: [{ id: 'g' }] }, { ...PAYPCA, cap_chain: ['x'] }, null, 5, 'x', {}];
for (const [pi, pc] of mpcas.entries()) for (const [oi, op] of mopts.entries()) {
  if (pi > 0 && oi % 4 !== 0) continue;
  await o.run('a2aPaymentMandateFromPca', `p${pi}o${oi}`, (p: any, x: any) => M.a2aPaymentMandateFromPca(p, x), [pc, op]);
}
const mandate = M.a2aPaymentMandateFromPca(PAYPCA, mopts[1]);
const mandate2 = M.a2aPaymentMandateFromPca(PAYPCA, { amount: { currency: 'USD', value: 1200 }, paymentMethod: { type: 'card', display: 'x' }, now: T0 });
for (const [i, m] of [mandate, mandate2, null, {}, { credentialSubject: null }, { credentialSubject: {} }, { credentialSubject: { x_pca: null } }, { credentialSubject: { x_pca: 'str' } }, { credentialSubject: { x_pca: { a: 1 } } }, 'x', [], { credentialSubject: 5 }].entries())
  await o.run('pcaBindingFromA2APaymentMandate', `m${i}`, M.pcaBindingFromA2APaymentMandate, [m]);

// verify: binding errors (the verifier is never reached)
const mctx = (params: any) => ({ params });
const PARAMS = { amount: 0, currency: 'USD', merchant: 'm1' };
const PARAMS2 = { amount: 1200, currency: 'USD' };
const mk = (p: any, x: any, m: any) => M.a2aPaymentMandateFromPca(p, { ...x, now: T0 });
const bind = (m: any, edit: (c: any) => any) => { const c = JSON.parse(JSON.stringify(m)); edit(c.credentialSubject); return c; };
const mandateVariants: any[] = [mandate, mandate2, bind(mandate, (c) => { c.x_pca.aud = 'other'; }), bind(mandate, (c) => { c.x_pca.verb = 'x'; }), bind(mandate, (c) => { c.x_pca.resource = 'x'; }), bind(mandate, (c) => { c.x_pca.params_digest = 'x'; }),
  bind(mandate, (c) => { c.x_pca.grant_ref = 'x'; }), bind(mandate, (c) => { c.x_pca.leaf_holder = 'x'; }), bind(mandate, (c) => { c.x_pca.leaf_holder = 5; }), bind(mandate, (c) => { delete c.x_pca.aud; }), bind(mandate, (c) => { c.x_pca = 'x'; }), bind(mandate, (c) => { delete c.x_pca; }),
  bind(mandate, (c) => { c.amount.value = 1; }), bind(mandate, (c) => { c.amount.value = 0.5; }), bind(mandate, (c) => { c.amount.value = -1; }), bind(mandate, (c) => { c.amount.currency = 'EUR'; }), bind(mandate, (c) => { c.amount.currency = 5; }), bind(mandate, (c) => { c.amount = null; }),
  bind(mandate, (c) => { c.merchant = 'other'; }), bind(mandate, (c) => { delete c.merchant; }), bind(mandate, (c) => { c.merchant = null; }), bind(mandate2, (c) => { c.merchant = 'x'; }), bind(mandate, (c) => { c.human_present = true; }), bind(mandate, (c) => { c.human_present = 'no'; }),
  bind(mandate, (c) => { delete c.human_present; }), bind(mandate, (c) => { c.payment_method = { type: 'other' }; }), bind(mandate, (c) => { delete c.payment_method; }), bind(mandate2, (c) => { c.payment_method = { type: 'card' }; })];
const pmParams = { amount: 0, currency: 'USD', merchant: 'm1', payment_method: { type: 'card' } };
const ctxs: any[] = [mctx(PARAMS), mctx(PARAMS2), mctx({ ...PARAMS, amount: -1 }), mctx({ ...PARAMS, amount: 1.5 }), mctx({ currency: 'USD' }), mctx({ amount: 0 }), mctx({ ...PARAMS, currency: 5 }), mctx({ ...PARAMS, merchant: 'zzz' }), mctx({ amount: 0, currency: 'USD' }),
  mctx(pmParams), mctx({ ...pmParams, payment_method: { type: 'other' } }), mctx({ ...pmParams, payment_method: null }), mctx({ ...PARAMS, merchant: null }), mctx({ ...PARAMS, amount: -0 }), mctx(null), mctx('x'), mctx([]), {}, mctx({ ...PARAMS2, merchant: { a: 1 } })];
const mcases = [] as any[];
for (const [mi, m] of mandateVariants.entries()) for (const [ci, c] of ctxs.entries()) mcases.push([`m${mi}c${ci}`, m, c]);
const vmo = (x: any) => { const { context, ...rest } = x; return { ...rest, ...(context !== undefined ? { context: () => context } : {}) }; };
let kept = 0;
for (const [name, m, c] of mcases) {
  for (const [oi, op] of [{ aud: 'rs-1', expectedRootIssuer: 'ROOT', now: T0, context: c }, { aud: 'rs-1', expectedRootIssuer: 'ROOT', now: T0, context: c, humanSignerSet: [] }].entries()) {
    if (oi > 0 && kept % 3 !== 0) continue;
    kept++;
    await keepRefused('verifyA2APaymentMandate', `${name}o${oi}`, async (mm: any, p: any, x: any) => norm(await M.verifyA2APaymentMandate(mm, p, vmo(x))), [m, PAYPCA, op]);
  }
}
for (const [pi, pc] of [mandate.credentialSubject ? null : null, 5, 'x', {}, { ...PAYPCA, cap_chain: [] }, { ...PAYPCA, aud: 'zz' }, [], { ...PAYPCA, action: { verb: 'pay' } }, { ...PAYPCA, cap_chain: [{ id: 'g1', issuer: 'ROOT', holder: 'H9' }] }].entries())
  await keepRefused('verifyA2APaymentMandate', `p${pi}`, async (mm: any, p: any, x: any) => norm(await M.verifyA2APaymentMandate(mm, p, vmo(x))), [mandate, pc, { aud: 'rs-1', expectedRootIssuer: 'ROOT', now: T0, context: mctx(PARAMS) }]);
await o.run('verifyA2APaymentMandate', 'noauthority', async (mm: any, p: any) => M.verifyA2APaymentMandate(mm, p, { aud: 'rs-1' }), [mandate, PAYPCA]);
void wrapO; void mk;

refWrite(o, 'a2a');
