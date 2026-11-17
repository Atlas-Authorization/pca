// Oracle (Java lane): @atlasauth/pca-ciba (CIBA on-ramp: binding message, auth request, gating, durable + in-memory brokers, KV store, client).
// Deterministic. Writes out/ref-ciba-java.json.gz. Args are the TS argument lists as JSON; a throw only requires the native to refuse.
// PORTING (fn -> native entry point, comparison rule)
//   cibaActionFromStepUp(stepUp)               Ciba.cibaActionFromStepUp           JSON equality
//   toCibaAuthRequest(stepUp[, opts])          Ciba.toCibaAuthRequest              JSON equality (numbers by value)
//   asciiForm(payee)                           Ciba.asciiForm                       exact string
//   requiresCiba(review)                       Ciba.requiresCiba                    boolean; a malformed review throws
//   cibaDecisionToCosign(decision, budget, policy, now[, opts])   Ciba.cibaDecisionToCosign   JSON equality
//   verifyPingCallback(input, flow)            CibaClient.verifyPingCallback(input.authorization, input.body, flow)   the auth_req_id | throw
//   createCibaClientConfig(cfg)                CibaClient.createCibaClient(config)  true | throw (cfg: the endpoints, clientId, secret, allowInsecureHttp, timeoutMs)
//   brokerScenario({kind, opts, steps})        kind memory | durable | durable-kv: the in-memory broker, the durable broker over an in-memory store, and over a
//                                              KV-backed store. The clock is scripted; every auth_req_id is random and is replaced by <ID1>, <ID2>.. in the trace.
//                                              Steps: start{stepUp,opts} poll{id} token{id} resolve{id,decision,by} get{id} advance{ms} storeSet{key,version,value}
//                                              (durable: replace a stored record) kvRaw{key,raw} (durable-kv: write raw text under a key). $id = last started flow,
//                                              $id1.. = by order. opts.onComplete: record | throws. A failure is {ok:false, msg[, code]} with the reference's message.
//   kvScenario({steps})                        get{key} cas{key,expected,value} kvSet{key,raw} kvGet{key}: createKvApprovalStore over the in-memory KV; trace of
//                                              {version,value} | null | boolean | {code}.
//   clientScenario({cfg, responses, steps})    scripted transport (responses consumed in order; {status, body: text|object} or {fail: true}), scripted clock and
//                                              sleep. Steps: initiate{stepUp,opts} poll wait notify advance{ms} interval. Trace per step: result or error
//                                              ({error,status,retryable,errorDescription} for a provider error, {other: true} otherwise), the requests sent and the sleeps.
//                                              A generated client_notification_token is replaced by <NTOKEN>.
import * as C0 from '@atlasauth/pca-ciba';
import * as P0 from '@atlasauth/pca';
import * as TST from '../../../packages/pca-ciba/src/testing.ts';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const P: any = (P0 as any).default ?? P0;
const T: any = (TST as any).default ?? TST;
const { createMemoryApprovalStore, createMemoryKv, createCibaBroker } = T;
const o = new Oracle('ciba', 'tools/pca-audit/oracles/ciba-java.mts', 'TS-reference oracle for the CIBA on-ramp (Java lane).');
const used = new Map<string, number>();
const run = (fn: string, name: string, ref: any, args: any[]) => { const k = `${fn}/${name}`; const n = (used.get(k) ?? 0) + 1; used.set(k, n); return o.run(fn, n === 1 ? name : `${name}~${n}`, ref, args); };
const T0 = 1_800_000_000_000;
const D = (l: string) => P.b64u(seed(`ref-ciba/${l}`));

const BASE = { id: 'su-1', verb: 'stripe.payout', resource: 'acct-1', tier: 3, reason: 'a large payout', goalCommit: 'abcdefghijklmnopqrstuvwxyz0123', lineage: {}, r: 0.9, requestedAt: T0 };
const SU = (over: any = {}) => ({ ...BASE, ...over });
const PAY = { amount: '80', currency: 'usd', payee: 'ACME Corp' };
const RENDER = { v: 1, kind: 'pca-approval-render', verb: 'stripe.payout', def_digest: D('def'), unreviewed: false,
  fields: [{ id: 'amount', class: 'money.amount', value: 8000, unit: { kind: 'money', ccy: 'USD', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'ACME Corp' }] };
const RD = P.approvalRenderDigest(RENDER);

// ---- the canonical action ----------------------------------------------------------------------------------------------------------
const A = (n: string, su: any) => run('cibaActionFromStepUp', n, C.cibaActionFromStepUp, [su]);
await A('plain', SU());
await A('params-undefined', SU({ params: undefined }));
await A('params-null', SU({ params: null }));
await A('params-empty', SU({ params: {} }));
await A('params-array', SU({ params: [] }));
await A('params-string', SU({ params: 'x' }));
await A('params-number', SU({ params: 5 }));
await A('full', SU({ params: PAY }));
for (const amt of ['80', '0', '0.5', '00', '01', '1.', '.5', '-1', '+1', '1e3', '', ' 1', '1 ', '1.50', '100000000000000000000', 80, 80.5, 0.1, 1e-7, 1e21, 123456789012345680000, -1, -0, 0, 1.5e-6, 0.000001, 1234567.891, true, false, null, [], {}, '٣'])
  await A(`amount ${JSON.stringify(amt)}`, SU({ params: { ...PAY, amount: amt } }));
for (const cur of ['usd', 'USD', 'Usd', 'us', 'usdx', '', 5, null, ' usd', 'us1', 'É', ['usd']]) await A(`currency ${JSON.stringify(cur)}`, SU({ params: { ...PAY, currency: cur } }));
await A('currency without amount', SU({ params: { currency: 'usd', payee: 'x' } }));
await A('currency null without amount', SU({ params: { currency: null, payee: 'x' } }));
await A('amount without payee', SU({ params: { amount: '5', currency: 'usd' } }));
await A('amount without currency', SU({ params: { amount: '5', payee: 'x' } }));
await A('payee only', SU({ params: { payee: 'x' } }));
for (const k of ['payee', 'to', 'recipient', 'beneficiary', 'destination']) await A(`payee key ${k}`, SU({ params: { amount: '5', currency: 'eur', [k]: 'Bob' } }));
await A('two payee keys', SU({ params: { ...PAY, to: 'Bob' } }));
await A('two payee keys one null', SU({ params: { ...PAY, to: null } }));
await A('unknown key', SU({ params: { ...PAY, memo: 'x' } }));
await A('unknown key null', SU({ params: { ...PAY, memo: null } }));
await A('unknown keys', SU({ params: { a: 1, b: 2 } }));
const PAYEES: any[] = ['ACME Corp', 'a', 'x'.repeat(64), 'x'.repeat(65), '', ' x', 'x ', 'a  b', 'a\tb', 'a\nb', 'a"b', 'a\\b', "a'b", 'because you asked', 'Because  YOU   Asked', 'x because you asked y',
  'user@example.com', 'a/b:c', 'École', 'école', 'Абв', 'Ромашка ООО', 'Pаypal', 'арре', 'Alpha α', 'Σίσυφος',
  '日本語', 'カタカナ', 'こんにちは', 'مرحبا', 'שלום', 'नमस्ते', 'Café', 'Straße', 'ＡＢＣ', 'ﬁ', '①', 'à́', '́',
  '​', 'a​b', '‮', 'a‮b', ' ', '­', '﻿', '\ud800', 'a\ud800', '', '￿', '͸', 'Café/evil.example', 'Café?x', 'Café%41', '\u0085', '\u007f', 'a\u0000b', 'x'.repeat(63) + 'é', 'x'.repeat(64) + 'é',
  '😀', 'ab12', '١٢٣', 'x-y_z.w', 5, null, true, {}, [], ['x']];
for (const [i, p] of PAYEES.entries()) await A(`payee ${i}`, SU({ params: { amount: '5', currency: 'eur', payee: p } }));
for (const v of ['stripe.payout', 'a', 'A1', 'a'.repeat(64), 'a'.repeat(65), '', ' a', 'a b', 'a\nb', '.a', '-a', 'a.b-c_d:e/f#g@h+i', 'a$', 'a,b', 'é', 5, null, ['a'], 'because you asked'])
  for (const k of ['verb', 'resource']) await A(`${k} ${JSON.stringify(v)}`, SU({ [k]: v }));
await A('verb missing', (() => { const s: any = SU(); delete s.verb; return s; })());
await A('resource missing', (() => { const s: any = SU(); delete s.resource; return s; })());

// ---- asciiForm -------------------------------------------------------------------------------------------------------------------
const ASCII: string[] = ['', 'ACME Corp', 'a b c', '~', 'Ромашка', 'Привет', 'Ёлка', 'Σίσυφος', 'Ελλάδα', '日本語', 'カタカナ',
  'Café', 'Straße', 'CAFÉ', 'مرحبا', 'שלום', 'नमस्ते', 'Привет мир', 'ααα βββ', 'ACME ООО', 'x é y',
  'Ромашка.рф', 'ПРИВЕТ-1', '日本。語', 'é%', 'é/x', 'é:x', 'é é', 'éééééééééé', 'abcédef', 'aé', 'éa', 'ü', 'über', 'München',
  'bücher', '中文', '한글', 'ไทย', 'აბგ', 'աբգ', 'é1', '1é', '-é', 'é/x', 'é?x', 'é#x', 'é%41', 'é%C3%A9', 'é%zz', 'é%', 'é.1', 'é.12a', 'é.', '.é', '/é', '?é', 'é:80', 'é@x', 'é|', 'é$', 'é!', 'İ', 'ǅ', 'éK', 'éµ', 'éⅠ', 'éΩ', 'éΣ', 'ẞ', 'é­', 'é​', 'é⁠', '1.é', 'é..é', 'é x', 'xéy.z', 'Café/evil', 'é-', 'é_é', 'ı', 'Iı', 'ς', 'Σ', 'abΣ'];
for (const [i, p] of ASCII.entries()) await run('asciiForm', `w${i}`, C.asciiForm, [p]);

// ---- the auth request --------------------------------------------------------------------------------------------------------------
const R = (n: string, su: any, opts?: any) => run('toCibaAuthRequest', n, C.toCibaAuthRequest, opts === undefined ? [su] : [su, opts]);
const PAYSU = SU({ params: PAY });
await R('plain', SU());
await R('pay', PAYSU);
await R('pay opts-empty', PAYSU, {});
await R('tier-2', SU({ tier: 2, params: PAY }));
await R('goal absent no commit', SU({ goalCommit: '' }));
await R('goal undefined', SU({ goal: undefined }));
for (const [n, g] of Object.entries<any>({ plain: 'Pay the vendor', empty: '', spaces: '   ', newline: 'a\nb\r\nc', tabs: 'a\t\tb', bidi: 'a‮b', zwsp: 'a​b', quotes: "it's ‘x’ ’y’", long: 'x'.repeat(100), longer: 'x'.repeat(101), long2: 'y '.repeat(80),
  because: 'because you asked me', unicode: 'Zahlung für München ☃', astral: '😀'.repeat(120), lone: 'a\ud800b', nbsp: 'a  b', ls: 'a b', nul: 'a\u0000b', emdash: 'a — b', trailing: 'x ', leading: ' x' }))
  await R(`goal ${n}`, SU({ goal: g, params: PAY }));
await R('goal null', SU({ goal: null }));
await R('goal number', SU({ goal: 5 }));
await R('commit short', SU({ goal: undefined, goalCommit: 'abc' }));
await R('commit 10', SU({ goal: undefined, goalCommit: 'abcdefghij' }));
await R('commit 11', SU({ goal: undefined, goalCommit: 'abcdefghijk' }));
await R('commit missing', (() => { const s: any = SU({ goal: undefined }); delete s.goalCommit; return s; })());
await R('commit null', SU({ goal: undefined, goalCommit: null }));
await R('commit number', SU({ goal: undefined, goalCommit: 5 }));
await R('commit empty goal empty', SU({ goal: '', goalCommit: 'zzzzzzzzzzzzzzzz' }));
for (const e of [undefined, 1, 5, 300, 301, 3600, 86400, 9007199254740991, 9007199254740992, 0, -1, 1.5, '300', null, true, [], 1e21, -0]) await R(`expiresInSec ${JSON.stringify(e)}`, SU(), e === undefined ? {} : { expiresInSec: e });
for (const e of [undefined, 1, 5, 30, 0, -5, 2.5, '5', null, 9007199254740991, 9007199254740992]) await R(`interval ${JSON.stringify(e)}`, SU(), e === undefined ? {} : { interval: e });
const ids = ['a'.repeat(22), 'a'.repeat(21), 'a'.repeat(1024), 'a'.repeat(1025), 'a-b_c.d'.repeat(4), 'a b'.repeat(8), 'a+b/c'.repeat(5), 'é'.repeat(22), '', 'a'.repeat(21) + '='];
for (const [i, id] of ids.entries()) await R(`authReqId ${i}`, SU(), { authReqId: id });
await R('authReqId null', SU(), { authReqId: null });
await R('authReqId derived stable', SU({ id: 'other-id' }));
await R('authReqId derived number id', SU({ id: 5 }));
await R('authReqId derived missing id', (() => { const s: any = SU(); delete s.id; return s; })());
await R('stepUpScope false', SU(), { stepUpScope: false });
await R('stepUpScope true', SU(), { stepUpScope: true });
await R('stepUpScope null', SU(), { stepUpScope: null });
await R('stepUpScope 0', SU(), { stepUpScope: 0 });
for (const v of ['a b', 'a\tb', 'a"b', 'a\\b', 'é', 'a\u007f', 'a!b', 'a#b', 'a[b', 'a]b']) await R(`scope verb ${JSON.stringify(v)}`, SU({ verb: v }));
await R('loginHint', SU(), { loginHint: 'alice@example.com' });
await R('loginHint empty', SU(), { loginHint: '' });
await R('loginHint null', SU(), { loginHint: null });
await R('loginHint number', SU(), { loginHint: 5 });
for (const a of ['support-bot', '', '   ', 'x'.repeat(40), 'x'.repeat(41), 'a\nb', 'because you asked', 'it’s', 'é'.repeat(45), null, 5, '‮']) await R(`actsFor ${JSON.stringify(a)}`, SU({ goal: 'Pay the vendor', params: PAY }), { actsFor: a });
for (const m of [undefined, 1, 10, 49, 50, 51, 80, 99, 100, 120, 140, 200, 1000, 0, -1, 1.5, '50', null, 9007199254740992])
  for (const t of [false, true]) {
    await R(`maxChars ${JSON.stringify(m)} tokenOnly=${t}`, SU({ goal: 'Pay the vendor', params: PAY }), { bindingMessage: { ...(m === undefined ? {} : { maxChars: m }), tokenOnly: t } });
    await R(`maxChars ${JSON.stringify(m)} tokenOnly=${t} nogoal`, SU({ goalCommit: '', params: PAY }), { bindingMessage: { ...(m === undefined ? {} : { maxChars: m }), tokenOnly: t } });
  }
for (const bm of [null, 'x', [], 5, true, {}, { tokenOnly: 'yes' }, { tokenOnly: 1 }, { maxChars: 30 }, { extra: 1 }]) await R(`bindingMessage ${JSON.stringify(bm)}`, PAYSU, { bindingMessage: bm });
await R('tokenOnly payee unicode', SU({ params: { amount: '5', currency: 'eur', payee: 'Café' } }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('tokenOnly resource punct', SU({ resource: 'a.b/c:d', params: PAY }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('tokenOnly verb dashes', SU({ verb: '-a-', params: PAY }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('tokenOnly resource dots', SU({ resource: '...', params: PAY }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('tokenOnly payee spaces', SU({ params: { amount: '5', currency: 'eur', payee: 'A B  C'.replace('  ', ' ') } }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('tokenOnly no payee', SU(), { bindingMessage: { tokenOnly: true } });
await R('render', SU({ params: PAY, render: RENDER, renderDigest: RD }));
await R('render tokenOnly', SU({ params: PAY, render: RENDER, renderDigest: RD }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('render tokenOnly default max', SU({ params: PAY, render: RENDER, renderDigest: RD }), { bindingMessage: { tokenOnly: true } });
await R('render maxChars', SU({ params: PAY, render: RENDER, renderDigest: RD }), { bindingMessage: { maxChars: 120 } });
await R('render maxChars small', SU({ params: PAY, render: RENDER, renderDigest: RD }), { bindingMessage: { maxChars: 60 } });
await R('render only', SU({ params: PAY, render: RENDER }));
await R('digest only', SU({ params: PAY, renderDigest: RD }));
await R('render wrong digest', SU({ params: PAY, render: RENDER, renderDigest: D('x') }));
await R('render bad shape', SU({ params: PAY, render: { v: 1 }, renderDigest: RD }));
await R('render null', SU({ params: PAY, render: null, renderDigest: RD }));
await R('digest null', SU({ params: PAY, render: RENDER, renderDigest: null }));
await R('render both null', SU({ params: PAY, render: null, renderDigest: null }));
await R('render digest number', SU({ params: PAY, render: RENDER, renderDigest: 5 }));
for (const [n, v] of variants(PAYSU, { hostile: [null, '', 'x', 0, 1.5, [], {}, true], maxPaths: 30 })) await R('variant ' + n, v);
for (const [n, v] of variants({ expiresInSec: 600, authReqId: 'a'.repeat(30), stepUpScope: true, loginHint: 'a@b', bindingMessage: { maxChars: 90, tokenOnly: false }, interval: 7, actsFor: 'bot' },
  { hostile: [null, '', 'x', 0, 1.5, [], {}, true], maxPaths: 30 })) await R('optvariant ' + n, SU({ goal: 'Pay the vendor', params: PAY }), v);
await R('opts null', SU(), null);

// ---- gating and the cosign hand-off ----------------------------------------------------------------------------------------------
const REVIEWS: any[] = [{ kind: 'auto' }, { kind: 'deny', reason: 'x' }, { kind: 'step_up', request: SU({ tier: 3 }) }, { kind: 'step_up', request: SU({ tier: 2 }) }, { kind: 'step_up', request: { tier: '3' } },
  { kind: 'step_up', request: { tier: 3.5 } }, { kind: 'step_up', request: { tier: 3.0 } }, { kind: 'step_up', request: {} }, { kind: 'step_up', request: null }, { kind: 'step_up' }, { kind: 'step_up', request: 'x' },
  { kind: 'step_up', request: [] }, { kind: 'Step_up', request: { tier: 3 } }, { kind: 'step-up', request: { tier: 3 } }, { request: { tier: 3 } }, {}, null, 5, 'x', [], true, { kind: ['step_up'], request: { tier: 3 } },
  { kind: 'step_up', request: { tier: [3] } }, { kind: 'deny', request: { tier: 3 } }, { kind: 'auto', request: null }];
for (const [i, r] of REVIEWS.entries()) await run('requiresCiba', `r${i}`, C.requiresCiba, [r]);

const BUDGETS: any[] = [{ B: 0, tau: 0 }, { B: 0.3, tau: 5, asOf: 7 }, { B: 1, tau: 1000 }, { B: 0.7, tau: 2 }, { B: 2, tau: 3 }, { B: 0.1, tau: 0 }];
const POLICIES: any[] = [{ rho: 0.25, bMax: 1 }, { rho: 0.9, bMax: 1 }, { rho: 0, bMax: 1 }, { rho: -1, bMax: 1 }, { rho: 0.5, bMax: 0 }, { rho: 0.5, bMax: -2 }, { rho: 0.5, bMax: 5 }, { rho: 0.1, bMax: 0.45 }, { bMax: 1 }, { rho: 0.2 }, { rho: 'x', bMax: '1' }, { rho: 1e21, bMax: 1e22 }];
for (const [bi, b] of BUDGETS.entries()) for (const [pi, p] of POLICIES.entries()) {
  await run('cibaDecisionToCosign', `approve b${bi}p${pi}`, C.cibaDecisionToCosign, ['approve', b, p, 1000]);
  await run('cibaDecisionToCosign', `approve full b${bi}p${pi}`, C.cibaDecisionToCosign, ['approve', b, p, 1000, { full: true }]);
}
for (const d of ['deny', 'Approve', 'approved', '', null, 5, true, ['approve']]) await run('cibaDecisionToCosign', `decision ${JSON.stringify(d)}`, C.cibaDecisionToCosign, [d, BUDGETS[1], POLICIES[0], 1000]);
for (const f of [true, false, 1, 0, '', 'x', null, [], {}]) await run('cibaDecisionToCosign', `full ${JSON.stringify(f)}`, C.cibaDecisionToCosign, ['approve', BUDGETS[1], POLICIES[0], 1000, { full: f }]);
for (const n of [0, 1.5, -5, 1e12, 1800000000000]) await run('cibaDecisionToCosign', `now ${n}`, C.cibaDecisionToCosign, ['approve', BUDGETS[1], POLICIES[0], n]);
await run('cibaDecisionToCosign', 'opts empty', C.cibaDecisionToCosign, ['approve', BUDGETS[1], POLICIES[0], 5, {}]);
await run('cibaDecisionToCosign', 'deny keeps budget', C.cibaDecisionToCosign, ['deny', BUDGETS[1], POLICIES[0], 5, { full: true }]);

// ---- the PING callback -----------------------------------------------------------------------------------------------------------
const TOK = 'tok_' + 'A'.repeat(30);
const FLOW = { authReqId: 'req-1', clientNotificationToken: TOK };
const VPC = (n: string, input: any, flow: any = FLOW) => run('verifyPingCallback', n, C.verifyPingCallback, [input, flow]);
await VPC('ok', { authorization: `Bearer ${TOK}`, body: { auth_req_id: 'req-1' } });
await VPC('ok lower', { authorization: `bearer ${TOK}`, body: { auth_req_id: 'req-1' } });
await VPC('ok upper', { authorization: `BEARER ${TOK}`, body: { auth_req_id: 'req-1' } });
await VPC('ok extra spaces', { authorization: `Bearer   ${TOK}`, body: { auth_req_id: 'req-1' } });
await VPC('ok extra body', { authorization: `Bearer ${TOK}`, body: { auth_req_id: 'req-1', other: 1 } });
for (const [n, a] of Object.entries<any>({ missing: undefined, empty: '', basic: `Basic ${TOK}`, 'no space': `Bearer${TOK}`, 'no token': 'Bearer ', 'only bearer': 'Bearer', wrong: 'Bearer nope', 'token+extra': `Bearer ${TOK} extra`, 'token+suffix': `Bearer ${TOK}x`,
  'token prefix': `Bearer ${TOK.slice(0, -1)}`, 'leading space': ` Bearer ${TOK}`, 'trailing space': `Bearer ${TOK} `, 'trailing nl': `Bearer ${TOK}\n`, 'tab': `Bearer\t${TOK}`, 'case differs': `Bearer ${TOK.toLowerCase()}`, null: null, number: 5 }))
  await VPC(`auth ${n}`, { authorization: a, body: { auth_req_id: 'req-1' } });
for (const [n, b] of Object.entries<any>({ other: { auth_req_id: 'req-2' }, number: { auth_req_id: 1 }, missing: {}, null: null, array: [], string: 'x', 'array id': [{ auth_req_id: 'req-1' }], undefined: undefined, case: { auth_req_id: 'REQ-1' }, 'padded': { auth_req_id: 'req-1 ' } }))
  await VPC(`body ${n}`, { authorization: `Bearer ${TOK}`, body: b });
await VPC('flow no token', { authorization: `Bearer ${TOK}`, body: { auth_req_id: 'req-1' } }, { authReqId: 'req-1' });
await VPC('flow token null', { authorization: `Bearer ${TOK}`, body: { auth_req_id: 'req-1' } }, { authReqId: 'req-1', clientNotificationToken: null });
await VPC('flow unicode token', { authorization: `Bearer éé`, body: { auth_req_id: 'req-1' } }, { authReqId: 'req-1', clientNotificationToken: 'éé' });

// ---- client configuration --------------------------------------------------------------------------------------------------------
const CFG = { backchannelAuthenticationEndpoint: 'https://op.example/bc', tokenEndpoint: 'https://op.example/token', clientId: 'cid', clientSecret: 'sec' };
const CC = (n: string, cfg: any) => run('createCibaClientConfig', n, (c: any) => { C.createCibaClient({ ...c, fetch: async () => new Response('{}') }); return true; }, [cfg]);
await CC('ok', CFG);
await CC('http', { ...CFG, tokenEndpoint: 'http://op.example/token' });
await CC('http allowed', { ...CFG, tokenEndpoint: 'http://op.example/token', backchannelAuthenticationEndpoint: 'http://localhost:8080/bc', allowInsecureHttp: true });
await CC('http allowed false', { ...CFG, tokenEndpoint: 'http://op.example/token', allowInsecureHttp: false });
await CC('ftp allowed', { ...CFG, tokenEndpoint: 'ftp://op.example/token', allowInsecureHttp: true });
for (const [n, u] of Object.entries<any>({ empty: '', relative: '/token', 'no scheme': 'op.example/token', words: 'not a url', 'only scheme': 'https:', javascript: 'javascript:alert(1)', data: 'data:,x', file: 'file:///x', 'https upper': 'HTTPS://op.example/x' })) {
  await CC(`token ${n}`, { ...CFG, tokenEndpoint: u });
  await CC(`bc ${n}`, { ...CFG, backchannelAuthenticationEndpoint: u });
}
for (const t of [0, -1, 1, 30000, 0.5, Infinity === 0 ? 0 : 1e9]) await CC(`timeout ${t}`, { ...CFG, timeoutMs: t });

// ---- brokers as scripted scenarios ----------------------------------------------------------------------------------------------
const sleepless = async () => undefined;
void sleepless;
const redactIds = (v: any, ids: string[]): any => {
  if (typeof v === 'string') { let s = v; ids.forEach((id, i) => { s = s.split(id).join(`<ID${i + 1}>`); }); return s; }
  if (Array.isArray(v)) return v.map((x) => redactIds(x, ids));
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => [k, redactIds(x, ids)]));
  return v;
};
const brokerScenario = async (s: any) => {
  let clock = T0;
  const completes: any[] = [];
  const onComplete = s.opts?.onComplete === 'record' || s.opts?.onComplete === 'throws'
    ? (sess: any) => { completes.push(JSON.parse(JSON.stringify(sess))); if (s.opts.onComplete === 'throws') throw new Error('notifier down'); } : undefined;
  let kv: any;
  let store: any;
  let broker: any;
  if (s.kind === 'memory') broker = createCibaBroker({ now: () => clock, ...(onComplete ? { onComplete } : {}) });
  else {
    if (s.kind === 'durable-kv') { kv = createMemoryKv(); store = C.createKvApprovalStore(kv); } else store = createMemoryApprovalStore();
    broker = C.createDurableCibaBroker({ store, now: () => clock, ...(s.opts?.decisionTtlSec !== undefined ? { decisionTtlSec: s.opts.decisionTtlSec } : {}), ...(onComplete ? { onComplete } : {}) });
  }
  const ids: string[] = [];
  const sub = (x: any) => (typeof x === 'string' && x.startsWith('$id') ? (x === '$id' ? ids[ids.length - 1] : ids[Number(x.slice(3)) - 1]) ?? x : x);
  const trace: any[] = [];
  for (const st of s.steps) {
    const entry: any = { op: st.op };
    try {
      let value: any;
      if (st.op === 'start') { value = await broker.start(st.stepUp, st.opts); if (!ids.includes(value.auth_req_id)) ids.push(value.auth_req_id); }
      else if (st.op === 'poll') value = await broker.poll(sub(st.id));
      else if (st.op === 'token') value = await broker.token(sub(st.id));
      else if (st.op === 'resolve') value = await broker.resolve(sub(st.id), st.decision, st.by);
      else if (st.op === 'get') value = (await broker.get(sub(st.id))) ?? null;
      else if (st.op === 'advance') { clock += st.ms; value = clock; }
      else if (st.op === 'storeSet') { const key = String(st.key).replace('$id', ids[ids.length - 1] ?? ''); const cur = await store.get(key); value = await store.cas(key, cur?.version ?? 0, st.value); }
      else if (st.op === 'kvRaw') { const key = String(st.key).replace('$id', ids[ids.length - 1] ?? ''); value = await kv.putIfEquals(key, await kv.get(key), st.raw); }
      entry.ok = true;
      entry.value = value === undefined ? null : JSON.parse(JSON.stringify(value));
    } catch (e: any) {
      entry.ok = false;
      entry.msg = e?.message ?? String(e);
      if (typeof e?.code === 'string') entry.code = e.code;
    }
    if (completes.length) { entry.complete = completes.splice(0); }
    trace.push(entry);
  }
  return redactIds(trace, ids);
};
const SUP = SU({ params: PAY, goal: 'Pay the vendor' });
const SU2 = SU({ id: 'su-2', params: PAY, goal: 'Pay another vendor' });
const BS: [string, any][] = [
  ['happy', { steps: [{ op: 'start', stepUp: SUP }, { op: 'poll', id: '$id' }, { op: 'get', id: '$id' }, { op: 'token', id: '$id' }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'alice' },
    { op: 'poll', id: '$id' }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id' }, { op: 'token', id: '$id' }, { op: 'get', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'bob' }] }],
  ['deny', { steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'deny', by: 'alice' }, { op: 'poll', id: '$id' }, { op: 'token', id: '$id' }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id' }, { op: 'get', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'x' }] }],
  ['pending-token', { steps: [{ op: 'start', stepUp: SUP }, { op: 'token', id: '$id' }, { op: 'advance', ms: 4999 }, { op: 'token', id: '$id' }, { op: 'advance', ms: 9999 }, { op: 'token', id: '$id' }, { op: 'advance', ms: 10000 }, { op: 'token', id: '$id' }, { op: 'advance', ms: 15000 }, { op: 'token', id: '$id' }] }],
  ['slow-down-grows', { steps: [{ op: 'start', stepUp: SUP }, { op: 'token', id: '$id' }, { op: 'token', id: '$id' }, { op: 'token', id: '$id' }, { op: 'advance', ms: 10000 }, { op: 'token', id: '$id' }, { op: 'advance', ms: 15000 }, { op: 'token', id: '$id' }] }],
  ['expiry', { steps: [{ op: 'start', stepUp: SUP, opts: { expiresInSec: 10 } }, { op: 'poll', id: '$id' }, { op: 'advance', ms: 9999 }, { op: 'poll', id: '$id' }, { op: 'advance', ms: 1 }, { op: 'poll', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' },
    { op: 'token', id: '$id' }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id' }, { op: 'get', id: '$id' }] }],
  ['idempotent-start', { steps: [{ op: 'start', stepUp: SUP }, { op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'start', stepUp: SUP }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id' }, { op: 'start', stepUp: SUP }, { op: 'start', stepUp: SU2 }] }],
  ['restart-after-deny', { steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'deny', by: 'a' }, { op: 'start', stepUp: SUP }, { op: 'poll', id: '$id' }, { op: 'poll', id: '$id1' }] }],
  ['restart-after-expiry', { steps: [{ op: 'start', stepUp: SUP, opts: { expiresInSec: 5 } }, { op: 'advance', ms: 5000 }, { op: 'start', stepUp: SUP }, { op: 'poll', id: '$id1' }, { op: 'poll', id: '$id2' }] }],
  ['approval-ttl', { opts: { decisionTtlSec: 60 }, steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'advance', ms: 59999 }, { op: 'poll', id: '$id' }, { op: 'advance', ms: 1 }, { op: 'poll', id: '$id' }, { op: 'token', id: '$id' }, { op: 'get', id: '$id' }] }],
  ['approval-never-expires-memory-or-ttl', { steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'advance', ms: 299999 }, { op: 'poll', id: '$id' }, { op: 'advance', ms: 1 }, { op: 'poll', id: '$id' }] }],
  ['unknown', { steps: [{ op: 'poll', id: 'nope' }, { op: 'token', id: 'nope' }, { op: 'resolve', id: 'nope', decision: 'approve', by: 'a' }, { op: 'get', id: 'nope' }] }],
  ['bad-resolve', { steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'maybe', by: 'a' }, { op: 'resolve', id: '$id', decision: 'approve', by: '' }, { op: 'resolve', id: '$id', decision: 'approve' },
    { op: 'resolve', id: '$id', decision: 'approve', by: 5 }, { op: 'resolve', id: '$id', decision: null, by: 'a' }, { op: 'poll', id: '$id' }] }],
  ['bad-start', { steps: [{ op: 'start', stepUp: SU({ verb: 'a b' }) }, { op: 'start', stepUp: SU({ params: { x: 1 } }) }, { op: 'start', stepUp: SUP, opts: { expiresInSec: 0 } }, { op: 'start', stepUp: SUP }, { op: 'poll', id: '$id' }] }],
  ['start-opts', { steps: [{ op: 'start', stepUp: SUP, opts: { loginHint: 'alice', bindingMessage: { tokenOnly: true, maxChars: 80 }, stepUpScope: false, interval: 9, expiresInSec: 100 } }, { op: 'token', id: '$id' }, { op: 'advance', ms: 9000 }, { op: 'token', id: '$id' }, { op: 'advance', ms: 1 }, { op: 'get', id: '$id' }] }],
  ['two-flows', { steps: [{ op: 'start', stepUp: SUP }, { op: 'start', stepUp: SU2 }, { op: 'resolve', id: '$id1', decision: 'approve', by: 'a' }, { op: 'resolve', id: '$id2', decision: 'deny', by: 'b' }, { op: 'poll', id: '$id1' }, { op: 'poll', id: '$id2' }, { op: 'advance', ms: 5000 }, { op: 'token', id: '$id1' }, { op: 'token', id: '$id2' }] }],
  ['on-complete', { opts: { onComplete: 'record' }, steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'start', stepUp: SU2 }, { op: 'resolve', id: '$id', decision: 'deny', by: 'b' }, { op: 'resolve', id: '$id', decision: 'deny', by: 'b' }] }],
  ['on-complete-throws', { opts: { onComplete: 'throws' }, steps: [{ op: 'start', stepUp: SUP }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'poll', id: '$id' }, { op: 'get', id: '$id' }] }],
  ['no-clock-skew-past', { steps: [{ op: 'start', stepUp: SUP }, { op: 'advance', ms: -1000 }, { op: 'poll', id: '$id' }, { op: 'token', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }] }],
];
const DURABLE_ONLY: [string, any][] = [
  ['corrupt-record', { steps: [{ op: 'start', stepUp: SUP }, { op: 'storeSet', key: 'a:$id', value: { nope: true } }, { op: 'poll', id: '$id' }, { op: 'token', id: '$id' }, { op: 'resolve', id: '$id', decision: 'approve', by: 'a' }, { op: 'get', id: '$id' }] }],
  ['corrupt-record-fields', { steps: [{ op: 'start', stepUp: SUP }, { op: 'storeSet', key: 'a:$id', value: { request: { auth_req_id: 'x' }, createdAt: 'now', expiresAt: 5, interval: 5 } }, { op: 'poll', id: '$id' }] }],
  ['corrupt-record-null', { steps: [{ op: 'start', stepUp: SUP }, { op: 'storeSet', key: 'a:$id', value: null }, { op: 'poll', id: '$id' }] }],
  ['dangling-live-index', { steps: [{ op: 'storeSet', key: 's:su-1', value: 'missing' }, { op: 'start', stepUp: SUP }, { op: 'poll', id: '$id' }] }],
  ['live-index-number', { steps: [{ op: 'storeSet', key: 's:su-1', value: 5 }, { op: 'start', stepUp: SUP }, { op: 'poll', id: '$id' }] }],
];
const KV_ONLY: [string, any][] = [
  ['kv-corrupt-json', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '{not json' }, { op: 'poll', id: '$id' }, { op: 'token', id: '$id' }, { op: 'get', id: '$id' }] }],
  ['kv-corrupt-version', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '{"version":0,"value":{}}' }, { op: 'poll', id: '$id' }] }],
  ['kv-corrupt-version-str', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '{"version":"1","value":{}}' }, { op: 'poll', id: '$id' }] }],
  ['kv-corrupt-no-value', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '{"version":1}' }, { op: 'poll', id: '$id' }] }],
  ['kv-corrupt-array', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '[]' }, { op: 'poll', id: '$id' }] }],
  ['kv-corrupt-null', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: 'null' }, { op: 'poll', id: '$id' }] }],
  ['kv-version-float', { steps: [{ op: 'start', stepUp: SUP }, { op: 'kvRaw', key: 'a:$id', raw: '{"version":1.5,"value":{}}' }, { op: 'poll', id: '$id' }] }],
  ['kv-start-over-corrupt-index', { steps: [{ op: 'kvRaw', key: 's:su-1', raw: 'garbage' }, { op: 'start', stepUp: SUP }] }],
];
// the in-memory broker does not validate decision / by (the test double); only the durable broker does
for (const [n, s] of BS) for (const kind of ['memory', 'durable', 'durable-kv']) { if (n === 'bad-resolve' && kind === 'memory') continue; await run('brokerScenario', `${kind} ${n}`, brokerScenario, [{ kind, ...s }]); }
for (const [n, s] of DURABLE_ONLY) for (const kind of ['durable', 'durable-kv']) await run('brokerScenario', `${kind} ${n}`, brokerScenario, [{ kind, ...s }]);
for (const [n, s] of KV_ONLY) await run('brokerScenario', `durable-kv ${n}`, brokerScenario, [{ kind: 'durable-kv', ...s }]);
const DBC = (n: string, cfg: any) => run('durableBrokerConfig', n, (c: any) => { try { C.createDurableCibaBroker(c.noStore ? {} : { store: createMemoryApprovalStore(), ...(c.decisionTtlSec !== undefined ? { decisionTtlSec: c.decisionTtlSec } : {}) }); return 'ok'; } catch { return 'throws'; } }, [cfg]);
await DBC('ttl default', {});
await DBC('ttl 60', { decisionTtlSec: 60 });
await DBC('ttl 0.5', { decisionTtlSec: 0.5 });
await DBC('ttl zero', { decisionTtlSec: 0 });
await DBC('ttl negative', { decisionTtlSec: -5 });
await DBC('no store', { noStore: true });

// ---- the KV approval store -------------------------------------------------------------------------------------------------------
const kvScenario = async (s: any) => {
  const kv = createMemoryKv();
  const store = C.createKvApprovalStore(kv);
  const trace: any[] = [];
  for (const st of s.steps) {
    try {
      let value: any;
      if (st.op === 'get') value = (await store.get(st.key)) ?? null;
      else if (st.op === 'cas') value = await store.cas(st.key, st.expected, st.value);
      else if (st.op === 'kvSet') value = await kv.putIfEquals(st.key, await kv.get(st.key), st.raw);
      else if (st.op === 'kvGet') value = (await kv.get(st.key)) ?? null;
      trace.push({ op: st.op, ok: true, value: value === undefined ? null : JSON.parse(JSON.stringify(value)) });
    } catch (e: any) {
      trace.push({ op: st.op, ok: false, code: e?.code ?? 'other' });
    }
  }
  return trace;
};
const KS: [string, any[]][] = [
  ['create', [{ op: 'get', key: 'k' }, { op: 'cas', key: 'k', expected: 0, value: { a: 1 } }, { op: 'get', key: 'k' }, { op: 'kvGet', key: 'k' }, { op: 'cas', key: 'k', expected: 0, value: 2 }, { op: 'cas', key: 'k', expected: 1, value: [1, 'x', null] }, { op: 'get', key: 'k' }, { op: 'cas', key: 'k', expected: 1, value: 3 }, { op: 'cas', key: 'k', expected: 5, value: 4 }, { op: 'kvGet', key: 'k' }]],
  ['json-forms', [{ op: 'cas', key: 'a', expected: 0, value: { z: 1, a: { y: 1.5, b: -0, c: 123456789012, d: 'q"\\\n \ud800', e: [true, false, null] } } }, { op: 'kvGet', key: 'a' }, { op: 'get', key: 'a' }]],
  ['nonzero-absent', [{ op: 'cas', key: 'k', expected: 1, value: 'x' }, { op: 'get', key: 'k' }, { op: 'cas', key: 'k', expected: -1, value: 'x' }, { op: 'cas', key: 'k', expected: 2, value: 'x' }]],
  ['independent', [{ op: 'cas', key: 'a', expected: 0, value: 'A' }, { op: 'cas', key: 'b', expected: 0, value: 'B' }, { op: 'cas', key: 'a', expected: 1, value: 'A2' }, { op: 'get', key: 'a' }, { op: 'get', key: 'b' }]],
  ['corrupt', [{ op: 'kvSet', key: 'k', raw: 'nope' }, { op: 'get', key: 'k' }, { op: 'cas', key: 'k', expected: 0, value: 1 }, { op: 'cas', key: 'k', expected: 1, value: 1 }]],
  ['corrupt-forms', [{ op: 'kvSet', key: 'a', raw: '' }, { op: 'get', key: 'a' }, { op: 'kvSet', key: 'b', raw: '{"version":2}' }, { op: 'get', key: 'b' }, { op: 'kvSet', key: 'c', raw: '{"version":2,"value":null}' }, { op: 'get', key: 'c' }, { op: 'cas', key: 'c', expected: 2, value: 5 }, { op: 'get', key: 'c' },
    { op: 'kvSet', key: 'd', raw: '{"value":1}' }, { op: 'get', key: 'd' }, { op: 'kvSet', key: 'e', raw: '{"version":2.0,"value":1}' }, { op: 'get', key: 'e' }, { op: 'kvSet', key: 'f', raw: '{"version":1e0,"value":"x"}' }, { op: 'get', key: 'f' }, { op: 'kvSet', key: 'g', raw: '{"version":true,"value":1}' }, { op: 'get', key: 'g' },
    { op: 'kvSet', key: 'h', raw: '{"version":-1,"value":1}' }, { op: 'get', key: 'h' }, { op: 'kvSet', key: 'i', raw: ' {"version":3,"value":{"x":1}} ' }, { op: 'get', key: 'i' }, { op: 'cas', key: 'i', expected: 3, value: 1 }, { op: 'kvGet', key: 'i' }]],
];
for (const [n, steps] of KS) await run('kvScenario', n, kvScenario, [{ steps }]);

// ---- the client ------------------------------------------------------------------------------------------------------------------
const clientScenario = async (s: any) => {
  let clock = T0;
  const reqs: any[] = [];
  const sleeps: number[] = [];
  const queue = [...s.responses];
  const fetchMock = async (url: string, init: any) => {
    reqs.push({ url, method: init.method, headers: init.headers, body: init.body });
    const r = queue.shift();
    if (r === undefined || r.fail) throw new Error(r === undefined ? 'no scripted response' : 'connection reset');
    return new Response(typeof r.body === 'string' ? r.body : JSON.stringify(r.body), { status: r.status });
  };
  const client = C.createCibaClient({ ...s.cfg, fetch: fetchMock, sleep: async (ms: number) => { sleeps.push(ms); clock += ms; }, now: () => clock });
  let flow: any;
  let poller: any;
  const trace: any[] = [];
  let nt = '';
  const mark = (v: any) => (nt ? JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'string' ? x.split(nt).join('<NTOKEN>') : x))) : v);
  for (const st of s.steps) {
    const entry: any = { op: st.op };
    try {
      let value: any;
      if (st.op === 'initiate') { flow = await client.initiate(st.stepUp, st.opts); poller = client.poller(flow); value = flow; if (flow.clientNotificationToken && st.opts?.clientNotificationToken === undefined) nt = flow.clientNotificationToken; }
      else if (st.op === 'poll') value = await poller.poll();
      else if (st.op === 'wait') value = await poller.wait();
      else if (st.op === 'notify') { poller.notify(); value = null; }
      else if (st.op === 'advance') { clock += st.ms; value = clock; }
      else if (st.op === 'interval') value = poller.intervalSec();
      entry.ok = true;
      entry.value = value === undefined ? null : JSON.parse(JSON.stringify(value));
    } catch (e: any) {
      entry.ok = false;
      if (e instanceof C.CibaProviderError) Object.assign(entry, { error: e.error, status: e.status, retryable: e.retryable, errorDescription: e.errorDescription ?? null });
      else { entry.other = true; }
    }
    entry.requests = reqs.splice(0);
    entry.sleeps = sleeps.splice(0);
    trace.push(mark(entry));
  }
  entry_unused: void 0;
  return trace;
};
const SUC = SU({ params: PAY, goal: 'Pay the vendor' });
const OK_INIT = { status: 200, body: { auth_req_id: 'req-abc', expires_in: 120, interval: 5 } };
const PEND = { status: 400, body: { error: 'authorization_pending' } };
const TOKENS = { status: 200, body: { access_token: 'at', token_type: 'Bearer', id_token: 'idt', expires_in: 300 } };
const CS: [string, any][] = [
  ['happy', { responses: [OK_INIT, PEND, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'alice' } }, { op: 'interval' }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }] }],
  ['wait-happy', { responses: [OK_INIT, PEND, PEND, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'alice' } }, { op: 'wait' }, { op: 'wait' }] }],
  ['no-interval-default', { responses: [{ status: 200, body: { auth_req_id: 'r', expires_in: 60 } }, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['slow-down', { responses: [OK_INIT, { status: 400, body: { error: 'slow_down' } }, { status: 400, body: { error: 'slow_down' } }, PEND, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'interval' }, { op: 'poll' }, { op: 'interval' }, { op: 'poll' }, { op: 'poll' }] }],
  ['denied', { responses: [OK_INIT, { status: 400, body: { error: 'access_denied' } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }, { op: 'poll' }] }],
  ['expired-token', { responses: [OK_INIT, { status: 400, body: { error: 'expired_token' } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }, { op: 'poll' }] }],
  ['deadline', { responses: [OK_INIT, PEND, PEND, PEND, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'advance', ms: 120000 }, { op: 'poll' }, { op: 'poll' }] }],
  ['deadline-after-polls', { responses: [OK_INIT, PEND, PEND, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'advance', ms: 120000 }, { op: 'poll' }, { op: 'poll' }] }],
  ['unknown-error', { responses: [OK_INIT, { status: 400, body: { error: 'invalid_grant', error_description: 'gone' } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }] }],
  ['error-no-body-error', { responses: [OK_INIT, { status: 400, body: { x: 1 } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['error-non-string', { responses: [OK_INIT, { status: 400, body: { error: 5, error_description: 7 } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['server-error-backoff', { responses: [OK_INIT, { status: 503, body: 'oops' }, { status: 502, body: '' }, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }] }],
  ['wait-retries-transient', { responses: [OK_INIT, { status: 503, body: 'x' }, { fail: true }, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }] }],
  ['wait-gives-up', { responses: [OK_INIT, { status: 503, body: 'x' }, { status: 503, body: 'x' }, { status: 503, body: 'x' }, { status: 503, body: 'x' }, { status: 503, body: 'x' }, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }, { op: 'wait' }] }],
  ['wait-definitive-error', { responses: [OK_INIT, { status: 400, body: { error: 'invalid_client' } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }] }],
  ['network-error', { responses: [OK_INIT, { fail: true }, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }] }],
  ['non-json', { responses: [OK_INIT, { status: 200, body: 'not json' }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['json-array', { responses: [OK_INIT, { status: 200, body: [] }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['token-missing-fields', { responses: [OK_INIT, { status: 200, body: { access_token: 'x' } }, { status: 200, body: { token_type: 'Bearer' } }], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }] }],
  ['notify', { responses: [OK_INIT, PEND, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'notify' }, { op: 'poll' }, { op: 'poll' }] }],
  ['initiate-ping', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'ping' } }] }],
  ['initiate-ping-token', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'N'.repeat(40) } }] }],
  ['initiate-poll-token', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', clientNotificationToken: 'N'.repeat(40) } }] }],
  ['initiate-other-delivery', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'push' } }] }],
  ['initiate-hints', { responses: [OK_INIT, OK_INIT, OK_INIT, OK_INIT, OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: {} }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', idTokenHint: 'b' } }, { op: 'initiate', stepUp: SUC, opts: { loginHintToken: 'tok' } },
    { op: 'initiate', stepUp: SUC, opts: { idTokenHint: 'idt' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: null } }, { op: 'initiate', stepUp: SUC }] }],
  ['initiate-extras', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHintToken: 'tok & more=1', acrValues: 'urn:acr 1', userCode: 'a+b c', interval: 9, expiresInSec: 99, stepUpScope: false } }] }],
  ['initiate-unicode-hint', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'Zürich ☃ ~!*()\'' } }] }],
  ['initiate-bad-ntoken', { responses: [OK_INIT, OK_INIT, OK_INIT, OK_INIT, OK_INIT, OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'short' } },
    { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'N'.repeat(21) } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'N'.repeat(22) } },
    { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', clientNotificationToken: 'N'.repeat(1024) } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', clientNotificationToken: 'N'.repeat(1025) } },
    { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', clientNotificationToken: 'N N'.repeat(10) } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a', clientNotificationToken: 'é'.repeat(30) } }] }],
  ['initiate-bad-stepup', { responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SU({ verb: 'a b' }), opts: { loginHint: 'a' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }] }],
  ['initiate-op-errors', { responses: [{ status: 400, body: { error: 'invalid_scope', error_description: 'no such scope' } }, { status: 500, body: { error: 'server_error' } }, { status: 200, body: 'not json' }, { status: 200, body: [] }, { fail: true }], steps: [
    { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }] }],
  ['initiate-bad-reply', { responses: [{ status: 200, body: {} }, { status: 200, body: { auth_req_id: '' , expires_in: 5 } }, { status: 200, body: { auth_req_id: 'a' } }, { status: 200, body: { auth_req_id: 'a', expires_in: 0 } }, { status: 200, body: { auth_req_id: 'a', expires_in: 1.5 } },
    { status: 200, body: { auth_req_id: 'a', expires_in: '60' } }, { status: 200, body: { auth_req_id: 'a', expires_in: 60, interval: 0 } }, { status: 200, body: { auth_req_id: 'a', expires_in: 60, interval: null } }, { status: 200, body: { auth_req_id: 5, expires_in: 60 } },
    { status: 200, body: { auth_req_id: 'a', expires_in: 60, interval: 2.5 } }, { status: 200, body: { auth_req_id: 'a', expires_in: 9007199254740991, interval: 9007199254740991 } }], steps: Array.from({ length: 11 }, () => ({ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } })) }],
  ['initiate-status-201', { responses: [{ status: 201, body: { auth_req_id: 'a', expires_in: 60 } }, { status: 299, body: { auth_req_id: 'a', expires_in: 60 } }, { status: 300, body: { auth_req_id: 'a', expires_in: 60 } }], steps: Array.from({ length: 3 }, () => ({ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } })) }],
  ['basic-auth-encoding', { cfg: { clientId: 'client id:é', clientSecret: "s/e c:r+e?t!~*'()" }, responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }] }],
  ['basic-auth-plain', { cfg: { clientId: 'a', clientSecret: 'b' }, responses: [OK_INIT], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }] }],
  ['settled-cached', { responses: [OK_INIT, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }, { op: 'wait' }, { op: 'interval' }] }],
  ['http-allowed', { cfg: { backchannelAuthenticationEndpoint: 'http://localhost:9/bc', tokenEndpoint: 'http://localhost:9/token', allowInsecureHttp: true }, responses: [OK_INIT, TOKENS], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }] }],
  ['poll-before-init-interval', { responses: [{ status: 200, body: { auth_req_id: 'r', expires_in: 3, interval: 2 } }, PEND, PEND, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }] }],
  ['expiry-exact', { responses: [{ status: 200, body: { auth_req_id: 'r', expires_in: 10, interval: 5 } }, PEND, PEND, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'poll' }, { op: 'poll' }, { op: 'poll' }] }],
  ['wait-pending-then-expire', { responses: [{ status: 200, body: { auth_req_id: 'r', expires_in: 10, interval: 5 } }, PEND, PEND, PEND], steps: [{ op: 'initiate', stepUp: SUC, opts: { loginHint: 'a' } }, { op: 'wait' }] }],
];
for (const [n, s] of CS) await run('clientScenario', n, clientScenario, [{ cfg: { ...CFG, ...(s.cfg ?? {}) }, responses: s.responses, steps: s.steps }]);

refWrite(o, 'ciba-java');
