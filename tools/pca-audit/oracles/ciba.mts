// Oracle: @atlasauth/pca-ciba (canonical action, binding message / auth request, gating, cosign budget effect, ping-callback check, and
// scripted lifecycles of the in-memory broker and the durable broker over the memory store). Deterministic: fixed clocks; the random
// auth_req_id is masked as "ID" in lifecycle outputs. Writes out/ref-ciba.json.gz.
//
// PORTING (fn(args) -> native entry point):
//   cibaActionFromStepUp(stepUp), asciiForm(s), requiresCiba(review) -> same; JSON compare, a throw requires a throw
//   toCibaAuthRequest(stepUp, opts) -> to_ciba_auth_request; opts keys snake_case (bindingMessage -> binding_message {max_chars, token_only})
//   cibaDecisionToCosign(decision, budget, policy, now, opts) -> ciba_decision_to_cosign(.., full=opts.full)
//   verifyPingCallback(input, flow) -> verify_ping_callback; returns the auth_req_id
//   lifecycle(kind, ops) -> a broker of kind 'memory' | 'durable' driven by the ops script; ops: {op:'now',t} sets the clock;
//     {op:'start',opts?}, {op:'poll'}, {op:'token'}, {op:'resolve',decision,by}, {op:'get'} act on the last started flow; each op's
//     result {ok,value}|{ok:false} with auth_req_id masked. The result list is compared.
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-ciba/src/index.ts');
const T: any = await import('../../../packages/pca-ciba/src/testing.ts');
const D: any = await import('../../../packages/pca-ciba/src/approval.ts');
const P: any = await import('../../../packages/pca/src/index.ts');
const o = new Oracle('ciba', 'tools/pca-audit/oracles/ciba.mts', 'TS-reference oracle for the CIBA bridge.');

const RENDER = {
  v: 1, kind: 'pca-approval-render', verb: 'stripe.payout', def_digest: 'A'.repeat(43), unreviewed: false,
  fields: [{ id: 'amount', class: 'money.amount', value: 80, unit: { kind: 'money', ccy: 'USD', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'bob' }],
};
const RD = P.approvalRenderDigest(RENDER);
const SU: any = { id: 'su1', verb: 'stripe.payout', resource: 'acct:1', params: { amount: 80, currency: 'USD', payee: 'bob' }, tier: 3, reason: 'r', goalCommit: 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq', goal: 'pay suppliers', lineage: {}, r: 0.5, requestedAt: 1 };
const su = (over: any = {}, params?: any) => {
  const s = { ...SU, ...over };
  if (params !== undefined) s.params = params;
  return s;
};
const withP = (p: any) => su({}, p);

// ---- cibaActionFromStepUp ------------------------------------------------------------------------------------------------
const A = (name: string, s: any) => o.run('cibaActionFromStepUp', name, M.cibaActionFromStepUp, [s]);
await A('payment', SU);
await A('no params', su({ params: undefined }));
await A('null params', su({ params: null }));
await A('array params', su({ params: [] }));
await A('string params', su({ params: 'x' }));
await A('empty params', withP({}));
await A('unknown key', withP({ amount: 1, currency: 'USD', payee: 'b', memo: 'x' }));
await A('unknown key null', withP({ memo: null }));
await A('amount number', withP({ amount: 1.5, currency: 'usd', to: 'bob' }));
await A('amount string', withP({ amount: '12.50', currency: 'EUR', recipient: 'bob' }));
await A('amount zero', withP({ amount: 0, currency: 'EUR', recipient: 'bob' }));
await A('amount leading zero', withP({ amount: '01', currency: 'EUR', recipient: 'bob' }));
await A('amount negative', withP({ amount: -1, currency: 'EUR', recipient: 'bob' }));
await A('amount exp', withP({ amount: 1e21, currency: 'EUR', recipient: 'bob' }));
await A('amount small', withP({ amount: 0.00001, currency: 'EUR', recipient: 'bob' }));
await A('amount big int', withP({ amount: 123456789012, currency: 'EUR', recipient: 'bob' }));
await A('amount bool', withP({ amount: true, currency: 'EUR', recipient: 'bob' }));
await A('amount object', withP({ amount: { v: 1 }, currency: 'EUR', recipient: 'bob' }));
await A('amount no currency', withP({ amount: 1, payee: 'bob' }));
await A('amount bad currency', withP({ amount: 1, currency: 'EURO', payee: 'bob' }));
await A('amount no payee', withP({ amount: 1, currency: 'EUR' }));
await A('currency alone', withP({ currency: 'EUR' }));
await A('two payees', withP({ payee: 'a', to: 'b' }));
await A('payee null with to', withP({ payee: null, to: 'b' }));
await A('payee only', withP({ beneficiary: 'Acme Inc' }));
await A('payee destination', withP({ destination: 'acct-1' }));
await A('payee number', withP({ payee: 5 }));
await A('payee object', withP({ payee: { a: 1 } }));
await A('payee empty', withP({ payee: '' }));
await A('payee leading space', withP({ payee: ' bob' }));
await A('payee double space', withP({ payee: 'a  b' }));
await A('payee control', withP({ payee: 'a\u0007b' }));
await A('payee bidi', withP({ payee: 'a‮b' }));
await A('payee zero width', withP({ payee: 'a​b' }));
await A('payee line sep', withP({ payee: 'a b' }));
await A('payee quote', withP({ payee: 'a"b' }));
await A('payee backslash', withP({ payee: 'a\\b' }));
await A('payee 64', withP({ payee: 'x'.repeat(64) }));
await A('payee 65', withP({ payee: 'x'.repeat(65) }));
await A('payee clause', withP({ payee: 'because you asked x' }));
await A('payee clause nbsp', withP({ payee: 'because you  asked' }));
await A('payee combining', withP({ payee: 'éx̂' }));
await A('payee nfc composes', withP({ payee: 'café' }));
await A('payee fullwidth', withP({ payee: 'Ａbc' }));
await A('payee ligature', withP({ payee: 'ﬁnance' }));
await A('payee mixed scripts', withP({ payee: 'Pаypal' }));
await A('payee cyrillic', withP({ payee: 'аррӏе' }));
await A('payee greek', withP({ payee: 'Αλφα' }));
await A('payee cjk', withP({ payee: '会社' }));
await A('payee japanese mixed', withP({ payee: '会社カー' }));
await A('payee hebrew', withP({ payee: 'שלום' }));
await A('payee arabic', withP({ payee: 'مرحبا' }));
await A('payee devanagari', withP({ payee: 'नमस्ते' }));
await A('payee emoji', withP({ payee: 'a😀' }));
await A('payee lone surrogate', withP({ payee: 'a\ud800' }));
await A('payee private use', withP({ payee: 'a' }));
await A('payee non-latin digits', withP({ payee: '١٢' }));
await A('payee latin accent', withP({ payee: 'Müller' }));
await A('verb space', su({ verb: 'a b' }));
await A('verb 64', su({ verb: 'a'.repeat(64) }));
await A('verb 65', su({ verb: 'a'.repeat(65) }));
await A('verb missing', su({ verb: undefined }));
await A('verb number', su({ verb: 5 }));
await A('verb leading dot', su({ verb: '.a' }));
await A('verb newline', su({ verb: 'a\n' }));
await A('verb clause', su({ verb: 'x' }));
await A('resource missing', su({ resource: undefined }));
await A('resource symbols', su({ resource: 'acct:1/x#y@z+q-w' }));
await A('resource quote', su({ resource: 'a"b' }));

// ---- asciiForm ---------------------------------------------------------------------------------------------------------------------
for (const s of ['bob', '', 'Acme Inc', 'Müller', 'аррӏе', '会社', 'שלום', 'مرحبا', 'café bar', 'Αλφα ΟΔΟΣ', 'Straße', 'a.bé', 'नमस्ते', 'สวัสดี'])
  await o.run('asciiForm', JSON.stringify(s), M.asciiForm, [s]);

// ---- toCibaAuthRequest ---------------------------------------------------------------------------------------------------------------
const R = (name: string, s: any, opts?: any) => o.run('toCibaAuthRequest', name, M.toCibaAuthRequest, opts === undefined ? [s] : [s, opts]);
await R('default', SU);
await R('no goal', su({ goal: undefined }));
await R('empty goal uses commit', su({ goal: '' }));
await R('blank goal uses commit', su({ goal: ' \n ' }));
await R('no goal no commit', su({ goal: undefined, goalCommit: '' }));
await R('goal null', su({ goal: null }));
await R('commit missing', su({ goal: undefined, goalCommit: undefined }));
await R('goal quotes', su({ goal: "it's ‘x’" }));
await R('goal control', su({ goal: 'a\u0000b‮c\r\nd' }));
await R('goal long', su({ goal: 'g'.repeat(300) }));
await R('goal emoji', su({ goal: '😀'.repeat(120) }));
await R('goal number', su({ goal: 5 }));
await R('acts for', SU, { actsFor: 'support-bot' });
await R('acts for blank', SU, { actsFor: '  ' });
await R('acts for long', SU, { actsFor: 'x'.repeat(80) });
await R('acts for control', SU, { actsFor: 'a\nb' });
await R('expiry 60', SU, { expiresInSec: 60 });
for (const [n, v] of [['zero', 0], ['negative', -5], ['fraction', 1.5], ['string', '5'], ['huge', 2 ** 60], ['null', null]] as any[]) await R('expiry ' + n, SU, { expiresInSec: v });
await R('interval 10', SU, { interval: 10 });
for (const [n, v] of [['zero', 0], ['fraction', 0.5], ['string', 'x']] as any[]) await R('interval ' + n, SU, { interval: v });
await R('no stepup scope', SU, { stepUpScope: false });
await R('stepup scope true', SU, { stepUpScope: true });
await R('login hint', SU, { loginHint: 'alice@example.com' });
await R('explicit auth_req_id', SU, { authReqId: 'A'.repeat(22) });
await R('auth_req_id short', SU, { authReqId: 'A'.repeat(21) });
await R('auth_req_id long', SU, { authReqId: 'A'.repeat(1024) });
await R('auth_req_id too long', SU, { authReqId: 'A'.repeat(1025) });
await R('auth_req_id bad char', SU, { authReqId: 'A'.repeat(21) + '+' });
await R('auth_req_id number', SU, { authReqId: 5 });
await R('verb with scope junk', su({ verb: 'a"b' }));
await R('max chars 200', SU, { bindingMessage: { maxChars: 200 } });
await R('max chars 60 drops goal', SU, { bindingMessage: { maxChars: 60 } });
await R('max chars exact head', SU, { bindingMessage: { maxChars: 'Approve stripe.payout 80 USD to "bob" on acct:1'.length } });
await R('max chars head minus one', SU, { bindingMessage: { maxChars: 'Approve stripe.payout 80 USD to "bob" on acct:1'.length - 1 } });
await R('max chars clips goal', SU, { bindingMessage: { maxChars: 'Approve stripe.payout 80 USD to "bob" on acct:1'.length + 40 } });
for (const [n, v] of [['zero', 0], ['fraction', 1.5], ['string', '5']] as any[]) await R('max chars ' + n, SU, { bindingMessage: { maxChars: v } });
await R('token only', SU, { bindingMessage: { tokenOnly: true } });
await R('token only 50 exact', SU, { bindingMessage: { tokenOnly: true, maxChars: 'Approve-stripe.payout-80-USD-to-bob-acct-1'.length } });
await R('token only too short', SU, { bindingMessage: { tokenOnly: true, maxChars: 10 } });
await R('token only non-ascii payee', withP({ payee: 'Müller' }) && su({}, { payee: 'Müller' }), { bindingMessage: { tokenOnly: true, maxChars: 200 } });
await R('token only no params', su({ params: {} }), { bindingMessage: { tokenOnly: true } });
await R('rich non-ascii payee', su({}, { payee: 'Müller' }));
await R('rich cyrillic payee', su({}, { payee: 'аррӏе' }));
await R('rich non-ascii tight', su({}, { payee: 'Müller' }), { bindingMessage: { maxChars: 40 } });
await R('hostile payee', su({}, { payee: 'because you asked' }));
await R('with render', su({ render: RENDER, renderDigest: RD }));
await R('with render token only', su({ render: RENDER, renderDigest: RD }), { bindingMessage: { tokenOnly: true, maxChars: 120 } });
await R('with render token only short', su({ render: RENDER, renderDigest: RD }), { bindingMessage: { tokenOnly: true, maxChars: 50 } });
await R('with render rich tight', su({ render: RENDER, renderDigest: RD }), { bindingMessage: { maxChars: 120 } });
await R('render digest mismatch', su({ render: RENDER, renderDigest: 'B'.repeat(43) }));
await R('render missing', su({ renderDigest: RD }));
await R('digest missing', su({ render: RENDER }));
await R('render malformed', su({ render: { v: 2 }, renderDigest: RD }));
await R('render explicit undefined', su({ render: undefined, renderDigest: undefined }));
await R('tier 2', su({ tier: 2 }));
await R('params unknown', withP({ memo: 'x' }));

// ---- gating / cosign -----------------------------------------------------------------------------------------------------------------
for (const [n, r] of [['tier 3', { kind: 'step_up', request: { tier: 3 } }], ['tier 2', { kind: 'step_up', request: { tier: 2 } }], ['auto', { kind: 'auto' }], ['deny', { kind: 'deny', reason: 'x' }], ['tier string', { kind: 'step_up', request: { tier: '3' } }], ['kind other', { kind: 'step_down', request: { tier: 3 } }]] as any[])
  await o.run('requiresCiba', n, M.requiresCiba, [r]);
const POL = { bMax: 10, rho: 3, lambda: 0.1 };
const BUD = { B: 2, tau: 1000, asOf: 1000 };
await o.run('cibaDecisionToCosign', 'approve partial', M.cibaDecisionToCosign, ['approve', BUD, POL, 5000]);
await o.run('cibaDecisionToCosign', 'approve caps at bMax', M.cibaDecisionToCosign, ['approve', { B: 9, tau: 1, asOf: 1 }, POL, 5000]);
await o.run('cibaDecisionToCosign', 'approve full', M.cibaDecisionToCosign, ['approve', BUD, POL, 5000, { full: true }]);
await o.run('cibaDecisionToCosign', 'deny', M.cibaDecisionToCosign, ['deny', BUD, POL, 5000]);
await o.run('cibaDecisionToCosign', 'deny full', M.cibaDecisionToCosign, ['deny', BUD, POL, 5000, { full: true }]);

// ---- verifyPingCallback --------------------------------------------------------------------------------------------------------------
const FLOW = { authReqId: 'req-1', clientNotificationToken: 'tok_ABCDEFGHIJKLMNOPQRSTUV' };
const V = (name: string, input: any, flow: any = FLOW) => o.run('verifyPingCallback', name, M.verifyPingCallback, [input, flow]);
await V('ok', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 'req-1' } });
await V('ok lowercase scheme', { authorization: 'bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 'req-1' } });
await V('ok many spaces', { authorization: 'Bearer    tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 'req-1' } });
await V('no header', { authorization: undefined, body: { auth_req_id: 'req-1' } });
await V('empty header', { authorization: '', body: { auth_req_id: 'req-1' } });
await V('basic scheme', { authorization: 'Basic tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 'req-1' } });
await V('trailing space', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV ', body: { auth_req_id: 'req-1' } });
await V('two tokens', { authorization: 'Bearer a b', body: { auth_req_id: 'req-1' } });
await V('wrong token', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUX', body: { auth_req_id: 'req-1' } });
await V('wrong id', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 'req-2' } });
await V('id number', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: { auth_req_id: 1 } });
await V('body null', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: null });
await V('body string', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: 'x' });
await V('body missing id', { authorization: 'Bearer tok_ABCDEFGHIJKLMNOPQRSTUV', body: {} });
await V('flow without token', { authorization: 'Bearer x', body: { auth_req_id: 'req-1' } }, { authReqId: 'req-1' });
await V('authorization number', { authorization: 5, body: { auth_req_id: 'req-1' } });

// ---- lifecycles ----------------------------------------------------------------------------------------------------------------------
const mask = (v: any, id: string | undefined): any => JSON.parse(JSON.stringify(v ?? null, (_k, x) => (id !== undefined && x === id ? 'ID' : x)));
const lifecycle = async (kind: string, ops: any[]) => {
  let t = 1_000_000;
  const now = () => t;
  const b = kind === 'memory' ? T.createCibaBroker({ now, onComplete: () => { /* noop */ } }) : D.createDurableCibaBroker({ store: T.createMemoryApprovalStore(), now, decisionTtlSec: 100 });
  let id: string | undefined;
  const out: any[] = [];
  for (const op of ops) {
    if (op.op === 'now') { t = op.t; out.push(null); continue; }
    try {
      let v: any;
      if (op.op === 'start') { v = await b.start(op.stepUp ?? SU, op.opts); id = v.auth_req_id; v = { ...v, auth_req_id: 'ID' }; }
      else if (op.op === 'poll') v = await b.poll(id);
      else if (op.op === 'token') v = await b.token(id);
      else if (op.op === 'resolve') v = await b.resolve(id, op.decision, op.by);
      else if (op.op === 'get') v = await b.get(id);
      else if (op.op === 'unknown') v = await b[op.fn]('nope', 'approve', 'x');
      out.push({ ok: true, value: mask(v, id) });
    } catch (e) { out.push({ ok: false }); }
  }
  return out;
};
const L = (kind: string, name: string, ops: any[]) => o.run('lifecycle', kind + ': ' + name, lifecycle, [kind, ops]);
const T0 = 1_000_000;
for (const kind of ['memory', 'durable']) {
  await L(kind, 'approve then redeem once', [{ op: 'start' }, { op: 'poll' }, { op: 'resolve', decision: 'approve', by: 'owner' }, { op: 'now', t: T0 + 10_000 }, { op: 'token' }, { op: 'token' }, { op: 'get' }]);
  await L(kind, 'deny', [{ op: 'start' }, { op: 'resolve', decision: 'deny', by: 'owner' }, { op: 'now', t: T0 + 10_000 }, { op: 'token' }, { op: 'poll' }]);
  await L(kind, 'token pending and slow_down', [{ op: 'start' }, { op: 'token' }, { op: 'now', t: T0 + 1000 }, { op: 'token' }, { op: 'now', t: T0 + 100_000 }, { op: 'token' }, { op: 'now', t: T0 + 100_500 }, { op: 'token' }]);
  await L(kind, 'expiry', [{ op: 'start', opts: { expiresInSec: 60 } }, { op: 'now', t: T0 + 59_999 }, { op: 'poll' }, { op: 'now', t: T0 + 60_000 }, { op: 'poll' }, { op: 'token' }, { op: 'resolve', decision: 'approve', by: 'late' }]);
  await L(kind, 'start is idempotent while live', [{ op: 'start' }, { op: 'start' }, { op: 'resolve', decision: 'approve', by: 'a' }, { op: 'start' }, { op: 'get' }]);
  await L(kind, 'start again after expiry', [{ op: 'start', opts: { expiresInSec: 10 } }, { op: 'now', t: T0 + 20_000 }, { op: 'start' }, { op: 'poll' }]);
  await L(kind, 'start again after deny', [{ op: 'start' }, { op: 'resolve', decision: 'deny', by: 'a' }, { op: 'start' }, { op: 'poll' }]);
  await L(kind, 'double resolve refused', [{ op: 'start' }, { op: 'resolve', decision: 'approve', by: 'a' }, { op: 'resolve', decision: 'deny', by: 'b' }, { op: 'get' }]);
  await L(kind, 'poll is a read', [{ op: 'start' }, { op: 'poll' }, { op: 'poll' }, { op: 'now', t: T0 + 5000 }, { op: 'resolve', decision: 'approve', by: 'a' }, { op: 'poll' }, { op: 'poll' }, { op: 'now', t: T0 + 6000 }, { op: 'token' }]);
  await L(kind, 'unknown ids', [{ op: 'start' }, { op: 'unknown', fn: 'poll' }, { op: 'unknown', fn: 'token' }, { op: 'unknown', fn: 'resolve' }, { op: 'unknown', fn: 'get' }]);
  await L(kind, 'interval option', [{ op: 'start', opts: { interval: 30 } }, { op: 'token' }, { op: 'now', t: T0 + 29_999 }, { op: 'token' }, { op: 'now', t: T0 + 100_000 }, { op: 'token' }]);
  await L(kind, 'start refuses an unrenderable step-up', [{ op: 'start', stepUp: { ...SU, params: { x: 1 } } }]);
}
await L('durable', 'approval goes stale after the decision ttl', [{ op: 'start' }, { op: 'resolve', decision: 'approve', by: 'a' }, { op: 'now', t: T0 + 99_999 }, { op: 'poll' }, { op: 'now', t: T0 + 100_000 }, { op: 'poll' }, { op: 'token' }]);
await L('durable', 'resolve validates decision and decider', [{ op: 'start' }, { op: 'resolve', decision: 'maybe', by: 'a' }, { op: 'resolve', decision: 'approve', by: '' }, { op: 'resolve', decision: 'approve', by: 'a' }]);

refWrite(o, 'ciba');
