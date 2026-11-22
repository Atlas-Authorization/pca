// Oracle: @atlasauth/pca-actions business-rules.ts. Writes out/ref-actions-rules.json.gz.
// PORTING table (defs and rules are plain JSON; every result is JSON; a reference throw must throw)
//   businessRulesError(d, rules)             -> ActionBusinessRules.businessRulesError (null = well formed)
//   compileBusinessRules(d, rules)           -> compileBusinessRules (compiled doc as a JSON map)
//   businessRulesDigest(verb, rules)         -> businessRulesDigest
//   moneyOf(d) / minorUnits(v, exp, at)      -> moneyOf / minorUnits (long as number)
//   evaluateBusinessRules(compiled, input)   -> evaluateBusinessRules; input {params, subject?, now, counts?, resource?}
//   runRuleExamples(d, rules)                -> runRuleExamples
//   explainBusinessRules(d, rules)           -> explainBusinessRules
//   lintBusinessRules(d, rules)              -> lintBusinessRules
//   diffBusinessRules(d, prev, next)         -> diffBusinessRules
//   clockAt(now, tz)                         -> clockAt (null when unknown)
//   formatMoney(minor, ccy, exp)             -> formatMoney
//   signRulesReview(body, {$bytes: seed})    -> signRulesReview (Ed25519, deterministic)
//   rulesReviewError(r, d, rules, pins)      -> rulesReviewError (null = valid)
import * as BR0 from '../../../packages/pca-actions/src/business-rules.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed, variants } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BR = un(BR0), BI = un(B0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const o = new Oracle('actions-rules', 'tools/pca-audit/oracles/actions-rules.mts', 'TS-reference oracle for pca-actions business rules.');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const unb = (s: any) => Uint8Array.from(Buffer.from(s.$bytes, 'base64url'));

const base = clone(BI.BUILTIN_DEFS[0]);
const mk = (verb: string, params: any) => ({ ...clone(base), verb, params });
const money = (ccy: any, extra: any = {}) => ({ type: 'integer', role: 'money.amount', min: 1, max: 100_000_000, unit: { kind: 'money', ccy, exp: 2 }, ...extra });
const D_PAY = mk('pay.send', { amount: money({ from: 'currency' }), currency: { type: 'string', values: ['USD', 'EUR', 'GBP'], max_len: 3 }, to: { type: 'string', role: 'id.account', max_len: 64 }, memo: { type: 'string', max_len: 100, required: false }, note: { type: 'string', max_len: 20 } });
const D_USD = mk('pay.usd', { amount: money('USD', { min: 500, max: 20_000 }), account: { type: 'string', role: 'id.account', max_len: 64 }, level: { type: 'integer', min: 0, max: 9 } });
const D_JPY = mk('pay.jpy', { amount: { ...money('JPY'), unit: { kind: 'money', ccy: 'JPY', exp: 0 } } });
const D_MAIL = mk('mail.send', { to: { type: 'string', role: 'contact.email', format: 'email', max_len: 254 }, body: { type: 'string', max_len: 1000 }, owner: { type: 'string', role: 'id.user', max_len: 64 } });
const D_LIST = mk('mail.bulk', { to: { type: 'array', items: 'string', max_items: 3 }, big: { type: 'array', items: 'string', max_items: 200 }, ints: { type: 'array', items: 'integer', max_items: 3 }, uid: { type: 'integer', role: 'id.user', min: 0, max: 1000 } });
const D_NONE = mk('plain.act', { a: { type: 'string', max_len: 8 }, flag: { type: 'boolean' } });
const D_TWO = mk('pay.two', { a: money('USD'), b: money('EUR') });
const D_NOINT = mk('pay.noint', { amount: { type: 'string', role: 'money.amount', max_len: 10 } });
const D_NOUNIT = mk('pay.nounit', { amount: { type: 'integer', role: 'money.amount', min: 1, max: 100 } });
const D_BADFROM = mk('pay.badfrom', { amount: money({ from: 'missing' }) });
const DEFS: [string, any][] = [['pay', D_PAY], ['usd', D_USD], ['jpy', D_JPY], ['mail', D_MAIL], ['list', D_LIST], ['none', D_NONE], ['two', D_TWO], ['noint', D_NOINT], ['nounit', D_NOUNIT], ['badfrom', D_BADFROM]];

const R: [string, any][] = [
  ['amount max', { amount: { max: { USD: '250.00', EUR: 20000 } } }],
  ['amount dec', { amount: { max: { USD: '250', GBP: '1000.5' } } }],
  ['amount big', { amount: { max: { USD: '99999999999999.99' } } }],
  ['amount over', { amount: { max: { USD: '1.234' } } }],
  ['amount neg', { amount: { max: { USD: -1 } } }],
  ['amount frac', { amount: { max: { USD: 1.5 } } }],
  ['amount badccy', { amount: { max: { usd: 5 } } }],
  ['amount empty', { amount: { max: {} } }],
  ['amount extra', { amount: { max: { USD: 5 }, min: 1 } }],
  ['amount jpy', { amount: { max: { JPY: '5000' } } }],
  ['amount jpy dec', { amount: { max: { JPY: '5000.5' } } }],
  ['amount below min', { amount: { max: { USD: 100 } } }],
  ['amount above max', { amount: { max: { USD: 20_000 } } }],
  ['approval above', { approval: { above: { USD: '100', EUR: 9000 }, approvers: 2, group: 'finance' } }],
  ['approval always', { approval: { always: true } }],
  ['approval always false', { approval: { always: false } }],
  ['approval both', { approval: { always: true, above: { USD: 5 } } }],
  ['approval none', { approval: {} }],
  ['approval approvers 0', { approval: { always: true, approvers: 0 } }],
  ['approval approvers 17', { approval: { always: true, approvers: 17 } }],
  ['approval approvers 1', { approval: { always: true, approvers: 1, group: 'a' } }],
  ['approval group bad', { approval: { always: true, group: 'Bad Group' } }],
  ['approval above ceil', { amount: { max: { USD: 1000 } }, approval: { above: { USD: 1000 } } }],
  ['approval above noceil', { amount: { max: { USD: 1000 } }, approval: { above: { EUR: 100 } } }],
  ['scope', { scope: [{ param: 'to', caller: 'account_id' }] }],
  ['scope role', { scope: [{ role: 'id.account', caller: 'acct' }, { param: 'note', caller: 'tag' }] }],
  ['scope int', { scope: [{ param: 'uid', caller: 'user' }] }],
  ['scope bool', { scope: [{ param: 'flag', caller: 'user' }] }],
  ['scope both', { scope: [{ param: 'to', role: 'id.account', caller: 'x' }] }],
  ['scope none', { scope: [{ caller: 'x' }] }],
  ['scope missing', { scope: [{ param: 'nope', caller: 'x' }] }],
  ['scope badcaller', { scope: [{ param: 'to', caller: 'Bad-Name' }] }],
  ['scope empty', { scope: [] }],
  ['rate', { rate: [{ max: 5, per: 'hour' }, { max: 20, per: 'day', by: 'org' }] }],
  ['rate dup', { rate: [{ max: 5, per: 'hour' }, { max: 3, per: 'hour' }, { max: 2, per: 'day' }] }],
  ['rate day below hour', { rate: [{ max: 5, per: 'hour' }, { max: 4, per: 'day' }] }],
  ['rate bad per', { rate: [{ max: 5, per: 'week' }] }],
  ['rate bad max', { rate: [{ max: 0, per: 'hour' }] }],
  ['rate bad by', { rate: [{ max: 5, per: 'hour', by: 'user' }] }],
  ['rate too many', { rate: [1, 2, 3, 4, 5].map((n) => ({ max: n, per: 'hour' })) }],
  ['hours day', { hours: { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '09:00', to: '17:30', tz: 'America/New_York' } }],
  ['hours deny', { hours: { days: ['sat', 'sun'], from: '00:00', to: '23:59', tz: 'UTC', outside: 'deny' } }],
  ['hours overnight', { hours: { days: ['fri', 'sat'], from: '22:00', to: '06:00', tz: 'Europe/Berlin' } }],
  ['hours empty', { hours: { days: ['mon'], from: '09:00', to: '09:00', tz: 'Asia/Tokyo', outside: 'deny' } }],
  ['hours mon wed', { hours: { days: ['wed', 'mon'], from: '08:00', to: '12:00', tz: 'Australia/Sydney' } }],
  ['hours bad tz', { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'Mars/Base' } }],
  ['hours bad time', { hours: { days: ['mon'], from: '9:00', to: '17:00', tz: 'UTC' } }],
  ['hours bad day', { hours: { days: ['mon', 'mon'], from: '09:00', to: '17:00', tz: 'UTC' } }],
  ['hours bad outside', { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'UTC', outside: 'allow' } }],
  ['recipients str', { recipients: { param: 'to', domains: ['example.com', 'corp.example.org'], addresses: ['boss@gmail.com', 'a.b+c@x.io'] } }],
  ['recipients domains', { recipients: { role: 'contact.email', domains: ['example.com'] } }],
  ['recipients addresses', { recipients: { param: 'to', addresses: ['z@x.io', 'a@x.io'] } }],
  ['recipients list', { recipients: { param: 'to', domains: ['example.com'], addresses: ['x@y.io'] } }],
  ['recipients big list', { recipients: { param: 'big', domains: ['example.com'] } }],
  ['recipients int list', { recipients: { param: 'ints', domains: ['example.com'] } }],
  ['recipients bad domain', { recipients: { param: 'to', domains: ['Example.com'] } }],
  ['recipients bad addr', { recipients: { param: 'to', addresses: ['nobody'] } }],
  ['recipients none', { recipients: { param: 'to' } }],
  ['recipients int', { recipients: { param: 'uid', domains: ['example.com'] } }],
  ['required', { required: ['to', 'memo'] }],
  ['required note', { required: ['note', 'a', 'flag'] }],
  ['required dup', { required: ['to', 'to'] }],
  ['required missing', { required: ['nope'] }],
  ['required empty', { required: [] }],
  ['combo pay', { amount: { max: { USD: 1000, EUR: 900 } }, approval: { above: { USD: 500 }, approvers: 2 }, rate: [{ max: 3, per: 'hour' }], hours: { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '08:00', to: '18:00', tz: 'Europe/London' }, required: ['to'], scope: [{ param: 'to', caller: 'acct' }] }],
  ['combo mail', { recipients: { param: 'to', domains: ['example.com'] }, scope: [{ param: 'owner', caller: 'uid' }], required: ['body'], rate: [{ max: 10, per: 'day' }] }],
  ['only examples', { examples: [{ params: {}, expect: 'allow' }] }],
  ['empty', {}],
  ['unknown', { frobnicate: 1 }],
  ['not object', []],
  ['null', null],
  ['string', 'rules'],
  ['examples ok', { required: ['to'], examples: [{ params: { to: 'x' }, expect: 'allow' }, { params: {}, expect: 'deny' }, { params: { to: '' }, expect: 'deny' }, { params: { to: 'x' }, expect: 'deny' }] }],
  ['examples bad at', { required: ['to'], examples: [{ params: {}, at: '2026-01-07 15:00:00', expect: 'deny' }] }],
  ['examples bad month', { required: ['to'], examples: [{ params: {}, at: '2026-13-07T15:00:00Z', expect: 'deny' }] }],
  ['examples rollover day', { required: ['to'], examples: [{ params: {}, at: '2026-02-31T15:00:00Z', expect: 'deny' }] }],
  ['examples h24', { required: ['to'], examples: [{ params: {}, at: '2026-02-01T24:00:00Z', expect: 'deny' }] }],
  ['examples bad expect', { required: ['to'], examples: [{ params: {}, expect: 'maybe' }] }],
  ['examples bad recent', { rate: [{ max: 2, per: 'hour' }], examples: [{ params: {}, recent: { 0: -1 }, expect: 'deny' }] }],
  ['examples rate', { rate: [{ max: 2, per: 'hour' }, { max: 9, per: 'day' }], examples: [{ params: {}, recent: { 0: 1 }, expect: 'allow' }, { params: {}, recent: { 0: 2 }, expect: 'deny' }, { params: {}, recent: { 1: 9 }, expect: 'deny' }, { params: {}, expect: 'allow' }] }],
  ['examples pay', { amount: { max: { USD: 1000, EUR: 900 } }, approval: { above: { USD: 500 }, approvers: 2 }, examples: [
    { params: { amount: 400, currency: 'USD' }, expect: 'allow' }, { params: { amount: 600, currency: 'USD' }, expect: 'escalate' }, { params: { amount: 1200, currency: 'USD' }, expect: 'deny' },
    { params: { amount: 1000, currency: 'GBP' }, expect: 'deny' }, { params: { amount: 10 }, expect: 'deny' }, { params: { amount: 950, currency: 'EUR' }, expect: 'deny' }] }],
  ['examples hours', { hours: { days: ['wed'], from: '09:00', to: '17:00', tz: 'UTC' }, examples: [{ params: {}, expect: 'allow' }, { params: {}, at: '2026-01-08T15:00:00Z', expect: 'escalate' }, { params: {}, at: '2026-01-07T08:59:59Z', expect: 'escalate' }] }],
  ['examples scope', { scope: [{ param: 'to', caller: 'acct' }], examples: [{ params: { to: 'a1' }, caller: { acct: 'a1' }, expect: 'allow' }, { params: { to: 'a1' }, caller: { acct: 'a2' }, expect: 'deny' }, { params: { to: 'a1' }, expect: 'deny' }] }],
  ['examples recipients', { recipients: { param: 'to', domains: ['example.com'], addresses: ['x@y.io'] }, examples: [
    { params: { to: 'a@example.com' }, expect: 'allow' }, { params: { to: 'x@y.io' }, expect: 'allow' }, { params: { to: 'a@evil.com' }, expect: 'deny' }, { params: { to: 'a@sub.example.com' }, expect: 'deny' }, { params: {}, expect: 'deny' }] }],
  ['examples list', { recipients: { param: 'to', domains: ['example.com'] }, examples: [
    { params: { to: ['a@example.com', 'b@example.com'] }, expect: 'allow' }, { params: { to: ['a@example.com', 'b@evil.com'] }, expect: 'deny' }, { params: { to: ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com'] }, expect: 'deny' }, { params: { to: [] }, expect: 'allow' }] }],
  ['examples approval always', { approval: { always: true, group: 'ops' }, examples: [{ params: {}, expect: 'escalate' }, { params: {}, expect: 'allow' }] }],
];
const cmp = (a: any) => a;
void cmp;

for (const [dn, d] of DEFS) {
  for (const [rn, r] of R) {
    const n = `${dn} ${rn}`;
    await o.run('businessRulesError', n, (dd: any, rr: any) => BR.businessRulesError(dd, rr), [d, r]);
    if (!['pay', 'usd', 'mail', 'list'].includes(dn)) continue;
    await o.run('compileBusinessRules', n, (dd: any, rr: any) => BR.compileBusinessRules(dd, rr), [d, r]);
    await o.run('explainBusinessRules', n, (dd: any, rr: any) => BR.explainBusinessRules(dd, rr), [d, r]);
    await o.run('lintBusinessRules', n, (dd: any, rr: any) => BR.lintBusinessRules(dd, rr), [d, r]);
    await o.run('runRuleExamples', n, (dd: any, rr: any) => BR.runRuleExamples(dd, rr), [d, r]);
  }
  await o.run('moneyOf', dn, (dd: any) => BR.moneyOf(dd), [d]);
}
for (const [rn, r] of R.filter(([, x]) => x !== null && typeof x === 'object' && !Array.isArray(x))) await o.run('businessRulesDigest', rn, (v: string, rr: any) => BR.businessRulesDigest(v, rr), ['pay.send', r]);

// diff: every pair of a pay-shaped and a mail-shaped block
const PAYR = R.filter(([n]) => /^(amount max|amount dec|approval above|approval always|combo pay|rate|scope|required|hours day|hours overnight|hours deny|hours mon wed|examples pay)/.test(n) && !/ (bad|over|neg|frac|empty|extra|both|none|too many|missing|dup)/.test(n));
for (const [an, a] of [['absent', undefined], ...PAYR] as [string, any][]) for (const [bn, b] of [['absent', undefined], ...PAYR] as [string, any][]) {
  await o.run('diffBusinessRules', `pay ${an} -> ${bn}`, (dd: any, p: any, q: any) => BR.diffBusinessRules(dd, p, q), [D_PAY, a, b]);
}
const MAILR = R.filter(([n]) => /^(recipients (str|domains|addresses|list)|combo mail|required$|scope$)/.test(n));
for (const [an, a] of [['absent', undefined], ...MAILR] as [string, any][]) for (const [bn, b] of [['absent', undefined], ...MAILR] as [string, any][]) {
  await o.run('diffBusinessRules', `mail ${an} -> ${bn}`, (dd: any, p: any, q: any) => BR.diffBusinessRules(dd, p, q), [D_MAIL, a, b]);
}
const widen = (a: any, f: (x: any) => void) => { const c = clone(a); f(c); return c; };
const H = { hours: { days: ['mon', 'tue'], from: '09:00', to: '17:00', tz: 'UTC' } };
for (const [n, b] of [
  ['shorter', widen(H, (x) => (x.hours.to = '16:00'))], ['longer', widen(H, (x) => (x.hours.to = '18:00'))], ['day added', widen(H, (x) => x.hours.days.push('wed'))], ['day removed', widen(H, (x) => x.hours.days.pop())],
  ['tz', widen(H, (x) => (x.hours.tz = 'Asia/Tokyo'))], ['deny', widen(H, (x) => (x.hours.outside = 'deny'))], ['overnight', widen(H, (x) => { x.hours.from = '22:00'; x.hours.to = '06:00'; })], ['same', clone(H)],
] as [string, any][]) {
  await o.run('diffBusinessRules', `hours ${n}`, (dd: any, p: any, q: any) => BR.diffBusinessRules(dd, p, q), [D_PAY, H, b]);
  await o.run('diffBusinessRules', `hours rev ${n}`, (dd: any, p: any, q: any) => BR.diffBusinessRules(dd, p, q), [D_PAY, b, H]);
}
await o.run('diffBusinessRules', 'null prev', (dd: any, p: any, q: any) => BR.diffBusinessRules(dd, p, q), [D_PAY, null, R[0][1]]);

// evaluation over compiled blocks
const T = (s: string) => Date.parse(s);
const NOWS = [T('2026-01-07T15:00:00Z'), T('2026-01-07T08:59:00Z'), T('2026-01-10T12:00:00Z'), T('2026-01-09T23:30:00Z'), T('2026-01-10T03:00:00Z'), T('2026-07-01T03:30:00Z'), T('2026-03-08T07:30:00Z'), 0, -86400000, 1.5e12 + 0.7];
const PARAMS = [
  {}, { amount: 100, currency: 'USD' }, { amount: 600, currency: 'USD' }, { amount: 2000, currency: 'USD' }, { amount: 1000, currency: 'GBP' }, { amount: 950, currency: 'EUR', to: 'a1' }, { amount: 100, currency: 'USD', to: 'a1', memo: '', note: 'n' },
  { to: 'a@example.com', body: 'x', owner: 'u1' }, { to: 'a@evil.com' }, { to: ['a@example.com', 'x@y.io'] }, { to: ['a@evil.com'] }, { to: [] }, { to: 'x@y.io' }, { uid: 5 }, { uid: '5' },
];
const SUBJECTS = [undefined, {}, { acct: 'a1' }, { uid: 'u1' }, { acct: 'a2', uid: 5 }, { user: 5 }];
const COUNTS = [undefined, {}, { rate_0: 0 }, { rate_0: 2, rate_1: 0 }, { rate_0: 1, rate_1: 9 }, { rate_0: -1 }, { rate_0: 1.5 }, { rate_0: '3' }];
let ev = 0;
const compiled: [string, any, any][] = [];
for (const [dn, d] of DEFS) for (const [rn, r] of R) {
  let c: any = null;
  try { c = BR.compileBusinessRules(d, r); } catch { continue; }
  compiled.push([`${dn} ${rn}`, d, c]);
}
for (const [n, , c] of compiled) {
  const hasHours = c.clock_tz !== undefined, hasRate = c.accumulators.length > 0;
  const nows = hasHours ? NOWS : [NOWS[0]];
  const counts = hasRate ? COUNTS : [undefined, { rate_0: 1 }];
  for (const params of PARAMS) for (const subject of SUBJECTS.slice(0, hasHours || hasRate ? 2 : SUBJECTS.length)) for (const now of nows) for (const cn of counts) {
    if (ev++ % 7 !== 0 || ev > 6000) continue;
    const input: any = { params, ...(subject !== undefined ? { subject } : {}), now, ...(cn !== undefined ? { counts: cn } : {}) };
    await o.run('evaluateBusinessRules', `${n} #${ev}`, (cc: any, i: any) => BR.evaluateBusinessRules(cc, i), [c, input]);
  }
}
for (const tz of ['UTC', 'America/New_York', 'Europe/Berlin', 'Asia/Kolkata', 'Australia/Lord_Howe', 'Asia/Tokyo', 'Pacific/Auckland'])
  for (const now of NOWS) await o.run('clockAt', `${tz} ${now}`, (t: number, z: string) => BR.clockAt(t, z), [now, tz]);
await o.run('clockAt', 'NaN', (t: number, z: string) => BR.clockAt(t, z), [null, 'UTC']);
await o.run('clockAt', 'huge', (t: number, z: string) => BR.clockAt(t, z), [8.64e15 + 1, 'UTC']);
await o.run('clockAt', 'edge', (t: number, z: string) => BR.clockAt(t, z), [8.64e15, 'UTC']);
for (const [v, e] of [[0, 2], [5, 2], [12345, 2], [99, 0], [7, 3], [100000, 6], [9007199254740991, 2]] as [number, number][]) await o.run('formatMoney', `${v}/${e}`, (a: number, b: string, c: number) => BR.formatMoney(a, b, c), [v, 'USD', e]);
for (const [v, e] of [['250', 2], ['250.5', 2], ['0.01', 2], ['0', 0], ['0.1', 0], ['007', 2], ['1e3', 2], ['', 2], [' 1', 2], [12, 2], [-1, 2], [1.5, 2], [9007199254740992, 2], ['9007199254740.99', 2], ['999999999999999.99', 2], ['1.234567', 6], ['1.2345678', 6], [null, 2], [true, 2]] as [any, number][])
  await o.run('minorUnits', `${JSON.stringify(v)}/${e}`, (a: any, b: number) => BR.minorUnits(a, b, 'x'), [v, e]);

// hostile variants of a representative block: only well-defined (non-engine) error messages are compared
const SEEDR = R.find(([n]) => n === 'combo pay')![1];
let hv = 0;
for (const [lbl, v] of variants(SEEDR, { maxPaths: 120, hostile: [null, 0, 1, '', 'x', [], {}, true, -1] })) {
  let msg: any;
  try { msg = BR.businessRulesError(D_PAY, v); } catch { continue; }
  if (typeof msg === 'string' && /Cannot |is not |undefined|iterable|function/.test(msg)) continue;
  if (hv++ > 400) break;
  await o.run('businessRulesError', `v ${lbl}`, (dd: any, rr: any) => BR.businessRulesError(dd, rr), [D_PAY, v]);
}

// reviews
const SK = seed('ref-actions-rules/reviewer'), SK2 = seed('ref-actions-rules/other');
const kd = (sk: Uint8Array) => P.b64u(P.publicKeyOf(sk));
const RULES = R.find(([n]) => n === 'combo pay')![1];
const dd = D_PAY;
const body = (over: any = {}) => ({ verb: dd.verb, def_digest: P.hashCanonical ? undefined : undefined, rules_digest: BR.businessRulesDigest(dd.verb, RULES), reviewer_kid: 'rv1', ts: 1_800_000_000, ...over });
let DD: any = null;
try { DD = (await import('../../../packages/pca-actions/src/digest.ts')).defDigest(dd); } catch { DD = 'x'; }
const mkBody = (over: any = {}) => ({ ...body(), def_digest: DD, ...over });
const PINS = { keys: [{ kid: 'rv1', pk: kd(SK), roles: ['reviewer'] }, { kid: 'rv2', pk: kd(SK2), roles: ['importer'] }, { kid: 'rv3', pk: kd(SK2), roles: ['reviewer'], not_before: 1_800_000_100, not_after: 1_800_000_200 }] };
await o.run('rulesReviewMessage', 'plain', (b: any) => ({ $bytes: P.b64u(BR.rulesReviewMessage(b)) }), [mkBody()]);
await o.run('signRulesReview', 'plain', (b: any, s: any) => BR.signRulesReview(b, unb(s)), [mkBody(), bytes(SK)]);
const sr = (b: any, sk = SK) => BR.signRulesReview(b, sk);
const RV = (n: string, r: any, d: any = dd, rules: any = RULES, pins: any = PINS) => o.run('rulesReviewError', n, (a: any, b: any, c: any, e: any) => BR.rulesReviewError(a, b, c, e), [r, d, rules, pins]);
await RV('ok', sr(mkBody()));
await RV('no pins', sr(mkBody()), dd, RULES, undefined);
await RV('bad pins', sr(mkBody()), dd, RULES, { keys: [{ kid: 'x' }] });
await RV('not object', 5);
await RV('other verb', sr(mkBody({ verb: 'other.verb' })));
await RV('other def', sr(mkBody({ def_digest: 'A'.repeat(43) })));
await RV('other rules', sr(mkBody({ rules_digest: 'A'.repeat(43) })));
await RV('other rules arg', sr(mkBody()), dd, { required: ['to'] });
await RV('unsigned', mkBody());
await RV('bad ts', sr(mkBody({ ts: 1.5 })));
await RV('no key', sr(mkBody({ reviewer_kid: 'nobody' })));
await RV('wrong role', sr(mkBody({ reviewer_kid: 'rv2' }), SK2));
await RV('too early', sr(mkBody({ reviewer_kid: 'rv3', ts: 1_800_000_050 }), SK2));
await RV('in window', sr(mkBody({ reviewer_kid: 'rv3', ts: 1_800_000_150 }), SK2));
await RV('too late', sr(mkBody({ reviewer_kid: 'rv3', ts: 1_800_000_250 }), SK2));
await RV('wrong signer', sr(mkBody(), SK2));
await RV('tampered', { ...sr(mkBody()), ts: 1_800_000_001 });
await RV('bad sig', { ...sr(mkBody()), sig: 'A'.repeat(86) });
await RV('short sig', { ...sr(mkBody()), sig: 'AAAA' });
refWrite(o, 'actions-rules');
