// Oracle (python lane): @atlasauth/pca-actions business-rules.ts. Writes out/ref-actions-rules-py.json.gz.
// PORTING table: same names as the module's exports (resolveParamRef(def, ref, at) moneyOf(def) minorUnits(v, exp, at) knownTimeZone(tz) businessRulesError(def, rules)
//   businessRulesDigest(verb, rules) compileBusinessRules(def, rules) clockAt(now, tz) evaluateBusinessRules(compiled, input) runRuleExamples(def, rules) formatMoney explainBusinessRules
//   lintBusinessRules diffBusinessRules(def, prev, next) rulesReviewMessage signRulesReview(body, {$bytes}) rulesReviewError(review, def, rules, pins)); a throw is compared by presence only.
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as BR0 from '../../../packages/pca-actions/src/business-rules.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), R = un(BR0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const o = new Oracle('actions-rules-py', 'tools/pca-audit/oracles/actions-rules-py.mts', 'TS-reference oracle for pca-actions business rules (python lane).');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const sk = (b: Uint8Array) => Uint8Array.from(Buffer.from((b as any).$bytes, 'base64url'));

const BASE = clone(BI.BUILTIN_DEFS.find((d: any) => d.verb === 'stripe.charge'));
const mut = (f: (x: any) => void, base: any = BASE) => { const c = clone(base); f(c); return c; };
const FX = mut((x) => {
  x.verb = 'acme.pay.send';
  x.params = {
    amount: { type: 'integer', role: 'money.amount', min: 1, max: 1_000_000_00, unit: { kind: 'money', ccy: { from: 'currency' }, exp: 2 } },
    currency: { type: 'string', role: 'money.currency', format: 'iso_currency', values: ['USD', 'EUR', 'GBP'], max_len: 3 },
    to: { type: 'string', role: 'contact.email', format: 'email', max_len: 254 },
    cc: { type: 'array', items: 'string', max_items: 3 },
    many: { type: 'array', items: 'string', max_items: 200 },
    customer: { type: 'string', role: 'id.acme.customer', max_len: 64 },
    note: { type: 'string', max_len: 100, required: false },
    count: { type: 'integer', min: 0, max: 9 },
    idempotency_key: { type: 'string', max_len: 128 },
  };
});
const LIT = BASE; // USD literal, amount param named amount
const NOMONEY = mut((x) => { x.verb = 'acme.note.add'; x.params = { note: { type: 'string', max_len: 10 }, owner: { type: 'string', max_len: 10, role: 'id.acme.owner' } }; x.effects = ['create']; });
const DEFS: [string, any][] = [['fx', FX], ['lit', LIT], ['nomoney', NOMONEY]];

const RULES: [string, any][] = [
  ['amount ok', { amount: { max: { USD: 5000, EUR: '250.50', GBP: 100 } } }], ['amount usd', { amount: { max: { USD: '12.34' } } }], ['amount decimal bad', { amount: { max: { USD: '12.345' } } }],
  ['amount neg', { amount: { max: { USD: -1 } } }], ['amount float', { amount: { max: { USD: 1.5 } } }], ['amount bad ccy', { amount: { max: { usd: 5 } } }], ['amount empty', { amount: { max: {} } }], ['amount not obj', { amount: 5 }],
  ['amount extra', { amount: { max: { USD: 5 }, x: 1 } }], ['amount big', { amount: { max: { USD: '99999999999999999' } } }], ['amount true', { amount: { max: { USD: true } } }],
  ['approval above', { approval: { above: { USD: '100' }, approvers: 2, group: 'finance' } }], ['approval always', { approval: { always: true } }], ['approval both', { approval: { always: true, above: { USD: 1 } } }],
  ['approval none', { approval: {} }], ['approval approvers 0', { approval: { always: true, approvers: 0 } }], ['approval approvers 17', { approval: { always: true, approvers: 17 } }], ['approval group bad', { approval: { always: true, group: 'Bad Group' } }],
  ['approval always false', { approval: { always: false } }], ['approval 1 eur', { approval: { above: { EUR: 50, USD: 70 } } }],
  ['scope param', { scope: [{ param: 'customer', caller: 'customer_id' }] }], ['scope role', { scope: [{ role: 'id.acme.customer', caller: 'cid' }] }], ['scope both', { scope: [{ param: 'customer', role: 'x', caller: 'c' }] }],
  ['scope unknown', { scope: [{ param: 'nope', caller: 'c' }] }], ['scope bad caller', { scope: [{ param: 'customer', caller: 'Bad' }] }], ['scope empty', { scope: [] }], ['scope bad type', { scope: [{ param: 'cc', caller: 'c' }] }],
  ['scope role none', { scope: [{ role: 'nope.role', caller: 'c' }] }], ['scope notobj', { scope: [5] }],
  ['rate ok', { rate: [{ max: 3, per: 'hour' }, { max: 10, per: 'day', by: 'org' }] }], ['rate dup', { rate: [{ max: 3, per: 'hour' }, { max: 2, per: 'hour' }, { max: 2, per: 'day' }] }], ['rate bad per', { rate: [{ max: 3, per: 'week' }] }],
  ['rate max0', { rate: [{ max: 0, per: 'hour' }] }], ['rate by bad', { rate: [{ max: 1, per: 'hour', by: 'user' }] }], ['rate five', { rate: [1, 2, 3, 4, 5].map((n) => ({ max: n, per: 'hour' })) }],
  ['hours day', { hours: { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '09:00', to: '17:00', tz: 'America/New_York' } }], ['hours overnight', { hours: { days: ['fri', 'sat'], from: '22:00', to: '06:00', tz: 'Europe/Berlin', outside: 'deny' } }],
  ['hours same', { hours: { days: ['mon'], from: '09:00', to: '09:00', tz: 'UTC' } }], ['hours bad tz', { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'Nope/Zone' } }], ['hours bad day', { hours: { days: ['monday'], from: '09:00', to: '17:00', tz: 'UTC' } }],
  ['hours dup day', { hours: { days: ['mon', 'mon'], from: '09:00', to: '17:00', tz: 'UTC' } }], ['hours bad time', { hours: { days: ['mon'], from: '9:00', to: '25:00', tz: 'UTC' } }], ['hours outside bad', { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'UTC', outside: 'allow' } }],
  ['hours kolkata', { hours: { days: ['sun', 'mon', 'tue'], from: '08:30', to: '20:15', tz: 'Asia/Kolkata' } }], ['hours lower tz', { hours: { days: ['wed'], from: '00:00', to: '23:59', tz: 'america/new_york' } }], ['hours all', { hours: { days: ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], from: '00:00', to: '23:59', tz: 'Pacific/Auckland' } }],
  ['recip domains', { recipients: { param: 'to', domains: ['example.com', 'corp.example.org'] } }], ['recip addr', { recipients: { role: 'contact.email', addresses: ['bob@x.io', 'amy@y.io'] } }], ['recip both', { recipients: { param: 'to', domains: ['example.com'], addresses: ['z@q.io'] } }],
  ['recip list', { recipients: { param: 'cc', domains: ['example.com'] } }], ['recip unbounded', { recipients: { param: 'many', domains: ['example.com'] } }], ['recip none', { recipients: { param: 'to' } }], ['recip bad domain', { recipients: { param: 'to', domains: ['Example.com'] } }],
  ['recip bad addr', { recipients: { param: 'to', addresses: ['nope'] } }], ['recip wrong type', { recipients: { param: 'count', domains: ['a.com'] } }],
  ['required', { required: ['note', 'to'] }], ['required dup', { required: ['to', 'to'] }], ['required unknown', { required: ['zz'] }], ['required empty', { required: [] }],
  ['combo', { amount: { max: { USD: 5000, EUR: 4000 } }, approval: { above: { USD: 1000 } }, scope: [{ param: 'customer', caller: 'cid' }], rate: [{ max: 5, per: 'hour' }], hours: { days: ['mon', 'tue'], from: '08:00', to: '18:00', tz: 'UTC' }, recipients: { param: 'to', domains: ['a.com'] }, required: ['note'] }],
  ['examples', { amount: { max: { USD: 100 } }, examples: [{ params: { amount: 50 }, expect: 'allow' }, { params: { amount: 500 }, expect: 'deny' }, { params: { amount: 5 }, expect: 'deny' }] }],
  ['examples bad at', { required: ['to'], examples: [{ params: {}, at: '2026-13-01T00:00:00Z', expect: 'deny' }] }], ['examples bad expect', { required: ['to'], examples: [{ params: {}, expect: 'maybe' }] }],
  ['examples day31', { required: ['to'], examples: [{ params: {}, at: '2026-02-31T10:00:00Z', expect: 'deny' }, { params: {}, at: '2026-01-01T24:00:00Z', expect: 'deny' }] }], ['examples recent', { rate: [{ max: 2, per: 'hour' }], examples: [{ params: {}, recent: { '0': 2 }, expect: 'deny' }, { params: {}, recent: { '0': 1 }, expect: 'allow' }, { params: {}, recent: { '0': -1 }, expect: 'allow' }] }],
  ['only examples', { examples: [] }], ['unknown key', { amount: { max: { USD: 1 } }, bogus: 1 }], ['empty', {}], ['null', null], ['array', []], ['string', 'x'],
];
const rnames = RULES.map(([n]) => n);
for (const [dn, d] of DEFS) {
  for (const [rn, r] of RULES) {
    await o.run('businessRulesError', `${dn} ${rn}`, R.businessRulesError, [d, r]);
    await o.run('compileBusinessRules', `${dn} ${rn}`, R.compileBusinessRules, [d, r]);
    await o.run('explainBusinessRules', `${dn} ${rn}`, R.explainBusinessRules, [d, r]);
    await o.run('lintBusinessRules', `${dn} ${rn}`, R.lintBusinessRules, [d, r]);
    await o.run('runRuleExamples', `${dn} ${rn}`, R.runRuleExamples, [d, r]);
    if (r && typeof r === 'object' && !Array.isArray(r)) await o.run('businessRulesDigest', `${dn} ${rn}`, R.businessRulesDigest, [d.verb, r]);
  }
}
// resolveParamRef / moneyOf / minorUnits / tz / clock / format
for (const [dn, d] of DEFS) {
  await o.run('moneyOf', dn, R.moneyOf, [d]);
  for (const ref of [{ param: 'customer' }, { role: 'id.acme.customer' }, { param: 'nope' }, { role: 'x' }, {}, { param: 'a', role: 'b' }, null, 5, { param: 5 }, { role: 'money.amount' }, { param: '__proto__' }]) await o.run('resolveParamRef', `${dn} ${JSON.stringify(ref)}`, R.resolveParamRef, [d, ref, 'at']);
}
for (const v of [0, 5, -1, 1.5, '12', '12.5', '12.50', '12.505', '0', '00', '1e3', '', 'abc', true, null, '999999999999999', '9007199254740993', 9007199254740991, 9007199254740992, '1.', '.5', ' 1']) for (const e of [0, 2, 3]) await o.run('minorUnits', `${JSON.stringify(v)} ${e}`, R.minorUnits, [v, e, 'at']);
for (const tz of ['UTC', 'America/New_York', 'Europe/Berlin', 'Asia/Kolkata', 'Pacific/Auckland', 'america/new_york', 'utc', 'Nope/Zone', '', 'A'.repeat(65), 'bad zone', 'Etc/GMT+5', 'EST', 5, null]) await o.run('knownTimeZone', String(tz), R.knownTimeZone, [tz]);
const NOWS = [0, 1767225600000, 1767225600000 + 3600_000 * 14, Date.parse('2026-03-08T06:59:59Z'), Date.parse('2026-03-08T07:00:00Z'), Date.parse('2026-11-01T05:59:59Z'), Date.parse('2026-11-01T06:00:00Z'), Date.parse('2026-01-07T15:00:00Z'), 1.5, -1000, Date.parse('2026-06-30T23:59:59Z')];
for (const tz of ['UTC', 'America/New_York', 'Asia/Kolkata', 'Pacific/Auckland', 'Europe/Berlin']) for (const n of NOWS) await o.run('clockAt', `${tz} ${n}`, R.clockAt, [n, tz]);
for (const n of ['5', null]) await o.run('clockAt', `bad ${String(n)}`, R.clockAt, [n, 'UTC']);
for (const [m, c, e] of [[12345, 'USD', 2], [5, 'USD', 2], [0, 'JPY', 0], [100, 'JPY', 0], [1, 'KWD', 3], [123456789, 'USD', 2]] as any[]) await o.run('formatMoney', `${m} ${c} ${e}`, R.formatMoney, [m, c, e]);

// evaluation: compile then evaluate over input variants
const INPUTS = [
  { params: { amount: 500, currency: 'USD', to: 'a@example.com', cc: [], customer: 'c1', note: 'x', count: 1 }, subject: { customer_id: 'c1', cid: 'c1' }, now: Date.parse('2026-01-07T15:00:00Z'), counts: { rate_0: 0, rate_1: 0 } },
  { params: { amount: 9999999, currency: 'EUR', to: 'x@evil.com', cc: ['a@example.com', 'b@evil.com'], customer: 'c2', note: '', count: 1 }, subject: { customer_id: 'c1' }, now: Date.parse('2026-01-10T03:00:00Z'), counts: { rate_0: 5, rate_1: 99 } },
  { params: { amount: 100, currency: 'JPY', to: 'bob@x.io', cc: ['a@example.com'], customer: 'c1' }, now: Date.parse('2026-01-11T23:30:00Z') },
  { params: { amount: 100, currency: 'GBP', to: 'amy@y.io', cc: ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com'], customer: 'c1', note: 'n' }, subject: { customer_id: 'c1', cid: 'c1' }, now: Date.parse('2026-01-09T07:59:59Z'), counts: { rate_0: -1 } },
  { params: { amount: 1000, currency: 'USD' }, subject: {}, now: null, counts: {} },
  { params: {}, now: Date.parse('2026-01-05T08:00:00Z') },
];
for (const [dn, d] of DEFS) for (const [rn, r] of RULES) {
  let c: any; try { c = R.compileBusinessRules(d, r); } catch { continue; }
  for (const [i, inp] of INPUTS.entries()) await o.run('evaluateBusinessRules', `${dn} ${rn} i${i}`, R.evaluateBusinessRules, [c, inp]);
}
await o.run('evaluateBusinessRules', 'garbage compiled', R.evaluateBusinessRules, [{ v: 1, verb: 'x.y', tighten: 5, accumulators: [] }, INPUTS[0]]);

// diff
const dpairs: [string, any, any][] = [];
for (let i = 0; i < RULES.length; i++) for (let j = 0; j < RULES.length; j++) if ((i * 7 + j * 3) % 5 === 0) dpairs.push([`${rnames[i]} -> ${rnames[j]}`, RULES[i][1], RULES[j][1]]);
for (const [n, a, b] of dpairs) await o.run('diffBusinessRules', `fx ${n}`, R.diffBusinessRules, [FX, a, b]);
await o.run('diffBusinessRules', 'undef both', R.diffBusinessRules, [FX, undefined, undefined]);
await o.run('diffBusinessRules', 'add', R.diffBusinessRules, [FX, undefined, RULES[0][1]]);
await o.run('diffBusinessRules', 'drop', R.diffBusinessRules, [FX, RULES[0][1], undefined]);
await o.run('diffBusinessRules', 'amount tighten', R.diffBusinessRules, [FX, { amount: { max: { USD: 500, EUR: 500 } } }, { amount: { max: { USD: 400, EUR: 500 } } }]);
await o.run('diffBusinessRules', 'amount widen', R.diffBusinessRules, [FX, { amount: { max: { USD: 500 } } }, { amount: { max: { USD: 600, EUR: 1 } } }]);
await o.run('diffBusinessRules', 'hours shrink', R.diffBusinessRules, [FX, { hours: { days: ['mon', 'tue'], from: '08:00', to: '18:00', tz: 'UTC' } }, { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'UTC' } }]);
await o.run('diffBusinessRules', 'hours overnight', R.diffBusinessRules, [FX, { hours: { days: ['fri'], from: '22:00', to: '06:00', tz: 'UTC' } }, { hours: { days: ['fri'], from: '23:00', to: '05:00', tz: 'UTC' } }]);

// review
const SKEY = seed('ref-actions-rules-py/reviewer'), SKEY2 = seed('ref-actions-rules-py/other');
const defDigest = (await import('../../../packages/pca-actions/src/digest.ts').then(un)).defDigest;
const RULE = RULES[0][1];
const body = (over: any = {}) => ({ verb: FX.verb, def_digest: defDigest(FX), rules_digest: R.businessRulesDigest(FX.verb, RULE), reviewer_kid: 'rev1', ts: 1000, ...over });
const PINS: any = { keys: [{ kid: 'rev1', pk: P.b64u(P.publicKeyOf(SKEY)), roles: ['reviewer'], not_before: 100, not_after: 2_000_000_000 }, { kid: 'imp1', pk: P.b64u(P.publicKeyOf(SKEY2)), roles: ['importer'] }] };
await o.run('rulesReviewMessage', 'base', R.rulesReviewMessage, [body()]);
await o.run('signRulesReview', 'base', (b: any, s: any) => R.signRulesReview(b, sk(s)), [body(), bytes(SKEY)]);
const good = R.signRulesReview(body(), SKEY);
const RR = (n: string, r: any, d: any = FX, rules: any = RULE, pins: any = PINS) => o.run('rulesReviewError', n, R.rulesReviewError, [r, d, rules, pins]);
await RR('ok', good); await RR('no pins', good, FX, RULE, undefined); await RR('bad pins', good, FX, RULE, { keys: 5 }); await RR('not obj', 5); await RR('null', null);
await RR('other verb', R.signRulesReview(body({ verb: 'x.y' }), SKEY)); await RR('other def', R.signRulesReview(body({ def_digest: 'D'.repeat(43) }), SKEY)); await RR('other rules', R.signRulesReview(body({ rules_digest: 'R'.repeat(43) }), SKEY));
await RR('wrong key', R.signRulesReview(body(), SKEY2)); await RR('importer', R.signRulesReview(body({ reviewer_kid: 'imp1' }), SKEY2)); await RR('unknown kid', R.signRulesReview(body({ reviewer_kid: 'zzz' }), SKEY));
await RR('early', R.signRulesReview(body({ ts: 50 }), SKEY)); await RR('late', R.signRulesReview(body({ ts: 3_000_000_000 }), SKEY)); await RR('ts float', R.signRulesReview(body({ ts: 1.5 }), SKEY)); await RR('ts neg0', { ...good, ts: -0 });
await RR('no sig', { ...body() }); await RR('tampered', { ...good, sig: 'A'.repeat(86) }); await RR('other rules arg', good, FX, RULES[1][1]);
refWrite(o, 'actions-rules-py');
