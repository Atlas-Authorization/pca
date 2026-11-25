// Oracle (python lane): @atlasauth/pca-actions author.ts (value-level: shorthands, expansion, document loader, action()). Writes out/ref-actions-author-py.json.gz.
// PORTING table: parseParamShorthand(src) parseResourceShorthand(src) defaultTitle(verb) expandAction(entry, since?) loadActionsValue(doc) action(verb, spec); a throw is compared by code.
import * as A0 from '../../../packages/pca-actions/src/author.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import { Oracle, refWrite, clone } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const A = un(A0), BI = un(B0);
const o = new Oracle('actions-author-py', 'tools/pca-audit/oracles/actions-author-py.mts', 'TS-reference oracle for pca-actions authoring (python lane).');

const PARAMS = ['email', 'phone', 'url', 'uuid', 'ccy', 'country', 'secret', 'bool', 'date', 'datetime', 'duration', 'duration(60000)', 'duration(x)', 'duration(1,2)', 'text', 'text(100)', 'string(20)', 'text(a)', 'message', 'message(500)',
  'int', 'int(0..100)', 'int(-5..5)', 'int(1)', 'int(a..b)', 'count', 'count(50)', 'money(USD)', 'money(USD, max=5000)', 'money(@currency)', 'money(EUR, max=100, min=5, exp=2, provenance=tool)', 'money', 'money(USD, provenance=nope)', 'money(USD, bogus=1)',
  'money(USD, max=x)', 'id:acme.invoice', 'id:x', 'id:Bad', 'enum(a|b|c)', 'enum(a||b)', 'enum', 'set(x|y)', 'array(string)', 'array(integer, max=5)', 'array(integer, max=5, min=1)', 'array(float)', 'array', 'email?', 'text(10)?', 'email(x)',
  'unknown', '', ' email ', 'EMAIL', 'text(10', 'enum( a | b )', 'money(USD,max=1)', 'int(0..100)?', 'bool(1)', 'id:acme.a.b.c.d.e', 'text(1,2)', 'array(string, max=1, bogus=2)', 'count(0)', 'text(1234567890123456)'];
for (const s of PARAMS) await o.run('parseParamShorthand', JSON.stringify(s), A.parseParamShorthand, [s]);
const RES = ['acme.invoice', 'acme.invoice:*', 'acme.invoice:inv_123', 'acme.invoice:inv_*', 'acme.invoice:inv_*{hex,4..8}', 'acme.invoice:*@global', 'acme.invoice@one', 'acme.invoice:inv_*@tenant', 'acme.invoice:inv_*{nope,1..2}', 'acme.invoice:inv_*{hex}', 'x@bad', 'x:y*z*', ' acme.invoice ', '', ':', 'a:b*{uuid,36..36}'];
for (const s of RES) await o.run('parseResourceShorthand', JSON.stringify(s), A.parseResourceShorthand, [s]);
for (const v of ['acme.invoice.send', 'acme.send', 'a.b.c.d', 'stripe.charge', 'x.y_z.do_it', 'single']) await o.run('defaultTitle', v, A.defaultTitle, [v]);

const E: [string, any][] = [
  ['minimal', { verb: 'acme.invoice.send', effects: 'send', resource: 'acme.invoice:inv_*', params: { to: 'email', body: 'message(500)' } }],
  ['read', { verb: 'acme.invoice.get', effects: ['read'], resource: 'acme.invoice:inv_*{alnum,4..16}', params: { id: 'id:acme.invoice' } }],
  ['pay keyed', { verb: 'acme.pay.send', effects: ['pay'], resource: 'acme.account:acct_*', params: { amount: 'money(USD, max=100000)', account: 'id:acme.account' }, blast: 'bounded' }],
  ['idem string', { verb: 'acme.pay.send', effects: ['pay'], resource: 'acme.account', params: { amount: 'money(USD)' }, idempotency: 'key_param' }],
  ['idem natural', { verb: 'acme.pay.send', effects: ['pay'], resource: 'acme.account', params: { amount: 'money(USD)' }, idempotency: 'natural' }],
  ['idem object', { verb: 'acme.x.y', effects: ['create'], resource: 'x', idempotency: { mode: 'key_param', param: 'k1' }, params: { k1: 'text(10)' } }],
  ['idem explicit param exists', { verb: 'acme.x.y', effects: ['create'], resource: 'x', params: { idempotency_key: 'text(5)' } }],
  ['bad blast', { verb: 'acme.x.y', effects: ['read'], resource: 'x', blast: 'huge' }], ['blast obj', { verb: 'acme.x.y', effects: ['read'], resource: 'x', blast: { radius: 'one', ppm: 100 } }],
  ['unknown member', { verb: 'acme.x.y', effects: 'read', resource: 'x', zzz: 1 }], ['not obj', 5], ['null', null], ['no verb', { effects: 'read', resource: 'x' }], ['verb num', { verb: 5 }],
  ['bad v', { verb: 'acme.x.y', effects: 'read', resource: 'x', v: 2 }], ['v true', { verb: 'acme.x.y', effects: 'read', resource: 'x', v: true }], ['bad kind', { verb: 'acme.x.y', kind: 'other' }],
  ['full', { ...clone(BI.BUILTIN_DEFS[0]) }], ['full no v', (() => { const d = clone(BI.BUILTIN_DEFS[1]); delete d.v; return d; })()],
  ['params not obj', { verb: 'acme.x.y', effects: 'read', resource: 'x', params: [] }], ['params mixed', { verb: 'acme.x.y', effects: 'read', resource: 'x', params: { a: 'text(5)', b: { type: 'boolean' } } }],
  ['title given', { verb: 'acme.x.y', title: 'Do it', effects: 'read', resource: 'x' }], ['title null', { verb: 'acme.x.y', title: null, effects: 'read', resource: 'x' }],
  ['aliases str', { verb: 'acme.x.y', aliases: 'doit', effects: 'read', resource: 'x' }], ['context str', { verb: 'acme.x.y', context: 'revocable', traits: 'pca.bulk', effects: 'read', resource: 'x' }],
  ['review given', { verb: 'acme.x.y', effects: 'read', resource: 'x', review: { state: 'unreviewed' } }], ['since', { verb: 'acme.x.y', effects: 'read', resource: 'x', since: '1.0.0' }],
  ['full extras', { verb: 'acme.x.y', effects: ['create', 'send'], resource: { type: 'x', id: '*', scope: 'set' }, audience: 'resource', compensates: 'acme.x.z', bindings: { mcp: { tool: 't' } }, examples: [], source: { kind: 'hand' }, side_effects: [{ target: 'a', kind: 'send' }], reversibility: 'rate_limited', description: 'd' }],
  ['no effects', { verb: 'acme.x.y', resource: 'x' }], ['bad shorthand in params', { verb: 'acme.x.y', effects: 'read', resource: 'x', params: { a: 'nope' } }], ['float', { verb: 'acme.x.y', effects: 'read', resource: 'x', params: { a: { type: 'integer', min: 1.5 } } }],
];
for (const [n, e] of E) { await o.run('expandAction', n, A.expandAction, [e]); await o.run('expandAction', n + ' since', (x: any) => A.expandAction(x, { since: '2.0.0' }), [e]); }

const FILE = (actions: any, extra: any = {}) => ({ ns: 'acme', ...extra, actions });
const GOOD = { verb: 'acme.invoice.send', effects: 'send', resource: 'acme.invoice:inv_*', params: { to: 'email', body: 'message(500)' } };
const GOOD2 = { verb: 'acme.invoice.get', effects: 'read', resource: 'acme.invoice:inv_*', params: { id: 'id:acme.invoice' } };
const DOCS: [string, any][] = [
  ['two', FILE([GOOD, GOOD2])], ['since', FILE([GOOD], { since: '1.2.3' })], ['one bad', FILE([GOOD, { verb: 'acme.bad.x', effects: 'read' }, GOOD2])], ['bad ns', { ns: 'Bad', actions: [] }], ['no ns', { actions: [] }], ['ns num', { ns: 5, actions: [] }],
  ['unknown top', { ns: 'acme', actions: [], extra: 1 }], ['since bad', FILE([], { since: 5 })], ['actions not list', { ns: 'acme', actions: {} }], ['raw def', clone(BI.BUILTIN_DEFS[2])], ['not obj', 5], ['null', null], ['array', []],
  ['proto', JSON.parse('{"ns":"acme","actions":[{"__proto__":{"x":1}}]}')], ['deep', (() => { let d: any = {}; const root = d; for (let i = 0; i < 45; i++) { d.a = {}; d = d.a; } return { ns: 'acme', actions: [root] }; })()],
  ['rules ok', FILE([{ ...GOOD2, rules: { required: ['id'] } }])], ['rules bad', FILE([{ ...GOOD2, rules: { required: ['nope'] } }])], ['rules and bad def', FILE([{ verb: 'acme.q.r', rules: { required: ['x'] } }])],
  ['rules amount', FILE([{ verb: 'acme.pay.send', effects: 'pay', resource: 'acme.account', params: { amount: 'money(USD, max=100000)', account: 'id:acme.account' }, rules: { amount: { max: { USD: 5000 } } } }])],
  ['entry not obj', FILE([5, GOOD])], ['empty actions', FILE([])], ['dup verbs', FILE([GOOD, GOOD])], ['idem note', FILE([{ verb: 'acme.x.send', effects: ['send'], resource: 'x', params: { a: 'text(3)' } }])],
];
for (const [n, d] of DOCS) await o.run('loadActionsValue', n, A.loadActionsValue, [d]);
for (const [n, e] of E.slice(0, 12)) await o.run('action', n, (v: any, s: any) => A.action(v, s), [e?.verb ?? 'acme.x.y', e && typeof e === 'object' ? { ...e, verb: undefined } : {}]);
refWrite(o, 'actions-author-py');
