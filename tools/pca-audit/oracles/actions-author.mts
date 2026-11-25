// Oracle: @atlasauth/pca-actions author.ts (shorthands, expansion, document loader, typed builder). Writes out/ref-actions-author.json.gz.
// PORTING table (documents arrive already parsed: YAML text is parsed by the generator, Java takes the value)
//   parseParamShorthand(s) / parseResourceShorthand(s) / defaultTitle(verb) -> ActionAuthor.<same>
//   expandAction(entry, since|null)      -> ActionAuthor.expandAction(entry, since): {def, notes}
//   loadActionsValue(doc)                -> ActionAuthor.loadActionsValue(doc): {defs, notes, errors, locs, rules[, ns]}  (errors compared without positions; locs is {})
//   builder(name, args...)               -> ActionAuthor.P.<name> (intRange for int, enumOf for enum, setOf for set), action(verb, spec) -> ActionAuthor.action
import * as AU0 from '../../../packages/pca-actions/src/author.ts';
import * as TP0 from '../../../packages/pca-actions/src/templates.ts';
import YAML from 'yaml';
import { Oracle, refWrite, clone, variants } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const AU = un(AU0), TP = un(TP0);
const o = new Oracle('actions-author', 'tools/pca-audit/oracles/actions-author.mts', 'TS-reference oracle for pca-actions authoring.');

const SH = ['email', 'phone', 'url', 'uuid', 'ccy', 'country', 'secret', 'bool', 'date', 'datetime', 'duration', 'duration(60000)', 'duration(x)', 'duration(1,2)', 'text', 'text(200)', 'string(12)', 'string(-5)', 'text(abc)',
  'message', 'message(300)', 'int', 'int(0..100)', 'int(-5..5)', 'int(5)', 'int(a..b)', 'int(0..100)?', 'count', 'count(10)', 'count(1,2)', 'money(USD)', 'money(USD, max=100000)', 'money(EUR, max=5, min=2, exp=0)',
  'money(@currency)', 'money(@currency, max=9)', 'money()', 'money', 'money(USD, provenance=tool)', 'money(USD, provenance=bogus)', 'money(USD, foo=1)', 'money(USD, USD)', 'enum(a|b|c)', 'enum(a||b)', 'enum()', 'enum', 'set(x|y)', 'set(x|)',
  'array(string)', 'array(integer, max=5)', 'array(integer, min=1, max=5)', 'array(float)', 'array()', 'array', 'id:acme.invoice', 'id:order', 'id:', 'id:a.b.c.d.e', 'id:acme.invoice?', 'email?', 'email()', 'email(x)', 'bool?', 'frob', 'EMAIL',
  '', '  email  ', 'email\n', 'text(\n)', 'text(200)\n', 'int(0..100)??', 'string(0)', 'string(007)', 'string(-0)', 'int(-0..0)', 'count(-0)', 'money(USD, max=-0)', 'text(1234567890123456)', 'money(USD, max = 5 , min = 2)', 'money(USD,,max=5)', 'enum( a | b )',
  'array(string, max=)', 'array(string, max=x)', 'a:b', 'id:A', 'text( )', 'text(\u0085)'];
for (const s of SH) await o.run('parseParamShorthand', JSON.stringify(s), (x: string) => AU.parseParamShorthand(x), [s]);

const RS = ['acme.order', 'acme.order:*', 'acme.order:ord_123', 'acme.order:ord_*', 'acme.order:ord_*{digits,4..12}', 'acme.order:*@tenant', 'acme.order@global', 'acme.order:ord_*@set', 'acme.order:x@bogus', 'acme.order:ord_*{bad,1..2}', 'acme.order:ord_*{hex,1..2',
  'acme.order:ord_*{hex,0001..0012}', 'acme.order:ord_*{hex,1..2}@one', '', ':x', 'a:b:c', 'acme.order:ord_*x', ' acme.order ', 'acme.order@ONE', 'acme.order@one\n', 'a@one@two', 'acme.order:*@one', 'acme.order:a*b*', 'acme.order:*{hex,1..2}'];
for (const s of RS) await o.run('parseResourceShorthand', JSON.stringify(s), (x: string) => AU.parseResourceShorthand(x), [s]);
for (const v of ['acme.invoice.send', 'acme.send', 'acme', 'acme.a.b.c', 'acme.order_item.cancel_all', '', 'x.', '.x', 'x..y', 'acme.ß.straße', 'acme.é.é']) await o.run('defaultTitle', JSON.stringify(v), (x: string) => AU.defaultTitle(x), [v]);

const E: [string, any][] = [
  ['minimal', { verb: 'acme.note.read', effects: ['read'], resource: 'acme.note' }],
  ['string effects', { verb: 'acme.note.read', effects: 'read', resource: 'acme.note:*' }],
  ['send autoidem', { verb: 'acme.note.send', effects: ['send'], resource: 'acme.note:n_*', params: { to: 'email', body: 'message(500)' } }],
  ['create autoidem', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', params: { title: 'text(80)' } }],
  ['idem string', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: 'natural' }],
  ['idem key', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: 'key_param' }],
  ['idem key given', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: 'key_param', params: { idempotency_key: 'string(10)' } }],
  ['idem object', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: { mode: 'key_param', param: 'idempotency_key' } }],
  ['idem null', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: null }],
  ['idem none', { verb: 'acme.note.create', effects: ['create'], resource: 'acme.note', idempotency: 'none' }],
  ['pay', { verb: 'acme.pay.send', effects: ['pay'], resource: 'acme.account:acc_*', params: { amount: 'money(USD, max=1000)', to: 'id:acme.account' }, reversibility: 'irreversible', blast: 'bounded' }],
  ['blast bad', { verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', blast: 'huge' }],
  ['blast obj', { verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', blast: { radius: 'one', ppm: 5 } }],
  ['all members', { verb: 'acme.note.update', aliases: 'edit', title: 'Edit a note', description: 'd', effects: ['update'], resource: { type: 'acme.note', id: '*', scope: 'set' }, params: { id: 'id:acme.note', body: { type: 'string', max_len: 10 } }, reversibility: 'reversible', side_effects: [], context: 'fresh_revocation', traits: 'pca.pii_access', audience: 'resource', compensates: 'acme.note.restore', examples: [{ params: { id: 'n1', body: 'x' }, expect: 'allow' }], review: { state: 'unreviewed' }, source: { kind: 'x', uri: 'y' }, since: '0.2.0' }],
  ['since arg', { verb: 'acme.note.read', effects: ['read'], resource: 'acme.note' }],
  ['full form', { v: 1, kind: 'pca-action-def', verb: 'acme.note.read', title: 'Read', effects: ['read'], resource: { type: 'acme.note', id: '*', scope: 'set' }, params: {}, reversibility: 'reversible', blast: { radius: 'one', ppm: 1 }, review: { state: 'authored' }, since: '0.1.0' }],
  ['full form no v', { kind: 'pca-action-def', verb: 'acme.note.read', effects: ['read'] }],
  ['full form float', { kind: 'pca-action-def', verb: 'acme.note.read', effects: ['read'], x: 1.5 }],
  ['not object', 5], ['null entry', null], ['array entry', []], ['no verb', { effects: ['read'], resource: 'acme.note' }], ['verb number', { verb: 5 }],
  ['unknown member', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', zzz: 1 }],
  ['bad v', { v: 2, verb: 'acme.x.y' }], ['bad kind', { kind: 'nope', verb: 'acme.x.y' }], ['params not object', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', params: [] }],
  ['bad param shorthand', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', params: { a: 'frob' } }], ['bad resource shorthand', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x:y@bogus' }],
  ['no effects', { verb: 'acme.x.y', resource: 'acme.x' }], ['no resource', { verb: 'acme.x.y', effects: ['read'] }], ['float param', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', params: { a: { type: 'integer', min: 1.5 } } }],
  ['non-nfc title', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', title: 'é' }], ['null title', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', title: null }], ['null review', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', review: null }],
  ['null since', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', since: null }], ['null aliases', { verb: 'acme.x.y', effects: ['read'], resource: 'acme.x', aliases: null }],
  ['effects mixed', { verb: 'acme.x.y', effects: ['read', 'pay', 5], resource: 'acme.x' }],
];
for (const [n, e] of E) {
  await o.run('expandAction', n, (x: any, s: any) => AU.expandAction(x, s === null ? {} : { since: s }), [e, null]);
  await o.run('expandAction', `${n} since`, (x: any, s: any) => AU.expandAction(x, s === null ? {} : { since: s }), [e, '0.9.0']);
}

const DOC = { ns: 'acme', since: '0.3.0', actions: [
  { verb: 'acme.invoice.send', effects: ['send'], resource: 'acme.invoice:inv_*', params: { to: 'email', amount: 'money(USD, max=100000)', note: 'text(200)?', n: 'count(5)', r: 'id:acme.invoice' }, rules: { amount: { max: { USD: '1000' } }, required: ['to'] } },
  { verb: 'acme.invoice.get', effects: ['read'], resource: 'acme.invoice:*', params: { invoice: 'id:acme.invoice' } },
] };
const D: [string, any][] = [
  ['ok', DOC], ['no actions', { ns: 'acme' }], ['bad ns', { ns: 'Acme', actions: [] }], ['no ns', { actions: [] }], ['unknown key', { ns: 'acme', zzz: 1, actions: [] }], ['since num', { ns: 'acme', since: 5, actions: [] }], ['empty actions', { ns: 'acme', actions: [] }],
  ['single def', { kind: 'pca-action-def', verb: 'acme.note.read', title: 'Read', effects: ['read'], resource: { type: 'acme.note', id: '*', scope: 'set' }, params: {}, reversibility: 'reversible', blast: { radius: 'one', ppm: 1 }, review: { state: 'authored' }, since: '0.1.0' }],
  ['not object', 5], ['null', null], ['array', []], ['proto', JSON.parse('{"ns":"acme","actions":[{"__proto__":{"a":1}}]}')], ['deep', (() => { let v: any = { a: 1 }; for (let i = 0; i < 45; i++) v = { a: v }; return { ns: 'acme', actions: [v] }; })()],
  ['bad rules', { ns: 'acme', actions: [{ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', rules: { required: ['nope'] } }] }],
  ['null rules', { ns: 'acme', actions: [{ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', rules: null }] }],
  ['rules ok', { ns: 'acme', actions: [{ verb: 'acme.note.read', effects: ['read'], resource: 'acme.note', params: { a: 'text(5)' }, rules: { required: ['a'] } }] }],
  ['one bad one good', { ns: 'acme', actions: [{ verb: 'acme.a.b', effects: ['read'] }, { verb: 'acme.c.d', effects: ['read'], resource: 'acme.c' }, 5, { verb: 5 }] }],
  ['dup verbs', { ns: 'acme', actions: [{ verb: 'acme.c.d', effects: ['read'], resource: 'acme.c' }, { verb: 'acme.c.d', effects: ['read'], resource: 'acme.c' }] }],
];
for (const [n, d] of D) await o.run('loadActionsValue', n, (x: any) => AU.loadActionsValue(x), [d]);
// the starter templates through the full loader (YAML parsed here, the value handed over)
for (const t of TP.STARTER_TEMPLATES) for (const ns of [t.ns, 'zed']) {
  const text = t.yaml(ns);
  const val = YAML.parse(text, { version: '1.2', schema: 'core' });
  await o.run('loadActionsValue', `template ${t.id} ${ns}`, (x: any) => AU.loadActionsValue(x), [val]);
}
let hv = 0;
for (const [lbl, v] of variants(DOC, { maxPaths: 80, hostile: [null, 0, 1, '', 'x', [], {}, true, -1, 1.5] })) {
  const r = AU.loadActionsValue(clone(v));
  if (JSON.stringify(r).includes('malformed action:') || JSON.stringify(r).includes('Cannot ')) continue;
  if (hv++ > 250) break;
  await o.run('loadActionsValue', `v ${lbl}`, (x: any) => AU.loadActionsValue(x), [v]);
}
// the typed builder
const P = AU.p;
const B: [string, any[], () => any][] = [
  ['email', [null], () => P.email()], ['email x', [{ required: false }], () => P.email({ required: false })], ['phone', [null], () => P.phone()], ['url', [null], () => P.url()], ['uuid', [null], () => P.uuid()], ['ccy', [null], () => P.ccy()],
  ['country', [null], () => P.country()], ['secret', [null], () => P.secret()], ['bool', [null], () => P.bool()], ['date', [null], () => P.date()], ['datetime', [null], () => P.datetime()],
  ['duration', [null, null], () => P.duration()], ['duration n', [5000, null], () => P.duration(5000)], ['message', [null, null], () => P.message()], ['message n', [300, { description: 'd' }], () => P.message(300, { description: 'd' })],
  ['text', [null, null], () => P.text()], ['text n', [64, null], () => P.text(64)], ['int', [null, null, null], () => P.int()], ['int r', [0, 9, null], () => P.int(0, 9)], ['count', [null, null], () => P.count()], ['count n', [7, null], () => P.count(7)],
  ['money', ['USD', {}, null], () => P.money('USD')], ['money o', ['EUR', { max: 500, min: 2, exp: 0 }, null], () => P.money('EUR', { max: 500, min: 2, exp: 0 })], ['money from', [{ from: 'cur' }, { max: 9 }, null], () => P.money({ from: 'cur' }, { max: 9 })],
  ['id', ['acme.order', null], () => P.id('acme.order')], ['enum', [['a', 'b'], null], () => P.enum(['a', 'b'])], ['set', [['a', 'b'], null], () => P.set(['a', 'b'])], ['array', ['string', null, null], () => P.array('string')],
  ['array m', ['integer', 4, null], () => P.array('integer', 4)], ['optional', [P.email()], () => P.optional(P.email())],
];
const NAMES: Record<string, string> = { 'int': 'int', 'enum': 'enum', 'set': 'set' };
void NAMES;
for (const [n, args, f] of B) await o.run('builder', n.replace(/ .*$/, '') + ' ' + n, () => f(), [n.replace(/ .*$/, ''), ...args]);
const AC: [string, any][] = [
  ['ok', { effects: ['read'], resource: 'acme.note' }], ['send', { effects: 'send', resource: 'acme.note:n_*', params: { to: P.email(), body: 'message(100)' } }],
  ['bad', { effects: ['read'], resource: 'acme.note:x@bogus' }], ['invalid def', { effects: ['frob'], resource: 'acme.note' }], ['full', { effects: ['update'], resource: 'acme.note', title: 'T', description: 'D', reversibility: 'reversible', since: '0.1.0' }],
];
for (const [n, s] of AC) await o.run('action', n, (v: string, sp: any) => AU.action(v, sp), ['acme.note.do', s]);
refWrite(o, 'actions-author');
