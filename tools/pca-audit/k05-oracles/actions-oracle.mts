// k05 differential oracle: the action kit (Java Actions.java; TS reference packages/pca-actions/src: validate, idpattern,
// traits, normalize, digest, effective, confirmation, derive). Writes tools/pca-audit/k05-oracles/out/k05-actions.json.gz.
//
// Input space: every builtin / domain def, two hand-built maximal defs (every optional member present) and a uuid/exact/'*'
// variant; the generated structural variants of each (lib.variants: delete / every hostile scalar / limits +-1); a boundary
// case at every limit constant; seeded multi-edit mutants. Every def the reference accepts also goes through normalize,
// defDigest, declProfile, hintTraits, effective and (as a schema verb) schemaVerbFloorError. The trait algebra, the id grammar,
// the strict JSON profile, the reviewer pins and the signed confirmation each get their own generated space.
//
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/actions-oracle.mts
// Deterministic (Ed25519 is deterministic; keys are seeded).
import * as A0 from '../../../packages/pca-actions/src/index.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, variants, around, rng, reparse, clone, seed, HOSTILE, setAt, paths, getAt } from './lib.mjs';

const A: any = (A0 as any).validateDef ? A0 : (A0 as any).default;
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const O = new Oracle('actions', 'tools/pca-audit/k05-oracles/actions-oracle.mts',
  'TS-reference oracle for the action kit (Actions.java and its ports): validateDef and its sub-checks, id patterns, the strict JSON profile, profiles, trait registries, closure / floor / floorDecision, normalize, defDigest, worstReversibility, impliedFromFacts, declProfile, hintTraits, effective, reviewer pins, the signed confirmation, factsDigest, schemaVerbFloorError / schemaFloorError, packRoot / packProof.');

// generated labels can collide (two different inputs, one label): suffix ~2, ~3 ... (identical inputs are still deduped by lib)
{ const add0 = O.add.bind(O); (O as any).add = (fn: string, name: string, args: any, out: any) => { let n = name, i = 1; while (O.names.has(`${fn}/${n}`)) n = `${name} ~${++i}`; return add0(fn, n, args, out); }; }
const CORE = A.CORE_REGISTRY;
const regOf = (custom: any) => (custom == null ? CORE : A.extendRegistry(CORE, custom));
const s = (n: number, ch = 'a') => ch.repeat(n);

// ---- keys and the signed confirmation ------------------------------------------------------------------------------------
const key = (l: string) => { const sk = seed(`k05-actions/${l}`); return { sk, pk: P.b64u(P.publicKeyOf(sk)) }; };
const REV = key('reviewer'), REV2 = key('reviewer2'), MACH = key('importer');
const PINS = { keys: [{ kid: 'rev1', pk: REV.pk, roles: ['reviewer'], not_before: 100, not_after: 2_000_000_000 }, { kid: 'imp1', pk: MACH.pk, roles: ['importer'] }, { kid: 'rev2', pk: REV2.pk, roles: ['reviewer', 'publisher'] }] };
const TD = A.traitsDigest(CORE);
/** A def confirmed by `kid` (signed over its own digest and declared traits). */
function confirm(d: any, over: any = {}, sk = REV.sk, kid = 'rev1') {
  const c = clone(d);
  c.review = { state: 'confirmed' };
  const body = { def_digest: A.defDigest(c), traits_digest: TD, facts_digest: P.b64u(seed('k05-actions/facts')), final_traits: [...(c.traits ?? [])].sort(), dismissed: [], reviewer_kid: kid, ts: 1000, ...over };
  c.review.attestation = A.signReview(body, sk);
  return c;
}

// ---- seeds -------------------------------------------------------------------------------------------------------------
const ATT = { def_digest: s(43, 'A'), traits_digest: s(43, 'B'), facts_digest: s(43, 'C'), final_traits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'one at a time' }], reviewer_kid: 'k1', ts: 1, sig: 'AA' };
const MAX_DEF: any = {
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.pay', aliases: ['pay_invoice', 'acme.pay'], title: 'Pay an invoice', description: 'Pays an invoice.',
  effects: ['pay', 'update'],
  resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [4, 16] }, scope: 'one' },
  params: {
    amount: { type: 'integer', role: 'money.amount', required: true, min: 0, max: 100000, unit: { kind: 'money', ccy: 'USD', exp: 2 }, tags: ['pci'], provenance_min: 'first_party', sensitivity: 'critical', accumulates: ['money.usd'], description: 'Amount' },
    fee: { type: 'integer', role: 'money.fee', unit: { kind: 'money', ccy: { from: 'currency' }, exp: 2 }, default: 0, principal_neutral_default: true, required: false },
    currency: { type: 'string', role: 'money.currency', values: ['USD', 'EUR'], format: 'iso_currency' },
    payee: { type: 'string', role: 'party.payee', max_len: 64, format: 'id:acme.vendor' },
    'meta.note': { type: 'string', max_len: 256, tags: ['free_text_outbound', 'pii'], sensitivity: 'material' },
    items: { type: 'array', items: 'integer', min: 0, max: 9, min_items: 1, max_items: 8, max_len: 8 },
    labels: { type: 'set', values: ['a', 'b', 'c'], min_items: 0, max_items: 2 },
    when: { type: 'datetime' }, day: { type: 'date' },
    wait: { type: 'duration', min: 0, max: 3600 }, secs: { type: 'integer', min: 0, unit: { kind: 'duration' } },
    ref: { type: 'object_ref', format: 'url', max_len: 2048 },
    flag: { type: 'boolean' },
    invoice_id: { type: 'string', role: 'id.invoice' },
    key: { type: 'string', role: 'x.acme.idem' },
  },
  reversibility: { by: 'flag', map: { true: 'reversible', false: 'irreversible' }, default: 'rate_limited' },
  blast: { radius: 'bounded', ppm: 400000 },
  side_effects: [{ target: 'acme.ledger', kind: 'update' }],
  idempotency: { mode: 'key_param', param: 'key' },
  context: ['approval_ref', 'session_taint_max:low'],
  traits: ['pca.money_moving'], audience: 'resource', compensates: 'acme.invoice.refund',
  bindings: { mcp: { tool: 'pay' }, openapi: { operationId: 'payInvoice', method: 'POST', path: '/x' }, http: { method: 'POST', path: '/x' }, graphql: { op: 'mutation', field: 'pay' }, grpc: { service: 'S', method: 'M' }, asyncapi: { channel: 'c', op: 'send' } },
  examples: [{ params: { amount: 1 }, under: {}, expect: 'allow' }],
  review: { state: 'suggested', suggested_by: { x: 1 }, provenance: { union: ['pca.money_moving'], adjudicated: ['pca.bulk'] }, attestation: ATT },
  source: { kind: 'openapi', uri: 'https://x.example', spec_digest: 'd', licence: 'MIT', imported_at: 0 }, since: '1.0',
};
const READ_DEF: any = {
  v: 1, kind: 'pca-action-def', verb: 'acme.report.get', title: 'Get a report', effects: ['read'],
  resource: { type: 'acme.report', id: '*', scope: 'tenant' },
  params: { q: { type: 'string', role: 'query.search', max_len: 64 }, n: { type: 'integer', role: 'count.limit', min: 1, max: 50 }, total: { type: 'integer', role: 'money.amount' }, rows: { type: 'array', items: 'string' } },
  reversibility: 'reversible', idempotency: { mode: 'natural' }, review: { state: 'authored' },
};
const UUID_DEF: any = {
  v: 1, kind: 'pca-action-def', verb: 'acme.user.delete', title: 'Delete a user', effects: ['delete'],
  resource: { type: 'acme.user', id: { prefix: '', class: 'uuid', len: [36, 36] }, scope: 'one' },
  params: { user: { type: 'string', role: 'id.acme.user', format: 'uuid' }, secret: { type: 'string', role: 'credential.secret', tags: ['secret'] }, mode: { type: 'string', values: ['soft', 'hard'] } },
  reversibility: { by: 'mode', map: { soft: 'reversible', hard: 'irreversible' } }, blast: { radius: 'one' }, review: { state: 'unreviewed' },
};
const EXACT_DEF: any = {
  v: 1, kind: 'pca-action-def', verb: 'acme.cfg.set', title: 'Set config', effects: ['update', 'privilege'],
  resource: { type: 'acme.cfg', id: { exact: 'main' }, scope: 'global' },
  params: { 'a.b.c': { type: 'string' }, on: { type: 'boolean' } },
  reversibility: { by: 'on', map: { true: 'reversible' } }, context: ['fresh_revocation'], traits: [], review: { state: 'confirmed' },
};
const SEEDS: [string, any][] = [
  ['max', MAX_DEF], ['read', READ_DEF], ['uuid', UUID_DEF], ['exact', EXACT_DEF],
  ...A.BUILTIN_DEFS.map((d: any) => [`builtin:${d.verb}`, d]), ...A.DOMAIN_DEFS.map((d: any) => [`domain:${d.verb}`, d]),
];

// ---- validateDef (and everything downstream of an accepted def) -------------------------------------------------------
const accepted: [string, any][] = [];
async function vdef(name: string, d: any) {
  const x = reparse(d);
  const added = O.add('validateDef', name, [x], A.validateDef(x));
  if (added && O.cases[O.cases.length - 1].out === null) accepted.push([name, x]);
}
for (const [n, d] of SEEDS) await vdef(`seed ${n}`, d);
const LENS = [0, 1, 31, 32, 33, 63, 64, 65, 119, 120, 121, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097];
for (const [n, d] of SEEDS.slice(0, 4)) for (const [lab, v] of variants(d, { lens: LENS })) await vdef(`${n} ${lab}`, v);
// the remaining seeds: delete / hostile only, on their top two levels (their params differ from the hand seeds)
for (const [n, d] of SEEDS.slice(4)) for (const [lab, v] of variants(d, { depth: 3, hostile: [null, 1.5, -0, '', [], {}, 'x'] })) await vdef(`${n} ${lab}`, v);

const W = (f: (d: any) => void, base = MAX_DEF) => { const d = clone(base); f(d); return d; };
const P_ = (name: string, p: any, base = MAX_DEF) => W((d) => { d.params[name] = p; }, base);
// def-level limits
for (const [k, mx] of [['title', 120], ['description', 1024], ['since', 64]] as const) {
  for (const v of around(mx)) await vdef(`limit ${k} ${v.length}${v.endsWith('é') ? 'mb' : ''}`, W((d) => { d[k] = v; }));
  await vdef(`limit ${k} nfd`, W((d) => { d[k] = 'é'; }));
}
const verbOf = (segs: number, len: number) => ['a' + s(len - 1, 'b'), ...Array.from({ length: segs - 1 }, () => s(len, 'c'))].join('.');
for (const segs of [1, 2, 6, 7]) for (const len of [1, 32, 33]) await vdef(`verb ${segs}x${len}`, W((d) => { d.verb = verbOf(segs, len); }));
for (const v of ['A.b', '1a.b', 'a..b', 'a.b.', '.a.b', 'a.B', 'a.b-c', 'a_.b_', 'a.b c', 'acme.invoice.pay']) await vdef(`verb '${v}'`, W((d) => { d.verb = v; }));
for (const n of [15, 16, 17]) await vdef(`aliases ${n}`, W((d) => { d.aliases = Array.from({ length: n }, (_, i) => `al${i}`); }));
for (const al of [['acme.invoice.pay'], ['a', 'a'], ['A'], [verbOf(6, 32)], [verbOf(7, 2)], ['x'], [5], []]) await vdef(`aliases ${JSON.stringify(al)}`, W((d) => { d.aliases = al; }));
const EFF = ['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'];
for (const e of [[], ['read'], EFF, [...EFF, 'read'], ['read', 'read'], ['read', 'mint'], EFF.slice(0, 11)]) await vdef(`effects ${e.length} ${e.join(',').slice(0, 30)}`, W((d) => { d.effects = e; }));
for (const t of [s(128), s(129), 'a.' + s(32), 'a.' + s(33), 'a.b.c.d.e', 'a.b.c.d.e.f', 'A', '1', '']) await vdef(`resource.type ${t.length} ${t.slice(0, 12)}`, W((d) => { d.resource.type = t; }));
for (const sc of ['one', 'set', 'tenant', 'global', 'all', null]) await vdef(`resource.scope ${sc}`, W((d) => { d.resource.scope = sc; }));
for (const r of [{ type: 'a', id: '*' }, { type: 'a', id: '*', scope: 'one', x: 1 }]) await vdef(`resource keys ${Object.keys(r).join(',')}`, W((d) => { d.resource = r; }));
for (const n of [63, 64, 65]) await vdef(`params ${n}`, W((d) => { d.params = Object.fromEntries(Array.from({ length: n }, (_, i) => [`p${i}`, { type: 'string' }])); d.reversibility = 'irreversible'; d.idempotency = { mode: 'none' }; }));
const pn = ['a', s(64), s(65), 'a.b.c', 'a.b.c.d', 'A_1', 'a-b', 'a..b', '', '__proto__', 'a.constructor', 'prototype.x', 'a.' + s(64), 'a.' + s(65), 'é'];
for (const n of pn) await vdef(`param name '${n.slice(0, 20)}'#${n.length}`, W((d) => { d.params[n] = { type: 'string' }; }));
await vdef('param leaf and parent', W((d) => { d.params.x = { type: 'string' }; d.params['x.y'] = { type: 'string' }; }));
await vdef('param parent prefix not dotted', W((d) => { d.params.x = { type: 'string' }; d.params.xy = { type: 'string' }; }));
await vdef('param grandparent', W((d) => { d.params.x = { type: 'string' }; d.params['x.y.z'] = { type: 'string' }; }));
// paramError: every member against every type
const TYPES = ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref', 'float', 'object'];
const MEMBERS: [string, any][] = [
  ['role money.amount', { role: 'money.amount' }], ['role count.limit', { role: 'count.limit' }], ['role bytes.size', { role: 'bytes.size' }], ['role money.fee', { role: 'money.fee' }],
  ['role contact.email', { role: 'contact.email' }], ['role id.x', { role: 'id.x' }], ['role id.a.b.c.d', { role: 'id.a.b.c.d' }], ['role id.a.b.c.d.e', { role: 'id.a.b.c.d.e' }],
  ['role x.a', { role: 'x.a' }], ['role x.a.b', { role: 'x.a.b' }], ['role x.a.b.c.d', { role: 'x.a.b.c.d' }], ['role x.a.b.c.d.e', { role: 'x.a.b.c.d.e' }], ['role bogus', { role: 'money.bogus' }], ['role 5', { role: 5 }],
  ['values', { values: ['a', 'b'] }], ['values items', { items: 'integer' }], ['items string', { items: 'string' }], ['items 64', { items: s(64) }], ['items 65', { items: s(65) }],
  ['min', { min: 0 }], ['max', { max: 5 }], ['min>max', { min: 5, max: 4 }], ['min=max', { min: 4, max: 4 }], ['min float', { min: 1.5 }], ['min -0', { min: -0 }],
  ['max_len 1', { max_len: 1 }], ['max_len 0', { max_len: 0 }], ['max_len 16777216', { max_len: 16777216 }], ['max_len 16777217', { max_len: 16777217 }],
  ['min_items', { min_items: 0 }], ['max_items', { max_items: 0 }], ['min_items>max_items', { min_items: 3, max_items: 2 }], ['min_items=max_items', { min_items: 2, max_items: 2 }], ['min_items -1', { min_items: -1 }],
  ['format email', { format: 'email' }], ['format id:a', { format: 'id:a' }], ['format id:a.b.c.d', { format: 'id:a.b.c.d' }], ['format id:a.b.c.d.e', { format: 'id:a.b.c.d.e' }], ['format bogus', { format: 'bogus' }],
  ['unit count', { unit: { kind: 'count' } }], ['unit money', { unit: { kind: 'money', ccy: 'EUR', exp: 2 } }],
  ['accumulates', { accumulates: ['a.b'] }], ['default', { default: 1 }], ['default null', { default: null }], ['pnd', { principal_neutral_default: true, default: 'x' }],
];
for (const t of TYPES) {
  await vdef(`ptype ${t}`, P_('zz', { type: t }));
  for (const [ml, m] of MEMBERS) await vdef(`ptype ${t} ${ml}`, P_('zz', { type: t, ...m }));
}
await vdef('ptype set no values', P_('zz', { type: 'set' }));
await vdef('ptype array items integer min', P_('zz', { type: 'array', items: 'integer', min: 1, max: 2 }));
await vdef('ptype array items string min', P_('zz', { type: 'array', items: 'string', min: 1 }));
for (const n of [255, 256, 257]) await vdef(`values ${n}`, P_('zz', { type: 'string', values: Array.from({ length: n }, (_, i) => `v${i}`) }));
for (const v of [[], ['a', 'a'], [''], [s(256)], [s(257)], [s(255) + 'é'], [1], [null]]) await vdef(`values ${JSON.stringify(v).slice(0, 20)}#${v.length}`, P_('zz', { type: 'set', values: v }));
const MONEY = (u: any) => P_('zz', { type: 'integer', unit: u });
for (const [l, u] of [
  ['exp 0', { kind: 'money', ccy: 'USD', exp: 0 }], ['exp 18', { kind: 'money', ccy: 'USD', exp: 18 }], ['exp 19', { kind: 'money', ccy: 'USD', exp: 19 }], ['exp -1', { kind: 'money', ccy: 'USD', exp: -1 }],
  ['exp missing', { kind: 'money', ccy: 'USD' }], ['exp 1.5', { kind: 'money', ccy: 'USD', exp: 1.5 }], ['ccy usd', { kind: 'money', ccy: 'usd', exp: 2 }], ['ccy USDX', { kind: 'money', ccy: 'USDX', exp: 2 }],
  ['ccy US', { kind: 'money', ccy: 'US', exp: 2 }], ['ccy missing', { kind: 'money', exp: 2 }], ['ccy 5', { kind: 'money', ccy: 5, exp: 2 }], ['ccy from', { kind: 'money', ccy: { from: 'currency' }, exp: 2 }],
  ['ccy from unknown', { kind: 'money', ccy: { from: 'nope' }, exp: 2 }], ['ccy from extra', { kind: 'money', ccy: { from: 'currency', x: 1 }, exp: 2 }], ['ccy from extra first', { kind: 'money', ccy: { x: 1, from: 'currency' }, exp: 2 }],
  ['ccy from 5', { kind: 'money', ccy: { from: 5 }, exp: 2 }], ['ccy from empty', { kind: 'money', ccy: {}, exp: 2 }], ['ccy array', { kind: 'money', ccy: ['USD'], exp: 2 }], ['ccy from self', { kind: 'money', ccy: { from: 'zz' }, exp: 2 }],
  ['money extra', { kind: 'money', ccy: 'USD', exp: 2, x: 1 }], ['count extra', { kind: 'count', x: 1 }], ['count extra first', { x: 1, kind: 'count' }], ['kind bogus', { kind: 'kg' }],
  ['kind missing', {}], ['unit array', []], ['unit string', 'money'], ['bytes', { kind: 'bytes' }], ['ratio', { kind: 'ratio' }], ['duration', { kind: 'duration' }],
] as [string, any][]) await vdef(`unit ${l}`, MONEY(u));
await vdef('unit on string', P_('zz', { type: 'string', unit: { kind: 'count' } }));
const TAGS = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'];
for (const tg of [[], TAGS, [...TAGS, 'pii'], ['pii', 'pii'], ['bogus'], [5], TAGS.slice(0, 8)]) await vdef(`tags ${tg.length} ${tg.slice(0, 2).join(',')}`, P_('zz', { type: 'string', tags: tg }));
await vdef('tags string', P_('zz', { type: 'string', tags: 'pii' }));
for (const pm of ['first_party', 'tool', 'agent', 'user', null]) await vdef(`provenance_min ${pm}`, P_('zz', { type: 'string', provenance_min: pm }));
for (const se of ['free', 'material', 'critical', 'high', 5]) await vdef(`sensitivity ${se}`, P_('zz', { type: 'string', sensitivity: se }));
for (const [l, a] of [
  ['1', ['a']], ['8', Array.from({ length: 8 }, (_, i) => `u${i}`)], ['9', Array.from({ length: 9 }, (_, i) => `u${i}`)], ['empty', []], ['dup', ['a', 'a']], ['64', [s(64)]], ['65', [s(65)]],
  ['dotted', ['a.b_c.d']], ['trailing dot', ['a.']], ['upper', ['A']], ['dash', ['a-b']], ['num', [5]], ['string', 'a'],
] as [string, any][]) await vdef(`accumulates ${l}`, P_('zz', { type: 'integer', accumulates: a }));
await vdef('accumulates on string', P_('zz', { type: 'string', accumulates: ['a'] }));
for (const [l, m] of [['pnd false no default', { principal_neutral_default: false }], ['pnd true no default', { principal_neutral_default: true }], ['pnd string', { principal_neutral_default: 'true' }], ['pnd null', { principal_neutral_default: null }], ['default object', { default: { a: 1 } }]] as [string, any][]) await vdef(l, P_('zz', { type: 'string', ...m }));
for (const v of around(1024)) await vdef(`param description ${v.length}${v.endsWith('é') ? 'mb' : ''}`, P_('zz', { type: 'string', description: v }));
await vdef('param description empty', P_('zz', { type: 'string', description: '' }));
await vdef('required string', P_('zz', { type: 'string', required: 'yes' }));
// reversibility
for (const [l, r] of [
  ['class reversible', 'reversible'], ['class rate_limited', 'rate_limited'], ['class bad', 'undoable'], ['number', 5], ['array', []], ['null', null],
  ['by ok no default', { by: 'flag', map: { true: 'reversible' } }], ['by unknown', { by: 'nope', map: { true: 'reversible' } }], ['by 5', { by: 5, map: { a: 'reversible' } }], ['by missing', { map: { a: 'reversible' } }],
  ['map empty', { by: 'flag', map: {} }], ['map array', { by: 'flag', map: [] }], ['map bad class', { by: 'flag', map: { true: 'x' } }], ['map key empty', { by: 'flag', map: { '': 'reversible' } }],
  ['map key 128', { by: 'flag', map: { [s(128)]: 'reversible' } }], ['map key 129', { by: 'flag', map: { [s(129)]: 'reversible' } }], ['map key 127mb', { by: 'flag', map: { [s(127) + 'é']: 'reversible' } }],
  ['map 256', { by: 'flag', map: Object.fromEntries(Array.from({ length: 256 }, (_, i) => [`k${i}`, 'reversible'])) }], ['map 257', { by: 'flag', map: Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`k${i}`, 'reversible'])) }],
  ['default bad', { by: 'flag', map: { true: 'reversible' }, default: 'x' }], ['default null', { by: 'flag', map: { true: 'reversible' }, default: null }], ['extra', { by: 'flag', map: { true: 'reversible' }, x: 1 }],
  ['extra first', { x: 1, by: 'flag', map: { true: 'reversible' } }],
] as [string, any][]) await vdef(`reversibility ${l}`, W((d) => { d.reversibility = r; }));
// blast / side effects / idempotency / context / traits / audience / compensates
for (const [l, b] of [['ppm 0', { radius: 'one', ppm: 0 }], ['ppm 1e6', { radius: 'one', ppm: 1000000 }], ['ppm 1e6+1', { radius: 'one', ppm: 1000001 }], ['ppm -1', { radius: 'one', ppm: -1 }], ['ppm 1.5', { radius: 'one', ppm: 1.5 }],
  ['radius bad', { radius: 'huge' }], ['radius missing', { ppm: 1 }], ['extra', { radius: 'one', x: 1 }], ['global', { radius: 'global' }], ['tenant', { radius: 'tenant' }], ['array', []]] as [string, any][]) await vdef(`blast ${l}`, W((d) => { d.blast = b; }));
const SE = (n: number) => Array.from({ length: n }, (_, i) => ({ target: `t${i}`, kind: 'update' }));
for (const [l, x] of [['15', SE(15)], ['16', SE(16)], ['17', SE(17)], ['empty', []], ['kind bad', [{ target: 't', kind: 'x' }]], ['target 128', [{ target: s(128), kind: 'read' }]], ['target 129', [{ target: s(129), kind: 'read' }]],
  ['target empty', [{ target: '', kind: 'read' }]], ['extra', [{ target: 't', kind: 'read', x: 1 }]], ['missing kind', [{ target: 't' }]], ['object', {}]] as [string, any][]) await vdef(`side_effects ${l}`, W((d) => { d.side_effects = x; }));
for (const [l, i] of [['natural', { mode: 'natural' }], ['none', { mode: 'none' }], ['natural param', { mode: 'natural', param: 'key' }], ['key_param no param', { mode: 'key_param' }], ['key_param unknown', { mode: 'key_param', param: 'nope' }],
  ['key_param 5', { mode: 'key_param', param: 5 }], ['mode bad', { mode: 'auto' }], ['extra', { mode: 'none', x: 1 }], ['array', []]] as [string, any][]) await vdef(`idempotency ${l}`, W((d) => { d.idempotency = i; }));
const CTX = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'];
for (const c of [[], CTX, [...CTX, ...Array.from({ length: 10 }, (_, i) => `session_taint_max:${s(i + 1, 'q')}`)], [...CTX, ...Array.from({ length: 11 }, (_, i) => `session_taint_max:${s(i + 1, 'q')}`)], ['session_taint_max:' + s(16)], ['session_taint_max:' + s(17)], ['session_taint_max:'], ['session_taint_max:A'], ['approval_ref', 'approval_ref'], ['bogus']])
  await vdef(`context ${c.length} ${c.slice(-1)[0] ?? ''}`.slice(0, 80) + `#${c.join().length}`, W((d) => { d.context = c; }));
const TR = (n: number) => Array.from({ length: n }, (_, i) => `acme.t${i}`);
for (const t of [TR(31), TR(32), TR(33), ['a.b', 'a.b'], ['A.b'], ['a'], ['a.' + s(64)], ['a.' + s(65), 'x.y'], [s(32) + '.b'], [s(33) + '.b'], ['a.1b'], ['a_.b_']]) await vdef(`traits ${t.length} ${t.slice(-1)[0].slice(0, 12)}#${t.join().length}`, W((d) => { d.traits = t; }));
for (const a of ['resource', 'self', null]) await vdef(`audience ${a}`, W((d) => { d.audience = a; }));
for (const c of ['acme.invoice.refund', 'refund', 'A.b', 5]) await vdef(`compensates ${c}`, W((d) => { d.compensates = c; }));
// bindings: every kind's members, each required member missing / empty / 256 / 257
const BSH: Record<string, [string[], string[]]> = { mcp: [['tool'], []], openapi: [['operationId'], ['method', 'path']], http: [['method', 'path'], []], graphql: [['op', 'field'], []], grpc: [['service', 'method'], []], asyncapi: [['channel', 'op'], []] };
for (const [k, [req, opt]] of Object.entries(BSH)) {
  const ok = MAX_DEF.bindings[k];
  await vdef(`bindings only ${k}`, W((d) => { d.bindings = { [k]: ok }; }));
  for (const m of [...req, ...opt]) {
    for (const [l, v] of [['missing', undefined], ['empty', ''], ['256', s(256)], ['257', s(257)], ['255mb', s(255) + 'é'], ['num', 1]] as [string, any][])
      await vdef(`bindings ${k}.${m} ${l}`, W((d) => { d.bindings = { [k]: { ...ok, [m]: v } }; }));
  }
  await vdef(`bindings ${k} extra`, W((d) => { d.bindings = { [k]: { ...ok, x: '1' } }; }));
  await vdef(`bindings ${k} not object`, W((d) => { d.bindings = { [k]: 'x' }; }));
}
for (const op of ['query', 'mutation', 'subscription', 'Query', 'x']) await vdef(`bindings graphql op ${op}`, W((d) => { d.bindings = { graphql: { op, field: 'f' } }; }));
for (const op of ['send', 'receive', 'publish']) await vdef(`bindings asyncapi op ${op}`, W((d) => { d.bindings = { asyncapi: { channel: 'c', op } }; }));
await vdef('bindings bad kind first', W((d) => { d.bindings = { soap: {}, mcp: { tool: 't' } }; }));
await vdef('bindings graphql bad op and asyncapi bad op', W((d) => { d.bindings = { graphql: { op: 'x', field: 'f' }, asyncapi: { channel: 'c', op: 'x' } }; }));
// examples
const EX = (n: number) => Array.from({ length: n }, () => ({ params: {}, expect: 'deny' }));
for (const [l, e] of [['31', EX(31)], ['32', EX(32)], ['33', EX(33)], ['expect bad', [{ params: {}, expect: 'maybe' }]], ['params array', [{ params: [], expect: 'deny' }]], ['extra', [{ params: {}, expect: 'deny', x: 1 }]], ['not array', {}], ['item null', [null]]] as [string, any][])
  await vdef(`examples ${l}`, W((d) => { d.examples = e; }));
// review
const RV = (r: any) => W((d) => { d.review = r; });
for (const st of ['authored', 'unreviewed', 'suggested', 'confirmed', 'stale', null]) await vdef(`review state ${st}`, RV({ state: st }));
await vdef('review missing', W((d) => { delete d.review; }));
await vdef('review extra', RV({ state: 'authored', x: 1 }));
for (const [l, pv] of [['ok', { union: ['a.b'] }], ['empty', {}], ['bad member', { other: [] }], ['33', { union: Array.from({ length: 33 }, (_, i) => `a.t${i}`) }], ['32', { adjudicated: Array.from({ length: 32 }, (_, i) => `a.t${i}`) }],
  ['dup', { union: ['a.b', 'a.b'] }], ['not trait', { union: ['ab'] }], ['three segments', { union: ['a.b.c'] }], ['upper', { union: ['A.b'] }], ['num', { union: [1] }], ['not array', { union: 'a.b' }], ['array', []]] as [string, any][])
  await vdef(`review provenance ${l}`, RV({ state: 'authored', provenance: pv }));
const AT = (o: any) => RV({ state: 'confirmed', attestation: { ...ATT, ...o } });
for (const [k, mx] of [['def_digest', 64], ['traits_digest', 64], ['facts_digest', 64], ['reviewer_kid', 128], ['sig', 4096]] as const) {
  for (const v of around(mx)) await vdef(`attestation ${k} ${v.length}${v.endsWith('é') ? 'mb' : ''}`, AT({ [k]: v }));
  await vdef(`attestation ${k} empty`, AT({ [k]: '' }));
}
for (const [l, o] of [['ts 0', { ts: 0 }], ['ts -1', { ts: -1 }], ['ts 1.5', { ts: 1.5 }], ['ts max', { ts: 2 ** 53 - 1 }], ['ts str', { ts: '1' }],
  ['final 32', { final_traits: TR(32) }], ['final 33', { final_traits: TR(33) }], ['final dup', { final_traits: ['a.b', 'a.b'] }], ['final bad', { final_traits: ['ab'] }], ['final num', { final_traits: [1] }],
  ['dismissed 32', { dismissed: TR(32).map((t) => ({ trait: t, reason: 'r' })) }], ['dismissed 33', { dismissed: TR(33).map((t) => ({ trait: t, reason: 'r' })) }],
  ['dismissed extra', { dismissed: [{ trait: 'a.b', reason: 'r', x: 1 }] }], ['dismissed reason empty', { dismissed: [{ trait: 'a.b', reason: '' }] }], ['dismissed reason 256', { dismissed: [{ trait: 'a.b', reason: s(256) }] }],
  ['dismissed reason 257', { dismissed: [{ trait: 'a.b', reason: s(257) }] }], ['dismissed trait bad', { dismissed: [{ trait: 'ab', reason: 'r' }] }], ['dismissed missing reason', { dismissed: [{ trait: 'a.b' }] }],
  ['dismissed null item', { dismissed: [null] }], ['dismissed not array', { dismissed: {} }], ['sig missing', { sig: undefined }], ['extra', { x: 1 }]] as [string, any][]) await vdef(`attestation ${l}`, AT(o));
await vdef('attestation not object', RV({ state: 'confirmed', attestation: 'x' }));
// source
for (const [l, o] of [['kind 64', { kind: s(64) }], ['kind 65', { kind: s(65) }], ['uri 2048', { uri: s(2048) }], ['uri 2049', { uri: s(2049) }], ['spec_digest 128', { spec_digest: s(128) }], ['spec_digest 129', { spec_digest: s(129) }],
  ['licence 129', { licence: s(129) }], ['imported_at -1', { imported_at: -1 }], ['imported_at 1.5', { imported_at: 1.5 }], ['no imported_at', { imported_at: undefined }], ['extra', { x: 1 }], ['missing licence', { licence: undefined }]] as [string, any][])
  await vdef(`source ${l}`, W((d) => { d.source = { ...d.source, ...o }; }));
// strict JSON profile reaching validateDef
const nest = (n: number): any => (n === 0 ? 1 : [nest(n - 1)]);
for (const n of [29, 30, 31, 32, 33]) await vdef(`json depth ${n}`, W((d) => { d.examples = [{ params: { x: nest(n) }, expect: 'deny' }]; }));
await vdef('json NFD member', W((d) => { d.examples = [{ params: { ['é']: 1 }, expect: 'deny' }]; }));
await vdef('json lone surrogate member', W((d) => { d.examples = [{ params: { ['\udc00']: 1 }, expect: 'deny' }]; }));
await vdef('json float in examples', W((d) => { d.examples = [{ params: { x: 0.5 }, expect: 'deny' }]; }));
// seeded multi-edit mutants (2..4 hostile / boundary edits at random paths)
{
  const r = rng(0x05ac7);
  const pool = [...HOSTILE, 'reversible', 'irreversible', 'one', 'set', 'pca.bulk', 'a.b', 'money.amount', 'integer', 'string', 'array', 'set', 'USD', { kind: 'count' }, { from: 'currency' }, s(65), s(129), 0, 64, 65, 256, 257];
  for (const [n, d] of SEEDS.slice(0, 4)) {
    const ps = paths(d, 6).filter((p) => p.length > 0);
    for (let i = 0; i < 700; i++) {
      let x = d;
      const k = r.int(2, 4);
      for (let j = 0; j < k; j++) { const p = r.pick(ps); const par = getAt(x, p.slice(0, -1)); if (par == null || typeof par !== 'object' || Array.isArray(par) !== (typeof p[p.length - 1] === 'number')) continue; const v = r.pick(pool); x = setAt(x, p, () => v); }
      await vdef(`${n} random#${i}`, x);
    }
  }
}

// ---- isRole / isFormat / isContextKey / paramNameError / jsonProfileError / idPatternError ------------------------------
for (const r of ['money.amount', 'bytes.size', 'id.x', 'id.a.b.c.d', 'id.a.b.c.d.e', 'id.', 'id.A', 'x.a', 'x.a.b', 'x.a.b.c.d', 'x.a.b.c.d.e', 'x.A.b', 'money.x', '', 5, null, 'ID.x', 'id.x-y'])
  O.add('isRole', `${JSON.stringify(r)}`, [r], A.isRole(r));
for (const f of ['email', 'url', 'uri_https', 'uuid', 'iban', 'phone_e164', 'cidr', 'iso_country', 'iso_currency', 'semver', 'sha256', 'id:a', 'id:a.b.c.d', 'id:a.b.c.d.e', 'id:', 'id:A', 'Email', '', 5, null, 'date'])
  O.add('isFormat', `${JSON.stringify(f)}`, [f], A.isFormat(f));
for (const c of [...CTX, 'session_taint_max:a', 'session_taint_max:' + s(16), 'session_taint_max:' + s(17), 'session_taint_max:', 'session_taint_max:a1', 'session_taint_max:a_b', 'Approval_ref', '', 5, null])
  O.add('isContextKey', `${JSON.stringify(c)}`, [c], A.isContextKey(c));
for (const n of [...pn, 'a.b', 'a.b.', '.a', 'a.__proto__', 'constructor', 'a.b.prototype', 'A.B.C']) O.add('paramNameError', `${JSON.stringify(n)}#${n.length}`, [n], A.paramNameError(n));
{
  const vals: [string, any][] = [['null', null], ['true', true], ['0', 0], ['-0', -0], ['1.5', 1.5], ['2^53', 2 ** 53], ['2^53-1', 2 ** 53 - 1], ['-(2^53-1)', -(2 ** 53 - 1)], ['1e21', 1e21], ['str', 'x'], ['nfd', 'é'], ['nfc', 'é'],
    ['lone hi', '\ud800'], ['lone lo', '\udc00'], ['pair', '😀'], ['hi at end', 'a\ud800'], ['lo first', '\udc00a'], ['swapped pair', '\ude00\ud83d'], ['arr', [1, 'x', null]], ['arr float', [1, 0.5]], ['obj', { a: 1 }],
    ['obj nfd key', { ['é']: 1 }], ['obj lone key', { ['\ud800']: 1 }], ['obj -0', { a: -0 }], ['empty obj', {}], ['empty arr', []]];
  for (const [l, v] of vals) await O.run('jsonProfileError', l, (x: any) => A.jsonProfileError(x), [v]);
  for (const n of [30, 31, 32, 33, 34]) {
    await O.run('jsonProfileError', `depth arr ${n}`, (x: any) => A.jsonProfileError(x), [nest(n)]);
    let o: any = 1; for (let i = 0; i < n; i++) o = { k: o };
    await O.run('jsonProfileError', `depth obj ${n}`, (x: any) => A.jsonProfileError(x), [o]);
    await O.run('jsonProfileError', `depth arr ${n} then float`, (x: any) => A.jsonProfileError(x), [[nest(n), 0.5]]);
  }
}
{
  const pats: any[] = ['*', '**', '', null, 5, [], {}, { exact: 'a' }, { exact: '' }, { exact: s(128) }, { exact: s(129) }, { exact: 'a b' }, { exact: 'a.b_c-d:e/f' }, { exact: 'é' }, { exact: 5 }, { exact: 'a', x: 1 },
    { prefix: 'p', class: 'hex', len: [1, 128] }, { prefix: s(32), class: 'hex', len: [1, 1] }, { prefix: s(33), class: 'hex', len: [1, 1] }, { prefix: 'a b', class: 'hex', len: [1, 1] }, { prefix: 5, class: 'hex', len: [1, 1] },
    { prefix: '', class: 'uuid', len: [36, 36] }, { prefix: 'x', class: 'uuid', len: [36, 36] }, { prefix: '', class: 'uuid', len: [35, 36] }, { prefix: '', class: 'uuid', len: [36, 37] },
    { prefix: '', class: 'bogus', len: [1, 2] }, { prefix: '', class: 'digits', len: [0, 2] }, { prefix: '', class: 'digits', len: [1, 129] }, { prefix: '', class: 'digits', len: [2, 1] }, { prefix: '', class: 'digits', len: [2, 2] },
    { prefix: '', class: 'digits', len: [1] }, { prefix: '', class: 'digits', len: [1, 2, 3] }, { prefix: '', class: 'digits', len: [1.5, 2] }, { prefix: '', class: 'digits', len: [-0, 2] }, { prefix: '', class: 'digits', len: '1,2' },
    { prefix: '', class: 'slug', len: [1, 2], x: 1 }, { prefix: '', class: 'alnum' }, { class: 'alnum', len: [1, 2] }, { prefix: 'a', len: [1, 2] }];
  for (const c of ['digits', 'hex', 'alnum', 'slug', 'uuid', 'any_safe']) for (const len of [[1, 1], [36, 36], [128, 128], [1, 128]]) pats.push({ prefix: '', class: c, len });
  for (const ch of [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`', '{', '|', '}', '~', '\u0000', '\u007f', 'é', '\ud800', '.', '_', '-', ':', '/', 'A', 'z', '0', '9'])
    pats.push({ exact: 'a' + ch }, { prefix: ch, class: 'hex', len: [1, 2] });
  for (const p of pats) await O.run('idPatternError', JSON.stringify(p), (x: any) => A.idPatternError(x), [p]);
}

// ---- profiles, registries, closure, floors, floorDecision -----------------------------------------------------------
const FULLP = { risk: 2, rev: 'rate_limited', blast_ppm: 500000, esc: 1, caveats: ['amount_cap', 'window'], context: ['approval_ref', 'session_taint_max:low'], prules: ['money_has_currency', 'pay_has_idempotency'] };
await O.run('profileError', 'full', (x: any) => A.profileError(x), [FULLP]);
for (const [lab, v] of variants(FULLP, { hostile: [null, -1, 4, 3, 0, 1.5, -0, 1000001, 2 ** 53, '', 'x', [], {}, ['amount_cap', 'amount_cap'], ['window', 'amount_cap'], ['zz']] }))
  await O.run('profileError', lab, (x: any) => A.profileError(x), [v]);
for (const [k, n] of [['caveats', 8], ['prules', 8]] as const) for (const m of [63, 64, 65]) {
  // only n distinct known values exist, so >n entries are either duplicates (unsorted) or unknown: both refused
  await O.run('profileError', `${k} ${m}`, (x: any) => A.profileError(x), [{ ...FULLP, [k]: Array.from({ length: m }, (_, i) => (i < n ? (k === 'caveats' ? A.CAVEAT_KINDS : A.PARAM_RULE_IDS)[i] : 'zz')).sort() }]);
}
for (const m of [64, 65]) await O.run('profileError', `context ${m} taint keys`, (x: any) => A.profileError(x), [{ ...FULLP, context: Array.from({ length: m }, (_, i) => `session_taint_max:${String.fromCharCode(97 + (i % 26))}${s(Math.floor(i / 26) + 1, 'z')}`).sort() }]);
for (const r of [0, 3, 4]) for (const e of [0, 3, 4]) await O.run('profileError', `risk ${r} esc ${e}`, (x: any) => A.profileError(x), [{ ...FULLP, risk: r, esc: e }]);

const prof = (o: any = {}) => ({ risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [], ...o });
const tdef = (id: string, implies: string[] = [], floor: any = prof(), extra: any = {}) => ({ id, implies, floor, card_phrase: id, ...extra });
const MM = A.CORE_REGISTRY.traits.get('pca.money_moving').floor;
const chain = (n: number, ns = 'acme') => Array.from({ length: n }, (_, i) => tdef(`${ns}.c${i}`, i + 1 < n ? [`${ns}.c${i + 1}`] : [], prof()));
const REG_CASES: [string, any, boolean][] = [
  ['core', A.CORE_TRAIT_DEFS, true], ['core not core', A.CORE_TRAIT_DEFS, false], ['empty', [], false], ['not array', {}, false], ['null', null, false],
  ['chain 8', chain(8), false], ['chain 9', chain(9), false], ['chain 7', chain(7), false],
  ['cycle 2', [tdef('a.x', ['a.y']), tdef('a.y', ['a.x'])], false], ['self cycle', [tdef('a.x', ['a.x'])], false],
  ['unknown implied', [tdef('a.x', ['a.nope'])], false], ['dup id', [tdef('a.x'), tdef('a.x')], false], ['bad id', [tdef('ax')], false], ['id upper', [tdef('A.x')], false], ['id 5', [tdef(5 as any)], false],
  ['pca ns non-core', [tdef('pca.x')], false], ['pca ns core', [tdef('pca.x')], true],
  ['implies 8', [tdef('a.x', Array.from({ length: 8 }, (_, i) => `a.y${i}`)), ...Array.from({ length: 8 }, (_, i) => tdef(`a.y${i}`))], false],
  ['implies 9', [tdef('a.x', Array.from({ length: 9 }, (_, i) => `a.y${i}`)), ...Array.from({ length: 9 }, (_, i) => tdef(`a.y${i}`))], false],
  ['implies dup', [tdef('a.x', ['a.y', 'a.y']), tdef('a.y')], false], ['implies num', [tdef('a.x', [5 as any])], false], ['implies not array', [{ ...tdef('a.x'), implies: 'a.y' }], false],
  ['T5 violated', [tdef('a.x', ['a.y'], prof({ risk: 1 })), tdef('a.y', [], prof({ risk: 2 }))], false], ['T5 equal', [tdef('a.x', ['a.y'], prof({ risk: 2 })), tdef('a.y', [], prof({ risk: 2 }))], false],
  ['T5 set', [tdef('a.x', ['a.y'], prof({ caveats: ['window'] })), tdef('a.y', [], prof({ caveats: ['amount_cap'] }))], false],
  ['T5 rev', [tdef('a.x', ['a.y'], prof({ rev: 'rate_limited' })), tdef('a.y', [], prof({ rev: 'irreversible' }))], false],
  ['bad floor', [tdef('a.x', [], prof({ risk: 9 }))], false], ['floor missing', [{ id: 'a.x', implies: [], card_phrase: 'p' }], false],
  ['card empty', [tdef('a.x', [], prof(), { card_phrase: '' })], false], ['card 120', [tdef('a.x', [], prof(), { card_phrase: s(120) })], false], ['card 121', [tdef('a.x', [], prof(), { card_phrase: s(121) })], false],
  ['card num', [tdef('a.x', [], prof(), { card_phrase: 5 })], false], ['trait null', [null], false], ['trait string', ['a.x'], false],
  ['512', Array.from({ length: 512 }, (_, i) => tdef(`a.t${i}`)), false], ['513', Array.from({ length: 513 }, (_, i) => tdef(`a.t${i}`)), false],
  ['extends core', [tdef('acme.mm', ['pca.money_moving'], MM)], true], ['below core', [tdef('acme.mm', ['pca.money_moving'], prof())], true],
  ['diamond', [tdef('a.top', ['a.l', 'a.r']), tdef('a.l', ['a.b']), tdef('a.r', ['a.b']), tdef('a.b')], false],
  ['depth via long branch', [tdef('a.top', ['a.c0', 'a.short']), tdef('a.short'), ...chain(8, 'a').slice(0)], false],
];
for (const [l, d, core] of REG_CASES) await O.run('registryError', l, (x: any, c: any) => A.registryError(x, { core: c }), [d, core]);
for (const [lab, v] of variants([tdef('acme.x', ['acme.y'], prof({ risk: 2, caveats: ['window'] })), tdef('acme.y', [], prof({ risk: 1 }))], { depth: 4, hostile: [null, '', 'pca.bulk', 'acme.x', 5, 1.5, [], {}, 121] }))
  await O.run('registryError', `variant ${lab}`, (x: any) => A.registryError(x, { core: false }), [v, false]);

const CUSTOMS: [string, any][] = [
  ['core', null],
  ['chain', [tdef('acme.c0', ['acme.c1'], { ...MM, esc: 3 }), tdef('acme.c1', ['acme.c2'], { ...MM, esc: 3 }), tdef('acme.c2', ['pca.money_moving'], MM)]],
  ['wide', [tdef('acme.w', ['pca.bulk', 'pca.pii_access'], prof({ risk: 3, rev: 'irreversible', blast_ppm: 1000000, esc: 3, caveats: [...A.CAVEAT_KINDS].sort(), context: ['approval_ref'], prules: [...A.PARAM_RULE_IDS].sort() }))]],
  ['redefine core', [tdef('pca.bulk', [], prof())]], ['below implied', [tdef('acme.x', ['pca.money_moving'], prof())]], ['custom pca ns', [tdef('pca.newone', [], prof())]],
];
const CORE_IDS = [...A.CORE_REGISTRY.traits.keys()];
for (const [cl, custom] of CUSTOMS) {
  const ids = [...CORE_IDS, ...(custom ?? []).map((t: any) => t.id)];
  const r = rng(0xc105e + cl.length);
  const sets: any[] = [[], ['acme.nope'], ['pca.bulk', 'acme.nope'], ids, [ids[0], ids[0]]];
  for (let i = 0; i < 120; i++) sets.push(Array.from({ length: r.int(1, 5) }, () => r.pick(ids)));
  for (const [i, set] of sets.entries()) {
    await O.run('closure', `${cl} #${i}`, (c: any, x: any) => A.closure(regOf(c), x), [custom, set]);
    await O.run('floorOf', `${cl} #${i}`, (c: any, x: any) => A.floorOf(regOf(c), x), [custom, set]);
  }
  await O.run('topTraits', cl, (c: any) => A.topTraits(regOf(c)), [custom]);
  await O.run('traitsDigest', cl, (c: any) => A.traitsDigest(regOf(c)), [custom]);
}
O.add('tablesDigest', 'core', [], A.tablesDigest());
{
  const cavs = [[], ['amount_cap'], ['amount_cap', 'window'], ['window']];
  for (const max_esc of [0, 1, 2, 3]) for (const pre of [0, 1, 2, 3]) for (const esc of [0, 1, 2, 3]) for (const [ci, gc] of cavs.entries()) for (const [ri, rc] of cavs.entries()) for (const [xi, ctx] of [[], ['approval_ref'], ['approval_ref', 'fresh_revocation']].entries()) {
    if ((max_esc + pre + esc + ci + ri + xi) % 3 !== 0 && !(ci === ri && xi === 1)) continue; // a thinned full grid (every boundary pair still appears)
    O.add('floorDecision', `me${max_esc} pe${pre} e${esc} g${ci} r${ri} x${xi}`, [{ caveats: gc, max_esc, preauth_esc: pre }, { context: ctx }, prof({ esc, caveats: rc, context: xi === 2 ? ['approval_ref'] : xi === 1 ? ['fresh_revocation'] : [] })],
      A.floorDecision({ caveats: gc, max_esc, preauth_esc: pre }, { context: ctx }, prof({ esc, caveats: rc, context: xi === 2 ? ['approval_ref'] : xi === 1 ? ['fresh_revocation'] : [] })));
  }
}

// ---- worstReversibility / sensitivityFloor / impliedFromFacts ------------------------------------------------------------
{
  const pts: [string, any][] = [['boolean', { type: 'boolean' }], ['enum', { type: 'string', values: ['a', 'b'] }], ['string', { type: 'string' }], ['set', { type: 'set', values: ['a', 'b'] }], ['integer', { type: 'integer' }]];
  const maps: [string, any][] = [['none', {}], ['true', { true: 'reversible' }], ['both bool', { true: 'reversible', false: 'rate_limited' }], ['a', { a: 'reversible' }], ['a b', { a: 'reversible', b: 'rate_limited' }], ['a b c', { a: 'reversible', b: 'reversible', c: 'irreversible' }], ['irrev a', { a: 'irreversible', b: 'reversible' }]];
  for (const r of ['reversible', 'rate_limited', 'irreversible']) O.add('worstReversibility', r, [r, {}], A.worstReversibility(r, {}));
  for (const [pl, p] of pts) for (const [ml, m] of maps) for (const def of [undefined, 'reversible', 'rate_limited', 'irreversible']) {
    O.add('worstReversibility', `${pl} ${ml} default ${def}`, reparse([{ by: 'x', map: m, default: def }, { x: p }]), A.worstReversibility({ by: 'x', map: m, default: def }, { x: p }));
    if (pl === 'boolean' && def === undefined) O.add('worstReversibility', `missing param ${ml}`, reparse([{ by: 'x', map: m }, {}]), A.worstReversibility({ by: 'x', map: m }, {}));
  }
  for (const role of [undefined, ...A.CORE_ROLES, 'id.x', 'x.a.b']) for (const tags of [undefined, [], ...TAGS.map((t) => [t]), ['pii', 'secret']]) {
    if (role !== undefined && tags !== undefined && tags.length > 1) continue;
    O.add('sensitivityFloor', `${role} ${JSON.stringify(tags)}`, reparse([{ role, tags }]), A.sensitivityFloor({ role, tags }));
  }
  const r = rng(0x1f4c75);
  const ptypes = ['string', 'integer', 'array', 'set', 'boolean'];
  for (let i = 0; i < 600; i++) {
    const f: any = { effects: r.sub(EFF, 4), worstRev: r.pick(['reversible', 'rate_limited', 'irreversible']), params: Array.from({ length: r.int(0, 3) }, () => reparse({ type: r.pick(ptypes), role: r.next() < 0.6 ? r.pick([...A.CORE_ROLES, 'id.x']) : undefined, tags: r.next() < 0.5 ? r.sub(TAGS, 3) : undefined, max_items: r.next() < 0.5 ? r.int(0, 3) : undefined })) };
    if (r.next() < 0.7) f.scope = r.pick(['one', 'set', 'tenant', 'global']);
    O.add('impliedFromFacts', `random#${i}`, [f], A.impliedFromFacts(f));
  }
  for (const e of EFF) O.add('impliedFromFacts', `effect ${e}`, [{ effects: [e], worstRev: 'reversible', params: [] }], A.impliedFromFacts({ effects: [e], worstRev: 'reversible', params: [] }));
  for (const role of A.CORE_ROLES) for (const eff of [['read'], ['update'], ['read', 'update']]) {
    const f = { effects: eff, worstRev: 'reversible', params: [{ type: 'string', role }] };
    O.add('impliedFromFacts', `role ${role} ${eff}`, [f], A.impliedFromFacts(f));
  }
}

// ---- downstream of every accepted def: normalize, defDigest, declProfile, hintTraits, effective, schema verb ----------
const effOut = (e: any) => ({ confirmed: e.confirmed, traits: e.traits, closure: e.closure, floor: e.floor, decl: e.decl, eff: e.eff });
const verbs: [string, any, any][] = [];
for (const [n, d] of accepted) {
  for (const [fn, f] of [['normalize', A.normalize], ['defDigest', A.defDigest], ['declProfile', A.declProfile], ['hintTraits', A.hintTraits]] as [string, any][])
    await O.run(fn, n, f, [d]);
  await O.run('effective', n, (x: any, pins: any) => effOut(A.effective(x, CORE, pins ? { attestationVerified: A.attestationVerifier({ pins, registry: CORE }) } : {})), [d, null]);
  try { verbs.push([n, A.toSchemaVerb(d, CORE).verb, null]); } catch { /* not every accepted def derives (e.g. a dangling ccy.from); the schema space below is built from those that do */ }
}

// ---- reviewer pins, review message, the signed confirmation ----------------------------------------------------------------
await O.run('reviewerPinsError', 'ok', A.reviewerPinsError, [PINS]);
for (const [lab, v] of variants(PINS, { hostile: [null, '', 'x', 5, -1, 1.5, -0, [], {}, ['reviewer', 'reviewer'], ['reviewer', 'model'], ['publisher'], ['admin'], s(128), s(129), MACH.pk, REV.pk, REV.pk + 'A', s(43, 'A'), s(44, 'A'), s(43, '_')] }))
  await O.run('reviewerPinsError', lab, A.reviewerPinsError, [v]);
for (const [l, p] of [
  ['same pk reviewer+importer kids', { keys: [{ kid: 'a', pk: MACH.pk, roles: ['importer'] }, { kid: 'b', pk: MACH.pk, roles: ['reviewer'] }] }],
  ['same pk reviewer first', { keys: [{ kid: 'b', pk: MACH.pk, roles: ['reviewer'] }, { kid: 'a', pk: MACH.pk, roles: ['model'] }] }],
  ['same pk publisher', { keys: [{ kid: 'a', pk: MACH.pk, roles: ['publisher'] }, { kid: 'b', pk: MACH.pk, roles: ['reviewer'] }] }],
  ['empty keys', { keys: [] }], ['traits_digests', { keys: [], traits_digests: ['x'] }], ['keys object', { keys: {} }], ['no keys', {}], ['null', null], ['array', []],
] as [string, any][]) await O.run('reviewerPinsError', l, A.reviewerPinsError, [p]);

const BODY = { def_digest: s(43, 'A'), traits_digest: TD, facts_digest: s(43, 'C'), final_traits: ['pca.bulk', 'acme.x', 'pca.bulk'], dismissed: [{ trait: 'pca.z', reason: 'b' }, { trait: 'pca.a', reason: 'a', extra: 1 }], reviewer_kid: 'rev1', ts: 7 };
await O.run('reviewMessage', 'body', A.reviewMessage, [BODY]);
await O.run('reviewMessage', 'empty lists', A.reviewMessage, [{ ...BODY, final_traits: [], dismissed: [] }]);
await O.run('reviewMessage', 'ts 0 unicode kid', A.reviewMessage, [{ ...BODY, ts: 0, reviewer_kid: 'é ' }]);

// isConfirmed (Java Actions.isConfirmed(d, CORE, pins); TS verifyAttestation(d, {pins, registry: CORE}).ok)
const isConf = (d: any, pins: any) => A.verifyAttestation(d, { pins, registry: CORE }).ok;
const CONF_SEEDS: [string, any][] = [['max', W((d) => { delete d.review.provenance; })], ['read', READ_DEF], ['uuid traits', W((d) => { d.traits = ['pca.bulk', 'acme.custom']; }, UUID_DEF)]];
for (const [n, d0] of CONF_SEEDS) {
  const good = confirm(d0);
  await O.run('isConfirmed', `${n} good`, isConf, [good, PINS]);
  await O.run('isConfirmed', `${n} good no pins`, isConf, [good, null]);
  await O.run('effective', `${n} confirmed`, (x: any, pins: any) => effOut(A.effective(x, CORE, pins ? { attestationVerified: A.attestationVerifier({ pins, registry: CORE }) } : {})), [good, PINS]);
  await O.run('effective', `${n} confirmed no pins`, (x: any, pins: any) => effOut(A.effective(x, CORE, pins ? { attestationVerified: A.attestationVerifier({ pins, registry: CORE }) } : {})), [good, null]);
  // the attestation's own members, each mutated (signature now stale or member malformed)
  for (const [lab, v] of variants(good.review.attestation, { hostile: [null, '', 5, -1, 1.5, [], {}, 'rev2', 'imp1', 'nobody', TD, 'pca.bulk'] }))
    await O.run('isConfirmed', `${n} att ${lab}`, isConf, [{ ...good, review: { ...good.review, attestation: v } }, PINS]);
  // re-signed variants: each reaches a different gate with a VALID signature
  const re: [string, any][] = [
    ['ts 99 (before not_before)', confirm(d0, { ts: 99 })], ['ts 100', confirm(d0, { ts: 100 })], ['ts 2e9', confirm(d0, { ts: 2_000_000_000 })], ['ts 2e9+1', confirm(d0, { ts: 2_000_000_001 })],
    ['other registry digest', confirm(d0, { traits_digest: s(43, 'Z') })], ['wrong def digest', confirm(d0, { def_digest: s(43, 'Q') })],
    ['final extra', confirm(d0, { final_traits: [...(d0.traits ?? []), 'pca.bulk'].sort() })], ['final missing', confirm(d0, { final_traits: [] })],
    ['dismissed ok', confirm(d0, { dismissed: [{ trait: 'pca.destructive', reason: 'no' }] })], ['dismissed also final', confirm(d0, { dismissed: [{ trait: (d0.traits ?? ['pca.bulk'])[0] ?? 'pca.bulk', reason: 'x' }] })],
    ...[' ', '\t', '\n', ' ', '﻿', ' ', '　', '\u001c', '\u0085', '​', '᠎', ' x '].map((w) => [`dismissed reason ${JSON.stringify(w)}`, confirm(d0, { dismissed: [{ trait: 'pca.destructive', reason: w }] })] as [string, any]),
    ['rev2 key', confirm(d0, {}, REV2.sk, 'rev2')], ['importer key', confirm(d0, {}, MACH.sk, 'imp1')], ['unknown kid', confirm(d0, {}, REV.sk, 'ghost')], ['rev1 kid rev2 key', confirm(d0, {}, REV2.sk, 'rev1')],
    ['facts_digest absent', (() => { try { return confirm(d0, { facts_digest: undefined }); } catch { return null; } })()], ['facts_digest number', (() => { try { return confirm(d0, { facts_digest: 5 }); } catch { return null; } })()],
  ];
  for (const [l, d] of re) if (d) await O.run('isConfirmed', `${n} ${l}`, isConf, [d, PINS]);
  await O.run('isConfirmed', `${n} extra traits digest`, isConf, [confirm(d0, { traits_digest: s(43, 'Z') }), { ...PINS, traits_digests: [s(43, 'Z')] }]);
  await O.run('isConfirmed', `${n} state suggested`, isConf, [{ ...good, review: { ...good.review, state: 'suggested' } }, PINS]);
  await O.run('isConfirmed', `${n} def edited after`, isConf, [{ ...good, title: good.title + '!' }, PINS]);
  await O.run('isConfirmed', `${n} examples edited after (not in digest)`, isConf, [{ ...good, examples: [{ params: {}, expect: 'deny' }] }, PINS]);
  await O.run('isConfirmed', `${n} bad pins`, isConf, [good, { keys: [...PINS.keys, PINS.keys[0]] }]);
  // 0.5: ts -0 is malformed (strict profile). The signature over ts 0 also covers -0, so only the shape check can refuse it.
  // Both run with not_before-free pins so ts 0 itself is in the validity window (the control).
  const pins0 = { ...PINS, keys: PINS.keys.map((k: any) => { const { not_before: _nb, not_after: _na, ...r } = k; return r; }) };
  const z = confirm(d0, { ts: 0 });
  await O.run('isConfirmed', `${n} ts 0 (control)`, isConf, [z, pins0]);
  await O.run('isConfirmed', `${n} ts -0 (sig over 0)`, isConf, [{ ...z, review: { ...z.review, attestation: { ...z.review.attestation, ts: -0 } } }, pins0]);
  // confirmed defs into the schema space (the verb then carries the confirmation)
  try { verbs.push([`${n} confirmed`, A.toSchemaVerb(good, CORE, { attestationVerified: A.attestationVerifier({ pins: PINS, registry: CORE }) }).verb, PINS]); } catch { /* a custom trait unknown to CORE: no verb */ }
}

// ---- factsDigest / schemaVerbFloorError / schemaFloorError ------------------------------------------------------------------
const SVF = (v: any, pins: any) => A.schemaVerbFloorError(v, CORE, pins ?? undefined);
for (const [n, v, pins] of verbs.slice(0, 400)) {
  await O.run('factsDigest', n, A.factsDigest, [v]);
  await O.run('schemaVerbFloorError', n, SVF, [v, pins]);
  if (pins) await O.run('schemaVerbFloorError', `${n} no pins`, SVF, [v, null]);
}
// structural variants of a few verbs (unconfirmed top-traits verbs and the confirmed ones)
const vsel = [...verbs.filter(([n]) => n.endsWith('confirmed')), ...verbs.filter(([n]) => /^seed (max|read|uuid|exact)$/.test(n))];
for (const [n, v, pins] of vsel) {
  for (const [lab, x] of variants(v, { depth: 3, hostile: [null, '', 5, [], {}, 'read', 'write', 'reversible', 'rate_limited', 'irreversible', 'pca.bulk', ['read'], ['pay'], 4, 3] }))
    await O.run('schemaVerbFloorError', `${n} ${lab}`, SVF, [x, pins]);
  // floors exactly at / one below each component of the carried closure's floor
  const fl = A.floorOf(CORE, v.traits);
  for (const [k, dv] of [['risk', -1], ['esc', -1], ['blast_ppm', -1], ['risk', 1], ['blast_ppm', 1]] as const)
    await O.run('schemaVerbFloorError', `${n} floors.${k} ${dv > 0 ? '+' : ''}${dv}`, SVF, [{ ...v, floors: { ...v.floors, [k]: fl[k] + dv } }, pins]);
  for (const rv of ['reversible', 'rate_limited', 'irreversible']) await O.run('schemaVerbFloorError', `${n} floors.rev ${rv}`, SVF, [{ ...v, floors: { ...v.floors, rev: rv } }, pins]);
  for (const k of ['caveats', 'context', 'prules']) if (fl[k].length) await O.run('schemaVerbFloorError', `${n} floors.${k} minus one`, SVF, [{ ...v, floors: { ...v.floors, [k]: fl[k].slice(1) } }, pins]);
  for (const t of [...v.traits]) await O.run('schemaVerbFloorError', `${n} drop trait ${t}`, SVF, [{ ...v, traits: v.traits.filter((x: string) => x !== t) }, pins]);
  await O.run('schemaVerbFloorError', `${n} unknown trait`, SVF, [{ ...v, traits: [...v.traits, 'acme.nope'] }, pins]);
}
// schema documents
{
  const pick = (vs: string[]) => accepted.filter(([n]) => vs.includes(n)).map(([, d]) => d);
  const docDefs = pick(['seed read', 'seed uuid', 'seed exact']);
  const doc = A.toSchemaDoc(docDefs, CORE, { site: 'https://s.example', aud: 's.example', version: '1' });
  await O.run('schemaFloorError', 'doc', (d: any, p: any) => A.schemaFloorError(d, p ?? undefined), [doc, null]);
  const ext = regOf(CUSTOMS[1][1]);
  const doc2 = A.toSchemaDoc(docDefs, ext, { site: 'https://s.example', aud: 's.example', version: '1' });
  await O.run('schemaFloorError', 'doc custom traits', (d: any, p: any) => A.schemaFloorError(d, p ?? undefined), [doc2, null]);
  for (const [lab, x] of [
    ['digest mismatch', { ...doc, traits_digest: s(43, 'Q') }], ['no digest', { ...doc, traits_digest: undefined }], ['custom no digest', { ...doc2, traits_digest: undefined }],
    ['custom digest of core', { ...doc2, traits_digest: doc.traits_digest }], ['trait_defs empty', { ...doc, trait_defs: [] }], ['trait_defs redefine core', { ...doc2, trait_defs: [tdef('pca.bulk')] }],
    ['trait_defs below implied', { ...doc2, trait_defs: [tdef('acme.x', ['pca.money_moving'], prof())] }], ['second verb forged', { ...doc, verbs: [doc.verbs[0], { ...doc.verbs[1], traits: [] }] }],
    ['first verb not v2', { ...doc, verbs: [{ ...doc.verbs[0], floors: undefined }, doc.verbs[1]] }],
  ] as [string, any][]) await O.run('schemaFloorError', lab, (d: any, p: any) => A.schemaFloorError(d, p ?? undefined), [x, null]);
}

// ---- packRoot / packProof ---------------------------------------------------------------------------------------------------
{
  const ds = accepted.slice(0, 40).map(([, d]) => A.defDigest(d)).filter((x, i, a) => a.indexOf(x) === i);
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, ds.length]) {
    const set = ds.slice(0, n);
    await O.run('packRoot', `n${n}`, A.packRoot, [set]);
    for (const i of [0, n - 1, Math.floor(n / 2)]) await O.run('packProof', `n${n} i${i}`, A.packProof, [set, set[i]]);
  }
  await O.run('packRoot', 'reversed order', A.packRoot, [[...ds.slice(0, 5)].reverse()]);
  await O.run('packRoot', 'empty', A.packRoot, [[]]);
  await O.run('packRoot', 'dup', A.packRoot, [[ds[0], ds[1], ds[0]]]);
  await O.run('packProof', 'not in pack', A.packProof, [ds.slice(0, 3), ds[5]]);
}

// schemaVerbFloorError / schemaFloorError messages that come from a caught exception carry the reference's own exception text:
// natives compare only the `<code>:` prefix for those (marked cmp = "code").
const FIXED = /^(?:[^:]*: )?(schema_floor_forged: (not a v2 verb|floors are below|floors\.rev is below)|schema_traits_forged: |unknown_trait: unknown trait|bad_registry: |traits_digest_mismatch: )/;
for (const c of O.cases) if ((c.fn === 'schemaVerbFloorError' || c.fn === 'schemaFloorError') && typeof c.out === 'string' && !FIXED.test(c.out)) (c as any).cmp = 'code';
for (const c of O.cases) if (c.fn === 'validateDef' && typeof c.out === 'string' && c.out.startsWith('malformed def: ')) (c as any).cmp = 'code';
O.write();
