// Oracle for the Kotlin IntentAcc kill tests (KillAccTest.kt): runs the TS reference (packages/pca/src/intent-acc.ts) on
// targeted inputs (each boundary on both sides, each refusal branch) and writes the golden. Deterministic: keys are
// sha256("atlas-pca-conformance/" + label); ML-DSA signing is deterministic.
//   <tsx> tools/pca-audit/kotlin-mutate/killAcc-oracle-gen.mjs sdks/kotlin-pca/test-data/killAcc.json
// Numbers that JSON cannot spell are written as the raw lexeme (-0) via a placeholder.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const pq = (l) => { const k = mk(l); const ml = pca.mlDsa65Keygen(seed(`${l}/ml-dsa`)); return { ...k, ml, pqPk: pca.b64u(ml.publicKey) }; };
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const NEG0 = '@@NEGZERO@@';
const NOW = 1_800_000_000_000;
const MAX = Number.MAX_SAFE_INTEGER;
const D = (l) => pca.b64u(seed(`acc/${l}`));
const s = (n, ch = 'a') => ch.repeat(n);
const DEL = Symbol('del');
const w = (o, ...kv) => { const r = clone(o); for (let i = 0; i < kv.length; i += 2) { if (kv[i + 1] === DEL) delete r[kv[i]]; else r[kv[i]] = kv[i + 1]; } return r; };

const cases = [];
const names = new Set();
const push = (fn, name, input, expect) => {
  const n = `${fn}/${name}`;
  if (names.has(n)) throw new Error(`duplicate case ${n}`);
  names.add(n);
  cases.push({ fn, name: n, in: input, expect });
};
const fix = (v) => (Object.is(v, -0) ? NEG0 : v);
const deep = (v) => (Array.isArray(v) ? v.map(deep) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x)])) : fix(v));

// ---- accumulatorDeclError ----
const BASE = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const SEQ = { kind: 'sequenced', uri: 'https://atlas.example/seq', root: D('root') };
const acc = (name, a) => push('acc', name, a, pca.accumulatorDeclError(a));
acc('valid', BASE);
for (const [n, v] of [['str', 'x'], ['null', null], ['list', []], ['num', 5], ['bool', true]]) acc(`not-object-${n}`, v);
acc('unknown-member', w(BASE, 'extra', 1));
acc('unknown-member-last', { ...BASE, zz: 1 });
acc('all-members', w(BASE, 'val', 'action.params.total', 'cap', 10, 'key', 'action.params.k'));
for (const [n, v] of [['missing', DEL], ['num', 5], ['empty', ''], ['dash', 'a-b'], ['64', s(64)], ['65', s(65)], ['proto', '__proto__'], ['ctor', 'constructor'], ['prototype', 'prototype'], ['digits', 'A_9z'], ['space', 'a b'], ['null', null]])
  acc(`id-${n}`, w(BASE, 'id', v));
for (const [n, v] of [['missing', DEL], ['num', 5], ['avg', 'avg'], ['upper', 'SUM'], ['null', null]]) acc(`agg-${n}`, w(BASE, 'agg', v));
for (const [n, v] of [['null', null], ['num', 5], ['ok', 'action.params.x'], ['empty-name', 'action.params.'], ['no-prefix', 'params.x'], ['64', `action.params.${s(64)}`], ['65', `action.params.${s(65)}`], ['dash', 'action.params.a-b'], ['nested', 'action.params.a.b'], ['prefix-only', 'action.params']])
  acc(`val-${n}`, w(BASE, 'val', v));
for (const [n, v] of [['null', null], ['num', 5], ['empty', ''], ['64', s(64)], ['65', s(65)], ['dotted', 'a.b'], ['upper', 'A'], ['double-dot', 'a..b'], ['lead-dot', '.a'], ['trail-dot', 'a.'], ['digits', 'usd_9'], ['dash', 'a-b'], ['63-dots', `${s(31)}.${s(31)}`], ['65-dots', `${s(32)}.${s(32)}`]])
  acc(`unit-${n}`, w(BASE, 'unit', v));
for (const [n, v] of [['missing', DEL], ['str', 'x'], ['list', []], ['null', null], ['empty', {}]]) acc(`sel-${n}`, w(BASE, 'sel', v));
acc('sel-unknown', w(BASE, 'sel', { accumulates_into: 'spend.usd_cents', zz: 1 }));
acc('sel-unknown-first', w(BASE, 'sel', { zz: 1, accumulates_into: 'spend.usd_cents' }));
const many = (k) => Array.from({ length: k }, (_, i) => `v${i}`);
for (const [n, v] of [['empty', []], ['one', ['a']], ['two', ['a', 'b']], ['64', many(64)], ['65', many(65)], ['empty-name', ['']], ['empty-name-second', ['a', '']], ['num', [5]], ['num-second', ['a', 5]], ['str', 'a'], ['null', null], ['obj', {}]])
  acc(`verbs-${n}`, w(BASE, 'sel', { verbs: v }));
acc('verbs-and-into', w(BASE, 'sel', { verbs: ['a'], accumulates_into: 'spend.usd_cents' }));
for (const [n, v] of [['num', 5], ['upper', 'A'], ['dot', 'a.'], ['null', null], ['ok', 'x']]) acc(`into-${n}`, w(BASE, 'sel', { accumulates_into: v }));
const WAL = w(BASE, 'sel', { event: 'question' }, 'holder', { kind: 'wallet' });
for (const ev of ['intent_required', 'question', 'clarification', 'other', 5, null]) acc(`event-${String(ev)}`, w(WAL, 'sel', { event: ev }));
acc('event-and-verbs', w(WAL, 'sel', { event: 'question', verbs: ['a'] }));
acc('event-and-into', w(WAL, 'sel', { event: 'question', accumulates_into: 'x' }));
for (const agg of ['sum', 'count', 'distinct', 'max']) acc(`wallet-${agg}`, w(WAL, 'agg', agg));
acc('wallet-action-sel', w(BASE, 'holder', { kind: 'wallet' }));
acc('site-event-sel', w(BASE, 'sel', { event: 'question' }));
acc('seq-event-sel', w(BASE, 'sel', { event: 'question' }, 'holder', SEQ));
for (const [n, v] of [['missing', DEL], ['str', 'x'], ['list', []], ['null', null], ['empty', {}], ['kind-num', { kind: 5 }], ['kind-x', { kind: 'x' }],
  ['task-extra', { kind: 'task', ms: 1 }], ['sliding-ok', { kind: 'sliding', ms: 1 }], ['sliding-0', { kind: 'sliding', ms: 0 }], ['sliding-neg', { kind: 'sliding', ms: -1 }],
  ['sliding-frac', { kind: 'sliding', ms: 1.5 }], ['sliding-str', { kind: 'sliding', ms: '1' }], ['sliding-no-ms', { kind: 'sliding' }], ['sliding-extra', { kind: 'sliding', ms: 1, t0: 0 }],
  ['sliding-negzero', { kind: 'sliding', ms: -0 }], ['sliding-max', { kind: 'sliding', ms: MAX }], ['sliding-2^53', { kind: 'sliding', ms: MAX + 1 }],
  ['period-ok', { kind: 'period', ms: 1, t0: 0 }], ['period-t0-big', { kind: 'period', ms: 5, t0: 7 }], ['period-t0-neg', { kind: 'period', ms: 1, t0: -1 }], ['period-t0-frac', { kind: 'period', ms: 1, t0: 0.5 }],
  ['period-t0-negzero', { kind: 'period', ms: 1, t0: -0 }], ['period-ms-0', { kind: 'period', ms: 0, t0: 0 }], ['period-ms-frac', { kind: 'period', ms: 1.5, t0: 0 }], ['period-no-t0', { kind: 'period', ms: 1 }],
  ['period-extra', { kind: 'period', ms: 1, t0: 0, x: 1 }], ['period-ms-str', { kind: 'period', ms: '1', t0: 0 }], ['period-swap', { kind: 'period', t0: 0, x: 1 }]])
  acc(`win-${n}`, w(BASE, 'win', v));
for (const [n, v] of [['missing', DEL], ['ok', 'action.params.k'], ['num', 5], ['bad', 'x'], ['empty', '']]) acc(`key-${n}`, w(BASE, 'key', v));
for (const m of ['domain_max', 'cap'])
  for (const [n, v] of [['0', 0], ['1', 1], ['neg', -1], ['frac', 1.5], ['max', MAX], ['2^53', MAX + 1], ['null', null], ['str', '1'], ['negzero', -0]]) acc(`${m}-${n}`, w(BASE, m, v));
for (const [n, v] of [['missing', DEL], ['str', 'x'], ['list', []], ['null', null], ['empty', {}], ['kind-x', { kind: 'x' }], ['kind-num', { kind: 5 }],
  ['site-extra', { kind: 'site_local', uri: 'x' }], ['wallet-kind', { kind: 'wallet' }],
  ['seq-ok', SEQ], ['seq-unknown', w(SEQ, 'zz', 1)], ['seq-unknown-first', { zz: 1, ...SEQ }], ['seq-no-uri', w(SEQ, 'uri', DEL)], ['seq-uri-empty', w(SEQ, 'uri', '')], ['seq-uri-num', w(SEQ, 'uri', 5)],
  ['seq-root-missing', w(SEQ, 'root', DEL)], ['seq-root-short', w(SEQ, 'root', 'AAAA')], ['seq-root-num', w(SEQ, 'root', 5)],
  ['seq-alg-ed', w(SEQ, 'root_alg', 'ed25519')], ['seq-alg-ml', w(SEQ, 'root_alg', 'ml-dsa-65', 'root_pq_pk', 'AAAA')], ['seq-alg-rsa', w(SEQ, 'root_alg', 'rsa')], ['seq-alg-num', w(SEQ, 'root_alg', 5)], ['seq-alg-null', w(SEQ, 'root_alg', null)],
  ['seq-pq-ok', w(SEQ, 'root_pq_pk', 'AAAA')], ['seq-pq-bad', w(SEQ, 'root_pq_pk', '!!')], ['seq-pq-num', w(SEQ, 'root_pq_pk', 5)], ['seq-pq-empty', w(SEQ, 'root_pq_pk', '')], ['seq-pq-pad', w(SEQ, 'root_pq_pk', 'AA==')],
  ['seq-keys-ok', w(SEQ, 'keys_uri', 'https://k')], ['seq-keys-empty', w(SEQ, 'keys_uri', '')], ['seq-keys-num', w(SEQ, 'keys_uri', 5)], ['seq-keys-null', w(SEQ, 'keys_uri', null)]])
  acc(`holder-${n}`, w(BASE, 'holder', v));
// value requirements of a non-wallet accumulator
const V = (agg, sel, val) => { const a = w(BASE, 'agg', agg, 'sel', sel); if (val !== undefined) a.val = val; return a; };
for (const agg of ['sum', 'count', 'distinct', 'max']) {
  acc(`need-${agg}-verbs-noval`, V(agg, { verbs: ['a'] }));
  acc(`need-${agg}-verbs-val`, V(agg, { verbs: ['a'] }, 'action.params.x'));
  acc(`need-${agg}-into-noval`, V(agg, { accumulates_into: 'x' }));
  acc(`need-${agg}-into-val`, V(agg, { accumulates_into: 'x' }, 'action.params.x'));
  acc(`need-${agg}-seq-verbs-noval`, w(V(agg, { verbs: ['a'] }), 'holder', SEQ));
}

// ---- monitorDeclError / monitorStates ----
const MON = { id: 'm1', kind: 'requires_prior', p: { verb: 'pay' }, q: { verb: ['quote'] } };
const mon = (name, m) => push('mon', name, m, pca.monitorDeclError(m));
mon('valid', MON);
for (const [n, v] of [['str', 'x'], ['null', null], ['list', []], ['num', 1]]) mon(`not-object-${n}`, v);
mon('unknown', w(MON, 'zz', 1));
mon('all-members', w(MON, 'status', 'admitted'));
for (const [n, v] of [['missing', DEL], ['num', 5], ['empty', ''], ['dash', 'a-b'], ['64', s(64)], ['65', s(65)], ['proto', '__proto__'], ['ctor', 'constructor'], ['prototype', 'prototype']]) mon(`id-${n}`, w(MON, 'id', v));
for (const [n, v] of [['missing', DEL], ['num', 5], ['x', 'x'], ['null', null]]) mon(`kind-${n}`, w(MON, 'kind', v));
for (const k of ['requires_prior', 'precedes', 'never', 'always', 'responds_within']) {
  const base = { id: 'm1', kind: k, p: { verb: 'a' } };
  mon(`kind-${k}-noq`, base);
  mon(`kind-${k}-q`, w(base, 'q', { verb: 'b' }));
  mon(`kind-${k}-q-within`, w(base, 'q', { verb: 'b' }, 'within', 3));
  mon(`kind-${k}-within`, w(base, 'within', 3));
}
for (const [n, v] of [['missing', DEL], ['str', 'x'], ['null', null], ['list', ['a']], ['empty', {}], ['verb-str', { verb: 'a' }], ['verb-empty-list', { verb: [] }], ['verb-list', { verb: ['a', 'b'] }],
  ['verb-mixed', { verb: ['a', 5] }], ['verb-num-first', { verb: [5, 'a'] }], ['verb-num', { verb: 5 }], ['verb-null', { verb: null }], ['verb-obj', { verb: {} }], ['verb-empty-str', { verb: '' }]]) {
  mon(`p-${n}`, w(MON, 'p', v));
  if (v !== DEL) mon(`q-${n}`, w(MON, 'q', v));
}
for (const [n, v] of [['admitted', 'admitted'], ['committed', 'committed'], ['x', 'x'], ['null', null], ['num', 1]]) mon(`status-${n}`, w(MON, 'status', v));
const RW = { id: 'm1', kind: 'responds_within', p: { verb: 'a' }, q: { verb: 'b' }, within: 3 };
for (const [n, v] of [['missing', DEL], ['0', 0], ['1', 1], ['2', 2], ['63', 63], ['64', 64], ['65', 65], ['neg', -1], ['frac', 1.5], ['str', '3'], ['null', null], ['negzero', -0], ['big', MAX + 1]]) mon(`within-${n}`, w(RW, 'within', v));
const states = (name, m) => push('states', name, m, pca.monitorStates(m) ?? []);
for (const k of ['requires_prior', 'precedes', 'never', 'always', 'x']) states(k, { kind: k });
states('kind-missing', {});
states('kind-num', { kind: 5 });
for (const [n, v] of [['0', 0], ['1', 1], ['2', 2], ['3', 3], ['64', 64], ['str', '2'], ['frac', 1.5], ['missing', DEL]]) states(`rw-${n}`, w({ kind: 'responds_within', within: 0 }, 'within', v));

// ---- accSelects / distinctKey / accValueOf ----
const SCHEMA = { verbs: [
  { verb: 'air.book', params: { 'action.params.total': { type: 'integer', accumulates_into: ['spend.usd_cents'] }, 'action.params.fee': { type: 'integer', accumulates_into: ['spend.usd_cents', 'fees'] }, 'action.params.note': { type: 'string' } } },
  { verb: 'hotel.book', params: { 'action.params.amount': { type: 'number', accumulates_into: ['spend.usd_cents'] }, 'action.params.nights': { type: 'integer' } } },
  { verb: 'car.book', params: {} },
] };
const sel = (name, a, verb, schema) => push('sel', name, { a, verb, ...(schema !== undefined ? { schema } : {}) }, pca.accSelects(a, verb, schema));
const SA = (selv) => w(BASE, 'sel', selv);
sel('verbs-hit', SA({ verbs: ['x', 'air.book'] }), 'air.book');
sel('verbs-miss', SA({ verbs: ['x'] }), 'air.book');
sel('verbs-miss-schema', SA({ verbs: ['x'] }), 'air.book', SCHEMA);
sel('event', SA({ event: 'question' }), 'air.book', SCHEMA);
sel('event-and-verbs', SA({ event: 'question', verbs: ['air.book'] }), 'air.book', SCHEMA);
sel('into-no-schema', SA({ accumulates_into: 'spend.usd_cents' }), 'air.book');
sel('into-hit', SA({ accumulates_into: 'spend.usd_cents' }), 'air.book', SCHEMA);
sel('into-hit-second-unit', SA({ accumulates_into: 'fees' }), 'air.book', SCHEMA);
sel('into-other-unit', SA({ accumulates_into: 'other' }), 'air.book', SCHEMA);
sel('into-number-type', SA({ accumulates_into: 'spend.usd_cents' }), 'hotel.book', SCHEMA);
sel('into-no-params', SA({ accumulates_into: 'spend.usd_cents' }), 'car.book', SCHEMA);
sel('into-unknown-verb', SA({ accumulates_into: 'spend.usd_cents' }), 'boat.book', SCHEMA);
sel('into-verbs-miss-into-hit', SA({ verbs: ['x'], accumulates_into: 'spend.usd_cents' }), 'air.book', SCHEMA);
sel('into-schema-no-verbs', SA({ accumulates_into: 'spend.usd_cents' }), 'air.book', {});
sel('empty-sel', SA({}), 'air.book', SCHEMA);
for (const [n, v] of [['str', 'a'], ['empty', ''], ['int', 5], ['neg', -5], ['zero', 0], ['frac', 1.5], ['bool', true], ['null', null], ['list', []], ['obj', {}], ['2^53', MAX + 1], ['max', MAX], ['negzero', -0], ['unicode', 'é'], ['quote', 'a"b']])
  push('dkey', n, { x: v }, pca.distinctKey(v));
const val = (name, a, verb, params, schema) => {
  const r = pca.accValueOf(a, verb, params, schema);
  push('val', name, { a, verb, params, ...(schema !== undefined ? { schema } : {}) }, r.ok ? { reason: null, value: r.val, key: r.key ?? null } : { reason: r.reason, value: 0, key: null });
};
const VA = (agg, v, selv = { verbs: ['air.book'] }) => { const a = w(BASE, 'agg', agg, 'sel', selv); if (v !== undefined) a.val = v; return a; };
val('count', VA('count'), 'air.book', { x: -1 });
for (const [n, v] of [['str', 'a'], ['int', 5], ['neg', -5], ['frac', 1.5], ['null', null], ['bool', false], ['list', []], ['2^53', MAX + 1]]) val(`distinct-${n}`, VA('distinct', 'action.params.x'), 'air.book', { x: v });
val('distinct-missing', VA('distinct', 'action.params.x'), 'air.book', { y: 'a' });
for (const agg of ['sum', 'max'])
  for (const [n, v] of [['0', 0], ['5', 5], ['max', MAX], ['neg', -1], ['frac', 1.5], ['str', '5'], ['null', null], ['2^53', MAX + 1], ['negzero', -0]]) val(`${agg}-val-${n}`, VA(agg, 'action.params.x'), 'air.book', { x: v });
val('sum-val-missing', VA('sum', 'action.params.x'), 'air.book', { y: 5 });
const INTO = VA('sum', undefined, { accumulates_into: 'spend.usd_cents' });
val('into-no-schema', INTO, 'air.book', { total: 1 });
val('into-unknown-verb', INTO, 'boat.book', { total: 1 }, SCHEMA);
val('into-both', INTO, 'air.book', { total: 100, fee: 7 }, SCHEMA);
val('into-total-only', INTO, 'air.book', { total: 100 }, SCHEMA);
val('into-fee-only', INTO, 'air.book', { fee: 7 }, SCHEMA);
val('into-none', INTO, 'air.book', { note: 'x' }, SCHEMA);
val('into-neg', INTO, 'air.book', { total: 100, fee: -1 }, SCHEMA);
val('into-frac-first', INTO, 'air.book', { fee: 1.5, total: 1 }, SCHEMA);
val('into-null', INTO, 'air.book', { total: null }, SCHEMA);
val('into-overflow', INTO, 'air.book', { total: MAX, fee: 1 }, SCHEMA);
val('into-at-max', INTO, 'air.book', { total: MAX - 7, fee: 7 }, SCHEMA);
val('into-max-zero', INTO, 'air.book', { total: MAX, fee: 0 }, SCHEMA);
val('into-number-type', INTO, 'hotel.book', { amount: 5 }, SCHEMA);
val('into-other-unit', VA('sum', undefined, { accumulates_into: 'fees' }), 'air.book', { total: 100, fee: 7 }, SCHEMA);

// ---- pre-state / combine / preValue / arithmetic ----
for (const agg of ['sum', 'count', 'max', 'distinct', 'x']) {
  const want = agg === 'sum' || agg === 'count' || agg === 'max' ? agg : 'values';
  const pre = (n, st) => push('pre', `${agg}-${n}`, { agg, s: st }, pca.preStateError({ agg }, st));
  for (const [n, v] of [['str', 'x'], ['null', null], ['list', []], ['empty', {}]]) pre(`not-${n}`, v);
  pre('wrong-key', { zz: 0 });
  pre('extra', { [want]: want === 'values' ? [] : 0, zz: 1 });
  pre('extra-first', { zz: 1, [want]: want === 'values' ? [] : 0 });
  for (const o of ['sum', 'count', 'max', 'values']) if (o !== want) pre(`other-${o}`, { [o]: 0 });
  if (want === 'values') {
    for (const [n, v] of [['empty', []], ['one', ['a']], ['two', ['a', 'b']], ['dup', ['a', 'a']], ['dup-late', ['a', 'b', 'a']], ['num', [1]], ['num-second', ['a', 1]], ['null-el', [null]], ['str', 'a'], ['obj', {}], ['null', null], ['num-val', 0]]) pre(`values-${n}`, { values: v });
  } else {
    for (const [n, v] of [['0', 0], ['1', 1], ['max', MAX], ['2^53', MAX + 1], ['neg', -1], ['frac', 0.5], ['str', '1'], ['null', null], ['negzero', -0], ['list', []]]) pre(`n-${n}`, { [want]: v });
  }
}
const comb = (name, agg, pre, v) => {
  push('combine', name, { agg, pre, value: v.val, key: v.key ?? null }, pca.combineAcc({ agg }, pre, v));
  push('prev', name, { agg, pre }, pca.preValue({ agg }, pre));
};
for (const [n, p, v] of [['0+0', 0, 0], ['3+4', 3, 4], ['max-1+1', MAX - 1, 1], ['max+0', MAX, 0], ['max+1', MAX, 1], ['0+max', 0, MAX], ['1+max', 1, MAX], ['big', MAX - 10, 11]]) comb(`sum-${n}`, 'sum', { sum: p }, { val: v });
for (const [n, p] of [['0', 0], ['7', 7], ['max-1', MAX - 1], ['max', MAX]]) comb(`count-${n}`, 'count', { count: p }, { val: 5 });
for (const [n, p, v] of [['lt', 3, 9], ['gt', 9, 3], ['eq', 4, 4], ['0-0', 0, 0], ['max', MAX, 1], ['to-max', 1, MAX]]) comb(`max-${n}`, 'max', { max: p }, { val: v });
for (const [n, p, k] of [['new', ['"a"', '"b"'], '"c"'], ['old', ['"a"', '"b"'], '"b"'], ['first', ['"a"'], '"a"'], ['empty', [], '"a"'], ['three', ['1', '2', '3'], '4']]) comb(`distinct-${n}`, 'distinct', { values: p }, { val: 1, key: k });
const arith = (name, agg, r, v) => push('arith', name, { agg, r, value: v }, pca.receiptArithmeticOk({ agg }, r, v));
for (const agg of ['sum', 'count', 'max', 'distinct']) {
  for (const [n, pre, delta, post, v] of [
    ['ok-sum', 10, 5, 15, 5], ['post-off+', 10, 5, 16, 5], ['post-off-', 10, 5, 14, 5], ['delta-ne-val', 10, 5, 15, 4], ['delta-ne-val-hi', 10, 5, 15, 6],
    ['count-ok', 10, 1, 11, 1], ['count-ok-val9', 10, 1, 11, 9], ['count-delta0', 10, 0, 11, 0], ['count-delta2', 10, 2, 12, 2], ['count-post-pre', 10, 1, 10, 1], ['count-post+2', 10, 1, 12, 1],
    ['max-up', 3, 9, 9, 9], ['max-keep', 9, 3, 9, 3], ['max-eq', 4, 4, 4, 4], ['max-wrong-sum', 9, 3, 12, 3], ['max-wrong-low', 9, 3, 3, 3], ['max-up-off', 3, 9, 10, 9],
    ['d0', 5, 0, 5, 0], ['d1', 5, 1, 6, 1], ['d2', 5, 2, 7, 2], ['d1-off', 5, 1, 5, 1], ['d0-off', 5, 0, 6, 0], ['d1-val0', 5, 1, 6, 0], ['zero', 0, 0, 0, 0], ['zero-1', 0, 1, 1, 1]])
    arith(`${agg}-${n}`, agg, { pre, delta, post }, v);
}

// ---- receipts ----
const SEQK = mk('acc/seq-key');
const ROOT = mk('acc/seq-root');
const OTHER = mk('acc/other');
const PQK = pq('acc/pq-seq-key');
const PQROOT = pq('acc/pq-seq-root');
const SESSION = D('session');
const DRAFT = { v: 1, kind: 'pca-actn', verb: 'air.book', params: { total: 48_900 }, sig: 'x', pq_sig: 'y', threshold: { m: 1 }, intent_session: { acc: [] } };
for (const [n, p] of [['full', DRAFT], ['bare', { v: 1, verb: 'air.book' }], ['only-stripped', { sig: 'x', pq_sig: 'y', threshold: 1, intent_session: 2 }], ['empty', {}], ['sig-only', w(DRAFT, 'pq_sig', DEL, 'threshold', DEL, 'intent_session', DEL)]])
  push('resdig', n, { p }, pca.pcactnReservationDigest(p));
const RBODY = (issued = NOW - 1_000, kid = 'k1') => ({ v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'trip_spend', seq: 3, pre: 1_000, delta: 48_900, post: 49_900,
  pcactn_digest: pca.pcactnReservationDigest(DRAFT), aud: 'skyair.example', issued_at: issued, expires_at: issued + 60_000, kid, ledger: { index: 7, head: D('head') } });
const signR = (body, key = SEQK, suite) => pca.signAccReceipt(body, key.sk, suite);
const R0 = signR(RBODY());
const rshape = (name, r) => push('rshape', name, r, pca.accReceiptShapeError(r));
rshape('valid', R0);
for (const [n, v] of [['str', 'x'], ['null', null], ['list', []]]) rshape(`not-object-${n}`, v);
rshape('unknown', w(R0, 'zz', 1));
rshape('unknown-first', { zz: 1, ...R0 });
for (const [m, vals] of [
  ['v', [['0', 0], ['2', 2], ['str', '1'], ['missing', DEL]]], ['kind', [['x', 'x'], ['missing', DEL]]],
  ['session', [['short', 'AAAA'], ['num', 1], ['missing', DEL]]], ['acc', [['dash', 'a-b'], ['65', s(65)], ['64', s(64)], ['num', 1], ['empty', ''], ['missing', DEL], ['proto', '__proto__']]],
  ['seq', [['0', 0], ['1', 1], ['neg', -1], ['frac', 1.5], ['str', '1'], ['max', MAX], ['2^53', MAX + 1], ['missing', DEL]]],
  ['pre', [['0', 0], ['neg', -1], ['frac', 0.5], ['str', '1'], ['negzero', -0], ['missing', DEL]]], ['delta', [['0', 0], ['neg', -1], ['frac', 0.5], ['missing', DEL]]], ['post', [['0', 0], ['neg', -1], ['frac', 0.5], ['missing', DEL]]],
  ['pcactn_digest', [['short', 'AAAA'], ['num', 1], ['missing', DEL]]], ['aud', [['empty', ''], ['num', 1], ['missing', DEL], ['one', 'a']]],
  ['kid', [['empty', ''], ['64', s(64, 'k')], ['65', s(65, 'k')], ['chars', 'a.b:c-d_e'], ['slash', 'a/b'], ['num', 1], ['missing', DEL]]],
  ['ledger', [['missing', DEL], ['str', 'x'], ['list', []], ['empty', {}], ['extra', { index: 7, head: D('head'), x: 1 }], ['no-head', { index: 7 }], ['no-index', { head: D('head') }], ['index-neg', { index: -1, head: D('head') }],
    ['index-frac', { index: 0.5, head: D('head') }], ['index-0', { index: 0, head: D('head') }], ['head-short', { index: 7, head: 'AAAA' }], ['swap-keys', { head: D('head'), index: 7 }], ['two-wrong', { index: 7, x: D('head') }]]],
  ['signer', [['short', 'AAAA'], ['num', 1], ['missing', DEL]]],
  ['alg', [['ed', 'ed25519'], ['rsa', 'rsa'], ['num', 1], ['null', null]]],
  ['sig', [['num', 1], ['missing', DEL], ['empty', ''], ['null', null]]],
]) for (const [n, v] of vals) rshape(`${m}-${n}`, w(R0, m, v));
for (const [n, ia, ea] of [['eq', NOW, NOW], ['max-life', NOW, NOW + 900_000], ['over-life', NOW, NOW + 900_001], ['before', NOW, NOW - 1], ['zero', 0, 0], ['zero-max', 0, 900_000], ['zero-over', 0, 900_001],
  ['ia-neg', -1, 0], ['ea-neg', 0, -1], ['ia-frac', 0.5, 1], ['ea-frac', 0, 0.5], ['ia-str', '0', 0], ['ea-missing', NOW, DEL]]) rshape(`life-${n}`, w(R0, 'issued_at', ia, 'expires_at', ea));
rshape('ed-pq-pk', w(R0, 'pq_pk', 'AAAA'));
rshape('ed-pq-sig', w(R0, 'pq_sig', 'AAAA'));
rshape('ed-named-pq-pk', w(R0, 'alg', 'ed25519', 'pq_pk', 'AAAA'));
rshape('ed-named-pq-sig', w(R0, 'alg', 'ed25519', 'pq_sig', 'AAAA'));
const RPQ = signR(RBODY(NOW - 1_000, 'kpq'), PQK, { alg: 'ml-dsa-65', mlDsa: PQK.ml });
const RHY = signR(RBODY(NOW - 1_000, 'khy'), PQK, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: PQK.ml });
rshape('pq-valid', RPQ);
rshape('hybrid-valid', RHY);
rshape('pq-no-pq-pk', w(RPQ, 'pq_pk', DEL));
rshape('pq-sig-num', w(RPQ, 'sig', 5));

const flip = (b64, i = 5) => { const b = Buffer.from(b64, 'base64url'); b[i] ^= 1; return pca.b64u(new Uint8Array(b)); };
const rsig = (name, r, signer, pin) => push('rsig', name, { r, signer, ...(pin !== undefined ? { pin } : {}) }, pca.verifyAccReceiptSignature(r, signer, pin !== undefined ? { pqPins: pin } : undefined));
rsig('valid', R0, SEQK.pk);
rsig('wrong-signer', R0, OTHER.pk);
rsig('unknown-member', w(R0, 'zz', 'x'), SEQK.pk);
rsig('forged', w(R0, 'sig', flip(R0.sig)), SEQK.pk);
rsig('tampered', w(R0, 'post', 49_901), SEQK.pk);
rsig('tampered-ledger', w(R0, 'ledger', { index: 8, head: D('head') }), SEQK.pk);
rsig('tampered-kid', w(R0, 'kid', 'k2'), SEQK.pk);
rsig('alg-added', w(R0, 'alg', 'ed25519'), SEQK.pk);
rsig('signer-swapped', w(R0, 'signer', OTHER.pk), OTHER.pk);
rsig('shape-bad', w(R0, 'aud', ''), SEQK.pk);
rsig('pq-pinned', RPQ, PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('pq-unpinned', RPQ, PQK.pk);
rsig('pq-wrong-pin', RPQ, PQK.pk, { [PQK.pk]: PQROOT.pqPk });
rsig('pq-pin-other-id', RPQ, PQK.pk, { [OTHER.pk]: PQK.pqPk });
rsig('pq-tampered', w(RPQ, 'post', 49_901), PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('pq-alg-swapped', w(RPQ, 'alg', 'hybrid-ed25519-ml-dsa-65'), PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('pq-pk-swapped', w(RPQ, 'pq_pk', PQROOT.pqPk), PQK.pk, { [PQK.pk]: PQROOT.pqPk });
rsig('pq-pk-dropped', w(RPQ, 'pq_pk', DEL), PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('hy-pinned', RHY, PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('hy-forged-ed', w(RHY, 'sig', flip(RHY.sig)), PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('hy-forged-pq', w(RHY, 'pq_sig', flip(RHY.pq_sig, 100)), PQK.pk, { [PQK.pk]: PQK.pqPk });
rsig('hy-unpinned', RHY, PQK.pk);
for (const [n, r] of [['ed', R0], ['pq', RPQ], ['hy', RHY], ['ed-mod', w(R0, 'seq', 4)]]) push('rdig', n, { r }, pca.accReceiptDigest(r));

// ---- sequencer key sets ----
const entry = (kid, key, nb = 0, extra = {}) => ({ kid, pk: key.pk, not_before: nb, ...extra });
const signKS = (version, issued, keys, root = ROOT, suite) => pca.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issued, keys }, root.sk, suite);
const KS0 = signKS(1, NOW - 100, [entry('k1', SEQK)]);
const ksshape = (name, k) => push('ksshape', name, k, pca.sequencerKeySetShapeError(k));
ksshape('valid', KS0);
for (const [n, v] of [['str', 'x'], ['null', null], ['list', []]]) ksshape(`not-object-${n}`, v);
ksshape('unknown', w(KS0, 'zz', 1));
ksshape('unknown-first', { zz: 1, ...KS0 });
for (const [m, vals] of [
  ['v', [['0', 0], ['2', 2], ['str', '1'], ['missing', DEL]]], ['kind', [['x', 'x'], ['missing', DEL]]],
  ['sequencer', [['short', 'AAAA'], ['num', 1], ['missing', DEL]]],
  ['version', [['0', 0], ['1', 1], ['2', 2], ['neg', -1], ['frac', 1.5], ['str', '1'], ['max', MAX], ['2^53', MAX + 1], ['negzero', -0], ['missing', DEL]]],
  ['issued_at', [['0', 0], ['neg', -1], ['frac', 0.5], ['str', '0'], ['negzero', -0], ['missing', DEL]]],
  ['keys', [['missing', DEL], ['str', 'x'], ['obj', {}], ['empty', []], ['one', [entry('a', SEQK)]], ['256', Array.from({ length: 256 }, (_, i) => entry(`k${i}`, SEQK))], ['257', Array.from({ length: 257 }, (_, i) => entry(`k${i}`, SEQK))]]],
  ['alg', [['ed', 'ed25519'], ['rsa', 'rsa'], ['num', 1], ['null', null]]],
  ['sig', [['num', 1], ['missing', DEL], ['null', null]]],
]) for (const [n, v] of vals) ksshape(`${m}-${n}`, w(KS0, m, v));
const E = entry('k1', SEQK);
const withE = (...es) => w(KS0, 'keys', es);
for (const [n, e] of [['str', 'x'], ['null', null], ['list', []], ['unknown', w(E, 'zz', 1)], ['unknown-first', { zz: 1, ...E }], ['all-members', w(E, 'alg', 'ed25519', 'not_after', 5)],
  ['kid-missing', w(E, 'kid', DEL)], ['kid-empty', w(E, 'kid', '')], ['kid-65', w(E, 'kid', s(65))], ['kid-64', w(E, 'kid', s(64))], ['kid-num', w(E, 'kid', 1)], ['kid-slash', w(E, 'kid', 'a/b')],
  ['pk-missing', w(E, 'pk', DEL)], ['pk-short', w(E, 'pk', 'AAAA')], ['pk-num', w(E, 'pk', 1)],
  ['alg-rsa', w(E, 'alg', 'rsa')], ['alg-num', w(E, 'alg', 1)], ['alg-ml', w(E, 'alg', 'ml-dsa-65', 'pq_pk', 'AAAA')],
  ['pq-ok', w(E, 'pq_pk', 'AAAA')], ['pq-bad', w(E, 'pq_pk', '!!')], ['pq-num', w(E, 'pq_pk', 1)], ['pq-empty', w(E, 'pq_pk', '')],
  ['nb-missing', w(E, 'not_before', DEL)], ['nb-neg', w(E, 'not_before', -1)], ['nb-frac', w(E, 'not_before', 0.5)], ['nb-str', w(E, 'not_before', '0')], ['nb-negzero', w(E, 'not_before', -0)],
  ['na-eq', w(E, 'not_before', 5, 'not_after', 5)], ['na-gt', w(E, 'not_before', 5, 'not_after', 6)], ['na-lt', w(E, 'not_before', 5, 'not_after', 4)], ['na-neg', w(E, 'not_after', -1)],
  ['na-frac', w(E, 'not_after', 5.5)], ['na-null', w(E, 'not_after', null)], ['na-str', w(E, 'not_after', '5')], ['na-0', w(E, 'not_after', 0)], ['na-max', w(E, 'not_after', MAX)], ['na-2^53', w(E, 'not_after', MAX + 1)]])
  ksshape(`entry-${n}`, withE(e));
ksshape('kids-dup', withE(E, w(E, 'pk', OTHER.pk)));
ksshape('kids-distinct', withE(E, entry('k2', OTHER)));
ksshape('kids-bad-second', withE(E, w(E, 'kid', 'a/b')));
ksshape('kids-second-unknown', withE(E, w(entry('k2', OTHER), 'zz', 1)));
ksshape('kids-second-pk', withE(E, w(entry('k2', OTHER), 'pk', 'AAAA')));
ksshape('ed-pq-pk', w(KS0, 'pq_pk', 'AAAA'));
ksshape('ed-pq-sig', w(KS0, 'pq_sig', 'AAAA'));
ksshape('ed-named-pq-pk', w(KS0, 'alg', 'ed25519', 'pq_pk', 'AAAA'));
ksshape('ed-named-pq-sig', w(KS0, 'alg', 'ed25519', 'pq_sig', 'AAAA'));
const KSPQ = signKS(1, NOW - 100, [entry('kpq', PQK, 0, { alg: 'ml-dsa-65', pq_pk: PQK.pqPk })], PQROOT, { alg: 'ml-dsa-65', mlDsa: PQROOT.ml });
const KSHY = signKS(1, NOW - 100, [entry('khy', PQK, 0, { alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: PQK.pqPk })], PQROOT, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: PQROOT.ml });
ksshape('pq-valid', KSPQ);
ksshape('hy-valid', KSHY);
ksshape('pq-sig-num', w(KSPQ, 'sig', 1));

const ksv = (name, k, root, rootPqPk) => push('ksverify', name, { k, root, ...(rootPqPk !== undefined ? { rootPqPk } : {}) }, pca.verifySequencerKeySet(k, root, rootPqPk));
ksv('valid', KS0, ROOT.pk);
ksv('other-root', KS0, OTHER.pk);
ksv('other-sequencer', w(KS0, 'sequencer', OTHER.pk), OTHER.pk);
ksv('forged', w(KS0, 'sig', flip(KS0.sig, 0)), ROOT.pk);
ksv('tampered-version', w(KS0, 'version', 2), ROOT.pk);
ksv('tampered-issued', w(KS0, 'issued_at', NOW), ROOT.pk);
ksv('tampered-keys', w(KS0, 'keys', [entry('k1', OTHER)]), ROOT.pk);
ksv('shape-bad', w(KS0, 'zz', 1), ROOT.pk);
ksv('alg-added', w(KS0, 'alg', 'ed25519'), ROOT.pk);
ksv('ed-with-root-pq', KS0, ROOT.pk, PQROOT.pqPk);
ksv('pq-pinned', KSPQ, PQROOT.pk, PQROOT.pqPk);
ksv('pq-unpinned', KSPQ, PQROOT.pk);
ksv('pq-wrong-pin', KSPQ, PQROOT.pk, PQK.pqPk);
ksv('pq-tampered', w(KSPQ, 'version', 2), PQROOT.pk, PQROOT.pqPk);
ksv('pq-alg-swapped', w(KSPQ, 'alg', 'hybrid-ed25519-ml-dsa-65'), PQROOT.pk, PQROOT.pqPk);
ksv('pq-pk-swapped', w(KSPQ, 'pq_pk', PQK.pqPk), PQROOT.pk, PQK.pqPk);
ksv('pq-pk-dropped', w(KSPQ, 'pq_pk', DEL), PQROOT.pk, PQROOT.pqPk);
ksv('hy-pinned', KSHY, PQROOT.pk, PQROOT.pqPk);
ksv('hy-forged-ed', w(KSHY, 'sig', flip(KSHY.sig, 0)), PQROOT.pk, PQROOT.pqPk);
ksv('hy-unpinned', KSHY, PQROOT.pk);
for (const [n, k] of [['ed', KS0], ['pq', KSPQ], ['v2', signKS(2, NOW - 100, [E])]]) push('ksdig', n, { k }, pca.sequencerKeySetDigest(k));
for (const [n, t] of [['ok', { version: 1, digest: D('d') }], ['v2', { version: 2, digest: D('d') }], ['swapped-order', { digest: D('d'), version: 1 }], ['str', 'x'], ['null', null], ['list', []], ['num', 1],
  ['unknown', { version: 1, digest: D('d'), zz: 1 }], ['unknown-first', { zz: 1, version: 1, digest: D('d') }], ['v0', { version: 0, digest: D('d') }], ['vneg', { version: -1, digest: D('d') }], ['vfrac', { version: 1.5, digest: D('d') }],
  ['vstr', { version: '1', digest: D('d') }], ['vmissing', { digest: D('d') }], ['vnegzero', { version: -0, digest: D('d') }], ['vmax', { version: MAX, digest: D('d') }], ['v2^53', { version: MAX + 1, digest: D('d') }],
  ['dshort', { version: 1, digest: 'AAAA' }], ['dnum', { version: 1, digest: 1 }], ['dmissing', { version: 1 }], ['empty', {}]])
  push('tracked', n, { t }, pca.trackedKeySetError(t));

// ---- verifyReceiptAgainstHolder ----
const HOLDER = { kind: 'sequenced', uri: 'https://atlas.example/seq', root: ROOT.pk };
const rc = (issued, kid = 'k1', key = SEQK, mut = (b) => b, suite) => signR(mut({ ...RBODY(issued, kid) }), key, suite);
const set = (version, issued, ...es) => signKS(version, issued, es.length ? es : [entry('k1', SEQK)]);
const hold = (name, r, keySets, now, f = {}, holder = HOLDER) => {
  const res = pca.verifyReceiptAgainstHolder(r, holder, keySets, now, f);
  push('holder', name, { r, holder, keySets, now, ...(f.maxReceiptAgeMs !== undefined ? { maxR: f.maxReceiptAgeMs } : {}), ...(f.maxKeySetAgeMs !== undefined ? { maxK: f.maxKeySetAgeMs } : {}), ...(f.tracked !== undefined ? { tracked: f.tracked } : {}) }, res);
};
const RV = rc(NOW - 1_000);
const SV = [set(1, NOW - 100)];
hold('valid', RV, SV, NOW);
for (const [n, now] of [['frac', NOW + 0.5], ['2^53', MAX + 1], ['max', MAX], ['neg-max', -MAX], ['neg-2^53', -(MAX + 1)], ['negzero', -0], ['zero', 0], ['neg', -1]]) hold(`now-${n}`, RV, SV, now);
for (const [n, v] of [['0', 0], ['frac', 0.5], ['neg', -1], ['max', MAX], ['2^53', MAX + 1], ['negzero', -0], ['1000', 1_000], ['999', 999]]) {
  hold(`maxR-${n}`, RV, SV, NOW, { maxReceiptAgeMs: v });
  hold(`maxK-${n}`, RV, SV, NOW, { maxKeySetAgeMs: v });
}
hold('maxR-0-fresh', rc(NOW), SV, NOW, { maxReceiptAgeMs: 0 });
hold('maxR-0-future', rc(NOW + 1), SV, NOW, { maxReceiptAgeMs: 0 });
hold('maxK-0-fresh', RV, [set(1, NOW)], NOW, { maxKeySetAgeMs: 0 });
hold('maxK-100', RV, SV, NOW, { maxKeySetAgeMs: 100 });
hold('maxK-99', RV, SV, NOW, { maxKeySetAgeMs: 99 });
hold('keysets-not-list', RV, SV[0], NOW);
hold('keysets-empty', RV, [], NOW);
hold('receipt-shape-bad', w(RV, 'zz', 1), SV, NOW);
for (const [n, d] of [['skew-edge', 60_000], ['skew-over', 60_001], ['age-edge', -900_000], ['age-over', -900_001], ['at-now', 0]]) hold(`issued-${n}`, rc(NOW + d), SV, NOW);
hold('issued-age-edge-maxR', rc(NOW - 5_000), SV, NOW, { maxReceiptAgeMs: 5_000 });
hold('issued-age-over-maxR', rc(NOW - 5_001), SV, NOW, { maxReceiptAgeMs: 5_000 });
for (const [n, d] of [['skew-edge', 60_000], ['skew-over', 60_001], ['age-edge', -3_600_000], ['age-over', -3_600_001]]) hold(`ks-issued-${n}`, RV, [set(1, NOW + d)], NOW);
hold('ks-age-edge-maxK', RV, [set(1, NOW - 5_000)], NOW, { maxKeySetAgeMs: 5_000 });
hold('ks-age-over-maxK', RV, [set(1, NOW - 5_001)], NOW, { maxKeySetAgeMs: 5_000 });
const dg1 = pca.sequencerKeySetDigest(SV[0]);
const S3 = set(3, NOW - 100);
const dg3 = pca.sequencerKeySetDigest(S3);
for (const [n, sets, t] of [['same', SV, { version: 1, digest: dg1 }], ['same-other-digest', SV, { version: 1, digest: D('x') }], ['rollback', SV, { version: 2, digest: dg1 }], ['newer', [S3], { version: 2, digest: D('x') }],
  ['v3-eq', [S3], { version: 3, digest: dg3 }], ['v3-eq-other', [S3], { version: 3, digest: dg1 }], ['v3-rollback', [S3], { version: 4, digest: dg3 }], ['bad-tracked', SV, { version: 0, digest: dg1 }], ['bad-tracked-digest', SV, { version: 1, digest: 'AAAA' }],
  ['bad-tracked-extra', SV, { version: 1, digest: dg1, x: 1 }], ['rollback-then-ok', [SV[0], S3], { version: 3, digest: dg3 }], ['equiv-then-ok', [set(3, NOW - 50), S3], { version: 3, digest: dg3 }]])
  hold(`tracked-${n}`, RV, sets, NOW, { tracked: t });
hold('set-wrong-root', RV, [signKS(1, NOW - 100, [entry('k1', SEQK)], OTHER)], NOW);
hold('set-forged', RV, [w(SV[0], 'sig', flip(SV[0].sig, 0))], NOW);
hold('set-bad-then-good', RV, ['x', w(SV[0], 'sig', flip(SV[0].sig, 0)), SV[0]], NOW);
hold('kid-missing', RV, [set(1, NOW - 100, entry('k2', SEQK))], NOW);
hold('kid-second', RV, [set(1, NOW - 100, entry('k0', OTHER), entry('k1', SEQK))], NOW);
hold('pk-mismatch', RV, [set(1, NOW - 100, entry('k1', OTHER))], NOW);
hold('pk-mismatch-then-ok', RV, [set(1, NOW - 100, entry('k1', OTHER)), SV[0]], NOW);
for (const [n, nb] of [['eq', NOW - 1_000], ['after', NOW - 999], ['before', NOW - 1_001], ['zero', 0]]) hold(`nb-${n}`, RV, [set(1, NOW - 100, entry('k1', SEQK, nb))], NOW);
for (const [n, na] of [['issued', NOW - 1_000], ['before-issued', NOW - 1_001], ['future', NOW + 10], ['retired-edge', NOW - 60_000], ['retired-over', NOW - 60_001]]) {
  const r = rc(Math.min(NOW - 1_000, na));
  hold(`na-${n}`, r, [set(1, NOW - 100, entry('k1', SEQK, 0, { not_after: na }))], NOW);
}
hold('na-retired-edge-issued-eq', rc(NOW - 60_000), [set(1, NOW - 100, entry('k1', SEQK, 0, { not_after: NOW - 60_000 }))], NOW);
hold('na-retired-over-issued-eq', rc(NOW - 60_001), [set(1, NOW - 100, entry('k1', SEQK, 0, { not_after: NOW - 60_001 }))], NOW);
hold('entry-alg-ed', RV, [set(1, NOW - 100, entry('k1', SEQK, 0, { alg: 'ed25519' }))], NOW);
hold('entry-alg-ml-receipt-ed', RV, [set(1, NOW - 100, entry('k1', SEQK, 0, { alg: 'ml-dsa-65', pq_pk: PQK.pqPk }))], NOW);
hold('receipt-alg-ed-named', rc(NOW - 1_000, 'k1', SEQK, (b) => b, { alg: 'ed25519' }), SV, NOW);
const RPQH = rc(NOW - 1_000, 'kpq', PQK, (b) => b, { alg: 'ml-dsa-65', mlDsa: PQK.ml });
const RHYH = rc(NOW - 1_000, 'khy', PQK, (b) => b, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: PQK.ml });
const PQHOLDER = { kind: 'sequenced', uri: 'https://atlas.example/seq', root: PQROOT.pk, root_alg: 'ml-dsa-65', root_pq_pk: PQROOT.pqPk };
const pqSet = (es) => signKS(1, NOW - 100, es, PQROOT, { alg: 'ml-dsa-65', mlDsa: PQROOT.ml });
const PQS = pqSet([entry('kpq', PQK, 0, { alg: 'ml-dsa-65', pq_pk: PQK.pqPk }), entry('khy', PQK, 0, { alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: PQK.pqPk }), entry('ked', PQK), entry('knopq', PQK, 0, { alg: 'ml-dsa-65' })]);
hold('pq-valid', RPQH, [PQS], NOW, {}, PQHOLDER);
hold('pq-hybrid-valid', RHYH, [PQS], NOW, {}, PQHOLDER);
hold('pq-holder-unpinned', RPQH, [PQS], NOW, {}, w(PQHOLDER, 'root_pq_pk', DEL));
hold('pq-holder-wrong-pin', RPQH, [PQS], NOW, {}, w(PQHOLDER, 'root_pq_pk', PQK.pqPk));
hold('pq-suite-mismatch', rc(NOW - 1_000, 'kpq', PQK, (b) => b, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: PQK.ml }), [PQS], NOW, {}, PQHOLDER);
hold('pq-ed-entry-ed-receipt', rc(NOW - 1_000, 'ked', PQK), [PQS], NOW, {}, PQHOLDER);
hold('pq-ed-entry-pq-receipt', rc(NOW - 1_000, 'ked', PQK, (b) => b, { alg: 'ml-dsa-65', mlDsa: PQK.ml }), [PQS], NOW, {}, PQHOLDER);
hold('pq-entry-no-pq-pk', rc(NOW - 1_000, 'knopq', PQK, (b) => b, { alg: 'ml-dsa-65', mlDsa: PQK.ml }), [PQS], NOW, {}, PQHOLDER);
hold('pq-receipt-forged', w(RPQH, 'sig', flip(RPQH.sig, 100)), [PQS], NOW, {}, PQHOLDER);
hold('pq-receipt-other-pq-pk', rc(NOW - 1_000, 'kpq', PQK, (b) => b, { alg: 'ml-dsa-65', mlDsa: PQROOT.ml }), [PQS], NOW, {}, PQHOLDER);
hold('pq-set-on-ed-holder', RPQH, [PQS], NOW, {}, w(PQHOLDER, 'root_alg', DEL, 'root_pq_pk', DEL));

const text = JSON.stringify({ generator: 'tools/pca-audit/kotlin-mutate/killAcc-oracle-gen.mjs', oracle: 'packages/pca/src/intent-acc.ts', now: NOW, cases: deep(cases) }, null, 0)
  .replaceAll(`"${NEG0}"`, '-0');
fs.writeFileSync(process.argv[2], text + '\n');
console.log(`${cases.length} cases -> ${process.argv[2]}`);
