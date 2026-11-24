// k05 oracle: session histories (Java IntentHistory and every native port). TS reference: packages/pca/src/intent-history.ts.
// Extends conformance/intent-state-vectors.json with: every window kind (and malformed ones) around its edges, histories with
// junk entries (null, strings, arrays, non-object params, non-string verbs), counted events with unreadable times, sums at the
// safe-integer edge, a candidate without its key parameter for every aggregate, and the responds_within counter over hostile
// `pending:` states (JS Number() of the tail: whitespace, hex / octal / binary, exponents, Infinity) and every rendering of the
// counter (JS String(n): exponent forms, large integers).
// Writes tools/pca-audit/k05-oracles/out/k05-intenthistory.json.gz. Deterministic.
// PORTING (fn -> Java). Compare by JSON value. A reference throw: accPreState / accPost return null; the others throw.
//   inWindow(win, ti, t)                       IntentHistory.inWindow(win, ti, t)
//   accKeyOf(a, params)                        IntentHistory.accKeyOf(a, params)
//   accPreState(a, history, {params, t}, null) IntentHistory.accPreState(a, history, params, t, null)
//   accPost(a, history, {verb, params, t}, null)  IntentHistory.accPost(a, history, verb, params, t, null)
//   monitorStep(m, q, e) / monitorState(m, history)
import * as H from '../../../packages/pca/src/intent-history.ts';
import { Oracle, ser } from './lib.mjs';

const o = new Oracle('intenthistory', 'tools/pca-audit/k05-oracles/intenthistory-oracle.mts', 'TS-reference oracle for session histories: windows, keys, pre-states, post values and monitor folds.');

// ---- windows ----
const WINS: Record<string, unknown> = {
  task: { kind: 'task' }, sliding100: { kind: 'sliding', ms: 100 }, sliding0: { kind: 'sliding', ms: 0 }, slidingNoMs: { kind: 'sliding' },
  period100: { kind: 'period', ms: 100, t0: 0 }, period100at50: { kind: 'period', ms: 100, t0: 50 }, periodNoMs: { kind: 'period', t0: 0 },
  periodNoT0: { kind: 'period', ms: 100 }, other: { kind: 'other', ms: 10, t0: 0 }, noKind: { ms: 10 }, none: null,
};
const TIS: unknown[] = [0, 1, 50, 899, 900, 901, 949, 950, 999, 1000, 1001, 2000, -1, -100, 1.5, -0, '5', null, true, 2 ** 53, 2 ** 53 - 1];
const TS_: unknown[] = [1000, 950, 0, 1, 1.5, -0, '1000', 2 ** 53];
for (const [wn, w] of Object.entries(WINS)) for (const ti of TIS) for (const t of TS_)
  await o.run('inWindow', `${wn} ${ser(ti)} at ${ser(t)}`, (a: never, b: never, c: never) => H.inWindow(a, b, c), [w, ti, t]);

// ---- accumulators ----
const base = { id: 's', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
const ACCS: Record<string, Record<string, unknown>> = {
  sum: { ...base, agg: 'sum', val: 'action.params.total' }, count: { ...base, agg: 'count' }, max: { ...base, agg: 'max', val: 'action.params.total' },
  distinct: { ...base, agg: 'distinct', val: 'action.params.item' },
};
const grouped = (a: Record<string, unknown>) => ({ ...a, key: 'action.params.payee' });
for (const [n, a] of Object.entries(ACCS)) for (const p of [{}, { payee: 'p1' }, { payee: 7 }, { payee: 1.5 }, { payee: -0 }, { payee: null }, { payee: true }, { payee: ['p1'] }, { payee: '\ud800' }, { payee: '' }, null, 'x', []])
  for (const [gn, ga] of [['ungrouped', a], ['grouped', grouped(a)]] as const)
    await o.run('accKeyOf', `${n} ${gn} ${ser(p)}`, (x: never, y: never) => H.accKeyOf(x, y), [ga, p]);

const E = (verb: unknown, params: unknown, t: unknown, status: string, resource = 'r') => ({ id: `e${String(t)}`, verb, resource, params, t, status });
const HIST: Record<string, unknown[]> = {
  empty: [],
  mixed: [
    E('shop.buy', { total: 5, payee: 'p1', item: 'a' }, 100, 'committed'), E('shop.buy', { total: 9, payee: 'p1', item: 'b' }, 940, 'reserved'),
    E('shop.buy', { total: 100, payee: 'p1', item: 'z' }, 960, 'released'), E('shop.buy', { total: 1000, payee: 'p1', item: 'y' }, 970, 'reverted'),
    E('shop.other', { total: 50, payee: 'p1', item: 'x' }, 980, 'committed'), E('shop.buy', { total: 3, payee: 'p2', item: 'a' }, 990, 'committed'),
    E('shop.buy', { total: 7, payee: 7, item: 7 }, 995, 'committed'), E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 1000, 'committed'),
    E('shop.buy', { total: 4, payee: 'p1', item: 'B' }, 2000, 'committed'), E('shop.buy', { total: 1, item: 'é' }, 999, 'reserved'),
    E('shop.buy', { total: 6, payee: 'p1', item: 'c' }, 899, 'committed'), E('shop.buy', { total: 8, payee: 'p1', item: 'd' }, 900, 'committed'),
  ],
  junk: ['x', 5, [], {}, true, E(5, { total: 1000, payee: 'p1', item: 'q' }, 990, 'committed'), E('shop.buy', 'x', 990, 'released'), E(null, {}, 1.5, 'released'),
    E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 991, 'committed')],
  nullEvent: [E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 991, 'committed'), null],
  paramsNotObject: [E('shop.buy', 'x', 990, 'committed')],
  badTimeCounted: [E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 1.5, 'committed')],
  badTimeCountedStr: [E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, '990', 'reserved')],
  badTimeUncounted: [E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 1.5, 'released'), E('shop.buy', { total: 3, payee: 'p1', item: 'b' }, 990, 'committed')],
  negValue: [E('shop.buy', { total: -1, payee: 'p1', item: 1.5 }, 990, 'committed')],
  negValueUnselected: [E('shop.other', { total: -1, payee: 'p1', item: 1.5 }, 990, 'committed'), E('shop.buy', { total: 2, payee: 'p1', item: 'a' }, 991, 'committed')],
  negValueOtherKey: [E('shop.buy', { total: -1, payee: 'p2', item: 1.5 }, 990, 'committed')],
  atSafeEdge: [E('shop.buy', { total: 2 ** 53 - 2, payee: 'p1', item: 'a' }, 990, 'committed'), E('shop.buy', { total: 1, payee: 'p1', item: 'b' }, 991, 'committed')],
  overSafeEdge: [E('shop.buy', { total: 2 ** 53 - 1, payee: 'p1', item: 'a' }, 990, 'committed'), E('shop.buy', { total: 1, payee: 'p1', item: 'b' }, 991, 'committed')],
  bigButOk: [E('shop.buy', { total: 2 ** 53 - 1, payee: 'p1', item: 'a' }, 990, 'committed')],
};
const CANDS: Record<string, Record<string, unknown>> = {
  p1: { total: 2, payee: 'p1', item: 'a' }, p1new: { total: 2, payee: 'p1', item: 'n' }, p2: { total: 3, payee: 'p2', item: 'c' }, nokey: { total: 2, item: 'a' },
  badval: { total: -1, payee: 'p1', item: 1.5 }, big: { total: 2 ** 53 - 1, payee: 'p1', item: 'a' },
};
const WIN_FOR_ACC: Record<string, unknown> = { task: { kind: 'task' }, sliding100: { kind: 'sliding', ms: 100 }, period100: { kind: 'period', ms: 100, t0: 0 }, periodNoMs: { kind: 'period', t0: 0 }, other: { kind: 'other' } };
const accVariants: [string, Record<string, unknown>][] = [];
for (const [n, a] of Object.entries(ACCS)) for (const [wn, w] of Object.entries(WIN_FOR_ACC)) {
  accVariants.push([`${n} ${wn}`, { ...a, win: w }]);
  accVariants.push([`${n} ${wn} grouped`, grouped({ ...a, win: w })]);
}
for (const [n, a] of Object.entries(ACCS)) { const { win: _w, ...noWin } = a; accVariants.push([`${n} noWin`, noWin]); }
accVariants.push(['avg task', { ...base, agg: 'avg', val: 'action.params.total' }]);
for (const [an, a] of accVariants) for (const [hn, h] of Object.entries(HIST)) {
  for (const [cn, c] of Object.entries(CANDS)) for (const t of [1000, 0, 1.5])
    await o.run('accPreState', `${an} ${hn} ${cn} t=${t}`, (x: never, y: never, z: never) => H.accPreState(x, y, z), [a, h, { params: c, t }, null]);
  if (an.startsWith('avg')) continue; // the reference's post of an unknown aggregate is undefined
  for (const [cn, c] of Object.entries(CANDS)) for (const verb of ['shop.buy', 'shop.other']) for (const t of [1000, 1.5])
    await o.run('accPost', `${an} ${hn} ${cn} ${verb} t=${t}`, (x: never, y: never, z: never) => H.accPost(x, y, z), [a, h, { verb, params: c, t }, null]);
}

// ---- monitors ----
const P = { verb: 'shop.verify', resource: 'r1' };
const Q = { verb: 'shop.buy', resource: '*' };
const MON: Record<string, Record<string, unknown>> = {
  requires_prior: { id: 'm', kind: 'requires_prior', p: P }, precedes: { id: 'm', kind: 'precedes', p: P, q: Q }, never: { id: 'm', kind: 'never', p: P },
  always: { id: 'm', kind: 'always', p: P }, neverCommitted: { id: 'm', kind: 'never', p: P, status: 'committed' }, alwaysAdmitted: { id: 'm', kind: 'always', p: P, status: 'admitted' },
  weird: { id: 'm', kind: 'weird', p: P },
};
const RW = (within: number, extra: Record<string, unknown> = {}) => ({ id: 'm', kind: 'responds_within', p: P, q: Q, within, ...extra });
const EV: Record<string, unknown> = {
  verify: E('shop.verify', {}, 1, 'committed', 'r1'), verifyR2: E('shop.verify', {}, 1, 'committed', 'r2'), verifyReserved: E('shop.verify', {}, 1, 'reserved', 'r1'),
  verifyReleased: E('shop.verify', {}, 1, 'released', 'r1'), buy: E('shop.buy', {}, 1, 'committed', 'r9'), buyReserved: E('shop.buy', {}, 1, 'reserved', 'r9'),
  other: E('shop.other', {}, 1, 'committed', 'r1'), nul: null,
};
const QS = ['idle', 'met', 'unmet', 'seen', 'clean', 'ok', 'broken', 'missed', 'pending:2'];
const ms = (n: string, m: unknown, q: string, e: unknown) => o.run('monitorStep', n, (a: never, b: never, c: never) => H.monitorStep(a, b, c), [m, q, e]);
for (const [mn, m] of Object.entries(MON)) for (const q of QS) for (const [en, e] of Object.entries(EV)) await ms(`${mn} ${q} ${en}`, m, q, e);
const TAILS = ['', ' ', '0', '1', '2', '3', '5', ' 5 ', ' 5', '﻿5', ' 5', '5\n', '\t5', '0x10', '0X10', '0o7', '0b11', '0x', '0b2', '0xg', '-0x1', '00x5', '1e21', '1e400', '1e-7', '1.0000001',
  'Infinity', '+Infinity', '-Infinity', 'infinity', 'NaN', '1.5', '.5', '5.', '+5', '-5', '1_0', '1e', 'abc', '2e0', '9007199254740993', '1152921504606846977', '1e+3', '0.0000015', '1.000001'];
for (const tail of TAILS) for (const en of ['verify', 'buy', 'other', 'verifyReleased']) await ms(`rw2 pending:${ser(tail)} ${en}`, RW(2), `pending:${tail}`, EV[en]);
const WS = [0, -0, 1, 2, 5, 0.5, 0.000001, 9.99999e-7, 1e-7, 1e21, 1.5e21, 1e21 - 131072, 123e25, -5, 2 ** 60, 2 ** 53 + 2, 1.25];
for (const w of WS) for (const q of ['idle', 'pending:3', 'pending:1e30', 'pending:0.5', 'missed', 'met']) for (const en of ['verify', 'buy', 'other'])
  await ms(`rw ${ser(w)} ${q} ${en}`, RW(w), q, EV[en]);
for (const en of Object.keys(EV)) for (const q of ['idle', 'pending:2']) await ms(`rw committed-only ${q} ${en}`, RW(2, { status: 'committed' }), q, EV[en]);
const mst = (n: string, m: unknown, h: unknown) => o.run('monitorState', n, (a: never, b: never) => H.monitorState(a, b), [m, h]);
const SEQ: Record<string, unknown[]> = {
  empty: [], v: [EV.verify], vb: [EV.verify, EV.buy], vo: [EV.verify, EV.other], voo: [EV.verify, EV.other, EV.other], vooo: [EV.verify, EV.other, EV.other, EV.other],
  junk: ['x', 5, [], {}, EV.verify, EV.verifyReleased], withNull: [EV.verify, null], released: [EV.verifyReleased, EV.other], r2: [EV.verifyR2, EV.buy],
};
for (const [mn, m] of Object.entries({ ...MON, rw2: RW(2), rw1: RW(1), rwCommitted: RW(2, { status: 'committed' }) })) for (const [sn, s] of Object.entries(SEQ)) await mst(`${mn} ${sn}`, m, s);
o.write();
