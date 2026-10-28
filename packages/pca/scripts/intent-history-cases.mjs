// The session-history cases of Intent Layer v2 (spec section 2.1, packages/pca/src/intent-history.ts): the window test, the
// grouping key, the pre-state and post-value of an accumulator over a session history, and a monitor folded over it. One
// case is {fn, name, args, out} (the shape of intent-acc-cases.mjs); a function that throws on a corrupt history has
// out = {"throws": true}. Reason texts are not part of the contract.
import { MAX, ser, reparse } from './intent-acc-cases.mjs';

export function buildIntentHistoryCases(pca) {
  const cases = [];
  const names = new Set();
  const add = (fn, name, args, out) => {
    let n = `${fn}/${name}`;
    for (let i = 2; names.has(n); i++) n = `${fn}/${name}#${i}`;
    names.add(n);
    cases.push({ fn, name: n, args: reparse(args), out });
  };
  const run = (f) => {
    try {
      return f();
    } catch {
      return { throws: true };
    }
  };
  const ev = (id, t, status = 'committed', params = { total: 5 }, verb = 'shop.buy', resource = 'shop.example/r') => ({ id, verb, resource, params, t, status });

  // ---- inWindow(win, ti, t)
  {
    const wins = [['task', { kind: 'task' }], ['slide1', { kind: 'sliding', ms: 1 }], ['slide100', { kind: 'sliding', ms: 100 }], ['period100', { kind: 'period', ms: 100, t0: 0 }], ['period100-t7', { kind: 'period', ms: 100, t0: 7 }], ['period100-neg', { kind: 'period', ms: 100, t0: -30 }]];
    for (const [wn, w] of wins) {
      for (const t of [1000, 0, 107, 106]) {
        for (const d of [-1001, -101, -100, -99, -50, -7, -2, -1, 0, 1, 7, 99, 100, 101, 1000]) add('inWindow', `${wn}/t${t}/ti${d >= 0 ? '+' : ''}${d}`, [w, t + d, t], pca.inWindow(w, t + d, t));
      }
    }
    for (const bad of [1.5, MAX + 1, -0, '5', null, true, [], {}]) {
      add('inWindow', `bad-ti-${ser(bad).slice(0, 12)}`, [{ kind: 'task' }, bad, 1000], pca.inWindow({ kind: 'task' }, bad, 1000));
      add('inWindow', `bad-t-${ser(bad).slice(0, 12)}`, [{ kind: 'task' }, 1000, bad], pca.inWindow({ kind: 'task' }, 1000, bad));
    }
    add('inWindow', 'safe-bounds', [{ kind: 'task' }, MAX, MAX], pca.inWindow({ kind: 'task' }, MAX, MAX));
    add('inWindow', 'neg-times', [{ kind: 'sliding', ms: 10 }, -5, -3], pca.inWindow({ kind: 'sliding', ms: 10 }, -5, -3));
  }

  // ---- declarations
  const SUM = { id: 'spend', agg: 'sum', val: 'action.params.total', unit: 'usd', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
  const COUNT = { ...SUM, id: 'n', agg: 'count', val: undefined };
  delete COUNT.val;
  const MAXA = { ...SUM, id: 'm', agg: 'max' };
  const DIST = { ...SUM, id: 'd', agg: 'distinct', val: 'action.params.sku' };
  const KEYED = { ...SUM, id: 'k', key: 'action.params.payee' };
  const SCHEMA = { verbs: [{ verb: 'shop.buy', kind: 'write', params: { 'action.params.total': { type: 'integer', unit: 'usd', semantic: 's', sensitivity: 'free', accumulates_into: ['spend.usd'] }, 'action.params.tip': { type: 'integer', unit: 'usd', semantic: 's', sensitivity: 'free', required: false, accumulates_into: ['spend.usd'] } } }, { verb: 'shop.view', kind: 'read', params: {} }] };
  const INTO = { ...SUM, id: 'u', val: undefined, sel: { accumulates_into: 'spend.usd' } };
  delete INTO.val;
  const slide = (d, ms) => ({ ...d, win: { kind: 'sliding', ms } });
  const period = (d, ms, t0) => ({ ...d, win: { kind: 'period', ms, t0 } });

  // ---- accKeyOf(decl, params)
  for (const [n, p] of [['string', { payee: 'p1' }], ['int', { payee: 7 }], ['absent', { total: 1 }], ['null', { payee: null }], ['array', { payee: ['p'] }], ['bool', { payee: true }], ['float', { payee: 1.5 }], ['empty', { payee: '' }], ['neg-zero', { payee: -0 }], ['unicode', { payee: 'é\u{1F600}' }], ['quote', { payee: 'a"b' }], ['own-proto', JSON.parse('{"__proto__":"x"}')]]) {
    add('accKeyOf', `keyed/${n}`, [KEYED, p], run(() => pca.accKeyOf(KEYED, reparse(p))));
  }
  add('accKeyOf', 'ungrouped', [SUM, { payee: 'p1' }], pca.accKeyOf(SUM, { payee: 'p1' }));

  // ---- accPreState / accPost
  const H = (...e) => e;
  const pre = (name, d, hist, cand, schema) => add('accPreState', name, [d, hist, cand, schema ?? null], run(() => pca.accPreState(reparse(d), reparse(hist), reparse(cand), schema === undefined ? undefined : reparse(schema))));
  const post = (name, d, hist, cand, schema) => add('accPost', name, [d, hist, cand, schema ?? null], run(() => pca.accPost(reparse(d), reparse(hist), reparse(cand), schema === undefined ? undefined : reparse(schema))));
  const c0 = { params: { total: 5 }, t: 1000 };
  const cv = { verb: 'shop.buy', params: { total: 5 }, t: 1000 };
  for (const [n, d] of [['sum', SUM], ['count', COUNT], ['max', MAXA], ['distinct', DIST]]) {
    const hist = H(ev('a', 100, 'committed', { total: 5, sku: 'x' }), ev('b', 200, 'reserved', { total: 9, sku: 'y' }), ev('c', 300, 'released', { total: 100, sku: 'z' }), ev('d', 400, 'reverted', { total: 100, sku: 'w' }), ev('e', 500, 'committed', { total: 2, sku: 'x' }), ev('f', 600, 'committed', { total: 4, sku: 'q' }, 'shop.view'));
    pre(`${n}/empty`, d, [], c0);
    pre(`${n}/mixed-statuses`, d, hist, c0);
    post(`${n}/mixed-statuses`, d, hist, { ...cv, params: { total: 5, sku: 'x' } });
    post(`${n}/new-value`, d, hist, { ...cv, params: { total: 50, sku: 'n' } });
    post(`${n}/unselected-verb`, d, hist, { ...cv, verb: 'shop.view' });
    post(`${n}/empty`, d, [], { ...cv, params: { total: 7, sku: 'x' } });
  }
  // windows over the same history
  for (const [n, d] of [['slide-100', slide(SUM, 100)], ['slide-450', slide(SUM, 450)], ['period-300', period(SUM, 300, 0)], ['period-300-t7', period(SUM, 300, 7)]]) {
    const hist = H(ev('a', 100), ev('b', 200, 'reserved', { total: 7 }), ev('c', 305), ev('d', 599, 'committed', { total: 11 }), ev('e', 600, 'committed', { total: 13 }));
    for (const t of [200, 599, 600, 601, 899, 900, 1000]) pre(`${n}/t${t}`, d, hist, { params: { total: 1 }, t });
  }
  // future-stamped events always count
  pre('future-stamped-counts', slide(SUM, 10), H(ev('a', 5000, 'committed', { total: 3 }), ev('b', 1, 'committed', { total: 9 })), { params: { total: 1 }, t: 1000 });
  pre('future-stamped-released-ignored', slide(SUM, 10), H(ev('a', 5000, 'released', { total: 3 })), { params: { total: 1 }, t: 1000 });
  // keys
  {
    const hist = H(ev('a', 1, 'committed', { total: 5, payee: 'p1' }), ev('b', 2, 'committed', { total: 7, payee: 'p2' }), ev('c', 3, 'committed', { total: 11, payee: 'p1' }), ev('d', 4, 'committed', { total: 13 }));
    pre('keyed/p1', KEYED, hist, { params: { payee: 'p1' }, t: 10 });
    pre('keyed/p2', KEYED, hist, { params: { payee: 'p2' }, t: 10 });
    pre('keyed/p3', KEYED, hist, { params: { payee: 'p3' }, t: 10 });
    pre('keyed/candidate-key-missing', KEYED, hist, { params: { total: 1 }, t: 10 });
    pre('keyed/int-vs-string', KEYED, H(ev('a', 1, 'committed', { total: 5, payee: 7 }), ev('b', 2, 'committed', { total: 3, payee: '7' })), { params: { payee: 7 }, t: 10 });
    post('keyed/candidate-key-missing', KEYED, hist, { verb: 'shop.buy', params: { total: 1 }, t: 10 });
    post('keyed/p1', KEYED, hist, { verb: 'shop.buy', params: { total: 1, payee: 'p1' }, t: 10 });
    post('keyed/unselected-verb-missing-key', KEYED, hist, { verb: 'shop.view', params: {}, t: 10 });
  }
  // accumulates_into with a schema
  {
    const hist = H(ev('a', 1, 'committed', { total: 5, tip: 2 }), ev('b', 2, 'committed', { total: 7 }), ev('c', 3, 'committed', {}, 'shop.view'));
    pre('into/schema', INTO, hist, c0, SCHEMA);
    post('into/schema', INTO, hist, { verb: 'shop.buy', params: { total: 3, tip: 1 }, t: 10 }, SCHEMA);
    post('into/view-not-selected', INTO, hist, { verb: 'shop.view', params: {}, t: 10 }, SCHEMA);
    pre('into/no-schema', INTO, hist, c0);
    post('into/no-schema', INTO, hist, { verb: 'shop.buy', params: { total: 3 }, t: 10 });
  }
  // corrupt histories: fail closed
  pre('corrupt/value-missing', SUM, H(ev('a', 1, 'committed', {})), c0);
  pre('corrupt/value-negative', SUM, H(ev('a', 1, 'committed', { total: -1 })), c0);
  pre('corrupt/value-string', SUM, H(ev('a', 1, 'committed', { total: '5' })), c0);
  pre('corrupt/value-in-released-ignored', SUM, H(ev('a', 1, 'released', {})), c0);
  pre('corrupt/value-outside-window-ignored', slide(SUM, 5), H(ev('a', 1, 'committed', {})), c0);
  pre('corrupt/time-float', SUM, H(ev('a', 1.5)), c0);
  pre('corrupt/time-float-released-ignored', SUM, H(ev('a', 1.5, 'released')), c0);
  pre('corrupt/time-negzero', SUM, H(ev('a', -0)), c0);
  pre('corrupt/candidate-time-float', SUM, H(ev('a', 1)), { params: { total: 1 }, t: 1.5 });
  pre('corrupt/candidate-time-over', SUM, [], { params: { total: 1 }, t: MAX + 1 });
  pre('corrupt/sum-overflow', SUM, H(ev('a', 1, 'committed', { total: MAX }), ev('b', 2, 'committed', { total: 1 })), c0);
  pre('ok/max-no-overflow', MAXA, H(ev('a', 1, 'committed', { total: MAX }), ev('b', 2, 'committed', { total: MAX })), c0);
  pre('ok/count-many', COUNT, Array.from({ length: 50 }, (_, i) => ev(`e${i}`, i)), c0);
  post('overflow/candidate', SUM, H(ev('a', 1, 'committed', { total: MAX })), { verb: 'shop.buy', params: { total: 1 }, t: 10 });
  post('candidate-value-bad', SUM, [], { verb: 'shop.buy', params: { total: 'x' }, t: 10 });
  post('distinct/candidate-key-bad', DIST, [], { verb: 'shop.buy', params: { sku: 1.5 }, t: 10 });
  post('distinct/int-and-string-differ', DIST, H(ev('a', 1, 'committed', { sku: 7 })), { verb: 'shop.buy', params: { sku: '7' }, t: 10 });
  post('distinct/same-int', DIST, H(ev('a', 1, 'committed', { sku: 7 })), { verb: 'shop.buy', params: { sku: 7 }, t: 10 });
  pre('distinct/sorted-utf8', DIST, H(ev('a', 1, 'committed', { sku: 'b' }), ev('b', 2, 'committed', { sku: 'a' }), ev('c', 3, 'committed', { sku: '\u{1F600}' }), ev('d', 4, 'committed', { sku: '￿' }), ev('e', 5, 'committed', { sku: 7 })), c0);

  // ---- monitors
  const P = (verb, extra = {}) => ({ verb, resource: '*', ...extra });
  const WHERE = (v) => ({ where: [{ field: 'action.params.k', op: 'eq', value: v }] });
  const mons = [
    ['requires_prior', { id: 'm1', kind: 'requires_prior', p: P('shop.verify'), q: P('shop.buy') }],
    ['precedes', { id: 'm2', kind: 'precedes', p: P('shop.verify'), q: P('shop.buy') }],
    ['never', { id: 'm3', kind: 'never', p: P('shop.refund') }],
    ['never-where', { id: 'm3w', kind: 'never', p: P('shop.refund', WHERE('x')) }],
    ['always', { id: 'm4', kind: 'always', p: P('shop.*') }],
    ['always-where', { id: 'm4w', kind: 'always', p: P('shop.buy', WHERE(1)) }],
    ['responds_within-2', { id: 'm5', kind: 'responds_within', p: P('shop.buy'), q: P('shop.confirm'), within: 2 }],
    ['responds_within-1', { id: 'm5b', kind: 'responds_within', p: P('shop.buy'), q: P('shop.confirm'), within: 1 }],
    ['never-committed-only', { id: 'm6', kind: 'never', p: P('shop.refund'), status: 'committed' }],
    ['always-committed-only', { id: 'm7', kind: 'always', p: P('shop.buy'), status: 'committed' }],
  ];
  const verbs = ['shop.verify', 'shop.buy', 'shop.refund', 'shop.confirm', 'shop.view', 'other.x'];
  const mev = (verb, status = 'committed', params = {}) => ({ verb, resource: 'shop.example/r', params, status });
  for (const [n, m] of mons) {
    for (const q of [...pca.monitorStates(m), 'bogus']) for (const v of verbs) for (const st of ['reserved', 'committed', 'released', 'reverted']) {
      if (q === 'bogus' && (v !== 'shop.buy' || st !== 'committed')) continue;
      add('monitorStep', `${n}/${q}/${v}/${st}`, [m, q, mev(v, st, { k: v === 'shop.refund' ? 'x' : 1 })], run(() => pca.monitorStep(m, q, mev(v, st, { k: v === 'shop.refund' ? 'x' : 1 }))));
    }
    const histories = [
      ['empty', []],
      ['verify-buy', [mev('shop.verify'), mev('shop.buy')]],
      ['buy-verify', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.verify')]],
      ['buy-confirm', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.confirm')]],
      ['buy-x-confirm', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.view'), mev('shop.confirm')]],
      ['buy-x-x-confirm', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.view'), mev('shop.view'), mev('shop.confirm')]],
      ['buy-buy-x', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.buy', 'committed', { k: 1 }), mev('shop.view')]],
      ['buy-x-x-x', [mev('shop.buy', 'committed', { k: 1 }), mev('shop.view'), mev('shop.view'), mev('shop.view')]],
      ['refund-x', [mev('shop.refund', 'committed', { k: 'x' }), mev('shop.view')]],
      ['refund-y', [mev('shop.refund', 'committed', { k: 'y' }), mev('shop.view')]],
      ['reserved-refund', [mev('shop.refund', 'reserved', { k: 'x' })]],
      ['released-refund', [mev('shop.refund', 'released', { k: 'x' })]],
      ['reserved-buy', [mev('shop.buy', 'reserved', { k: 1 })]],
      ['buy-wrong-k', [mev('shop.buy', 'committed', { k: 2 })]],
      ['all-shop', [mev('shop.verify'), mev('shop.buy', 'committed', { k: 1 }), mev('shop.confirm')]],
      ['shop-then-other', [mev('shop.verify'), mev('other.x')]],
    ];
    for (const [hn, h] of histories) add('monitorState', `${n}/${hn}`, [m, h], run(() => pca.monitorState(m, h)));
  }
  add('monitorState', 'initial-states', [{ id: 'z', kind: 'never', p: P('x') }, []], 'clean');
  return cases;
}
