// The accumulator / monitor / sequencer-receipt cases of Intent Layer v2 rule 15, built from the TypeScript reference
// (packages/pca/src/intent-acc.ts). One case is {fn, name, args, out}; `out` is what the reference returns for `args`.
// Used by gen-conformance-intent-state.mjs (the conformance corpus file intent-state-vectors.json) and by the native
// differential oracle (tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs). PQ keys and signatures are deterministic.
import { createHash } from 'node:crypto';

export const NOW = 1_800_000_000_000;
export const MAX = Number.MAX_SAFE_INTEGER;
export const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
// JSON text with -0 kept (JSON.stringify prints -0 as 0)
export function ser(v) {
  if (typeof v === 'number') {
    if (Object.is(v, -0)) return '-0';
    if (!Number.isFinite(v)) throw new Error('non-finite');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (v !== null && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
// JSON.parse keeps -0 for the literal "-0"
export const reparse = (x) => JSON.parse(ser(x));
const DEL = Symbol('del');

export function buildIntentAccCases(pca) {
  const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
  const D = (l) => pca.b64u(seed(l));
  const clone = (x) => (x === undefined ? undefined : JSON.parse(ser(x)));
  const cases = [];
  const names = new Set();
  function add(fn, name, args, out) {
    let n = `${fn}/${name}`;
    for (let i = 2; names.has(n); i++) n = `${fn}/${name}#${i}`;
    names.add(n);
    cases.push({ fn, name: n, args, out });
  }
  const set = (o, path, v) => {
    const r = reparse(o);
    const ks = path.split('/');
    let cur = r;
    for (const k of ks.slice(0, -1)) cur = cur[k];
    const last = ks[ks.length - 1];
    if (v === DEL) delete cur[last];
    else cur[last] = v;
    return r;
  };
  const PALETTE = [null, true, false, 0, 1, -1, -0, 1.5, 2, '', 'x', [], {}, ['x'], MAX, MAX + 1, 64, 65, '1'];
  const nm = (v) => (v === DEL ? 'DEL' : ser(v).slice(0, 40));

  // ---------------------------------------------------------------- validators (string | null)
  function vcase(fn, f, name, arg) {
    const a = reparse(arg);
    add(fn, name, [a], f(reparse(a)));
  }
  function perturb(fn, f, base, path, vals) {
    for (const v of vals) vcase(fn, f, `${path}=${nm(v)}`, set(base, path, v));
  }

  // ---- accumulatorDeclError
  {
    const F = pca.accumulatorDeclError;
    const fn = 'accumulatorDeclError';
    const A = { id: 'trip', agg: 'sum', val: 'action.params.total', unit: 'usd_cents', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 5, cap: 5, holder: { kind: 'site_local' } };
    vcase(fn, F, 'base', A);
    for (const x of [null, 1, 'x', [], [A]]) vcase(fn, F, `top=${nm(x)}`, x);
    vcase(fn, F, 'unknown-member', { ...A, extra: 1 });
    vcase(fn, F, 'unknown-member-first', { zz: 1, ...A });
    for (const k of Object.keys(A)) perturb(fn, F, A, k, [DEL, ...PALETTE]);
    perturb(fn, F, A, 'id', ['a', 'A_9', 'k'.repeat(64), 'k'.repeat(65), 'a-b', 'a b', '__proto__', 'constructor', 'prototype', 'proto', 'x__proto__']);
    perturb(fn, F, A, 'agg', ['sum', 'count', 'distinct', 'max', 'min', 'SUM']);
    perturb(fn, F, A, 'val', ['action.params.x', 'action.params.' + 'p'.repeat(64), 'action.params.' + 'p'.repeat(65), 'action.params.', 'action.params.a.b', 'params.x', 'action.params.a-b']);
    perturb(fn, F, A, 'unit', ['a', 'a.b', 'a.b.c', 'a_1.b2', 'A', 'a..b', '.a', 'a.', 'a-b', 'u'.repeat(64), 'u'.repeat(65), 'a.' + 'u'.repeat(62), 'a.' + 'u'.repeat(63)]);
    perturb(fn, F, A, 'sel', [{ verbs: ['a'], zz: 1 }, { verbs: ['a'], accumulates_into: 'x.y' }, { accumulates_into: 'x.y' }, { accumulates_into: 'X' }, { accumulates_into: 1 }, { accumulates_into: '' },
      { verbs: [] }, { verbs: [''] }, { verbs: ['a', ''] }, { verbs: ['a', 1] }, { verbs: 'a' }, { verbs: null }, { verbs: Array.from({ length: 64 }, (_, i) => 'v' + i) }, { verbs: Array.from({ length: 65 }, (_, i) => 'v' + i) },
      { event: 'intent_required' }, { event: 'question' }, { event: 'clarification' }, { event: 'other' }, { event: null }, { verbs: ['a'], event: 'question' }, { accumulates_into: 'x', event: 'question' }, {}]);
    // sel.event: wallet-held
    const W = { ...A, agg: 'count', sel: { event: 'question' }, holder: { kind: 'wallet' } };
    delete W.val;
    vcase(fn, F, 'wallet-event-count', W);
    vcase(fn, F, 'wallet-event-sum-noval', { ...W, agg: 'sum' });
    vcase(fn, F, 'wallet-event-max-noval', { ...W, agg: 'max' });
    vcase(fn, F, 'wallet-event-count-val', { ...W, val: 'action.params.x' });
    vcase(fn, F, 'wallet-event-sitelocal', { ...W, holder: { kind: 'site_local' } });
    vcase(fn, F, 'wallet-verbs', { ...A, holder: { kind: 'wallet' } });
    vcase(fn, F, 'wallet-extra', { ...W, holder: { kind: 'wallet', x: 1 } });
    perturb(fn, F, A, 'win', [{ kind: 'task', x: 1 }, { kind: 'sliding', ms: 1 }, { kind: 'sliding', ms: 0 }, { kind: 'sliding', ms: -1 }, { kind: 'sliding', ms: 1.5 }, { kind: 'sliding', ms: -0 }, { kind: 'sliding', ms: MAX }, { kind: 'sliding', ms: MAX + 1 },
      { kind: 'sliding' }, { kind: 'sliding', ms: 5, x: 1 }, { kind: 'sliding', t0: 5 }, { kind: 'sliding', ms: '5' },
      { kind: 'period', ms: 1, t0: 0 }, { kind: 'period', ms: 0, t0: 0 }, { kind: 'period', ms: 1, t0: -1 }, { kind: 'period', ms: 1, t0: -0 }, { kind: 'period', ms: 1, t0: 1.5 }, { kind: 'period', ms: 1.5, t0: 0 }, { kind: 'period', ms: 1 }, { kind: 'period', ms: 1, x: 0 }, { kind: 'period', ms: 1, t0: 0, x: 1 }, { kind: 'period', t0: 0, x: 1 },
      { kind: 'other' }, { kind: null }, {}, { ms: 5 }]);
    perturb(fn, F, A, 'key', ['action.params.x', 'x', 'action.params.', 'action.params.a.b']);
    perturb(fn, F, A, 'domain_max', [0, MAX, -1, -0, 1.5, MAX + 1, '1']);
    perturb(fn, F, A, 'cap', [0, MAX, -1, -0, 1.5, MAX + 1, '1']);
    const ROOT = mk('k042/root').pk;
    const SQ = { kind: 'sequenced', uri: 'https://seq.example', root: ROOT };
    perturb(fn, F, A, 'holder', [{ kind: 'site_local', x: 1 }, { kind: 'other' }, { kind: null }, {}, { kind: 'wallet' }, SQ, { ...SQ, root_alg: 'ed25519' }, { ...SQ, root_alg: 'ml-dsa-65', root_pq_pk: 'AAAA' }, { ...SQ, root_alg: 'x-unknown' }, { ...SQ, root_alg: 5 }, { ...SQ, root_alg: null },
      { ...SQ, root_pq_pk: 'AA=' }, { ...SQ, root_pq_pk: 5 }, { ...SQ, root_pq_pk: '' }, { ...SQ, keys_uri: 'https://k' }, { ...SQ, keys_uri: '' }, { ...SQ, keys_uri: 5 }, { ...SQ, keys_uri: null }, { ...SQ, x: 1 },
      { ...SQ, uri: '' }, { ...SQ, uri: 5 }, { kind: 'sequenced', root: ROOT }, { ...SQ, root: 'AAAA' }, { ...SQ, root: ROOT + 'A' }, { ...SQ, root: 5 }, { kind: 'sequenced', uri: 'u' }]);
    // agg / val / accumulates_into combinations (non-wallet)
    const NV = { ...A };
    delete NV.val;
    for (const agg of ['sum', 'count', 'distinct', 'max']) {
      vcase(fn, F, `combo-${agg}-val`, { ...A, agg });
      vcase(fn, F, `combo-${agg}-noval-verbs`, { ...NV, agg });
      vcase(fn, F, `combo-${agg}-noval-into`, { ...NV, agg, sel: { accumulates_into: 'spend.usd' } });
      vcase(fn, F, `combo-${agg}-val-into`, { ...A, agg, sel: { accumulates_into: 'spend.usd' } });
      vcase(fn, F, `combo-${agg}-noval-both`, { ...NV, agg, sel: { verbs: ['a'], accumulates_into: 'spend.usd' } });
    }
  }

  // ---- monitorDeclError
  {
    const F = pca.monitorDeclError;
    const fn = 'monitorDeclError';
    const M = { id: 'm1', kind: 'responds_within', p: { verb: 'a' }, q: { verb: ['b', 'c'] }, status: 'admitted', within: 3 };
    vcase(fn, F, 'base', M);
    for (const x of [null, 1, 'x', [], [M]]) vcase(fn, F, `top=${nm(x)}`, x);
    vcase(fn, F, 'unknown-member', { ...M, extra: 1 });
    for (const k of Object.keys(M)) perturb(fn, F, M, k, [DEL, ...PALETTE]);
    perturb(fn, F, M, 'id', ['a', 'k'.repeat(64), 'k'.repeat(65), 'a-b', '__proto__', 'constructor', 'prototype']);
    perturb(fn, F, M, 'status', ['committed', 'Admitted']);
    perturb(fn, F, M, 'within', [1, 63, 64, 65, 0, -1, -0, 1.5]);
    perturb(fn, F, M, 'p', [{ verb: [] }, { verb: ['a', 1] }, { verb: [1] }, { verb: 1 }, { verb: null }, { verb: ['a'] }, {}, { x: 'a' }]);
    perturb(fn, F, M, 'q', [{ verb: [] }, { verb: ['a', 1] }, { verb: 1 }, { verb: ['a'] }, {}]);
    for (const kind of ['requires_prior', 'precedes', 'never', 'always', 'responds_within', 'other']) {
      vcase(fn, F, `kind-${kind}-q-within`, { ...M, kind });
      const nq = { ...M, kind }; delete nq.q;
      vcase(fn, F, `kind-${kind}-noq-within`, nq);
      const nw = { ...M, kind }; delete nw.within;
      vcase(fn, F, `kind-${kind}-q-nowithin`, nw);
      const nn = { ...nq }; delete nn.within;
      vcase(fn, F, `kind-${kind}-noq-nowithin`, nn);
      vcase(fn, F, `kind-${kind}-badq-nowithin`, { ...nw, q: { verb: [] } });
    }
  }

  // ---- monitorStates (list of strings)
  for (const [name, m] of [['rp', { kind: 'requires_prior' }], ['pr', { kind: 'precedes' }], ['nv', { kind: 'never' }], ['al', { kind: 'always' }],
    ['rw0', { kind: 'responds_within', within: 0 }], ['rw1', { kind: 'responds_within', within: 1 }], ['rw3', { kind: 'responds_within', within: 3 }], ['rw-str', { kind: 'responds_within', within: '3' }],
    ['rw-frac', { kind: 'responds_within', within: 1.5 }], ['rw-abs', { kind: 'responds_within' }]]) add('monitorStates', name, [m], pca.monitorStates(reparse(m)));

  // ---- trackedKeySetError
  {
    const F = pca.trackedKeySetError;
    const T = { version: 2, digest: D('k042/dig') };
    vcase('trackedKeySetError', F, 'base', T);
    for (const x of [null, 1, 'x', []]) vcase('trackedKeySetError', F, `top=${nm(x)}`, x);
    vcase('trackedKeySetError', F, 'extra', { ...T, x: 1 });
    vcase('trackedKeySetError', F, 'extra-first', { x: 1, ...T });
    perturb('trackedKeySetError', F, T, 'version', [DEL, 1, 0, -1, -0, 1.5, MAX, MAX + 1, '2', null]);
    perturb('trackedKeySetError', F, T, 'digest', [DEL, 'AAAA', D('a') + 'A', 5, null]);
  }

  // ---- preStateError / combineAcc / preValue
  {
    const fn = 'preStateError';
    for (const agg of ['sum', 'count', 'max', 'distinct', 'other']) {
      const want = agg === 'sum' ? 'sum' : agg === 'count' ? 'count' : agg === 'max' ? 'max' : 'values';
      const vals = want === 'values' ? [[], ['a'], ['a', 'b'], ['a', 'a'], ['a', 1], [1], 'a', null, {}] : [0, 5, MAX, MAX + 1, -1, -0, 1.5, '5', null];
      for (const v of vals) { const s = { [want]: v }; add(fn, `${agg}-${nm(v)}`, [agg, s], pca.preStateError({ agg }, reparse(s))); }
      add(fn, `${agg}-extra`, [agg, { [want]: want === 'values' ? [] : 1, x: 1 }], pca.preStateError({ agg }, { [want]: want === 'values' ? [] : 1, x: 1 }));
      add(fn, `${agg}-empty`, [agg, {}], pca.preStateError({ agg }, {}));
      add(fn, `${agg}-wrongkey`, [agg, { zz: 1 }], pca.preStateError({ agg }, { zz: 1 }));
      for (const x of [null, 1, [], 'x']) add(fn, `${agg}-top-${nm(x)}`, [agg, x], pca.preStateError({ agg }, x));
    }
    const cfn = 'combineAcc';
    const C = (name, agg, pre, v) => add(cfn, name, [agg, pre, v], pca.combineAcc({ agg }, reparse(pre), reparse(v)));
    C('sum', 'sum', { sum: 5 }, { val: 3 });
    C('sum-max', 'sum', { sum: MAX - 1 }, { val: 1 });
    C('sum-over', 'sum', { sum: MAX }, { val: 1 });
    C('sum-0', 'sum', { sum: 0 }, { val: 0 });
    C('count', 'count', { count: 5 }, { val: 7 });
    C('count-max', 'count', { count: MAX - 1 }, { val: 1 });
    C('count-over', 'count', { count: MAX }, { val: 1 });
    C('max-pre', 'max', { max: 5 }, { val: 3 });
    C('max-val', 'max', { max: 3 }, { val: 5 });
    C('max-eq', 'max', { max: 4 }, { val: 4 });
    C('max-big', 'max', { max: MAX }, { val: 1 });
    C('distinct-new', 'distinct', { values: ['"a"', '"b"'] }, { val: 1, key: '"c"' });
    C('distinct-old', 'distinct', { values: ['"a"', '"b"'] }, { val: 1, key: '"b"' });
    C('distinct-empty', 'distinct', { values: [] }, { val: 1, key: '1' });
    const pfn = 'preValue';
    for (const [agg, pre] of [['sum', { sum: 7 }], ['count', { count: 8 }], ['max', { max: 9 }], ['distinct', { values: ['a', 'b', 'c'] }], ['sum', { sum: MAX }], ['count', { count: 0 }]])
      add(pfn, `${agg}-${ser(pre)}`, [agg, pre], pca.preValue({ agg }, pre));
  }

  // ---- accSelects / accValueOf (on well-formed declarations)
  {
    const SCHEMA = { verbs: [
      { verb: 'air.book', params: { 'action.params.total': { type: 'integer', accumulates_into: ['spend.usd'] }, 'action.params.fee': { type: 'integer', accumulates_into: ['spend.usd', 'other'] }, 'action.params.note': { type: 'string', accumulates_into: ['spend.usd'] }, 'action.params.miles': { type: 'integer', accumulates_into: ['miles'] }, 'action.params.zz': { type: 'integer' } } },
      { verb: 'air.cancel', params: { 'action.params.total': { type: 'integer' } } },
      { verb: 'air.str', params: { 'action.params.total': { type: 'string', accumulates_into: ['spend.usd'] } } },
    ] };
    const base = { id: 'a', agg: 'sum', win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
    const sel = (name, a, verb, schema) => add('accSelects', name, [a, verb, schema ?? null], pca.accSelects(reparse(a), verb, schema === undefined ? undefined : reparse(schema)));
    const V = { ...base, val: 'action.params.total', sel: { verbs: ['air.book', 'x'] } };
    const I = { ...base, sel: { accumulates_into: 'spend.usd' } };
    const VI = { ...base, sel: { verbs: ['x'], accumulates_into: 'spend.usd' } };
    const E = { ...base, agg: 'count', sel: { event: 'question' }, holder: { kind: 'wallet' } };
    for (const verb of ['air.book', 'x', 'air.cancel', 'air.str', 'nope']) {
      for (const [sn, s] of [['none', undefined], ['schema', SCHEMA], ['noverbs', {}]]) {
        sel(`V-${verb}-${sn}`, V, verb, s);
        sel(`I-${verb}-${sn}`, I, verb, s);
        sel(`VI-${verb}-${sn}`, VI, verb, s);
        sel(`E-${verb}-${sn}`, E, verb, s);
      }
    }
    sel('I-miles', { ...base, sel: { accumulates_into: 'miles' } }, 'air.book', SCHEMA);
    sel('I-other', { ...base, sel: { accumulates_into: 'other' } }, 'air.book', SCHEMA);
    sel('I-unknown-unit', { ...base, sel: { accumulates_into: 'nothing' } }, 'air.book', SCHEMA);
    // a verb whose parameter lists a null unit: only an accumulates_into selector may consult the schema
    const NULLS = { verbs: [{ verb: 'air.null', params: { 'action.params.total': { type: 'integer', accumulates_into: [null] } } }] };
    sel('V-null-unit', V, 'air.null', NULLS);
    sel('E-null-unit', E, 'air.null', NULLS);
    sel('E-with-verbs-listed', { ...E, sel: { event: 'question', verbs: ['air.book'] } }, 'air.book', SCHEMA);

    const val = (name, a, verb, params, schema) => {
      const r = pca.accValueOf(reparse(a), verb, reparse(params), schema === undefined ? undefined : reparse(schema));
      add('accValueOf', name, [a, verb, params, schema ?? null], r.ok ? { ok: true, val: r.val, key: r.key ?? null } : { ok: false, reason: r.reason });
    };
    const P = (x) => ({ 'total': x, 'fee': 2 });
    for (const [agg, vpath] of [['count', undefined], ['distinct', 'action.params.total'], ['sum', 'action.params.total'], ['max', 'action.params.total']]) {
      const a = { ...base, agg, sel: { verbs: ['air.book'] } };
      if (vpath) a.val = vpath;
      for (const x of [0, 7, MAX, MAX + 1, -1, -0, 1.5, 'abc', '', null, true, [], {}, ['a']]) val(`${agg}-${nm(x)}`, a, 'air.book', P(x), SCHEMA);
      val(`${agg}-absent`, a, 'air.book', { fee: 2 }, SCHEMA);
      val(`${agg}-empty`, a, 'air.book', {}, undefined);
    }
    val('distinct-lone-surrogate', { ...base, agg: 'distinct', val: 'action.params.total', sel: { verbs: ['air.book'] } }, 'air.book', { total: '\ud800' }, undefined);
    val('distinct-unicode', { ...base, agg: 'distinct', val: 'action.params.total', sel: { verbs: ['air.book'] } }, 'air.book', { total: 'é"\\' }, undefined);
    const sumI = { ...base, sel: { accumulates_into: 'spend.usd' } };
    val('into-no-schema', sumI, 'air.book', { total: 1 }, undefined);
    val('into-no-verb', sumI, 'nope', { total: 1 }, SCHEMA);
    val('into-noverbs-doc', sumI, 'air.book', { total: 1 }, {});
    val('into-both', sumI, 'air.book', { total: 5, fee: 2, note: 'x', miles: 100, zz: 9 }, SCHEMA);
    val('into-total-only', sumI, 'air.book', { total: 5 }, SCHEMA);
    val('into-fee-only', sumI, 'air.book', { fee: 3 }, SCHEMA);
    val('into-none', sumI, 'air.book', {}, SCHEMA);
    val('into-null', sumI, 'air.book', { total: null, fee: 3 }, SCHEMA);
    val('into-neg-fee', sumI, 'air.book', { total: 1, fee: -1 }, SCHEMA);
    val('into-frac-total', sumI, 'air.book', { total: 1.5, fee: 1 }, SCHEMA);
    val('into-negzero', sumI, 'air.book', { total: -0 }, SCHEMA);
    val('into-max-exact', sumI, 'air.book', { total: MAX - 2, fee: 2 }, SCHEMA);
    val('into-max-over', sumI, 'air.book', { total: MAX - 2, fee: 3 }, SCHEMA);
    val('into-max-each', sumI, 'air.book', { total: MAX, fee: MAX }, SCHEMA);
    val('into-max-fee', sumI, 'air.book', { fee: MAX }, SCHEMA);
    val('into-cancel', sumI, 'air.cancel', { total: 5 }, SCHEMA);
    val('into-str', sumI, 'air.str', { total: 5 }, SCHEMA);
    val('into-miles', { ...base, sel: { accumulates_into: 'miles' } }, 'air.book', { total: 5, miles: 9 }, SCHEMA);
    val('into-verbs-also', { ...base, sel: { verbs: ['air.book'], accumulates_into: 'spend.usd' } }, 'air.book', { total: 4, fee: 4 }, SCHEMA);
  }

  // ---- receiptArithmeticOk
  for (const agg of ['sum', 'count', 'max', 'distinct']) {
    for (const [pre, delta, post, v] of [[5, 3, 8, 3], [5, 3, 8, 4], [5, 3, 9, 3], [5, 3, 7, 3], [5, 1, 6, 1], [5, 1, 6, 2], [5, 1, 7, 1], [5, 0, 5, 0], [5, 0, 5, 1], [5, 2, 7, 2], [5, 3, 5, 3], [3, 5, 5, 5], [3, 5, 8, 5], [3, 5, 5, 4], [4, 4, 4, 4], [5, 1, 5, 1], [0, 0, 0, 0], [0, 0, 1, 0]]) {
      const r = { pre, delta, post };
      add('receiptArithmeticOk', `${agg}-${pre}-${delta}-${post}-${v}`, [agg, r, v], pca.receiptArithmeticOk({ agg }, r, v));
    }
  }

  // ---- pcactnReservationDigest / receiptDigest / keySetDigest
  {
    const P = { v: 1, verb: 'air.book', params: { total: 5 }, sig: 's', pq_sig: 'q', threshold: { t: 1 }, intent_session: { x: 1 }, nonce: 'n' };
    add('pcactnReservationDigest', 'full', [P], pca.pcactnReservationDigest(reparse(P)));
    for (const k of Object.keys(P)) { const p = reparse(P); delete p[k]; add('pcactnReservationDigest', `no-${k}`, [p], pca.pcactnReservationDigest(reparse(p))); }
    add('pcactnReservationDigest', 'bare', [{ v: 1 }], pca.pcactnReservationDigest({ v: 1 }));
  }

  // ---------------------------------------------------------------- receipts and key sets (signed)
  const ROOT = mk('k042/seq-root');
  const SEQ = mk('k042/sequencer');
  const SEQ2 = mk('k042/sequencer-2');
  const ROGUE = mk('k042/rogue');
  const ml65 = pca.mlDsa65Keygen(seed('k042/ml65'));
  const pq65 = pca.encodeMlDsaPublicKey(ml65.publicKey);
  const ml65b = pca.mlDsa65Keygen(seed('k042/ml65-b'));
  const pq65b = pca.encodeMlDsaPublicKey(ml65b.publicKey);
  const SESSION = D('k042/session');
  const HEAD = D('k042/head');
  const RB = { v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'trip', seq: 1, pre: 0, delta: 5, post: 5, pcactn_digest: D('k042/pd'), aud: 'skyair.example', issued_at: NOW, expires_at: NOW + 60_000, kid: 's1', ledger: { index: 0, head: HEAD } };
  const RC = pca.signAccReceipt(RB, SEQ.sk);
  const RCpq = pca.signAccReceipt({ ...RB, kid: 'pq1' }, SEQ.sk, { alg: 'ml-dsa-65', mlDsa: ml65 });
  const RChy = pca.signAccReceipt({ ...RB, kid: 'hy1' }, SEQ.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml65 });

  // ---- receiptShapeError
  {
    const F = pca.accReceiptShapeError;
    const fn = 'receiptShapeError';
    vcase(fn, F, 'base', RC);
    vcase(fn, F, 'pq', RCpq);
    vcase(fn, F, 'hybrid', RChy);
    for (const x of [null, 1, 'x', []]) vcase(fn, F, `top=${nm(x)}`, x);
    vcase(fn, F, 'unknown', { ...RC, zz: 1 });
    for (const k of Object.keys(RC)) perturb(fn, F, RC, k, [DEL, ...PALETTE]);
    for (const k of ['alg', 'pq_pk', 'pq_sig']) perturb(fn, F, RC, k, [DEL, ...PALETTE, 'ed25519', 'ml-dsa-65', 'x-unknown', pq65]);
    perturb(fn, F, RCpq, 'pq_pk', [DEL, 'AA=', 5]);
    perturb(fn, F, RCpq, 'pq_sig', [DEL, 'x']);
    perturb(fn, F, RChy, 'pq_sig', [DEL, 5]);
    perturb(fn, F, RC, 'v', [1, 1.0, '1', 2, 0]);
    perturb(fn, F, RC, 'kind', ['pca-acc-receipt', 'pca-sequencer-keys']);
    perturb(fn, F, RC, 'acc', ['a', 'k'.repeat(64), 'k'.repeat(65), 'a-b', '__proto__']);
    perturb(fn, F, RC, 'seq', [1, 0, -1, MAX, MAX + 1, 1.5, -0]);
    for (const k of ['pre', 'delta', 'post']) perturb(fn, F, RC, k, [0, MAX, -1, -0, 1.5, MAX + 1]);
    perturb(fn, F, RC, 'aud', ['a', '', 5]);
    perturb(fn, F, RC, 'kid', ['a', 'a.b:c-d_e', 'k'.repeat(64), 'k'.repeat(65), '', 'a b', 'a/b']);
    for (const [n, ia, ea] of [['eq', NOW, NOW], ['lt', NOW, NOW - 1], ['life', NOW, NOW + 900_000], ['life+1', NOW, NOW + 900_001], ['life-1', NOW, NOW + 899_999], ['zero', 0, 0], ['ia-neg', -1, 5], ['ea-neg', 0, -1], ['ia-frac', 1.5, 5], ['ea-frac', 0, 1.5], ['ia-negz', -0, 5], ['ea-negz', 0, -0], ['ia-big', MAX + 1, MAX + 1], ['ia-str', '1', 5]])
      vcase(fn, F, `times-${n}`, { ...RC, issued_at: ia, expires_at: ea });
    perturb(fn, F, RC, 'ledger', [{ index: 0, head: HEAD }, { index: MAX, head: HEAD }, { head: HEAD, index: 3 }, { index: -1, head: HEAD }, { index: 1.5, head: HEAD }, { index: -0, head: HEAD }, { index: 0 }, { head: HEAD }, { index: 0, head: HEAD, x: 1 }, { index: 0, x: HEAD }, { index: 0, head: 'AAAA' }, { index: '0', head: HEAD }, {}, null, [], 'x']);
    perturb(fn, F, RC, 'signer', ['AAAA', SEQ.pk + 'A', SEQ2.pk]);
    perturb(fn, F, RC, 'session', ['AAAA', SESSION.slice(0, -1)]);
    perturb(fn, F, RC, 'pcactn_digest', ['AAAA']);
    perturb(fn, F, RC, 'sig', ['', 'x', 5, null, DEL]);
  }

  // ---- keySetShapeError
  const E1 = { kid: 's1', pk: SEQ.pk, not_before: NOW - 10_000 };
  const KB = { v: 1, kind: 'pca-sequencer-keys', version: 2, issued_at: NOW - 100, keys: [E1] };
  const KS = pca.signSequencerKeySet(KB, ROOT.sk);
  const KSpq = pca.signSequencerKeySet(KB, ROOT.sk, { alg: 'ml-dsa-65', mlDsa: ml65b });
  {
    const F = pca.sequencerKeySetShapeError;
    const fn = 'keySetShapeError';
    vcase(fn, F, 'base', KS);
    vcase(fn, F, 'pq', KSpq);
    for (const x of [null, 1, 'x', []]) vcase(fn, F, `top=${nm(x)}`, x);
    vcase(fn, F, 'unknown', { ...KS, zz: 1 });
    for (const k of Object.keys(KS)) perturb(fn, F, KS, k, [DEL, ...PALETTE]);
    for (const k of ['alg', 'pq_pk', 'pq_sig']) perturb(fn, F, KS, k, [DEL, ...PALETTE, 'ed25519', 'ml-dsa-65', 'x-unknown', pq65]);
    perturb(fn, F, KSpq, 'pq_pk', [DEL, 'AA=', 5]);
    perturb(fn, F, KS, 'v', [2, '1']);
    perturb(fn, F, KS, 'kind', ['pca-acc-receipt']);
    perturb(fn, F, KS, 'sequencer', ['AAAA']);
    perturb(fn, F, KS, 'version', [1, 0, -1, -0, 1.5, MAX, MAX + 1]);
    perturb(fn, F, KS, 'issued_at', [0, -1, -0, 1.5, MAX, MAX + 1]);
    const many = (n) => Array.from({ length: n }, (_, i) => ({ kid: 'k' + i, pk: SEQ.pk, not_before: 0 }));
    perturb(fn, F, KS, 'keys', [[], many(1), many(255), many(256), many(257), 'x', {}, [null], [1], [[]],
      [E1, E1], [E1, { ...E1, kid: 's2' }], [{ ...E1, zz: 1 }], [{ ...E1, alg: 'ed25519' }], [{ ...E1, alg: 'ml-dsa-65', pq_pk: pq65 }], [{ ...E1, alg: 'x-unknown' }], [{ ...E1, alg: 5 }], [{ ...E1, alg: null }],
      [{ ...E1, pq_pk: 'AA=' }], [{ ...E1, pq_pk: 5 }], [{ ...E1, pq_pk: '' }], [{ ...E1, pq_pk: pq65 }],
      [{ ...E1, kid: '' }], [{ ...E1, kid: 'k'.repeat(64) }], [{ ...E1, kid: 'k'.repeat(65) }], [{ ...E1, kid: 'a b' }], [{ ...E1, kid: 5 }], [{ pk: SEQ.pk, not_before: 0 }],
      [{ ...E1, pk: 'AAAA' }], [{ ...E1, pk: 5 }], [{ kid: 's1', not_before: 0 }],
      [{ ...E1, not_before: 0 }], [{ ...E1, not_before: -1 }], [{ ...E1, not_before: -0 }], [{ ...E1, not_before: 1.5 }], [{ ...E1, not_before: MAX + 1 }], [{ kid: 's1', pk: SEQ.pk }],
      [{ ...E1, not_after: E1.not_before }], [{ ...E1, not_after: E1.not_before - 1 }], [{ ...E1, not_after: E1.not_before + 1 }], [{ ...E1, not_after: -1 }], [{ ...E1, not_after: -0, not_before: 0 }], [{ ...E1, not_after: 0, not_before: 0 }], [{ ...E1, not_after: 1.5 }], [{ ...E1, not_after: null }], [{ ...E1, not_after: '5' }],
      [E1, { ...E1, kid: 's2', pk: 'AAAA' }], [E1, { ...E1, kid: 's2', not_before: -1 }], [E1, { ...E1, kid: 's2', alg: 'x-unknown' }], [E1, { kid: 's2' }]]);
  }

  // ---- verifyKeySet (k, root, rootPqPk, rootPqPresent)
  {
    const fn = 'verifyKeySet';
    const V = (name, k, root, pq) => add(fn, name, [k, root, pq ?? null, pq !== undefined], pca.verifySequencerKeySet(reparse(k), root, pq));
    V('ok', KS, ROOT.pk);
    V('ok-with-unused-pin', KS, ROOT.pk, pq65b);
    V('wrong-root', KS, SEQ.pk);
    V('tampered-version', { ...KS, version: 3 }, ROOT.pk);
    V('tampered-issued', { ...KS, issued_at: KS.issued_at + 1 }, ROOT.pk);
    V('tampered-keys', { ...KS, keys: [{ ...E1, kid: 's2' }] }, ROOT.pk);
    V('tampered-v', { ...KS, v: 2 }, ROOT.pk);
    V('bad-shape', { ...KS, zz: 1 }, ROOT.pk);
    V('sig-garbage', { ...KS, sig: 'x' }, ROOT.pk);
    V('not-object', 5, ROOT.pk);
    V('pq-pinned', KSpq, ROOT.pk, pq65b);
    V('pq-unpinned', KSpq, ROOT.pk);
    V('pq-wrong-pin', KSpq, ROOT.pk, pq65);
    V('pq-pin-nonstring', KSpq, ROOT.pk, 5);
    V('pq-alg-stripped', (() => { const k = reparse(KSpq); delete k.alg; delete k.pq_pk; return k; })(), ROOT.pk, pq65b);
    V('pq-alg-swapped', { ...KSpq, alg: 'hybrid-ed25519-ml-dsa-65' }, ROOT.pk, pq65b);
    V('pq-pk-swapped', { ...KSpq, pq_pk: pq65 }, ROOT.pk, pq65);
    V('pq-tampered', { ...KSpq, version: 9 }, ROOT.pk, pq65b);
    V('ed-sig-under-pq-alg', { ...KS, alg: 'ml-dsa-65', pq_pk: pq65b }, ROOT.pk, pq65b);
    V('ed-explicit-alg', { ...KS, alg: 'ed25519' }, ROOT.pk);
    // a set whose sequencer field names another key but whose signature is the root's: refused by the sequencer check alone
    {
      const body = { v: 1, kind: 'pca-sequencer-keys', sequencer: SEQ2.pk, version: 2, issued_at: NOW - 100, keys: [E1] };
      const msg = new Uint8Array([...pca.utf8(pca.SEQUENCER_KEYS_DOMAIN), ...pca.canonicalBytesStrict(body)]);
      V('foreign-sequencer-root-signed', { ...body, sig: pca.b64u(pca.sign(ROOT.sk, msg)) }, ROOT.pk);
    }
    const KShy = pca.signSequencerKeySet(KB, ROOT.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml65b });
    V('hy-pinned', KShy, ROOT.pk, pq65b);
    V('hy-unpinned', KShy, ROOT.pk);
    V('hy-no-pqsig', (() => { const k = reparse(KShy); delete k.pq_sig; return k; })(), ROOT.pk, pq65b);
  }

  // ---- verifyReceiptSignature (r, expectedSigner, pin)
  {
    const fn = 'verifyReceiptSignature';
    const V = (name, r, signer, pinPq) => add(fn, name, [r, signer, pinPq === undefined ? null : { [signer]: pinPq }], pca.verifyAccReceiptSignature(reparse(r), signer, pinPq === undefined ? {} : { pqPins: { [signer]: pinPq } }));
    V('ok', RC, SEQ.pk);
    V('wrong-signer', RC, SEQ2.pk);
    V('ok-unused-pin', RC, SEQ.pk, pq65);
    for (const k of ['seq', 'pre', 'delta', 'post', 'issued_at', 'expires_at']) V(`tampered-${k}`, { ...RC, [k]: RC[k] + 1 }, SEQ.pk);
    V('tampered-kid', { ...RC, kid: 's9' }, SEQ.pk);
    V('tampered-aud', { ...RC, aud: 'other' }, SEQ.pk);
    V('tampered-acc', { ...RC, acc: 'other' }, SEQ.pk);
    V('tampered-session', { ...RC, session: D('other') }, SEQ.pk);
    V('tampered-digest', { ...RC, pcactn_digest: D('other') }, SEQ.pk);
    V('tampered-ledger-index', { ...RC, ledger: { index: 1, head: HEAD } }, SEQ.pk);
    V('tampered-ledger-head', { ...RC, ledger: { index: 0, head: D('other') } }, SEQ.pk);
    V('ledger-reordered', { ...RC, ledger: { head: HEAD, index: 0 } }, SEQ.pk);
    V('signer-swapped', { ...RC, signer: SEQ2.pk }, SEQ2.pk);
    V('bad-shape', { ...RC, zz: 1 }, SEQ.pk);
    V('bad-shape-sig', { ...RC, sig: 5 }, SEQ.pk);
    V('sig-garbage', { ...RC, sig: 'x' }, SEQ.pk);
    V('not-object', 5, SEQ.pk);
    V('pq-pinned', RCpq, SEQ.pk, pq65);
    V('pq-unpinned', RCpq, SEQ.pk);
    V('pq-wrong-pin', RCpq, SEQ.pk, pq65b);
    V('pq-tampered', { ...RCpq, post: 6 }, SEQ.pk, pq65);
    V('pq-alg-swapped', { ...RCpq, alg: 'hybrid-ed25519-ml-dsa-65' }, SEQ.pk, pq65);
    V('pq-pk-swapped', { ...RCpq, pq_pk: pq65b }, SEQ.pk, pq65b);
    V('hy-pinned', RChy, SEQ.pk, pq65);
    V('hy-unpinned', RChy, SEQ.pk);
    V('hy-no-pqsig', (() => { const r = reparse(RChy); delete r.pq_sig; return r; })(), SEQ.pk, pq65);
    V('ed-explicit-alg', { ...RC, alg: 'ed25519' }, SEQ.pk);
    V('ed-sig-under-pq-alg', { ...RC, alg: 'ml-dsa-65', pq_pk: pq65 }, SEQ.pk, pq65);
    V('aud-lone-surrogate', { ...RC, aud: '\ud800' }, SEQ.pk);
  }

  // ---- verifyReceiptAgainstHolder (r, holder, keySets, now, maxReceiptAgeMs, maxKeySetAgeMs, tracked)
  {
    const fn = 'verifyReceiptAgainstHolder';
    const HOLDER = { kind: 'sequenced', uri: 'https://seq.example', root: ROOT.pk };
    const HOLDERpq = { ...HOLDER, root_pq_pk: pq65b };
    const DR = 900_000, DK = 3_600_000;
    const V = (name, r, holder, keySets, now, mr = DR, mk2 = DK, tracked) => {
      const f = { maxReceiptAgeMs: mr, maxKeySetAgeMs: mk2 };
      if (tracked !== undefined) f.tracked = reparse(tracked);
      add(fn, name, [r, holder, keySets, now, mr, mk2, tracked ?? null], pca.verifyReceiptAgainstHolder(reparse(r), reparse(holder), reparse(keySets), now, f));
    };
    const signKS = (body, opts) => pca.signSequencerKeySet(body, ROOT.sk, opts);
    const ks = (over = {}, e = {}) => signKS({ ...KB, ...over, keys: [{ ...E1, ...e }] });
    V('ok', RC, HOLDER, [KS], NOW);
    V('ok-second-set', RC, HOLDER, [5, { ...KS, version: 9 }, KS], NOW);
    V('no-sets', RC, HOLDER, [], NOW);
    V('sets-not-list', RC, HOLDER, KS, NOW);
    V('bad-receipt', { ...RC, zz: 1 }, HOLDER, [KS], NOW);
    V('tampered-receipt', { ...RC, post: 6 }, HOLDER, [KS], NOW);
    // clock
    for (const [n, now] of [['now-frac', NOW + 0.5], ['now-negz', -0], ['now-neg', -5], ['now-max', MAX], ['now-over', MAX + 1], ['now-0', 0]]) V(n, RC, HOLDER, [KS], now);
    V('now-neg-receipt0', { ...RC }, HOLDER, [KS], -1);
    // the clock's own bounds: now = 2^53-1 is a clock, 2^53 is not; -0 is not (a receipt and set issued at 0)
    V('now-max-all-max', RC, HOLDER, [KS], MAX, MAX, MAX);
    V('now-over-all-max', RC, HOLDER, [KS], MAX + 1, MAX, MAX);
    {
      const R0 = pca.signAccReceipt({ ...RB, issued_at: 0, expires_at: 0 }, SEQ.sk);
      const K0 = pca.signSequencerKeySet({ ...KB, issued_at: 0, keys: [{ ...E1, not_before: 0 }] }, ROOT.sk);
      V('epoch0-now0', R0, HOLDER, [K0], 0);
      V('epoch0-now-negz', R0, HOLDER, [K0], -0);
      V('epoch0-now1', R0, HOLDER, [K0], 1);
    }
    // negative bounds with a receipt issued in the (allowed) future: only the bound check refuses
    V('mr-neg-future', RC, HOLDER, [KS], NOW - 30_000, -1);
    V('mk-neg-future', RC, HOLDER, [KS], NOW - 30_000, DR, -1);
    V('mr-over-future', RC, HOLDER, [KS], NOW - 30_000, MAX + 1);
    V('mk-over-future', RC, HOLDER, [KS], NOW - 30_000, DR, MAX + 1);
    V('future-ok', RC, HOLDER, [KS], NOW - 30_000);
    V('receipt-no-issued', (() => { const r = reparse(RC); delete r.issued_at; return r; })(), HOLDER, [KS], NOW);
    V('receipt-issued-str', { ...RC, issued_at: 'x' }, HOLDER, [KS], NOW);
    V('kid-first-other-pk', RC, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 's0', pk: SEQ2.pk }, E1] })], NOW);
    V('kid-first-not-yet', RC, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 's0', not_before: NOW + 1 }, E1] })], NOW);
    // bounds
    for (const [n, mr] of [['mr-0', 0], ['mr-neg', -1], ['mr-negz', -0], ['mr-frac', 1.5], ['mr-max', MAX], ['mr-over', MAX + 1]]) V(n, RC, HOLDER, [KS], NOW, mr);
    for (const [n, mk2] of [['mk-0', 0], ['mk-neg', -1], ['mk-negz', -0], ['mk-frac', 1.5], ['mk-max', MAX], ['mk-over', MAX + 1]]) V(n, RC, HOLDER, [KS], NOW, DR, mk2);
    // receipt freshness: issued_at <= now + 60s ; now - issued_at <= maxAge
    V('r-future-edge', RC, HOLDER, [KS], NOW - 60_000);
    V('r-future-over', RC, HOLDER, [KS], NOW - 60_001);
    V('r-age-edge', RC, HOLDER, [KS], NOW + 1_000, 1_000);
    V('r-age-over', RC, HOLDER, [KS], NOW + 1_001, 1_000);
    V('r-age-zero', RC, HOLDER, [KS], NOW, 0);
    // key-set freshness (KS issued NOW-100)
    V('ks-age-edge', RC, HOLDER, [KS], NOW, DR, 100);
    V('ks-age-over', RC, HOLDER, [KS], NOW, DR, 99);
    const KSfut = ks({ issued_at: NOW + 60_000 });
    const KSfut1 = ks({ issued_at: NOW + 60_001 });
    V('ks-future-edge', RC, HOLDER, [KSfut], NOW);
    V('ks-future-over', RC, HOLDER, [KSfut1], NOW);
    V('ks-future-over-then-ok', RC, HOLDER, [KSfut1, KS], NOW);
    // tracked
    const dig = pca.sequencerKeySetDigest(KS);
    V('tr-eq', RC, HOLDER, [KS], NOW, DR, DK, { version: 2, digest: dig });
    V('tr-eq-other-digest', RC, HOLDER, [KS], NOW, DR, DK, { version: 2, digest: D('x') });
    V('tr-lower', RC, HOLDER, [KS], NOW, DR, DK, { version: 1, digest: D('x') });
    V('tr-higher', RC, HOLDER, [KS], NOW, DR, DK, { version: 3, digest: dig });
    V('tr-bad', RC, HOLDER, [KS], NOW, DR, DK, { version: 0, digest: dig });
    V('tr-bad-extra', RC, HOLDER, [KS], NOW, DR, DK, { version: 2, digest: dig, x: 1 });
    V('tr-rollback-then-ok', RC, HOLDER, [ks({ version: 1 }), KS], NOW, DR, DK, { version: 2, digest: dig });
    V('tr-equiv-then-ok', RC, HOLDER, [ks({}, { not_before: NOW - 10_001 }), KS], NOW, DR, DK, { version: 2, digest: dig });
    // the entry
    V('kid-missing', { ...RC, kid: 's9' }, HOLDER, [KS], NOW);
    V('kid-second', RC, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 's0' }, E1] })], NOW);
    V('kid-dup-pk-mismatch', RC, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 's1', pk: SEQ2.pk }] })], NOW);
    V('nb-edge', RC, HOLDER, [ks({}, { not_before: NOW })], NOW);
    V('nb-over', RC, HOLDER, [ks({}, { not_before: NOW + 1 })], NOW);
    V('na-edge', RC, HOLDER, [ks({}, { not_after: NOW })], NOW);
    V('na-under', RC, HOLDER, [ks({}, { not_after: NOW - 1 })], NOW);
    V('na-retired-edge', RC, HOLDER, [ks({}, { not_after: NOW })], NOW + 60_000);
    V('na-retired-over', RC, HOLDER, [ks({}, { not_after: NOW })], NOW + 60_001);
    V('na-future', RC, HOLDER, [ks({}, { not_after: NOW + 5 })], NOW);
    V('na-late-retired', RC, HOLDER, [ks({}, { not_after: NOW + 5 })], NOW + 60_006);
    // root / PQ
    V('wrong-root', RC, { ...HOLDER, root: SEQ.pk }, [KS], NOW);
    V('rogue-set', RC, HOLDER, [pca.signSequencerKeySet(KB, ROGUE.sk)], NOW);
    V('pq-root-pinned', RC, HOLDERpq, [KSpq], NOW);
    V('pq-root-unpinned', RC, HOLDER, [KSpq], NOW);
    V('pq-root-wrong-pin', RC, { ...HOLDER, root_pq_pk: pq65 }, [KSpq], NOW);
    V('ed-set-under-pq-holder', RC, HOLDERpq, [KS], NOW);
    // suites of the entry vs the receipt
    const KSentPq = signKS({ ...KB, keys: [{ ...E1, kid: 'pq1', alg: 'ml-dsa-65', pq_pk: pq65 }] });
    const KSentPqNoPk = signKS({ ...KB, keys: [{ ...E1, kid: 'pq1', alg: 'ml-dsa-65' }] });
    const KSentHy = signKS({ ...KB, keys: [{ ...E1, kid: 'hy1', alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: pq65 }] });
    const KSentEdPq = signKS({ ...KB, keys: [{ ...E1, kid: 'pq1' }] });
    const KSentEdAlg = signKS({ ...KB, keys: [{ ...E1, alg: 'ed25519' }] });
    const KSentUnk = signKS({ ...KB, keys: [{ ...E1, kid: 'pq1', pq_pk: pq65 }] });
    V('pq-receipt-pq-entry', RCpq, HOLDER, [KSentPq], NOW);
    V('pq-receipt-pq-entry-nopk', RCpq, HOLDER, [KSentPqNoPk], NOW);
    V('pq-receipt-ed-entry', RCpq, HOLDER, [KSentEdPq], NOW);
    V('pq-receipt-pk-only-entry', RCpq, HOLDER, [KSentUnk], NOW);
    V('pq-receipt-hy-entry', RCpq, HOLDER, [KSentHy], NOW);
    V('hy-receipt-hy-entry', RChy, HOLDER, [KSentHy], NOW);
    V('hy-receipt-pq-entry', RChy, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 'hy1', alg: 'ml-dsa-65', pq_pk: pq65 }] })], NOW);
    V('ed-receipt-pq-entry', { ...RC }, HOLDER, [signKS({ ...KB, keys: [{ ...E1, alg: 'ml-dsa-65', pq_pk: pq65 }] })], NOW);
    V('ed-receipt-ed-alg-entry', RC, HOLDER, [KSentEdAlg], NOW);
    V('ed-receipt-alg-ed', { ...RC, alg: 'ed25519' }, HOLDER, [KS], NOW);
    V('ed-receipt-alg-ed-entry-alg-ed', { ...RC, alg: 'ed25519' }, HOLDER, [KSentEdAlg], NOW);
    V('pq-receipt-pq-entry-wrongpk', RCpq, HOLDER, [signKS({ ...KB, keys: [{ ...E1, kid: 'pq1', alg: 'ml-dsa-65', pq_pk: pq65b }] })], NOW);
    V('receipt-unknown-alg', { ...RC, alg: 'x-unknown' }, HOLDER, [KS], NOW);
  }

  return cases;
}
