// Oracle for the Java K042MapArtCls*Test mutation-kill tests (IntentMap.java rule 19, IntentClassifier.java rule 18,
// IntentArtifacts.java helpers): runs the TS reference (packages/pca/src/intent-map-commit.ts, intent-classifier.ts,
// intent-artifacts.ts) on targeted inputs and writes sdks/java-pca/test-data/k042-mapartcls.json.gz.
//   cd <repo> && npx tsx tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs [out.json]
// Every case is {fn, name, args, out}; the args are JSON text the Java test parses with Json.parseLenient (so -0 / 1.5 /
// 2^53 / lone surrogates reach both sides as the same value). Deterministic: keys and salts are seeded.
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const OUT = process.argv[2] ?? new URL('../../../sdks/java-pca/test-data/k042-mapartcls.json.gz', import.meta.url).pathname;
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const D = (l) => pca.b64u(seed(l));
const DEL = Symbol('del');
const MAX = Number.MAX_SAFE_INTEGER;
const OTHER = pca.MAP_OTHER;

function ser(v) {
  if (typeof v === 'number') {
    if (Object.is(v, -0)) return '-0';
    if (!Number.isFinite(v)) throw new Error('non-finite');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : ser(x))).join(',') + ']'; // absent args = Java null
  if (v !== null && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const reparse = (x) => JSON.parse(ser(x));

const cases = [];
const names = new Set();
function add(fn, name, args, out) {
  const n = `${fn}/${name}`;
  if (names.has(n)) throw new Error('dup ' + n);
  names.add(n);
  cases.push({ fn, name: n, args, out: out === undefined ? null : out });
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
const nm = (v) => { if (v === DEL) return 'DEL'; const t = ser(v); return t.length > 40 ? `${t.length}:${t.slice(0, 20)}..${t.slice(-8)}` : t; };
const PALETTE = [null, true, 0, 1, -1, -0, 1.5, '', 'x', [], {}, MAX + 1];

function vcase(fn, f, name, arg) {
  const a = reparse(arg);
  add(fn, name, [a], f(reparse(a)));
}
function perturb(fn, f, base, path, vals) {
  for (const v of vals) vcase(fn, f, `${path}=${nm(v)}`, set(base, path, v));
}
const str = (n, ch = 'a') => ch.repeat(n);

// ================================================================ rule 19: leaf shapes
const numDim = (path, lo, hi, cuts) => ({ kind: 'num', path, lo, hi, cuts });
const catDim = (path, values) => ({ kind: 'cat', path, values });
const ex = (v) => ({ kind: 'exact', value: v });
const px = (v) => ({ kind: 'prefix', value: v });
const ot = () => ({ kind: 'other', value: OTHER });
const cellsOf = (dims) => {
  try {
    const n = dims.reduce((n, d) => n * (d.kind === 'num' ? pca.mapNumCells(d).length : d.values.length), 1);
    return Number.isSafeInteger(n) && n >= 1 ? n : 1;
  } catch {
    return 1; // a malformed dimension: the header is refused before the cell count matters
  }
};
const hdr = (dims, extra = {}) => ({ verb: 'v', first: 1, cells: cellsOf(dims), dims, ...extra });
const H = pca.mapHeaderError;

// header-level members
const H0 = hdr([numDim('action.params.n', -10, 10, [-5, 5]), catDim('action.resource', [ex('a'), px('b'), ot()])]);
vcase('header', H, 'base', H0);
for (const v of [...PALETTE, 'x'.repeat(128), 'x'.repeat(129), 'é'.repeat(64), 'é'.repeat(65), 'a\ud800', '\udc00']) vcase('header', H, `verb=${nm(v)}`, set(H0, 'verb', v));
for (const v of [...PALETTE, 2 ** 24 - 1, 2 ** 24, 2 ** 24 + 1]) vcase('header', H, `first=${nm(v)}`, set(H0, 'first', v));
for (const v of [...PALETTE, H0.cells - 1, H0.cells + 1, 2 ** 20, 2 ** 20 + 1]) vcase('header', H, `cells=${nm(v)}`, set(H0, 'cells', v));
for (const v of PALETTE) vcase('header', H, `dims=${nm(v)}`, set(H0, 'dims', v));
vcase('header', H, 'extra', { ...H0, x: 1 });
for (const k of ['verb', 'first', 'cells', 'dims']) vcase('header', H, `missing-${k}`, set(H0, k, DEL));
for (const v of [null, 'h', 1, [], true]) vcase('header', H, `not-object=${nm(v)}`, v);
// dims count 16 / 17 (1-cell numeric dims on distinct paths), duplicate paths, too many cells
const one = (i) => numDim(`action.params.p${i}`, 0, 0, []);
vcase('header', H, 'dims-16', hdr(Array.from({ length: 16 }, (_, i) => one(i))));
vcase('header', H, 'dims-17', hdr(Array.from({ length: 17 }, (_, i) => one(i))));
vcase('header', H, 'dims-0', hdr([]));
vcase('header', H, 'dup-path', hdr([one(1), one(1)]));
vcase('header', H, 'dup-path-cat', hdr([catDim('action.resource', [ot()]), catDim('action.resource', [ot()])]));
const catN = (p, n) => catDim(p, [...Array.from({ length: n - 1 }, (_, i) => ex(`v${i}`)), ot()]);
vcase('header', H, 'cells-2^20', hdr([catN('action.params.a', 256), catN('action.params.b', 256), catN('action.params.c', 16)]));
vcase('header', H, 'cells-2^20-x2', { ...hdr([catN('action.params.a', 256), catN('action.params.b', 256), catN('action.params.c', 16), catN('action.params.d', 2)]), cells: 2 ** 20 });
vcase('header', H, 'cells-2^20-x2-last', { ...hdr([catN('action.params.a', 256), catN('action.params.b', 256), catN('action.params.c', 32)]), cells: 2 ** 20 });
vcase('header', H, 'dims[1]-bad-index', hdr([one(1), 5]));

// numeric dims (wrapped in a header at index 0 and index 1)
const ND = numDim('action.params.n', -10, 10, [-5, 5]);
const hn = (d, at1 = false) => ({ verb: 'v', first: 1, cells: 1, dims: at1 ? [one(9), d] : [d] });
const NUMCASES = [
  ['base', ND],
  ['extra', { ...ND, x: 1 }],
  ['missing-cuts', set(ND, 'cuts', DEL)],
  ['missing-lo', set(ND, 'lo', DEL)],
  ['path-resource', { ...ND, path: 'action.resource' }],
  ['path-env', { ...ND, path: 'env.x' }],
  ['path-num', { ...ND, path: 5 }],
  ['path-dash', { ...ND, path: 'action.params.a-b' }],
  ['path-64', { ...ND, path: 'action.params.' + str(64) }],
  ['path-65', { ...ND, path: 'action.params.' + str(65) }],
  ['lo>hi', numDim('action.params.n', 5, 3, [])],
  ['lo>hi-neg', numDim('action.params.n', -3, -5, [])],
  ['lo<hi-neg', numDim('action.params.n', -5, -3, [])],
  ['lo=hi', numDim('action.params.n', 7, 7, [])],
  ['lo=hi-cut', numDim('action.params.n', 7, 7, [7])],
  ['lo-1.5', numDim('action.params.n', 1.5, 3, [])],
  ['hi-1.5', numDim('action.params.n', 1, 3.5, [])],
  ['lo--0', numDim('action.params.n', -0, 3, [])],
  ['hi--0', numDim('action.params.n', -3, -0, [])],
  ['lo-str', numDim('action.params.n', '1', 3, [])],
  ['hi-unsafe', numDim('action.params.n', 0, MAX + 1, [])],
  ['hi-max', numDim('action.params.n', 0, MAX, [])],
  ['cuts-obj', { ...ND, cuts: {} }],
  ['cuts-null', { ...ND, cuts: null }],
  ['cuts-256', numDim('action.params.n', 0, 1000, Array.from({ length: 256 }, (_, i) => i * 2))],
  ['cuts-257', numDim('action.params.n', 0, 1000, Array.from({ length: 257 }, (_, i) => i * 2))],
  ['cut-eq', numDim('action.params.n', 0, 10, [3, 3])],
  ['cut-dec', numDim('action.params.n', 0, 10, [4, 3])],
  ['cut-at-lo', numDim('action.params.n', 2, 10, [2])],
  ['cut-below-lo', numDim('action.params.n', 2, 10, [1])],
  ['cut-at-hi', numDim('action.params.n', 2, 10, [10])],
  ['cut-above-hi', numDim('action.params.n', 2, 10, [11])],
  ['cut-pos', numDim('action.params.n', 1, 10, [5])],
  ['cut-neg', numDim('action.params.n', -10, -1, [-5])],
  ['cuts-pos-pair', numDim('action.params.n', 0, 10, [5, 7])],
  ['cuts-neg-pair', numDim('action.params.n', -10, 10, [-5, -3])],
  ['cut-one', numDim('action.params.n', -10, 10, [1])],
  ['cut-zero', numDim('action.params.n', -10, 10, [0])],
  ['cut-1.5', numDim('action.params.n', 0, 10, [1.5])],
  ['cut--0', numDim('action.params.n', -10, 10, [-0])],
  ['cut-str', numDim('action.params.n', 0, 10, ['3'])],
  ['cut-neg-then-pos', numDim('action.params.n', -10, 10, [-5, 5])],
  ['cut-bad-second', numDim('action.params.n', 0, 10, [3, 11])],
];
for (const [n, d] of NUMCASES) {
  const fix = (h) => ({ ...h, cells: H(h) === null ? h.cells : (() => { try { return cellsOf(h.dims); } catch { return 1; } })() });
  for (const at1 of [false, true]) {
    let h = hn(d, at1);
    try { h = { ...h, cells: cellsOf(h.dims) }; } catch { /* malformed dim: keep 1 */ }
    if (typeof h.cells !== 'number' || !Number.isSafeInteger(h.cells) || h.cells < 1) h.cells = 1;
    void fix;
    vcase('header', H, `num-${n}${at1 ? '@1' : ''}`, h);
  }
}
// categorical dims
const CD = catDim('action.resource', [ex('a'), px('b'), ot()]);
const CATCASES = [
  ['base', CD],
  ['extra', { ...CD, x: 1 }],
  ['missing-values', set(CD, 'values', DEL)],
  ['missing-path', set(CD, 'path', DEL)],
  ['path-param', { ...CD, path: 'action.params.x' }],
  ['path-env', { ...CD, path: 'env.x' }],
  ['path-num', { ...CD, path: 1 }],
  ['path-dash', { ...CD, path: 'action.params.a.b' }],
  ['values-obj', { ...CD, values: {} }],
  ['values-empty', { ...CD, values: [] }],
  ['values-256', catN('action.resource', 256)],
  ['values-257', catN('action.resource', 257)],
  ['value-not-object', { ...CD, values: ['a', ot()] }],
  ['value-null', { ...CD, values: [null, ot()] }],
  ['value-extra', { ...CD, values: [{ ...ex('a'), x: 1 }, ot()] }],
  ['value-missing-kind', { ...CD, values: [{ value: 'a' }, ot()] }],
  ['value-missing-value', { ...CD, values: [{ kind: 'exact' }, ot()] }],
  ['kind-foo', { ...CD, values: [{ kind: 'foo', value: 'a' }, ot()] }],
  ['kind-num', { ...CD, values: [{ kind: 1, value: 'a' }, ot()] }],
  ['only-exact', { ...CD, values: [ex('a'), ex('b')] }],
  ['only-prefix-last', { ...CD, values: [ex('a'), px('b')] }],
  ['value-num', { ...CD, values: [{ kind: 'exact', value: 1 }, ot()] }],
  ['value-256', { ...CD, values: [ex(str(256)), ot()] }],
  ['value-257', { ...CD, values: [ex(str(257)), ot()] }],
  ['value-128e', { ...CD, values: [ex('é'.repeat(128)), ot()] }],
  ['value-129e', { ...CD, values: [ex('é'.repeat(129)), ot()] }],
  ['value-lone', { ...CD, values: [ex('a\ud800'), ot()] }],
  ['value-lone-low', { ...CD, values: [ex('\udc00b'), ot()] }],
  ['other-not-last', { ...CD, values: [ot(), ex('a'), ot()] }],
  ['other-only-first', { ...CD, values: [ot(), ex('a')] }],
  ['other-wrong-value', { ...CD, values: [ex('a'), { kind: 'other', value: 'x' }] }],
  ['other-empty-value', { ...CD, values: [ex('a'), { kind: 'other', value: '' }] }],
  ['prefix-empty', { ...CD, values: [px(''), ot()] }],
  ['exact-empty', { ...CD, values: [ex(''), ot()] }],
  ['exact-other-char', { ...CD, values: [ex(OTHER), ot()] }],
  ['prefix-other-char', { ...CD, values: [px(OTHER), ot()] }],
  ['dup-exact', { ...CD, values: [ex('a'), ex('a'), ot()] }],
  ['dup-prefix', { ...CD, values: [px('a'), px('a'), ot()] }],
  ['exact-and-prefix', { ...CD, values: [ex('a'), px('a'), ot()] }],
  ['two-others', { ...CD, values: [ot(), ot()] }],
  ['only-other', { ...CD, values: [ot()] }],
  ['dup-after-bad', { ...CD, values: [ex('a'), ex('a'), { kind: 'foo', value: 'b' }, ot()] }],
];
for (const [n, d] of CATCASES) {
  for (const at1 of [false, true]) {
    const h = hn(d, at1);
    try { h.cells = cellsOf(h.dims); } catch { h.cells = 1; }
    if (!Number.isSafeInteger(h.cells) || h.cells < 1) h.cells = 1;
    vcase('header', H, `cat-${n}${at1 ? '@1' : ''}`, h);
  }
}
for (const [n, d] of [['kind-foo', { kind: 'foo', path: 'action.resource' }], ['kind-missing', { path: 'action.resource' }], ['kind-num', { kind: 1 }], ['null', null], ['array', []], ['string', 'num']]) {
  vcase('header', H, `dim-${n}`, hn(d));
  vcase('header', H, `dim-${n}@1`, hn(d, true));
}

// cell leaf
const C0 = { verb: 'v', cell: [0, 1], p_ppm: 5, in_grant: true };
const CE = pca.mapCellError;
vcase('cell', CE, 'base', C0);
for (const v of [...PALETTE, 'x'.repeat(128), 'x'.repeat(129), 'é'.repeat(64), 'é'.repeat(65), 'a\ud800']) vcase('cell', CE, `verb=${nm(v)}`, set(C0, 'verb', v));
for (const v of [...PALETTE, Array(16).fill(0), Array(17).fill(0), [0, -1], [1.5], [-0], [MAX], [MAX + 1], ['1'], [null], [2, 3, -1]]) vcase('cell', CE, `cell=${nm(v)}`, set(C0, 'cell', v));
for (const v of [...PALETTE, 1_000_000, 1_000_001, 999_999]) vcase('cell', CE, `p_ppm=${nm(v)}`, set(C0, 'p_ppm', v));
for (const v of [...PALETTE, false]) vcase('cell', CE, `in_grant=${nm(v)}`, set(C0, 'in_grant', v));
vcase('cell', CE, 'extra', { ...C0, x: 1 });
for (const k of Object.keys(C0)) vcase('cell', CE, `missing-${k}`, set(C0, k, DEL));
for (const v of [null, 'c', 1, [], true]) vcase('cell', CE, `not-object=${nm(v)}`, v);

// metrics leaf
const M0 = { residual_risk_ppm: 1200, burden_ppm: 3, uncertainty_ppm: 4, disagreement_ppm: 0, mean_harm_ppm: 10, fidelity_est_ppm: 990000, entropy_mbits: 12, questions: 2, conflicts: 0 };
const ME = pca.mapMetricsError;
vcase('metrics', ME, 'base', M0);
vcase('metrics', ME, 'log2', { ...M0, log2_vs_mbits: 4500 });
for (const v of PALETTE) vcase('metrics', ME, `log2=${nm(v)}`, { ...M0, log2_vs_mbits: v });
for (const k of Object.keys(M0)) {
  vcase('metrics', ME, `missing-${k}`, set(M0, k, DEL));
  for (const v of [-1, 1.5, null, '1', MAX + 1]) vcase('metrics', ME, `${k}=${nm(v)}`, set(M0, k, v));
}
vcase('metrics', ME, 'extra', { ...M0, x: 1 });
for (const v of [null, 'm', 1, [], true]) vcase('metrics', ME, `not-object=${nm(v)}`, v);

// learner leaf
const LE = pca.mapLearnerError;
const L0 = { learner_digest: D('k042map/learner') };
vcase('learner', LE, 'base', L0);
vcase('learner', LE, 'extra', { ...L0, x: 1 });
vcase('learner', LE, 'missing', {});
for (const v of [...PALETTE, D('x').slice(0, 42), D('x') + 'A', D('x') + '=']) vcase('learner', LE, `digest=${nm(v)}`, { learner_digest: v });
for (const v of [null, 'l', 1, [], true]) vcase('learner', LE, `not-object=${nm(v)}`, v);

// numeric cells
for (const [n, d] of [
  ['basic', numDim('action.params.n', 0, 10, [5])],
  ['lo5', numDim('action.params.n', 5, 20, [9])],
  ['cut-lo+1', numDim('action.params.n', 0, 10, [1])],
  ['cut-at-lo', numDim('action.params.n', 3, 10, [3])],
  ['cut-hi-1', numDim('action.params.n', 0, 10, [9])],
  ['cut-at-hi', numDim('action.params.n', 0, 10, [10])],
  ['adjacent', numDim('action.params.n', -4, 4, [-2, -1, 1, 2])],
  ['no-cuts', numDim('action.params.n', -7, 7, [])],
  ['lo=hi', numDim('action.params.n', 7, 7, [])],
  ['lo=hi-cut', numDim('action.params.n', 7, 7, [7])],
  ['negative', numDim('action.params.n', -20, -5, [-10])],
]) add('numcells', n, [d], pca.mapNumCells(d));

// cell of ω (headers are well-formed)
const COF = (h, r, p) => { const w = pca.mapCellOf(h, r, p); return 'error' in w ? null : w; };
const cof = (name, h, r, p) => { if (H(h) !== null) throw new Error(`cellof ${name}: ${H(h)}`); add('cellof', name, p === undefined ? [h, r] : [h, r, p], COF(h, r, p)); };
const HP = hdr([catDim('action.resource', [px('a'), px('ab'), ex('abc'), px('b'), ot()])]);
for (const r of ['abc', 'abd', 'ax', 'a', 'b', 'bz', 'c', '', OTHER, OTHER + 'x', 'a\ud800', '\udc00', 5, null, true, ['a'], { a: 1 }]) cof(`prefix-order r=${nm(r)}`, HP, r, {});
const HQ = hdr([catDim('action.resource', [px('ab'), px('a'), ot()])]);
for (const r of ['abc', 'ab', 'a', 'az', 'x']) cof(`prefix-order-rev r=${nm(r)}`, HQ, r, {});
const HX = hdr([catDim('action.resource', [px('ab'), ex('ab'), ot()])]);
for (const r of ['ab', 'abc', 'b']) cof(`prefix-then-exact r=${nm(r)}`, HX, r, {});
const HE = hdr([catDim('action.resource', [ex('a'), ex(''), ot()])]);
for (const r of ['a', 'ab', '', 'b']) cof(`exact-as-prefix r=${nm(r)}`, HE, r, {});
const HN = hdr([numDim('action.params.n', 5, 20, [9]), catDim('action.params.c', [ex('x'), ex('y'), ot()])]);
for (const [n, p] of [
  ['5,x', { n: 5, c: 'x' }], ['4', { n: 4, c: 'x' }], ['8,y', { n: 8, c: 'y' }], ['9', { n: 9, c: 'z' }], ['10', { n: 10, c: 'x' }], ['20', { n: 20, c: 'y' }],
  ['21', { n: 21, c: 'x' }], ['1.5', { n: 1.5, c: 'x' }], ['-0', { n: -0, c: 'x' }], ['str', { n: '9', c: 'x' }], ['null', { n: null, c: 'x' }],
  ['n-absent', { c: 'x' }], ['c-absent', { n: 9 }], ['c-null', { n: 9, c: null }], ['c-num', { n: 9, c: 1 }], ['c-lone', { n: 9, c: '\ud800' }], ['empty', {}],
  ['proto', { n: 9, c: 'x', __proto__x: 1 }],
]) cof(`num-cat ${n}`, HN, 'r', p);
cof('num-cat params-null', HN, 'r', null);
cof('num-cat params-array', HN, 'r', [9, 'x']);
cof('num-cat params-absent', HN, 'r');
cof('zero-dims', hdr([]), 'r', {});
const HR = hdr([catDim('action.params.c', [ex('x'), ot()]), catDim('action.resource', [ex('r'), ot()])]);
for (const [n, r, p] of [['both', 'r', { c: 'x' }], ['other-res', 'q', { c: 'x' }], ['res-absent', undefined, { c: 'x' }], ['param-e', 'r', { e: 'x' }]]) cof(`param-res ${n}`, HR, r, p);

// ================================================================ rule 19: disclosures and decisions
// a committed map from an explicit leaf list (any kinds, any order) with seeded salts
function build(tag, leaves) {
  const salts = leaves.map((_, i) => seed(`k042map/${tag}/salt/${i}`));
  const hashes = leaves.map((l, i) => pca.mapLeafHash(l.kind, salts[i], l.leaf));
  const tree = pca.mapTree(hashes);
  const size = leaves.length;
  return {
    commit: pca.mapCommitOf(size, tree.root),
    size,
    leaves: leaves.map((l, i) => ({ kind: l.kind, salt: pca.b64u(salts[i]), leaf: l.leaf })),
    entry: (i) => ({ index: i, salt: pca.b64u(salts[i]), leaf: reparse(leaves[i].leaf), path: tree.path(i) }),
  };
}
const BOOK = { verb: 'air.book', first: 3, cells: 9, dims: [numDim('action.params.total', 0, 100000, [40000]), catDim('action.params.cabin', [ex('economy'), ex('business'), ot()])] };
const STATUS = { verb: 'air.status', first: 12, cells: 1, dims: [] };
const RES = { verb: 'res.get', first: 13, cells: 4, dims: [catDim('action.resource', [ex('a'), ex('b'), ex('c'), ot()])] };
const TWO = { verb: 'two.d', first: 17, cells: 2, dims: [catDim('action.resource', [ex('a'), ot()]), numDim('action.params.n', 0, 1, [])] };
const ML = [
  { kind: 'header', leaf: BOOK }, { kind: 'header', leaf: STATUS }, { kind: 'header', leaf: RES },
];
for (let f = 0; f < 9; f++) ML.push({ kind: 'cell', leaf: { verb: 'air.book', cell: [Math.floor(f / 3), f % 3], p_ppm: 1000 + f, in_grant: Math.floor(f / 3) < 2 && f % 3 === 0 } });
ML.push({ kind: 'cell', leaf: { verb: 'air.status', cell: [], p_ppm: 7, in_grant: true } }); // 12
ML.push({ kind: 'cell', leaf: { verb: 'res.get', cell: [0], p_ppm: 70, in_grant: true } }); // 13: a
ML.push({ kind: 'cell', leaf: { verb: 'res.gex', cell: [1], p_ppm: 71, in_grant: true } }); // 14: b, wrong verb
ML.push({ kind: 'cell', leaf: { verb: 'res.get', cell: [], p_ppm: 72, in_grant: true } }); // 15: c, short cell
ML.push({ kind: 'cell', leaf: { verb: 'res.get', cell: [0], p_ppm: 73, in_grant: true } }); // 16: other, element mismatch
// TWO is not in the header list of ML (its header is leaf 17 of M2 below)
ML.push({ kind: 'metrics', leaf: M0 }, { kind: 'learner', leaf: L0 });
const M1 = build('m1', ML);
// M2: a two-dimension verb (index-only and element-0-only mismatches) + metrics in the WRONG position (last)
const ML2 = [
  { kind: 'header', leaf: { ...TWO, first: 1 } },
  { kind: 'cell', leaf: { verb: 'two.d', cell: [1, 0], p_ppm: 9, in_grant: true } }, // 1: (a,0) is [0,0]; leaf says [1,0]
  { kind: 'cell', leaf: { verb: 'two.d', cell: [0, 0], p_ppm: 9, in_grant: true } }, // 2: (other,0) is [1,0]; leaf says [0,0]
  { kind: 'metrics', leaf: { ...M0, residual_risk_ppm: 77 } },
  { kind: 'learner', leaf: L0 },
];
const M2 = build('m2', ML2);
const M3 = build('m3', [
  { kind: 'header', leaf: { verb: 'x.y', first: 1, cells: 1, dims: [] } },
  { kind: 'cell', leaf: { verb: 'x.y', cell: [], p_ppm: 3, in_grant: true } },
  { kind: 'learner', leaf: L0 },
  { kind: 'metrics', leaf: { ...M0, residual_risk_ppm: 5 } },
]);
add('commit', 'm1', [M1.leaves], M1.commit);
add('commit', 'm2', [M2.leaves], M2.commit);
add('commit', 'm3', [M3.leaves], M3.commit);
add('commit', 'single', [[M1.leaves[0]]], pca.mapCommitOf(1, pca.mapLeafHash('header', seed('k042map/m1/salt/0'), BOOK)));

const dis = (M, h, c, m) => ({ size: M.size, header: M.entry(h), cell: M.entry(c), metrics: M.entry(m === undefined ? M.size - 2 : m) });
function decideCase(name, M, action, params, disclosure, eps, opts = {}) {
  const pdig = opts.digest ?? pca.paramsDigest(params === undefined ? {} : params);
  const act = { ...action, params_digest: pdig };
  const input = { map_commit: 'commit' in opts ? opts.commit : M.commit, action: act, disclosure };
  if (params !== undefined) input.params = params;
  if (eps !== undefined) input.max_residual_risk_ppm = eps;
  const r = pca.decideMapDisclosure({ mapCommit: input.map_commit, action: act, params, disclosure, maxResidualRiskPpm: eps });
  add('decide', name, [input], r);
}
const book = (total, cabin) => ({ total, cabin });
const okD = dis(M1, 0, 3);
decideCase('ok', M1, { verb: 'air.book', resource: 'r' }, book(38900, 'economy'), okD);
decideCase('ok-cut', M1, { verb: 'air.book', resource: 'r' }, book(40000, 'economy'), dis(M1, 0, 6));
decideCase('eps=risk', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, 1200);
decideCase('eps<risk', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, 1199);
decideCase('outside-grant', M1, { verb: 'air.book', resource: 'r' }, book(40001, 'economy'), dis(M1, 0, 9));
decideCase('outside-dim', M1, { verb: 'air.book', resource: 'r' }, book(100001, 'economy'), okD);
decideCase('status-no-params', M1, { verb: 'air.status' }, undefined, dis(M1, 1, 12));
decideCase('status-empty-params', M1, { verb: 'air.status' }, {}, dis(M1, 1, 12));
decideCase('status-params-digest-other', M1, { verb: 'air.status' }, undefined, dis(M1, 1, 12), undefined, { digest: pca.paramsDigest({ a: 1 }) });
decideCase('res-a', M1, { verb: 'res.get', resource: 'a' }, {}, dis(M1, 2, 13));
decideCase('res-b-wrong-verb', M1, { verb: 'res.get', resource: 'b' }, {}, dis(M1, 2, 14));
decideCase('res-c-short-cell', M1, { verb: 'res.get', resource: 'c' }, {}, dis(M1, 2, 15));
decideCase('res-other-mismatch', M1, { verb: 'res.get', resource: 'zz' }, {}, dis(M1, 2, 16));
decideCase('res-lone', M1, { verb: 'res.get', resource: '\ud800' }, {}, dis(M1, 2, 16));
decideCase('res-number', M1, { verb: 'res.get', resource: 5 }, {}, dis(M1, 2, 13));
decideCase('res-a-at-b', M1, { verb: 'res.get', resource: 'a' }, {}, dis(M1, 2, 14));
// layout
const fwd = (d, path, v) => set(d, path, v);
decideCase('header-index=first', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'header/index', 3));
decideCase('header-index>first', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'header/index', 5));
decideCase('header-index=first-1-moved', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'header/index', 2));
decideCase('size-too-small', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'size', 13));
decideCase('size-first+cells+2', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'size', 14));
decideCase('size+1', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'size', M1.size + 1));
decideCase('res-last-fits', M1, { verb: 'res.get', resource: 'zz' }, {}, fwd(dis(M1, 2, 16), 'size', 19));
// openings
decideCase('header-wrong-salt', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'header/salt', D('other')));
decideCase('cell-wrong-salt', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'cell/salt', D('other')));
decideCase('metrics-wrong-salt', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'metrics/salt', D('other')));
decideCase('cell-short-path', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'cell/path', okD.cell.path.slice(1)));
decideCase('cell-long-path', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'cell/path', [...okD.cell.path, D('extra')]));
decideCase('cell-index-off', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'cell/index', 4));
decideCase('cell-index-size', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), fwd(okD, 'cell/index', M1.size));
decideCase('metrics-learner', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), { ...okD, metrics: { ...M1.entry(M1.size - 1), leaf: M0 } });
decideCase('verb-other', M1, { verb: 'air.search', resource: 'r' }, book(1, 'economy'), okD);
decideCase('verb-absent', M1, { resource: 'r' }, book(1, 'economy'), okD);
decideCase('params-digest', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, undefined, { digest: pca.paramsDigest({}) });
decideCase('params-array', M1, { verb: 'air.book', resource: 'r' }, [1], okD, undefined, { digest: pca.paramsDigest({}) });
decideCase('params-null', M1, { verb: 'air.book', resource: 'r' }, null, okD, undefined, { digest: pca.paramsDigest({}) });
decideCase('no-commit', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, undefined, { commit: 'abc' });
decideCase('commit-null', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, undefined, { commit: null });
decideCase('other-commit', M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), okD, undefined, { commit: M2.commit });
// M2 / M3
decideCase('two-ok-shape-mismatch0', M2, { verb: 'two.d', resource: 'a' }, { n: 0 }, dis(M2, 0, 1));
decideCase('two-index-only', M2, { verb: 'two.d', resource: 'a' }, { n: 0 }, dis(M2, 0, 2));
decideCase('two-other-mismatch0', M2, { verb: 'two.d', resource: 'q' }, { n: 0 }, dis(M2, 0, 2));
decideCase('two-n-out', M2, { verb: 'two.d', resource: 'a' }, { n: 2 }, dis(M2, 0, 1));
decideCase('m3-metrics-last', M3, { verb: 'x.y' }, {}, dis(M3, 0, 1, 3));
decideCase('m3-learner-as-metrics', M3, { verb: 'x.y' }, {}, { ...dis(M3, 0, 1, 2), metrics: { ...M3.entry(2), leaf: M0 } });
// disclosure shapes (malformed => the reason prefix)
for (const [n, d] of [
  ['size-3', fwd(okD, 'size', 3)], ['size-4', fwd(okD, 'size', 4)], ['size-2^24', fwd(okD, 'size', 2 ** 24)], ['size-2^24+1', fwd(okD, 'size', 2 ** 24 + 1)],
  ['size-1.5', fwd(okD, 'size', 4.5)], ['size-str', fwd(okD, 'size', '14')], ['extra', { ...okD, x: 1 }], ['missing-metrics', set(okD, 'metrics', DEL)],
  ['not-object', [okD]], ['null', null],
]) decideCase(`disclosure-${n}`, M1, { verb: 'air.book', resource: 'r' }, book(1, 'economy'), d);

// disclosureError directly (entry shapes)
const DE = pca.mapDisclosureError;
vcase('disclosure', DE, 'base', okD);
for (const k of ['header', 'cell', 'metrics']) {
  for (const v of [null, 'e', [], 1]) vcase('disclosure', DE, `${k}=${nm(v)}`, set(okD, k, v));
  vcase('disclosure', DE, `${k}-extra`, set(okD, `${k}/x`, 1));
  for (const f of ['index', 'salt', 'leaf', 'path']) vcase('disclosure', DE, `${k}-missing-${f}`, set(okD, `${k}/${f}`, DEL));
  for (const v of [-1, 1.5, -0, '1', null, MAX, MAX + 1]) vcase('disclosure', DE, `${k}/index=${nm(v)}`, set(okD, `${k}/index`, v));
  for (const v of [null, 1, '', D('x').slice(1), D('x') + 'A', 'AAAA']) vcase('disclosure', DE, `${k}/salt=${nm(v)}`, set(okD, `${k}/salt`, v));
  for (const [n, v] of [['64', Array(64).fill(D('p'))], ['65', Array(65).fill(D('p'))], ['empty', []], ['obj', {}], ['bad-first', ['x', D('p')]], ['bad-last', [D('p'), 'x']], ['null-elem', [null]], ['str', D('p')]])
    vcase('disclosure', DE, `${k}/path=${n}`, set(okD, `${k}/path`, v));
}
vcase('disclosure', DE, 'header-leaf-bad', set(okD, 'header/leaf/verb', ''));
vcase('disclosure', DE, 'cell-leaf-bad', set(okD, 'cell/leaf/p_ppm', -1));
vcase('disclosure', DE, 'metrics-leaf-bad', set(okD, 'metrics/leaf/questions', -1));
vcase('disclosure', DE, 'header-and-cell-bad', set(set(okD, 'header/leaf/verb', ''), 'cell/leaf/p_ppm', -1));
vcase('disclosure', DE, 'cell-and-metrics-bad', set(set(okD, 'cell/leaf/p_ppm', -1), 'metrics/leaf/questions', -1));
vcase('disclosure', DE, 'header-bad-and-cell-entry-bad', set(set(okD, 'header/leaf/verb', ''), 'cell/index', -1));
for (const v of [3, 4, 2 ** 24, 2 ** 24 + 1, 4.5, -0, '4', null]) vcase('disclosure', DE, `size=${nm(v)}`, set(okD, 'size', v));
vcase('disclosure', DE, 'extra', { ...okD, x: 1 });
for (const k of ['size', 'header', 'cell', 'metrics']) vcase('disclosure', DE, `missing-${k}`, set(okD, k, DEL));
for (const v of [null, 'd', 1, []]) vcase('disclosure', DE, `not-object=${nm(v)}`, v);

// ================================================================ rule 18: classifier verdicts
const SESSION = D('k042cls/session');
const J = [mk('k042cls/judge-1'), mk('k042cls/judge-2'), mk('k042cls/judge-3')];
const ROGUE = mk('k042cls/rogue');
const TEXT = 'please refund my order';
const verdict = (j, over = {}) =>
  pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(TEXT), label: 'calm', measurement: 'm-1', ...over }, j.sk);
const V0 = verdict(J[0]);
const VW = pca.validateClassifierVerdictWire;
vcase('verdictwire', VW, 'base', V0);
vcase('verdictwire', VW, 'extra', { ...V0, x: 1 });
for (const k of ['v', 'kind', 'classifier', 'session', 'content_digest', 'label', 'measurement', 'judge', 'sig']) vcase('verdictwire', VW, `missing-${k}`, set(V0, k, DEL));
for (const [k, vals] of Object.entries({
  v: [2, 0, '1', 1.5, null], kind: ['pca-fact', '', null, 1],
  classifier: ['Tone', '', '1a', 'a'.repeat(64), 'a'.repeat(65), 'a-b', 5, null, 'classifier'],
  session: ['x', 5, null, D('x').slice(1)], content_digest: ['x', 5, null],
  label: ['', 'l'.repeat(64), 'l'.repeat(65), 'é'.repeat(32), 'é'.repeat(33), 5, null, 'label'],
  measurement: ['', 'm'.repeat(256), 'm'.repeat(257), 'é'.repeat(128), 'é'.repeat(129), 5, null, 'measurement'],
  judge: ['x', 5, null], sig: [5, null, [], '', 'sig'],
})) for (const v of vals) vcase('verdictwire', VW, `${k}=${nm(v)}`, set(V0, k, v));
for (const [k, v] of [['alg', 'ed25519'], ['pq_pk', 'x'], ['pq_sig', 'x'], ['alg', 5]]) vcase('verdictwire', VW, `suite-${k}=${nm(v)}`, { ...V0, [k]: v });
for (const v of [null, 'v', 1, [], true]) vcase('verdictwire', VW, `not-object=${nm(v)}`, v);

// policy
const CL0 = { id: 'tone', param: 'action.params.text', labels: ['calm', 'angry'], keys: [J[0].pk, J[1].pk, J[2].pk], k: 2 };
const P0 = { classifiers: [CL0] };
const VP = pca.validateClassifierPolicy;
vcase('policy', VP, 'base', P0);
vcase('policy', VP, 'empty', { classifiers: [] });
vcase('policy', VP, 'extra', { ...P0, x: 1 });
for (const v of [null, 'p', 1, [], {}, { classifiers: null }, { classifiers: {} }, { classifiers: 'x' }]) vcase('policy', VP, `shape=${nm(v)}`, v);
for (const v of [null, 'c', 1, []]) vcase('policy', VP, `classifier=${nm(v)}`, { classifiers: [v] });
vcase('policy', VP, 'classifier-extra', { classifiers: [{ ...CL0, x: 1 }] });
for (const k of Object.keys(CL0)) vcase('policy', VP, `classifier-missing-${k}`, { classifiers: [set(CL0, k, DEL)] });
for (const [k, vals] of Object.entries({
  id: ['Tone', '', 5, null, 'a'.repeat(64), 'a'.repeat(65)],
  param: ['action.params.', 'action.params.a.', 'action.params.a..b', 'action.params.__proto__', 'action.params.constructor', 'action.params.prototype',
    'action.params.' + str(64), 'action.params.' + str(65), 'action.params.a-b', 'action.params.a.b.c.d.e.f.g.h', 'action.params.a.b.c.d.e.f.g.h.i',
    'action.params', 'x.params.a', 'action.resource', 5, null, 'action.params.a b', 'action.params.é'],
  labels: [[], Array.from({ length: 32 }, (_, i) => `l${i}`), Array.from({ length: 33 }, (_, i) => `l${i}`), ['a', 'a'], [''], [5], [null], ['l'.repeat(64)], ['l'.repeat(65)],
    ['é'.repeat(32)], ['é'.repeat(33)], {}, null, 'calm', ['calm', 'x', 'calm']],
  keys: [[], {}, null, [J[0].pk, J[0].pk], ['x'], [J[0].pk, 5], [J[0].pk]],
  k: [0, 1, 3, 4, -1, 1.5, '2', null, -0],
  measurements: [[], ['m'], [5], [null], {}, null, 'm', ['m', 1]],
  pq_keys: [{}, { [J[0].pk]: 'pq' }, { [ROGUE.pk]: 'pq' }, { [J[0].pk]: '' }, { [J[0].pk]: 5 }, { [J[0].pk]: null }, null, [], 'x', { [J[0].pk]: 'pq', [ROGUE.pk]: 'pq' }, { [J[1].pk]: 'pq', [J[0].pk]: '' }],
})) for (const v of vals) vcase('policy', VP, `${k}=${nm(v)}`, { classifiers: [{ ...CL0, [k]: v }] });
vcase('policy', VP, 'dup-id', { classifiers: [CL0, { ...CL0 }] });
vcase('policy', VP, 'two-ids', { classifiers: [CL0, { ...CL0, id: 'tone2' }] });
vcase('policy', VP, 'second-bad', { classifiers: [CL0, { ...CL0, id: 'tone2', k: 9 }] });
vcase('policy', VP, 'third-dup', { classifiers: [CL0, { ...CL0, id: 'b' }, { ...CL0, id: 'b' }] });

// decisions
const DC = pca.decideClassifierDimensions;
const ref = (v) => pca.classifierVerdictRef(v);
const ACT = { params: { text: TEXT } };
function ccase(name, input) {
  const r = DC(reparse(input));
  const out = r.ok ? { ok: true, classes: { ...r.classes } } : { ok: false, reason: r.reason };
  add('classify', name, [input], out);
}
const V1 = verdict(J[1]);
const V2 = verdict(J[2]);
const VA = verdict(J[2], { label: 'angry' });
const base = (over = {}) => ({ session: SESSION, action: ACT, committed: [ref(V0), ref(V1)], verdicts: [V0, V1], policy: P0, ...over });
ccase('ok', base());
ccase('ok-k1', base({ policy: { classifiers: [{ ...CL0, k: 1 }] }, committed: [ref(V0)], verdicts: [V0] }));
ccase('ambiguous', base({ policy: { classifiers: [{ ...CL0, k: 1 }] }, committed: [ref(V0), ref(VA)], verdicts: [V0, VA] }));
ccase('no-quorum', base({ committed: [ref(V0), ref(VA)], verdicts: [V0, VA] }));
ccase('no-quorum-empty', base({ committed: [], verdicts: [] }));
ccase('quorum-3-of-3', base({ policy: { classifiers: [{ ...CL0, k: 3 }] }, committed: [ref(V0), ref(V1), ref(V2)], verdicts: [V0, V1, V2] }));
ccase('empty-policy', { session: SESSION, action: ACT, policy: { classifiers: [] } });
ccase('empty-policy-no-verdicts', { session: SESSION, action: {}, committed: [], policy: { classifiers: [] } });
ccase('empty-policy-action-no-params', { session: SESSION, action: {}, policy: { classifiers: [] } });
ccase('verdicts-null', { session: SESSION, action: ACT, verdicts: null, policy: { classifiers: [] } });
ccase('verdicts-obj', { session: SESSION, action: ACT, verdicts: {}, policy: { classifiers: [] } });
ccase('action-absent', { session: SESSION, policy: { classifiers: [] } });
ccase('action-array', { session: SESSION, action: [], policy: { classifiers: [] } });
ccase('action-null', { session: SESSION, action: null, policy: { classifiers: [] } });
ccase('params-null', { session: SESSION, action: { params: null }, policy: { classifiers: [] } });
ccase('params-array', { session: SESSION, action: { params: [] }, policy: { classifiers: [] } });
ccase('params-str', { session: SESSION, action: { params: 'x' }, policy: { classifiers: [] } });
ccase('committed-null', { session: SESSION, action: ACT, committed: null, policy: { classifiers: [] } });
ccase('committed-obj', { session: SESSION, action: ACT, committed: {}, policy: { classifiers: [] } });
const digests = (n) => Array.from({ length: n }, (_, i) => D(`k042cls/c${i}`));
ccase('committed-8', { session: SESSION, action: ACT, committed: digests(8), policy: { classifiers: [] } });
ccase('committed-9', { session: SESSION, action: ACT, committed: digests(9), policy: { classifiers: [] } });
ccase('committed-bad', { session: SESSION, action: ACT, committed: ['abc'], policy: { classifiers: [] } });
ccase('committed-num', { session: SESSION, action: ACT, committed: [5], policy: { classifiers: [] } });
ccase('committed-dup', { session: SESSION, action: ACT, committed: [D('k042cls/c0'), D('k042cls/c0')], policy: { classifiers: [] } });
ccase('policy-bad', base({ policy: { classifiers: [{ ...CL0, k: 0 }] } }));
ccase('policy-missing', { session: SESSION, action: ACT });
ccase('not-supplied', base({ verdicts: [V0] }));
ccase('malformed-supplied', base({ verdicts: [V0, { ...V1, x: 1 }] }));
ccase('supplied-junk', base({ verdicts: [5, null, 'x', V0, V1] }));
ccase('suite-unsupported', (() => { const v = { ...V1, alg: 'x-unknown' }; return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('suite-ed-pq', (() => { const v = { ...V1, pq_pk: 'x' }; return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('undeclared', (() => { const v = verdict(J[1], { classifier: 'other' }); return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('rogue-judge', (() => { const v = verdict(ROGUE); return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('bad-sig', (() => { const v = { ...V1, sig: V0.sig }; return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('bad-sig-label', (() => { const v = { ...V1, label: 'angry' }; return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('other-session', (() => { const v = verdict(J[1], { session: D('k042cls/other') }); return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('session-absent', { ...base(), session: undefined });
ccase('no-content', base({ action: { params: { other: TEXT } } }));
ccase('no-params', base({ action: {} }));
ccase('other-content', base({ action: { params: { text: 'something else' } } }));
ccase('label-not-in-set', (() => { const v = verdict(J[1], { label: 'sad' }); return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('measurement-pinned', base({ policy: { classifiers: [{ ...CL0, measurements: ['m-1'] }] } }));
ccase('measurement-not-pinned', base({ policy: { classifiers: [{ ...CL0, measurements: ['m-2'] }] } }));
ccase('measurement-empty-list', base({ policy: { classifiers: [{ ...CL0, measurements: [] }] } }));
ccase('two-from-one-judge', (() => { const v = verdict(J[0], { measurement: 'm-2' }); return base({ committed: [ref(V0), ref(v)], verdicts: [V0, v] }); })());
ccase('pq-keys-ed-verdict', base({ policy: { classifiers: [{ ...CL0, pq_keys: { [J[0].pk]: 'pqkey' } }] } }));
ccase('two-classifiers', (() => {
  const w0 = verdict(J[0], { classifier: 'risk', label: 'low', content_digest: pca.classifierContentDigest(42) });
  const CL1 = { id: 'risk', param: 'action.params.n.v', labels: ['low', 'high'], keys: [J[0].pk], k: 1 };
  return { session: SESSION, action: { params: { text: TEXT, n: { v: 42 } } }, committed: [ref(V0), ref(V1), ref(w0)], verdicts: [V0, V1, w0], policy: { classifiers: [CL0, CL1] } };
})());
ccase('content-number', (() => {
  const w0 = verdict(J[0], { content_digest: pca.classifierContentDigest(1) });
  return { session: SESSION, action: { params: { text: 1 } }, committed: [ref(w0)], verdicts: [w0], policy: { classifiers: [{ ...CL0, k: 1 }] } };
})());
ccase('content-object', (() => {
  const c = { b: [1, 'x'], a: true };
  const w0 = verdict(J[0], { content_digest: pca.classifierContentDigest(c) });
  return { session: SESSION, action: { params: { text: c } }, committed: [ref(w0)], verdicts: [w0], policy: { classifiers: [{ ...CL0, k: 1 }] } };
})());
ccase('content-null', (() => {
  const w0 = verdict(J[0], { content_digest: pca.classifierContentDigest(null) });
  return { session: SESSION, action: { params: { text: null } }, committed: [ref(w0)], verdicts: [w0], policy: { classifiers: [{ ...CL0, k: 1 }] } };
})());
// a signed verdict for the IntentArtifacts.verifyArtifactSig checks
add('sigfixture', 'verdict', [V0, J[0].pk, J[1].pk], true);

fs.writeFileSync(OUT, zlib.gzipSync(Buffer.from('[\n' + cases.map((c) => ser(c)).join(',\n') + '\n]\n', 'utf8'), { level: 9 }));
console.log(`wrote ${cases.length} cases to ${OUT}`);
