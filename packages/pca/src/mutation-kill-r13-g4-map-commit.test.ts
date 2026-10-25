/**
 * r13 mutation kills for intent-map-commit.ts (rule 19, the committed Intent Map and the Z0 disclosure).
 *
 * The leaf / node / commit hashes and the salt derivation are pinned against an INDEPENDENT construction (node:crypto,
 * a BigInt u64be, the RFC 6962 split) including sizes and indices past one byte; every shape refusal of the header, cell,
 * metrics, learner and disclosure leaves is pinned to its exact reason with the accepted boundary next to it; and each
 * step of decideMapDisclosure is reached on its own with HAND-BUILT commitments (the exported leaf hash, tree and commit
 * primitives), so a single condition of the cell match can fail while the leaf still opens. Every fixture is built
 * inside a test (Stryker activates a mutant only while a test runs).
 */
import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { b64u, canonicalBytesStrict, unb64u } from './hash';
import { paramsDigest } from './merkle';
import {
  MAX_MAP_LEAVES,
  commitMap,
  decideMapDisclosure,
  mapCellError as mapCellError0,
  mapCellOf as mapCellOf0,
  mapCommitOf,
  mapDisclosureError as mapDisclosureError0,
  mapHeaderError as mapHeaderError0,
  mapLeafHash,
  mapLeafSalt,
  mapLearnerError as mapLearnerError0,
  mapMetricsError as mapMetricsError0,
  mapNodeHash,
  mapNumCells as mapNumCells0,
  mapRootFromPath as mapRootFromPath0,
  mapTree,
  type CommittedMapInput,
  type MapDisclosure,
  type MapHeaderLeaf,
  type MapLeafKind,
  type MapNumDim,
} from './intent-map-commit';

/** Wraps a total function: a throw becomes the value 'THREW: <message>', so a mutant that makes it throw fails an assertion. */
const W =
  <A extends unknown[], R>(f: (...a: A) => R) =>
  (...a: A): R => {
    try {
      return f(...a);
    } catch (e) {
      return `THREW: ${(e as Error).message}` as unknown as R;
    }
  };
const mapCellError = W(mapCellError0);
const mapCellOf = W(mapCellOf0);
const mapDisclosureError = W(mapDisclosureError0);
const mapHeaderError = W(mapHeaderError0);
const mapLearnerError = W(mapLearnerError0);
const mapMetricsError = W(mapMetricsError0);
const mapNumCells = W(mapNumCells0);
const mapRootFromPath = W(mapRootFromPath0);

// ---- independent reference construction ---------------------------------------------------------------------------
const H = (...parts: (Uint8Array | string)[]) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? Buffer.from(p, 'utf8') : p);
  return new Uint8Array(h.digest());
};
const U64 = (n: number) => {
  const out = new Uint8Array(8);
  let x = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 255n);
    x >>= 8n;
  }
  return out;
};
const TAG: Record<MapLeafKind, string> = {
  header: 'atlas-pca/intent-map/header/v1\0',
  cell: 'atlas-pca/intent-map/cell/v1\0',
  metrics: 'atlas-pca/intent-map/metrics/v1\0',
  learner: 'atlas-pca/intent-map/learner/v1\0',
};
const refLeaf = (kind: MapLeafKind, salt: Uint8Array, leaf: unknown) => H(TAG[kind], salt, canonicalBytesStrict(leaf));
const refNode = (l: Uint8Array, r: Uint8Array) => H('atlas-pca/intent-map/node/v1\0', l, r);
const refRoot = (hs: Uint8Array[]): Uint8Array => {
  if (hs.length === 1) return hs[0]!;
  let k = 1;
  while (k * 2 < hs.length) k *= 2;
  return refNode(refRoot(hs.slice(0, k)), refRoot(hs.slice(k)));
};
const refPath = (hs: Uint8Array[], i: number): Uint8Array[] => {
  if (hs.length === 1) return [];
  let k = 1;
  while (k * 2 < hs.length) k *= 2;
  return i < k ? [...refPath(hs.slice(0, k), i), refRoot(hs.slice(k))] : [...refPath(hs.slice(k), i - k), refRoot(hs.slice(0, k))];
};
const refCommit = (size: number, root: Uint8Array) => b64u(H('atlas-pca/intent-map/commit/v1\0', U64(size), root));
const refSalt = (secret: Uint8Array, i: number) => H('atlas-pca/intent-map/salt/v1\0', secret, U64(i));

const SECRET = () => H('r13-g4-map-commit');
const METRICS = () => ({ residual_risk_ppm: 1200, burden_ppm: 3, uncertainty_ppm: 4, disagreement_ppm: 0, mean_harm_ppm: 10, fidelity_est_ppm: 990_000, entropy_mbits: 12, questions: 2, conflicts: 0 });
const LEARNER = () => b64u(H('learner'));
const OTHER = { kind: 'other' as const, value: '⊥' };
const RES = () => ({ kind: 'cat' as const, path: 'action.resource', values: [{ kind: 'exact' as const, value: 'r' }, OTHER] });
const KDIM = () => ({ kind: 'cat' as const, path: 'action.params.k', values: [{ kind: 'exact' as const, value: 'a' }, OTHER] });

/** A commitment over arbitrary leaves (built with the exported primitives, salts from mapLeafSalt). */
function hand(leaves: { kind: MapLeafKind; leaf: unknown }[]) {
  const salts = leaves.map((_, i) => mapLeafSalt(SECRET(), i));
  const hashes = leaves.map((l, i) => mapLeafHash(l.kind, salts[i]!, l.leaf));
  const t = mapTree(hashes);
  const size = leaves.length;
  const entry = (i: number) => ({ index: i, salt: b64u(salts[i]!), leaf: JSON.parse(JSON.stringify(leaves[i]!.leaf)), path: t.path(i) });
  return { size, commit: mapCommitOf(size, t.root), entry };
}
const header = (dims: unknown[], first: number, cells: number, verb = 'v') => ({ kind: 'header' as const, leaf: { verb, first, cells, dims } });
const cellL = (cell: number[], verb = 'v', in_grant = true, p_ppm = 900_000) => ({ kind: 'cell' as const, leaf: { verb, cell, p_ppm, in_grant } });
const metricsL = () => ({ kind: 'metrics' as const, leaf: METRICS() });
const learnerL = () => ({ kind: 'learner' as const, leaf: { learner_digest: LEARNER() } });
/** The base map: verb v, one cat dim on action.resource {r, other}; leaves header, cell [0], cell [1], metrics, learner. */
const base = () => hand([header([RES()], 1, 2), cellL([0]), cellL([1], 'v', false, 10), metricsL(), learnerL()]);
const disc = (m: ReturnType<typeof hand>, headerIdx: number, cellIdx: number, metricsIdx: number): MapDisclosure => ({
  size: m.size,
  header: m.entry(headerIdx),
  cell: m.entry(cellIdx),
  metrics: m.entry(metricsIdx),
});
const ACT = (resource: unknown = 'r', verb: unknown = 'v', params: unknown = {}) => ({ verb, resource, params_digest: paramsDigest(params) });
const no = (reason: string) => ({ ok: false, reason });

describe('hash construction against an independent reference', () => {
  it('leaf, node, commit and salt hashes, with sizes and indices past one byte', () => {
    const salt = refSalt(SECRET(), 0);
    for (const kind of ['header', 'cell', 'metrics', 'learner'] as const) expect(b64u(mapLeafHash(kind, salt, { a: 1 }))).toBe(b64u(refLeaf(kind, salt, { a: 1 })));
    const l = H('l');
    const r = H('r');
    expect(b64u(mapNodeHash(l, r))).toBe(b64u(refNode(l, r)));
    for (const n of [4, 255, 256, 300, 65_536, 16_777_216, 2 ** 40 + 7, 2 ** 53 - 1]) expect(mapCommitOf(n, l)).toBe(refCommit(n, l));
    for (const i of [0, 1, 255, 256, 300, 70_000, 2 ** 40 + 7, 2 ** 60, 2 ** 53 - 1]) expect(b64u(mapLeafSalt(SECRET(), i))).toBe(b64u(refSalt(SECRET(), i)));
  });
  it('the salt is 32 bytes', () => {
    expect(() => mapLeafHash('cell', new Uint8Array(31), {})).toThrow(new RangeError('mapLeafHash: the salt is 32 bytes'));
    expect(() => mapLeafHash('cell', new Uint8Array(33), {})).toThrow(new RangeError('mapLeafHash: the salt is 32 bytes'));
  });
  it('mapTree: empty is refused; root and paths match the reference', () => {
    expect(() => mapTree([])).toThrow(new RangeError('mapTree: empty'));
    for (const n of [1, 2, 3, 5, 8, 13]) {
      const hs = Array.from({ length: n }, (_, i) => H('h' + i));
      expect(b64u(mapTree(hs).root)).toBe(b64u(refRoot(hs)));
    }
  });
  it('commitMap equals the reference commitment over the rule 19 leaf order', () => {
    const input: CommittedMapInput = {
      headers: [{ verb: 'b', dims: [RES()] }, { verb: 'a', dims: [KDIM()] }],
      cells: { a: [{ cell: [0], p_ppm: 1, in_grant: true }, { cell: [1], p_ppm: 2, in_grant: false }], b: [{ cell: [0], p_ppm: 3, in_grant: true }, { cell: [1], p_ppm: 4, in_grant: false }] },
      metrics: METRICS(),
      learner_digest: LEARNER(),
    };
    const cm = commitMap(input, SECRET());
    const leaves: [MapLeafKind, unknown][] = [
      ['header', { verb: 'a', first: 2, cells: 2, dims: [KDIM()] }],
      ['header', { verb: 'b', first: 4, cells: 2, dims: [RES()] }],
      ['cell', { verb: 'a', cell: [0], p_ppm: 1, in_grant: true }],
      ['cell', { verb: 'a', cell: [1], p_ppm: 2, in_grant: false }],
      ['cell', { verb: 'b', cell: [0], p_ppm: 3, in_grant: true }],
      ['cell', { verb: 'b', cell: [1], p_ppm: 4, in_grant: false }],
      ['metrics', METRICS()],
      ['learner', { learner_digest: LEARNER() }],
    ];
    const hs = leaves.map(([k, l], i) => refLeaf(k, refSalt(SECRET(), i), l));
    expect(cm.map_commit).toBe(refCommit(8, refRoot(hs)));
    expect(cm.size).toBe(8);
    expect(cm.leaves).toEqual(leaves.map(([kind, leaf], i) => ({ kind, leaf, salt: b64u(refSalt(SECRET(), i)) })));
    // the caller's header list is not reordered
    expect(input.headers.map((h) => h.verb)).toEqual(['b', 'a']);
    // disclose: the right header for each verb, the action's cell, the metrics; paths are the reference audit paths
    const d = cm.disclose({ verb: 'b', resource: 'x' }, {});
    expect(d.size).toBe(8);
    expect(d.header).toEqual({ index: 1, salt: b64u(refSalt(SECRET(), 1)), leaf: leaves[1]![1], path: mapTree(hs).path(1) });
    expect(d.cell.index).toBe(5);
    expect(d.cell.leaf).toEqual(leaves[5]![1]);
    expect(d.metrics.index).toBe(6);
    expect(d.metrics.leaf).toEqual(METRICS());
    const r = mapRootFromPath(d.cell.index, 8, refLeaf('cell', unb64u(d.cell.salt), d.cell.leaf), d.cell.path.map(unb64u))!;
    expect(refCommit(8, r)).toBe(cm.map_commit);
    expect(cm.disclose({ verb: 'a', resource: 'x' }, { k: 'a' }).header.leaf.verb).toBe('a');
    expect(decideMapDisclosure({ mapCommit: cm.map_commit, action: ACT('r', 'b'), params: {}, disclosure: cm.disclose({ verb: 'b', resource: 'r' }, {}) })).toEqual({ ok: true, cell: [0], p_ppm: 3, residual_risk_ppm: 1200 });
  });
});

describe('mapRootFromPath bounds', () => {
  it('an index outside [0, size) is null even with an empty path', () => {
    const h = H('x');
    expect(mapRootFromPath(1, 1, h, [])).toBeNull();
    expect(mapRootFromPath(-1, 1, h, [])).toBeNull();
    expect(mapRootFromPath(5, 4, h, [h, h])).toBeNull();
    expect(b64u(mapRootFromPath(0, 1, h, [])!)).toBe(b64u(h));
  });
});

describe('mapNumCells', () => {
  const nd = (lo: number, hi: number, cuts: number[]): MapNumDim => ({ kind: 'num', path: 'action.params.n', lo, hi, cuts });
  it('exact cell lists', () => {
    expect(mapNumCells(nd(0, 10, []))).toEqual([[0, 10]]);
    expect(mapNumCells(nd(0, 10, [0]))).toEqual([[0, 0], [1, 10]]);
    expect(mapNumCells(nd(0, 10, [1]))).toEqual([[0, 0], [1, 1], [2, 10]]);
    expect(mapNumCells(nd(0, 10, [10]))).toEqual([[0, 9], [10, 10]]);
    expect(mapNumCells(nd(0, 10, [9]))).toEqual([[0, 8], [9, 9], [10, 10]]);
    expect(mapNumCells(nd(0, 10, [3, 4]))).toEqual([[0, 2], [3, 3], [4, 4], [5, 10]]);
    expect(mapNumCells(nd(5, 5, [5]))).toEqual([[5, 5]]);
  });
});

const H0 = (): MapHeaderLeaf => ({ verb: 'v', first: 1, cells: 2, dims: [RES()] });
const hdr = (patch: Record<string, unknown>) => mapHeaderError({ ...H0(), ...patch });
const withDim = (d: unknown, cells = 2) => hdr({ dims: [d], cells });
const NUM = () => ({ kind: 'num' as const, path: 'action.params.n', lo: 0, hi: 10, cuts: [5] });

describe('mapHeaderError', () => {
  it('the closed member set', () => {
    expect(mapHeaderError(H0())).toBeNull();
    const { dims: _d, ...noDims } = H0();
    void _d;
    for (const h of [null, 5, [], { ...H0(), x: 1 }, noDims]) expect(mapHeaderError(h)).toBe('the header leaf must be exactly {verb, first, cells, dims}');
  });
  it('verb', () => {
    for (const verb of ['', 5, 'x'.repeat(129), 'é'.repeat(64) + 'a', '\uD800']) expect(hdr({ verb })).toBe('header.verb must be a non-empty string of at most 128 UTF-8 bytes');
    expect(hdr({ verb: 'x'.repeat(128) })).toBeNull();
    expect(hdr({ verb: 'é'.repeat(64) })).toBeNull();
  });
  it('first', () => {
    for (const first of [-1, 1.5, MAX_MAP_LEAVES, '1']) expect(hdr({ first })).toBe('header.first must be a leaf index');
    expect(hdr({ first: MAX_MAP_LEAVES - 1 })).toBeNull();
    expect(hdr({ first: 0 })).toBeNull();
  });
  it('cells', () => {
    for (const cells of [0, -1, 1.5, 2 ** 20 + 1, '2']) expect(hdr({ cells })).toBe('header.cells must be a safe integer in [1, 1048576]');
    expect(hdr({ cells: 1, dims: [] })).toBeNull();
    expect(hdr({ cells: 3 })).toBe("header.cells is not the product of the dimensions' cell counts");
    const vals = (n: number) => [...Array.from({ length: n - 1 }, (_, i) => ({ kind: 'exact' as const, value: `v${i}` })), OTHER];
    const big = [256, 256, 16].map((n, j) => ({ kind: 'cat' as const, path: `action.params.p${j}`, values: vals(n) }));
    expect(hdr({ cells: 2 ** 20, dims: big })).toBeNull();
    expect(hdr({ cells: 2 ** 20, dims: [...big, { kind: 'cat', path: 'action.params.q', values: vals(2) }] })).toBe('header: too many cells');
  });
  it('dims', () => {
    for (const dims of ['x', {}, null]) expect(hdr({ dims })).toBe('header.dims must be an array of at most 16');
    const one = (j: number) => ({ kind: 'cat' as const, path: `action.params.p${j}`, values: [OTHER] });
    expect(hdr({ cells: 1, dims: Array.from({ length: 16 }, (_, j) => one(j)) })).toBeNull();
    expect(hdr({ cells: 1, dims: Array.from({ length: 17 }, (_, j) => one(j)) })).toBe('header.dims must be an array of at most 16');
    expect(hdr({ cells: 4, dims: [RES(), RES()] })).toBe('header.dims paths must be distinct');
    expect(hdr({ cells: 4, dims: [RES(), KDIM()] })).toBeNull();
    expect(hdr({ cells: 2, dims: [KDIM(), 5] })).toBe('header.dims[1] must be an object');
    expect(hdr({ dims: [5] })).toBe('header.dims[0] must be an object');
    expect(withDim({ ...RES(), kind: 'x' })).toBe('header.dims[0].kind must be num or cat');
  });
  it('numeric dimensions', () => {
    expect(withDim(NUM(), 3)).toBeNull();
    const { cuts: _c, ...noCuts } = NUM();
    void _c;
    for (const d of [{ ...NUM(), x: 1 }, noCuts]) expect(withDim(d, 3)).toBe('header.dims[0] must be exactly {kind, path, lo, hi, cuts}');
    for (const path of ['action.resource', 'x', 'xaction.params.n', 'action.params.n.x', 'action.params.', 'action.params.a-b', 'action.params.' + 'a'.repeat(65), ['action.params.n'], 5]) {
      expect(withDim({ ...NUM(), path }, 3)).toBe('header.dims[0].path must be action.params.<name>');
    }
    expect(withDim({ ...NUM(), path: 'action.params.' + 'a'.repeat(64) }, 3)).toBeNull();
    for (const lohi of [{ lo: 5, hi: 1, cuts: [] }, { lo: '0' }, { hi: 1.5 }, { lo: -0 }]) expect(withDim({ ...NUM(), ...lohi }, 3)).toBe('header.dims[0] lo / hi must be safe integers with lo <= hi');
    expect(withDim({ ...NUM(), lo: 5, hi: 5, cuts: [] }, 1)).toBeNull();
    expect(withDim({ ...NUM(), cuts: 'x' }, 3)).toBe('header.dims[0].cuts must be an array of at most 256');
    expect(withDim({ ...NUM(), hi: 1000, cuts: Array.from({ length: 257 }, (_, i) => i * 2 + 1) }, 515)).toBe('header.dims[0].cuts must be an array of at most 256');
    expect(withDim({ ...NUM(), hi: 1000, cuts: Array.from({ length: 256 }, (_, i) => i * 2 + 1) }, 513)).toBeNull();
    const cutsErr = 'header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]';
    for (const cuts of [['5'], [5, 5], [5, 3], [-1], [11], [1.5]]) expect(withDim({ ...NUM(), cuts }, 3)).toBe(cutsErr);
    expect(withDim({ ...NUM(), lo: 2, cuts: [1] }, 3)).toBe(cutsErr);
    expect(withDim({ ...NUM(), cuts: [0] }, 2)).toBeNull();
    expect(withDim({ ...NUM(), cuts: [10] }, 2)).toBeNull();
    expect(withDim({ ...NUM(), cuts: [3, 4] }, 4)).toBeNull();
  });
  it('categorical dimensions', () => {
    const { values: _v, ...noValues } = RES();
    void _v;
    for (const d of [{ ...RES(), x: 1 }, noValues]) expect(withDim(d)).toBe('header.dims[0] must be exactly {kind, path, values}');
    for (const path of ['x', 'xaction.params.x', 'action.params.x ', 'action.params.', ['action.params.x'], 5]) expect(withDim({ ...RES(), path })).toBe('header.dims[0].path must be action.resource or action.params.<name>');
    expect(withDim({ ...RES(), path: 'action.params.x' })).toBeNull();
    for (const values of ['x', [], null]) expect(withDim({ ...RES(), values })).toBe('header.dims[0].values must be an array of 1..256');
    const many = (n: number) => [...Array.from({ length: n - 1 }, (_, i) => ({ kind: 'exact' as const, value: `v${i}` })), OTHER];
    expect(withDim({ ...RES(), values: many(257) }, 257)).toBe('header.dims[0].values must be an array of 1..256');
    expect(withDim({ ...RES(), values: many(256) }, 256)).toBeNull();
    expect(withDim({ ...RES(), values: [OTHER] }, 1)).toBeNull();
    const vs = (values: unknown[], cells = values.length) => withDim({ ...RES(), values }, cells);
    for (const v of [5, null, { kind: 'exact', value: 'a', x: 1 }, { kind: 'exact' }]) expect(vs([{ kind: 'exact', value: 'b' }, v, OTHER])).toBe('header.dims[0].values[1] must be exactly {kind, value}');
    expect(vs([{ kind: 'bad', value: 'a' }, OTHER])).toBe('header.dims[0].values[0].kind must be exact, prefix or other');
    for (const value of [5, 'x'.repeat(257), '\uD800']) expect(vs([{ kind: 'exact', value }, OTHER])).toBe('header.dims[0].values[0].value must be a string of at most 256 UTF-8 bytes');
    expect(vs([{ kind: 'exact', value: 'x'.repeat(256) }, OTHER])).toBeNull();
    const oneOther = "header.dims[0].values: exactly one other ('⊥'), last; prefixes non-empty";
    expect(vs([OTHER, { kind: 'exact', value: 'a' }])).toBe(oneOther);
    expect(vs([OTHER, OTHER])).toBe(oneOther);
    expect(vs([{ kind: 'exact', value: 'a' }, { kind: 'other', value: 'x' }])).toBe(oneOther);
    expect(vs([{ kind: 'prefix', value: '' }, OTHER])).toBe(oneOther);
    expect(vs([{ kind: 'exact', value: '' }, { kind: 'prefix', value: 'a' }, OTHER])).toBeNull();
    expect(vs([{ kind: 'exact', value: 'a' }, { kind: 'exact', value: 'a' }, OTHER])).toBe('header.dims[0].values must be distinct');
    expect(vs([{ kind: 'prefix', value: 'a' }, { kind: 'prefix', value: 'a' }, OTHER])).toBe('header.dims[0].values must be distinct');
    expect(vs([{ kind: 'exact', value: 'a' }, { kind: 'prefix', value: 'a' }, OTHER])).toBeNull();
    expect(vs([{ kind: 'exact', value: 'a' }])).toBe('header.dims[0].values must end with the other value');
  });
});

describe('mapCellError / mapMetricsError / mapLearnerError', () => {
  const C0 = () => ({ verb: 'v', cell: [0, 1], p_ppm: 5, in_grant: false });
  it('cell leaves', () => {
    expect(mapCellError(C0())).toBeNull();
    const { in_grant: _g, ...noG } = C0();
    void _g;
    for (const c of [null, 5, [], { ...C0(), x: 1 }, noG]) expect(mapCellError(c)).toBe('the cell leaf must be exactly {verb, cell, p_ppm, in_grant}');
    for (const verb of ['', 5, 'x'.repeat(129)]) expect(mapCellError({ ...C0(), verb })).toBe('cell.verb must be a non-empty string of at most 128 UTF-8 bytes');
    expect(mapCellError({ ...C0(), verb: 'x'.repeat(128) })).toBeNull();
    for (const cell of ['x', null, [-1], [0, -1], [1.5], ['0'], Array(17).fill(0)]) expect(mapCellError({ ...C0(), cell })).toBe('cell.cell must be an array of non-negative safe integers');
    expect(mapCellError({ ...C0(), cell: Array(16).fill(0) })).toBeNull();
    expect(mapCellError({ ...C0(), cell: [] })).toBeNull();
    for (const p_ppm of [-1, 1_000_001, 1.5, '5']) expect(mapCellError({ ...C0(), p_ppm })).toBe('cell.p_ppm must be a safe integer in [0, 1000000]');
    for (const p_ppm of [0, 1_000_000]) expect(mapCellError({ ...C0(), p_ppm })).toBeNull();
    for (const in_grant of [1, 'true', null]) expect(mapCellError({ ...C0(), in_grant })).toBe('cell.in_grant must be a boolean');
    expect(mapCellError({ ...C0(), in_grant: true })).toBeNull();
  });
  it('metrics leaves', () => {
    const all = 'the metrics leaf must be exactly {residual_risk_ppm, burden_ppm, uncertainty_ppm, disagreement_ppm, mean_harm_ppm, fidelity_est_ppm, entropy_mbits, questions, conflicts, log2_vs_mbits?}';
    expect(mapMetricsError(METRICS())).toBeNull();
    expect(mapMetricsError({ ...METRICS(), log2_vs_mbits: 0 })).toBeNull();
    const { conflicts: _c, ...noC } = METRICS();
    void _c;
    for (const m of [null, 5, [], { ...METRICS(), x: 1 }, noC]) expect(mapMetricsError(m)).toBe(all);
    for (const k of Object.keys(METRICS())) {
      for (const bad of [-1, 1.5, '1', null, undefined]) expect(mapMetricsError({ ...METRICS(), [k]: bad })).toBe(`metrics.${k} must be a non-negative safe integer`);
    }
    for (const bad of [-1, null, '1']) expect(mapMetricsError({ ...METRICS(), log2_vs_mbits: bad })).toBe('metrics.log2_vs_mbits must be a non-negative safe integer');
  });
  it('learner leaves', () => {
    expect(mapLearnerError({ learner_digest: LEARNER() })).toBeNull();
    for (const l of [null, 5, {}, { learner_digest: LEARNER(), x: 1 }]) expect(mapLearnerError(l)).toBe('the learner leaf must be exactly {learner_digest}');
    expect(mapLearnerError({ learner_digest: 'x' })).toBe('learner.learner_digest must be canonical base64url (32 bytes)');
  });
});

describe('mapCellOf', () => {
  const book = (): MapHeaderLeaf => ({
    verb: 'air.book',
    first: 2,
    cells: 9,
    dims: [
      { kind: 'num', path: 'action.params.total', lo: 0, hi: 100_000, cuts: [40_000] },
      { kind: 'cat', path: 'action.resource', values: [{ kind: 'exact', value: 'skyair.example/bookings' }, { kind: 'prefix', value: 'skyair.example/' }, OTHER] },
    ],
  });
  it('numeric cells: each range, both edges', () => {
    const at = (total: unknown) => mapCellOf(book(), 'skyair.example/bookings', { total });
    expect(at(0)).toEqual({ cell: [0, 0], flat: 0 });
    expect(at(39_999)).toEqual({ cell: [0, 0], flat: 0 });
    expect(at(40_000)).toEqual({ cell: [1, 0], flat: 3 });
    expect(at(50_000)).toEqual({ cell: [2, 0], flat: 6 });
    expect(at(100_000)).toEqual({ cell: [2, 0], flat: 6 });
    for (const t of [100_001, -1, 1.5, '5', undefined]) expect(at(t)).toEqual({ error: "the action's action.params.total lies outside the committed map's dimension" });
    expect(mapCellOf(book(), 'r', 5)).toEqual({ error: "the action's action.params.total lies outside the committed map's dimension" });
    expect(mapCellOf(book(), 'r', Object.defineProperty({}, 'total', { get: () => 1 }))).toEqual({ error: "the action's action.params.total lies outside the committed map's dimension" });
  });
  it('categorical cells: exact > longest prefix > other; non-strings fail closed', () => {
    const at = (r: unknown) => mapCellOf(book(), r, { total: 1 });
    expect(at('skyair.example/bookings')).toEqual({ cell: [0, 0], flat: 0 });
    expect(at('skyair.example/x')).toEqual({ cell: [0, 1], flat: 1 });
    expect(at('evil.example')).toEqual({ cell: [0, 2], flat: 2 });
    for (const r of [5, undefined, null, '\uD800']) expect(at(r)).toEqual({ error: "the action's action.resource lies outside the committed map's dimension" });
    const h = (values: { kind: 'exact' | 'prefix' | 'other'; value: string }[]): MapHeaderLeaf => ({ verb: 'v', first: 1, cells: values.length, dims: [{ kind: 'cat', path: 'action.resource', values }] });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, OTHER]), 'ab', {})).toEqual({ cell: [0], flat: 0 });
    expect(mapCellOf(h([{ kind: 'exact', value: 'x' }, { kind: 'exact', value: 'y' }, OTHER]), 'y', {})).toEqual({ cell: [1], flat: 1 });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'ab' }, { kind: 'prefix', value: 'a' }, OTHER]), 'abc', {})).toEqual({ cell: [0], flat: 0 });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, { kind: 'prefix', value: 'ab' }, OTHER]), 'abc', {})).toEqual({ cell: [1], flat: 1 });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, { kind: 'prefix', value: 'b' }, OTHER]), 'ax', {})).toEqual({ cell: [0], flat: 0 });
    // an unvalidated header with equal prefixes: the FIRST longest wins
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, { kind: 'prefix', value: 'a' }, OTHER]), 'ab', {})).toEqual({ cell: [0], flat: 0 });
    expect(mapCellOf(h([{ kind: 'exact', value: 'ab' }, { kind: 'prefix', value: 'a' }, OTHER]), 'ab', {})).toEqual({ cell: [0], flat: 0 });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, { kind: 'exact', value: 'ab' }, OTHER]), 'ab', {})).toEqual({ cell: [1], flat: 1 });
    // an exact value is never read as a prefix, and a prefix equal to the value is not an exact match
    expect(mapCellOf(h([{ kind: 'exact', value: 'a' }, OTHER]), 'ab', {})).toEqual({ cell: [1], flat: 1 });
    expect(mapCellOf(h([{ kind: 'prefix', value: 'a' }, { kind: 'exact', value: 'a' }, OTHER]), 'a', {})).toEqual({ cell: [1], flat: 1 });
  });
});

describe('mapDisclosureError', () => {
  const D = () => disc(base(), 0, 1, 3);
  it('the closed disclosure and its size', () => {
    expect(mapDisclosureError(D())).toBeNull();
    const { metrics: _m, ...noM } = D();
    void _m;
    for (const d of [null, 5, [], { ...D(), x: 1 }, noM]) expect(mapDisclosureError(d)).toBe('the disclosure must be exactly {size, header, cell, metrics}');
    for (const size of [3, 1.5, MAX_MAP_LEAVES + 1, '5', -0]) expect(mapDisclosureError({ ...D(), size })).toBe('disclosure.size must be a safe integer in [4, 16777216]');
    for (const size of [4, MAX_MAP_LEAVES]) expect(mapDisclosureError({ ...D(), size })).toBeNull();
  });
  it('each entry', () => {
    const d = D();
    for (const k of ['header', 'cell', 'metrics'] as const) {
      const { path: _p, ...noPath } = d[k];
      void _p;
      for (const e of [null, 5, { ...d[k], x: 1 }, noPath]) expect(mapDisclosureError({ ...d, [k]: e })).toBe(`disclosure.${k} must be exactly {index, salt, leaf, path}`);
      for (const index of [-1, 1.5, '1']) expect(mapDisclosureError({ ...d, [k]: { ...d[k], index } })).toBe(`disclosure.${k}.index must be a non-negative safe integer`);
      expect(mapDisclosureError({ ...d, [k]: { ...d[k], salt: 'x' } })).toBe(`disclosure.${k}.salt must be canonical base64url (32 bytes)`);
      const good = d[k].path[0]!;
      for (const path of ['x', ['x'], [good, 'x'], Array(65).fill(good)]) expect(mapDisclosureError({ ...d, [k]: { ...d[k], path } })).toBe(`disclosure.${k}.path must be an array of 32-byte digests`);
      expect(mapDisclosureError({ ...d, [k]: { ...d[k], path: Array(64).fill(good) } })).toBeNull();
      expect(mapDisclosureError({ ...d, [k]: { ...d[k], path: [] } })).toBeNull();
    }
  });
  it('the leaves, in order header, cell, metrics', () => {
    const d = D();
    const leaf = (k: 'header' | 'cell' | 'metrics', l: unknown) => ({ [k]: { ...d[k], leaf: l } });
    expect(mapDisclosureError({ ...d, ...leaf('header', { ...d.header.leaf, cells: 0 }) })).toBe('header.cells must be a safe integer in [1, 1048576]');
    expect(mapDisclosureError({ ...d, ...leaf('header', { ...d.header.leaf, cells: 0 }), ...leaf('cell', null) })).toBe('header.cells must be a safe integer in [1, 1048576]');
    expect(mapDisclosureError({ ...d, ...leaf('cell', { ...d.cell.leaf, p_ppm: -1 }) })).toBe('cell.p_ppm must be a safe integer in [0, 1000000]');
    expect(mapDisclosureError({ ...d, ...leaf('cell', { ...d.cell.leaf, p_ppm: -1 }), ...leaf('metrics', null) })).toBe('cell.p_ppm must be a safe integer in [0, 1000000]');
    expect(mapDisclosureError({ ...d, ...leaf('metrics', { ...d.metrics.leaf, questions: -1 }) })).toBe('metrics.questions must be a non-negative safe integer');
  });
});

describe('decideMapDisclosure, one step at a time', () => {
  const run = (m: ReturnType<typeof hand>, d: unknown, extra: Partial<Parameters<typeof decideMapDisclosure>[0]> = {}) =>
    decideMapDisclosure({ mapCommit: m.commit, action: ACT(), params: {}, disclosure: d, ...extra });
  it('admits; params may be absent (= {})', () => {
    const m = base();
    expect(run(m, disc(m, 0, 1, 3))).toEqual({ ok: true, cell: [0], p_ppm: 900_000, residual_risk_ppm: 1200 });
    expect(run(m, disc(m, 0, 1, 3), { params: undefined })).toEqual({ ok: true, cell: [0], p_ppm: 900_000, residual_risk_ppm: 1200 });
    expect(run(m, disc(m, 0, 1, 3), { maxResidualRiskPpm: 1200 })).toEqual({ ok: true, cell: [0], p_ppm: 900_000, residual_risk_ppm: 1200 });
  });
  it('steps 1-2: malformed disclosure, commitment, params', () => {
    const m = base();
    const d = disc(m, 0, 1, 3);
    expect(run(m, null)).toEqual(no('map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}'));
    expect(run(m, { ...d, size: 3 })).toEqual(no('map disclosure malformed: disclosure.size must be a safe integer in [4, 16777216]'));
    expect(run(m, d, { mapCommit: 'x' })).toEqual(no('the PCActn carries no map commitment'));
    expect(run(m, d, { mapCommit: undefined })).toEqual(no('the PCActn carries no map commitment'));
    for (const params of [5, 'p', [], null]) expect(run(m, d, { params })).toEqual(no('params must be an object'));
    expect(run(m, d, { params: { a: 1 } })).toEqual(no('the params do not hash to action.params_digest'));
  });
  it('step 3: verb and layout', () => {
    const m = base();
    const d = disc(m, 0, 1, 3);
    expect(run(m, d, { action: ACT('r', 'w') })).toEqual(no("the disclosed header is not the action's verb"));
    expect(run(m, { ...d, header: { ...d.header, index: 1 } })).toEqual(no('the disclosed header does not fit the committed layout'));
    expect(run(m, { ...d, header: { ...d.header, index: 2 } })).toEqual(no('the disclosed header does not fit the committed layout'));
    expect(run(m, { ...d, size: 4 })).toEqual(no('the disclosed header does not fit the committed layout'));
    // header first + cells == size - 2 exactly is the committed layout (accepted above); one leaf short is not
    const tight = hand([header([RES()], 1, 2), cellL([0]), cellL([1]), metricsL()]);
    expect(run(tight, { size: 4, header: tight.entry(0), cell: tight.entry(1), metrics: tight.entry(3) })).toEqual(no('the disclosed header does not fit the committed layout'));
  });
  it('step 4: each leaf must open', () => {
    const m = base();
    const d = disc(m, 0, 1, 3);
    const s = m.entry(4).salt;
    expect(run(m, { ...d, header: { ...d.header, salt: s } })).toEqual(no('the header leaf does not open the map commitment'));
    expect(run(m, { ...d, header: { ...d.header, path: d.header.path.slice(1) } })).toEqual(no('the header leaf does not open the map commitment'));
    expect(run(m, { ...d, header: { ...d.header, path: [...d.header.path, d.header.path[0]!] } })).toEqual(no('the header leaf does not open the map commitment'));
    expect(run(m, { ...d, cell: { ...d.cell, salt: s } })).toEqual(no('the cell leaf does not open the map commitment'));
    expect(run(m, { ...d, cell: { ...d.cell, path: [] } })).toEqual(no('the cell leaf does not open the map commitment'));
    expect(run(m, { ...d, metrics: { ...d.metrics, salt: s } })).toEqual(no('the metrics leaf does not open the map commitment'));
    expect(run(m, { ...d, metrics: { ...d.metrics, path: [] } })).toEqual(no('the metrics leaf does not open the map commitment'));
    // the right leaf against the wrong size
    expect(run(m, { ...d, size: 6 })).toEqual(no('the header leaf does not open the map commitment'));
  });
  it("step 5: the action's own cell", () => {
    const m = base();
    expect(run(m, disc(m, 0, 1, 3), { action: ACT(5) })).toEqual(no("the action's action.resource lies outside the committed map's dimension"));
    const notMine = no("the disclosed cell is not the action's cell");
    // the genuine leaf of another cell
    expect(run(m, disc(m, 0, 2, 3))).toEqual(notMine);
    // only the index differs (the leaf at flat 1 claims cell [0])
    const m1 = hand([header([RES()], 1, 2), cellL([0]), cellL([0]), metricsL(), learnerL()]);
    expect(run(m1, disc(m1, 0, 1, 3)).ok).toBe(true);
    expect(run(m1, disc(m1, 0, 2, 3))).toEqual(notMine);
    // only the verb differs
    const m2 = hand([header([RES()], 1, 2), cellL([0], 'w'), cellL([1]), metricsL(), learnerL()]);
    expect(run(m2, disc(m2, 0, 1, 3))).toEqual(notMine);
    // only the length differs
    const m3 = hand([header([RES()], 1, 2), cellL([]), cellL([1]), metricsL(), learnerL()]);
    expect(run(m3, disc(m3, 0, 1, 3))).toEqual(notMine);
    // only a coordinate differs (one dimension, then the second of two)
    const m4 = hand([header([RES()], 1, 2), cellL([1]), cellL([1]), metricsL(), learnerL()]);
    expect(run(m4, disc(m4, 0, 1, 3))).toEqual(notMine);
    const two = [RES(), KDIM()];
    const m5 = hand([header(two, 1, 4), cellL([0, 1]), cellL([0, 1]), cellL([1, 0]), cellL([1, 1]), metricsL(), learnerL()]);
    expect(run(m5, disc(m5, 0, 1, 5), { action: ACT('r', 'v', { k: 'a' }), params: { k: 'a' } })).toEqual(notMine);
    const m6 = hand([header(two, 1, 4), cellL([0, 0]), cellL([0, 1]), cellL([1, 0]), cellL([1, 1]), metricsL(), learnerL()]);
    expect(run(m6, disc(m6, 0, 1, 5), { action: ACT('r', 'v', { k: 'a' }), params: { k: 'a' } })).toEqual({ ok: true, cell: [0, 0], p_ppm: 900_000, residual_risk_ppm: 1200 });
    expect(run(m6, disc(m6, 0, 2, 5), { action: ACT('r', 'v', { k: 'b' }), params: { k: 'b' } })).toEqual({ ok: true, cell: [0, 1], p_ppm: 900_000, residual_risk_ppm: 1200 });
  });
  it('steps 6-7: grant, metrics position, ε', () => {
    const m = base();
    expect(run(m, disc(m, 0, 2, 3), { action: ACT('x') })).toEqual(no("the action's cell is outside the committed grant"));
    // a metrics-shaped leaf committed at the learner position
    const mm = hand([header([{ kind: 'cat', path: 'action.resource', values: [OTHER] }], 1, 1), cellL([0]), learnerL(), metricsL()]);
    expect(run(mm, disc(mm, 0, 1, 3))).toEqual(no('the disclosed metrics leaf is not at its committed position'));
    expect(run(m, disc(m, 0, 1, 3), { maxResidualRiskPpm: 1199 })).toEqual(no('the committed residual risk 1200 ppm exceeds ε = 1199'));
  });
  it('a leaf that throws while it is opened does not open (and is never admitted)', () => {
    const m = base();
    const d = disc(m, 0, 1, 3);
    let reads = 0;
    const leaf = { ...d.cell.leaf };
    Object.defineProperty(leaf, 'in_grant', {
      enumerable: true,
      get: () => {
        reads++;
        if (reads > 1) throw new Error('second read');
        return true;
      },
    });
    expect(run(m, { ...d, cell: { ...d.cell, leaf } })).toEqual(no('the cell leaf does not open the map commitment'));
  });
  it('the catch fails closed', () => {
    const m = base();
    const r = decideMapDisclosure({ mapCommit: m.commit, action: null as never, params: {}, disclosure: disc(m, 0, 1, 3) });
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/^map error \(fail closed\): \S/) });
  });
});

describe('commitMap builder refusals', () => {
  const IN = (): CommittedMapInput => ({ headers: [{ verb: 'v', dims: [RES()] }], cells: { v: [{ cell: [0], p_ppm: 1, in_grant: true }, { cell: [1], p_ppm: 2, in_grant: false }] }, metrics: METRICS(), learner_digest: LEARNER() });
  it('secret, duplicate verbs, cell counts, malformed leaves, leaf count', () => {
    expect(W(() => commitMap(IN(), SECRET()).size)()).toBe(5);
    expect(W(() => commitMap({ ...IN(), headers: [{ verb: 'w', dims: [RES()] }, ...IN().headers], cells: { ...IN().cells, w: IN().cells.v! } }, SECRET()).size)()).toBe(8);
    expect(() => commitMap(IN(), new Uint8Array(31))).toThrow(new RangeError('commitMap: the secret is 32 bytes'));
    expect(() => commitMap({ ...IN(), headers: [{ verb: 'v', dims: [RES()] }, { verb: 'v', dims: [KDIM()] }] }, SECRET())).toThrow(new Error('commitMap: duplicate verb'));
    expect(() => commitMap({ ...IN(), cells: {} }, SECRET())).toThrow(new Error('commitMap: verb v needs 2 cell leaves'));
    expect(() => commitMap({ ...IN(), cells: { v: [{ cell: [0], p_ppm: 1, in_grant: true }] } }, SECRET())).toThrow(new Error('commitMap: verb v needs 2 cell leaves'));
    expect(() => commitMap({ ...IN(), metrics: { ...METRICS(), questions: -1 } }, SECRET())).toThrow(new Error('commitMap: metrics.questions must be a non-negative safe integer'));
    expect(() => commitMap({ ...IN(), learner_digest: 'x' }, SECRET())).toThrow(new Error('commitMap: learner.learner_digest must be canonical base64url (32 bytes)'));
    expect(() => commitMap({ ...IN(), headers: [], cells: {} }, SECRET())).toThrow(new Error('commitMap: the map has too few or too many leaves'));
    expect(settle(() => commitMap({ ...IN(), headers: [{ verb: 'v', dims: [{ kind: 'cat', path: 'action.resource', values: [OTHER] }] }], cells: { v: [{ cell: [0], p_ppm: 1, in_grant: true }] } }, SECRET()).size)).toEqual({ ok: true, value: 4 });
    const one = commitMap({ ...IN(), headers: [{ verb: 'v', dims: [{ kind: 'cat', path: 'action.resource', values: [OTHER] }] }], cells: { v: [{ cell: [0], p_ppm: 1, in_grant: true }] } }, SECRET());
    expect(one.size).toBe(4);
    expect(one.leaves.map((l) => l.kind)).toEqual(['header', 'cell', 'metrics', 'learner']);
  });
  it('disclose refuses an unknown verb and an action outside the map', () => {
    const cm = commitMap({ ...IN(), headers: [{ verb: 'v', dims: [{ kind: 'num', path: 'action.params.n', lo: 0, hi: 1, cuts: [] }] }], cells: { v: [{ cell: [0], p_ppm: 1, in_grant: true }] } }, SECRET());
    expect(() => cm.disclose({ verb: 'w' }, {})).toThrow(new Error('commitMap.disclose: verb w is not in the map'));
    expect(() => cm.disclose({ verb: 'v' }, { n: 2 })).toThrow(new Error("commitMap.disclose: the action's action.params.n lies outside the committed map's dimension"));
    expect(settle(() => {
      const d = cm.disclose({ verb: 'v' }, { n: 1 });
      return [d.size, d.header.index, d.cell.index, d.metrics.index, d.metrics.leaf];
    })).toEqual({ ok: true, value: [4, 0, 1, 2, METRICS()] });
  });
});

/**
 * The MAX_MAP_LEAVES cap of commitMap (2^24 leaves) needs ~16.8M leaf objects, too heavy for CI: run on a large box with
 * PCA_HEAVY_MAP_CAP=1 (and node --max-old-space-size >= 12000). A secret whose bytes throw on read marks "past the cap
 * check" (the salts are derived right after it), so the test never hashes 16M leaves.
 */
describe.skipIf(process.env.PCA_HEAVY_MAP_CAP !== '1')('commitMap leaf cap (heavy, gated)', () => {
  const PAST = 'past the leaf-count check';
  const trapSecret = () =>
    new Proxy(new Uint8Array(32), {
      get(t, k) {
        if (k === 'length') return 32;
        if (typeof k === 'string' && /^\d+$/.test(k)) throw new Error(PAST);
        return Reflect.get(t, k);
      },
    }) as Uint8Array;
  // verbs of 2^20 cells (cat dims 256 x 256 x 16), then one 2-cell verb and n one-cell verbs, so total = target
  const vals = (n: number) => [...Array.from({ length: n - 1 }, (_, i) => ({ kind: 'exact' as const, value: `v${i}` })), OTHER];
  const big = [256, 256, 16].map((n, j) => ({ kind: 'cat' as const, path: `action.params.p${j}`, values: vals(n) }));
  const input = (target: number): CommittedMapInput => {
    const cell = { cell: [0], p_ppm: 1, in_grant: true };
    const headers: CommittedMapInput['headers'] = [];
    const cells: CommittedMapInput['cells'] = {};
    for (let i = 0; i < 15; i++) {
      headers.push({ verb: `big${i}`, dims: big });
      cells[`big${i}`] = new Array(2 ** 20).fill(cell);
    }
    let used = 15 * (2 ** 20 + 1) + 2;
    if ((target - used) % 2 === 1) {
      headers.push({ verb: 'two', dims: [RES()] });
      cells.two = [cell, cell];
      used += 3;
    }
    for (let i = 0; used < target; i++, used += 2) {
      headers.push({ verb: `one${i}`, dims: [{ kind: 'cat', path: 'action.resource', values: [OTHER] }] });
      cells[`one${i}`] = [cell];
    }
    expect(used).toBe(target);
    return { headers, cells, metrics: METRICS(), learner_digest: LEARNER() };
  };
  it('exactly MAX_MAP_LEAVES leaves pass the cap', () => {
    expect(() => commitMap(input(MAX_MAP_LEAVES), trapSecret())).toThrow(new Error(PAST));
  }, 600_000);
  it('MAX_MAP_LEAVES + 1 leaves are refused', () => {
    expect(() => commitMap(input(MAX_MAP_LEAVES + 1), trapSecret())).toThrow(new Error('commitMap: the map has too few or too many leaves'));
  }, 600_000);
});

/** A computation's outcome for toEqual: a throw becomes { ok: false, error: { name, message } }. */
const settle = <T>(f: () => T): { ok: true; value: T } | { ok: false; error: { name: string; message: string } } => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: { name: (e as Error).name, message: (e as Error).message } };
  }
};

describe('published constants (fresh module)', () => {
  it('tags, map form, other value, limits, metric fields', async () => {
    vi.resetModules();
    const m = await import('./intent-map-commit');
    expect([m.MAP_TAG_HEADER, m.MAP_TAG_CELL, m.MAP_TAG_METRICS, m.MAP_TAG_LEARNER, m.MAP_TAG_NODE, m.MAP_TAG_COMMIT, m.MAP_TAG_SALT]).toEqual([
      'atlas-pca/intent-map/header/v1\0',
      'atlas-pca/intent-map/cell/v1\0',
      'atlas-pca/intent-map/metrics/v1\0',
      'atlas-pca/intent-map/learner/v1\0',
      'atlas-pca/intent-map/node/v1\0',
      'atlas-pca/intent-map/commit/v1\0',
      'atlas-pca/intent-map/salt/v1\0',
    ]);
    expect([m.MAP_FORM_COMMIT, m.MAP_OTHER]).toEqual(['commit', '⊥']);
    expect([m.MAX_MAP_LEAVES, m.MAX_VERB_CELLS, m.MAX_MAP_DIMS, m.MAX_MAP_CUTS, m.MAX_MAP_VALUES, m.MAX_MAP_STRING_BYTES]).toEqual([2 ** 24, 2 ** 20, 16, 256, 256, 256]);
    expect(m.MAP_METRIC_FIELDS).toEqual(['residual_risk_ppm', 'burden_ppm', 'uncertainty_ppm', 'disagreement_ppm', 'mean_harm_ppm', 'fidelity_est_ppm', 'entropy_mbits', 'questions', 'conflicts']);
  });
});

describe('tree and audit paths, every index for sizes 1..33 (outcomes compared, never thrown)', () => {
  it('mapTree root and paths equal the reference; mapRootFromPath recomputes the root', () => {
    for (let n = 1; n <= 33; n++) {
      const hs = Array.from({ length: n }, (_, i) => H('leaf' + n + '/' + i));
      const root = b64u(refRoot(hs));
      expect(settle(() => b64u(mapTree(hs).root))).toEqual({ ok: true, value: root });
      for (let i = 0; i < n; i++) {
        const path = settle(() => mapTree(hs).path(i));
        expect(path.ok).toBe(true);
        const p = (path as { value: string[] }).value;
        expect(p).toEqual(refPath(hs, i).map(b64u));
        expect(settle(() => {
          const r = mapRootFromPath0(i, n, hs[i]!, p.map(unb64u));
          return r === null ? null : b64u(r);
        })).toEqual({ ok: true, value: root });
      }
    }
  });
});
