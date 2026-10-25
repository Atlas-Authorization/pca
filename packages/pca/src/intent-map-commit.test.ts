import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  commitMap,
  decideMapDisclosure,
  mapCellOf,
  mapCommitOf,
  mapHeaderError,
  mapLeafHash,
  mapRootFromPath,
  mapTree,
  type CommittedMapInput,
  type MapHeaderLeaf,
} from './intent-map-commit';
import { paramsDigest } from './merkle';
import { b64u, unb64u } from './hash';

// Rule 19 (Intent Layer v2 V15): committed map, cell of ω, Z0 disclosure.

const secret = new Uint8Array(createHash('sha256').update('map-commit-test').digest());
const METRICS = { residual_risk_ppm: 1200, burden_ppm: 3, uncertainty_ppm: 4, disagreement_ppm: 0, mean_harm_ppm: 10, fidelity_est_ppm: 990_000, entropy_mbits: 12, questions: 2, conflicts: 0 };
const book = {
  verb: 'air.book',
  dims: [
    { kind: 'num' as const, path: 'action.params.total', lo: 0, hi: 100_000, cuts: [40_000] },
    { kind: 'cat' as const, path: 'action.resource', values: [{ kind: 'exact' as const, value: 'skyair.example/bookings' }, { kind: 'prefix' as const, value: 'skyair.example/' }, { kind: 'other' as const, value: '⊥' }] },
  ],
};
const search = { verb: 'air.search', dims: [{ kind: 'cat' as const, path: 'action.params.from', values: [{ kind: 'exact' as const, value: 'SFO' }, { kind: 'other' as const, value: '⊥' }] }] };
// air.book: total cells [0,39999], {40000}, [40001,100000] x 3 resource cells = 9; in grant iff total cell 0 or 1 and resource exact
const bookCells = Array.from({ length: 9 }, (_, f) => {
  const cell = [Math.floor(f / 3), f % 3];
  return { cell, p_ppm: cell[0]! < 2 && cell[1] === 0 ? 990_000 : 10_000, in_grant: cell[0]! < 2 && cell[1] === 0 };
});
const searchCells = [
  { cell: [0], p_ppm: 999_000, in_grant: true },
  { cell: [1], p_ppm: 500_000, in_grant: false },
];
const INPUT: CommittedMapInput = { headers: [search, book], cells: { 'air.book': bookCells, 'air.search': searchCells }, metrics: METRICS, learner_digest: b64u(new Uint8Array(32)) };
const action = (params: Record<string, unknown>, resource = 'skyair.example/bookings', verb = 'air.book') => ({ verb, resource, params_digest: paramsDigest(params) });

describe('commitMap / decideMapDisclosure', () => {
  const cm = commitMap(INPUT, secret);
  it('lays out headers (verbs in UTF-8 order), cells in flat order, metrics, learner', () => {
    expect(cm.size).toBe(2 + 9 + 2 + 2);
    expect(cm.leaves.map((l) => l.kind)).toEqual(['header', 'header', ...Array(11).fill('cell'), 'metrics', 'learner']);
    expect((cm.leaves[0]!.leaf as MapHeaderLeaf).verb).toBe('air.book');
    expect((cm.leaves[0]!.leaf as MapHeaderLeaf).first).toBe(2);
    expect((cm.leaves[1]!.leaf as MapHeaderLeaf).first).toBe(11);
  });
  it('admits an action in a granted cell and reports its p', () => {
    const params = { total: 38_900 };
    const d = decideMapDisclosure({ mapCommit: cm.map_commit, action: action(params), params, disclosure: cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, params), maxResidualRiskPpm: 5000 });
    expect(d).toEqual({ ok: true, cell: [0, 0], p_ppm: 990_000, residual_risk_ppm: 1200 });
  });
  it('denies a cell outside the grant, a breached ε, a foreign commitment and a swapped cell', () => {
    const params = { total: 50_000 };
    const disc = cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, params);
    expect(decideMapDisclosure({ mapCommit: cm.map_commit, action: action(params), params, disclosure: disc })).toMatchObject({ ok: false, reason: expect.stringContaining('outside the committed grant') });
    const p2 = { total: 100 };
    const ok = cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, p2);
    expect(decideMapDisclosure({ mapCommit: cm.map_commit, action: action(p2), params: p2, disclosure: ok, maxResidualRiskPpm: 1199 }).ok).toBe(false);
    const other = commitMap(INPUT, new Uint8Array(32).fill(7));
    expect(other.map_commit).not.toBe(cm.map_commit);
    expect(decideMapDisclosure({ mapCommit: other.map_commit, action: action(p2), params: p2, disclosure: ok }).ok).toBe(false);
    // the disclosure for 50000 (cell [2, 0]) presented for an action whose cell is [0, 0]
    expect(decideMapDisclosure({ mapCommit: cm.map_commit, action: action(p2), params: p2, disclosure: disc })).toMatchObject({ ok: false, reason: expect.stringContaining("not the action's cell") });
  });
  it('categorical cells: exact > longest prefix > other', () => {
    const h = cm.leaves[0]!.leaf as MapHeaderLeaf;
    expect(mapCellOf(h, 'skyair.example/bookings', { total: 1 })).toEqual({ cell: [0, 0], flat: 0 });
    expect(mapCellOf(h, 'skyair.example/x', { total: 40_000 })).toEqual({ cell: [1, 1], flat: 4 });
    expect(mapCellOf(h, 'evil.example', { total: 100_000 })).toEqual({ cell: [2, 2], flat: 8 });
    expect('error' in mapCellOf(h, 'x', { total: 100_001 })).toBe(true);
    expect('error' in mapCellOf(h, 'x', { total: '5' })).toBe(true);
    expect('error' in mapCellOf(h, 'x', {})).toBe(true);
    expect('error' in mapCellOf(h, 'x', { total: 1.5 })).toBe(true);
  });
  it('a leaf of one kind never opens as another (domain tags), and the salt hides the leaf', () => {
    const d = cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, { total: 1 });
    const salt = unb64u(d.cell.salt);
    const asHeader = mapLeafHash('header', salt, d.cell.leaf);
    const root = mapRootFromPath(d.cell.index, d.size, asHeader, d.cell.path.map(unb64u))!;
    expect(mapCommitOf(d.size, root)).not.toBe(cm.map_commit);
    const real = mapRootFromPath(d.cell.index, d.size, mapLeafHash('cell', salt, d.cell.leaf), d.cell.path.map(unb64u))!;
    expect(mapCommitOf(d.size, real)).toBe(cm.map_commit);
  });
  it('the RFC 9162 path verification agrees with the builder for every index and size up to 40', () => {
    for (let n = 1; n <= 40; n++) {
      const hs = Array.from({ length: n }, (_, i) => new Uint8Array(32).fill(i + 1));
      const t = mapTree(hs);
      for (let i = 0; i < n; i++) {
        const path = t.path(i).map(unb64u);
        expect(b64u(mapRootFromPath(i, n, hs[i]!, path)!)).toBe(b64u(t.root));
        if (path.length > 0) expect(mapRootFromPath(i, n, hs[i]!, path.slice(1))).toBeNull();
        expect(mapRootFromPath(i, n, hs[i]!, [...path, hs[0]!])).toBeNull();
      }
    }
  });
  it('closed and typed leaves and disclosures (absent vs null)', () => {
    const h = cm.leaves[0]!.leaf as MapHeaderLeaf;
    expect(mapHeaderError(h)).toBeNull();
    expect(mapHeaderError({ ...h, extra: 1 })).not.toBeNull();
    expect(mapHeaderError({ ...h, cells: 8 })).not.toBeNull();
    expect(mapHeaderError({ ...h, dims: [{ ...h.dims[0], cuts: [5, 5] }, h.dims[1]] })).not.toBeNull();
    expect(mapHeaderError({ ...h, dims: [{ ...h.dims[0], lo: '0' }, h.dims[1]] })).not.toBeNull();
    const params = { total: 1 };
    const d = cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, params);
    const run = (disclosure: unknown) => decideMapDisclosure({ mapCommit: cm.map_commit, action: action(params), params, disclosure });
    expect(run(d).ok).toBe(true);
    expect(run({ ...d, extra: 1 }).ok).toBe(false);
    expect(run({ ...d, size: null }).ok).toBe(false);
    expect(run({ ...d, metrics: { ...d.metrics, leaf: { ...d.metrics.leaf, log2_vs_mbits: null } } }).ok).toBe(false);
    expect(run({ ...d, cell: { ...d.cell, leaf: { ...d.cell.leaf, in_grant: 1 } } }).ok).toBe(false);
    expect(run(null).ok).toBe(false);
  });
});
