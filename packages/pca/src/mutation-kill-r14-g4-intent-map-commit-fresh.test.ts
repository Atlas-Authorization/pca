/**
 * r14 static mutants of intent-map-commit.ts: the TAGS table, the module-level helpers (u8len, isStr, closed, isDimPath,
 * dimCells) and PATH_RE, checked on a re-evaluated module (vi.resetModules + dynamic import).
 */
import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { b64u, canonicalBytesStrict } from './hash';

async function fresh() {
  vi.resetModules();
  return import('./intent-map-commit');
}
const H = (...parts: (Uint8Array | string)[]) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(typeof p === 'string' ? Buffer.from(p, 'utf8') : p);
  return b64u(new Uint8Array(h.digest()));
};
const OTHER = { kind: 'other' as const, value: '⊥' };
const RES = () => ({ kind: 'cat' as const, path: 'action.resource', values: [{ kind: 'exact' as const, value: 'r' }, OTHER] });
const NUM = (path = 'action.params.n') => ({ kind: 'num' as const, path, lo: 0, hi: 10, cuts: [5] });
const H0 = () => ({ verb: 'v', first: 1, cells: 2, dims: [RES()] });

describe('intent-map-commit module tables and helpers (fresh module)', () => {
  it('TAGS: each leaf kind is hashed under its own tag', async () => {
    const m = await fresh();
    const salt = new Uint8Array(32).fill(3);
    const leaf = { a: 1 };
    for (const [kind, tag] of [['header', 'header'], ['cell', 'cell'], ['metrics', 'metrics'], ['learner', 'learner']] as const) {
      expect(b64u(m.mapLeafHash(kind, salt, leaf))).toBe(H(`atlas-pca/intent-map/${tag}/v1\0`, salt, canonicalBytesStrict(leaf)));
    }
  });
  it('closed / isStr / u8len / dimCells: a valid header is accepted', async () => {
    const m = await fresh();
    expect(m.mapHeaderError(H0())).toBeNull();
    expect(m.mapHeaderError({ ...H0(), cells: 6, dims: [RES(), NUM()] })).toBeNull();
    expect(m.mapCellError({ verb: 'v', cell: [0], p_ppm: 1, in_grant: true })).toBeNull();
  });
  it('isStr / u8len: the verb limit counts UTF-8 bytes', async () => {
    const m = await fresh();
    expect(m.mapHeaderError({ ...H0(), verb: 'é'.repeat(64) })).toBeNull();
    expect(m.mapHeaderError({ ...H0(), verb: 'é'.repeat(64) + 'a' })).toBe('header.verb must be a non-empty string of at most 128 UTF-8 bytes');
    expect(m.mapHeaderError({ ...H0(), verb: 5 })).toBe('header.verb must be a non-empty string of at most 128 UTF-8 bytes');
  });
  it('closed: a missing member is refused', async () => {
    const m = await fresh();
    const { dims: _d, ...noDims } = H0();
    void _d;
    expect(m.mapHeaderError(noDims)).toBe('the header leaf must be exactly {verb, first, cells, dims}');
  });
  it('dimCells: the cell count is the product of the dimensions', async () => {
    const m = await fresh();
    expect(m.mapHeaderError({ ...H0(), cells: 2, dims: [RES(), NUM()] })).toBe("header.cells is not the product of the dimensions' cell counts");
  });
  it('PATH_RE / isDimPath: exactly action.params.<1..64 of [A-Za-z0-9_]>', async () => {
    const m = await fresh();
    const err = 'header.dims[0].path must be action.params.<name>';
    for (const p of ['action.params.n', 'action.params.ab_9', 'action.params.' + 'a'.repeat(64)]) expect(m.mapHeaderError({ ...H0(), cells: 3, dims: [NUM(p)] })).toBeNull();
    for (const p of ['xaction.params.n', 'action.params.n-x', 'action.params.' + 'a'.repeat(65), 'action.params.', 'action.params.-']) {
      expect(m.mapHeaderError({ ...H0(), cells: 3, dims: [NUM(p)] })).toBe(err);
    }
    expect(m.mapHeaderError({ ...H0(), dims: [{ ...RES(), path: 'action.params.k' }] })).toBeNull();
    expect(m.mapHeaderError({ ...H0(), dims: [{ ...RES(), path: 'x' }] })).toBe('header.dims[0].path must be action.resource or action.params.<name>');
  });
});
