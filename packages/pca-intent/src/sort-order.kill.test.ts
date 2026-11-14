import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import { OTHER, boundaryWitnesses, withDims, worldDim, type CatDim, type Dim, type Omega, type VerbSpace } from './index';

// Large inputs (hundreds of items, reversed, shuffled and with long monotone runs) so the engine's merge sort reaches its
// galloping paths; the expected order comes from the default string order of the keys.
const N = 360;
const ids = Array.from({ length: N }, (_, i) => i);
const reversed = [...ids].reverse();
const organPipe = [...ids.filter((i) => i % 2 === 0), ...ids.filter((i) => i % 2 === 1).reverse()];
const shuffled = (() => {
  const a = [...ids];
  let s = 12345;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) % 2147483648;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a;
})();
const runsOfShuffled = [...shuffled.slice(0, 120).sort((a, b) => a - b), ...shuffled.slice(120, 240).sort((a, b) => b - a), ...shuffled.slice(240)];
const orders: Array<[string, number[]]> = [
  ['ascending', ids],
  ['reversed', reversed],
  ['organ pipe', organPipe],
  ['shuffled', shuffled],
  ['shuffled with long runs', runsOfShuffled],
];

describe('withDims keeps dimensions sorted by path for large inputs', () => {
  it.each(orders)('%s', (_name, order) => {
    const vs: VerbSpace = { verb: 'x.one', reversibility: 'reversible', weight: 1, dims: [] };
    const omega: Omega = { v: 1, verbs: [vs], approximate: [] };
    const pad = (i: number) => `p${String(i).padStart(4, '0')}`;
    const dims: Dim[] = order.map((i) => worldDim(pad(i), { lo: 0, hi: 1 }));
    const out = withDims(omega, 'x.one', dims);
    const expected = ids.map((i) => `env.world.${pad(i)}`).sort();
    expect(out.verbs[0]!.dims.map((d) => d.path)).toEqual(expected);
  });
});

describe('boundaryWitnesses orders facets by facet text for large inputs', () => {
  const cat = (path: string, n: number): CatDim => ({
    kind: 'cat',
    path,
    values: [...Array.from({ length: n }, (_, i) => ({ kind: 'exact' as const, value: `v${i}` })), { kind: 'other' as const, value: OTHER }],
  });
  const R = 'stripe.refund';
  const grantAt = (...fields: string[]) => ({
    predicates: [{ verb: R, resource: '*', where: fields.map((field) => ({ field, op: 'eq', value: 'v0' })) }] as unknown as Predicate[],
    caveats: [],
  });

  it('one wide dimension: numeric insertion order differs from facet text order', () => {
    const path = 'action.params.k';
    const vs: VerbSpace = { verb: R, reversibility: 'reversible', weight: 1, dims: [cat(path, N)] };
    const out = boundaryWitnesses(grantAt(path), { v: 1, verbs: [vs], approximate: [] });
    const facets = out.filter((w) => w.kind === 'boundary' && w.side === 'outside').map((w) => w.facet);
    const expected = Array.from({ length: N }, (_, i) => `${R}|${path}|${i + 1}`).sort();
    expect(facets).toEqual(expected);
    expect(out.filter((w) => w.kind === 'boundary' && w.side === 'outside').map((w) => w.cell[0])).toEqual(expected.map((f) => Number(f.split('|')[2])));
  });

  it('two wide dimensions: the later-declared path sorts first', () => {
    const z = 'action.params.z';
    const a = 'action.params.a';
    const n = 150;
    const vs: VerbSpace = { verb: R, reversibility: 'reversible', weight: 1, dims: [cat(z, n), cat(a, n)] };
    const out = boundaryWitnesses(grantAt(z, a), { v: 1, verbs: [vs], approximate: [] });
    const facets = out.filter((w) => w.kind === 'boundary' && w.side === 'outside').map((w) => w.facet);
    const expected = [z, a].flatMap((p) => Array.from({ length: n }, (_, i) => `${R}|${p}|${i + 1}`)).sort();
    expect(facets).toEqual(expected);
  });
});
