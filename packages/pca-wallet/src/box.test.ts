import { describe, expect, it } from 'vitest';
import { cellCoords, decodeCell, rng, verbCellCount } from '@atlasauth/pca-intent';
import { SHOP, SKY } from './fixtures.test-util';
import { boxCells, cellInBox, coordsOfBox, coordsOfCell, resolveCoords } from './index';

describe('cell coordinates against the wallet Ω', () => {
  it('speaks the core convention: coordsOfCell = pca-intent cellCoords, and resolveCoords inverts it (property)', () => {
    const r = rng(12);
    for (const om of [SKY, SHOP]) {
      for (const vs of om.verbs) {
        for (let t = 0; t < 50; t++) {
          const idx = decodeCell(vs, Math.floor(r() * verbCellCount(vs)));
          expect(coordsOfCell(vs, idx)).toEqual(cellCoords(vs, idx));
          const back = resolveCoords(om, vs.verb, cellCoords(vs, idx));
          if (!back.ok) throw new Error(back.reason);
          expect(boxCells(back.box)).toEqual([idx]);
        }
      }
    }
  });
  it('accepts the spec short aliases for lifted dimensions, but not a dimension named twice', () => {
    const viaAlias = resolveCoords(SKY, 'air.book', { 'action.params.add_ons': ['none'], 'action.params.total': [2, 3], 'prov:action.params.add_ons': ['trusted|first_party'] });
    expect(viaAlias.ok && viaAlias.box).toEqual([[0], [2, 3], [0]]);
    const twice = resolveCoords(SKY, 'air.book', { 'action.params.add_ons': ['none'], 'action.params.total': [2, 3], 'prov:action.params.add_ons': ['trusted|first_party'], 'env.prov.action.params.add_ons': ['trusted|first_party'] });
    expect(twice).toEqual({ ok: false, reason: 'dimension env.prov.action.params.add_ons is named twice' });
  });
  it('a box round-trips and contains exactly its cells (property)', () => {
    const r = rng(3);
    const vs = SKY.verbs[0]!;
    for (let t = 0; t < 100; t++) {
      const lo = Math.floor(r() * 5);
      const hi = lo + Math.floor(r() * (5 - lo));
      const cats = [0, 1, 2].filter(() => r() < 0.6);
      const box = [cats.length ? cats : [2], Array.from({ length: hi - lo + 1 }, (_, i) => lo + i), [0]];
      const coords = coordsOfBox(vs, box);
      const back = resolveCoords(SKY, 'air.book', coords);
      if (!back.ok) throw new Error(back.reason);
      expect(back.box).toEqual(box);
      for (let c = 0; c < verbCellCount(vs); c++) {
        const idx = decodeCell(vs, c);
        expect(cellInBox(back.box, idx)).toBe(box.every((ids, k) => ids.includes(idx[k]!)));
      }
    }
  });
  it('refuses a value two cells share (exact and prefix with the same text)', () => {
    const om = { v: 1 as const, approximate: [], verbs: [{ verb: 'x', reversibility: 'reversible' as const, weight: 1, dims: [{ kind: 'cat' as const, path: 'action.resource', values: [{ kind: 'exact' as const, value: '/a' }, { kind: 'prefix' as const, value: '/a' }, { kind: 'other' as const, value: '⊥' }] }] }] };
    expect(resolveCoords(om, 'x', { 'action.resource': ['/a'] })).toEqual({ ok: false, reason: 'value "/a" names two cells of action.resource' });
    expect(resolveCoords(om, 'x', { 'action.resource': ['⊥'] }).ok).toBe(true);
  });
});
