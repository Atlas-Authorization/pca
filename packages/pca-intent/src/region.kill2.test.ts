import { describe, expect, it } from 'vitest';
import { dimCellsIn, regionCells, regionOfCell, restrictRegion, valueInRegionDim, type CatRegionDim, type Region } from './region';
import type { CatDim, NumDim, VerbSpace } from './omega';

const numD: NumDim = { kind: 'num', path: 'action.params.n', lo: 0, hi: 9, cuts: [3, 6], dist: 'uniform' };
// cells: 0:[0,2] 1:[3,3] 2:[4,5] 3:[6,6] 4:[7,9]
const catD: CatDim = {
  kind: 'cat',
  path: 'action.params.c',
  values: [
    { kind: 'exact', value: 'a' },
    { kind: 'prefix', value: 'p/' },
    { kind: 'other', value: '⊥' },
  ],
};
const vs: VerbSpace = { verb: 'v.x', reversibility: 'reversible', weight: 1, dims: [numD, catD] };

describe('regionOfCell', () => {
  it('writes a cell in value terms with its own copy of the value list', () => {
    const r = regionOfCell(vs, [2, 1]);
    expect(r).toEqual({
      verb: 'v.x',
      dims: {
        'action.params.n': { kind: 'num', lo: 4, hi: 5 },
        'action.params.c': { kind: 'cat', values: catD.values, cells: [1] },
      },
    });
    const c = r.dims['action.params.c'] as CatRegionDim;
    expect(c.values).not.toBe(catD.values);
    expect(c.values[0]).not.toBe(catD.values[0]);
  });
});

describe('restrictRegion', () => {
  const base: Region = { verb: 'v.x', dims: {} };
  it('restricts a numeric dimension to a range and a categorical one to a copy of the cells', () => {
    expect(restrictRegion(base, numD, { lo: 1, hi: 2 })).toEqual({ verb: 'v.x', dims: { [numD.path]: { kind: 'num', lo: 1, hi: 2 } } });
    const cells = [0, 2];
    const r = restrictRegion(base, catD, { cells });
    expect(r).toEqual({ verb: 'v.x', dims: { [catD.path]: { kind: 'cat', values: catD.values, cells: [0, 2] } } });
    const rd = r.dims[catD.path] as CatRegionDim;
    expect(rd.cells).not.toBe(cells);
    expect(rd.values).not.toBe(catD.values);
    expect(rd.values[1]).not.toBe(catD.values[1]);
    expect(base.dims).toEqual({});
  });
  it('refuses a part of the wrong kind, either way round', () => {
    const msg = (p: string) => new Error(`restrictRegion: part does not match the kind of ${p}`);
    expect(() => restrictRegion(base, numD, { cells: [0] })).toThrow(msg(numD.path));
    expect(() => restrictRegion(base, catD, { lo: 0, hi: 1 })).toThrow(msg(catD.path));
  });
});

describe('dimCellsIn', () => {
  it('no restriction means every cell', () => {
    expect(dimCellsIn(numD, undefined, 'inner')).toEqual([0, 1, 2, 3, 4]);
    expect(dimCellsIn(catD, undefined, 'outer')).toEqual([0, 1, 2]);
  });
  it('inner takes cells wholly inside, outer takes cells meeting the range', () => {
    const rd = { kind: 'num', lo: 4, hi: 7 } as const;
    expect(dimCellsIn(numD, rd, 'inner')).toEqual([2, 3]);
    expect(dimCellsIn(numD, rd, 'outer')).toEqual([2, 3, 4]);
    expect(dimCellsIn(numD, { kind: 'num', lo: 3, hi: 3 }, 'outer')).toEqual([1]);
  });
  it('refuses a kind mismatch with the exact message', () => {
    const cat: CatRegionDim = { kind: 'cat', values: catD.values, cells: [0] };
    expect(() => dimCellsIn(numD, cat, 'inner')).toThrow(new Error(`region: ${numD.path} is numeric in Ω but categorical in the region`));
    expect(() => dimCellsIn(catD, { kind: 'num', lo: 0, hi: 1 }, 'inner')).toThrow(
      new Error(`region: ${catD.path} is categorical in Ω but numeric in the region`),
    );
  });
  it('tests categorical cells by representative under the region reference partition', () => {
    const fine: CatDim = {
      kind: 'cat',
      path: catD.path,
      values: [
        { kind: 'exact', value: 'a' },
        { kind: 'exact', value: 'p/q' },
        { kind: 'prefix', value: 'p/' },
        { kind: 'other', value: '⊥' },
      ],
    };
    const rd: CatRegionDim = { kind: 'cat', values: catD.values, cells: [1] };
    expect(dimCellsIn(fine, rd, 'inner')).toEqual([1, 2]);
    expect(dimCellsIn(fine, { ...rd, cells: [0, 2] }, 'outer')).toEqual([0, 3]);
  });
});

describe('regionCells', () => {
  const r: Region = {
    verb: 'v.x',
    dims: {
      [numD.path]: { kind: 'num', lo: 4, hi: 7 },
      [catD.path]: { kind: 'cat', values: catD.values, cells: [1, 2] },
    },
  };
  it('lists flat indices row-major, last dimension fastest', () => {
    expect(regionCells(vs, r, 'outer')).toEqual([7, 8, 10, 11, 13, 14]);
    expect(regionCells(vs, r, 'inner')).toEqual([7, 8, 10, 11]);
  });
  it('an absent dimension is unrestricted', () => {
    expect(regionCells(vs, { verb: 'v.x', dims: { [catD.path]: { kind: 'cat', values: catD.values, cells: [0] } } }, 'inner')).toEqual([0, 3, 6, 9, 12]);
  });
  it('a region covering no cell of some dimension covers nothing', () => {
    expect(regionCells(vs, { verb: 'v.x', dims: { [numD.path]: { kind: 'num', lo: 100, hi: 200 } } }, 'outer')).toEqual([]);
  });
  it('refuses another verb and a dimension Ω does not have', () => {
    expect(() => regionCells(vs, { verb: 'v.y', dims: {} }, 'inner')).toThrow(new Error('region: verb v.y does not match v.x'));
    expect(() => regionCells(vs, { verb: 'v.x', dims: { 'action.params.zzz': { kind: 'num', lo: 0, hi: 1 } } }, 'inner')).toThrow(
      new Error('region: restricts action.params.zzz, which Ω has no dimension for'),
    );
  });
});

describe('valueInRegionDim', () => {
  const nd = { kind: 'num', lo: 1, hi: 9 } as const;
  it('numeric: inclusive range, numbers only', () => {
    expect(valueInRegionDim('p', nd, 1)).toBe(true);
    expect(valueInRegionDim('p', nd, 9)).toBe(true);
    expect(valueInRegionDim('p', nd, 5)).toBe(true);
    expect(valueInRegionDim('p', nd, 0)).toBe(false);
    expect(valueInRegionDim('p', nd, 10)).toBe(false);
    expect(valueInRegionDim('p', nd, '5')).toBe(false);
    expect(valueInRegionDim('p', nd, 'abc')).toBe(false);
  });
  it('categorical: strings whose cell is listed, never numbers', () => {
    const cd: CatRegionDim = { kind: 'cat', values: catD.values, cells: [1] };
    expect(valueInRegionDim('p', cd, 'p/x')).toBe(true);
    expect(valueInRegionDim('p', cd, 'a')).toBe(false);
    expect(valueInRegionDim('p', cd, 'zzz')).toBe(false);
    expect(valueInRegionDim('p', { ...cd, cells: [2] }, 'zzz')).toBe(true);
    expect(valueInRegionDim('p', { ...cd, cells: [2] }, 7)).toBe(false);
  });
});
