import { describe, expect, it } from 'vitest';
import { SKY } from './fixtures.test-util';
import { boxCells, boxSize, cellInBox, cellOfAction, coordKeyOf, coordsOfBox, flatIndex, resolveCoords, type CellCoords } from './index';

const raw = (x: unknown): CellCoords[string] => x as CellCoords[string];
const sky = SKY.verbs[0]!;
const okCoords = (total: unknown, addOns: unknown = ['none']): CellCoords => ({
  'action.params.add_ons': raw(addOns),
  'action.params.total': raw(total),
  'env.prov.action.params.add_ons': ['trusted|first_party'],
});

describe('coordKeyOf aliases', () => {
  it('maps lifted dimensions, whole path only', () => {
    expect(coordKeyOf('env.acc.spent-x_y.z.post')).toBe('spent-x_y.z');
    expect(coordKeyOf('env.acc.ab.post')).toBe('ab');
    expect(coordKeyOf('zenv.acc.ab.post')).toBe('zenv.acc.ab.post');
    expect(coordKeyOf('env.acc.ab.post.x')).toBe('env.acc.ab.post.x');
    expect(coordKeyOf('env.acc..post')).toBe('env.acc..post');
    expect(coordKeyOf('env.mon.door-lock.state')).toBe('mon:door-lock');
    expect(coordKeyOf('zenv.mon.ab.state')).toBe('zenv.mon.ab.state');
    expect(coordKeyOf('env.mon.ab.state.x')).toBe('env.mon.ab.state.x');
    expect(coordKeyOf('env.prov.x.y')).toBe('prov:x.y');
    expect(coordKeyOf('zenv.prov.x')).toBe('zenv.prov.x');
    expect(coordKeyOf('env.prov.a\nb')).toBe('env.prov.a\nb');
    expect(coordKeyOf('env.world.fx-rate_1.x')).toBe('fx-rate_1.x');
    expect(coordKeyOf('zenv.world.ab')).toBe('zenv.world.ab');
    expect(coordKeyOf('env.world.a b')).toBe('env.world.a b');
    expect(coordKeyOf('action.params.total')).toBe('action.params.total');
  });
});

describe('resolveCoords refusals', () => {
  it('names the exact reason', () => {
    expect(resolveCoords(SKY, 'nope', {})).toEqual({ ok: false, reason: "verb nope is not in the wallet's outcome space" });
    expect(resolveCoords(SKY, 'air.book', { ...okCoords([0, 1]), zzz: ['x'] })).toEqual({ ok: false, reason: 'unknown dimension zzz' });
    const { 'action.params.total': _t, ...noTotal } = okCoords([0, 1]);
    expect(resolveCoords(SKY, 'air.book', noTotal)).toEqual({ ok: false, reason: 'coordinates leave out dimension action.params.total' });
  });
  it('numeric side: shape and range', () => {
    const shape = { ok: false, reason: 'dimension action.params.total is numeric: expected an index range' };
    for (const bad of [[1], [0, 1, 2], ['0', '1'], ['a', 2], [0, 'x'], [2, '3'], ['2', 3]]) expect(resolveCoords(SKY, 'air.book', okCoords(bad))).toEqual(shape);
    const range = { ok: false, reason: 'index range of action.params.total is out of range' };
    for (const bad of [[-1, 2], [3, 2], [0, 5], [1.5, 2], [1, 2.5]]) expect(resolveCoords(SKY, 'air.book', okCoords(bad))).toEqual(range);
    expect(resolveCoords(SKY, 'air.book', okCoords([0, 4])).ok).toBe(true);
    expect(resolveCoords(SKY, 'air.book', okCoords([4, 4])).ok).toBe(true);
  });
  it('categorical side: shape, unknown value, sorted and de-duplicated ids', () => {
    expect(resolveCoords(SKY, 'air.book', okCoords([0, 1], [1]))).toEqual({ ok: false, reason: 'dimension action.params.add_ons is categorical: expected a value set' });
    expect(resolveCoords(SKY, 'air.book', okCoords([0, 1], ['none', 5]))).toEqual({ ok: false, reason: 'dimension action.params.add_ons is categorical: expected a value set' });
    expect(resolveCoords(SKY, 'air.book', okCoords([0, 1], ['bag']))).toEqual({ ok: false, reason: 'unknown value "bag" for action.params.add_ons' });
    const r = resolveCoords(SKY, 'air.book', okCoords([0, 1], ['⊥', 'tripshield', 'none', 'none']));
    expect(r.ok && r.box).toEqual([[0, 1, 2], [0, 1], [0]]);
  });
});

describe('box helpers', () => {
  it('coordsOfBox refuses a non-contiguous numeric side', () => {
    expect(() => coordsOfBox(sky, [[0], [0, 2], [0]])).toThrow('coordsOfBox: numeric side of action.params.total is not contiguous');
    expect(coordsOfBox(sky, [[0], [1, 2], [0]])['action.params.total']).toEqual([1, 2]);
  });
  it('cellInBox needs the same number of dimensions', () => {
    expect(cellInBox([[0]], [0, 1])).toBe(false);
    expect(cellInBox([[0], [1]], [0, 1])).toBe(true);
    expect(cellInBox([[0], [1]], [0, 2])).toBe(false);
  });
  it('boxCells, boxSize, flatIndex', () => {
    expect(boxCells([[0, 1], [2]])).toEqual([[0, 2], [1, 2]]);
    expect(boxSize([[0, 1], [0, 1, 2]])).toBe(6);
    expect(flatIndex(sky, [1, 2, 1])).toBe(22);
  });
  it('cellOfAction is null when a dimension value is missing', () => {
    expect(cellOfAction(SKY, { verb: 'air.book', values: { 'action.params.add_ons': 'none' } })).toBeNull();
    expect(cellOfAction(SKY, { verb: 'nope', values: {} })).toBeNull();
  });
});
