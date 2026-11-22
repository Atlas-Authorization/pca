// The side-effect comparator is checked by calling it directly (captured from Array.prototype.sort), so the result does not depend on
// how the engine's sort uses the comparator's value: every ordering outcome of the comparator is pinned.
import { describe, expect, it, vi } from 'vitest';
import { normalize, type ActionDef } from '../src';

type Cmp = (a: { target: string; kind: string }, b: { target: string; kind: string }) => number;

const DEF = {
  v: 1, kind: 'pca-action-def', verb: 'a.b.c', title: 'T', effects: ['read'], resource: { type: 'a.b', id: '*', scope: 'one' }, params: {}, review: { state: 'authored' },
  side_effects: [{ target: 't', kind: 'k' }],
} as unknown as ActionDef;

function captured(): Cmp {
  const orig = Array.prototype.sort;
  const seen: Cmp[] = [];
  const spy = vi.spyOn(Array.prototype, 'sort').mockImplementation(function (this: unknown[], fn?: (a: unknown, b: unknown) => number) {
    if (fn) seen.push(fn as unknown as Cmp);
    return orig.call(this, fn);
  });
  try {
    normalize(DEF);
  } finally {
    spy.mockRestore();
  }
  expect(seen).toHaveLength(1);
  return seen[0]!;
}

describe('normalize: the side-effect comparator', () => {
  const cmp = captured();
  const e = (target: string, kind: string) => ({ target, kind });
  it('orders by target first', () => {
    expect(cmp(e('a', 'z'), e('b', 'a'))).toBeLessThan(0);
    expect(cmp(e('b', 'a'), e('a', 'z'))).toBeGreaterThan(0);
  });
  it('orders equal targets by kind', () => {
    expect(cmp(e('t', 'a'), e('t', 'b'))).toBe(-1);
    expect(cmp(e('t', 'b'), e('t', 'a'))).toBe(1);
  });
  it('is 0 for identical entries', () => {
    expect(cmp(e('t', 'k'), e('t', 'k'))).toBe(0);
  });
});
