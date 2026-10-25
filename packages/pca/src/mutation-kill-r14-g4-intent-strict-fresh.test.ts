/**
 * r14 static mutants of intent-strict.ts: the module-level arrow functions isSafeInt, isSafeNonNeg and isPlainObject,
 * checked on a re-evaluated module (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./intent-strict');
}

describe('intent-strict predicates (fresh module)', () => {
  it('isSafeInt', async () => {
    const s = await fresh();
    expect([1, 0, -5, 1.5, -0, '1'].map((v) => s.isSafeInt(v))).toEqual([true, true, true, false, false, false]);
  });
  it('isSafeNonNeg', async () => {
    const s = await fresh();
    expect([1, 0, -5, 1.5].map((v) => s.isSafeNonNeg(v))).toEqual([true, true, false, false]);
  });
  it('isPlainObject', async () => {
    const s = await fresh();
    expect([{}, Object.create(null), [], null, new Date(0), 5].map((v) => s.isPlainObject(v))).toEqual([true, true, false, false, false, false]);
  });
});
