// Extra boundary tests for the importers' shared helpers: param segment hygiene and enum item typing.
import { describe, expect, it } from 'vitest';
import { leafParam, newBudget, newCtx, paramSeg } from '../src/import/common';

describe('paramSeg underscores', () => {
  it('keeps a leading or trailing underscore and replaces only an all-underscore name', () => {
    expect(paramSeg('_a')).toBe('_a');
    expect(paramSeg('a_')).toBe('a_');
    expect(paramSeg('_a_')).toBe('_a_');
    expect(paramSeg('__')).toBe('p');
  });
});

describe('leafParam enum items', () => {
  const run = (en: unknown[]) => {
    const c = newCtx('openapi', {}, { ns: 't' });
    const p = leafParam({ type: 'string', enum: en }, true, c, newBudget(c), 'w');
    return { p, todo: c.todo };
  };
  const dropped = [{ where: 'w', code: 'enum_dropped', message: 'enum values are not 1..256 plain strings (declared as a free string; refine)' }];
  it('drops an enum holding a non-string item that has a length', () => {
    const r = run([['a']]);
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual(dropped);
  });
  it('drops an enum holding a decomposed (non-NFC) string', () => {
    const r = run(['e\u0301']);
    expect(r.p).toEqual({ type: 'string' });
    expect(r.todo).toEqual(dropped);
  });
});
