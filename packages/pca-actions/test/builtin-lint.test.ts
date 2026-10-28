import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, lintDefs, prulesViolations, effective, CORE_REGISTRY } from '../src';

describe('the built-in actions', () => {
  it('lint with no findings at all', () => {
    expect(lintDefs(BUILTIN_DEFS, { stability: 'stable' })).toEqual([]);
  });
  it('satisfy every structural rule their traits require', () => {
    for (const d of BUILTIN_DEFS) expect(prulesViolations(d, effective(d, CORE_REGISTRY).hint.eff.prules), d.verb).toEqual([]);
  });
});
