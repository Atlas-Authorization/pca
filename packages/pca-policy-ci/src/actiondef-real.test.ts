import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, type ActionDef } from '@atlasauth/pca-actions';
import { verbShapesFromActionDefs, type ActionDefStructural } from '@atlasauth/pca-analyzer';

// The analyzer cannot import the action kit (the kit depends on the intent package, which depends on the analyzer), so it reads a
// structural mirror of ActionDef. This file is where both packages are visible: the mirror must accept the REAL type (checked by
// the compiler on the next line) and every built-in definition must adapt without losing its verb or its parameters.
const _assignable: ActionDefStructural = {} as ActionDef;
void _assignable;

describe('the analyzer reads the real ActionDef', () => {
  it('every built-in definition adapts, parameter for parameter', () => {
    const shapes = verbShapesFromActionDefs(BUILTIN_DEFS);
    expect(shapes.map((s) => s.verb)).toEqual(BUILTIN_DEFS.map((d) => d.verb));
    for (const [i, s] of shapes.entries()) expect(Object.keys(s.params)).toEqual(Object.keys(BUILTIN_DEFS[i]!.params));
    expect(shapes.length).toBeGreaterThan(5);
  });
});
