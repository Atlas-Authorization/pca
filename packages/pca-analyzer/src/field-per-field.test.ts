import { describe, expect, it } from 'vitest';
import type { Condition } from '@atlasauth/pca';
import { numericConjunctionSatisfiable } from './field';
import { predicateNumericSatisfiable } from './index';

const C = (field: string, op: 'lt' | 'lte' | 'gt' | 'gte' | 'eq', value: number): Condition => ({ field, op, value }) as Condition;

describe('numeric conjunctions are decided per field', () => {
  it('bounds on different fields never contradict each other', () => {
    expect(numericConjunctionSatisfiable([C('action.params.a', 'gte', 100), C('action.params.b', 'lte', 10)])).toBe(true);
    expect(numericConjunctionSatisfiable([C('action.params.a', 'eq', 5), C('action.params.b', 'eq', 6)])).toBe(true);
    expect(predicateNumericSatisfiable([C('action.params.a', 'gt', 5), C('action.params.b', 'lt', 5)])).toBe(true);
  });
  it('a contradiction on one field is found even when other fields are satisfiable', () => {
    expect(numericConjunctionSatisfiable([C('action.params.b', 'lte', 10), C('action.params.a', 'gte', 100), C('action.params.a', 'lte', 10)])).toBe(false);
    expect(numericConjunctionSatisfiable([C('action.params.a', 'gte', 100), C('action.params.b', 'gt', 3), C('action.params.a', 'lt', 100)])).toBe(false);
  });
  it('several satisfiable fields stay satisfiable', () => {
    expect(numericConjunctionSatisfiable([C('action.params.a', 'gte', 1), C('action.params.a', 'lte', 2), C('action.params.b', 'gte', 5), C('action.params.b', 'lte', 5)])).toBe(true);
  });
});
