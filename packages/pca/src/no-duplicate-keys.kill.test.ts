import { describe, expect, it } from 'vitest';
import { duplicateKey, parseNoDuplicates } from './no-duplicate-keys';

describe('duplicate-only JSON check', () => {
  it('finds a duplicate at every depth, in objects inside arrays, and by escape spelling', () => {
    expect(duplicateKey('{"a":1,"a":2}')).toBe('a');
    expect(duplicateKey('{"x":{"y":[{"k":1,"k":2}]}}')).toBe('k');
    expect(duplicateKey('{"a":1,"\\u0061":2}')).toBe('a');
    expect(duplicateKey('{"\\u00e9":1,"\u00e9":2}')).toBe('\u00e9');
    expect(duplicateKey('{"a":{"a":1},"b":["a","a"],"c":{"a":2}}')).toBeUndefined();
  });
  it('refuses with the exact message and accepts non-canonical numbers', () => {
    expect(() => parseNoDuplicates('{"a":1,"a":2}')).toThrow('duplicate key "a"');
    expect(parseNoDuplicates('{"x":8.0,"y":1e3,"z":-0.5e-9}')).toEqual({ x: 8, y: 1000, z: -5e-10 });
  });
});
