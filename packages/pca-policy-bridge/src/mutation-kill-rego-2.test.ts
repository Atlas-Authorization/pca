import { describe, expect, it } from 'vitest';
import { regoToPca } from './rego';

const NODEF = 'no `default allow = false` found; assuming default-deny';
const preds = (body: string) => regoToPca(`default allow = false\nallow {\n${body}\n}\n`).predicates;
const skipped = (body: string) => regoToPca(`default allow = false\nallow {\n${body}\n}\n`).report.skipped;
void NODEF;

describe('rego round 2', () => {
  it('"not" must start the statement', () => {
    expect(preds('input.b == 2 not input.a == 1')).toEqual([]);
    expect(preds('x not input.a == 1')).toEqual([]);
    expect(preds('not input.a == 1')).toEqual([{ verb: '*', where: [{ not: { all_of: [{ field: 'env.a', op: 'exists' }, { field: 'env.a', op: 'eq', value: 1 }] } }] }]);
  });
  it('negating ref / != / glob conditions works', () => {
    expect(preds('not input.a != 1')).toEqual([{ verb: '*', where: [{ not: { field: 'env.a', op: 'ne', value: 1 } }] }]);
    expect(preds('not input.a == input.b')).toEqual([{ verb: '*', where: [{ not: { all_of: [{ field: 'env.a', op: 'exists' }, { field: 'env.b', op: 'exists' }, { field: 'env.a', op: 'eq', ref: 'env.b' }] } }] }]);
    expect(preds('not input.a != input.b')).toEqual([{ verb: '*', where: [{ not: { field: 'env.a', op: 'ne', ref: 'env.b' } }] }]);
    expect(preds('not glob.match("a*", null, input.p)')).toEqual([{ verb: '*', where: [{ not: { field: 'env.p', op: 'like', value: 'a*' } }] }]);
    expect(preds('not input.a < 3')).toEqual([{ verb: '*', where: [{ not: { field: 'env.a', op: 'lt', value: 3 } }] }]);
  });
  it('parentheses and brackets inside string literals fail closed', () => {
    expect(preds('input.a == "f(x)"')).toEqual([]);
    expect(preds('input.a in ["x", "input.yy["]')).toEqual([]);
    expect(preds('input.a in {"input.yy["}')).toEqual([]);
    expect(preds('input.a == "input.y["')).toEqual([]);
    expect(skipped('input.a == "f(x)"')).toEqual(['unmodeled statement "input.a == "f(x)"" — rule dropped (fail closed)']);
  });
  it('rhs that merely contains an input path is not a ref', () => {
    expect(preds('input.a == foo input.b')).toEqual([]);
    expect(preds('input.a == input.b junk')).toEqual([]);
    expect(preds('input.a != foo input.b')).toEqual([]);
    expect(preds('input.a == input.b')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', ref: 'env.b' }] }]);
  });
  it('operator whitespace is optional but never swallows operand characters', () => {
    expect(preds('input.a ==12')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', value: 12 }] }]);
    expect(preds('input.a==12')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', value: 12 }] }]);
    expect(preds('input.a>=789')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'gte', value: 789 }] }]);
    expect(preds('input.a in{"x","y"}')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'in', value: ['x', 'y'] }] }]);
    expect(preds('input.a !="xyz"')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'ne', value: 'xyz' }] }]);
  });
  it('glob.match whitespace is optional and the call must start the statement', () => {
    expect(preds('glob.match("a",[],input.p)')).toEqual([{ verb: '*', where: [{ field: 'env.p', op: 'like', value: 'a' }] }]);
    expect(preds('glob.match("a",null,input.p)')).toEqual([{ verb: '*', where: [{ field: 'env.p', op: 'like', value: 'a' }] }]);
    expect(preds('glob.match("a" ,  [ ]  ,  input.p )')).toEqual([{ verb: '*', where: [{ field: 'env.p', op: 'like', value: 'a' }] }]);
    expect(preds('x glob.match("a*", [], input.p)')).toEqual([]);
    expect(preds('startswith(input.a,"p")')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'prefix', value: 'p' }] }]);
    expect(preds('x startswith(input.a, "p")')).toEqual([]);
  });
  it('string and number literal anchoring', () => {
    expect(preds('input.a == foo "x"')).toEqual([]);
    expect(preds('input.a == "x" junk')).toEqual([]);
    expect(preds('input.a == 12')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', value: 12 }] }]);
    expect(preds('input.a == -345.678')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'eq', value: -345.678 }] }]);
    expect(preds('input.a in [10, 20]')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'in', value: [10, 20] }] }]);
  });
  it('array literals need both delimiters', () => {
    expect(preds('input.a in 1]')).toEqual([]);
    expect(preds('input.a in [1')).toEqual([]);
    expect(preds('input.a in x]')).toEqual([]);
    expect(preds('input.a in [1]')).toEqual([{ verb: '*', where: [{ field: 'env.a', op: 'in', value: [1] }] }]);
  });
});
