import { describe, expect, it } from 'vitest';
import { translateCedar } from './cedar';

const permit = (expr: string, guards: boolean) =>
  translateCedar(`permit(principal, action, resource) when { ${expr} };`, guards);
const bare = (expr: string) => permit(expr, false).predicates[0]?.where;
const guarded = (expr: string) => permit(expr, true).predicates[0]?.where;
const dropped = (expr: string) => {
  const r = permit(expr, false);
  return r.predicates.length === 0 && r.report.errors.length === 0 && r.report.skipped.length === 1;
};

describe('action verb conditions', () => {
  it('== and != compare the verb id; other operators are not modeled', () => {
    expect(bare('action == Action::"a"')).toEqual([{ field: 'action.verb', op: 'eq', value: 'a' }]);
    expect(bare('action != Action::"a"')).toEqual([{ field: 'action.verb', op: 'ne', value: 'a' }]);
    expect(dropped('action < Action::"a"')).toBe(true);
    expect(dropped('action >= Action::"a"')).toBe(true);
    expect(dropped('action == foo')).toBe(true);
    expect(dropped('action != "a"')).toBe(true);
  });
  it('in accepts a bracketed list or a single id and nothing else', () => {
    expect(bare('action in [Action::"a", Action::"b"]')).toEqual([{ field: 'action.verb', op: 'in', value: ['a', 'b'] }]);
    expect(bare('action in Action::"a"')).toEqual([{ field: 'action.verb', op: 'in', value: ['a'] }]);
    expect(bare('action in [Action::"a",  ]')).toEqual([{ field: 'action.verb', op: 'in', value: ['a'] }]);
    expect(dropped('action in []')).toBe(true);
    expect(dropped('action in [Action::"a", foo]')).toBe(true);
    expect(dropped('action in Action::"a"]')).toBe(true);
    expect(dropped('action is Foo::"a"')).toBe(true);
    expect(dropped('action like Foo::"a"')).toBe(true);
  });
});

describe('unmodeled operands drop the policy', () => {
  it('any unmodeled branch of || or && drops the whole condition', () => {
    expect(dropped('context.a == 1 || context.b.contains(1)')).toBe(true);
    expect(dropped('context.b.contains(1) || context.a == 1')).toBe(true);
    expect(dropped('context.a == 1 && context.b.contains(1)')).toBe(true);
    expect(dropped('context.b.contains(1) && context.a == 1')).toBe(true);
    expect(bare('context.a == 1 || context.b == 2')).toEqual([
      { any_of: [{ field: 'env.a', op: 'eq', value: 1 }, { field: 'env.b', op: 'eq', value: 2 }] },
    ]);
  });
  it('a path-looking right-hand side that is not a path is not a literal either', () => {
    expect(dropped('context.a == context.b.contains(1)')).toBe(true);
    expect(dropped('principal in principal.foo()')).toBe(true);
  });
  it('a left-hand side that is not a scope path drops has/in', () => {
    expect(dropped('foo has bar')).toBe(true);
    expect(dropped('foo in [1]')).toBe(true);
  });
  it('in against a path is a member_of on the entity parents', () => {
    expect(bare('principal in resource.parent')).toEqual([
      { field: 'subject.id', op: 'member_of', ref: 'env.resource.parent', collection: 'env.entity_parents' },
    ]);
  });
});

describe('error guards', () => {
  it('a single attribute read gets exactly one exists guard (not wrapped)', () => {
    expect(guarded('context.a == 1')).toEqual([
      { field: 'env.a', op: 'eq', value: 1 },
      { field: 'env.a', op: 'exists' },
    ]);
  });
  it('two attribute reads are guarded together', () => {
    expect(guarded('context.a == context.b')).toEqual([
      { field: 'env.a', op: 'eq', ref: 'env.b' },
      { all_of: [{ field: 'env.a', op: 'exists' }, { field: 'env.b', op: 'exists' }] },
    ]);
  });
  it('total fields are never guarded', () => {
    expect(guarded('principal == User::"alice"')).toEqual([{ field: 'subject.id', op: 'eq', value: 'User::alice' }]);
    expect(guarded('context.entity_parents.x == 1')).toEqual([{ field: 'env.entity_parents.x', op: 'eq', value: 1 }]);
  });
  it('has needs its base present only when the base is itself an attribute', () => {
    expect(guarded('principal has dept')).toEqual([{ field: 'subject.dept', op: 'exists' }]);
    expect(guarded('resource has owner')).toEqual([{ field: 'env.resource.owner', op: 'exists' }]);
    expect(guarded('context has mfa')).toEqual([{ field: 'env.mfa', op: 'exists' }]);
    expect(guarded('principal.a has b')).toEqual([
      { field: 'subject.a.b', op: 'exists' },
      { field: 'subject.a', op: 'exists' },
    ]);
    expect(guarded('principal.a.b has c')).toEqual([
      { field: 'subject.a.b.c', op: 'exists' },
      { field: 'subject.a.b', op: 'exists' },
    ]);
    expect(guarded('resource.a has b')).toEqual([
      { field: 'env.resource.a.b', op: 'exists' },
      { field: 'env.resource.a', op: 'exists' },
    ]);
    expect(guarded('context.a has b')).toEqual([
      { field: 'env.a.b', op: 'exists' },
      { field: 'env.a', op: 'exists' },
    ]);
  });
});
