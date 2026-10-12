import { describe, expect, it } from 'vitest';
import { cedarToPca } from './cedar';

const P = (s: string) => cedarToPca(s);
const wherePermit = (expr: string) => cedarToPca(`permit(principal, action, resource) when { ${expr} };`);
const dropped = (expr: string) => {
  const r = wherePermit(expr);
  return r.predicates.length === 0 && r.report.errors.length === 0 && r.report.skipped.length === 1;
};

describe('round 2: scope & annotations', () => {
  it('forbid with a resource scope reports it', () => {
    const r = P('forbid(principal, action, resource == Photo::"p1");');
    expect(r.denies).toEqual([{ verb: '*', resource: 'Photo::p1' }]);
    expect(r.report.translated).toEqual(['forbid → deny verb "*" on Photo::p1 (0 condition(s))']);
  });
  it('annotation whitespace handling', () => {
    expect(P('@id ("x") permit(principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
    expect(P('@a("x")  @b("y")   permit(principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
    expect(P('@a("x")\n\n@b("y")\npermit(principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
  });
  it('scope text is not searched for when/unless', () => {
    const r = P('permit(principal, action, resource == Photo::"when { x }");');
    expect(r.predicates).toEqual([{ verb: '*', resource: 'Photo::when { x }' }]);
    expect(r.report.skipped).toEqual([]);
    const u = P('permit(principal == User::"unless { y }", action, resource);');
    expect(u.predicates).toHaveLength(1);
  });
  it('scope clauses are anchored', () => {
    expect(P('permit(x principal == User::"a");').report.errors).toEqual(['policy "permit(x principal == User::"a")": unparseable scope clause "x principal == User::"a""']);
    expect(P('permit(zaction == Action::"a");').report.errors).toHaveLength(1);
  });
  it('action "in" requires a list; other operators never do', () => {
    expect(P('permit(principal, action is [Action::"a"], resource);').report.errors).toEqual([
      'policy "permit(principal, action is [Action::"a"], resource)": unsupported action scope operator "is"',
    ]);
    expect(P('permit(action in [Action::"a", ]);').predicates).toEqual([{ verb: ['a'] }]);
    expect(P('permit(action in [ Action::"a" ,  , Action::"b"]);').predicates).toEqual([{ verb: ['a', 'b'] }]);
  });
  it('entity references must end with the closing quote', () => {
    expect(P('permit(action == Action::"a" junk);').report.errors).toEqual(['policy "permit(action == Action::"a" junk)": action == expects an Action entity, got "Action::"a" junk"']);
    expect(P('permit(resource == Photo::"a" junk);').report.errors).toHaveLength(1);
    expect(P('permit(principal == User::"a" junk);').report.errors).toHaveLength(1);
  });
});

describe('round 2: expressions', () => {
  const A = { field: 'env.a', op: 'eq', value: 1 };
  const B = { field: 'env.b', op: 'eq', value: 2 };
  it('empty conjuncts are ignored; blank ones still count', () => {
    expect(wherePermit('context.a == 1 && && context.b == 2').predicates[0]?.where).toEqual([{ all_of: [A, B] }]);
    expect(wherePermit('context.a == 1 &&   && context.b == 2').predicates[0]?.where).toEqual([{ all_of: [A, B] }]);
    expect(wherePermit('context.a == 1 ||   || context.b == 2').predicates[0]?.where).toEqual([{ any_of: [A, B] }]);
    expect(wherePermit('  context.a == 1   &&   context.b == 2  ').predicates[0]?.where).toEqual([{ all_of: [A, B] }]);
  });
  it('operators inside string literals are not operators', () => {
    expect(wherePermit('context.s != "x==y"').predicates[0]?.where).toEqual([{ field: 'env.s', op: 'ne', value: 'x==y' }]);
    expect(wherePermit('context.s in ["a<b", "c>d"]').predicates[0]?.where).toEqual([{ field: 'env.s', op: 'in', value: ['a<b', 'c>d'] }]);
    expect(wherePermit('context.s >= "a!=b"').predicates[0]?.where).toEqual([{ field: 'env.s', op: 'gte', value: 'a!=b' }]);
    expect(wherePermit('context.s like "a<=b"').predicates[0]?.where).toEqual([{ field: 'env.s', op: 'like', value: 'a<=b' }]);
    expect(wherePermit('context.s == "a\\"b"').predicates).toEqual([]);
  });
  it('word operators tolerate runs of whitespace', () => {
    expect(wherePermit('principal    in    Group::"g"').predicates[0]?.where).toEqual([
      { field: 'subject.id', op: 'member_of', value: 'Group::g', collection: 'env.entity_parents' },
    ]);
    expect(wherePermit('principal.x   is   User').predicates[0]?.where).toEqual([{ field: 'subject.x', op: 'is_a', value: 'User' }]);
    expect(wherePermit('principal\thas\tdept').predicates[0]?.where).toEqual([{ field: 'subject.dept', op: 'exists' }]);
    expect(wherePermit('resource.n\nlike\n"a*"').predicates[0]?.where).toEqual([{ field: 'env.resource.n', op: 'like', value: 'a*' }]);
  });
  it('like needs a fully quoted pattern', () => {
    expect(dropped('resource.n like foo "bar"')).toBe(true);
    expect(dropped('resource.n like "abc" tail')).toBe(true);
    expect(wherePermit('resource.n like "abc').predicates).toEqual([]);
    const r = wherePermit('resource.n like abc');
    expect(r.report.errors).toEqual([]);
    expect(r.report.skipped).toEqual(['unmodeled when-condition "resource.n like abc" — policy dropped (fail closed)']);
  });
  it('paths are anchored on both ends', () => {
    expect(dropped('yprincipal.a == 1')).toBe(true);
    expect(dropped('principal.a-b == 1')).toBe(true);
    expect(dropped('yresource.a == 1')).toBe(true);
    expect(dropped('resource.a-b == 1')).toBe(true);
    expect(dropped('ycontext.a == 1')).toBe(true);
    expect(dropped('context.a-b == 1')).toBe(true);
    expect(dropped('principal.a b == 1')).toBe(true);
  });
  it('type names are anchored on the right', () => {
    expect(dropped('principal is User extra')).toBe(true);
    expect(dropped('principal is User-x')).toBe(true);
    expect(dropped('principal is Ns::User::')).toBe(true);
  });
  it('numbers keep every decimal digit', () => {
    expect(wherePermit('context.n == 1.25').predicates[0]?.where).toEqual([{ field: 'env.n', op: 'eq', value: 1.25 }]);
    expect(wherePermit('context.n == -10.125').predicates[0]?.where).toEqual([{ field: 'env.n', op: 'eq', value: -10.125 }]);
    expect(wherePermit('context.n in [1.25, 2]').predicates[0]?.where).toEqual([{ field: 'env.n', op: 'in', value: [1.25, 2] }]);
  });
  it('a literal that is neither path nor value fails closed, not with an error', () => {
    const r = wherePermit('context.a == foo');
    expect(r.report.errors).toEqual([]);
    expect(r.predicates).toEqual([]);
  });
  it('paren stripping needs the whole term to be enclosed', () => {
    expect(wherePermit('(context.a == 1) || (context.b == 2)').predicates[0]?.where).toEqual([{ any_of: [A, B] }]);
    expect(dropped('(context.a == 1) == true')).toBe(true);
    expect(dropped('foo(context.a == 1)')).toBe(true);
    expect(dropped('(context.a == 1) junk')).toBe(true);
    expect(wherePermit('( ( context.a == 1 ) )').predicates[0]?.where).toEqual([A]);
  });
});
