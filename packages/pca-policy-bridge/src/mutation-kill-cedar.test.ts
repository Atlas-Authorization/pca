import { describe, expect, it } from 'vitest';
import { translateCedar } from './cedar';
const cedarToPca = (text: string) => translateCedar(text, false); // structure tests: bare expressions, no error guards


const EP = 'env.entity_parents';
const P = (stmt: string) => cedarToPca(stmt);
const wherePermit = (expr: string) => cedarToPca(`permit(principal, action, resource) when { ${expr} };`).predicates[0]?.where;
const whereOf = (expr: string) => wherePermit(expr)?.[0];
const dropped = (expr: string) => cedarToPca(`permit(principal, action, resource) when { ${expr} };`).predicates.length === 0;

describe('statement framing', () => {
  it('empty / comments only', () => {
    expect(P('')).toEqual({ predicates: [], denies: [], caveats: [], report: { source: 'cedar', translated: [], skipped: [], errors: [] } });
    expect(P('// nothing\n  ; ;').report).toEqual({ source: 'cedar', translated: [], skipped: [], errors: [] });
  });
  it('permit and forbid land in separate lists with messages', () => {
    const r = P('permit(principal, action == Action::"view", resource == Photo::"p1");\nforbid(principal, action, resource);');
    expect(r.predicates).toEqual([{ verb: 'view', resource: 'Photo::p1' }]);
    expect(r.denies).toEqual([{ verb: '*' }]);
    expect(r.report.translated).toEqual(['permit → verb "view" on Photo::p1 (0 condition(s))', 'forbid → deny verb "*" (0 condition(s))']);
    expect(r.caveats).toEqual([]);
    expect(Object.keys(r.predicates[0]!)).toEqual(['verb', 'resource']);
    expect(Object.keys(r.denies[0]!)).toEqual(['verb']);
  });
  it('effect keyword case-insensitive; annotations stripped; whitespace before paren', () => {
    expect(P('PERMIT (principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
    expect(P('Forbid(principal, action, resource);').denies).toEqual([{ verb: '*' }]);
    expect(P('@id("x") @advice("y z")  permit(principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
    expect(P('  @id("a")\npermit (principal, action, resource);').predicates).toEqual([{ verb: '*' }]);
    expect(P('@id permit(principal, action, resource);').report.skipped).toEqual(['unrecognized statement: "@id permit(principal, action, resource)"']);
    expect(P('@1x("y") permit(principal, action, resource);').predicates).toEqual([]);
  });
  it('unrecognized statements are skipped, not errors', () => {
    const r = P('garbage here; permitx(principal, action, resource); permit principal;');
    expect(r.report.skipped).toEqual([
      'unrecognized statement: "garbage here"',
      'unrecognized statement: "permitx(principal, action, resource)"',
      'unrecognized statement: "permit principal"',
    ]);
    expect(r.report.errors).toEqual([]);
  });
  it('long statements are truncated at 80 chars', () => {
    const long = 'x'.repeat(80);
    expect(P(long).report.skipped).toEqual([`unrecognized statement: "${long}"`]);
    expect(P(long + 'y').report.skipped).toEqual([`unrecognized statement: "${'x'.repeat(77)}..."`]);
    expect(P('a   b\n c').report.skipped).toEqual(['unrecognized statement: "a b c"']);
  });
  it('semicolons inside strings / brackets do not split', () => {
    const r = P('permit(principal, action, resource) when { resource.n == "a;b" };');
    expect(r.predicates).toEqual([{ verb: '*', where: [{ field: 'env.resource.n', op: 'eq', value: 'a;b' }] }]);
    expect(r.report.translated).toEqual(['permit → verb "*" (1 condition(s))']);
  });
  it('errors carry the statement and message', () => {
    expect(P('permit (principal').report.errors).toEqual(['policy "permit (principal": unterminated scope parentheses']);
    expect(P('permit(foo);').report.errors).toEqual(['policy "permit(foo)": unparseable scope clause "foo"']);
    expect(P('permit(principalx);').report.errors).toEqual(['policy "permit(principalx)": unparseable scope clause "principalx"']);
    // one bad policy does not stop the next
    const r = P('permit(foo); permit(principal, action, resource);');
    expect(r.predicates).toEqual([{ verb: '*' }]);
    expect(r.report.errors).toHaveLength(1);
  });
  it('comment stripping removes // to end of line only', () => {
    expect(P('permit(principal, action, resource); // c\nforbid(principal, action, resource);').denies).toEqual([{ verb: '*' }]);
    expect(P('permit(principal, // c1\n action == Action::"a", // c2\n resource);').predicates).toEqual([{ verb: 'a' }]);
  });
});

describe('scope', () => {
  const pred = (scope: string) => P(`permit(${scope});`);
  it('unconstrained and multiple clauses; missing clauses', () => {
    expect(pred('principal, action, resource').predicates).toEqual([{ verb: '*' }]);
    expect(pred('').predicates).toEqual([{ verb: '*' }]);
    expect(pred('principal').predicates).toEqual([{ verb: '*' }]);
    expect(pred(' principal , , action ').predicates).toEqual([{ verb: '*' }]);
  });
  it('action scope', () => {
    expect(pred('principal, action == Action::"read", resource').predicates).toEqual([{ verb: 'read' }]);
    expect(pred('principal, action == NS::Action::"a b", resource').predicates).toEqual([{ verb: 'a b' }]);
    expect(pred('action == Action::""').predicates).toEqual([{ verb: '' }]);
    expect(pred('action in [Action::"a", Action::"b"]').predicates).toEqual([{ verb: ['a', 'b'] }]);
    expect(pred('action in [Action::"a",]').predicates).toEqual([{ verb: ['a'] }]);
    expect(pred('action in []').predicates).toEqual([{ verb: [] }]);
    expect(pred('action in [ Action::"a" , Action::"b,c" ]').predicates).toEqual([{ verb: ['a', 'b,c'] }]);
    expect(pred('action == foo').report.errors).toEqual(['policy "permit(action == foo)": action == expects an Action entity, got "foo"']);
    expect(pred('action in [foo]').report.errors).toEqual(['policy "permit(action in [foo])": action in [...] expects Action entities, got "foo"']);
    expect(pred('action in Action::"g"').report.errors).toEqual(['policy "permit(action in Action::"g")": unsupported action scope operator "in"']);
    expect(pred('action is Action').report.errors).toEqual(['policy "permit(action is Action)": unsupported action scope operator "is"']);
    // bare action with an unknown operator is not a clause op
    expect(pred('action ==').report.errors).toEqual(['policy "permit(action ==)": action == expects an Action entity, got ""']);
  });
  it('principal scope', () => {
    expect(pred('principal == User::"alice", action, resource').predicates).toEqual([
      { verb: '*', where: [{ field: 'subject.id', op: 'eq', value: 'User::alice' }] },
    ]);
    expect(pred('principal in Group::"g"').predicates).toEqual([
      { verb: '*', where: [{ field: 'subject.id', op: 'member_of', value: 'Group::g', collection: EP }] },
    ]);
    expect(pred('principal is User').predicates).toEqual([{ verb: '*', where: [{ field: 'subject.id', op: 'is_a', value: 'User' }] }]);
    expect(pred('principal is Ns::User').predicates).toEqual([{ verb: '*', where: [{ field: 'subject.id', op: 'is_a', value: 'Ns::User' }] }]);
    expect(pred('principal == 5').report.errors).toEqual(['policy "permit(principal == 5)": principal == expects an entity, got "5"']);
    expect(pred('principal is 5x').report.errors).toEqual(['policy "permit(principal is 5x)": principal is expects a type, got "5x"']);
    expect(pred('principal in foo').report.errors).toEqual(['policy "permit(principal in foo)": principal in expects an entity (hierarchy), got "foo"']);
    expect(pred('principal in [A::"a"]').report.errors).toHaveLength(1);
    expect(pred('principal in resource').predicates).toEqual([
      { verb: '*', where: [{ field: 'subject.id', op: 'member_of', ref: 'action.resource', collection: EP }] },
    ]);
  });
  it('resource scope', () => {
    expect(pred('resource == Photo::"p1"').predicates).toEqual([{ verb: '*', resource: 'Photo::p1' }]);
    expect(pred('resource == Ns::Photo::"p 1"').predicates).toEqual([{ verb: '*', resource: 'Ns::Photo::p 1' }]);
    expect(pred('resource in Folder::"f"').predicates).toEqual([
      { verb: '*', where: [{ field: 'action.resource', op: 'member_of', value: 'Folder::f', collection: EP }] },
    ]);
    expect(pred('resource is Photo').predicates).toEqual([{ verb: '*', where: [{ field: 'action.resource', op: 'is_a', value: 'Photo' }] }]);
    expect(pred('resource == 7').report.errors).toEqual(['policy "permit(resource == 7)": resource == expects an entity, got "7"']);
    expect(pred('resource is "x"').report.errors).toEqual(['policy "permit(resource is "x")": resource is expects a type, got ""x""']);
    expect(pred('resource in 7').report.errors).toEqual(['policy "permit(resource in 7)": resource in expects an entity (hierarchy), got "7"']);
    expect(pred('resource in principal').predicates).toEqual([
      { verb: '*', where: [{ field: 'action.resource', op: 'member_of', ref: 'subject.id', collection: EP }] },
    ]);
  });
  it('scope conditions precede when/unless in order', () => {
    const r = P('permit(principal is User, action, resource is Photo) when { context.x == 1 } unless { context.y == 2 };');
    expect(r.predicates[0]?.where).toEqual([
      { field: 'subject.id', op: 'is_a', value: 'User' },
      { field: 'action.resource', op: 'is_a', value: 'Photo' },
      { field: 'env.x', op: 'eq', value: 1 },
      { not: { field: 'env.y', op: 'eq', value: 2 } },
    ]);
    expect(r.report.translated).toEqual(['permit → verb "*" (4 condition(s))']);
  });
});

describe('condition blocks', () => {
  it('when / unless, multiple, case-sensitive keyword boundaries', () => {
    const r = P('permit(principal, action, resource) when { context.a == 1 } when { context.b == 2 } unless { context.c == 3 };');
    expect(r.predicates[0]?.where).toEqual([
      { field: 'env.a', op: 'eq', value: 1 },
      { field: 'env.b', op: 'eq', value: 2 },
      { not: { field: 'env.c', op: 'eq', value: 3 } },
    ]);
    expect(P('permit(principal, action, resource) whenx { context.a == 1 };').predicates).toEqual([{ verb: '*' }]);
    expect(P('permit(principal, action, resource) when{context.a == 1};').predicates[0]?.where).toHaveLength(1);
    expect(P('permit(principal, action, resource) when\n  {\n context.a == 1\n };').predicates[0]?.where).toHaveLength(1);
  });
  it('braces nested and in strings', () => {
    expect(wherePermit('context.s == "}{"')).toEqual([{ field: 'env.s', op: 'eq', value: '}{' }]);
    expect(wherePermit('context.s in ["a", "b"]')).toEqual([{ field: 'env.s', op: 'in', value: ['a', 'b'] }]);
  });
  it('unterminated block is an error', () => {
    expect(P('permit(principal, action, resource) when { context.a == 1').report.errors).toEqual([
      'policy "permit(principal, action, resource) when { context.a == 1": unterminated when block',
    ]);
    expect(P('permit(principal, action, resource) unless { context.a == 1').report.errors[0]).toMatch(/unterminated unless block$/);
  });
  it('unmodeled permit is dropped without error; unmodeled forbid is an error', () => {
    const r = P('permit(principal, action, resource) when { resource.a + 1 < 10 };');
    expect(r.predicates).toEqual([]);
    expect(r.report.translated).toEqual([]);
    expect(r.report.errors).toEqual([]);
    expect(r.report.skipped).toEqual(['unmodeled when-condition "resource.a + 1 < 10" — policy dropped (fail closed)']);
    const u = P('permit(principal, action, resource) unless { foo };');
    expect(u.report.skipped).toEqual(['unmodeled unless-condition "foo" — policy dropped (fail closed)']);
    const f = P('forbid(principal, action, resource) when { foo };');
    expect(f.denies).toEqual([]);
    expect(f.report.skipped).toEqual(['unmodeled when-condition "foo" — policy dropped (fail closed)']);
    expect(f.report.errors).toEqual([
      'forbid could not be fully modeled and was dropped — treat result as fail-closed: "forbid(principal, action, resource) when { foo }"',
    ]);
    // later good blocks are not consulted after a drop
    expect(P('permit(principal, action, resource) when { foo } when { context.a == 1 };').report.skipped).toHaveLength(1);
    expect(dropped('')).toBe(true);
    expect(dropped('   ')).toBe(true);
  });
});

describe('expressions', () => {
  it('comparisons', () => {
    expect(whereOf('principal == User::"a"')).toEqual({ field: 'subject.id', op: 'eq', value: 'User::a' });
    expect(whereOf('principal != User::"a"')).toEqual({ field: 'subject.id', op: 'ne', value: 'User::a' });
    expect(whereOf('principal.age < 18')).toEqual({ field: 'subject.age', op: 'lt', value: 18 });
    expect(whereOf('principal.age <= 18')).toEqual({ field: 'subject.age', op: 'lte', value: 18 });
    expect(whereOf('principal.age > 18')).toEqual({ field: 'subject.age', op: 'gt', value: 18 });
    expect(whereOf('principal.age >= 18')).toEqual({ field: 'subject.age', op: 'gte', value: 18 });
    expect(whereOf('principal.age>=18')).toEqual({ field: 'subject.age', op: 'gte', value: 18 });
    expect(whereOf('resource.price == -1.5')).toEqual({ field: 'env.resource.price', op: 'eq', value: -1.5 });
    expect(whereOf('context.ok == true')).toEqual({ field: 'env.ok', op: 'eq', value: true });
    expect(whereOf('context.ok != false')).toEqual({ field: 'env.ok', op: 'ne', value: false });
    expect(whereOf('context.a.b.c == "x"')).toEqual({ field: 'env.a.b.c', op: 'eq', value: 'x' });
    expect(whereOf('context == 1')).toEqual({ field: 'env', op: 'eq', value: 1 });
    expect(whereOf('action == Action::"a"')).toEqual({ field: 'action.verb', op: 'eq', value: 'a' });
    expect(whereOf('resource == Photo::"p"')).toEqual({ field: 'action.resource', op: 'eq', value: 'Photo::p' });
    expect(whereOf('resource.n == ""')).toEqual({ field: 'env.resource.n', op: 'eq', value: '' });
    expect(whereOf('context.s == "a<b==c"')).toEqual({ field: 'env.s', op: 'eq', value: 'a<b==c' });
    expect(whereOf('context.s == "has x"')).toEqual({ field: 'env.s', op: 'eq', value: 'has x' });
  });
  it('first operator by precedence order', () => {
    // `==` is found before `<=`; the LHS then is not a path, so the atom is unmodeled
    expect(dropped('context.a <= 1 == 2')).toBe(true);
    expect(whereOf('context.a != 1')).toEqual({ field: 'env.a', op: 'ne', value: 1 });
  });
  it('bad literals / lhs are unmodeled', () => {
    for (const bad of ['context.a == 1e3', 'context.a == .5', 'context.a == foo', 'context.a == [1]', 'context.a == "a" "b"', 'context.a == 5.', 'foo == 1', 'principal.1x == 1', 'context.a.b() == 1', 'resource.a + 1 < 10', 'principal.age', 'principal.tags.contains("x")', 'context.a == --1', 'context.a == 1 + 2', ' == 1', 'principal ==']) {
      expect(dropped(bad)).toBe(true);
    }
  });
  it('rhs paths become refs', () => {
    expect(whereOf('resource.owner == principal')).toEqual({ field: 'env.resource.owner', op: 'eq', ref: 'subject.id' });
    expect(whereOf('principal.dept != resource.dept')).toEqual({ field: 'subject.dept', op: 'ne', ref: 'env.resource.dept' });
    expect(whereOf('context.a < context.b')).toEqual({ field: 'env.a', op: 'lt', ref: 'env.b' });
    expect(whereOf('context.a >= action')).toEqual({ field: 'env.a', op: 'gte', ref: 'action.verb' });
    expect(whereOf('context.a == resource')).toEqual({ field: 'env.a', op: 'eq', ref: 'action.resource' });
    expect(whereOf('context.a == context')).toEqual({ field: 'env.a', op: 'eq', ref: 'env' });
    expect(whereOf('context.a == principal.b.c')).toEqual({ field: 'env.a', op: 'eq', ref: 'subject.b.c' });
    // a path-looking rhs that is not a valid path is not a literal either
    expect(dropped('context.a == resource.1x')).toBe(true);
    expect(dropped('context.a == principalx')).toBe(true);
    expect(dropped('context.a == contextual')).toBe(true);
  });
  it('word operators: in', () => {
    expect(whereOf('principal.d in ["a", "b"]')).toEqual({ field: 'subject.d', op: 'in', value: ['a', 'b'] });
    expect(whereOf('principal.d in [1, true, "x"]')).toEqual({ field: 'subject.d', op: 'in', value: [1, true, 'x'] });
    expect(whereOf('principal.d in []')).toEqual({ field: 'subject.d', op: 'in', value: [] });
    expect(whereOf('principal.d in [ "a" , ]')).toEqual({ field: 'subject.d', op: 'in', value: ['a'] });
    expect(whereOf('principal.d in ["a"')).toEqual({ field: 'subject.d', op: 'in', value: ['a'] });
    expect(whereOf('principal in [Group::"a", Group::"b"]')).toEqual({ field: 'subject.id', op: 'member_of', value: ['Group::a', 'Group::b'], collection: EP });
    expect(whereOf('principal in [Group::"a", "x"]')).toEqual({ field: 'subject.id', op: 'in', value: ['Group::a', 'x'] });
    expect(dropped('principal.d in [foo]')).toBe(true);
    expect(whereOf('principal in Group::"g"')).toEqual({ field: 'subject.id', op: 'member_of', value: 'Group::g', collection: EP });
    expect(whereOf('resource in Folder::"f"')).toEqual({ field: 'action.resource', op: 'member_of', value: 'Folder::f', collection: EP });
    expect(whereOf('principal in resource.group')).toEqual({ field: 'subject.id', op: 'member_of', ref: 'env.resource.group', collection: EP });
    expect(dropped('principal in foo')).toBe(true);
    expect(dropped('principal in resource.1x')).toBe(true);
    expect(dropped('foo in [1]')).toBe(true);
    expect(whereOf('principal in context')).toEqual({ field: 'subject.id', op: 'member_of', ref: 'env', collection: EP });
  });
  it('word operators: is / has / like', () => {
    expect(whereOf('principal is User')).toEqual({ field: 'subject.id', op: 'is_a', value: 'User' });
    expect(whereOf('resource.o is Ns::Org')).toEqual({ field: 'env.resource.o', op: 'is_a', value: 'Ns::Org' });
    expect(dropped('principal is "x"')).toBe(true);
    expect(dropped('foo is User')).toBe(true);
    expect(dropped('principal is 1x')).toBe(true);
    expect(whereOf('principal has dept')).toEqual({ field: 'subject.dept', op: 'exists' });
    expect(Object.keys(whereOf('principal has dept') as object)).toEqual(['field', 'op']);
    expect(whereOf('resource has _x9')).toEqual({ field: 'env.resource._x9', op: 'exists' });
    expect(whereOf('context has flag')).toEqual({ field: 'env.flag', op: 'exists' });
    expect(whereOf('principal.org has dept')).toEqual({ field: 'subject.org.dept', op: 'exists' });
    expect(dropped('principal has a.b')).toBe(true);
    expect(dropped('principal has 1x')).toBe(true);
    expect(dropped('action has x')).toBe(true);
    expect(dropped('foo has x')).toBe(true);
    expect(whereOf('resource.name like "a*b"')).toEqual({ field: 'env.resource.name', op: 'like', value: 'a*b' });
    expect(whereOf('resource.name like ""')).toEqual({ field: 'env.resource.name', op: 'like', value: '' });
    expect(dropped('resource.name like foo')).toBe(true);
    expect(dropped('foo like "a"')).toBe(true);
    expect(whereOf('resource.name like "multi word *"')).toEqual({ field: 'env.resource.name', op: 'like', value: 'multi word *' });
  });
  it('like glob conversion', () => {
    const g = (pat: string) => (whereOf(`resource.n like "${pat}"`) as { value: string }).value;
    expect(g('a*b')).toBe('a*b');
    expect(g('a?b')).toBe('a\\?b');
    expect(g('a\\*b')).toBe('a\\*b');
    expect(g('a\\\\b')).toBe('a\\\\b');
    expect(g('a\\?b')).toBe('a\\?b');
    expect(g('a\\nb')).toBe('anb');
    expect(g('a\\')).toBe('a\\\\');
    expect(g('**')).toBe('**');
    expect(g('\\*\\*')).toBe('\\*\\*');
    expect(g('plain')).toBe('plain');
    expect(g('x\\\\*')).toBe('x\\\\*');
  });
  it('boolean structure', () => {
    const A = { field: 'env.a', op: 'eq', value: 1 };
    const B = { field: 'env.b', op: 'eq', value: 2 };
    const C = { field: 'env.c', op: 'eq', value: 3 };
    expect(whereOf('context.a == 1 && context.b == 2')).toEqual({ all_of: [A, B] });
    expect(whereOf('context.a == 1 || context.b == 2')).toEqual({ any_of: [A, B] });
    expect(whereOf('context.a == 1 && context.b == 2 && context.c == 3')).toEqual({ all_of: [A, B, C] });
    expect(whereOf('context.a == 1 || context.b == 2 && context.c == 3')).toEqual({ any_of: [A, { all_of: [B, C] }] });
    expect(whereOf('(context.a == 1 || context.b == 2) && context.c == 3')).toEqual({ all_of: [{ any_of: [A, B] }, C] });
    expect(whereOf('(context.a == 1)')).toEqual(A);
    expect(whereOf('((context.a == 1))')).toEqual(A);
    expect(whereOf(' ( context.a == 1 ) ')).toEqual(A);
    expect(whereOf('(context.a == 1) || (context.b == 2)')).toEqual({ any_of: [A, B] });
    expect(whereOf('context.a == 1 && (context.b == 2 || context.c == 3)')).toEqual({ all_of: [A, { any_of: [B, C] }] });
    expect(dropped('context.a == 1 && foo')).toBe(true);
    expect(dropped('context.a == 1 || foo')).toBe(true);
    expect(dropped('(context.a == 1')).toBe(true);
    expect(whereOf('context.s == "a&&b" && context.t == "c||d"')).toEqual({
      all_of: [{ field: 'env.s', op: 'eq', value: 'a&&b' }, { field: 'env.t', op: 'eq', value: 'c||d' }],
    });
    expect(whereOf('principal in [Group::"a(", Group::"b"] && context.a == 1')).toEqual({
      all_of: [{ field: 'subject.id', op: 'member_of', value: ['Group::a(', 'Group::b'], collection: EP }, A],
    });
  });
  it('unless wraps in not, multi-condition exact', () => {
    const r = P('permit(principal, action, resource) unless { context.a == 1 && context.b == 2 };');
    expect(r.predicates[0]?.where).toEqual([{ not: { all_of: [{ field: 'env.a', op: 'eq', value: 1 }, { field: 'env.b', op: 'eq', value: 2 }] } }]);
    const f = P('forbid(principal, action, resource) when { context.a == 1 };');
    expect(f.denies[0]?.where).toEqual([{ field: 'env.a', op: 'eq', value: 1 }]);
    expect(f.report.translated).toEqual(['forbid → deny verb "*" (1 condition(s))']);
  });
  it('quadratic-guard regex handles long whitespace runs quickly', () => {
    const t = Date.now();
    wherePermit('principal' + ' '.repeat(50000) + 'zzz');
    expect(Date.now() - t).toBeLessThan(2000);
  });
});
