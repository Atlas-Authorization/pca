import { describe, expect, it } from 'vitest';
import { regoToPca } from './rego';
import { openfgaToPca } from './openfga';

const rego = (body: string) => regoToPca(`default allow = false\nallow {\n${body}\n}\n`);

describe('rego selectors', () => {
  it('a repeated or narrowing action selector keeps the common verbs', () => {
    expect(rego('input.action == "read"\ninput.action == "read"').predicates).toEqual([{ verb: 'read' }]);
    expect(rego('input.action == "a"\ninput.action in {"a", "b"}').predicates).toEqual([{ verb: 'a' }]);
    expect(rego('input.action in {"a", "b", "c"}\ninput.action in {"b", "c", "d"}').predicates).toEqual([{ verb: ['b', 'c'] }]);
  });
  it('contradictory action selectors emit nothing and say so', () => {
    const r = rego('input.action == "a"\ninput.action == "b"');
    expect(r.predicates).toEqual([]);
    expect(r.report.translated).toContain('rule can never match (contradictory action selectors), nothing emitted');
  });
  it('resource selectors: equal ones merge, different ones emit nothing and say so', () => {
    expect(rego('input.resource == "r1"\ninput.resource == "r1"').predicates).toEqual([{ verb: '*', resource: 'r1' }]);
    const r = rego('input.resource == "r1"\ninput.resource == "r2"');
    expect(r.predicates).toEqual([]);
    expect(r.report.translated).toContain('rule can never match (contradictory resource selectors), nothing emitted');
  });
  it('a double negation stays a modeled condition', () => {
    expect(rego('not not input.a < 3').predicates).toEqual([
      { verb: '*', where: [{ not: { not: { field: 'env.a', op: 'lt', value: 3 } } }] },
    ]);
  });
});

describe('openfga public tuples', () => {
  const model = {
    schema_version: '1.1',
    type_definitions: [{ type: 'user' }, { type: 'bot' }, { type: 'doc', relations: { viewer: { this: {} } } }],
  };
  const t = (user: string) => ({ user, relation: 'viewer', object: 'doc:d' });
  const pred = (where: unknown[]) => ({ verb: 'viewer', resource: 'doc:d', where });
  const like = (value: string) => ({ field: 'subject.id', op: 'like', value });

  it('a public tuple with no named subject has no exclusion', () => {
    expect(openfgaToPca(model, [t('user:*')]).predicates).toEqual([pred([like('user:*')])]);
  });
  it('the exclusion lists only named subjects of the public type', () => {
    expect(openfgaToPca(model, [t('user:*'), t('bot:b1'), t('user:u1')]).predicates).toEqual([
      pred([{ field: 'subject.id', op: 'eq', value: 'bot:b1' }]),
      pred([{ field: 'subject.id', op: 'eq', value: 'user:u1' }]),
      pred([like('user:*'), { not: { field: 'subject.id', op: 'in', value: ['user:u1'] } }]),
    ]);
  });
  it('public types are emitted in sorted order', () => {
    expect(openfgaToPca(model, [t('user:*'), t('bot:*')]).predicates).toEqual([pred([like('bot:*')]), pred([like('user:*')])]);
  });
  it('glob metacharacters in a type name are escaped, other characters are not', () => {
    expect(openfgaToPca(model, [t('a*b?c\\d:*')]).predicates).toEqual([pred([like('a\\*b\\?c\\\\d:*')])]);
  });
  it('":*" with no type is an ordinary subject, not a public tuple', () => {
    expect(openfgaToPca(model, [t(':*')]).predicates).toEqual([pred([{ field: 'subject.id', op: 'eq', value: ':*' }])]);
  });
});
