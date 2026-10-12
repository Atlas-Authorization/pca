import { describe, expect, it } from 'vitest';
import { openfgaToPca } from './openfga';

const THIS = { this: {} };
const cu = (relation: unknown) => ({ computedUserset: { relation } });
const t = (user: string, relation: string, object: string) => ({ user, relation, object });
const grant = (verb: string, resource: string, user: string) => ({ verb, resource, where: [{ field: 'subject.id', op: 'eq', value: user }] });
const ttu = (tupleset: string, computed: string) => ({ tupleToUserset: { tupleset: { relation: tupleset }, computedUserset: { relation: computed } } });

describe('openfga round 2', () => {
  it('results always carry empty denies/caveats', () => {
    const r = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { r: THIS } }] }, [t('user:a', 'r', 'doc:1')]);
    expect(r.denies).toEqual([]);
    expect(r.caveats).toEqual([]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a')]);
  });
  it('tupleToUserset with no tupleset tuples for the object grants nothing', () => {
    const m = { type_definitions: [{ type: 'doc', relations: { parent: THIS, v: ttu('parent', 'v'), other: THIS } }] };
    const r = openfgaToPca(m, [t('user:a', 'other', 'doc:2'), t('user:b', 'other', 'doc:3')]);
    expect(r.predicates.filter((p) => p.verb === 'v')).toEqual([]);
    expect(r.predicates.map((p) => p.verb)).toEqual(['other', 'other']);
  });
  it('a ttu relation is not flagged as partial', () => {
    const m = { type_definitions: [{ type: 'doc', relations: { parent: THIS, v: ttu('parent', 'v') } }] };
    expect(openfgaToPca(m, []).report.skipped).toEqual([]);
  });
  it('cycle detection is what stops a non-monotone cycle (6-cycle with a difference)', () => {
    const names = ['a', 'b', 'c', 'd', 'e', 'f'];
    const rel: Record<string, unknown> = { a: { difference: { base: THIS, subtract: cu('b') } } };
    for (let i = 1; i < names.length; i++) rel[names[i]!] = cu(names[(i + 1) % names.length]!);
    const r = openfgaToPca({ type_definitions: [{ type: 'doc', relations: rel }] }, [t('user:u', 'a', 'doc:1')]);
    expect(r.predicates.filter((p) => p.verb === 'a')).toEqual([grant('a', 'doc:1', 'user:u')]);
  });
  it('malformed callable inputs are ignored', () => {
    const fnDef = Object.assign(() => 0, { type: 'fn', relations: { r: THIS } });
    const fnTuple = Object.assign(() => 0, { user: 'user:a', relation: 'r', object: 'fn:1' });
    const r = openfgaToPca({ type_definitions: [fnDef, { type: 'doc', relations: { r: THIS } }] }, [fnTuple, t('user:a', 'r', 'doc:1')]);
    expect(r.report.translated).toEqual(['relation doc#r (direct)']);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a')]);
    expect(r.report.skipped).toEqual([]);
  });
  it('computedUserset objects must be real objects', () => {
    const fnCu = Object.assign(() => 0, { relation: 'x' });
    const r = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { a: { computedUserset: fnCu } } }] }, []);
    expect(r.report.skipped).toEqual(['relation doc#a: computedUserset without a relation — skipped']);
    const arr = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { a: ttu('p', 'v'), b: { tupleToUserset: { tupleset: { relation: ['x'] }, computedUserset: { relation: 'v' } } } } }] }, []);
    expect(arr.report.skipped).toEqual(['relation doc#b: tupleToUserset without a tupleset relation — skipped']);
    const arr2 = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { b: { tupleToUserset: { tupleset: { relation: 'p' }, computedUserset: { relation: ['v'] } } } } }] }, []);
    expect(arr2.report.skipped).toEqual(['relation doc#b: tupleToUserset without a computedUserset relation — skipped']);
  });
  it('an empty type name defines nothing', () => {
    const r = openfgaToPca({ type_definitions: [{ type: '', relations: { r: THIS } }] }, [t('user:a', 'r', ':1')]);
    expect(r.predicates).toEqual([]);
    expect(r.report.skipped).toEqual(['object :1: type "" not defined in model — ignored']);
    expect(r.report.translated).toEqual([]);
  });
  it('a userset suffix that starts the string resolves to the empty object, not to the whole string', () => {
    const m = {
      type_definitions: [
        { type: '#x', relations: { viewer: THIS } },
        { type: 'doc', relations: { parent: THIS, viewer: ttu('parent', 'viewer') } },
      ],
    };
    const r = openfgaToPca(m, [t('user:a', 'viewer', '#x'), t('#x', 'parent', 'doc:1')]);
    expect(r.predicates.filter((p) => p.resource === 'doc:1')).toEqual([]);
    expect(r.predicates).toEqual([grant('viewer', '#x', 'user:a')]);
  });
  it('non-string tuple relations are never coerced', () => {
    const r = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { '5': THIS } }] }, [{ user: 'user:a', relation: 5, object: 'doc:1' }]);
    expect(r.predicates).toEqual([]);
    const ok = openfgaToPca({ type_definitions: [{ type: 'doc', relations: { '5': THIS } }] }, [t('user:a', '5', 'doc:1')]);
    expect(ok.predicates).toEqual([grant('5', 'doc:1', 'user:a')]);
  });
});
