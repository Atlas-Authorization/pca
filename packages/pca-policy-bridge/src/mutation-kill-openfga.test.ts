import { describe, expect, it } from 'vitest';
import { openfgaToPca } from './openfga';

const THIS = { this: {} };
const cu = (relation: unknown) => ({ computedUserset: { relation } });
const model = (...types: [string, Record<string, unknown>?][]) => ({
  type_definitions: types.map(([type, relations]) => (relations === undefined ? { type } : { type, relations })),
});
const t = (user: string, relation: string, object: string) => ({ user, relation, object });
const grant = (verb: string, resource: string, user: string) => ({ verb, resource, where: [{ field: 'subject.id', op: 'eq', value: user }] });
const run = (rel: Record<string, unknown>, tuples: unknown[] = []) => openfgaToPca(model(['doc', rel]), tuples);

describe('model & tuple parsing', () => {
  it('bad models', () => {
    for (const m of [null, undefined, 'x', 5]) {
      expect(openfgaToPca(m, [])).toEqual({
        predicates: [],
        denies: [],
        caveats: [],
        report: { source: 'openfga', translated: [], skipped: [], errors: ['model is not an object'] },
      });
    }
    expect(openfgaToPca({}, []).report.errors).toEqual(['model.type_definitions is missing or not an array']);
    expect(openfgaToPca({ type_definitions: {} }, []).report.errors).toEqual(['model.type_definitions is missing or not an array']);
    expect(openfgaToPca({ type_definitions: 'x' }, []).report.errors).toEqual(['model.type_definitions is missing or not an array']);
  });
  it('tuple argument validation (model error first)', () => {
    expect(openfgaToPca(null, 'x').report.errors).toEqual(['model is not an object', 'tuples is not an array']);
    expect(openfgaToPca(model(), 'x').report.errors).toEqual(['tuples is not an array']);
    expect(openfgaToPca(model(), null).report.errors).toEqual(['tuples is not an array']);
    expect(openfgaToPca(model(), {}).report.errors).toEqual(['tuples is not an array']);
    expect(openfgaToPca(model(), undefined).report.errors).toEqual([]);
    expect(openfgaToPca(model(), []).report.errors).toEqual([]);
  });
  it('junk definitions and relations are skipped', () => {
    const m = {
      type_definitions: [
        null,
        'x',
        { type: '' },
        { type: 5 },
        { relations: { r: THIS } },
        { type: 'doc', relations: { r: THIS, s: 'str', u: null, v: 7 } },
        { type: 'bare', relations: null },
        { type: 'bare2', relations: 'x' },
      ],
    };
    const r = openfgaToPca(m, [t('user:a', 'r', 'doc:1'), t('user:a', 'r', 'bare:1'), t('user:a', 'r', 'bare2:1')]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a')]);
    expect(r.report.translated).toEqual(['relation doc#r (direct)']);
    expect(r.report.errors).toEqual([]);
  });
  it('junk tuples are skipped; only complete string triples count', () => {
    const r = run({ r: THIS }, [
      null,
      'x',
      5,
      { user: 'user:a', relation: 'r' },
      { user: 1, relation: 'r', object: 'doc:1' },
      { user: 'user:a', relation: 2, object: 'doc:1' },
      { user: 'user:a', relation: 'r', object: 3 },
      t('user:ok', 'r', 'doc:1'),
    ]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:ok')]);
    expect(r.report.skipped).toEqual([]);
  });
  it('model-less result stops before userset accounting', () => {
    const r = openfgaToPca(null, [t('g#m', 'r', 'doc:1')]);
    expect(r.report.skipped).toEqual([]);
  });
});

describe('userset tuples and enumeration', () => {
  it('counts userset tuples (not users) and never expands them', () => {
    const r = run({ r: THIS }, [t('grp:a#member', 'r', 'doc:1'), t('grp:b#member', 'r', 'doc:1'), t('user:a', 'r', 'doc:1')]);
    expect(r.report.skipped).toEqual(["2 userset-valued tuple(s) (user contains '#') not expanded to concrete users"]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a')]);
    expect(run({ r: THIS }, [t('grp:a#member', 'r', 'doc:1')]).report.skipped).toEqual([
      "1 userset-valued tuple(s) (user contains '#') not expanded to concrete users",
    ]);
    expect(run({ r: THIS }, [t('user:a', 'r', 'doc:1')]).report.skipped).toEqual([]);
  });
  it('userset-only objects are still enumerated (and unknown types reported)', () => {
    const r = openfgaToPca(model(['doc', { r: THIS }]), [t('grp:a#m', 'r', 'ghost:1'), t('user:a', 'r', 'doc:2')]);
    expect(r.report.skipped).toEqual([
      "1 userset-valued tuple(s) (user contains '#') not expanded to concrete users",
      'object ghost:1: type "ghost" not defined in model — ignored',
    ]);
  });
  it('sorted by object, then relation, then user; duplicates collapse', () => {
    const r = openfgaToPca(model(['doc', { b: THIS, a: THIS }]), [
      t('user:z', 'a', 'doc:2'),
      t('user:y', 'b', 'doc:1'),
      t('user:y', 'a', 'doc:1'),
      t('user:x', 'a', 'doc:1'),
      t('user:x', 'a', 'doc:1'),
      t('user:x', 'b', 'doc:2'),
    ]);
    expect(r.predicates.map((p) => [p.resource, p.verb, (p.where![0] as { value: string }).value])).toEqual([
      ['doc:1', 'a', 'user:x'],
      ['doc:1', 'a', 'user:y'],
      ['doc:1', 'b', 'user:y'],
      ['doc:2', 'a', 'user:z'],
      ['doc:2', 'b', 'user:x'],
    ]);
  });
  it('type extraction uses the first colon; objects without colon are their own type', () => {
    const r = openfgaToPca(model(['a', { r: THIS }], ['bare', { r: THIS }]), [t('user:u', 'r', 'a:b:c'), t('user:u', 'r', 'bare')]);
    expect(r.predicates.map((p) => p.resource)).toEqual(['a:b:c', 'bare']);
    const miss = openfgaToPca(model(['a', { r: THIS }]), [t('user:u', 'r', 'zzz')]);
    expect(miss.report.skipped).toEqual(['object zzz: type "zzz" not defined in model — ignored']);
  });
  it('relations without a plan are silently ignored; tuples on undeclared relations grant nothing', () => {
    const r = run({ r: THIS, bad: {} }, [t('user:a', 'bad', 'doc:1'), t('user:a', 'nope', 'doc:1'), t('user:a', 'r', 'doc:1')]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a')]);
  });
  it('same relation name on two types is resolved per type', () => {
    const r = openfgaToPca(model(['a', { r: THIS }], ['b', { r: cu('s'), s: THIS }]), [t('user:u', 'r', 'a:1'), t('user:u', 's', 'b:1')]);
    expect(r.predicates).toEqual([grant('r', 'a:1', 'user:u'), grant('r', 'b:1', 'user:u'), grant('s', 'b:1', 'user:u')]);
  });
  it('a user is only granted where the tuples say so', () => {
    const r = run({ r: THIS }, [t('user:a', 'r', 'doc:1'), t('user:b', 'r', 'doc:2')]);
    expect(r.predicates).toEqual([grant('r', 'doc:1', 'user:a'), grant('r', 'doc:2', 'user:b')]);
    expect(Object.keys(r.predicates[0]!)).toEqual(['verb', 'resource', 'where']);
  });
});

describe('plan building & reports', () => {
  const rep = (rel: Record<string, unknown>) => run(rel).report;
  it('describe strings', () => {
    expect(rep({ a: THIS }).translated).toEqual(['relation doc#a (direct)']);
    expect(rep({ a: cu('b') }).translated).toEqual(['relation doc#a (computed b)']);
    expect(rep({ a: { union: { child: [THIS, cu('b')] } } }).translated).toEqual(['relation doc#a (union[direct, computed b])']);
    expect(rep({ a: { intersection: { child: [THIS, cu('b')] } } }).translated).toEqual(['relation doc#a (intersection[direct, computed b])']);
    expect(rep({ a: { difference: { base: THIS, subtract: cu('b') } } }).translated).toEqual(['relation doc#a (difference(direct - computed b))']);
    expect(rep({ a: { tupleToUserset: { tupleset: { relation: 'p' }, computedUserset: { relation: 'v' } } } }).translated).toEqual(['relation doc#a (v from p)']);
    expect(rep({ a: { union: { child: [{ union: { child: [THIS] } }, cu('x')] } } }).translated).toEqual(['relation doc#a (union[union[direct], computed x])']);
  });
  it('order: types then relations in declaration order', () => {
    const r = openfgaToPca(model(['b', { z: THIS, a: THIS }], ['a', { m: THIS }]), []);
    expect(r.report.translated).toEqual(['relation b#z (direct)', 'relation b#a (direct)', 'relation a#m (direct)']);
  });
  it('failures', () => {
    const sk = (rel: Record<string, unknown>) => rep(rel).skipped;
    expect(sk({ a: {} })).toEqual(['relation doc#a: unknown rewrite node — skipped']);
    expect(sk({ a: cu('') })).toEqual(['relation doc#a: computedUserset without a relation — skipped']);
    expect(sk({ a: cu(5) })).toEqual(['relation doc#a: computedUserset without a relation — skipped']);
    expect(sk({ a: { computedUserset: null } })).toEqual(['relation doc#a: computedUserset without a relation — skipped']);
    expect(sk({ a: { computedUserset: 'x' } })).toEqual(['relation doc#a: computedUserset without a relation — skipped']);
    expect(sk({ a: { union: {} } })).toEqual(['relation doc#a: union without children — skipped']);
    expect(sk({ a: { union: null } })).toEqual(['relation doc#a: union without children — skipped']);
    expect(sk({ a: { union: 'x' } })).toEqual(['relation doc#a: union without children — skipped']);
    expect(sk({ a: { union: { child: 'x' } } })).toEqual(['relation doc#a: union without children — skipped']);
    expect(sk({ a: { union: { child: [] } } })).toEqual(['relation doc#a: union with no modeled children — skipped']);
    expect(sk({ a: { union: { child: [{}, null] } } })).toEqual(['relation doc#a: union with no modeled children — skipped']);
    expect(sk({ a: { intersection: {} } })).toEqual(['relation doc#a: intersection without children — skipped']);
    expect(sk({ a: { intersection: null } })).toEqual(['relation doc#a: intersection without children — skipped']);
    expect(sk({ a: { intersection: { child: [] } } })).toEqual(['relation doc#a: intersection with no children — skipped']);
    expect(sk({ a: { intersection: { child: [THIS, 5] } } })).toEqual(['relation doc#a: intersection child is not a rewrite — skipped']);
    expect(sk({ a: { intersection: { child: [THIS, null] } } })).toEqual(['relation doc#a: intersection child is not a rewrite — skipped']);
    expect(sk({ a: { intersection: { child: [THIS, {}] } } })).toEqual(['relation doc#a: intersection child unmodeled (unknown rewrite node) — skipped']);
    expect(sk({ a: { difference: null } })).toEqual(['relation doc#a: malformed difference — skipped']);
    expect(sk({ a: { difference: 'x' } })).toEqual(['relation doc#a: malformed difference — skipped']);
    expect(sk({ a: { difference: { base: THIS } } })).toEqual(['relation doc#a: difference needs both base and subtract — skipped']);
    expect(sk({ a: { difference: { subtract: THIS } } })).toEqual(['relation doc#a: difference needs both base and subtract — skipped']);
    expect(sk({ a: { difference: { base: 1, subtract: THIS } } })).toEqual(['relation doc#a: difference needs both base and subtract — skipped']);
    expect(sk({ a: { difference: { base: {}, subtract: THIS } } })).toEqual(['relation doc#a: difference base unmodeled (unknown rewrite node) — skipped']);
    expect(sk({ a: { difference: { base: THIS, subtract: {} } } })).toEqual(['relation doc#a: difference subtract unmodeled (unknown rewrite node) — skipped']);
    expect(sk({ a: { tupleToUserset: null } })).toEqual(['relation doc#a: malformed tupleToUserset — skipped']);
    expect(sk({ a: { tupleToUserset: 'x' } })).toEqual(['relation doc#a: malformed tupleToUserset — skipped']);
    expect(sk({ a: { tupleToUserset: { computedUserset: { relation: 'v' } } } })).toEqual(['relation doc#a: tupleToUserset without a tupleset relation — skipped']);
    expect(sk({ a: { tupleToUserset: { tupleset: { relation: '' }, computedUserset: { relation: 'v' } } } })).toEqual(['relation doc#a: tupleToUserset without a tupleset relation — skipped']);
    expect(sk({ a: { tupleToUserset: { tupleset: null, computedUserset: { relation: 'v' } } } })).toEqual(['relation doc#a: tupleToUserset without a tupleset relation — skipped']);
    expect(sk({ a: { tupleToUserset: { tupleset: { relation: 7 }, computedUserset: { relation: 'v' } } } })).toEqual(['relation doc#a: tupleToUserset without a tupleset relation — skipped']);
    expect(sk({ a: { tupleToUserset: { tupleset: { relation: 'p' } } } })).toEqual(['relation doc#a: tupleToUserset without a computedUserset relation — skipped']);
    expect(sk({ a: { tupleToUserset: { tupleset: { relation: 'p' }, computedUserset: { relation: '' } } } })).toEqual(['relation doc#a: tupleToUserset without a computedUserset relation — skipped']);
    expect(rep({ a: {} }).translated).toEqual([]);
  });
  it('rewrite kinds are matched by own key, in priority order', () => {
    // `this` wins over everything
    expect(rep({ a: { this: null, union: { child: [] }, computedUserset: cu('x').computedUserset } }).translated).toEqual(['relation doc#a (direct)']);
    expect(rep({ a: { computedUserset: { relation: 'x' }, union: { child: [] } } }).translated).toEqual(['relation doc#a (computed x)']);
    expect(rep({ a: { union: { child: [THIS] }, intersection: { child: [] } } }).translated).toEqual(['relation doc#a (union[direct])']);
    expect(rep({ a: { intersection: { child: [THIS] }, difference: null } }).translated).toEqual(['relation doc#a (intersection[direct])']);
    expect(rep({ a: { difference: { base: THIS, subtract: THIS }, tupleToUserset: null } }).translated).toEqual(['relation doc#a (difference(direct - direct))']);
    expect(rep({ a: Object.create({ this: {} }) }).skipped).toEqual(['relation doc#a: unknown rewrite node — skipped']);
  });
  it('union: unmodeled children are dropped with a partial note (before translated)', () => {
    const r = rep({ a: { union: { child: [THIS, {}, 5, cu('b')] } } });
    expect(r.skipped).toEqual(['relation doc#a: some union children unsupported and dropped (under-approximated)']);
    expect(r.translated).toEqual(['relation doc#a (union[direct, computed b])']);
    // partial propagates from nested unions and through differences
    expect(rep({ a: { union: { child: [{ union: { child: [THIS, {}] } }] } } }).skipped).toEqual([
      'relation doc#a: some union children unsupported and dropped (under-approximated)',
    ]);
    expect(rep({ a: { difference: { base: { union: { child: [THIS, {}] } }, subtract: THIS } } }).skipped).toEqual([
      'relation doc#a: some union children unsupported and dropped (under-approximated)',
    ]);
    expect(rep({ a: { difference: { base: THIS, subtract: { union: { child: [THIS, {}] } } } } }).skipped).toEqual([
      'relation doc#a: some union children unsupported and dropped (under-approximated)',
    ]);
    // a nested partial that is not the last child still marks the outer union partial
    expect(rep({ a: { union: { child: [{ union: { child: [THIS, {}] } }, THIS] } } }).skipped).toHaveLength(1);
    // intersection of a partial union is NOT partial-flagged (flag is dropped)
    expect(rep({ a: { intersection: { child: [{ union: { child: [THIS, {}] } }] } } }).skipped).toEqual([]);
    expect(rep({ a: { union: { child: [THIS, cu('b')] } } }).skipped).toEqual([]);
    expect(rep({ a: { difference: { base: THIS, subtract: THIS } } }).skipped).toEqual([]);
  });
});

describe('evaluation semantics', () => {
  it('computedUserset', () => {
    const r = run({ viewer: THIS, can_view: cu('viewer') }, [t('user:a', 'viewer', 'doc:1')]);
    expect(r.predicates).toEqual([grant('can_view', 'doc:1', 'user:a'), grant('viewer', 'doc:1', 'user:a')]);
    expect(run({ can_view: cu('missing') }, [t('user:a', 'viewer', 'doc:1')]).predicates).toEqual([]);
  });
  it('union / intersection / difference', () => {
    const rel = {
      a: THIS,
      b: THIS,
      u: { union: { child: [cu('a'), cu('b')] } },
      i: { intersection: { child: [cu('a'), cu('b')] } },
      d: { difference: { base: cu('a'), subtract: cu('b') } },
    };
    const tuples = [t('user:1', 'a', 'doc:x'), t('user:2', 'b', 'doc:x'), t('user:3', 'a', 'doc:x'), t('user:3', 'b', 'doc:x')];
    const r = run(rel, tuples);
    const by = (verb: string) => r.predicates.filter((p) => p.verb === verb).map((p) => (p.where![0] as { value: string }).value);
    expect(by('u')).toEqual(['user:1', 'user:2', 'user:3']);
    expect(by('i')).toEqual(['user:3']);
    expect(by('d')).toEqual(['user:1']);
  });
  it('union grants through a modeled child even when siblings are unsupported', () => {
    const r = run({ a: THIS, u: { union: { child: [{}, cu('a')] } } }, [t('user:1', 'a', 'doc:x')]);
    expect(r.predicates.map((p) => p.verb)).toEqual(['a', 'u']);
  });
  it('tupleToUserset follows the tupleset relation and strips userset suffixes', () => {
    const m = openfgaToPca(
      model(['folder', { viewer: THIS }], ['doc', { parent: THIS, viewer: { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } } } }]),
      [
        t('user:a', 'viewer', 'folder:f1'),
        t('folder:f1', 'parent', 'doc:d1'),
        t('folder:f2#parent', 'parent', 'doc:d2'),
        t('user:a', 'viewer', 'folder:f2'),
        t('folder:f3', 'parent', 'doc:d3'),
      ],
    );
    expect(m.predicates.filter((p) => p.verb === 'viewer' && String(p.resource).startsWith('doc'))).toEqual([
      grant('viewer', 'doc:d1', 'user:a'),
      grant('viewer', 'doc:d2', 'user:a'),
    ]);
    // no tupleset tuples for the object: nothing
    expect(openfgaToPca(model(['doc', { v: { tupleToUserset: { tupleset: { relation: 'p' }, computedUserset: { relation: 'v' } } }, p: THIS }]), [t('user:a', 'p', 'doc:1')]).predicates.filter((p) => p.verb === 'v')).toEqual([]);
  });
  it('tupleToUserset with several parents: any parent suffices', () => {
    const m = openfgaToPca(
      model(['folder', { viewer: THIS }], ['doc', { parent: THIS, viewer: { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } } } }]),
      [t('folder:f1', 'parent', 'doc:d'), t('folder:f2', 'parent', 'doc:d'), t('user:a', 'viewer', 'folder:f2')],
    );
    expect(m.predicates.filter((p) => p.resource === 'doc:d' && p.verb === 'viewer')).toEqual([grant('viewer', 'doc:d', 'user:a')]);
  });
  it('cycles terminate and grant nothing', () => {
    expect(run({ a: cu('b'), b: cu('a') }, [t('user:a', 'a', 'doc:1')]).predicates).toEqual([]);
    expect(run({ a: cu('a') }, [t('user:a', 'a', 'doc:1')]).predicates).toEqual([]);
    const m = openfgaToPca(
      model(['doc', { parent: THIS, v: { union: { child: [THIS, { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'v' } } }] } } }]),
      [t('doc:2', 'parent', 'doc:1'), t('doc:1', 'parent', 'doc:2'), t('user:a', 'v', 'doc:1')],
    );
    expect(m.predicates.filter((p) => p.verb === 'v')).toEqual([grant('v', 'doc:1', 'user:a'), grant('v', 'doc:2', 'user:a')]);
  });
  it('visited set is per-path, not global (diamond)', () => {
    const r = run({ c: THIS, a: cu('c'), b: cu('c'), both: { intersection: { child: [cu('a'), cu('b')] } } }, [t('user:u', 'c', 'doc:1')]);
    expect(r.predicates.map((p) => p.verb)).toEqual(['a', 'b', 'both', 'c']);
  });
  it('depth bound: a chain of 33 computed hops resolves, 34 does not', () => {
    const chain = (n: number): Record<string, unknown> => {
      const rel: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) rel[`r${String(i).padStart(2, '0')}`] = cu(`r${String(i + 1).padStart(2, '0')}`);
      rel[`r${String(n).padStart(2, '0')}`] = THIS;
      return rel;
    };
    const holds = (n: number) => run(chain(n), [t('user:u', `r${String(n).padStart(2, '0')}`, 'doc:1')]).predicates.some((p) => p.verb === 'r00');
    expect(holds(32)).toBe(true);
    expect(holds(33)).toBe(false);
  });
  it('depth bound applies to tupleToUserset hops', () => {
    // docN --parent--> docN+1 ; viewer on final doc; chain length = number of ttu hops
    const mk = (hops: number) => {
      const tuples: unknown[] = [];
      for (let i = 0; i < hops; i++) tuples.push(t(`doc:d${i + 1}`, 'parent', `doc:d${i}`));
      tuples.push(t('user:u', 'viewer', `doc:d${hops}`));
      const m = openfgaToPca(
        model(['doc', { parent: THIS, viewer: { union: { child: [THIS, { tupleToUserset: { tupleset: { relation: 'parent' }, computedUserset: { relation: 'viewer' } } }] } } }]),
        tuples,
      );
      return m.predicates.some((p) => p.verb === 'viewer' && p.resource === 'doc:d0');
    };
    expect(mk(32)).toBe(true);
    expect(mk(33)).toBe(false);
  });
  it('direct tuples are per (object, relation)', () => {
    const r = run({ a: THIS, b: THIS }, [t('user:u', 'a', 'doc:1')]);
    expect(r.predicates).toEqual([grant('a', 'doc:1', 'user:u')]);
  });
});
