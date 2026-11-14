import { describe, expect, it } from 'vitest';
import { checkFrame, snapshotState, stateDigest, writeSetOf, type FramePostcondition, type FrameReport, type FrameSpec } from './index';

const e = (field: string, value: unknown = 1) => ({ field, op: 'eq' as const, value });
const rep = (over: Partial<FrameReport>): FrameReport => ({ status: 'ok', outOfFrame: [], attributed: [], postViolated: [], missing: [], unmonitored: false, ...over });
const act = { verb: 'v', resource: 'r', params: { t: 3 } };

function run(post: FramePostcondition[], o: { pre?: Record<string, unknown>; post?: Record<string, unknown>; effect?: Record<string, unknown>; state?: string[]; keep?: boolean } = {}): FrameReport {
  const spec: FrameSpec = { state: o.state ?? ['s'], writes: {}, post };
  return checkFrame(spec, act, snapshotState(o.pre ?? { s: 1 }, o.keep ?? true), snapshotState(o.post ?? { s: 1 }, o.keep ?? true), { effect: o.effect ?? {} });
}

describe('snapshots', () => {
  it('an undefined state value digests as null; keepValues=false stores digests only', () => {
    expect(stateDigest(undefined)).toBe(stateDigest(null));
    const s = snapshotState({ a: 1 }, false);
    expect(s.a).toEqual({ digest: stateDigest(1) });
    expect('value' in s.a!).toBe(false);
    expect(snapshotState({ a: 1 }).a).toEqual({ digest: stateDigest(1), value: 1 });
  });
});

describe('writeSetOf parameter selection', () => {
  const spec: FrameSpec = {
    state: [],
    writes: {
      u: { param: 'field', map: { email: ['e'], '5': ['five'], true: ['yes'], undefined: ['bad'], '[object Object]': ['bad'] }, default: ['dflt'] },
      p: { param: 'action.params.field', map: { email: ['e'] }, default: ['dflt'] },
      n: { param: 'field', map: { email: ['e'] } },
      s: { param: 'k.length', map: { '3': ['bad'] }, default: ['d2'] },
      z: { param: 'a.b', map: { '1': ['bad'] } },
    },
  };
  it('string, number and boolean values select by their text; anything else takes the default', () => {
    expect(writeSetOf(spec, { verb: 'u', params: { field: 'email' } })).toEqual(['e']);
    expect(writeSetOf(spec, { verb: 'u', params: { field: 5 } })).toEqual(['five']);
    expect(writeSetOf(spec, { verb: 'u', params: { field: true } })).toEqual(['yes']);
    expect(writeSetOf(spec, { verb: 'u', params: { field: {} } })).toEqual(['dflt']);
    expect(writeSetOf(spec, { verb: 'u', params: {} })).toEqual(['dflt']);
    expect(writeSetOf(spec, { verb: 'u' })).toEqual(['dflt']);
  });
  it('the param may be bare or prefixed with action.params.', () => {
    expect(writeSetOf(spec, { verb: 'p', params: { field: 'email' } })).toEqual(['e']);
    expect(writeSetOf(spec, { verb: 'u', params: { field: 'email' } })).toEqual(['e']);
  });
  it('no default means the empty set, and a copy is returned', () => {
    expect(writeSetOf(spec, { verb: 'n', params: { field: 'phone' } })).toEqual([]);
    const a = writeSetOf(spec, { verb: 'p', params: { field: 'email' } });
    a.push('x');
    expect(writeSetOf(spec, { verb: 'p', params: { field: 'email' } })).toEqual(['e']);
  });
  it('parameter lookup never reads through a string or a null', () => {
    expect(writeSetOf(spec, { verb: 's', params: { k: 'abc' } })).toEqual(['d2']);
    expect(writeSetOf(spec, { verb: 'z', params: { a: null } })).toEqual([]);
  });
});

describe('checkFrame input guard', () => {
  const msg = 'error: spec, action, pre and post must be objects (spec.state an array)';
  const good = { state: ['s'], writes: {} } as FrameSpec;
  const S = snapshotState({ s: 1 });
  it.each([
    ['spec null', null, act, S, S],
    ['spec number', 5, act, S, S],
    ['spec without state array', { writes: {} }, act, S, S],
    ['spec with a non-array state', { state: 'x', writes: {} }, act, S, S],
    ['action null', good, null, S, S],
    ['action number', good, 5, S, S],
    ['pre null', good, act, null, S],
    ['pre number', good, act, 5, S],
    ['post null', good, act, S, null],
    ['post number', good, act, S, 5],
  ])('%s is a pending error report', (_n, spec, action, pre, post) => {
    expect(checkFrame(spec as never, action as never, pre as never, post as never)).toEqual(rep({ status: 'pending', missing: [msg] }));
  });
  it('an empty state is reported as unmonitored', () => {
    expect(checkFrame({ state: [], writes: {} }, act, S, S)).toEqual(rep({ unmonitored: true }));
  });
});

describe('checkFrame frame condition', () => {
  const spec: FrameSpec = { state: ['b', 'a'], writes: {} };
  it('out-of-frame variables are listed in sorted order', () => {
    const r = checkFrame(spec, act, snapshotState({ a: 1, b: 1 }), snapshotState({ a: 2, b: 2 }));
    expect(r).toEqual(rep({ status: 'violated', outOfFrame: ['a', 'b'] }));
  });
  it('an attribution for another variable does not excuse this one', () => {
    const r = checkFrame({ state: ['a'], writes: {} }, act, snapshotState({ a: 1 }), snapshotState({ a: 2 }), { attributions: [{ var: 'zzz', actor: 'user' }], self: 'agent' });
    expect(r).toEqual(rep({ status: 'violated', outOfFrame: ['a'] }));
  });
});

describe('checkFrame deltas', () => {
  const d: FramePostcondition = { id: 'd', verb: 'v', deltas: [{ path: 'cnt', by: 1 }], where: [e('env.effect.x')] };
  it('a delta input that is not a number is pending and the where clause is not evaluated', () => {
    expect(run([d], { pre: { s: 1 }, post: { s: 1, cnt: 2 } })).toEqual(rep({ status: 'pending', missing: ['d:cnt'] }));
    expect(run([d], { pre: { s: 1, cnt: 1 }, post: { s: 1 } })).toEqual(rep({ status: 'pending', missing: ['d:cnt'] }));
    expect(run([d], { pre: { s: 1, cnt: 'a' }, post: { s: 1, cnt: 2 } })).toEqual(rep({ status: 'pending', missing: ['d:cnt'] }));
  });
  it('a wrong delta is a violation and the where clause is not evaluated', () => {
    expect(run([d], { pre: { s: 1, cnt: 1 }, post: { s: 1, cnt: 5 } })).toEqual(rep({ status: 'violated', postViolated: ['d'] }));
  });
  it('an exact delta then evaluates the where clause', () => {
    expect(run([d], { pre: { s: 1, cnt: 1 }, post: { s: 1, cnt: 2 }, effect: { x: 1 } })).toEqual(rep({}));
    expect(run([d], { pre: { s: 1, cnt: 1 }, post: { s: 1, cnt: 2 }, effect: { x: 2 } })).toEqual(rep({ status: 'violated', postViolated: ['d'] }));
  });
  it('missing and violated lists are sorted and de-duplicated', () => {
    const post: FramePostcondition[] = [
      { id: 'z', verb: 'v', deltas: [{ path: 'cnt', by: 1 }] },
      { id: 'y', verb: 'v', deltas: [{ path: 'cnt', by: 1 }] },
      { id: 'a1', verb: 'v', deltas: [{ path: 'p', by: 1 }] },
    ];
    const r = run(post, { state: ['b'], pre: { b: 1, cnt: 1 }, post: { cnt: 5 } });
    expect(r).toEqual(rep({ status: 'violated', missing: ['a1:p', 'b'], postViolated: ['y', 'z'] }));
  });
  it('a postcondition with no where clause (or an empty one) is not evaluated, even for a resource-less action', () => {
    const spec: FrameSpec = { state: [], writes: {}, post: [{ id: 'dd', verb: 'v', deltas: [{ path: 'cnt', by: 1 }] }, { id: 'ee', verb: 'v', where: [] }] };
    const r = checkFrame(spec, { verb: 'v', params: {} } as never, snapshotState({ cnt: 1 }), snapshotState({ cnt: 2 }));
    expect(r).toEqual(rep({ unmonitored: true }));
  });
});

describe('checkFrame where clauses: which env paths must be present', () => {
  it('all_of, any_of and not each contribute the env paths they read', () => {
    const where = [{ all_of: [e('env.effect.a'), e('env.effect.a2')] }, { any_of: [e('env.effect.b')] }, { not: e('env.effect.c') }];
    expect(run([{ id: 'g', verb: 'v', where }])).toEqual(rep({ status: 'pending', missing: ['g:env.effect.a', 'g:env.effect.a2', 'g:env.effect.b', 'g:env.effect.c'] }));
  });
  it('a group key holding a non-array falls through to the next group key', () => {
    const where = [{ all_of: 'x', any_of: [e('env.effect.m')] }, { any_of: 'y', not: e('env.effect.n') }] as never;
    expect(run([{ id: 'g2', verb: 'v', where }])).toEqual(rep({ status: 'pending', missing: ['g2:env.effect.m', 'g2:env.effect.n'] }));
  });
  it('a ref to env counts as a read; action fields, non-env refs and ref-less leaves do not', () => {
    const where = [
      { field: 'action.params.t', op: 'lte' as const, ref: 'env.effect.r' },
      { field: 'action.params.t', op: 'gte' as const, value: 0 },
      { field: 'action.params.t', op: 'eq' as const, ref: 'action.params.t' },
    ];
    expect(run([{ id: 'p3', verb: 'v', where }])).toEqual(rep({ status: 'pending', missing: ['p3:env.effect.r'] }));
    expect(run([{ id: 'p3', verb: 'v', where }], { effect: { r: 3 } })).toEqual(rep({}));
  });
  it('a condition with no field is not a leaf; the evaluator fails it closed', () => {
    expect(run([{ id: 'p4', verb: 'v', where: [{ op: 'eq', value: 1 } as never] }])).toEqual(rep({ status: 'violated', postViolated: ['p4'] }));
  });
  it('path lookup does not read through strings, nulls or the prototype chain', () => {
    const where = [e('env.effect.s.length'), e('env.effect.n.b'), e('env.constructor')];
    expect(run([{ id: 'p5', verb: 'v', where }], { effect: { s: 'str', n: null } })).toEqual(rep({ status: 'pending', missing: ['p5:env.constructor', 'p5:env.effect.n.b', 'p5:env.effect.s.length'] }));
  });
});

describe('checkFrame pre/post nesting of dotted variable names', () => {
  it('siblings share a parent, a null or scalar parent is replaced', () => {
    const vals = { 'a.b': 1, 'a.c': 2, n: null, 'n.x': 3, p: 5, 'p.y': 4 };
    const where = [e('env.pre.a.b', 1), e('env.pre.a.c', 2), e('env.pre.n.x', 3), e('env.pre.p.y', 4), e('env.post.a.c', 2)];
    const r = checkFrame({ state: [], writes: {}, post: [{ id: 'q', verb: 'v', where }] }, act, snapshotState(vals), snapshotState(vals));
    expect(r).toEqual(rep({ unmonitored: true }));
  });
  it('digest-only snapshots contribute no values, not even empty parents', () => {
    const r = checkFrame({ state: [], writes: {}, post: [{ id: 'q', verb: 'v', where: [e('env.pre.a')] }] }, act, snapshotState({ 'a.b': 1 }, false), snapshotState({ 'a.b': 1 }, false));
    expect(r).toEqual(rep({ status: 'pending', missing: ['q:env.pre.a'], unmonitored: true }));
  });
});
