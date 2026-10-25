/**
 * r13 mutation kills for intent-history.ts (group g2): windows, keys, pre-states of every agg, accPost (including the
 * missing-key empty pre-state), every monitor kind step by step, accContextFor's holder / key filter, and the in-memory
 * session store (duplicate ids, settle, lock hand-off and cleanup). Exact outcomes throughout.
 */
import { describe, expect, it } from 'vitest';
import {
  COUNTED_STATUSES,
  EVENT_STATUSES,
  MemoryIntentSessionStore,
  accContextFor as accContextFor_,
  accKeyOf as accKeyOf_,
  accPost as accPost_,
  accPreState as accPreState_,
  admitIntentAction,
  inWindow as inWindow_,
  isCounted as isCounted_,
  monitorState as monitorState_,
  monitorStep as monitorStep_,
  settleIntentEvent,
  type EventStatus,
  type IntentEvent,
} from './intent-history';
import type { AccumulatorDecl, MonitorDecl } from './intent-acc';

// ---- exact outcomes: every call of the module under test is settled, so a thrown error is an outcome compared with
// toEqual (an assertion), never an uncaught error. A throw comes back as { ok: false, error: { name, message } }.
type Settled = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const failed = (e: unknown): Settled => ({ ok: false, error: { name: e instanceof Error ? e.name : typeof e, message: e instanceof Error ? e.message : String(e) } });
const settle = (f: () => unknown): Settled => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return failed(e);
  }
};
const sv = <F extends (...a: never[]) => unknown>(f: F): F =>
  ((...a: Parameters<F>) => {
    const r = settle(() => f(...a));
    return r.ok ? r.value : r;
  }) as unknown as F;
const thrown = (message: string, name = 'Error') => ({ ok: false, error: { name, message } });
const accContextFor = sv(accContextFor_);
const accKeyOf = sv(accKeyOf_);
const accPost = sv(accPost_);
const accPreState = sv(accPreState_);
const inWindow = sv(inWindow_);
const isCounted = sv(isCounted_);
const monitorState = sv(monitorState_);
const monitorStep = sv(monitorStep_);

const T = 1_000_000;
let n = 0;
const ev = (verb: string, params: Record<string, unknown>, t = T, status: EventStatus = 'committed', id = `e${++n}`): IntentEvent => ({ id, verb, resource: 'r', params, t, status });
const SUM: AccumulatorDecl = { id: 'spend', agg: 'sum', val: 'action.params.total', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
const acc = (o: Partial<AccumulatorDecl>): AccumulatorDecl => ({ ...SUM, ...o });

describe('inWindow', () => {
  it('a non-integer time is never in a window', () => {
    expect(inWindow({ kind: 'task' }, 1.5, T)).toBe(false);
    expect(inWindow({ kind: 'task' }, T, 1.5)).toBe(false);
    expect(inWindow({ kind: 'task' }, Number.NaN, T)).toBe(false);
  });
  it('task, sliding, period and future-stamped events', () => {
    expect(inWindow({ kind: 'task' }, 0, T)).toBe(true);
    expect(inWindow({ kind: 'sliding', ms: 10 }, T - 10, T)).toBe(false);
    expect(inWindow({ kind: 'sliding', ms: 10 }, T - 9, T)).toBe(true);
    expect(inWindow({ kind: 'sliding', ms: 10 }, T + 50, T)).toBe(true);
    expect(inWindow({ kind: 'sliding', ms: 0 }, T, T)).toBe(false); // same instant: only the window decides
    expect(inWindow({ kind: 'period', ms: 10, t0: 3 }, 23, 25)).toBe(true);
    expect(inWindow({ kind: 'period', ms: 10, t0: 3 }, 22, 25)).toBe(false);
    expect(inWindow({ kind: 'period', ms: 10, t0: 3 }, 40, 25)).toBe(true);
    expect(inWindow({ kind: 'period', ms: 10, t0: 3 }, 23, 29)).toBe(true); // period [23, 33) is anchored at t0
    expect(inWindow({ kind: 'period', ms: 10, t0: 3 }, 22, 29)).toBe(false);
  });
  it('the status sets', () => {
    expect(EVENT_STATUSES).toEqual(['reserved', 'committed', 'released', 'reverted']);
    expect(COUNTED_STATUSES).toEqual(['reserved', 'committed']);
  });
});

describe('accKeyOf', () => {
  it('the bullet when ungrouped, the canonical key, null when missing', () => {
    expect(accKeyOf({ key: null }, {})).toBe('•');
    expect(accKeyOf({ key: 'action.params.k' }, { k: 'x' })).toBe('"x"');
    expect(accKeyOf({ key: 'action.params.k' }, { k: 7 })).toBe('7');
    expect(accKeyOf({ key: 'action.params.k' }, {})).toBeNull();
    expect(accKeyOf({ key: 'action.params.k' }, Object.create({ k: 'x' }))).toBeNull();
    expect(accKeyOf({ key: 'action.params.k' }, { k: 1.5 })).toBeNull();
  });
});

describe('accPreState', () => {
  const H = [
    ev('pay', { total: 5, to: 'b' }, T - 30),
    ev('pay', { total: 9, to: 'a' }, T - 20, 'reserved'),
    ev('pay', { total: 100, to: 'c' }, T - 10, 'released'),
    ev('pay', { total: 200, to: 'd' }, T - 10, 'reverted'),
    ev('look', { total: 300, to: 'e' }, T - 10),
    ev('pay', { total: 2, to: 'b' }, T - 5),
  ];
  it('every agg over the counted, selected events', () => {
    expect(accPreState(SUM, H, { params: {}, t: T })).toEqual({ sum: 16 });
    expect(accPreState(acc({ agg: 'count', val: undefined }), H, { params: {}, t: T })).toEqual({ count: 3 });
    expect(accPreState(acc({ agg: 'max' }), H, { params: {}, t: T })).toEqual({ max: 9 });
    expect(accPreState(acc({ agg: 'distinct', val: 'action.params.to' }), H, { params: {}, t: T })).toEqual({ values: ['"a"', '"b"'] });
    expect(accPreState(acc({ agg: 'distinct', val: 'action.params.to' }), [], { params: {}, t: T })).toEqual({ values: [] });
    expect(accPreState(SUM, [], { params: {}, t: T })).toEqual({ sum: 0 });
  });
  it('the window and the key group', () => {
    expect(accPreState(acc({ win: { kind: 'sliding', ms: 21 } }), H, { params: {}, t: T })).toEqual({ sum: 11 });
    const K = acc({ key: 'action.params.to' });
    expect(accPreState(K, H, { params: { to: 'b' }, t: T })).toEqual({ sum: 7 });
    expect(accPreState(K, H, { params: { to: 'z' }, t: T })).toEqual({ sum: 0 });
  });
  it('fails closed on a missing key, a bad time, an unreadable value, an overflow', () => {
    expect(accPreState(acc({ key: 'action.params.to' }), H, { params: {}, t: T })).toEqual(thrown('accPreState: the key parameter action.params.to is missing'));
    expect(accPreState(SUM, H, { params: {}, t: 1.5 })).toEqual(thrown('accPreState: the candidate time is not a safe integer'));
    expect(accPreState(SUM, [ev('pay', { total: 1 }, 1.5, 'reserved', 'bad')], { params: {}, t: T })).toEqual(thrown('accPreState: event bad: the time is not a safe integer'));
    expect(accPreState(SUM, [ev('pay', { total: 1 }, 1.5, 'released', 'old')], { params: {}, t: T })).toEqual({ sum: 0 });
    expect(accPreState(SUM, [ev('pay', { total: -1 }, T, 'committed', 'neg')], { params: {}, t: T })).toEqual(thrown('accPreState: event neg: action.params.total must be a non-negative safe integer'));
    expect(accPreState(SUM, [ev('pay', { total: Number.MAX_SAFE_INTEGER }), ev('pay', { total: 1 })], { params: {}, t: T })).toEqual(thrown('accPreState: sum exceeds 2^53-1'));
  });
  it('only a sum accumulator refuses a history whose values add past 2^53-1', () => {
    const big = [ev('pay', { total: Number.MAX_SAFE_INTEGER, to: 'a' }), ev('pay', { total: 7, to: 'b' })];
    expect(accPreState(acc({ agg: 'max' }), big, { params: {}, t: T })).toEqual({ max: Number.MAX_SAFE_INTEGER });
    expect(accPreState(acc({ agg: 'count', val: undefined }), big, { params: {}, t: T })).toEqual({ count: 2 });
    expect(accPreState(acc({ agg: 'distinct', val: 'action.params.to' }), big, { params: {}, t: T })).toEqual({ values: ['"a"', '"b"'] });
  });
});

describe('accPost', () => {
  const H = [ev('pay', { total: 10, k: 'x', to: 'p' })];
  it('combines a selected action, passes the pre-state through otherwise', () => {
    expect(accPost(SUM, H, { verb: 'pay', params: { total: 5 }, t: T })).toBe(15);
    expect(accPost(SUM, H, { verb: 'look', params: { total: 5 }, t: T })).toBe(10);
    expect(accPost(acc({ key: 'action.params.k' }), H, { verb: 'pay', params: { total: 5, k: 'x' }, t: T })).toBe(15);
  });
  it('a missing key starts from the empty pre-state of the agg', () => {
    const K = (o: Partial<AccumulatorDecl>) => acc({ key: 'action.params.k', ...o });
    expect(accPost(K({}), H, { verb: 'pay', params: { total: 5 }, t: T })).toBe(5);
    expect(accPost(K({ agg: 'count', val: undefined }), H, { verb: 'pay', params: {}, t: T })).toBe(1);
    expect(accPost(K({ agg: 'max' }), H, { verb: 'pay', params: { total: 7 }, t: T })).toBe(7);
    expect(accPost(K({ agg: 'distinct', val: 'action.params.to' }), H, { verb: 'pay', params: { to: 'z' }, t: T })).toBe(1);
    for (const o of [{}, { agg: 'count' as const, val: undefined }, { agg: 'max' as const }, { agg: 'distinct' as const, val: 'action.params.to' }]) expect(accPost(K(o), H, { verb: 'look', params: {}, t: T })).toBe(0);
  });
  it('fails closed on an unreadable value or an overflow', () => {
    expect(accPost(SUM, H, { verb: 'pay', params: { total: -1 }, t: T })).toEqual(thrown('accPost: action.params.total must be a non-negative safe integer'));
    expect(accPost(SUM, [ev('pay', { total: Number.MAX_SAFE_INTEGER })], { verb: 'pay', params: { total: 1 }, t: T })).toEqual(thrown('accPost: overflow'));
  });
});

const step = (m: MonitorDecl, q: string, verb: string, status: EventStatus = 'committed') => monitorStep(m, q, { verb, resource: 'r', params: {}, status });
const fold = (m: MonitorDecl, verbs: string[]) => monitorState(m, verbs.map((v) => ev(v, {})));

describe('monitors', () => {
  it('requires_prior / precedes become met and stay met', () => {
    for (const kind of ['requires_prior', 'precedes'] as const) {
      const m: MonitorDecl = { id: 'm', kind, p: { verb: 'a' }, q: { verb: 'g' } };
      expect(fold(m, [])).toBe('unmet');
      expect(fold(m, ['b'])).toBe('unmet');
      expect(fold(m, ['b', 'a', 'b'])).toBe('met');
      expect(step(m, 'unmet', 'a')).toBe('met');
      expect(step(m, 'unmet', 'b')).toBe('unmet');
      expect(step(m, 'met', 'b')).toBe('met');
    }
  });
  it('never: seen is sticky', () => {
    const m: MonitorDecl = { id: 'm', kind: 'never', p: { verb: 'x' } };
    expect(fold(m, ['a', 'b'])).toBe('clean');
    expect(fold(m, ['a', 'x', 'b'])).toBe('seen');
    expect(step(m, 'clean', 'a')).toBe('clean');
    expect(step(m, 'clean', 'x')).toBe('seen');
    expect(step(m, 'seen', 'a')).toBe('seen');
  });
  it('always: broken is sticky', () => {
    const m: MonitorDecl = { id: 'm', kind: 'always', p: { verb: 'a' } };
    expect(fold(m, ['a', 'a'])).toBe('ok');
    expect(fold(m, ['a', 'b', 'a'])).toBe('broken');
    expect(step(m, 'ok', 'a')).toBe('ok');
    expect(step(m, 'ok', 'b')).toBe('broken');
    expect(step(m, 'broken', 'a')).toBe('broken');
  });
  it('responds_within: deadline countdown, response, re-stimulus, missed is sticky', () => {
    const m: MonitorDecl = { id: 'm', kind: 'responds_within', p: { verb: 's' }, q: { verb: 'r' }, within: 3 };
    expect(step(m, 'idle', 'n')).toBe('idle');
    expect(step(m, 'idle', 's')).toBe('pending:3');
    expect(step(m, 'pending:3', 'n')).toBe('pending:2');
    expect(step(m, 'pending:2', 'r')).toBe('idle');
    expect(step(m, 'pending:1', 'n')).toBe('missed');
    expect(step(m, 'pending:2', 's')).toBe('pending:1'); // a new stimulus never extends a running deadline
    expect(step(m, 'missed', 'r')).toBe('missed');
    expect(step(m, 'missed', 's')).toBe('missed');
    expect(fold(m, ['s', 'n', 'n', 'n'])).toBe('missed');
    expect(fold(m, ['s', 'n', 'r'])).toBe('idle');
    const both: MonitorDecl = { id: 'm', kind: 'responds_within', p: { verb: ['s', 'x'] }, q: { verb: ['r', 'x'] }, within: 2 };
    expect(step(both, 'pending:1', 'x')).toBe('pending:2'); // answered, then a fresh stimulus
  });
  it('status: admitted (default) counts reserved and committed; committed counts only committed', () => {
    const adm: MonitorDecl = { id: 'm', kind: 'never', p: { verb: 'x' } };
    const com: MonitorDecl = { ...adm, status: 'committed' };
    expect(step(adm, 'clean', 'x', 'reserved')).toBe('seen');
    expect(step(adm, 'clean', 'x', 'committed')).toBe('seen');
    expect(step(adm, 'clean', 'x', 'released')).toBe('clean');
    expect(step(adm, 'clean', 'x', 'reverted')).toBe('clean');
    expect(step({ ...adm, status: 'admitted' }, 'clean', 'x', 'reserved')).toBe('seen');
    expect(step(com, 'clean', 'x', 'reserved')).toBe('clean');
    expect(step(com, 'clean', 'x', 'committed')).toBe('seen');
    expect(isCounted('reserved')).toBe(true);
    expect(isCounted('released')).toBe(false);
  });
});

describe('accContextFor', () => {
  it('pre-states of the site-local accumulators whose key is present, and every monitor state', () => {
    const H = [ev('pay', { total: 4, k: 'x' }), ev('x', {})];
    const S = {
      accumulators: [
        SUM,
        acc({ id: 'seq', holder: { kind: 'sequenced', uri: 'u', root: 'r' } }),
        acc({ id: 'wal', agg: 'count', val: undefined, sel: { event: 'question' }, holder: { kind: 'wallet' } }),
        acc({ id: 'keyed', key: 'action.params.k' }),
        acc({ id: 'other', key: 'action.params.j' }),
      ],
      monitors: [{ id: 'nv', kind: 'never', p: { verb: 'x' } } as MonitorDecl, { id: 'al', kind: 'always', p: { verb: 'pay' } } as MonitorDecl],
    };
    const c = accContextFor(S, H, { params: { k: 'x' }, t: T });
    expect(settle(() => ({ state: { ...c.state }, monitors: { ...c.monitors }, proto: Object.getPrototypeOf(c.state) }))).toEqual({ ok: true, value: { state: { spend: { sum: 4 }, keyed: { sum: 4 } }, monitors: { nv: 'seen', al: 'broken' }, proto: null } });
  });
});

/** An async outcome, or a 'Hang' failure when it does not settle in time (a lock that is never released). */
const settleA = async (f: () => Promise<unknown>, ms = 1_500): Promise<Settled> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const hang = new Promise<Settled>((r) => {
    timer = setTimeout(() => r({ ok: false, error: { name: 'Hang', message: `no outcome within ${ms} ms` } }), ms);
  });
  try {
    return await Promise.race([Promise.resolve().then(f).then((value): Settled => ({ ok: true, value }), failed), hang]);
  } finally {
    clearTimeout(timer);
  }
};
const okv = (value: unknown) => ({ ok: true, value });

describe('MemoryIntentSessionStore', () => {
  it('append refuses a duplicate id; setStatus reports unknown ids; snapshots are copies', async () => {
    const store = new MemoryIntentSessionStore();
    expect(settle(() => store.snapshot('none'))).toEqual(okv([]));
    const inner: Settled[] = [];
    const body = await settleA(() =>
      store.withSession('s', async (tx) => {
        inner.push(await settleA(() => tx.append(ev('pay', { total: 1 }, T, 'reserved', 'a'))));
        inner.push(await settleA(() => tx.append(ev('pay', { total: 2 }, T, 'reserved', 'b'))));
        inner.push(await settleA(() => tx.append(ev('pay', { total: 3 }, T, 'reserved', 'a'))));
        inner.push(await settleA(() => tx.setStatus('zz', 'committed')));
        inner.push(await settleA(() => tx.setStatus('b', 'committed')));
        inner.push(await settleA(async () => {
          const es = await tx.events();
          const ids = es.map((e) => [e.id, e.status]);
          (es[0] as IntentEvent).status = 'reverted';
          return ids;
        }));
        return 'done';
      }),
    );
    expect({ body, inner }).toEqual({ body: okv('done'), inner: [okv(undefined), okv(undefined), thrown('duplicate event id'), okv(false), okv(true), okv([['a', 'reserved'], ['b', 'committed']])] });
    expect(settle(() => store.snapshot('s').map((e) => [e.id, e.status]))).toEqual(okv([['a', 'reserved'], ['b', 'committed']]));
    expect(settle(() => {
      store.snapshot('s')[0]!.status = 'reverted';
      return store.snapshot('s')[0]!.status;
    })).toEqual(okv('reserved'));
    expect(await settleA(() => settleIntentEvent(store, 's', 'a', 'released'))).toEqual(okv(true));
    expect(await settleA(() => settleIntentEvent(store, 's', 'nope', 'released'))).toEqual(okv(false));
    expect(settle(() => store.snapshot('s').map((e) => e.status))).toEqual(okv(['released', 'committed']));
  });
  it('serialises a session: a caller arriving while a queued holder runs waits for it; the lock map empties', async () => {
    const store = new MemoryIntentSessionStore();
    const log: string[] = [];
    let openA!: () => void;
    let openB!: () => void;
    const gA = new Promise<void>((r) => (openA = r));
    const gB = new Promise<void>((r) => (openB = r));
    const tick = () => new Promise((r) => setTimeout(r, 0));
    const pA = settleA(() =>
      store.withSession('s', async () => {
        log.push('A');
        await gA;
        log.push('A-end');
      }),
    );
    const pB = settleA(() =>
      store.withSession('s', async () => {
        log.push('B');
        await gB;
        log.push('B-end');
      }),
    );
    await tick();
    openA();
    const ra = await pA;
    await tick();
    const pC = settleA(() =>
      store.withSession('s', async () => {
        log.push('C');
      }),
    );
    await tick();
    log.push('gate');
    openB();
    const rest = await Promise.all([pB, pC]);
    const locks = (store as unknown as { locks: Map<string, unknown> }).locks.size;
    expect({ ra, rest, log, locks }).toEqual({ ra: okv(undefined), rest: [okv(undefined), okv(undefined)], log: ['A', 'A-end', 'B', 'gate', 'B-end', 'C'], locks: 0 });
  });
  it('admitIntentAction appends a reserved event only on allow, with the computed context', async () => {
    const store = new MemoryIntentSessionStore();
    const root = { accumulators: [SUM], monitors: [{ id: 'nv', kind: 'never', p: { verb: 'pay' } } as MonitorDecl] };
    const seen: unknown[] = [];
    const run = (id: string, allow: boolean) =>
      settleA(() =>
        admitIntentAction(store, {
          session: 's',
          root,
          event: { id, verb: 'pay', resource: 'r', params: { total: 3 }, t: T },
          verify: async (a) => {
            seen.push({ state: { ...a.state }, monitors: { ...a.monitors } });
            return { allow };
          },
        }),
      );
    const results = [await run('a', true), await run('b', false), await run('c', true)];
    expect({ results, seen, log: settle(() => store.snapshot('s').map((e) => [e.id, e.status])) }).toEqual({
      results: [okv({ allow: true }), okv({ allow: false }), okv({ allow: true })],
      seen: [
        { state: { spend: { sum: 0 } }, monitors: { nv: 'clean' } },
        { state: { spend: { sum: 3 } }, monitors: { nv: 'seen' } },
        { state: { spend: { sum: 3 } }, monitors: { nv: 'seen' } },
      ],
      log: okv([['a', 'reserved'], ['c', 'reserved']]),
    });
  });
});
