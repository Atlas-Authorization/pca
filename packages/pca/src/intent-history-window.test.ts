import { describe, expect, it } from 'vitest';
import { accPreState, admitIntentAction, inWindow, type AccumulatorDecl, type IntentEvent } from './ext/intent';
import { MemoryIntentSessionStore } from './intent-history-testing';

/**
 * 0.4.2 SECURITY: a counted event stamped AFTER the candidate's time must count toward the cap (spec §2.1,
 * E_ψ uses t_i ∈ win(t) ∪ (t, ∞)). Before the fix `inWindow` returned false for t_i > t, so a reservation committed by a
 * concurrent request (whose clock read was later than ours) was invisible to the cap sum and the sequencer over-admitted.
 */

const T = 1_800_000_000_000;

describe('inWindow boundaries (spec §2.1)', () => {
  it('task: every safe-integer time, past, present and future', () => {
    const w = { kind: 'task' } as const;
    expect(inWindow(w, 0, T)).toBe(true);
    expect(inWindow(w, T, T)).toBe(true);
    expect(inWindow(w, T + 1, T)).toBe(true); // future-stamped (was false: the bug)
    expect(inWindow(w, Number.MAX_SAFE_INTEGER, 0)).toBe(true);
  });

  it('sliding(Δ): (t − Δ, t] plus everything after t', () => {
    const w = { kind: 'sliding', ms: 1_000 } as const;
    expect(inWindow(w, T - 1_000, T)).toBe(false); // open lower bound
    expect(inWindow(w, T - 999, T)).toBe(true);
    expect(inWindow(w, T, T)).toBe(true); // closed upper bound
    expect(inWindow(w, T + 1, T)).toBe(true); // future-stamped (was false)
    expect(inWindow(w, T + 10 * 1_000, T)).toBe(true); // far future still has not left the window
    expect(inWindow({ kind: 'sliding', ms: 1 }, T, T)).toBe(true);
    expect(inWindow({ kind: 'sliding', ms: 1 }, T - 1, T)).toBe(false);
  });

  it('period(P, t0): the period containing t plus everything after t', () => {
    const w = { kind: 'period', ms: 1_000, t0: 0 } as const;
    const t = 10_500;
    expect(inWindow(w, 9_999, t)).toBe(false); // previous period
    expect(inWindow(w, 10_000, t)).toBe(true); // period start (inclusive)
    expect(inWindow(w, t, t)).toBe(true);
    expect(inWindow(w, 10_999, t)).toBe(true); // same period, after t
    expect(inWindow(w, 11_000, t)).toBe(true); // next period, after t: counts (fail closed)
    const off = { kind: 'period', ms: 1_000, t0: 250 } as const;
    expect(inWindow(off, 10_249, 10_250)).toBe(false);
    expect(inWindow(off, 10_250, 10_250)).toBe(true);
    expect(inWindow(off, 10_249, 10_249)).toBe(true);
  });

  it('a time that is not a safe integer is never in a window', () => {
    for (const w of [{ kind: 'task' }, { kind: 'sliding', ms: 1_000 }, { kind: 'period', ms: 1_000, t0: 0 }] as const) {
      for (const bad of [Number.NaN, 1.5, Number.POSITIVE_INFINITY, 2 ** 53, -(2 ** 53)]) {
        expect(inWindow(w, bad, T)).toBe(false);
        expect(inWindow(w, T, bad)).toBe(false);
      }
    }
  });
});

const CAP: AccumulatorDecl = { id: 'spend', agg: 'sum', unit: 'usd_cents', val: 'action.params.amount', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, domain_max: 100_000, holder: { kind: 'site_local' } };
const ev = (id: string, amount: number, t: number, status: IntentEvent['status'] = 'reserved'): IntentEvent => ({ id, verb: 'pay', resource: 'r', params: { amount }, t, status });

describe('accPreState: future-stamped events count; unreadable times fail closed', () => {
  it('a counted event stamped after the candidate is in the pre-state (every window kind)', () => {
    const h = [ev('a', 30_000, T + 5)];
    for (const win of [{ kind: 'task' }, { kind: 'sliding', ms: 1_000 }, { kind: 'period', ms: 60_000, t0: 0 }] as const) {
      expect(accPreState({ ...CAP, win }, h, { params: { amount: 1 }, t: T })).toEqual({ sum: 30_000 });
    }
    expect(accPreState({ ...CAP, agg: 'count' }, h, { params: {}, t: T })).toEqual({ count: 1 });
    expect(accPreState({ ...CAP, agg: 'max' }, h, { params: {}, t: T })).toEqual({ max: 30_000 });
    // released / reverted events still never count, future-stamped or not
    expect(accPreState(CAP, [ev('a', 30_000, T + 5, 'released'), ev('b', 1, T + 5, 'reverted')], { params: {}, t: T })).toEqual({ sum: 0 });
  });

  it('a counted event (or a candidate) with a non-integer time throws instead of being dropped from the cap', () => {
    expect(() => accPreState(CAP, [ev('a', 30_000, Number.NaN)], { params: {}, t: T })).toThrow(/safe integer/);
    expect(() => accPreState(CAP, [ev('a', 30_000, 1.5)], { params: {}, t: T })).toThrow(/safe integer/);
    expect(() => accPreState(CAP, [ev('a', 30_000, T)], { params: {}, t: Number.NaN })).toThrow(/safe integer/);
    // an event that does not count is irrelevant to the cap
    expect(accPreState(CAP, [ev('a', 30_000, Number.NaN, 'released')], { params: {}, t: T })).toEqual({ sum: 0 });
  });

  it('DETERMINISTIC REGRESSION: stale admission times (time read before the lock) never pass the cap', async () => {
    // 8 actions of 30000 under a 100000 cap. Each captured its time BEFORE queueing for the session lock, and they
    // obtain the lock in the REVERSE order of their clock reads: every admission after the first carries a time older
    // than all the reservations already in the history. The old window dropped all of those (t_i > t), so every one of
    // the 8 saw pre = 0 and was admitted (240000). Now exactly 3 are admitted.
    const store = new MemoryIntentSessionStore();
    const admitted: string[] = [];
    for (let k = 7; k >= 0; k--) {
      const id = `a${k}`;
      const v = await admitIntentAction(store, { requireDurable: false,
        session: 's',
        root: { accumulators: [CAP], monitors: [] },
        event: { id, verb: 'pay', resource: 'r', params: { amount: 30_000 }, t: T + k },
        verify: async (acc) => ({ allow: (acc.state.spend as { sum: number }).sum + 30_000 <= CAP.domain_max! }),
      });
      if (v.allow) admitted.push(id);
    }
    expect(admitted).toHaveLength(3);
    expect(store.snapshot('s').reduce((s, e) => s + (e.params.amount as number), 0)).toBe(90_000);
  });
});
