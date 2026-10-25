import { describe, expect, it } from 'vitest';
import { applyFrameReport, captureState, checkFrame, createLearner, deriveOmega, elicit, admitter, rng, snapshotState, writeSetOf, type FrameSpec } from './index';

// Intent Layer v2 milestone V9: frames (declared state monitors, write sets, postconditions with env.pre/env.post,
// exact deltas) and T21 (every unattributed out-of-frame change is a divergence that vetoes the cell for good).

const SPEC: FrameSpec = {
  state: ['account.contact_email', 'account.payment_methods', 'loyalty.points', 'bookings'],
  writes: {
    'air.book': ['bookings', 'loyalty.points'],
    'air.update': { param: 'action.params.field', map: { email: ['account.contact_email'] }, default: [] },
  },
  post: [
    { id: 'book.charged', verb: 'air.book', where: [{ field: 'env.effect.charged_cents', op: 'lte', ref: 'action.params.total' }] },
    { id: 'book.count', verb: 'air.book', deltas: [{ path: 'bookings.count', by: 1 }] },
  ],
};
const PRE = { 'account.contact_email': 'ana@example.com', 'account.payment_methods': ['pm_1'], 'loyalty.points': 100, bookings: { count: 3 } };
const book = { verb: 'air.book', resource: 'skyair.example/bookings', params: { total: 77_800 } };

describe('write sets', () => {
  it('fixed and parameter-selected write sets', () => {
    expect(writeSetOf(SPEC, book)).toEqual(['bookings', 'loyalty.points']);
    expect(writeSetOf(SPEC, { verb: 'air.update', params: { field: 'email' } })).toEqual(['account.contact_email']);
    expect(writeSetOf(SPEC, { verb: 'air.update', params: { field: 'phone' } })).toEqual([]);
    expect(writeSetOf(SPEC, { verb: 'air.cancel' })).toEqual([]);
  });
});

describe('checkFrame', () => {
  it('the walkthrough booking: writes inside W, charged <= total, count + 1: ok', () => {
    const post = { ...PRE, 'loyalty.points': 880, bookings: { count: 4 } };
    const r = checkFrame(SPEC, book, snapshotState(PRE), snapshotState(post), { effect: { charged_cents: 77_800 } });
    expect(r).toEqual({ status: 'ok', outOfFrame: [], attributed: [], postViolated: [], missing: [], unmonitored: false });
  });

  it('an out-of-frame change is a violation unless the site log attributes it to another actor', () => {
    const post = { ...PRE, 'account.contact_email': 'evil@example.com', bookings: { count: 4 } };
    const r = checkFrame(SPEC, book, snapshotState(PRE), snapshotState(post), { effect: { charged_cents: 1 } });
    expect(r).toMatchObject({ status: 'violated', outOfFrame: ['account.contact_email'] });
    const excused = checkFrame(SPEC, book, snapshotState(PRE), snapshotState(post), { effect: { charged_cents: 1 }, attributions: [{ var: 'account.contact_email', actor: 'user:ana' }], self: 'agent:a1' });
    expect(excused).toMatchObject({ status: 'ok', attributed: ['account.contact_email'] });
    const own = checkFrame(SPEC, book, snapshotState(PRE), snapshotState(post), { effect: { charged_cents: 1 }, attributions: [{ var: 'account.contact_email', actor: 'agent:a1' }], self: 'agent:a1' });
    expect(own.status).toBe('violated');
  });

  it('postconditions read env.pre / env.post / env.effect; deltas are exact', () => {
    const over = checkFrame(SPEC, book, snapshotState(PRE), snapshotState({ ...PRE, bookings: { count: 4 } }), { effect: { charged_cents: 80_000 } });
    expect(over).toMatchObject({ status: 'violated', postViolated: ['book.charged'] });
    const twice = checkFrame(SPEC, book, snapshotState(PRE), snapshotState({ ...PRE, bookings: { count: 5 } }), { effect: { charged_cents: 1 } });
    expect(twice).toMatchObject({ status: 'violated', postViolated: ['book.count'] });
  });

  it('missing snapshots or effect fields are pending, never a conclusion', () => {
    const { 'loyalty.points': _drop, ...partial } = PRE;
    const a = checkFrame(SPEC, { ...book, verb: 'air.cancel' }, snapshotState(PRE), snapshotState(partial));
    expect(a).toMatchObject({ status: 'pending', missing: ['loyalty.points'] });
    const b = checkFrame(SPEC, book, snapshotState(PRE), snapshotState({ ...PRE, bookings: { count: 4 } }), {});
    expect(b).toMatchObject({ status: 'pending', missing: ['book.charged:env.effect.charged_cents'] });
  });

  it('an empty 𝒱 is reported as unmonitored', () => {
    expect(checkFrame({ state: [], writes: {} }, book, {}, {}).unmonitored).toBe(true);
  });

  it('captureState reads every monitored variable', async () => {
    const s = await captureState({ b: () => 2, a: async () => 1 });
    expect(Object.keys(s)).toEqual(['a', 'b']);
    expect(s.a!.value).toBe(1);
    expect(s.a!.digest).toBe(snapshotState({ a: 1 }).a!.digest);
  });
});

describe('T21: frame detection and the veto ratchet', () => {
  it('every unattributed change outside W is detected, whatever else changes', () => {
    const r = rng(21);
    const vars = SPEC.state;
    for (let i = 0; i < 300; i++) {
      const post: Record<string, unknown> = { ...PRE, bookings: { count: 4 } };
      const changed: string[] = [];
      for (const v of vars) {
        if (r() < 0.3) {
          post[v] = `changed-${i}`;
          changed.push(v);
        }
      }
      const W = new Set(writeSetOf(SPEC, book));
      const outside = changed.filter((v) => !W.has(v)).sort();
      const rep = checkFrame({ ...SPEC, post: [] }, book, snapshotState(PRE), snapshotState(post));
      expect(rep.outOfFrame).toEqual(outside);
      expect(rep.status).toBe(outside.length ? 'violated' : 'ok');
    }
  });

  it('a violation vetoes the action cell, and no later yes re-admits it', () => {
    const V = 'stripe.refund';
    const AMT = 'action.params.amount';
    const omega = deriveOmega({ policies: [], slots: { verbs: [V], constraints: [{ path: AMT, max: 100 }] } });
    const vs = omega.verbs[0]!;
    const truth = admitter({ predicates: [{ verb: V, resource: '*', where: [{ field: AMT, op: 'lte', value: 100 }] }] });
    const l = createLearner(omega, { nullMass: 0.05 });
    elicit(l, (q) => (truth.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 30 });
    const o = { verb: V, values: { [AMT]: 50 } };
    expect(l.admitsOutcome(o)).toBe(true);
    const report = checkFrame({ state: ['x'], writes: {} }, { verb: V, resource: 'r', params: { amount: 50 } }, snapshotState({ x: 1 }), snapshotState({ x: 2 }));
    const res = applyFrameReport(l, o, report);
    expect(res.signal).toBe('postcondition-violation');
    expect(l.admitsOutcome(o)).toBe(false);
    expect(l.isVetoed(o)).toBe(true);
    l.observe(o, 1, 'elicitation');
    l.observe(o, 1, 'runtime');
    expect(l.admitsOutcome(o)).toBe(false);
    expect(applyFrameReport(l, o, { ...report, status: 'ok', outOfFrame: [] })).toEqual({});
  });
});

describe('prototype-named state variables', () => {
  it('constructor / __proto__ / toString are ordinary monitored variables', () => {
    const spec: FrameSpec = { state: ['constructor', '__proto__', 'toString.x'], writes: { v: ['constructor'] } };
    const pre = JSON.parse('{"constructor":1,"__proto__":2,"toString.x":3}') as Record<string, unknown>;
    const post = JSON.parse('{"constructor":9,"__proto__":5,"toString.x":3}') as Record<string, unknown>;
    const r = checkFrame(spec, { verb: 'v', resource: 'r' }, snapshotState(pre), snapshotState(post));
    expect(r).toMatchObject({ status: 'violated', outOfFrame: ['__proto__'] });
    const missing = checkFrame(spec, { verb: 'v', resource: 'r' }, snapshotState({}), snapshotState({}));
    expect(missing.missing).toEqual(['__proto__', 'toString.x']);
    expect(({} as Record<string, unknown>).constructor).toBe(Object);
  });
});

describe('frames and quorum entry points never throw', () => {
  it('checkFrame on malformed input is pending (no conclusion), applyFrameReport ignores a malformed report', () => {
    for (const x of [null, undefined, 1, 'x', []]) {
      expect(checkFrame(x as never, x as never, x as never, x as never).status).toBe('pending');
      expect(applyFrameReport(null as never, null as never, x as never)).toEqual({});
    }
  });
});
