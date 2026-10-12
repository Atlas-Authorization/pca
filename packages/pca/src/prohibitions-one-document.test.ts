/**
 * checkAndAdvance evaluates the constitution ONCE (one regex document) and feeds that result to both the evidence and the
 * decision. Differential: the result is identical to the former two-evaluation composition (frozen below as `legacy`)
 * over a seeded corpus of every invariant kind, regex and glob triggers, where-conditions, allowed / refused / CAS paths
 * and state chains. Cost: the evidence + decision share exactly ONE document of regex work.
 */
import { describe, expect, it } from 'vitest';
import {
  advanceStateStrict, checkAndAdvance, checkProhibitions, composeAuthority, emptyState, proveSafety, stateDigest,
  type CheckAndAdvanceOptions, type CheckAndAdvanceResult, type Constitution, type Invariant, type MonitorState,
} from './prohibitions';
import { RegexBudget } from './regex-budget';
import type { ActionContext } from './predicates';

/** The pre-change body of checkAndAdvance, verbatim except for the two separate evaluations it made. */
function legacy(permitted: boolean, action: ActionContext, constitution: Constitution, state: MonitorState, opts: CheckAndAdvanceOptions = {}): CheckAndAdvanceResult {
  const evidence = proveSafety(action, constitution, state);
  const decision = composeAuthority(permitted, action, constitution, state);
  const refuse = (decidedBy: CheckAndAdvanceResult['decidedBy'], reason?: string): CheckAndAdvanceResult => ({
    allow: false, decidedBy, evidence, prohibition: decision.prohibition, next: state, ...(reason ? { reason } : {}),
  });
  try {
    if (opts.expectedSeq !== undefined && (state === null || typeof state !== 'object' || Array.isArray(state) || state.seq !== opts.expectedSeq)) return refuse('state', 'stale state head (seq)');
    if (opts.expectedStateDigest !== undefined) {
      let d: string;
      try { d = stateDigest(state); } catch { d = '<unhashable>'; }
      if (d !== opts.expectedStateDigest) return refuse('state', 'stale state head (digest)');
    }
    if (!decision.allow) return refuse(decision.decidedBy === 'none' ? 'permission' : decision.decidedBy);
    if (!evidence.ok) return refuse('prohibition', 'evidence not attestable');
    const adv = advanceStateStrict(action, constitution, state);
    if (!adv.ok) return refuse('state', 'advance failed: ' + adv.reason);
    return { allow: true, decidedBy: 'none', evidence, prohibition: decision.prohibition, next: adv.state };
  } catch {
    return refuse('state', 'check-and-advance error (fail closed)');
  }
}

class Prng {
  constructor(private s: number) {}
  next(): number {
    this.s = (this.s * 1103515245 + 12345) & 0x7fffffff;
    return this.s / 0x80000000;
  }
  int(n: number): number {
    return Math.floor(this.next() * n);
  }
  pick<T>(a: readonly T[]): T {
    return a[this.int(a.length)]!;
  }
}

const NOW = 1_700_000_000_000;
const VERBS = ['pay', 'send', 'read', 'delete', 'deploy', 'review', 'export'];
const RES = ['/vendor/acme', '/prod/db1', '/secrets/k', '/net/out', '/a/b', 'x'];
const PATTERNS = ['*', '/prod/*', '/secrets/*', '/net/*', 're:/a/[^/]+', 're:/(prod|net)/.*', 're:' + '.*' + '[^]{8}'.repeat(4) + '.*', 're:(a+)+', 're:('];
const when = (r: Prng) => ({
  verb: r.int(4) === 0 ? [r.pick(VERBS), r.pick(VERBS)] : r.pick([...VERBS, '*']),
  ...(r.int(3) ? { resource: r.pick(PATTERNS) } : {}),
  ...(r.int(4) === 0 ? { where: [{ field: 'action.params.flag', op: 'eq', value: true }] } : {}),
});
function invariant(r: Prng, i: number): Invariant {
  const id = `i${i}`;
  switch (r.int(7)) {
    case 0: return { id, kind: 'never', when: when(r) } as Invariant;
    case 1: return { id, kind: 'never_unless', when: when(r), unless: [{ field: 'env.ok', op: 'eq', value: true }] } as Invariant;
    case 2: return { id, kind: 'cap', when: when(r), amount: 'action.params.usd', max: r.pick([10, 100, 1000]), window_secs: 86_400 } as Invariant;
    case 3: return { id, kind: 'rate', when: when(r), max: r.pick([1, 2, 5]), window_secs: 60 } as Invariant;
    case 4: return { id, kind: 'never_after', after: when(r), forbid: when(r) } as Invariant;
    case 5: return { id, kind: 'require_prior', when: when(r), prior: when(r) } as Invariant;
    default: return { id, kind: 'require_approval_over', when: when(r), amount: 'action.params.usd', threshold: 50, approved: [{ field: 'env.ok', op: 'eq', value: true }] } as Invariant;
  }
}
const action = (r: Prng): ActionContext => ({
  action: { verb: r.pick(VERBS), resource: r.pick(RES), params: { usd: r.pick([1, 20, 60, 200]), flag: r.int(2) === 0 } },
  env: { ok: r.int(3) === 0 },
});

describe('checkAndAdvance: one evaluation, identical results', () => {
  it('differential vs the former two-evaluation composition over a seeded corpus (sequences of 6 actions)', () => {
    const r = new Prng(20261011);
    let allowed = 0, refused = 0;
    for (let k = 0; k < 400; k++) {
      const c: Constitution = { version: 1, principal: 'P'.repeat(43), invariants: Array.from({ length: 1 + r.int(5) }, (_, i) => invariant(r, i)) };
      let st = emptyState(NOW);
      for (let step = 0; step < 6; step++) {
        const a = action(r);
        const permitted = r.int(4) !== 0;
        const opts: CheckAndAdvanceOptions = r.pick([{}, {}, { expectedSeq: st.seq }, { expectedSeq: st.seq + 1 }, { expectedStateDigest: stateDigest(st) }, { expectedStateDigest: 'stale' }]);
        const want = legacy(permitted, a, c, st, opts);
        const got = checkAndAdvance(permitted, a, c, st, opts);
        expect(got, `case ${k}.${step}`).toEqual(want);
        if (got.allow) { allowed++; st = { ...got.next, now: got.next.now + 1000 }; } else refused++;
      }
    }
    expect(allowed).toBeGreaterThan(100);
    expect(refused).toBeGreaterThan(100);
  });
  it('malformed inputs: identical results', () => {
    const c: Constitution = { version: 1, principal: 'P'.repeat(43), invariants: [{ id: 'n', kind: 'never', when: { verb: 'x' } } as Invariant] };
    for (const [a, cc, st] of [[null, c, emptyState(NOW)], [{ action: { verb: 'x', resource: 'r' } }, null, emptyState(NOW)], [{ action: { verb: 'y', resource: 'r' } }, c, null], [{ action: { verb: 'y', resource: 'r' } }, { ...c, invariants: [{ kind: 'zz' }] }, emptyState(NOW)]] as const) {
      expect(checkAndAdvance(true, a as never, cc as never, st as never)).toEqual(legacy(true, a as never, cc as never, st as never));
    }
  });
  it('the evidence does not alias the returned prohibition result', () => {
    const c: Constitution = { version: 1, principal: 'P'.repeat(43), invariants: [{ id: 'n', kind: 'never', when: { verb: 'x' } } as Invariant] };
    const res = checkAndAdvance(true, { action: { verb: 'x', resource: 'r' } } as never, c, emptyState(NOW));
    expect(res.evidence.evaluated).toEqual(res.prohibition.evaluated);
    expect(res.evidence.evaluated).not.toBe(res.prohibition.evaluated);
    expect(res.evidence.evaluated[0]).not.toBe(res.prohibition.evaluated[0]);
  });
});

describe('checkAndAdvance cost: exactly one document for evidence + decision', () => {
  const heavy = '.*' + '[^]{64}'.repeat(24) + '.*';
  const c: Constitution = { version: 1, principal: 'P'.repeat(43), invariants: Array.from({ length: 256 }, (_, i) => ({ id: `n${i}`, kind: 'never', when: { verb: '*', resource: 're:' + heavy } }) as Invariant) };
  const a = { action: { verb: 'read', resource: 'a'.repeat(512) }, env: {} } as never;
  it('a refused action: steps, evaluations and chars are exactly one checkProhibitions', () => {
    const one = RegexBudget.request();
    one.run(() => checkProhibitions(a, c, emptyState(NOW)));
    const caa = RegexBudget.request();
    const res = caa.run(() => checkAndAdvance(true, a, c, emptyState(NOW)));
    expect(res.allow).toBe(false);
    expect(one.steps).toBeGreaterThan(0);
    expect([caa.steps, caa.evaluations, caa.chars]).toEqual([one.steps, one.evaluations, one.chars]);
  });
  it('an allowed action: one checkProhibitions plus the state advance (its own document), nothing more', () => {
    const light: Constitution = { version: 1, principal: 'P'.repeat(43), invariants: [{ id: 'r', kind: 'rate', when: { verb: 'read', resource: 're:/a/[^/]+' }, max: 5, window_secs: 60 } as Invariant] };
    const act = { action: { verb: 'read', resource: '/a/b' }, env: {} } as never;
    const one = RegexBudget.request();
    one.run(() => checkProhibitions(act, light, emptyState(NOW)));
    const adv = RegexBudget.request();
    adv.run(() => advanceStateStrict(act, light, emptyState(NOW)));
    const caa = RegexBudget.request();
    const res = caa.run(() => checkAndAdvance(true, act, light, emptyState(NOW)));
    expect(res.allow).toBe(true);
    expect(caa.steps).toBe(one.steps + adv.steps);
    expect(caa.evaluations).toBe(one.evaluations + adv.evaluations);
  });
});
