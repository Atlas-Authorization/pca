import { describe, expect, it } from 'vitest';
import { hashCanonical } from './hash';
import { generateKeyPair, encodeKey } from './keys';
import type { ActionContext } from './predicates';
import {
  advanceState,
  advanceStateStrict,
  checkProhibitions,
  emptyState,
  stateDigest,
  type Constitution,
  type Invariant,
  type MonitorState,
} from './prohibitions';
import {
  advanceContract,
  checkAndAdvanceContract,
  checkContract,
  contractFromConstitution,
  contractId,
  CONTRACT_VERSION,
  embeddedConstitution,
  signContract,
  validateContract,
  verifyContract,
  type Clause,
  type Contract,
} from './contracts';

const P = generateKeyPair();
const PRIN = encodeKey(P.publicKey);
const NOW = 1_700_000_000_000;

const act = (verb: string, resource = '/r', params?: Record<string, unknown>, env?: Record<string, unknown>): ActionContext => ({
  action: { verb, resource, ...(params ? { params } : {}) },
  ...(env ? { env } : {}),
});

const contract = (clauses: Clause[], invariants: Invariant[] = []): Contract => ({ version: CONTRACT_VERSION, principal: PRIN, invariants, clauses });

/** Fold a contract over a trace from genesis. Advances only on ok (fail-closed leaves state unchanged). */
function run(c: Contract, actions: ActionContext[], startNow = NOW) {
  let state = emptyState(startNow);
  const results = [];
  let rejected = false;
  let firstReject = -1;
  const states: MonitorState[] = [state];
  for (let i = 0; i < actions.length; i++) {
    const r = advanceContract(state, actions[i]!, c, { now: state.now });
    results.push(r);
    if (!r.ok) {
      rejected = true;
      if (firstReject < 0) firstReject = i;
    }
    state = r.next;
    states.push(state);
  }
  return { state, results, rejected, firstReject, states };
}

// ============================================================================================
// 1. UNIT TESTS — one per operator (accept / reject)
// ============================================================================================

describe('operator: always P (safety / positive authority)', () => {
  const c = contract([{ id: 'only-safe', kind: 'always', p: { verb: '*', resource: '/safe/*' } }]);
  it('accepts a trace where every action satisfies P', () => {
    const r = run(c, [act('read', '/safe/a'), act('write', '/safe/b')]);
    expect(r.rejected).toBe(false);
  });
  it('rejects the first action that does not satisfy P', () => {
    const r = run(c, [act('read', '/safe/a'), act('read', '/prod/x')]);
    expect(r.rejected).toBe(true);
    expect(r.firstReject).toBe(1);
    expect(r.results[1]!.violated).toContain('only-safe');
  });
  it('fail-closed: an unresolvable predicate counts as NOT satisfying P', () => {
    // p requires a param that is absent => affirmative match fails => violation
    const cc = contract([{ id: 'need-param', kind: 'always', p: { verb: '*', where: [{ field: 'action.params.ok', op: 'eq', value: true }] } }]);
    expect(run(cc, [act('read', '/r')]).rejected).toBe(true);
    expect(run(cc, [act('read', '/r', { ok: true })]).rejected).toBe(false);
  });
});

describe('operator: never P (= always ¬P)', () => {
  const c = contract([{ id: 'no-delete', kind: 'never', p: { verb: 'delete', resource: '*' } }]);
  it('accepts when no action matches P', () => {
    expect(run(c, [act('read'), act('write')]).rejected).toBe(false);
  });
  it('rejects when some action matches P', () => {
    const r = run(c, [act('read'), act('delete', '/x')]);
    expect(r.rejected).toBe(true);
    expect(r.results[1]!.violated).toContain('no-delete');
  });
  it('fail-closed: an unresolvable trigger counts as MATCHED (veto)', () => {
    // an unsafe regex resource makes the matcher conservative => matched => violation
    const cc = contract([{ id: 'bad-re', kind: 'never', p: { verb: 'x', resource: 're:(a+)+' } }]);
    // the clause is structurally invalid (unsafe regex) => fails validation => fail closed
    expect(validateContract(cc).length).toBeGreaterThan(0);
    expect(run(cc, [act('x', '/anything')]).rejected).toBe(true);
  });
});

describe('operator: p precedes q / q requires_prior p (precedence)', () => {
  const precedes = contract([{ id: 'review-before-deploy', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } }]);
  const requires = contract([{ id: 'review-before-deploy', kind: 'requires_prior', q: { verb: 'deploy' }, p: { verb: 'review' } }]);

  it('accepts q after p', () => {
    expect(run(precedes, [act('review'), act('deploy')]).rejected).toBe(false);
    expect(run(requires, [act('review'), act('deploy')]).rejected).toBe(false);
  });
  it('rejects q with no prior p', () => {
    const r = run(precedes, [act('deploy')]);
    expect(r.rejected).toBe(true);
    expect(r.results[0]!.violated).toContain('review-before-deploy');
  });
  it('the two spellings are semantically identical', () => {
    const trace = [act('deploy'), act('review'), act('deploy')];
    const a = run(precedes, trace);
    const b = run(requires, trace);
    expect(a.results.map((x) => x.ok)).toEqual(b.results.map((x) => x.ok));
  });
  it('an action that is both p and q does NOT self-satisfy (prior must be a PREVIOUS admitted action)', () => {
    const c = contract([{ id: 'x', kind: 'precedes', p: { verb: 'open' }, q: { verb: 'open' } }]);
    expect(run(c, [act('open')]).rejected).toBe(true); // first open is q with no prior open
    expect(run(c, [act('open'), act('open')]).results.map((x) => x.ok)).toEqual([false, false]);
    // once a DIFFERENT prior p is latched, q is allowed
    const c2 = contract([{ id: 'y', kind: 'precedes', p: { verb: 'prep' }, q: { verb: 'open' } }]);
    expect(run(c2, [act('prep'), act('open')]).rejected).toBe(false);
  });
});

describe('operator: p responds_within N q (bounded liveness as a safety obligation)', () => {
  const c = contract([{ id: 'ack', kind: 'responds_within', p: { verb: 'request' }, q: { verb: 'ack' }, within: 2 }]);

  it('accepts when q lands within N actions of p', () => {
    expect(run(c, [act('request'), act('ack')]).rejected).toBe(false); // within 1
    expect(run(c, [act('request'), act('noise'), act('ack')]).rejected).toBe(false); // within 2 (the boundary)
  });
  it('rejects when q does not land within N actions', () => {
    const r = run(c, [act('request'), act('noise'), act('noise'), act('ack')]);
    expect(r.rejected).toBe(true);
    // deadline missed on the 2nd non-ack action after the request (index 2)
    expect(r.firstReject).toBe(2);
    expect(r.results[2]!.violated).toContain('ack');
  });
  it('a pending-but-unexpired obligation at end of trace is NOT a violation', () => {
    expect(run(c, [act('request')]).rejected).toBe(false); // window has not elapsed
    expect(run(c, [act('request'), act('noise')]).rejected).toBe(false); // still 1 action of budget left
  });
  it('a single response discharges all open obligations (overlapping stimuli)', () => {
    expect(run(c, [act('request'), act('request'), act('ack')]).rejected).toBe(false);
  });
  it('within:1 demands the very next action be q', () => {
    const c1 = contract([{ id: 'ack', kind: 'responds_within', p: { verb: 'request' }, q: { verb: 'ack' }, within: 1 }]);
    expect(run(c1, [act('request'), act('ack')]).rejected).toBe(false);
    expect(run(c1, [act('request'), act('noise')]).rejected).toBe(true);
  });
});

describe('operator: and (conjunction)', () => {
  const c = contract([
    {
      id: 'both',
      kind: 'and',
      clauses: [
        { id: 'no-delete', kind: 'never', p: { verb: 'delete' } },
        { id: 'review-first', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } },
      ],
    },
  ]);
  it('accepts when all sub-clauses hold', () => {
    expect(run(c, [act('review'), act('deploy')]).rejected).toBe(false);
  });
  it('rejects when any sub-clause fails (either child)', () => {
    expect(run(c, [act('delete')]).results[0]!.violated).toContain('no-delete');
    expect(run(c, [act('deploy')]).results[0]!.violated).toContain('review-first');
  });
});

// ============================================================================================
// 2. COMPOSITION WITH THE EXISTING CONSTITUTION
// ============================================================================================

describe('composition: a plain prohibition constitution is the degenerate contract', () => {
  const SPEND: Invariant = { id: 'spend', kind: 'cap', when: { verb: 'pay' }, amount: 'action.params.usd', max: 100, window_secs: 86_400 };
  const LOCK: Invariant = { id: 'lock', kind: 'never_after', after: { verb: 'read', resource: '/s/*' }, forbid: { verb: 'send' } };
  const invs = [SPEND, LOCK];
  const constitution: Constitution = { version: 1, principal: PRIN, invariants: invs };
  const degenerate = contractFromConstitution(constitution);

  it('embeddedConstitution round-trips the invariants', () => {
    expect(embeddedConstitution(degenerate).invariants).toEqual(invs);
  });

  it('advanceContract == advanceStateStrict + checkProhibitions when there are no temporal clauses', () => {
    const trace = [act('pay', '/v', { usd: 40 }), act('read', '/s/x'), act('send', '/y'), act('pay', '/v', { usd: 80 })];
    let cs = emptyState(NOW); // contract state
    let ps = emptyState(NOW); // prohibition state
    for (const a of trace) {
      const pr = checkProhibitions(a, constitution, ps);
      const cr = advanceContract(cs, a, degenerate, { now: cs.now });
      expect(cr.ok).toBe(pr.ok);
      expect(cr.violated).toEqual(pr.violated);
      // advance both the same way and compare state digests byte-for-byte
      const adv = advanceStateStrict(a, constitution, ps);
      if (pr.ok) {
        expect(adv.ok).toBe(true);
        if (adv.ok) {
          expect(stateDigest(cr.next)).toBe(stateDigest(adv.state));
          expect(cr.next).toEqual(adv.state);
          ps = adv.state;
          cs = cr.next;
        }
      } else {
        // refused: both leave their state unchanged
        expect(cr.next).toEqual(cs);
        cs = cr.next;
        ps = advanceState(a, constitution, ps); // advanceState no-ops on failure
      }
    }
  });

  it('a degenerate contract state is digest-identical to the plain prohibition state (no deadlines key)', () => {
    const a = act('pay', '/v', { usd: 10 });
    const cr = advanceContract(emptyState(NOW), a, degenerate, { now: NOW });
    const adv = advanceStateStrict(a, constitution, emptyState(NOW));
    expect(adv.ok && stateDigest(cr.next)).toBe(stateDigest(adv.ok ? adv.state : ({} as never)));
    expect((cr.next as { deadlines?: unknown }).deadlines).toBeUndefined();
  });

  it('constitution AND temporal clauses compose (both can veto)', () => {
    const c = contract(
      [{ id: 'ack', kind: 'responds_within', p: { verb: 'open' }, q: { verb: 'close' }, within: 2 }],
      invs,
    );
    // prohibition veto (cap) fires
    const over = run(c, [act('pay', '/v', { usd: 200 })]);
    expect(over.rejected).toBe(true);
    expect(over.results[0]!.violated).toContain('spend');
    // temporal veto (liveness) fires independently
    const live = run(c, [act('open'), act('x'), act('y')]);
    expect(live.rejected).toBe(true);
    expect(live.results[2]!.violated).toContain('ack');
    // the evaluated trace covers BOTH the invariants and the clause
    const row = checkContract(act('read', '/z'), c, emptyState(NOW));
    expect(row.evaluated.map((e) => e.id)).toEqual(['spend', 'lock', 'ack']);
  });
});

// ============================================================================================
// 3. COMMITMENT / SIGNING
// ============================================================================================

describe('contract commitment', () => {
  const c = contract([{ id: 'a', kind: 'never', p: { verb: 'delete' } }]);
  it('signs and verifies; id binds the content', () => {
    const sc = signContract(c, P.secretKey);
    expect(sc.id).toBe(contractId(c));
    expect(verifyContract(sc)).toEqual({ ok: true });
    expect(verifyContract(sc, PRIN)).toEqual({ ok: true });
  });
  it('rejects tampering and a wrong principal', () => {
    const sc = signContract(c, P.secretKey);
    expect(verifyContract({ ...sc, clauses: [{ id: 'a', kind: 'never', p: { verb: 'write' } }] }).ok).toBe(false);
    expect(verifyContract({ ...sc, principal: encodeKey(generateKeyPair().publicKey) }).ok).toBe(false);
    expect(verifyContract(sc, encodeKey(generateKeyPair().publicKey)).ok).toBe(false);
  });
  it('refuses to sign a malformed contract', () => {
    expect(() => signContract({ version: CONTRACT_VERSION, principal: PRIN, clauses: [{ id: 'x' } as unknown as Clause] }, P.secretKey)).toThrow();
  });
  it('validation rejects duplicate ids across clauses AND invariants', () => {
    const bad = contract([{ id: 'dup', kind: 'never', p: { verb: 'a' } }], [{ id: 'dup', kind: 'never', when: { verb: 'b' } }]);
    expect(validateContract(bad).some((p) => p.includes('duplicate'))).toBe(true);
  });
});

// ============================================================================================
// 4. PROPERTY-BASED TESTS (deterministic generators — fast-check is not a dep)
// ============================================================================================

/** mulberry32 — a tiny deterministic PRNG so the "random" tests are reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const VERBS = ['read', 'write', 'pay', 'deploy', 'delete', 'review', 'ack', 'request', 'send', 'open', 'close'];
const RESOURCES = ['/a', '/b', '/prod/x', '/safe/y', '/s/z'];
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length) % xs.length]!;

function randomAction(r: () => number): ActionContext {
  return act(pick(r, VERBS), pick(r, RESOURCES), r() < 0.3 ? { usd: Math.floor(r() * 300) } : undefined);
}
function randomTrace(r: () => number, len: number): ActionContext[] {
  return Array.from({ length: len }, () => randomAction(r));
}
function randomClause(r: () => number, id: string): Clause {
  const kind = pick(r, ['always', 'never', 'precedes', 'requires_prior', 'responds_within'] as const);
  const p = { verb: pick(r, VERBS) };
  const q = { verb: pick(r, VERBS) };
  switch (kind) {
    case 'always':
    case 'never':
      return { id, kind, p };
    case 'precedes':
      return { id, kind, p, q };
    case 'requires_prior':
      return { id, kind, q, p };
    case 'responds_within':
      return { id, kind, p, q, within: 1 + Math.floor(r() * 4) };
  }
}
function randomContract(r: () => number): Contract {
  const n = 1 + Math.floor(r() * 3);
  return contract(Array.from({ length: n }, (_, i) => randomClause(r, `c${i}`)));
}

describe('property: determinism', () => {
  it('same (state, trace, contract) => identical verdicts and identical final state digest', () => {
    for (let seed = 1; seed <= 200; seed++) {
      const r1 = rng(seed);
      const c = randomContract(r1);
      const trace = randomTrace(r1, 8);
      const a = run(c, trace);
      const b = run(c, trace);
      expect(a.results.map((x) => x.ok)).toEqual(b.results.map((x) => x.ok));
      expect(a.results.map((x) => x.violated.join(','))).toEqual(b.results.map((x) => x.violated.join(',')));
      expect(stateDigest(a.state)).toBe(stateDigest(b.state));
    }
  });
});

describe('property: monotonic hash-chaining', () => {
  it('each admitted action strictly increments seq and binds history in the digest', () => {
    for (let seed = 1; seed <= 200; seed++) {
      const r = rng(seed + 10_000);
      const c = randomContract(r);
      const trace = randomTrace(r, 8);
      let prev = emptyState(NOW);
      const digests = new Set<string>([stateDigest(prev)]);
      for (const action of trace) {
        const res = advanceContract(prev, action, c, { now: prev.now });
        if (res.ok) {
          expect(res.next.seq).toBe(prev.seq + 1); // strictly increases
          expect(res.next.parent).not.toBeNull();
          // parent binds the PRE-state digest and the action
          expect(res.next.parent).toBe(hashCanonical({ d: 'atlas-pca/monitor-state-link/v1', state: stateDigest(prev), action: hashCanonical(action) }));
          const d = stateDigest(res.next);
          expect(digests.has(d)).toBe(false); // history-binding => fresh digest
          digests.add(d);
          prev = res.next;
        } else {
          expect(res.next).toEqual(prev); // refusal never advances the chain
          expect(res.next.seq).toBe(prev.seq);
        }
      }
    }
  });
});

describe('property: never P rejects iff some action satisfies P', () => {
  it('matches an independent oracle over 300 random traces', () => {
    for (let seed = 1; seed <= 300; seed++) {
      const r = rng(seed + 20_000);
      const V = pick(r, VERBS);
      const c = contract([{ id: 'n', kind: 'never', p: { verb: V } }]);
      const trace = randomTrace(r, 7);
      const oracle = trace.some((a) => a.action.verb === V);
      expect(run(c, trace).rejected).toBe(oracle);
    }
  });
});

describe('property: responds_within N rejects iff the obligation is unmet within N', () => {
  /** Independent oracle: P@i violates iff its window (i+1..i+N) has fully elapsed with no Q. */
  function oracle(trace: ActionContext[], vp: string, vq: string, N: number): boolean {
    const len = trace.length;
    for (let i = 0; i < len; i++) {
      if (trace[i]!.action.verb !== vp) continue;
      if (i + N > len - 1) continue; // window not fully elapsed by end of trace => pending, not a violation
      let hasQ = false;
      for (let j = i + 1; j <= i + N; j++) if (trace[j]!.action.verb === vq) { hasQ = true; break; }
      if (!hasQ) return true;
    }
    return false;
  }
  it('matches the oracle over 400 random traces', () => {
    for (let seed = 1; seed <= 400; seed++) {
      const r = rng(seed + 30_000);
      const vp = 'request';
      const vq = 'ack';
      const N = 1 + Math.floor(r() * 3);
      const c = contract([{ id: 'ack', kind: 'responds_within', p: { verb: vp }, q: { verb: vq }, within: N }]);
      // bias the alphabet so P and Q actually appear
      const alpha = [vp, vq, 'noise', 'noise'];
      const trace = Array.from({ length: 2 + Math.floor(r() * 7) }, () => act(pick(r, alpha)));
      expect(run(c, trace).rejected).toBe(oracle(trace, vp, vq, N));
    }
  });
});

// ============================================================================================
// 5. ADVERSARIAL TESTS
// ============================================================================================

describe('adversarial: obligations cannot be satisfied out of order', () => {
  it('precedence: q before p is caught even if a p appears later in the trace', () => {
    const c = contract([{ id: 'r', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } }]);
    // agent tries to deploy first then "backfill" a review — the early deploy is still refused
    const r = run(c, [act('deploy'), act('review'), act('deploy')]);
    expect(r.results[0]!.ok).toBe(false); // first deploy refused
    expect(r.results[1]!.ok).toBe(true); // review latches
    expect(r.results[2]!.ok).toBe(true); // later deploy now allowed
    expect(r.rejected).toBe(true); // the trace as a whole is rejected
  });
  it('responds_within: moving the response outside the window is caught (reorder/omit)', () => {
    const c = contract([{ id: 'ack', kind: 'responds_within', p: { verb: 'request' }, q: { verb: 'ack' }, within: 2 }]);
    // an ack that arrives too late cannot retroactively satisfy the expired obligation
    const late = run(c, [act('request'), act('noise'), act('noise'), act('ack')]);
    expect(late.rejected).toBe(true);
    expect(late.firstReject).toBe(2);
    // an ack BEFORE the request does not pre-satisfy a future obligation
    const early = run(c, [act('ack'), act('request'), act('noise'), act('noise')]);
    expect(early.rejected).toBe(true);
  });
});

describe('adversarial: monitor-state rollback is refused (compare-and-swap)', () => {
  const c = contract([{ id: 'ack', kind: 'responds_within', p: { verb: 'request' }, q: { verb: 'ack' }, within: 3 }, { id: 'no-del', kind: 'never', p: { verb: 'delete' } }]);

  it('a stale seq is refused', () => {
    const s0 = emptyState(NOW);
    const s1 = advanceContract(s0, act('request'), c, { now: NOW });
    expect(s1.ok).toBe(true);
    // replaying against s1 but asserting the head is still at seq 0 (a rollback) is refused
    const replay = advanceContract(s1.next, act('ack'), c, { expectedSeq: 0 });
    expect(replay.ok).toBe(false);
    expect(replay.decidedBy).toBe('state');
    expect(replay.violated).toContain('<state>');
    expect(replay.next).toEqual(s1.next); // unchanged
  });

  it('a stale/forged state digest is refused', () => {
    const s0 = emptyState(NOW);
    const s1 = advanceContract(s0, act('request'), c, { now: NOW });
    const genesisDigest = stateDigest(s0);
    // present the ADVANCED state but claim its digest is still the genesis digest (rollback attempt)
    const res = advanceContract(s1.next, act('ack'), c, { expectedStateDigest: genesisDigest });
    expect(res.ok).toBe(false);
    expect(res.decidedBy).toBe('state');
  });

  it('presenting an OLD state (losing a pending obligation) is caught by CAS on the real head', () => {
    // request opens an obligation; an attacker tries to continue from the pre-request state to drop it
    const s0 = emptyState(NOW);
    const s1 = advanceContract(s0, act('request'), c, { now: NOW });
    expect((s1.next as { deadlines?: Record<string, number> }).deadlines).toBeDefined();
    const realHeadSeq = s1.next.seq;
    const realHeadDigest = stateDigest(s1.next);
    // the rolled-back state (s0) does not match the real head => refused
    expect(advanceContract(s0, act('read'), c, { expectedSeq: realHeadSeq }).ok).toBe(false);
    expect(advanceContract(s0, act('read'), c, { expectedStateDigest: realHeadDigest }).ok).toBe(false);
  });

  it('a correct CAS head is accepted', () => {
    const s1 = advanceContract(emptyState(NOW), act('request'), c, { now: NOW });
    const ok = advanceContract(s1.next, act('ack'), c, { expectedSeq: s1.next.seq, expectedStateDigest: stateDigest(s1.next) });
    expect(ok.ok).toBe(true);
    expect(ok.next.seq).toBe(2);
  });
});

describe('composition: checkAndAdvanceContract (permission AND contract)', () => {
  const c = contract([{ id: 'no-del', kind: 'never', p: { verb: 'delete' } }]);
  it('allow = permitted AND contract.ok; the monitor runs even when not permitted', () => {
    const permittedOk = checkAndAdvanceContract(true, emptyState(NOW), act('read'), c, { now: NOW });
    expect(permittedOk.allow).toBe(true);
    expect(permittedOk.next.seq).toBe(1);

    const notPermitted = checkAndAdvanceContract(false, emptyState(NOW), act('read'), c, { now: NOW });
    expect(notPermitted.allow).toBe(false);
    expect(notPermitted.next).toEqual(emptyState(NOW)); // no advance

    const vetoed = checkAndAdvanceContract(true, emptyState(NOW), act('delete'), c, { now: NOW });
    expect(vetoed.allow).toBe(false);
    expect(vetoed.violated).toContain('no-del');
  });
});

// ============================================================================================
// 6. TOTALITY / FAIL-CLOSED (never throws; malformed input => refused)
// ============================================================================================

describe('totality: every entry point is total and fails closed', () => {
  const c = contract([{ id: 'a', kind: 'never', p: { verb: 'delete' } }]);
  it('malformed action / state / contract are refused, never thrown', () => {
    expect(advanceContract(emptyState(NOW), { action: { verb: 1 } } as never, c).ok).toBe(false);
    expect(advanceContract({ now: NaN } as never, act('read'), c).ok).toBe(false);
    expect(advanceContract(emptyState(NOW), act('read'), { version: 2, principal: PRIN, clauses: [] } as Contract).ok).toBe(false);
    expect(checkContract(act('read'), null as never, emptyState(NOW)).ok).toBe(false);
  });
  it('a malformed input leaves the state unchanged', () => {
    const r = advanceContract(emptyState(NOW), { action: {} } as never, c);
    expect(r.next).toEqual(emptyState(NOW));
  });
});
