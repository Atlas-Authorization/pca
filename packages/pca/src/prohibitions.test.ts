import { describe, expect, it } from 'vitest';
import { hashCanonical } from './hash';
import { generateKeyPair, encodeKey } from './keys';
import { evaluatePredicates, type ActionContext, type Predicate } from './predicates';
import {
  advanceState,
  advanceStateStrict,
  canonicalState,
  checkAndAdvance,
  checkProhibitions,
  evidenceDigest,
  safetyBindingId,
  signSafetyEvidence,
  stateDigest,
  stateProblem,
  tickState,
  verifySignedSafetyEvidence,
  whenMatches,
  type SignedSafetyEvidence,
  composeAuthority,
  emptyState,
  proveSafety,
  signConstitution,
  validateConstitution,
  verifyConstitution,
  verifySafetyEvidence,
  type Constitution,
  type Invariant,
  type MonitorState,
} from './prohibitions';

const P = generateKeyPair();
const DAY = 86_400;
const NOW = 1_700_000_000_000;

const act = (verb: string, resource: string, params?: Record<string, unknown>, env?: Record<string, unknown>): ActionContext => ({
  action: { verb, resource, ...(params ? { params } : {}) },
  ...(env ? { env } : {}),
});

const constitution = (invariants: Invariant[]): Constitution => ({
  version: 1,
  principal: encodeKey(P.publicKey),
  invariants,
});

const SPEND: Invariant = {
  id: 'spend-day',
  kind: 'cap',
  when: { verb: 'pay', resource: '*' },
  amount: 'action.params.usd',
  max: 100,
  window_secs: DAY,
};
const NO_PROD_DELETE: Invariant = {
  id: 'no-prod-delete-without-human',
  kind: 'never_unless',
  when: { verb: 'delete', resource: '/prod/*' },
  unless: [{ field: 'env.human_approved', op: 'eq', value: true }],
};
const NO_EXFIL: Invariant = {
  id: 'no-pii-exfil',
  kind: 'never',
  when: { verb: ['export', 'send'], resource: '*', where: [{ field: 'action.params.contains_pii', op: 'eq', value: true }] },
};

// Permission layer: plan membership + envelope predicates (independent of the prohibitions).
const PLAN = [
  { verb: 'pay', resource: '/vendor/acme' },
  { verb: 'delete', resource: '/prod/db1' },
  { verb: 'export', resource: '/reports/q3' },
];
const ENVELOPE: Predicate[] = [{ verb: ['pay', 'delete', 'export'], resource: '*' }];
const permitted = (a: ActionContext) =>
  PLAN.some((n) => n.verb === a.action.verb && n.resource === a.action.resource) && evaluatePredicates(ENVELOPE, a).allowed;

describe('negative authority: veto over permission', () => {
  it('an in-plan, policy-permitted action is REFUSED by a prohibition', () => {
    const c = constitution([NO_PROD_DELETE, NO_EXFIL]);
    const a = act('delete', '/prod/db1', {}, { human_approved: false });
    expect(permitted(a)).toBe(true);
    const d = composeAuthority(permitted(a), a, c, emptyState(NOW));
    expect(d.allow).toBe(false);
    expect(d.decidedBy).toBe('prohibition');
    expect(d.prohibition.violated).toEqual(['no-prod-delete-without-human']);
    // same action with a human in the loop is allowed
    const ok = act('delete', '/prod/db1', {}, { human_approved: true });
    expect(composeAuthority(permitted(ok), ok, c, emptyState(NOW)).allow).toBe(true);
  });

  it('prohibitions are independent of the plan: they fire on out-of-plan actions and cannot be disabled by permission', () => {
    const c = constitution([NO_EXFIL]);
    const outOfPlan = act('send', '/mail/x', { contains_pii: true });
    expect(permitted(outOfPlan)).toBe(false);
    const d = composeAuthority(false, outOfPlan, c, emptyState(NOW));
    expect(d.allow).toBe(false);
    expect(d.prohibition.violated).toEqual(['no-pii-exfil']); // monitor ran regardless
    // a lying/maximal permission input still loses
    expect(composeAuthority(true, outOfPlan, c, emptyState(NOW)).allow).toBe(false);
    // permission denial alone is attributed to permission
    const benign = act('send', '/mail/x', { contains_pii: false });
    expect(composeAuthority(false, benign, c, emptyState(NOW)).decidedBy).toBe('permission');
    // the monitor does not read the plan at all: same verdict with no plan context
    expect(checkProhibitions(outOfPlan, c, emptyState(NOW)).ok).toBe(false);
  });
});

describe('stateful invariants', () => {
  it('daily spend cap triggers across a sequence and the window rolls', () => {
    const c = constitution([SPEND]);
    let s: MonitorState = emptyState(NOW);
    const pay = (usd: number) => act('pay', '/vendor/acme', { usd });
    for (const [i, usd] of [40, 40].entries()) {
      const t = NOW + i * 1000;
      s = { ...s, now: t };
      expect(checkProhibitions(pay(usd), c, s).ok).toBe(true);
      s = advanceState(pay(usd), c, s, t);
    }
    s = { ...s, now: NOW + 3000 };
    const r = checkProhibitions(pay(30), c, s); // 80 + 30 > 100
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['spend-day']);
    expect(checkProhibitions(pay(20), c, s).ok).toBe(true); // exactly 100 is allowed
    // a day later the old spend has rolled out of the window
    const later = { ...s, now: NOW + (DAY + 10) * 1000 };
    expect(checkProhibitions(pay(30), c, later).ok).toBe(true);
  });

  it('cap fails closed on a missing / negative / non-numeric amount', () => {
    const c = constitution([SPEND]);
    const s = emptyState(NOW);
    for (const params of [undefined, {}, { usd: -5 }, { usd: '5' }, { usd: NaN as unknown as number }]) {
      expect(checkProhibitions(act('pay', '/v', params as never), c, s).ok).toBe(false);
    }
    expect(checkProhibitions(act('refund', '/v'), c, s).ok).toBe(true); // not a matching action
  });

  it('rate limit and never_after latch', () => {
    const c = constitution([
      { id: 'rate', kind: 'rate', when: { verb: 'send', resource: '*' }, max: 2, window_secs: 60 },
      { id: 'lockdown', kind: 'never_after', after: { verb: 'read', resource: '/secrets/*' }, forbid: { verb: 'send', resource: '/net/*' } },
    ]);
    let s = emptyState(NOW);
    const send = act('send', '/net/out');
    for (let i = 0; i < 2; i++) {
      expect(checkProhibitions(send, c, s).ok).toBe(true);
      s = advanceState(send, c, s);
    }
    expect(checkProhibitions(send, c, s).violated).toEqual(['rate']);
    s = emptyState(NOW);
    s = advanceState(act('read', '/secrets/key'), c, s);
    expect(checkProhibitions(send, c, s).violated).toEqual(['lockdown']);
    expect(checkProhibitions(act('read', '/pub/x'), c, s).ok).toBe(true);
  });

  it('advanceState is pure', () => {
    const c = constitution([SPEND]);
    const s = emptyState(NOW);
    const before = JSON.stringify(s);
    const s2 = advanceState(act('pay', '/v', { usd: 5 }), c, s);
    expect(JSON.stringify(s)).toBe(before);
    expect(s2.ledger['spend-day']).toHaveLength(1);
  });
});

describe('"never" invariants and conservative matching', () => {
  it('never forbids matching actions only', () => {
    const c = constitution([NO_EXFIL]);
    expect(checkProhibitions(act('export', '/r', { contains_pii: true }), c, emptyState(NOW)).ok).toBe(false);
    expect(checkProhibitions(act('export', '/r', { contains_pii: false }), c, emptyState(NOW)).ok).toBe(true);
    expect(checkProhibitions(act('read', '/r', { contains_pii: true }), c, emptyState(NOW)).ok).toBe(true);
  });

  it('an unresolvable trigger condition counts as MATCHED (veto applies; the agent cannot dodge by omitting params)', () => {
    const c = constitution([NO_EXFIL]);
    expect(checkProhibitions(act('export', '/r'), c, emptyState(NOW)).ok).toBe(false); // params absent
    expect(checkProhibitions(act('export', '/r', {}), c, emptyState(NOW)).ok).toBe(false); // field absent
    expect(checkProhibitions(act('export', '/r', { contains_pii: 'yes' }), c, emptyState(NOW)).ok).toBe(true); // resolvable, simply != true
  });

  it('never_unless: unresolvable exception is NOT satisfied', () => {
    const c = constitution([NO_PROD_DELETE]);
    expect(checkProhibitions(act('delete', '/prod/x'), c, emptyState(NOW)).ok).toBe(false);
    expect(checkProhibitions(act('delete', '/staging/x'), c, emptyState(NOW)).ok).toBe(true);
  });

  it('oversized subject against a regex resource still vetoes', () => {
    const c = constitution([{ id: 'r', kind: 'never', when: { verb: 'x', resource: 're:/a/[^/]+' } }]);
    expect(checkProhibitions(act('x', '/a/' + 'b'.repeat(600)), c, emptyState(NOW)).ok).toBe(false);
  });
});

describe('fail closed on malformed input', () => {
  const bad: unknown[] = [
    { id: 'u', kind: 'eventually_always', when: { verb: 'x' } }, // unknown form
    { id: 'u', kind: 'never', when: { verb: '' } },
    { id: 'u', kind: 'never', when: { verb: 'x', where: [{ field: 'action.verb', op: 'regex', value: '.' }] } },
    { id: 'u', kind: 'never', when: { verb: 'x', resource: 're:(a+)+' } }, // unsafe regex would never match
    { id: 'u', kind: 'cap', when: { verb: 'x' }, amount: 'env.x', max: 1 },
    { id: 'u', kind: 'cap', when: { verb: 'x' }, amount: 'action.params.u', max: Infinity },
    { id: 'u', kind: 'rate', when: { verb: 'x' }, max: 1.5, window_secs: 1 },
    { id: 'u', kind: 'never_unless', when: { verb: 'x' }, unless: [] },
    { kind: 'never', when: { verb: 'x' } },
    null,
  ];
  it.each(bad.map((b, i) => [i, b] as const))('malformed invariant %i denies everything', (_i, inv) => {
    const c = constitution([inv as Invariant]);
    expect(validateConstitution(c).length).toBeGreaterThan(0);
    const r = checkProhibitions(act('anything', '/ok'), c, emptyState(NOW));
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['<constitution>']);
    expect(() => signConstitution(c, P.secretKey)).toThrow();
  });

  it('malformed constitution / action / state', () => {
    const c = constitution([NO_EXFIL]);
    expect(checkProhibitions(act('a', '/b'), { ...c, version: 2 }, emptyState(NOW)).ok).toBe(false);
    expect(checkProhibitions(act('a', '/b'), constitution([NO_EXFIL, NO_EXFIL]), emptyState(NOW)).ok).toBe(false); // duplicate id
    expect(checkProhibitions({ action: { verb: 1 } } as never, c, emptyState(NOW)).violated).toEqual(['<action>']);
    expect(checkProhibitions(act('a', '/b'), c, { now: NaN } as never).violated).toEqual(['<state>']);
    expect(checkProhibitions(undefined as never, undefined as never, undefined as never).ok).toBe(false);
  });
});

describe('committed constitution', () => {
  it('sign / verify / tamper', () => {
    const sc = signConstitution(constitution([SPEND, NO_EXFIL]), P.secretKey);
    expect(verifyConstitution(sc, encodeKey(P.publicKey)).ok).toBe(true);
    expect(verifyConstitution(sc, encodeKey(generateKeyPair().publicKey)).ok).toBe(false);
    const weakened = { ...sc, invariants: [{ ...SPEND, max: 1e9 } as Invariant, NO_EXFIL] };
    expect(verifyConstitution(weakened).ok).toBe(false);
    const dropped = { ...sc, invariants: [SPEND] };
    expect(verifyConstitution(dropped).ok).toBe(false);
    // other principal re-signing is detected by principal pin
    const other = generateKeyPair();
    const forged = signConstitution({ ...constitution([]), principal: encodeKey(other.publicKey) }, other.secretKey);
    expect(verifyConstitution(forged, encodeKey(P.publicKey)).ok).toBe(false);
  });
});

describe('per-action safety evidence', () => {
  const c = constitution([SPEND, NO_PROD_DELETE, NO_EXFIL]);
  let s = emptyState(NOW);
  s = advanceState(act('pay', '/v', { usd: 60 }), c, s);
  const a = act('pay', '/vendor/acme', { usd: 30 });

  it('is deterministic and re-checks offline', () => {
    const e1 = proveSafety(a, c, s);
    const e2 = proveSafety(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(c)), JSON.parse(JSON.stringify(s)));
    expect(e1).toEqual(e2);
    expect(e1.ok).toBe(true);
    expect(e1.evaluated.map((x) => x.id)).toEqual(['spend-day', 'no-prod-delete-without-human', 'no-pii-exfil']); // every invariant covered
    expect(verifySafetyEvidence(e1, a, c, s)).toEqual({ ok: true });
  });

  it('rejects tampered evidence, wrong state, wrong action, wrong constitution', () => {
    const e = proveSafety(a, c, s);
    expect(verifySafetyEvidence({ ...e, state_digest: 'x' }, a, c, s).ok).toBe(false);
    expect(verifySafetyEvidence({ ...e, evaluated: e.evaluated.slice(1) }, a, c, s).ok).toBe(false); // dropped invariant
    expect(verifySafetyEvidence(e, act('pay', '/vendor/acme', { usd: 31 }), c, s).ok).toBe(false);
    expect(verifySafetyEvidence(e, a, constitution([SPEND]), s).ok).toBe(false);
    const s2 = advanceState(act('pay', '/v', { usd: 1 }), c, s);
    expect(verifySafetyEvidence(e, a, c, s2).ok).toBe(false);
  });

  it('forged all-clear evidence for a violating action is rejected', () => {
    const bad = act('pay', '/vendor/acme', { usd: 99 });
    const real = proveSafety(bad, c, s);
    expect(real.ok).toBe(false);
    expect(verifySafetyEvidence(real, bad, c, s).ok).toBe(false); // honest violation evidence is not an admit
    const forged = { ...real, ok: true, violated: [], evaluated: real.evaluated.map((x) => ({ ...x, result: 'pass' as const, reason: undefined })) };
    expect(verifySafetyEvidence(JSON.parse(JSON.stringify(forged)), bad, c, s).ok).toBe(false);
  });
});

// =====================================================================================
// production hardening
// =====================================================================================

const SIGNER = generateKeyPair();
const SIGNER_PUB = encodeKey(SIGNER.publicKey);
const signEv = (a: ActionContext, c: Constitution, s: MonitorState) => signSafetyEvidence(proveSafety(a, c, s), SIGNER.secretKey, SIGNER_PUB);

describe('canonical state digest', () => {
  const c = constitution([SPEND, { id: 'rate', kind: 'rate', when: { verb: 'send' }, max: 5, window_secs: 60 }]);
  const pay = (usd: number) => act('pay', '/v', { usd });

  it('is deterministic across key / entry order, unknown fields and empty arrays', () => {
    const a: MonitorState = { now: NOW, seq: 0, parent: null, ledger: { x: [{ t: 1, amount: 2 }, { t: 0, amount: 5 }], y: [] }, latched: { b: 1, a: 2 } };
    const b = { latched: { a: 2, b: 1 }, ledger: { x: [{ amount: 5, t: 0, junk: 1 }, { amount: 2, t: 1 }] }, parent: null, seq: 0, now: NOW, extra: 'ignored' } as unknown as MonitorState;
    expect(stateDigest(a)).toBe(stateDigest(b));
    expect(canonicalState(a).ledger.x).toEqual([{ t: 0, amount: 5 }, { t: 1, amount: 2 }]);
    expect(stateDigest(JSON.parse(JSON.stringify(a)))).toBe(stateDigest(a));
  });

  it('every state field moves the digest (tamper rejection)', () => {
    let s = advanceState(pay(10), c, emptyState(NOW));
    const base = stateDigest(s);
    const variants: MonitorState[] = [
      { ...s, now: s.now + 1 },
      { ...s, seq: s.seq + 1 },
      { ...s, parent: 'other' },
      { ...s, ledger: { ...s.ledger, 'spend-day': [{ t: NOW, amount: 9 }] } },
      { ...s, ledger: { ...s.ledger, 'spend-day': [] } },
      { ...s, latched: { z: NOW } },
    ];
    for (const v of variants) expect(stateDigest(v)).not.toBe(base);
    s = advanceState(pay(1), c, s);
    expect(stateDigest(s)).not.toBe(base);
  });

  it('malformed states are rejected by stateProblem / stateDigest', () => {
    const ok = emptyState(NOW);
    const bad: unknown[] = [
      null, { ...ok, now: NaN }, { ...ok, seq: -1 }, { ...ok, seq: 1.5 }, { ...ok, parent: 5 }, { ...ok, parent: 'p' }, { ...ok, seq: 2 },
      { ...ok, ledger: { a: 'x' } }, { ...ok, ledger: { a: [{ t: 1, amount: -1 }] } }, { ...ok, ledger: { a: [{ t: NOW + 1, amount: 1 }] } },
      { ...ok, latched: { a: NOW + 1 } }, { ...ok, latched: { a: 'x' } },
      { ...ok, ledger: JSON.parse('{"__proto__": []}') }, { ...ok, ledger: { a: new Array(10_001).fill({ t: 1, amount: 1 }) } },
    ];
    for (const b of bad) {
      expect(stateProblem(b)).not.toBeNull();
      expect(() => stateDigest(b as MonitorState)).toThrow();
    }
    expect(stateProblem(ok)).toBeNull();
  });

  it('tickState is deterministic and refuses regression', () => {
    const s = emptyState(NOW);
    const t = tickState(s, NOW + 5);
    expect(t.ok && t.state.now).toBe(NOW + 5);
    expect(tickState(s, NOW - 1).ok).toBe(false);
    expect(tickState(s, NaN).ok).toBe(false);
    expect(tickState({ now: NaN } as never, NOW).ok).toBe(false);
  });
});

function chainLink(prev: string, a: ActionContext): string {
  // mirrors the documented link: hashCanonical({d, state, action})
  return hashCanonical({ d: 'atlas-pca/monitor-state-link/v1', state: prev, action: hashCanonical(a) });
}

describe('advanceState: pure, deterministic, chained', () => {
  const c = constitution([SPEND, { id: 'lock', kind: 'never_after', after: { verb: 'read', resource: '/s/*' }, forbid: { verb: 'send' } }]);
  const pay = (usd: number) => act('pay', '/v', { usd });

  it('same inputs => identical state; chain links seq/parent', () => {
    const a = advanceStateStrict(pay(5), c, emptyState(NOW));
    const b = advanceStateStrict(pay(5), c, emptyState(NOW));
    expect(a).toEqual(b);
    if (!a.ok) throw new Error('x');
    expect(a.state.seq).toBe(1);
    expect(a.state.parent).toBe(chainLink(stateDigest(emptyState(NOW)), pay(5)));
    const a2 = advanceStateStrict(pay(6), c, a.state);
    expect(a2.ok && a2.state.seq).toBe(2);
    expect(a2.ok && a2.state.parent).not.toBe(a.state.parent);
  });

  it('ledger content is order-independent; the chain link is not', () => {
    const t1 = NOW + 10;
    const t2 = NOW + 20;
    const x = advanceState(pay(2), c, advanceState(pay(1), c, emptyState(NOW), t1), t2);
    const y = advanceState(pay(1), c, advanceState(pay(2), c, emptyState(NOW), t1), t2);
    expect(canonicalState(x).ledger['spend-day']!.map((e) => e.amount).sort()).toEqual([1, 2]);
    expect(x.parent).not.toBe(y.parent);
    const same = advanceState(pay(2), c, advanceState(pay(2), c, emptyState(NOW), t1), t2);
    const same2 = advanceState(pay(2), c, advanceState(pay(2), c, emptyState(NOW), t1), t2);
    expect(stateDigest(same)).toBe(stateDigest(same2));
  });

  it('refuses (strict) rather than silently under-counting', () => {
    expect(advanceStateStrict(act('pay', '/v'), c, emptyState(NOW)).ok).toBe(false); // unresolvable amount
    expect(advanceStateStrict(pay(1), c, emptyState(NOW), NOW - 1).ok).toBe(false); // clock regression
    expect(advanceStateStrict(pay(1), c, { now: NaN } as never).ok).toBe(false);
    expect(advanceStateStrict({ action: { verb: 1 } } as never, c, emptyState(NOW)).ok).toBe(false);
    expect(advanceStateStrict(pay(1), constitution([{ kind: 'x' } as never]), emptyState(NOW)).ok).toBe(false);
    const s = emptyState(NOW);
    expect(advanceState(act('pay', '/v'), c, s)).toBe(s); // wrapper returns input unchanged
  });

  it('prunes expired entries, merges cap overflow without under-counting, latches earliest time only', () => {
    const s0 = advanceState(pay(50), c, emptyState(NOW));
    const s1 = advanceState(pay(1), c, s0, NOW + (DAY + 1) * 1000);
    expect(s1.ledger['spend-day']).toEqual([{ t: NOW + (DAY + 1) * 1000, amount: 1 }]);
    const lifetime = constitution([{ ...SPEND, window_secs: undefined, max: 1e9 }]);
    const s: MonitorState = { ...emptyState(NOW), ledger: { 'spend-day': Array.from({ length: 10_000 }, (_, i) => ({ t: NOW - 10_000 + i, amount: 1 })) } };
    const grown = advanceStateStrict(pay(1), lifetime, s);
    expect(grown.ok && grown.state.ledger['spend-day']).toHaveLength(10_000);
    expect(grown.ok && grown.state.ledger['spend-day']!.reduce((a, e) => a + e.amount, 0)).toBe(10_001);
    const l1 = advanceState(act('read', '/s/k'), c, emptyState(NOW));
    const l2 = advanceState(act('read', '/s/k'), c, l1, NOW + 5);
    expect(l2.latched.lock).toBe(NOW);
  });

  it('rate ledger overflow is a hard failure', () => {
    const rc = constitution([{ id: 'r', kind: 'rate', when: { verb: 'x' }, max: 10_000, window_secs: 1e9 }]);
    const s: MonitorState = { ...emptyState(NOW), ledger: { r: Array.from({ length: 10_000 }, () => ({ t: NOW, amount: 1 })) } };
    expect(advanceStateStrict(act('x', '/a'), rc, s).ok).toBe(false);
  });
});

describe('signed + bound safety evidence', () => {
  const c = constitution([SPEND, NO_PROD_DELETE, NO_EXFIL]);
  const sc = signConstitution(c, P.secretKey);
  let s = emptyState(NOW);
  s = advanceState(act('pay', '/v', { usd: 60 }), c, s);
  const a = act('pay', '/vendor/acme', { usd: 30 });
  const full = (over: Record<string, unknown> = {}) => ({ signer: SIGNER_PUB, action: a, constitution: c, state: s, ...over });

  it('signs, verifies, and the binding is deterministic', () => {
    const se = signEv(a, c, s);
    expect(verifySignedSafetyEvidence(se, full())).toEqual({ ok: true });
    expect(se.id).toBe(safetyBindingId(se.evidence, SIGNER_PUB));
    expect(signEv(a, c, s).id).toBe(se.id);
    const flipped = { ...se, sig: (se.sig[0] === 'A' ? 'B' : 'A') + se.sig.slice(1) };
    expect(verifySignedSafetyEvidence(flipped, full()).ok).toBe(false);
  });

  it('verifies with digests only (no recomputation) and with a pinned signed constitution', () => {
    const se = signEv(a, c, s);
    const ok = verifySignedSafetyEvidence(se, {
      signer: [SIGNER_PUB],
      actionDigest: se.evidence.action_digest,
      constitutionId: se.evidence.constitution,
      stateDigest: stateDigest(s),
    });
    expect(ok).toEqual({ ok: true });
    expect(verifySignedSafetyEvidence(signEv(a, sc, s), { signer: SIGNER_PUB, action: a, constitution: sc, state: s, principal: encodeKey(P.publicKey) }).ok).toBe(true);
  });

  it('cannot be lifted to another action', () => {
    const se = signEv(a, c, s);
    const other = act('pay', '/vendor/acme', { usd: 31 });
    const r = verifySignedSafetyEvidence(se, full({ action: other }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/action/);
    expect(verifySignedSafetyEvidence(se, full({ action: undefined, actionDigest: 'x' })).ok).toBe(false);
  });

  it('cannot be lifted to another constitution (id or content)', () => {
    const se = signEv(a, c, s);
    expect(verifySignedSafetyEvidence(se, full({ constitution: constitution([SPEND]) })).reason).toMatch(/constitution/);
    expect(verifySignedSafetyEvidence(se, full({ constitution: undefined, constitutionId: 'nope' })).ok).toBe(false);
    const weak = constitution([{ ...SPEND, max: 1e9 } as Invariant, NO_PROD_DELETE, NO_EXFIL]);
    expect(verifySignedSafetyEvidence(se, full({ constitution: weak })).ok).toBe(false);
  });

  it('cannot be lifted to another state (advance, tick, tamper)', () => {
    const se = signEv(a, c, s);
    expect(verifySignedSafetyEvidence(se, full({ state: advanceState(act('pay', '/v', { usd: 1 }), c, s) })).reason).toMatch(/state/);
    expect(verifySignedSafetyEvidence(se, full({ state: { ...s, now: s.now + 1 } })).ok).toBe(false);
    expect(verifySignedSafetyEvidence(se, full({ state: emptyState(NOW) })).ok).toBe(false); // empty-ledger dodge
  });

  it('rejects wrong / unpinned signers, re-attribution, tampered evidence and missing bindings', () => {
    const se = signEv(a, c, s);
    expect(verifySignedSafetyEvidence(se, full({ signer: encodeKey(generateKeyPair().publicKey) })).reason).toMatch(/signer/);
    expect(verifySignedSafetyEvidence(se, full({ signer: [] })).ok).toBe(false);
    const other = generateKeyPair();
    const reattributed: SignedSafetyEvidence = { ...se, signer: encodeKey(other.publicKey) };
    expect(verifySignedSafetyEvidence(reattributed, full({ signer: encodeKey(other.publicKey) })).ok).toBe(false);
    expect(verifySignedSafetyEvidence({ ...se, evidence: { ...se.evidence, now: se.evidence.now + 1 } }, full()).ok).toBe(false);
    expect(verifySignedSafetyEvidence({ ...se, evidence: { ...se.evidence, action_digest: 'x' } }, full()).ok).toBe(false);
    for (const k of ['action', 'constitution', 'state'] as const) {
      expect(verifySignedSafetyEvidence(se, full({ [k]: undefined })).reason).toMatch(/unbound/);
    }
    expect(verifySignedSafetyEvidence(se, full({ action: a, actionDigest: 'mismatch' })).ok).toBe(false);
    expect(verifySignedSafetyEvidence(null as never, full()).ok).toBe(false);
    expect(verifySignedSafetyEvidence(se, null as never).ok).toBe(false);
  });

  it('a signed forged all-clear for a violating action never verifies as an admit', () => {
    const bad = act('pay', '/vendor/acme', { usd: 99 });
    const real = proveSafety(bad, c, s);
    expect(real.ok).toBe(false);
    const honest = signSafetyEvidence(real, SIGNER.secretKey, SIGNER_PUB);
    expect(verifySignedSafetyEvidence(honest, { signer: SIGNER_PUB, action: bad, constitution: c, state: s }).ok).toBe(false);
    expect(verifySignedSafetyEvidence(honest, { signer: SIGNER_PUB, action: bad, constitution: c, state: s, requireOk: false }).ok).toBe(true);
    const lie = { ...real, ok: true, violated: [], evaluated: real.evaluated.map((x) => ({ ...x, result: 'pass' as const })) };
    const signedLie = signSafetyEvidence(lie, SIGNER.secretKey, SIGNER_PUB); // a compromised signer
    expect(verifySignedSafetyEvidence(signedLie, { signer: SIGNER_PUB, action: bad, constitution: c, state: s }).ok).toBe(false); // recompute catches
    const inconsistent = signSafetyEvidence({ ...real, ok: true }, SIGNER.secretKey, SIGNER_PUB);
    expect(verifySignedSafetyEvidence(inconsistent, { signer: SIGNER_PUB, actionDigest: real.action_digest, constitutionId: real.constitution, stateDigest: real.state_digest }).ok).toBe(false);
  });

  it('digest-only mode rejects evidence that does not cover every invariant', () => {
    const real = proveSafety(a, c, s);
    const dropped = signSafetyEvidence({ ...real, evaluated: real.evaluated.slice(1) }, SIGNER.secretKey, SIGNER_PUB);
    expect(verifySignedSafetyEvidence(dropped, { signer: SIGNER_PUB, actionDigest: real.action_digest, constitution: c, stateDigest: real.state_digest }).ok).toBe(false);
  });

  it('principal pin demands an authentic signed constitution', () => {
    const se = signEv(a, c, s);
    expect(verifySignedSafetyEvidence(se, full({ principal: encodeKey(P.publicKey) })).ok).toBe(false); // unsigned
    const forged = { ...sc, sig: signConstitution({ ...c, principal: SIGNER_PUB }, SIGNER.secretKey).sig };
    expect(verifySignedSafetyEvidence(signEv(a, forged, s), { signer: SIGNER_PUB, action: a, constitution: forged, state: s, principal: encodeKey(P.publicKey) }).ok).toBe(false);
  });

  it('refuses to sign unbound evidence; unhashable inputs never produce ok evidence', () => {
    const badAction = { action: { verb: 'pay', resource: '/v', params: { usd: 1, x: undefined } } } as ActionContext;
    const ev = proveSafety(badAction, c, s);
    expect(ev.ok).toBe(false);
    expect(ev.violated).toContain('<action>');
    expect(() => signSafetyEvidence(ev, SIGNER.secretKey, SIGNER_PUB)).toThrow();
    expect(() => signSafetyEvidence({ ...proveSafety(a, c, s), v: 9 }, SIGNER.secretKey, SIGNER_PUB)).toThrow();
    expect(() => signSafetyEvidence(proveSafety(a, c, s), SIGNER.secretKey, '')).toThrow();
    const bs = proveSafety(a, c, { now: NaN } as never);
    expect(bs.ok).toBe(false);
    expect(bs.violated).toContain('<state>');
    expect(evidenceDigest(bs)).toBeTruthy();
  });
});

describe('new invariant forms', () => {
  it('require_approval_over: threshold, approval, unresolvable amount', () => {
    const inv: Invariant = {
      id: 'big-pay', kind: 'require_approval_over', when: { verb: 'pay' }, amount: 'action.params.usd', threshold: 100,
      approved: [{ field: 'env.cfo_approved', op: 'eq', value: true }],
    };
    const c = constitution([inv]);
    const s = emptyState(NOW);
    expect(checkProhibitions(act('pay', '/v', { usd: 100 }), c, s).ok).toBe(true); // at threshold: fine
    expect(checkProhibitions(act('pay', '/v', { usd: 101 }), c, s).violated).toEqual(['big-pay']);
    expect(checkProhibitions(act('pay', '/v', { usd: 101 }, { cfo_approved: true }), c, s).ok).toBe(true);
    expect(checkProhibitions(act('pay', '/v', { usd: 101 }, { cfo_approved: 'true' }), c, s).ok).toBe(false);
    for (const params of [undefined, {}, { usd: '5' }, { usd: -1 }]) expect(checkProhibitions(act('pay', '/v', params as never), c, s).ok).toBe(false);
    expect(checkProhibitions(act('pay', '/v', undefined, { cfo_approved: true }), c, s).ok).toBe(true);
    expect(checkProhibitions(act('refund', '/v', { usd: 1e9 }), c, s).ok).toBe(true);
  });

  it('require_prior: forbidden until the prerequisite was admitted; ambiguous prerequisite does not count', () => {
    const c = constitution([{ id: 'review-first', kind: 'require_prior', when: { verb: 'deploy' }, prior: { verb: 'review', where: [{ field: 'action.params.passed', op: 'eq', value: true }] } }]);
    let s = emptyState(NOW);
    const deploy = act('deploy', '/prod');
    expect(checkProhibitions(deploy, c, s).violated).toEqual(['review-first']);
    s = advanceState(act('review', '/pr/1', { passed: false }), c, s);
    expect(s.latched).toEqual({});
    s = advanceState(act('review', '/pr/1'), c, s); // params missing => ambiguous => NOT latched
    expect(s.latched).toEqual({});
    expect(checkProhibitions(deploy, c, s).ok).toBe(false);
    s = advanceState(act('review', '/pr/1', { passed: true }), c, s);
    expect(s.latched['review-first']).toBe(NOW);
    expect(checkProhibitions(deploy, c, s).ok).toBe(true);
    expect(checkProhibitions(deploy, c, emptyState(NOW)).ok).toBe(false); // empty state => forbidden (fail closed)
  });

  it('validation of the new forms and id hygiene', () => {
    const bad: unknown[] = [
      { id: 'a', kind: 'require_prior', when: { verb: 'x' } },
      { id: 'a', kind: 'require_prior', when: { verb: 'x' }, prior: { verb: '' } },
      { id: 'a', kind: 'require_approval_over', when: { verb: 'x' }, amount: 'env.x', threshold: 1, approved: [{ field: 'env.a', op: 'eq', value: 1 }] },
      { id: 'a', kind: 'require_approval_over', when: { verb: 'x' }, amount: 'action.x', threshold: -1, approved: [{ field: 'env.a', op: 'eq', value: 1 }] },
      { id: 'a', kind: 'require_approval_over', when: { verb: 'x' }, amount: 'action.x', threshold: 1, approved: [] },
      { id: 'a', kind: 'require_approval_over', when: { verb: 'x' }, amount: 'action.x', threshold: Infinity, approved: [{ field: 'env.a', op: 'eq', value: 1 }] },
      { id: '__proto__', kind: 'never', when: { verb: 'x' } },
      { id: 'x'.repeat(129), kind: 'never', when: { verb: 'x' } },
      { id: 'a', kind: 'never', when: { verb: 'x', resource: 're:(' } }, // uncompilable
      { id: 'a', kind: 'never_unless', when: { verb: 'x' }, unless: [{ field: 'env.a', op: 'eq', ref: '' }] },
    ];
    for (const b of bad) expect(validateConstitution(constitution([b as Invariant])).length).toBeGreaterThan(0);
  });
});

describe('exhaustive fail-closed matrix (trigger evaluation)', () => {
  const ctx = act('export', '/r', { n: 5, s: 'abc', arr: [1, 2], flag: true }, { tenant: 'a' });
  const w = (c: unknown): Invariant => ({ id: 'v', kind: 'never', when: { verb: 'export', where: [c as never] } });
  const matches = (c: unknown, a: ActionContext = ctx) => whenMatches({ verb: 'export', where: [c as never] }, a);

  it('cannot-evaluate => MATCHED for every operator', () => {
    const cases: unknown[] = [
      { field: 'action.params.missing', op: 'eq', value: 1 },
      { field: 'action.params.n', op: 'eq' }, // no operand
      { field: 'action.params.n', op: 'eq', ref: 'action.params.nope' },
      { field: 'env.nope', op: 'ne', value: 1 },
      { field: 'subject.x', op: 'eq', value: 1 }, // subject absent
      { field: 'bogus.root', op: 'eq', value: 1 },
      { field: 'action.params.n', op: 'in', value: 'notarray' },
      { field: 'action.params.n', op: 'nin', value: 5 },
      { field: 'action.params.n', op: 'lt', value: 'str' }, // incomparable
      { field: 'action.params.s', op: 'gt', value: 3 },
      { field: 'action.params.flag', op: 'gte', value: true },
      { field: 'action.params.n', op: 'lte', value: NaN },
      { field: 'action.params.n', op: 'prefix', value: 'a' }, // non-string field
      { field: 'action.params.s', op: 'prefix', value: 1 },
      { field: 'action.params.n', op: 'explode', value: 1 }, // unknown op
      { field: '', op: 'eq', value: 1 },
      { op: 'eq', value: 1 },
      null,
      'str',
      { field: 'action.params.n', op: 'eq', value: undefined },
    ];
    for (const c of cases) {
      expect(matches(c), JSON.stringify(c)).toBe(true);
      expect(checkProhibitions(ctx, constitution([w(c)]), emptyState(NOW)).ok).toBe(false);
    }
  });

  it('params unavailable / malformed subject / malformed trigger / unsafe regex => MATCHED', () => {
    const noParams = act('export', '/r');
    expect(matches({ field: 'action.params.n', op: 'eq', value: 5 }, noParams)).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'exists' }, noParams)).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'exists', value: false }, noParams)).toBe(true);
    expect(matches({ field: 'env.t', op: 'eq', ref: 'action.params.n' }, noParams)).toBe(true);
    expect(whenMatches({ verb: 'export' }, { action: { verb: 1 } } as never)).toBe(true);
    expect(whenMatches({ verb: '' } as never, ctx)).toBe(true);
    expect(whenMatches(null as never, ctx)).toBe(true);
    expect(whenMatches({ verb: 'export', resource: 're:(a+)+' }, ctx)).toBe(true);
    expect(whenMatches({ verb: 'export', resource: 're:(' }, ctx)).toBe(true);
    expect(whenMatches({ verb: 'export', where: 'x' as never }, ctx)).toBe(true);
    expect(whenMatches({ verb: 'export', resource: 're:/a/[^/]+' }, act('export', '/a/' + 'b'.repeat(600)))).toBe(true);
  });

  it('cleanly evaluable conditions still evaluate normally (no over-blocking)', () => {
    expect(matches({ field: 'action.params.n', op: 'eq', value: 5 })).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'eq', value: 6 })).toBe(false);
    expect(matches({ field: 'action.params.n', op: 'ne', value: 6 })).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'in', value: [1, 5] })).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'nin', value: [1, 5] })).toBe(false);
    expect(matches({ field: 'action.params.n', op: 'lt', value: 6 })).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'gt', value: 6 })).toBe(false);
    expect(matches({ field: 'action.params.s', op: 'prefix', value: 'ab' })).toBe(true);
    expect(matches({ field: 'action.params.s', op: 'prefix', value: 'zz' })).toBe(false);
    expect(matches({ field: 'action.params.n', op: 'exists' })).toBe(true);
    expect(matches({ field: 'action.params.zz', op: 'exists' })).toBe(false); // genuinely absent
    expect(matches({ field: 'action.params.zz', op: 'exists', value: false })).toBe(true);
    expect(matches({ field: 'action.params.n', op: 'eq', ref: 'action.params.n' })).toBe(true);
  });

  it('ReDoS-shaped resource patterns are rejected at authoring time and veto at runtime', () => {
    for (const re of ['re:(a+)+$', 're:(a|aa)+', 're:(.*a){10}', 're:(?=a)', 're:(a)\\1']) {
      const c = constitution([{ id: 'r', kind: 'never', when: { verb: 'x', resource: re } }]);
      expect(validateConstitution(c).length).toBeGreaterThan(0);
      expect(() => signConstitution(c, P.secretKey)).toThrow();
      expect(checkProhibitions(act('x', '/' + 'a'.repeat(40) + '!'), c, emptyState(NOW)).ok).toBe(false);
    }
    const t0 = Date.now();
    whenMatches({ verb: 'x', resource: 're:(a+)+$' }, act('x', '/' + 'a'.repeat(500) + '!'));
    expect(Date.now() - t0).toBeLessThan(500);
  });

  it('a stateful invariant with an ambiguous action cannot be dodged by omitting fields', () => {
    const c = constitution([SPEND]);
    expect(checkProhibitions(act('pay', '/v', { usd: undefined as never }), c, emptyState(NOW)).ok).toBe(false);
    const rc = constitution([{ id: 'r', kind: 'rate', when: { verb: 'send', where: [{ field: 'action.params.ext', op: 'eq', value: true }] }, max: 1, window_secs: 60 }]);
    const s = advanceState(act('send', '/x'), rc, emptyState(NOW)); // ambiguous => counted
    expect(s.ledger.r).toHaveLength(1);
    expect(checkProhibitions(act('send', '/x'), rc, s).violated).toEqual(['r']);
    expect(checkProhibitions(act('send', '/x', { ext: false }), rc, emptyState(NOW)).ok).toBe(true);
  });

  it('forged / future / negative ledger entries are refused, not trusted', () => {
    const c = constitution([SPEND]);
    const futureEntry = { ...emptyState(NOW), ledger: { 'spend-day': [{ t: NOW + 1, amount: 99 }] } };
    expect(checkProhibitions(act('pay', '/v', { usd: 1 }), c, futureEntry).violated).toEqual(['<state>']);
    const negative = { ...emptyState(NOW), ledger: { 'spend-day': [{ t: NOW, amount: -50 }] } };
    expect(checkProhibitions(act('pay', '/v', { usd: 1 }), c, negative).violated).toEqual(['<state>']);
  });
});

describe('composition still holds with hardened pieces', () => {
  const c = constitution([NO_PROD_DELETE, SPEND]);
  it('permitted can never override a veto, for every permission input', () => {
    const a = act('delete', '/prod/db1', {}, { human_approved: false });
    for (const p of [true, false, 1 as never, 'yes' as never, undefined as never]) {
      expect(composeAuthority(p, a, c, emptyState(NOW)).allow).toBe(false);
    }
    expect(composeAuthority(1 as never, act('delete', '/staging/x'), c, emptyState(NOW)).decidedBy).toBe('permission'); // only literal true grants
  });

  it('checkAndAdvance: allow advances, veto/permission-denial do not, stale heads refused', () => {
    const s = emptyState(NOW);
    const pay = act('pay', '/vendor/acme', { usd: 40 });
    const r = checkAndAdvance(true, pay, c, s, { expectedSeq: 0, expectedStateDigest: stateDigest(s) });
    expect(r.allow).toBe(true);
    expect(r.next.seq).toBe(1);
    expect(r.evidence.state_digest).toBe(stateDigest(s)); // evidence is over the PRE-state
    expect(verifySafetyEvidence(r.evidence, pay, c, s).ok).toBe(true);
    expect(checkAndAdvance(false, pay, c, s).next).toBe(s);
    expect(checkAndAdvance(false, pay, c, s).decidedBy).toBe('permission');
    const veto = checkAndAdvance(true, act('pay', '/v', { usd: 500 }), c, s);
    expect(veto.allow).toBe(false);
    expect(veto.decidedBy).toBe('prohibition');
    expect(veto.next).toBe(s);
    const stale = checkAndAdvance(true, pay, c, s, { expectedSeq: r.next.seq });
    expect(stale.allow).toBe(false);
    expect(stale.decidedBy).toBe('state');
    expect(checkAndAdvance(true, pay, c, s, { expectedStateDigest: 'old' }).allow).toBe(false);
    expect(checkAndAdvance(true, act('pay', '/v'), c, s).allow).toBe(false);
    expect(checkAndAdvance(true, pay, c, { now: NaN } as never).allow).toBe(false);
  });
});

describe('long sequence: all stateful forms, digest continuity', () => {
  const c = constitution([
    SPEND,
    { id: 'rate', kind: 'rate', when: { verb: 'send' }, max: 3, window_secs: 60 },
    { id: 'lock', kind: 'never_after', after: { verb: 'read', resource: '/secrets/*' }, forbid: { verb: 'send', resource: '/net/*' } },
    { id: 'review', kind: 'require_prior', when: { verb: 'deploy' }, prior: { verb: 'review' } },
    { id: 'big', kind: 'require_approval_over', when: { verb: 'pay' }, amount: 'action.params.usd', threshold: 60, approved: [{ field: 'env.ok', op: 'eq', value: true }] },
  ]);
  const sc = signConstitution(c, P.secretKey);

  it('runs a scripted session; every admit is signed, bound, replayable, and chained', () => {
    let s = emptyState(NOW);
    let t = NOW;
    const log: Array<{ a: ActionContext; pre: MonitorState; se: SignedSafetyEvidence }> = [];
    const step = (a: ActionContext, expectAllow: boolean, dt = 1000, violated?: string[]) => {
      t += dt;
      const tk = tickState(s, t);
      if (!tk.ok) throw new Error('tick');
      const pre = tk.state;
      const r = checkAndAdvance(true, a, sc, pre, { expectedSeq: pre.seq });
      expect(r.allow, `${a.action.verb} ${a.action.resource}`).toBe(expectAllow);
      if (violated) expect(r.prohibition.violated).toEqual(violated);
      if (r.allow) {
        const se = signSafetyEvidence(r.evidence, SIGNER.secretKey, SIGNER_PUB);
        expect(verifySignedSafetyEvidence(se, { signer: SIGNER_PUB, action: a, constitution: sc, state: pre, principal: encodeKey(P.publicKey) })).toEqual({ ok: true });
        log.push({ a, pre, se });
        expect(r.next.seq).toBe(pre.seq + 1);
        s = r.next;
      } else {
        expect(r.next).toBe(pre);
        s = pre; // time still advances on a refusal
      }
    };
    step(act('deploy', '/prod'), false, 1000, ['review']);
    step(act('review', '/pr/1'), true);
    step(act('deploy', '/prod'), true);
    step(act('pay', '/v', { usd: 50 }), true);
    step(act('pay', '/v', { usd: 70 }), false, 1000, ['spend-day', 'big']); // over threshold, no approval (and over the cap)
    step(act('pay', '/v', { usd: 40 }), true); // 90 total
    step(act('pay', '/v', { usd: 20 }), false, 1000, ['spend-day']);
    step(act('send', '/net/a'), true);
    step(act('send', '/net/a'), true);
    step(act('send', '/net/a'), true);
    step(act('send', '/net/a'), false, 1000, ['rate']);
    step(act('send', '/net/a'), true, 61_000); // window rolled
    step(act('read', '/secrets/k'), true);
    step(act('send', '/net/a'), false, 1000, ['lock']);
    step(act('send', '/mail/a'), true); // lock only forbids /net/*
    step(act('pay', '/v', { usd: 20 }), false, 1000, ['spend-day']); // still within the day
    step(act('pay', '/v', { usd: 5 }), true, DAY * 1000); // day rolled
    step(act('pay', '/v', { usd: 500 }), false, 1000, ['spend-day', 'big']);
    expect(s.latched.lock).toBeDefined();
    expect(s.latched.review).toBeDefined();

    // continuity: replaying the admitted actions from genesis reproduces the identical chain
    let replay = emptyState(NOW);
    for (const e of log) {
      const tk = tickState(replay, e.pre.now);
      if (!tk.ok) throw new Error('tick');
      expect(stateDigest(tk.state)).toBe(stateDigest(e.pre)); // each evidence pinned exactly this state
      expect(e.se.evidence.state_digest).toBe(stateDigest(e.pre));
      const adv = advanceStateStrict(e.a, c, tk.state);
      if (!adv.ok) throw new Error('adv');
      replay = adv.state;
    }
    expect(replay.seq).toBe(log.length);
    expect(replay.parent).not.toBeNull();
    expect(new Set(log.map((e) => stateDigest(e.pre))).size).toBe(log.length);
    const first = log[0]!;
    const last = log[log.length - 1]!;
    expect(verifySignedSafetyEvidence(first.se, { signer: SIGNER_PUB, action: first.a, constitution: sc, state: last.pre }).ok).toBe(false);
    expect(verifySignedSafetyEvidence(last.se, { signer: SIGNER_PUB, action: last.a, constitution: sc, state: { ...last.pre, ledger: {}, latched: {} } }).ok).toBe(false);
  });
});
