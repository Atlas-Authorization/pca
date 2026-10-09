import { describe, expect, it } from 'vitest';
import {
  IRREVERSIBLE_CLASS,
  adjudicateDispute,
  adjudicateDisputeGame,
  challengeWindowEnd,
  claimStatus,
  fileFraudProof,
  freezeOpenSnapshot,
  resolveWindow,
  DEFAULT_WINDOW_POLICY,
  DEFAULT_MIN_CHALLENGE_WINDOW_MS,
  openOptimistic,
  verifyClaim,
  verifyFraudProof,
  withinChallengeWindow,
  type DisputableInput,
  type DisputeGame,
  type ObjectiveOracle,
  type OracleResolution,
} from './optimistic';
import { commitGoal, InMemoryInverseRegistry, nativeHashEmbedder, objectiveRiskOracle, ResourceGraph, type ObjectiveRiskContext } from './objective-risk';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { decide, type DecideInput } from './policy-vm';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], // 'exfiltrate' is NOT permitted
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

function actn(verb: string, reversibility_class = 'reversible'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}

function decideInputFor(p: PCActn, risk: Partial<DecideInput['risk']> = {}): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: {
      action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class },
    },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0, ...risk },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}

describe('openOptimistic / verifyClaim', () => {
  it('signs a claim over a reversible action that verifies', () => {
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'bond-1', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    expect(verifyClaim(claim, p, encodeKey(A.publicKey), { serverNow: NOW })).toEqual({ ok: true });
  });

  it('refuses irreversible actions on the optimistic path', () => {
    const p = actn('revoke_session', IRREVERSIBLE_CLASS);
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 1000, issuedAt: NOW, serverNow: NOW }, A.secretKey)).toThrow(/irreversible/);
  });

  it('a claim for a different PCActn or wrong key does not verify', () => {
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    // A genuinely different action has a different digest -> the claim does not cover it.
    const other = actn('revoke_session', 'rate_limited');
    expect(verifyClaim(claim, other, encodeKey(A.publicKey), { serverNow: NOW }).ok).toBe(false);
    // Wrong signer public key.
    expect(verifyClaim(claim, p, encodeKey(generateKeyPair().publicKey), { serverNow: NOW }).ok).toBe(false);
  });
});

describe('challenge window', () => {
  it('open until issued_at + window, finalized after', () => {
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 5000, issuedAt: 1000, serverNow: 1000 }, A.secretKey);
    expect(challengeWindowEnd(claim)).toBe(6000);
    expect(withinChallengeWindow(claim, 5999)).toBe(true);
    expect(withinChallengeWindow(claim, 6000)).toBe(true);
    expect(withinChallengeWindow(claim, 6001)).toBe(false);
    expect(claimStatus(claim, 3000)).toBe('open');
    expect(claimStatus(claim, 6001)).toBe('finalized');
  });
});

describe('fraud proofs', () => {
  it('a compliant claim has no fraud proof', () => {
    const p = actn('revoke_session');
    const di = decideInputFor(p);
    const d = decide(di);
    expect(d.releaseGuardianShare).toBe(true);
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: d.r, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    expect(fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: d, decideInput: di })).toBeNull();
  });

  it('an out-of-policy optimistic claim yields a verifying fraud proof -> slash', () => {
    const p = actn('exfiltrate'); // reversible action, but the verb is NOT permitted by the envelope
    const claim = openOptimistic(p, { bondRef: 'bond-X', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const di = decideInputFor(p);
    const d = decide(di);
    expect(d.releaseGuardianShare).toBe(false);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: d, decideInput: di });
    expect(proof).not.toBeNull();
    expect(proof!.kind).toBe('policy-denied');
    const verdict = verifyFraudProof(claim, proof!, GRANT, di);
    expect(verdict.fraudulent).toBe(true);
    expect(verdict.slashBondRef).toBe('bond-X');
  });

  it('understating risk yields a verifying fraud proof', () => {
    const p = actn('revoke_session');
    // real risk is high (blastRadius=1 => r>=0.2), but the agent claimed r=0.
    const di = decideInputFor(p, { blastRadius: 1 });
    const d = decide(di);
    expect(d.r).toBeGreaterThan(0);
    const claim = openOptimistic(p, { bondRef: 'bond-R', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: d, decideInput: di });
    expect(proof).not.toBeNull();
    expect(['risk-understated', 'optimistic-not-allowed']).toContain(proof!.kind);
    expect(verifyFraudProof(claim, proof!, GRANT, di)).toMatchObject({ fraudulent: true, slashBondRef: 'bond-R' });
  });

  it('a fraud proof with a fabricated decision is rejected on recomputation', () => {
    const p = actn('revoke_session');
    const di = decideInputFor(p);
    const d = decide(di); // genuinely compliant
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: d.r, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    // forge a proof asserting a denial that did not happen
    const forged = {
      pcactn_digest: claim.pcactn_digest,
      bond_ref: claim.bond_ref,
      claimed_r: claim.claimed_r,
      kind: 'policy-denied' as const,
      decision: { releaseGuardianShare: false, r: 1, optimisticAllowed: false },
      evidence: (() => { const { grant: _g, ...rest } = di; void _g; return rest; })(),
      r_margin: 1e-9,
      reason: 'fabricated',
    };
    expect(verifyFraudProof(claim, forged, GRANT, di)).toMatchObject({ fraudulent: false });
  });

  it('cannot file a fraud proof against a mismatched PCActn', () => {
    const p = actn('exfiltrate');
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const other = actn('revoke_session');
    const di = decideInputFor(other);
    const d = decide(di);
    expect(fileFraudProof({ claim, pcactn: other, grant: GRANT, actualDecision: d, decideInput: di })).toBeNull();
  });
});

describe('server-authoritative challenge window', () => {
  const pk = () => encodeKey(A.publicKey);
  it('resolveWindow derives issued_at = serverNow and clamps the window to policy', () => {
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW)).toEqual({ issued_at: NOW, challenge_window_ms: DEFAULT_WINDOW_POLICY.defaultWindowMs });
    // A sub-floor (or zero) request is clamped UP to the realistic 30s floor, NOT to the old 1s minimum.
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 0).challenge_window_ms).toBe(DEFAULT_MIN_CHALLENGE_WINDOW_MS);
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 1e15).challenge_window_ms).toBe(DEFAULT_WINDOW_POLICY.maxWindowMs);
  });
  it('resolveWindow raises the floor to a realistic 30s — a 1-second request can no longer finalize before a watchtower reacts', () => {
    expect(DEFAULT_MIN_CHALLENGE_WINDOW_MS).toBe(30_000);
    // The vulnerable case: an agent asks for a 1s window. The old floor (1_000) would have let it through;
    // the hardened floor clamps it UP to 30s.
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 1).challenge_window_ms).toBe(30_000);
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 1_000).challenge_window_ms).toBe(30_000);
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 29_999).challenge_window_ms).toBe(30_000);
    // An above-floor request is preserved (only sub-floor requests are clamped up).
    expect(resolveWindow(DEFAULT_WINDOW_POLICY, NOW, 45_000).challenge_window_ms).toBe(45_000);
    // The floor is a hard minimum no policy can dip below via the derivation path, even a looser one.
    const loose = { ...DEFAULT_WINDOW_POLICY, minWindowMs: 1 };
    expect(resolveWindow(loose, NOW, 1).challenge_window_ms).toBe(30_000);
    // A policy demanding an EVEN HIGHER minimum still wins over the floor.
    const strict = { ...DEFAULT_WINDOW_POLICY, minWindowMs: 60_000 };
    expect(resolveWindow(strict, NOW, 1).challenge_window_ms).toBe(60_000);
  });
  it('accepts a valid server-set window (default issuedAt = serverNow)', () => {
    const p = actn('revoke_session');
    const c = openOptimistic(p, { bondRef: 'b', claimedR: 0, serverNow: NOW }, A.secretKey);
    expect(c.issued_at).toBe(NOW);
    expect(verifyClaim(c, p, pk(), { serverNow: NOW + 100 })).toEqual({ ok: true });
  });
  it('rejects window 0 at open and at verify', () => {
    const p = actn('revoke_session');
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 0, serverNow: NOW }, A.secretKey)).toThrow(/minimum/);
    // forge an agent-signed claim with window 0 by loosening the policy at open
    const loose = { ...DEFAULT_WINDOW_POLICY, minWindowMs: 0 };
    const c = openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 0, serverNow: NOW, windowPolicy: loose }, A.secretKey);
    expect(verifyClaim(c, p, pk(), { serverNow: NOW })).toMatchObject({ ok: false, reason: expect.stringMatching(/minimum/) });
  });
  it('rejects backdated and future-dated issued_at', () => {
    const p = actn('revoke_session');
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, issuedAt: NOW - 3_600_000, serverNow: NOW }, A.secretKey)).toThrow(/skew/);
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, issuedAt: NOW + 3_600_000, serverNow: NOW }, A.secretKey)).toThrow(/skew/);
    const loose = { ...DEFAULT_WINDOW_POLICY, maxSkewMs: 1e12 };
    const c = openOptimistic(p, { bondRef: 'b', claimedR: 0, issuedAt: NOW - 3_600_000, serverNow: NOW, windowPolicy: loose }, A.secretKey);
    expect(verifyClaim(c, p, pk(), { serverNow: NOW })).toMatchObject({ ok: false, reason: expect.stringMatching(/skew/) });
  });
  it('rejects an over-maximum window; irreversible stays blocked', () => {
    const p = actn('revoke_session');
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 1e12, serverNow: NOW }, A.secretKey)).toThrow(/maximum/);
    expect(() => openOptimistic(actn('revoke_session', IRREVERSIBLE_CLASS), { bondRef: 'b', claimedR: 0, serverNow: NOW }, A.secretKey)).toThrow(/irreversible/);
  });
});

describe('deterministic fraud replay on a frozen open-time snapshot', () => {
  it('slashes a genuine fraud found at open-time inputs even if current inputs look fine', () => {
    const p = actn('revoke_session');
    const open = freezeOpenSnapshot(decideInputFor(p, { blastRadius: 1 })); // real overrun at open
    const claim = openOptimistic(p, { bondRef: 'bond-F', claimedR: 0, serverNow: NOW }, A.secretKey);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, openSnapshot: open })!;
    expect(proof).not.toBeNull();
    // Drift: challenger-supplied evidence is clean, current budget is full — irrelevant.
    const tampered = { ...proof, evidence: (({ grant: _g, ...r }) => r)(decideInputFor(p)) };
    expect(verifyFraudProof(claim, tampered, GRANT, open)).toMatchObject({ fraudulent: true, slashBondRef: 'bond-F' });
  });
  it('does NOT slash an honest claim when current taint/budget/time have drifted', () => {
    const p = actn('revoke_session');
    const open = freezeOpenSnapshot(decideInputFor(p));
    const d = decide(open);
    const claim = openOptimistic(p, { bondRef: 'bond-H', claimedR: d.r, serverNow: NOW }, A.secretKey);
    // Later, taint is high, the budget is spent and time has moved: a drifted decision would flag fraud.
    const drifted: DecideInput = { ...decideInputFor(p, { taint: 1, blastRadius: 1 }), budget: { B: 0, tau: NOW, asOf: NOW }, now: NOW + 9_999_999 };
    expect(decide(drifted).r).toBeGreaterThan(d.r);
    // A challenger builds a proof from drifted inputs (decision matches the drift, not the open state).
    const dd = decide({ ...drifted, grant: GRANT });
    const bad = {
      pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, claimed_r: claim.claimed_r,
      kind: 'risk-understated' as const,
      decision: { releaseGuardianShare: dd.releaseGuardianShare, r: dd.r, optimisticAllowed: dd.requiredThreshold.optimisticAllowed },
      evidence: (({ grant: _g, ...r }) => r)(drifted), r_margin: 1e-9, reason: 'drift',
    };
    expect(verifyFraudProof(claim, bad, GRANT, open)).toMatchObject({ fraudulent: false });
    expect(fileFraudProof({ claim, pcactn: p, grant: GRANT, openSnapshot: open })).toBeNull();
  });
  it('requires a snapshot to judge', () => {
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: 0, serverNow: NOW }, A.secretKey);
    const di = decideInputFor(p);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, openSnapshot: decideInputFor(actn('exfiltrate')) });
    void di;
    expect(verifyFraudProof(claim, proof ?? ({} as never), GRANT, undefined as never).fraudulent).toBe(false);
  });
});

// A deterministic, server-authoritative stub oracle: it returns a FIXED authoritative class/value regardless
// of the challenger. Used to prove the dispute game resolves by the ORACLE, never the challenger's say-so.
const stubOracle = (res: Partial<OracleResolution> & { valid: boolean }): ObjectiveOracle => ({
  resolve: (input: DisputableInput) => ({ input, ...res }),
});

describe('contestable dispute game (optimistic bisection with an objective oracle)', () => {
  const disputeFor = (claim: { pcactn_digest: string; bond_ref: string }, input: DisputableInput, extra = {}) => ({
    pcactn_digest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    input,
    ...extra,
  });

  it('SLASHES an agent that understated reversibility_class: a catalog-irreversible verb declared reversible', () => {
    // Agent declares `reversible` for revoke_session and takes the fast path (baseline admits at r=0).
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p); // reversible baked in; r = 0 -> t=1 -> optimisticAllowed
    const baseline = decide({ ...snap });
    expect(baseline.releaseGuardianShare).toBe(true);
    expect(baseline.requiredThreshold.optimisticAllowed).toBe(true);
    const claim = openOptimistic(p, { bondRef: 'bond-rc', claimedR: 0, serverNow: NOW }, A.secretKey);

    // The objective oracle reclassifies the verb to IRREVERSIBLE (server-authoritative).
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const v = adjudicateDispute({ claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.fraudulent).toBe(true);
    expect(v.slashBondRef).toBe('bond-rc');
    expect(v.slashCounterBond).toBe(false);
    expect(v.agentValue).toBe('reversible');
    expect(v.oracleValue).toBe(IRREVERSIBLE_CLASS);
    // under the truthful class the optimistic path is NOT allowed
    expect(v.baseline.optimisticAllowed).toBe(true);
    expect(v.adjudicated.optimisticAllowed).toBe(false);
  });

  it('SLASHES an agent that understated a numeric input (blastRadius): oracle value pushes r past the claim', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p, { blastRadius: 0 }); // agent baked blastRadius = 0 (r = 0), claimed r = 0
    const claim = openOptimistic(p, { bondRef: 'bond-bl', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, value: 1 }); // truthful blast radius = 1 -> r = gamma*1 = 0.2 > 0
    const v = adjudicateDispute({ claim, dispute: disputeFor(claim, 'blastRadius'), grant: GRANT, openSnapshot: snap, oracle });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.fraudulent).toBe(true);
    expect(v.agentValue).toBe(0);
    expect(v.oracleValue).toBe(1);
    expect(v.adjudicated.r).toBeGreaterThan(claim.claimed_r);
  });

  it('UPHOLDS an honest claim against a frivolous dispute AND marks the counter-bond for slashing', () => {
    // Honest: revoke_session genuinely reversible; the challenger falsely asserts it is irreversible.
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-honest', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: 'reversible' }); // oracle AGREES with the agent
    const v = adjudicateDispute({
      claim,
      dispute: disputeFor(claim, 'reversibility_class', { asserted_class: 'irreversible' }), // challenger lies
      grant: GRANT,
      openSnapshot: snap,
      oracle,
    });
    expect(v.outcome).toBe('claim-upheld');
    expect(v.fraudulent).toBe(false);
    expect(v.slashCounterBond).toBe(true);
    expect(v.slashBondRef).toBeUndefined();
    expect(v.adjudicated.optimisticAllowed).toBe(true);
  });

  it('is the ORACLE, not the challengers say-so, that decides: the asserted value is never substituted', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-saysso', claimedR: 0, serverNow: NOW }, A.secretKey);
    // Challenger asserts the worst (irreversible), but the oracle upholds reversible → claim-upheld, not a slash.
    const oracle = stubOracle({ valid: true, class: 'reversible' });
    const v = adjudicateDispute({
      claim,
      dispute: disputeFor(claim, 'reversibility_class', { asserted_class: 'irreversible', asserted_value: 0 }),
      grant: GRANT,
      openSnapshot: snap,
      oracle,
    });
    expect(v.outcome).toBe('claim-upheld');
    expect(v.fraudulent).toBe(false);
  });

  it('FAILS CLOSED to indeterminate when the oracle cannot authoritatively resolve (slashes no one)', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-ind', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: false, reason: 'commitments not reproducible' });
    const v = adjudicateDispute({ claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle });
    expect(v.outcome).toBe('indeterminate');
    expect(v.fraudulent).toBe(false);
    expect(v.slashCounterBond).toBe(false);
  });

  it('refuses a dispute that targets a different claim (digest / bond mismatch) → indeterminate', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-tgt', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const wrongDigest = adjudicateDispute({ claim, dispute: { pcactn_digest: 'nope', bond_ref: 'bond-tgt', input: 'reversibility_class' }, grant: GRANT, openSnapshot: snap, oracle });
    expect(wrongDigest.outcome).toBe('indeterminate');
    const wrongBond = adjudicateDispute({ claim, dispute: { pcactn_digest: claim.pcactn_digest, bond_ref: 'other', input: 'reversibility_class' }, grant: GRANT, openSnapshot: snap, oracle });
    expect(wrongBond.outcome).toBe('indeterminate');
  });

  it('requires a frozen snapshot: a missing one is indeterminate (never a slash on the challengers word)', () => {
    const p = actn('revoke_session', 'reversible');
    const claim = openOptimistic(p, { bondRef: 'bond-nosnap', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const v = adjudicateDispute({ claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: undefined as never, oracle });
    expect(v.outcome).toBe('indeterminate');
    expect(v.fraudulent).toBe(false);
  });
});

describe('dispute game wired to the REAL objective-risk oracle (objectiveRiskOracle)', () => {
  // A grant that permits db.delete on orders (so the baseline admits), with the objective-risk facts the oracle needs.
  const DB_GRANT: Capability = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'maintain the orders table',
    envelope: {
      predicates: [{ verb: 'db.delete', resource: 'orders' }],
      caveats: [{ type: 'expires', at: 9e12 }],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;

  const embedder = nativeHashEmbedder();
  const goal = commitGoal(embedder, { verb: 'db.read', resource: 'orders', params: {} });
  const registry = new InMemoryInverseRegistry([]); // db.delete has NO verified inverse → irreversible
  const graph = new ResourceGraph().addNode({ id: 'orders', harm: { rows: 10 } });
  const ctx = (over: Partial<ObjectiveRiskContext> = {}): ObjectiveRiskContext => ({
    registry,
    authorizedKinds: new Set<string>(),
    graph,
    embedder,
    goal,
    commitments: { registryDigest: registry.digest(), graphDigest: graph.digest() },
    denominations: [],
    weights: DEFAULT_RISK_POLICY.weights,
    taint: 0,
    age: 0,
    ...over,
  });

  const snap = (): DecideInput => ({
    grant: DB_GRANT,
    chain: [DB_GRANT],
    action: { action: { verb: 'db.delete', resource: 'orders', params: {}, reversibility_class: 'reversible' } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
  });
  const claim = { pcactn_digest: 'd-db', bond_ref: 'bond-db', claimed_r: 0, reversibility_class: 'reversible', issued_at: NOW, challenge_window_ms: 5000, sig: '' };
  const dispute = { pcactn_digest: 'd-db', bond_ref: 'bond-db', input: 'reversibility_class' as const };

  it('the real oracle resolves an unregistered verb to irreversible and the dispute SLASHES the agent', () => {
    const oracle = objectiveRiskOracle(ctx());
    const res = oracle.resolve('reversibility_class', snap());
    expect(res).toMatchObject({ valid: true, class: 'irreversible' });
    const v = adjudicateDispute({ claim, dispute, grant: DB_GRANT, openSnapshot: snap(), oracle });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.fraudulent).toBe(true);
    expect(v.oracleValue).toBe('irreversible');
    expect(v.adjudicated.optimisticAllowed).toBe(false);
  });

  it('the real oracle FAILS CLOSED on a commitment mismatch → the dispute is indeterminate (no slash)', () => {
    const oracle = objectiveRiskOracle(ctx({ commitments: { registryDigest: 'tampered', graphDigest: graph.digest() } }));
    const res = oracle.resolve('reversibility_class', snap());
    expect(res.valid).toBe(false);
    const v = adjudicateDispute({ claim, dispute, grant: DB_GRANT, openSnapshot: snap(), oracle });
    expect(v.outcome).toBe('indeterminate');
    expect(v.fraudulent).toBe(false);
  });

  it('the real oracle resolves a numeric blastRadius from the committed resource graph', () => {
    const oracle = objectiveRiskOracle(ctx());
    const res = oracle.resolve('blastRadius', snap());
    expect(res.valid).toBe(true);
    expect(typeof res.value).toBe('number');
  });

  it('a MULTI-STEP game over the real oracle bisects to the reversibility_class step and SLASHES the agent', () => {
    const oracle = objectiveRiskOracle(ctx());
    const game: DisputeGame = {
      pcactn_digest: 'd-db',
      bond_ref: 'bond-db',
      steps: ['blastRadius', 'reversibility_class'],
      // Both sides agree blastRadius = 0; the challenger contests only reversibility_class.
      defender: [{ value: 0 }, { class: 'reversible' }],
      challenger: [{ value: 0 }, { class: 'irreversible' }],
    };
    const r = adjudicateDisputeGame({ claim, game, grant: DB_GRANT, openSnapshot: snap(), oracle });
    expect(r.converged).toBe(true);
    expect(r.contestedStep).toBe(1);
    expect(r.contestedInput).toBe('reversibility_class');
    expect(r.verdict.outcome).toBe('agent-fraud');
    expect(r.verdict.fraudulent).toBe(true);
    expect(r.verdict.slashBondRef).toBe('bond-db');
    expect(r.verdict.oracleValue).toBe('irreversible');
  });
});

// A stub oracle that COUNTS how many times it is consulted — to prove the game does O(1) oracle work for an
// O(n)-step dispute (the oracle is only asked about the single converged step).
function countingOracle(res: Partial<OracleResolution> & { valid: boolean }): { oracle: ObjectiveOracle; calls: () => number } {
  let calls = 0;
  return {
    oracle: { resolve: (input: DisputableInput) => { calls += 1; return { input, ...res }; } },
    calls: () => calls,
  };
}

describe('interactive multi-round dispute game (refereed bisection)', () => {
  const makeClaim = (bondRef: string, p: PCActn) =>
    openOptimistic(p, { bondRef, claimedR: 0, serverNow: NOW }, A.secretKey);
  const gameFor = (
    claim: { pcactn_digest: string; bond_ref: string },
    steps: DisputableInput[],
    defender: DisputeGame['defender'],
    challenger: DisputeGame['challenger'],
  ): DisputeGame => ({ pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, steps, defender, challenger });

  it('bisects a 3-step dispute to the contested step and SLASHES the agent (oracle consulted ONCE)', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p, { semanticDistance: 0, blastRadius: 0 });
    const claim = makeClaim('bond-ms', p);
    // Defender = agent's values (admits). Challenger agrees on the first two steps, contests ONLY the last
    // (reversibility_class -> irreversible), so the first divergence is step index 2.
    const game = gameFor(
      claim,
      ['semanticDistance', 'blastRadius', 'reversibility_class'],
      [{ value: 0 }, { value: 0 }, { class: 'reversible' }],
      [{ value: 0 }, { value: 0 }, { class: IRREVERSIBLE_CLASS }],
    );
    const { oracle, calls } = countingOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.converged).toBe(true);
    expect(r.contestedStep).toBe(2);
    expect(r.contestedInput).toBe('reversibility_class');
    expect(r.rounds).toBe(2);
    expect(r.transcript.length).toBe(2);
    expect(r.verdict.outcome).toBe('agent-fraud');
    expect(r.verdict.fraudulent).toBe(true);
    expect(r.verdict.slashBondRef).toBe('bond-ms');
    expect(r.verdict.slashCounterBond).toBe(false);
    expect(r.verdict.adjudicated.optimisticAllowed).toBe(false);
    // Minimal oracle work: resolved exactly once, for the single converged step.
    expect(calls()).toBe(1);
  });

  it('an HONEST defender wins a frivolous multi-step challenge -> claim-upheld + counter-bond slashed', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p, { blastRadius: 0 });
    const claim = makeClaim('bond-honest-ms', p);
    // Challenger contests reversibility_class (asserts irreversible) but the oracle UPHOLDS reversible.
    const game = gameFor(
      claim,
      ['blastRadius', 'reversibility_class'],
      [{ value: 0 }, { class: 'reversible' }],
      [{ value: 0 }, { class: IRREVERSIBLE_CLASS }],
    );
    const { oracle, calls } = countingOracle({ valid: true, class: 'reversible' });
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.converged).toBe(true);
    expect(r.contestedStep).toBe(1);
    expect(r.verdict.outcome).toBe('claim-upheld');
    expect(r.verdict.fraudulent).toBe(false);
    expect(r.verdict.slashCounterBond).toBe(true);
    expect(r.verdict.slashBondRef).toBeUndefined();
    expect(calls()).toBe(1);
  });

  it('the single-step game reduces EXACTLY to the one-shot adjudicateDispute (0 rounds)', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = makeClaim('bond-1step', p);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const game = gameFor(claim, ['reversibility_class'], [{ class: 'reversible' }], [{ class: IRREVERSIBLE_CLASS }]);
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.rounds).toBe(0);
    expect(r.transcript).toEqual([]);
    expect(r.contestedStep).toBe(0);
    // Identical to running the one-shot referee directly on the raw snapshot for that single input.
    const single = adjudicateDispute({
      claim,
      dispute: { pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, input: 'reversibility_class', asserted_class: IRREVERSIBLE_CLASS },
      grant: GRANT,
      openSnapshot: snap,
      oracle,
    });
    expect(r.verdict).toEqual(single);
    expect(r.verdict.outcome).toBe('agent-fraud');
    expect(r.verdict.slashBondRef).toBe('bond-1step');
  });

  it('FAILS CLOSED (indeterminate) when the oracle cannot resolve the converged step — no slash', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p, { blastRadius: 0 });
    const claim = makeClaim('bond-oracledown', p);
    const game = gameFor(
      claim,
      ['blastRadius', 'reversibility_class'],
      [{ value: 0 }, { class: 'reversible' }],
      [{ value: 0 }, { class: IRREVERSIBLE_CLASS }],
    );
    const oracle = stubOracle({ valid: false, reason: 'commitments unavailable' });
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.verdict.outcome).toBe('indeterminate');
    expect(r.verdict.fraudulent).toBe(false);
    expect(r.verdict.slashCounterBond).toBe(false);
    expect(r.verdict.slashBondRef).toBeUndefined();
  });

  it('FAILS CLOSED (non-convergence) when the parties do not disagree on admission', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = makeClaim('bond-nodispute', p);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    // Both sides assert the SAME truthful class -> identical traces -> nothing to bisect.
    const game = gameFor(claim, ['reversibility_class'], [{ class: 'reversible' }], [{ class: 'reversible' }]);
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.converged).toBe(false);
    expect(r.contestedStep).toBe(-1);
    expect(r.verdict.outcome).toBe('indeterminate');
    expect(r.verdict.fraudulent).toBe(false);
    expect(r.verdict.slashCounterBond).toBe(false);
  });

  it('FAILS CLOSED on malformed / mis-bound games (slashes no one)', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = makeClaim('bond-bad', p);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    // Binding mismatch (wrong pcactn_digest).
    const wrongDigest = adjudicateDisputeGame({
      claim,
      game: { pcactn_digest: 'nope', bond_ref: 'bond-bad', steps: ['reversibility_class'], defender: [{ class: 'reversible' }], challenger: [{ class: IRREVERSIBLE_CLASS }] },
      grant: GRANT, openSnapshot: snap, oracle,
    });
    expect(wrongDigest.converged).toBe(false);
    expect(wrongDigest.verdict.outcome).toBe('indeterminate');
    // Assertion arrays do not cover every step.
    const shortTrace = adjudicateDisputeGame({
      claim,
      game: gameFor(claim, ['blastRadius', 'reversibility_class'], [{ value: 0 }], [{ value: 0 }, { class: IRREVERSIBLE_CLASS }]),
      grant: GRANT, openSnapshot: snap, oracle,
    });
    expect(shortTrace.verdict.outcome).toBe('indeterminate');
    // Empty step list.
    const noSteps = adjudicateDisputeGame({ claim, game: gameFor(claim, [], [], []), grant: GRANT, openSnapshot: snap, oracle });
    expect(noSteps.verdict.outcome).toBe('indeterminate');
    // Missing snapshot.
    const noSnap = adjudicateDisputeGame({ claim, game: gameFor(claim, ['reversibility_class'], [{ class: 'reversible' }], [{ class: IRREVERSIBLE_CLASS }]), grant: GRANT, openSnapshot: undefined as never, oracle });
    expect(noSnap.verdict.outcome).toBe('indeterminate');
  });

  it('bisects a numeric understatement (blastRadius) in the MIDDLE of the step list', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p, { semanticDistance: 0, blastRadius: 0, reversibility: 1 });
    const claim = makeClaim('bond-mid', p);
    // Steps: [reversibility(agree), blastRadius(contested), semanticDistance(agree-but-irrelevant-after)].
    const game = gameFor(
      claim,
      ['reversibility', 'blastRadius', 'semanticDistance'],
      [{ value: 1 }, { value: 0 }, { value: 0 }],
      [{ value: 1 }, { value: 1 }, { value: 0 }], // challenger contests blastRadius (0 -> 1)
    );
    const { oracle, calls } = countingOracle({ valid: true, value: 1 }); // truthful blastRadius = 1 -> r > 0
    const r = adjudicateDisputeGame({ claim, game, grant: GRANT, openSnapshot: snap, oracle });
    expect(r.converged).toBe(true);
    expect(r.contestedStep).toBe(1);
    expect(r.contestedInput).toBe('blastRadius');
    expect(r.verdict.outcome).toBe('agent-fraud');
    expect(r.verdict.fraudulent).toBe(true);
    expect(r.verdict.slashBondRef).toBe('bond-mid');
    expect(r.verdict.adjudicated.r).toBeGreaterThan(claim.claimed_r);
    expect(calls()).toBe(1);
  });
});
