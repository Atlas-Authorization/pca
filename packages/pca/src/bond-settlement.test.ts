import { describe, expect, it } from 'vitest';
import { BondLedger, InMemoryBondAccount, bondAmount, DEFAULT_BOND_POLICY, DEFAULT_SLASH_SPLIT_POLICY, computeSlashSplit, disputeEvidenceDigest, settlementEvidenceDigest, verifySettlement, revocationEvidenceDigest } from './bond-settlement';
import { adjudicateDispute, fileFraudProof, openOptimistic, verifyFraudProof, IRREVERSIBLE_CLASS, type DisputableInput, type ObjectiveOracle, type OracleResolution } from './optimistic';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { decide, type DecideInput } from './policy-vm';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const G = generateKeyPair(); // the guardian / settlement key
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

const ledger = () => new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }) });
const gpk = encodeKey(G.publicKey);

describe('BondLedger — open → release (unchallenged)', () => {
  it('returns the bond to the depositor with a verifying signed record', () => {
    const L = ledger();
    const openRec = L.openBond({ claimId: 'bond-1', amount: 100, depositor: 'alice', at: NOW });
    expect(openRec.action).toBe('open');
    expect(L.bondStatus('bond-1')).toBe('open');
    expect(verifySettlement(openRec, gpk)).toBe(true);
    expect(L.balanceOf('alice')).toBe(900); // collateral debited into escrow

    const relRec = L.releaseBond({ claimId: 'bond-1', at: NOW + 10 });
    expect(relRec.action).toBe('release');
    expect(relRec.to).toBe('alice');
    expect(relRec.amount).toBe(100);
    expect(relRec.evidenceDigest).toBe('');
    expect(verifySettlement(relRec, gpk)).toBe(true);
    expect(L.bondStatus('bond-1')).toBe('released');
    expect(L.balanceOf('alice')).toBe(1000); // returned to the depositor
  });
});

describe('BondLedger — open → slash (verified fraud)', () => {
  it('moves the bond to the treasury with a record bound to the server-derived verdict', () => {
    const L = ledger();
    const p = actn('exfiltrate'); // reversible but NOT permitted by the envelope → policy-denied
    const claim = openOptimistic(p, { bondRef: 'bond-X', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const di = decideInputFor(p);
    const d = decide(di);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: d, decideInput: di })!;
    expect(proof).not.toBeNull();

    L.openBond({ claimId: 'bond-X', amount: 250, depositor: 'alice', at: NOW });
    const slashRec = L.slashBond({ claimId: 'bond-X', claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury', at: NOW + 1 });

    expect(slashRec.action).toBe('slash');
    expect(slashRec.to).toBe('treasury');
    expect(slashRec.amount).toBe(250);
    expect(verifySettlement(slashRec, gpk)).toBe(true);
    expect(L.bondStatus('bond-X')).toBe('slashed');
    expect(L.balanceOf('treasury')).toBe(250);
    expect(L.balanceOf('alice')).toBe(750);

    // The evidence digest is bound to verifyFraudProof's OWN verdict, not challenger input.
    const verdict = verifyFraudProof(claim, proof, GRANT, di);
    expect(slashRec.evidenceDigest).toBe(settlementEvidenceDigest(claim, verdict));
    expect(slashRec.evidenceDigest).not.toBe('');
  });
});

describe('BondLedger — refusals', () => {
  it('a slash WITHOUT a valid fraud verdict is refused (bond stands)', () => {
    const L = ledger();
    const p = actn('revoke_session'); // compliant action
    const di = decideInputFor(p);
    const d = decide(di);
    expect(d.releaseGuardianShare).toBe(true);
    const claim = openOptimistic(p, { bondRef: 'bond-C', claimedR: d.r, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    // A compliant claim yields no genuine fraud proof; fabricate one asserting a denial that did not happen.
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

    L.openBond({ claimId: 'bond-C', amount: 50, depositor: 'alice', at: NOW });
    expect(() => L.slashBond({ claimId: 'bond-C', claim, fraudProof: forged, grant: GRANT, openSnapshot: di, treasury: 'treasury', at: NOW })).toThrow(/refused/);
    expect(L.bondStatus('bond-C')).toBe('open'); // bond still stands
    expect(L.balanceOf('treasury')).toBe(0);
  });

  it('double-settle is refused (release/slash after a bond is settled, and double-open)', () => {
    const L = ledger();
    L.openBond({ claimId: 'bond-D', amount: 10, depositor: 'alice', at: NOW });
    L.releaseBond({ claimId: 'bond-D', at: NOW });
    // Second settlement of the same bond is refused.
    expect(() => L.releaseBond({ claimId: 'bond-D', at: NOW })).toThrow(/double-settle|already/);
    // Re-opening the same claim id is refused.
    expect(() => L.openBond({ claimId: 'bond-D', amount: 10, depositor: 'alice', at: NOW })).toThrow(/double-open|already/);
    // Releasing / slashing a bond that does not exist is refused.
    expect(() => L.releaseBond({ claimId: 'no-such', at: NOW })).toThrow(/no bond/);
  });

  it('a tampered settlement record fails verification', () => {
    const L = ledger();
    const rec = L.openBond({ claimId: 'bond-T', amount: 100, depositor: 'alice', at: NOW });
    expect(verifySettlement(rec, gpk)).toBe(true);
    // Flip the amount → the signature no longer matches the body.
    expect(verifySettlement({ ...rec, amount: 999 }, gpk)).toBe(false);
    // Flip the destination account → also fails.
    expect(verifySettlement({ ...rec, to: 'mallory' }, gpk)).toBe(false);
    // Wrong guardian public key → fails.
    expect(verifySettlement(rec, encodeKey(generateKeyPair().publicKey))).toBe(false);
  });

  it('slashes a bond on a post-open revocation (server-derived evidence, not a fraud proof)', () => {
    const L = ledger();
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'bond-R', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    L.openBond({ claimId: 'bond-R', amount: 70, depositor: 'alice', at: NOW });
    const rec = L.slashBondOnRevocation({ claimId: 'bond-R', claim, revokedCapId: 'cap:leaf', treasury: 'treasury', at: NOW + 1 });
    expect(rec.action).toBe('slash');
    expect(rec.to).toBe('treasury');
    expect(rec.evidenceDigest).toBe(revocationEvidenceDigest(claim, 'cap:leaf'));
    expect(verifySettlement(rec, gpk)).toBe(true);
    expect(L.balanceOf('treasury')).toBe(70);
    // double-settle refused
    expect(() => L.slashBondOnRevocation({ claimId: 'bond-R', claim, revokedCapId: 'cap:leaf', treasury: 'treasury', at: NOW + 2 })).toThrow(/double-settle|already/);
  });
});

describe('slash split — the cryptoeconomic engine (challenger reward + victim compensation)', () => {
  const dest = { challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: 'treasury' };

  it('computeSlashSplit is EXACT and INTEGER-SAFE across edge amounts (1, odd, large)', () => {
    for (const amt of [1, 2, 3, 7, 13, 99, 100, 1_000_001, 2_500_000]) {
      const s = computeSlashSplit(amt, DEFAULT_SLASH_SPLIT_POLICY, dest);
      // sums reconcile EXACTLY to the slashed amount
      expect(s.challengerReward + s.victimCompensation + s.treasuryRemainder).toBe(amt);
      expect(s.amount).toBe(amt);
      // integer bond → integer shares (dust to treasury), never negative
      expect(Number.isInteger(s.challengerReward)).toBe(true);
      expect(Number.isInteger(s.victimCompensation)).toBe(true);
      expect(Number.isInteger(s.treasuryRemainder)).toBe(true);
      expect(s.treasuryRemainder).toBeGreaterThanOrEqual(0);
      // percentages honored (50% / 40%, remainder+dust to treasury)
      expect(s.challengerReward).toBe(Math.floor(amt * 0.5));
      expect(s.victimCompensation).toBe(Math.floor(amt * 0.4));
    }
    // amount 1 is pure dust: the whole bond lands in the treasury
    expect(computeSlashSplit(1, DEFAULT_SLASH_SPLIT_POLICY, dest)).toMatchObject({
      challengerReward: 0,
      victimCompensation: 0,
      treasuryRemainder: 1,
    });
    // odd number: 7 → 3 / 2 / 2 (dust to treasury), still sums to 7
    expect(computeSlashSplit(7, DEFAULT_SLASH_SPLIT_POLICY, dest)).toMatchObject({
      challengerReward: 3,
      victimCompensation: 2,
      treasuryRemainder: 2,
    });
  });

  it('keeps exact fractions for a fractional bond (sums reconcile)', () => {
    const s = computeSlashSplit(2.5, DEFAULT_SLASH_SPLIT_POLICY, dest);
    expect(s.challengerReward).toBeCloseTo(1.25, 10);
    expect(s.victimCompensation).toBeCloseTo(1.0, 10);
    expect(s.challengerReward + s.victimCompensation + s.treasuryRemainder).toBeCloseTo(2.5, 10);
  });

  it('honors a tuned policy', () => {
    const s = computeSlashSplit(1000, { challengerBps: 2000, victimBps: 1000 }, dest); // 20/10/70
    expect(s).toMatchObject({ challengerReward: 200, victimCompensation: 100, treasuryRemainder: 700 });
  });

  it('anonymous (challengerAccount null) folds the whole bond to the treasury — today behavior', () => {
    const s = computeSlashSplit(100, DEFAULT_SLASH_SPLIT_POLICY, { ...dest, challengerAccount: null });
    expect(s).toMatchObject({ challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: null });
  });

  it('rejects an over-100% or out-of-range policy and a non-positive amount', () => {
    expect(() => computeSlashSplit(100, { challengerBps: 7000, victimBps: 4000 }, dest)).toThrow(/exceed/);
    expect(() => computeSlashSplit(100, { challengerBps: -1, victimBps: 0 }, dest)).toThrow(/\[0,10000\]/);
    expect(() => computeSlashSplit(0, DEFAULT_SLASH_SPLIT_POLICY, dest)).toThrow(/positive/);
  });

  const fraudClaim = (bondRef: string) => {
    const p = actn('exfiltrate'); // reversible but NOT permitted → policy-denied fraud
    const claim = openOptimistic(p, { bondRef, claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const di = decideInputFor(p);
    const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    return { claim, di, proof };
  };

  it('slashBond WITH a challenger credits challenger + victim-pool + treasury; the signed record carries the split', () => {
    const L = ledger();
    const { claim, di, proof } = fraudClaim('bond-S');
    L.openBond({ claimId: 'bond-S', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBond({
      claimId: 'bond-S',
      claim,
      fraudProof: proof,
      grant: GRANT,
      openSnapshot: di,
      treasury: 'treasury',
      challengerAccount: 'watchtower',
      compensationAccount: 'pool:g1',
      at: NOW + 1,
    });
    expect(rec.split).toMatchObject({
      amount: 100,
      challengerReward: 50,
      victimCompensation: 40,
      treasuryRemainder: 10,
      challengerAccount: 'watchtower',
      victimAccount: 'pool:g1',
      treasuryAccount: 'treasury',
    });
    expect(L.balanceOf('watchtower')).toBe(50);
    expect(L.balanceOf('pool:g1')).toBe(40);
    expect(L.balanceOf('treasury')).toBe(10);
    expect(L.balanceOf('alice')).toBe(900); // the depositor really lost the full bond
    // the split is part of the SIGNED body → it verifies, and tampering any share fails verification
    expect(verifySettlement(rec, gpk)).toBe(true);
    expect(verifySettlement({ ...rec, split: { ...rec.split!, challengerReward: 99 } }, gpk)).toBe(false);
  });

  it('slashBond WITHOUT a challenger still sends 100% to the treasury (anonymous default — no regression)', () => {
    const L = ledger();
    const { claim, di, proof } = fraudClaim('bond-A');
    L.openBond({ claimId: 'bond-A', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBond({ claimId: 'bond-A', claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury', at: NOW + 1 });
    expect(rec.split).toMatchObject({ challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: null });
    expect(L.balanceOf('treasury')).toBe(100);
    expect(L.balanceOf('alice')).toBe(900);
  });

  it('slashBondOnRevocation also honors the split when a challenger is named', () => {
    const L = ledger();
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'bond-RS', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    L.openBond({ claimId: 'bond-RS', amount: 200, depositor: 'alice', at: NOW });
    const rec = L.slashBondOnRevocation({ claimId: 'bond-RS', claim, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'wt', compensationAccount: 'pool:g2', at: NOW + 1 });
    expect(rec.split).toMatchObject({ challengerReward: 100, victimCompensation: 80, treasuryRemainder: 20, challengerAccount: 'wt' });
    expect(L.balanceOf('wt')).toBe(100);
    expect(L.balanceOf('pool:g2')).toBe(80);
    expect(L.balanceOf('treasury')).toBe(20);
    expect(verifySettlement(rec, gpk)).toBe(true);
  });
});

describe('dispute-game slashes (understated risk input, objective oracle) + the split', () => {
  // Deterministic server-authoritative stub oracle (the challenger never supplies the value).
  const stubOracle = (res: Partial<OracleResolution> & { valid: boolean }): ObjectiveOracle => ({
    resolve: (input: DisputableInput) => ({ input, ...res }),
  });
  const disputeFor = (claim: { pcactn_digest: string; bond_ref: string }, input: DisputableInput) => ({
    pcactn_digest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    input,
  });

  it('slashBondOnDispute slashes the agent for an understated reversibility_class; the split credits challenger + victim-pool + treasury', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible'); // declared reversible, catalog oracle says irreversible
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-DG', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS });
    const dispute = disputeFor(claim, 'reversibility_class');

    L.openBond({ claimId: 'bond-DG', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBondOnDispute({
      claimId: 'bond-DG',
      claim,
      dispute,
      grant: GRANT,
      openSnapshot: snap,
      oracle,
      treasury: 'treasury',
      challengerAccount: 'watchtower',
      compensationAccount: 'pool:g1',
      at: NOW + 1,
    });
    expect(rec.action).toBe('slash');
    expect(rec.split).toMatchObject({ amount: 100, challengerReward: 50, victimCompensation: 40, treasuryRemainder: 10, challengerAccount: 'watchtower', victimAccount: 'pool:g1' });
    expect(L.balanceOf('watchtower')).toBe(50);
    expect(L.balanceOf('pool:g1')).toBe(40);
    expect(L.balanceOf('treasury')).toBe(10);
    expect(L.balanceOf('alice')).toBe(900); // the lying agent really lost the full bond
    expect(L.bondStatus('bond-DG')).toBe('slashed');
    // the record is bound to the SERVER-DERIVED dispute verdict, and the signed split verifies / tamper-fails
    const verdict = adjudicateDispute({ claim, dispute, grant: GRANT, openSnapshot: snap, oracle });
    expect(rec.evidenceDigest).toBe(disputeEvidenceDigest(claim, verdict));
    expect(verifySettlement(rec, gpk)).toBe(true);
    expect(verifySettlement({ ...rec, split: { ...rec.split!, challengerReward: 99 } }, gpk)).toBe(false);
  });

  it('slashBondOnDispute anonymous (no challenger) folds the whole bond to the treasury — no regression', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-DGA', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    L.openBond({ claimId: 'bond-DGA', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBondOnDispute({ claimId: 'bond-DGA', claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle: stubOracle({ valid: true, class: IRREVERSIBLE_CLASS }), treasury: 'treasury', at: NOW + 1 });
    expect(rec.split).toMatchObject({ challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, challengerAccount: null });
    expect(L.balanceOf('treasury')).toBe(100);
  });

  it('slashBondOnDispute is REFUSED when the oracle upholds the agent (claim-upheld) — the honest bond stands', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-UP', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    L.openBond({ claimId: 'bond-UP', amount: 100, depositor: 'alice', at: NOW });
    const oracle = stubOracle({ valid: true, class: 'reversible' }); // upholds
    expect(() =>
      L.slashBondOnDispute({ claimId: 'bond-UP', claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle, treasury: 'treasury' }),
    ).toThrow(/refused/);
    expect(L.bondStatus('bond-UP')).toBe('open');
    expect(L.balanceOf('treasury')).toBe(0);
  });

  it('slashBondOnDispute is REFUSED when the oracle is indeterminate (fail closed)', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-IN', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    L.openBond({ claimId: 'bond-IN', amount: 100, depositor: 'alice', at: NOW });
    const oracle = stubOracle({ valid: false, reason: 'commitments not reproducible' });
    expect(() =>
      L.slashBondOnDispute({ claimId: 'bond-IN', claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle, treasury: 'treasury' }),
    ).toThrow(/refused/);
    expect(L.bondStatus('bond-IN')).toBe('open');
  });

  it('slashCounterBond slashes the GRIEFERs counter-bond when the oracle upholds the agent (frivolous dispute)', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible'); // honest, genuinely reversible
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-honest', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: 'reversible' }); // upholds the agent → the dispute is frivolous
    const dispute = disputeFor(claim, 'reversibility_class');

    // The challenger stakes a counter-bond; the agent's claim bond is untouched.
    L.openBond({ claimId: 'counter-1', amount: 20, depositor: 'alice', at: NOW });
    const rec = L.slashCounterBond({ counterBondId: 'counter-1', claim, dispute, grant: GRANT, openSnapshot: snap, oracle, treasury: 'treasury', at: NOW + 1 });
    expect(rec.action).toBe('slash');
    expect(rec.split).toMatchObject({ challengerReward: 0, victimCompensation: 0, treasuryRemainder: 20, challengerAccount: null });
    expect(L.bondStatus('counter-1')).toBe('slashed');
    expect(L.balanceOf('treasury')).toBe(20);
    expect(L.balanceOf('alice')).toBe(980); // the griefer forfeits the counter-bond stake
    const verdict = adjudicateDispute({ claim, dispute, grant: GRANT, openSnapshot: snap, oracle });
    expect(rec.evidenceDigest).toBe(disputeEvidenceDigest(claim, verdict));
    expect(verifySettlement(rec, gpk)).toBe(true);
  });

  it('slashCounterBond is REFUSED when the dispute is genuine (agent-fraud) — the challenger keeps the stake', () => {
    const L = ledger();
    const p = actn('revoke_session', 'reversible');
    const snap = decideInputFor(p);
    const claim = openOptimistic(p, { bondRef: 'bond-genuine', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: IRREVERSIBLE_CLASS }); // genuine fraud
    L.openBond({ claimId: 'counter-2', amount: 20, depositor: 'alice', at: NOW });
    expect(() =>
      L.slashCounterBond({ counterBondId: 'counter-2', claim, dispute: disputeFor(claim, 'reversibility_class'), grant: GRANT, openSnapshot: snap, oracle, treasury: 'treasury' }),
    ).toThrow(/refused/);
    expect(L.bondStatus('counter-2')).toBe('open');
  });
});

describe('BondLedger — real collateral, sizing, caps', () => {
  it('bondAmount = max(floor, k * exposure)', () => {
    const pol = { ...DEFAULT_BOND_POLICY, floor: 10, k: 0.5 };
    expect(bondAmount(pol, 0)).toBe(10);
    expect(bondAmount(pol, 100)).toBe(50);
    expect(bondAmount(pol, 4)).toBe(10);
  });
  it('refuses when the balance is insufficient; succeeds + debits when funded', () => {
    const acc = new InMemoryBondAccount({ bob: 50 });
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: acc });
    expect(() => L.openBond({ claimId: 'c1', amount: 100, depositor: 'bob', at: NOW })).toThrow(/insufficient/);
    expect(L.bondStatus('c1')).toBe('none');
    expect(acc.balanceOf('bob')).toBe(50);
    L.openBond({ claimId: 'c2', amount: 30, depositor: 'bob', at: NOW });
    expect(acc.balanceOf('bob')).toBe(20);
    expect(acc.balanceOf('escrow')).toBe(30);
  });
  it('refuses a bond below the sized requirement', () => {
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ a: 1000 }), bondPolicy: { ...DEFAULT_BOND_POLICY, floor: 5, k: 1 } });
    expect(() => L.openBond({ claimId: 'x', amount: 5, depositor: 'a', exposure: 100, at: NOW })).toThrow(/below the required/);
    expect(() => L.openBond({ claimId: 'x', amount: 1, depositor: 'a', at: NOW })).toThrow(/below the required/);
    L.openBond({ claimId: 'x', amount: 100, depositor: 'a', exposure: 100, at: NOW });
  });
  it('enforces the aggregate open-claim cap per depositor and frees it on settle', () => {
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ a: 1000, b: 1000 }), bondPolicy: { ...DEFAULT_BOND_POLICY, maxOpenClaims: 2, maxOpenAmount: 50 } });
    L.openBond({ claimId: '1', amount: 20, depositor: 'a', at: NOW });
    L.openBond({ claimId: '2', amount: 20, depositor: 'a', at: NOW });
    expect(() => L.openBond({ claimId: '3', amount: 1, depositor: 'a', at: NOW })).toThrow(/cap/);
    L.openBond({ claimId: 'b1', amount: 20, depositor: 'b', at: NOW }); // other depositor unaffected
    L.releaseBond({ claimId: '1', at: NOW });
    expect(() => L.openBond({ claimId: '4', amount: 31, depositor: 'a', at: NOW })).toThrow(/aggregate/);
    L.openBond({ claimId: '4', amount: 30, depositor: 'a', at: NOW });
  });
});
