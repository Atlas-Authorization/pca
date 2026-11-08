/**
 * Mutation-kill tests for bond-settlement.ts: exact money arithmetic edges (toMicros / quantizeUp / the dyadic
 * fallback split), every exact guard message in the ledger (each operand reached on its own), the signed-message
 * layout, the evidence digests field-for-field, the curve validators, the account/pool guards, and the
 * "who actually got credited" calls observed through a recording BondAccount.
 */
import { describe, expect, it, vi } from 'vitest';
import { COMPENSATION_POOL_ACCOUNT, ESCROW_ACCOUNT, InsuranceCapitalPool, bondAmount, computeSlashSplit, disputeEvidenceDigest, quantizeUp, revocationEvidenceDigest, settlementCommit, settlementEvidenceDigest, toMicros, verifySettlement, verifySettlementCommit, type BondAccount, type BondPolicy, type SettlementRecord } from './bond-settlement';
import { BondLedger, InMemoryBondAccount } from './bond-ledger-testing';
import { b64u, canonicalBytesLenient, hashCanonicalLenient, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { decide, type DecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';
import {
  IRREVERSIBLE_CLASS,
  adjudicateDispute,
  fileFraudProof,
  openOptimistic,
  verifyFraudProof,
  type DisputableInput,
  type DisputeVerdict,
  type ObjectiveOracle,
} from './optimistic';
import type { Reputation } from './reputation';

// Pass-through spies so a few tests can feed the ledger a hostile verdict (defense in depth behind the verdict).
vi.mock('./optimistic', async (importOriginal) => {
  const m = await importOriginal<typeof import('./optimistic')>();
  return { ...m, verifyFraudProof: vi.fn(m.verifyFraudProof), adjudicateDispute: vi.fn(m.adjudicateDispute) };
});

const P = generateKeyPair();
const A = generateKeyPair();
const G = generateKeyPair();
const gpk = encodeKey(G.publicKey);
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

function actn(verb: string, reversibility_class = 'reversible'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}
function decideInputFor(p: PCActn): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}

/** A fraudulent claim (policy-denied) + its genuine proof + frozen snapshot. */
function fraudKit(bondRef: string) {
  const p = actn('exfiltrate');
  const claim = openOptimistic(p, { bondRef, claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
  const di = decideInputFor(p);
  const proof = fileFraudProof({ claim, pcactn: p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
  return { p, claim, di, proof };
}
/** A compliant claim whose reversibility_class dispute the oracle can refute / uphold. */
function disputeKit(bondRef: string) {
  const p = actn('revoke_session', 'reversible');
  const claim = openOptimistic(p, { bondRef, claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
  const di = decideInputFor(p);
  const dispute = { pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, input: 'reversibility_class' as DisputableInput };
  const oracle = (cls: string): ObjectiveOracle => ({ resolve: (input: DisputableInput) => ({ input, valid: true, class: cls }) });
  return { p, claim, di, dispute, fraudOracle: oracle(IRREVERSIBLE_CLASS), upholdOracle: oracle('reversible') };
}

const ledger = (extra: Record<string, unknown> = {}, funds: Record<string, number> = { alice: 1000 }) =>
  new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount(funds), ...extra });
const thr = (fn: () => unknown, msg: string) => expect(fn).toThrow(new Error(msg));

/** BondAccount that records every call (so a zero-amount or spurious credit/debit is visible). */
class RecAccount implements BondAccount {
  readonly inner: InMemoryBondAccount;
  readonly calls: Array<['credit' | 'debit', string, number]> = [];
  constructor(init: Record<string, number>) {
    this.inner = new InMemoryBondAccount(init);
  }
  balanceOf(a: string) {
    return this.inner.balanceOf(a);
  }
  debit(a: string, n: number) {
    this.calls.push(['debit', a, n]);
    this.inner.debit(a, n);
  }
  credit(a: string, n: number) {
    this.calls.push(['credit', a, n]);
    this.inner.credit(a, n);
  }
}

describe('computeSlashSplit — input guards (exact messages)', () => {
  const dest = { challengerAccount: 'c', victimAccount: 'v', treasuryAccount: 't' };
  it('a basis-point share above 10000 is refused per field (not merely via the sum check)', () => {
    thr(() => computeSlashSplit(100, { challengerBps: 10_001, victimBps: 0 }, dest), 'slash split: challengerBps must be an integer in [0,10000]');
    thr(() => computeSlashSplit(100, { challengerBps: 0, victimBps: 10_001 }, dest), 'slash split: victimBps must be an integer in [0,10000]');
    expect(computeSlashSplit(100, { challengerBps: 10_000, victimBps: 0 }, dest).challengerReward).toBe(100);
    expect(computeSlashSplit(100, { challengerBps: 0, victimBps: 10_000 }, dest).victimCompensation).toBe(100);
  });
  it('victim / treasury accounts must be non-empty strings', () => {
    const pol = { challengerBps: 5000, victimBps: 4000 };
    thr(() => computeSlashSplit(100, pol, { ...dest, victimAccount: '' }), 'computeSlashSplit: victimAccount is required');
    thr(() => computeSlashSplit(100, pol, { ...dest, victimAccount: 5 as unknown as string }), 'computeSlashSplit: victimAccount is required');
    thr(() => computeSlashSplit(100, pol, { ...dest, treasuryAccount: '' }), 'computeSlashSplit: treasuryAccount is required');
    thr(() => computeSlashSplit(100, pol, { ...dest, treasuryAccount: 5 as unknown as string }), 'computeSlashSplit: treasuryAccount is required');
  });
});

describe('toMicros / quantizeUp edges', () => {
  it('toMicros: negatives and non-finite are not micro amounts (and never throw)', () => {
    expect(toMicros(-1)).toBeNull();
    expect(toMicros(-0.5)).toBeNull();
    expect(toMicros(Number.NaN)).toBeNull();
    expect(toMicros(Number.POSITIVE_INFINITY)).toBeNull();
    expect(toMicros(Number.NEGATIVE_INFINITY)).toBeNull();
  });
  it('toMicros: exact upper bound is 1e15 micros (1e9 units) inclusive', () => {
    expect(toMicros(1e9)).toBe(1_000_000_000_000_000n);
    expect(toMicros(1e10)).toBeNull();
  });
  it('toMicros: sub-micro amounts are refused; float noise <= 1e-3 micro is absorbed (boundary inclusive)', () => {
    expect(toMicros(5e-7)).toBeNull();
    expect(toMicros(27.500000000000004)).toBe(27_500_000n);
    expect(toMicros(1e-9)).toBe(0n); // scaled is exactly 0.001 micro: not strictly greater than the tolerance
    expect(toMicros(0.000001)).toBe(1n);
  });
  it('toMicros: an amount that round-trips exactly is accepted even when its scaled product is off by > 1e-3', () => {
    expect(toMicros(561248123.497673)).toBe(561_248_123_497_673n);
    expect(toMicros(545024894.88398)).toBe(545_024_894_883_980n);
  });
  it('quantizeUp: non-positive / non-finite pass through untouched', () => {
    expect(quantizeUp(-1e-9)).toBe(-1e-9);
    expect(quantizeUp(-5)).toBe(-5);
    expect(quantizeUp(0)).toBe(0);
    expect(quantizeUp(Number.NaN)).toBeNaN();
    expect(quantizeUp(Number.POSITIVE_INFINITY)).toBe(Number.POSITIVE_INFINITY);
  });
  it('quantizeUp: rounds UP onto the micro grid but absorbs float noise <= 1e-3 micro', () => {
    expect(quantizeUp(27.500000000000004)).toBe(27.5);
    expect(quantizeUp(27.5000011)).toBe(27.500002);
    expect(quantizeUp(1e-9)).toBe(0); // scaled exactly 0.001: absorbed (the tolerance is inclusive)
    expect(quantizeUp(1.0000001)).toBe(1.000001);
    expect(quantizeUp(561248123.497673)).toBe(561248123.497673); // exact round-trip: kept, not ceiled
  });
  it('quantizeUp: amounts beyond 1e15 micros are returned unchanged; the boundary itself is on-grid', () => {
    expect(quantizeUp(2324922190.0575905)).toBe(2324922190.0575905);
    expect(quantizeUp(1e9)).toBe(1e9);
  });
});

describe('computeSlashSplit — dyadic fallback (outside the exact micro range)', () => {
  /** Independent ulp via the IEEE bit pattern (no Math.log2). */
  const ulp = (x: number): number => {
    const dv = new DataView(new ArrayBuffer(8));
    dv.setFloat64(0, x);
    const exp = (dv.getUint16(0) >> 4) & 0x7ff;
    return exp === 0 ? 2 ** -1074 : 2 ** (exp - 1023 - 52);
  };
  const refShare = (a: number, bps: number, q: number) => Math.floor((a * bps) / 10_000 / q) * q;
  const amounts: number[] = [];
  for (let k = 20; k <= 70; k++) {
    const p = 2 ** k;
    amounts.push(p, p - 1, p + 1, p * 1.5, p + 0.5, p - 0.5, p * 1.0000001, p * (1 - 1e-9));
  }
  amounts.push(1e7 + 0.0000005, 12345678.9000001, 3e9 + 0.0000003, 123.0000007, 7612809664210701, 8975955382388558, 60973040.35335186);
  const fallback = amounts.filter((a) => Number.isFinite(a) && a > 0 && (Number.isInteger(a) || toMicros(a) === null));
  const dest = { challengerAccount: 'c', victimAccount: 'v', treasuryAccount: 't' };

  it('sanity: the sweep covers integers and non-integers', () => {
    expect(fallback.some((a) => Number.isInteger(a))).toBe(true);
    expect(fallback.some((a) => !Number.isInteger(a))).toBe(true);
  });
  it('every share is floor(amount*bps/10000) on the amount quantum grid (integer => >= 1, else >= 2^-30), exactly reconciling', () => {
    for (const a of fallback) {
      const q = Number.isInteger(a) ? Math.max(1, ulp(a)) : Math.max(2 ** -30, ulp(a));
      for (const [cb, vb] of [[5000, 4000], [3333, 3333], [1, 9999], [9999, 1], [10000, 0], [0, 10000]] as const) {
        const s = computeSlashSplit(a, { challengerBps: cb, victimBps: vb }, dest);
        const c = Math.min(refShare(a, cb, q), a);
        const v = Math.min(refShare(a, vb, q), a - c);
        expect(s.amount).toBe(a);
        expect(s.challengerReward).toBe(c);
        expect(s.victimCompensation).toBe(v);
        expect(s.treasuryRemainder).toBe(a - c - v);
        expect(s.challengerReward + s.victimCompensation + s.treasuryRemainder).toBe(a);
      }
    }
  });
  it('the victim share is clamped to what is left after the challenger (float rounding of raw can overshoot)', () => {
    for (const [a, cb, vb] of [[6918774109526983, 6960, 3040], [8975955382388558, 8696, 1304], [60973040.35335186, 3999, 6001]] as const) {
      const s = computeSlashSplit(a, { challengerBps: cb, victimBps: vb }, dest);
      expect(s.victimCompensation).toBe(a - s.challengerReward);
      expect(s.treasuryRemainder).toBe(0);
    }
  });
  it('a tiny integer bond keeps whole-unit shares (dust to the treasury)', () => {
    const s = computeSlashSplit(7, { challengerBps: 5000, victimBps: 4000 }, dest);
    expect([s.challengerReward, s.victimCompensation, s.treasuryRemainder]).toEqual([3, 2, 2]);
  });
  it('a non-integer fallback amount uses the fractional 2^-30 grid, not whole units', () => {
    const s = computeSlashSplit(1e7 + 0.0000005, { challengerBps: 5000, victimBps: 4000 }, dest);
    expect(Number.isInteger(s.challengerReward)).toBe(false);
    expect(s.challengerReward).toBeGreaterThan(5_000_000);
  });
});

describe('evidence digests — field-for-field', () => {
  const claim = { pcactn_digest: 'dig-1', bond_ref: 'bond-1' } as never;
  it('settlementEvidenceDigest commits to the claim digest, bond, fraudulent, slashBondRef (null when absent) and reason', () => {
    expect(settlementEvidenceDigest(claim, { fraudulent: true, slashBondRef: 'bond-1', reason: 'r' })).toBe(
      hashCanonicalLenient({ claimDigest: 'dig-1', bond_ref: 'bond-1', fraudulent: true, slashBondRef: 'bond-1', reason: 'r' }),
    );
    expect(settlementEvidenceDigest(claim, { fraudulent: false, reason: 'r' })).toBe(
      hashCanonicalLenient({ claimDigest: 'dig-1', bond_ref: 'bond-1', fraudulent: false, slashBondRef: null, reason: 'r' }),
    );
  });
  it('revocationEvidenceDigest binds kind=revocation and the revoked capability id', () => {
    expect(revocationEvidenceDigest(claim, 'cap-9')).toBe(hashCanonicalLenient({ claimDigest: 'dig-1', bond_ref: 'bond-1', kind: 'revocation', revokedCapId: 'cap-9' }));
    expect(revocationEvidenceDigest(claim, 'cap-9')).not.toBe(revocationEvidenceDigest(claim, 'cap-8'));
  });
  it('disputeEvidenceDigest binds kind=dispute and every verdict field (undefined values as null)', () => {
    const v = { outcome: 'agent-fraud', input: 'blastRadius', agentValue: 0.1, oracleValue: 0.9, slashBondRef: 'bond-1', reason: 'why' } as unknown as DisputeVerdict;
    expect(disputeEvidenceDigest(claim, v)).toBe(
      hashCanonicalLenient({ claimDigest: 'dig-1', bond_ref: 'bond-1', kind: 'dispute', outcome: 'agent-fraud', input: 'blastRadius', agentValue: 0.1, oracleValue: 0.9, slashBondRef: 'bond-1', reason: 'why' }),
    );
    const bare = { outcome: 'claim-upheld', input: 'blastRadius', reason: 'why' } as unknown as DisputeVerdict;
    expect(disputeEvidenceDigest(claim, bare)).toBe(
      hashCanonicalLenient({ claimDigest: 'dig-1', bond_ref: 'bond-1', kind: 'dispute', outcome: 'claim-upheld', input: 'blastRadius', agentValue: null, oracleValue: null, slashBondRef: null, reason: 'why' }),
    );
  });
});

describe('signed record layout + verifySettlement', () => {
  const rec = (): SettlementRecord => ledger().openBond({ claimId: 'b1', amount: 100, depositor: 'alice', at: NOW });
  it('the signature covers DOMAIN || canonical(body), body excluding sig', () => {
    const r = rec();
    const { sig, ...body } = r;
    const msg = new Uint8Array([...utf8('atlas-pca/bond-settlement/v1\0'), ...canonicalBytesLenient(body)]);
    expect(sig).toBe(b64u(sign(G.secretKey, msg)));
    // a signature over the bare body (no domain prefix) is not accepted
    const bare = { ...r, sig: b64u(sign(G.secretKey, canonicalBytesLenient(body))) };
    expect(verifySettlement(bare, gpk)).toBe(false);
    expect(verifySettlement(r, gpk)).toBe(true);
  });
  it('malformed inputs verify false (never throw)', () => {
    const r = rec();
    expect(verifySettlement(null as never, gpk)).toBe(false);
    expect(verifySettlement(undefined as never, gpk)).toBe(false);
    expect(verifySettlement('x' as never, gpk)).toBe(false);
    expect(verifySettlement({ ...r, sig: undefined } as never, gpk)).toBe(false);
    expect(verifySettlement({ ...r, alg: 'bogus' } as never, gpk)).toBe(false);
    expect(verifySettlement(r, 'not-a-key')).toBe(false);
  });
  it('a record whose body cannot be canonicalised verifies false (caught, exactly false)', () => {
    const r = rec();
    expect(verifySettlement({ ...r, extra: new Date() } as never, gpk)).toBe(false);
    expect(verifySettlement({ ...r, extra: new Map() } as never, gpk)).toBe(false);
  });
  it('a tampered field fails', () => {
    const r = rec();
    expect(verifySettlement({ ...r, amount: 101 }, gpk)).toBe(false);
    expect(verifySettlement({ ...r, to: 'mallory' }, gpk)).toBe(false);
  });
});

describe('settlementCommit / verifySettlementCommit', () => {
  const r = ledger().openBond({ claimId: 'b1', amount: 100, depositor: 'alice', at: NOW });
  it('salt must be a non-empty string (exact message)', () => {
    thr(() => settlementCommit('', r), 'settlementCommit: salt must be a non-empty string');
    thr(() => settlementCommit(123 as never, r), 'settlementCommit: salt must be a non-empty string');
    thr(() => settlementCommit(undefined as never, r), 'settlementCommit: salt must be a non-empty string');
    expect(() => settlementCommit('s', r)).not.toThrow();
  });
  it('verifySettlementCommit: true on a match, false (not throw) on mismatch / bad salt', () => {
    const c = settlementCommit('salt', r);
    expect(verifySettlementCommit(c, 'salt', r)).toBe(true);
    expect(verifySettlementCommit(c, 'other', r)).toBe(false);
    expect(verifySettlementCommit(c, '', r)).toBe(false);
    expect(verifySettlementCommit(c, 123 as never, r)).toBe(false);
  });
});

describe('bondAmount — curve validation + values', () => {
  const pol = (curve?: BondPolicy['curve'], over: Partial<BondPolicy> = {}): BondPolicy => ({ floor: 0, k: 1, maxOpenClaims: 100, maxOpenAmount: Infinity, curve, ...over });
  it('power curve needs a finite gamma >= 1 (gamma = 1 allowed)', () => {
    const m = 'bondAmount: power curve requires finite gamma >= 1';
    thr(() => bondAmount(pol({ kind: 'power', gamma: 0.99 }), 5), m);
    thr(() => bondAmount(pol({ kind: 'power', gamma: Number.NaN }), 5), m);
    thr(() => bondAmount(pol({ kind: 'power', gamma: Infinity }), 5), m);
    expect(bondAmount(pol({ kind: 'power', gamma: 1 }), 5)).toBe(5);
    expect(bondAmount(pol({ kind: 'power', gamma: 2 }), 5)).toBe(25);
  });
  it('piecewise needs a non-empty tier array', () => {
    const m = 'bondAmount: piecewise curve requires at least one tier';
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: [] }), 5), m);
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: undefined as never }), 5), m);
  });
  it('piecewise upTo must be strictly increasing (Infinity allowed as the last bound)', () => {
    const m = 'bondAmount: piecewise tier `upTo` must be strictly increasing';
    const t = (...ups: number[]) => ups.map((upTo) => ({ upTo, marginalK: 1 }));
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: t(0) }), 5), m); // first must exceed 0
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: t(10, 10) }), 50), m);
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: t(10, 5) }), 50), m); // finite but not increasing
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: t(Number.NaN) }), 5), m);
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: t(-Infinity) }), 5), m);
    expect(bondAmount(pol({ kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: Infinity, marginalK: 2 }] }), 15)).toBe(20);
    expect(bondAmount(pol({ kind: 'piecewise', tiers: [{ upTo: Infinity, marginalK: 3 }] }), 5)).toBe(15);
  });
  it('piecewise marginalK must be finite and >= 0 (0 allowed); rates must be non-decreasing (equal allowed)', () => {
    const m = 'bondAmount: piecewise `marginalK` must be a finite number >= 0';
    const one = (marginalK: number) => pol({ kind: 'piecewise', tiers: [{ upTo: 10, marginalK }] });
    thr(() => bondAmount(one(-1), 5), m);
    thr(() => bondAmount(one(Number.NaN), 5), m);
    thr(() => bondAmount(one(Infinity), 5), m);
    expect(bondAmount(one(0), 5)).toBe(0); // zero marginal rate is allowed
    thr(
      () => bondAmount(pol({ kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 2 }, { upTo: 20, marginalK: 1 }] }), 50),
      'bondAmount: piecewise marginal rates must be non-decreasing (convex)',
    );
    expect(bondAmount(pol({ kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 20, marginalK: 1 }] }), 15)).toBe(15);
  });
  it('piecewise integrates the marginal schedule and extends the last rate beyond the last tier', () => {
    const tiers = [{ upTo: 10, marginalK: 1 }, { upTo: 20, marginalK: 2 }];
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 0)).toBe(0);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 4)).toBe(4);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 10)).toBe(10);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 15)).toBe(20);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 20)).toBe(30);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }), 30)).toBe(50);
    expect(bondAmount(pol({ kind: 'piecewise', tiers }, { k: 3 }), 30)).toBe(150);
  });
  it('tiers beyond the exposure are not validated (the walk stops at the covering tier, boundary inclusive)', () => {
    const bad = [{ upTo: 10, marginalK: 1 }, { upTo: 5, marginalK: 2 }];
    expect(bondAmount(pol({ kind: 'piecewise', tiers: bad }), 3)).toBe(3);
    expect(bondAmount(pol({ kind: 'piecewise', tiers: bad }), 10)).toBe(10);
    thr(() => bondAmount(pol({ kind: 'piecewise', tiers: bad }), 11), 'bondAmount: piecewise tier `upTo` must be strictly increasing');
  });
  it('non-finite / non-positive exposure sizes to the floor; floor wins over a smaller curve value', () => {
    for (const e of [Number.NaN, Infinity, -Infinity, -5, 0]) {
      expect(bondAmount(pol(undefined, { floor: 7 }), e)).toBe(7);
      expect(bondAmount(pol({ kind: 'power', gamma: 1.5 }, { floor: 7 }), e)).toBe(7);
    }
    expect(bondAmount(pol(undefined, { floor: 7, k: 2 }), 3)).toBe(7);
    expect(bondAmount(pol(undefined, { floor: 7, k: 2 }), 4)).toBe(8);
  });
});

describe('InMemoryBondAccount + exactAdd', () => {
  it('debit / credit reject negative and non-finite amounts with exact messages; zero is allowed', () => {
    const a = new InMemoryBondAccount({ x: 10 });
    for (const bad of [-1, Number.NaN, Infinity, -Infinity]) {
      thr(() => a.debit('x', bad), 'debit: invalid amount');
      thr(() => a.credit('x', bad), 'credit: invalid amount');
    }
    expect(() => a.debit('x', 0)).not.toThrow();
    expect(() => a.credit('x', 0)).not.toThrow();
    expect(a.balanceOf('x')).toBe(10);
  });
  it('debit refuses to overdraw (exact message); an exact drain is fine', () => {
    const a = new InMemoryBondAccount({ x: 10 });
    thr(() => a.debit('x', 10.000001), 'debit: insufficient balance for x');
    thr(() => a.debit('nobody', 1), 'debit: insufficient balance for nobody');
    a.debit('x', 10);
    expect(a.balanceOf('x')).toBe(0);
  });
  it('micro-grid amounts add without float drift', () => {
    const a = new InMemoryBondAccount({ x: 0.1 });
    a.credit('x', 0.2);
    expect(a.balanceOf('x')).toBe(0.3);
    a.debit('x', 0.1);
    expect(a.balanceOf('x')).toBe(0.2);
  });
  it('off-grid amounts fall back to plain float add/subtract (either operand off-grid)', () => {
    const a = new InMemoryBondAccount({ x: 1e-7 });
    a.credit('x', 2e-7);
    expect(a.balanceOf('x')).toBe(1e-7 + 2e-7);
    a.debit('x', 1e-7);
    expect(a.balanceOf('x')).toBe(1e-7 + 2e-7 - 1e-7);
    const b = new InMemoryBondAccount({ y: 1 });
    b.credit('y', 1e-7); // a on-grid, b off-grid
    expect(b.balanceOf('y')).toBe(1 + 1e-7);
    const c = new InMemoryBondAccount({ z: 1e-7 });
    c.credit('z', 1); // a off-grid, b on-grid
    expect(c.balanceOf('z')).toBe(1e-7 + 1);
    c.debit('z', 0.5);
    expect(c.balanceOf('z')).toBe(1e-7 + 1 - 0.5);
  });
});

describe('BondLedger constructor', () => {
  it('guardianSecret must be a Uint8Array', () => {
    thr(() => new BondLedger({ guardianSecret: 'abc' as never }), 'BondLedger: guardianSecret must be a Uint8Array');
    thr(() => new BondLedger({ guardianSecret: [1, 2, 3] as never }), 'BondLedger: guardianSecret must be a Uint8Array');
  });
  it('guardianEpoch must be a non-negative safe integer; 0 is valid and is signed into the record', () => {
    const m = 'BondLedger: guardianEpoch must be a non-negative safe integer';
    for (const bad of [-1, 1.5, Number.NaN, 2 ** 53, Infinity]) thr(() => new BondLedger({ guardianSecret: G.secretKey, guardianEpoch: bad }), m);
    const L = new BondLedger({ guardianSecret: G.secretKey, guardianEpoch: 0, accounts: new InMemoryBondAccount({ a: 5 }) });
    const r = L.openBond({ claimId: 'e0', amount: 5, depositor: 'a', at: NOW });
    expect(r.guardian_epoch).toBe(0);
    expect(verifySettlement(r, gpk)).toBe(true);
    expect(verifySettlement({ ...r, guardian_epoch: 1 }, gpk)).toBe(false);
    const L2 = new BondLedger({ guardianSecret: G.secretKey, guardianEpoch: 7, accounts: new InMemoryBondAccount({ a: 5 }) });
    expect(L2.openBond({ claimId: 'e7', amount: 5, depositor: 'a', at: NOW }).guardian_epoch).toBe(7);
    expect('guardian_epoch' in ledger().openBond({ claimId: 'n', amount: 1, depositor: 'alice', at: NOW })).toBe(false);
  });
  it('an unknown signature alg is refused with its name', () => {
    thr(() => new BondLedger({ guardianSecret: G.secretKey, suite: { alg: 'bogus' as never } }), "BondLedger: unknown signature alg 'bogus'");
  });
  it('defaults: escrow label, publishes the guardian public key, default policies', () => {
    const L = new BondLedger({ guardianSecret: G.secretKey });
    expect(L.guardianPublicKey).toBe(gpk);
    expect(ESCROW_ACCOUNT).toBe('escrow');
    expect(COMPENSATION_POOL_ACCOUNT).toBe('pca:pool:compensation');
    expect(L.bondPolicy.floor).toBe(1);
    expect(L.slashSplitPolicy).toEqual({ challengerBps: 5000, victimBps: 4000 });
    const custom = new BondLedger({ guardianSecret: G.secretKey, escrowAccount: 'vault', accounts: new InMemoryBondAccount({ a: 10 }) });
    expect(custom.openBond({ claimId: 'x', amount: 10, depositor: 'a', at: NOW }).to).toBe('vault');
    expect(custom.balanceOf('vault')).toBe(10);
  });
});

describe('openBond — guards (exact messages)', () => {
  it('claimId / depositor must be non-empty strings', () => {
    const L = ledger();
    thr(() => L.openBond({ claimId: '', amount: 5, depositor: 'alice' }), 'openBond: claimId is required');
    thr(() => L.openBond({ claimId: 5 as never, amount: 5, depositor: 'alice' }), 'openBond: claimId is required');
    thr(() => L.openBond({ claimId: 'c', amount: 5, depositor: '' }), 'openBond: depositor is required');
    thr(() => L.openBond({ claimId: 'c', amount: 5, depositor: 5 as never }), 'openBond: depositor is required');
  });
  it('amount must be positive and finite (zero refused)', () => {
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 100 }), bondPolicy: { floor: 0, k: 0, maxOpenClaims: 10, maxOpenAmount: Infinity } });
    const m = 'openBond: amount must be a positive finite number';
    for (const bad of [0, -1, Number.NaN, Infinity]) thr(() => L.openBond({ claimId: 'c', amount: bad, depositor: 'alice' }), m);
    expect(L.bondStatus('c')).toBe('none');
  });
  it('the depositor must actually hold the amount: exact balance succeeds, one micro short is refused before any debit', () => {
    const acc = new RecAccount({ alice: 100 });
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: acc, bondPolicy: { floor: 0, k: 0, maxOpenClaims: 10, maxOpenAmount: Infinity } });
    thr(() => L.openBond({ claimId: 'c1', amount: 100.000001, depositor: 'alice' }), 'openBond: insufficient balance for the bond');
    expect(acc.calls).toEqual([]);
    expect(L.bondStatus('c1')).toBe('none');
    L.openBond({ claimId: 'c2', amount: 100, depositor: 'alice' });
    expect(acc.calls).toEqual([['debit', 'alice', 100], ['credit', 'escrow', 100]]);
    expect(L.balanceOf('alice')).toBe(0);
  });
  it('the open record carries an empty evidence digest and the escrow destination', () => {
    const r = ledger().openBond({ claimId: 'c', amount: 5, depositor: 'alice', at: NOW });
    expect(r).toMatchObject({ claimId: 'c', action: 'open', amount: 5, from: 'alice', to: 'escrow', at: NOW, evidenceDigest: '' });
    expect(r.split).toBeUndefined();
  });
});

describe('releaseBond — escrow really drains', () => {
  it('debits escrow, credits the depositor, record has empty evidence digest', () => {
    const acc = new RecAccount({ alice: 100 });
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: acc });
    L.openBond({ claimId: 'r1', amount: 40, depositor: 'alice', at: NOW });
    expect(L.balanceOf('escrow')).toBe(40);
    acc.calls.length = 0;
    const r = L.releaseBond({ claimId: 'r1', at: NOW });
    expect(acc.calls).toEqual([['debit', 'escrow', 40], ['credit', 'alice', 40]]);
    expect(L.balanceOf('escrow')).toBe(0);
    expect(r.evidenceDigest).toBe('');
    expect(r).toMatchObject({ action: 'release', from: 'escrow', to: 'alice', amount: 40 });
  });
  it('exact messages for a missing and an already-settled bond', () => {
    const L = ledger();
    thr(() => L.releaseBond({ claimId: 'zz' }), 'releaseBond: no bond for zz');
    L.openBond({ claimId: 'q', amount: 5, depositor: 'alice' });
    L.releaseBond({ claimId: 'q' });
    thr(() => L.releaseBond({ claimId: 'q' }), 'releaseBond: bond q is already released (double-settle refused)');
  });
});

describe('slash paths — guards in order, exact messages', () => {
  it('slashBond: missing / settled / treasury / bond_ref mismatch each refuse on their own', () => {
    const kit = fraudKit('s1');
    const base = { claimId: 's1', claim: kit.claim, fraudProof: kit.proof, grant: GRANT, openSnapshot: kit.di, treasury: 'tr' };
    const L = ledger();
    thr(() => L.slashBond(base), 'slashBond: no bond for s1');
    L.openBond({ claimId: 's1', amount: 10, depositor: 'alice', at: NOW });
    thr(() => L.slashBond({ ...base, treasury: '' }), 'slashBond: treasury is required');
    thr(() => L.slashBond({ ...base, treasury: 5 as never }), 'slashBond: treasury is required');
    thr(() => L.slashBond({ ...base, claim: { ...kit.claim, bond_ref: 'other' } }), 'slashBond: claim.bond_ref does not match claimId');
    expect(L.bondStatus('s1')).toBe('open');
    L.releaseBond({ claimId: 's1' });
    thr(() => L.slashBond(base), 'slashBond: bond s1 is already released (double-settle refused)');
    // a slashed bond reports "slashed"
    const k2 = fraudKit('s2');
    L.openBond({ claimId: 's2', amount: 10, depositor: 'alice', at: NOW });
    L.slashBond({ claimId: 's2', claim: k2.claim, fraudProof: k2.proof, grant: GRANT, openSnapshot: k2.di, treasury: 'tr' });
    thr(
      () => L.slashBond({ claimId: 's2', claim: k2.claim, fraudProof: k2.proof, grant: GRANT, openSnapshot: k2.di, treasury: 'tr' }),
      'slashBond: bond s2 is already slashed (double-settle refused)',
    );
  });
  it('slashBond: refuses a verdict that is fraudulent for a different bond, or a non-fraud verdict naming this bond (hostile verdict)', () => {
    const kit = fraudKit('s3');
    const args = { claimId: 's3', claim: kit.claim, fraudProof: kit.proof, grant: GRANT, openSnapshot: kit.di, treasury: 'tr' };
    const L = ledger();
    L.openBond({ claimId: 's3', amount: 10, depositor: 'alice', at: NOW });
    vi.mocked(verifyFraudProof).mockReturnValueOnce({ fraudulent: true, slashBondRef: 'someone-else', reason: 'x' });
    thr(() => L.slashBond(args), 'slashBond: refused — no verified fraud verdict slashing s3 (x)');
    vi.mocked(verifyFraudProof).mockReturnValueOnce({ fraudulent: false, slashBondRef: 's3', reason: 'y' });
    thr(() => L.slashBond(args), 'slashBond: refused — no verified fraud verdict slashing s3 (y)');
    vi.mocked(verifyFraudProof).mockReturnValueOnce({ fraudulent: true, reason: 'z' });
    thr(() => L.slashBond(args), 'slashBond: refused — no verified fraud verdict slashing s3 (z)');
    expect(L.bondStatus('s3')).toBe('open');
    expect(L.balanceOf('escrow')).toBe(10);
  });
  it('slashBondOnRevocation: each guard on its own, exact messages; then slashes', () => {
    const kit = fraudKit('v1');
    const base = { claimId: 'v1', claim: kit.claim, revokedCapId: 'cap-1', treasury: 'tr' };
    const L = ledger();
    thr(() => L.slashBondOnRevocation(base), 'slashBondOnRevocation: no bond for v1');
    L.openBond({ claimId: 'v1', amount: 10, depositor: 'alice', at: NOW });
    thr(() => L.slashBondOnRevocation({ ...base, treasury: '' }), 'slashBondOnRevocation: treasury is required');
    thr(() => L.slashBondOnRevocation({ ...base, treasury: 7 as never }), 'slashBondOnRevocation: treasury is required');
    thr(() => L.slashBondOnRevocation({ ...base, claim: { ...kit.claim, bond_ref: 'other' } }), 'slashBondOnRevocation: claim.bond_ref does not match claimId');
    thr(() => L.slashBondOnRevocation({ ...base, revokedCapId: '' }), 'slashBondOnRevocation: revokedCapId is required');
    thr(() => L.slashBondOnRevocation({ ...base, revokedCapId: 7 as never }), 'slashBondOnRevocation: revokedCapId is required');
    expect(L.bondStatus('v1')).toBe('open');
    const rec = L.slashBondOnRevocation({ ...base, at: NOW });
    expect(L.bondStatus('v1')).toBe('slashed');
    expect(rec.evidenceDigest).toBe(revocationEvidenceDigest(kit.claim, 'cap-1'));
    thr(() => L.slashBondOnRevocation(base), 'slashBondOnRevocation: bond v1 is already slashed (double-settle refused)');
    L.openBond({ claimId: 'v2', amount: 10, depositor: 'alice', at: NOW });
    L.releaseBond({ claimId: 'v2' });
    thr(() => L.slashBondOnRevocation({ ...base, claimId: 'v2', claim: { ...kit.claim, bond_ref: 'v2' } }), 'slashBondOnRevocation: bond v2 is already released (double-settle refused)');
  });
  it('slashBondOnDispute: each guard on its own, exact messages', () => {
    const k = disputeKit('d1');
    const base = { claimId: 'd1', claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.fraudOracle, treasury: 'tr' };
    const L = ledger();
    thr(() => L.slashBondOnDispute(base), 'slashBondOnDispute: no bond for d1');
    L.openBond({ claimId: 'd1', amount: 10, depositor: 'alice', at: NOW });
    thr(() => L.slashBondOnDispute({ ...base, treasury: '' }), 'slashBondOnDispute: treasury is required');
    thr(() => L.slashBondOnDispute({ ...base, treasury: 7 as never }), 'slashBondOnDispute: treasury is required');
    thr(() => L.slashBondOnDispute({ ...base, claim: { ...k.claim, bond_ref: 'other' } }), 'slashBondOnDispute: claim.bond_ref does not match claimId');
    L.releaseBond({ claimId: 'd1' });
    thr(() => L.slashBondOnDispute(base), 'slashBondOnDispute: bond d1 is already released (double-settle refused)');
  });
  it('slashBondOnDispute: only an agent-fraud verdict naming this bond slashes (hostile verdicts refused)', () => {
    const k = disputeKit('d2');
    const base = { claimId: 'd2', claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.fraudOracle, treasury: 'tr' };
    const L = ledger();
    L.openBond({ claimId: 'd2', amount: 10, depositor: 'alice', at: NOW });
    const v = (over: Partial<DisputeVerdict>) =>
      ({ outcome: 'agent-fraud', fraudulent: true, slashBondRef: 'd2', slashCounterBond: false, input: 'reversibility_class', agentValue: 'reversible', oracleValue: 'irreversible', reason: 'rr', ...over }) as DisputeVerdict;
    const refuse = (verdict: DisputeVerdict, tag: string) => {
      vi.mocked(adjudicateDispute).mockReturnValueOnce(verdict);
      thr(() => L.slashBondOnDispute(base), `slashBondOnDispute: refused — no verified agent-fraud verdict slashing d2 (${tag}: rr)`);
    };
    refuse(v({ outcome: 'claim-upheld' }), 'claim-upheld'); // fraudulent+ref ok but the wrong outcome
    refuse(v({ fraudulent: false }), 'agent-fraud');
    refuse(v({ slashBondRef: 'other' }), 'agent-fraud');
    refuse(v({ slashBondRef: undefined }), 'agent-fraud');
    expect(L.bondStatus('d2')).toBe('open');
    expect(L.slashBondOnDispute(base).action).toBe('slash');
  });
  it('slashCounterBond: each guard on its own, exact messages', () => {
    const k = disputeKit('cb-target');
    const base = { counterBondId: 'cb1', claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.upholdOracle, treasury: 'tr' };
    const L = ledger();
    thr(() => L.slashCounterBond(base), 'slashCounterBond: no counter-bond for cb1');
    L.openBond({ claimId: 'cb1', amount: 10, depositor: 'alice', at: NOW });
    thr(() => L.slashCounterBond({ ...base, treasury: '' }), 'slashCounterBond: treasury is required');
    thr(() => L.slashCounterBond({ ...base, treasury: 7 as never }), 'slashCounterBond: treasury is required');
    L.releaseBond({ claimId: 'cb1' });
    thr(() => L.slashCounterBond(base), 'slashCounterBond: counter-bond cb1 is already released (double-settle refused)');
  });
  it('slashCounterBond: requires BOTH outcome claim-upheld and slashCounterBond (hostile verdicts refused)', () => {
    const k = disputeKit('cb-target2');
    const base = { counterBondId: 'cb2', claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.upholdOracle, treasury: 'tr' };
    const L = ledger();
    L.openBond({ claimId: 'cb2', amount: 10, depositor: 'alice', at: NOW });
    const v = (over: Partial<DisputeVerdict>) =>
      ({ outcome: 'claim-upheld', fraudulent: false, slashCounterBond: true, input: 'reversibility_class', reason: 'rr', ...over }) as DisputeVerdict;
    vi.mocked(adjudicateDispute).mockReturnValueOnce(v({ outcome: 'agent-fraud' }));
    thr(() => L.slashCounterBond(base), 'slashCounterBond: refused — the dispute is not frivolous (agent-fraud: rr)');
    vi.mocked(adjudicateDispute).mockReturnValueOnce(v({ slashCounterBond: false }));
    thr(() => L.slashCounterBond(base), 'slashCounterBond: refused — the dispute is not frivolous (claim-upheld: rr)');
    expect(L.bondStatus('cb2')).toBe('open');
    const rec = L.slashCounterBond(base);
    expect(rec.claimId).toBe('cb2');
    expect(rec.split).toMatchObject({ challengerReward: 0, victimCompensation: 0, treasuryRemainder: 10, challengerAccount: null });
  });
});

describe('settleSlashSplit — exactly the credits that are owed (observed through a recording account)', () => {
  const mk = (init: Record<string, number>, policy?: { challengerBps: number; victimBps: number }, bondPolicy?: BondPolicy) => {
    const acc = new RecAccount(init);
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts: acc, slashSplitPolicy: policy, bondPolicy: bondPolicy ?? { floor: 0, k: 0, maxOpenClaims: 10, maxOpenAmount: Infinity } });
    return { acc, L };
  };
  const revoke = (L: BondLedger, id: string, extra: Record<string, unknown> = {}) =>
    L.slashBondOnRevocation({ claimId: id, claim: { pcactn_digest: 'd', bond_ref: id } as never, revokedCapId: 'cap', treasury: 'tr', at: NOW, ...extra });

  it('anonymous: the full bond leaves escrow and ONLY the treasury is credited (no zero-credit to anyone)', () => {
    const { acc, L } = mk({ alice: 100 });
    L.openBond({ claimId: 'a1', amount: 100, depositor: 'alice' });
    acc.calls.length = 0;
    revoke(L, 'a1');
    expect(acc.calls).toEqual([['debit', 'escrow', 100], ['credit', 'tr', 100]]);
    expect(L.balanceOf('escrow')).toBe(0);
  });
  it('identified challenger: challenger, victim pool and treasury credited in that order with the signed split', () => {
    const { acc, L } = mk({ alice: 100 });
    L.openBond({ claimId: 'a2', amount: 100, depositor: 'alice' });
    acc.calls.length = 0;
    const r = revoke(L, 'a2', { challengerAccount: 'wt', compensationAccount: 'pool' });
    expect(acc.calls).toEqual([['debit', 'escrow', 100], ['credit', 'wt', 50], ['credit', 'pool', 40], ['credit', 'tr', 10]]);
    expect(r.split).toMatchObject({ amount: 100, challengerReward: 50, victimCompensation: 40, treasuryRemainder: 10, challengerAccount: 'wt', victimAccount: 'pool', treasuryAccount: 'tr' });
    expect(r.amount).toBe(100);
    expect(r.to).toBe('tr');
    expect(r.from).toBe('escrow');
    expect(verifySettlement(r, gpk)).toBe(true);
  });
  it('default compensation account is the reserved pool label', () => {
    const { L } = mk({ alice: 100 });
    L.openBond({ claimId: 'a3', amount: 100, depositor: 'alice' });
    revoke(L, 'a3', { challengerAccount: 'wt' });
    expect(L.balanceOf(COMPENSATION_POOL_ACCOUNT)).toBe(40);
  });
  it('a zero treasury remainder is not credited', () => {
    const { acc, L } = mk({ alice: 100 }, { challengerBps: 5000, victimBps: 5000 });
    L.openBond({ claimId: 'a4', amount: 100, depositor: 'alice' });
    acc.calls.length = 0;
    revoke(L, 'a4', { challengerAccount: 'wt' });
    expect(acc.calls).toEqual([['debit', 'escrow', 100], ['credit', 'wt', 50], ['credit', fallbackPool(), 50]]);
  });
  it('a zero challenger reward / zero victim share (tiny bond) are not credited', () => {
    const { acc, L } = mk({ alice: 1 });
    L.openBond({ claimId: 'a5', amount: 0.000001, depositor: 'alice' });
    acc.calls.length = 0;
    revoke(L, 'a5', { challengerAccount: 'wt' });
    expect(acc.calls).toEqual([['debit', 'escrow', 0.000001], ['credit', 'tr', 0.000001]]);
  });
  it('a challenger share of zero bps (identified challenger) credits only victim + treasury', () => {
    const { acc, L } = mk({ alice: 100 }, { challengerBps: 0, victimBps: 4000 });
    L.openBond({ claimId: 'a6', amount: 100, depositor: 'alice' });
    acc.calls.length = 0;
    revoke(L, 'a6', { challengerAccount: 'wt' });
    expect(acc.calls).toEqual([['debit', 'escrow', 100], ['credit', fallbackPool(), 40], ['credit', 'tr', 60]]);
  });
  it('a per-call splitPolicy overrides the ledger policy; the bond status becomes slashed', () => {
    const { L } = mk({ alice: 100 });
    L.openBond({ claimId: 'a7', amount: 100, depositor: 'alice' });
    const r = revoke(L, 'a7', { challengerAccount: 'wt', splitPolicy: { challengerBps: 1000, victimBps: 1000 } });
    expect(r.split).toMatchObject({ challengerReward: 10, victimCompensation: 10, treasuryRemainder: 80 });
    expect(L.bondStatus('a7')).toBe('slashed');
  });
  function fallbackPool() {
    return COMPENSATION_POOL_ACCOUNT;
  }
});

describe('slashBond / slashBondOnDispute end-to-end settle with the same split', () => {
  it('slashBond: escrow drained, split recorded, status slashed', () => {
    const kit = fraudKit('e1');
    const L = ledger();
    L.openBond({ claimId: 'e1', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBond({ claimId: 'e1', claim: kit.claim, fraudProof: kit.proof, grant: GRANT, openSnapshot: kit.di, treasury: 'tr', challengerAccount: 'wt', at: NOW });
    expect(L.balanceOf('escrow')).toBe(0);
    expect(L.balanceOf('wt')).toBe(50);
    expect(L.balanceOf(COMPENSATION_POOL_ACCOUNT)).toBe(40);
    expect(L.balanceOf('tr')).toBe(10);
    expect(L.bondStatus('e1')).toBe('slashed');
    expect(rec.evidenceDigest).toBe(settlementEvidenceDigest(kit.claim, verifyFraudProof(kit.claim, kit.proof, GRANT, kit.di)));
  });
  it('slashBondOnDispute: escrow drained and the record binds the dispute verdict', () => {
    const k = disputeKit('e2');
    const L = ledger();
    L.openBond({ claimId: 'e2', amount: 100, depositor: 'alice', at: NOW });
    const rec = L.slashBondOnDispute({ claimId: 'e2', claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.fraudOracle, treasury: 'tr', at: NOW });
    expect(L.balanceOf('escrow')).toBe(0);
    expect(L.bondStatus('e2')).toBe('slashed');
    expect(rec.evidenceDigest).toBe(disputeEvidenceDigest(k.claim, adjudicateDispute({ claim: k.claim, dispute: k.dispute, grant: GRANT, openSnapshot: k.di, oracle: k.fraudOracle })));
  });
});

describe('InsuranceCapitalPool', () => {
  const rep = (score: number): Reputation => ({ subject: 's', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score, factors: [] });
  it('initial capital must be a non-negative finite number (exact message; zero allowed)', () => {
    const m = 'InsuranceCapitalPool: initial capital must be a non-negative finite number';
    thr(() => new InsuranceCapitalPool(-1), m);
    thr(() => new InsuranceCapitalPool(Number.NaN), m);
    thr(() => new InsuranceCapitalPool(Infinity), m);
    expect(new InsuranceCapitalPool(0).balance).toBe(0);
    expect(new InsuranceCapitalPool().state()).toEqual({ initial: 0, premiumsIn: 0, payoutsOut: 0, balance: 0 });
  });
  it('collectPremium credits a priced premium; declined / zero / negative premiums credit nothing; a non-finite premium is refused', () => {
    const pool = new InsuranceCapitalPool(100);
    const c = pool.collectPremium(rep(1), 1000, { baseRate: 0.01 });
    expect(c.pricing.premium).toBe(10);
    expect(c.state).toEqual({ initial: 100, premiumsIn: 10, payoutsOut: 0, balance: 110 });
    expect(pool.collectPremium(rep(0.1), 1000).state.premiumsIn).toBe(10); // declined
    expect(pool.collectPremium(rep(1), 0).state.premiumsIn).toBe(10); // zero premium
    expect(pool.collectPremium(rep(1), 1000, { baseRate: -0.01 }).state.premiumsIn).toBe(10); // negative premium: not credited, not thrown
    thr(() => pool.collectPremium(rep(1), 1000, { baseRate: Infinity }), 'collectPremium: priced premium is not a non-negative finite number');
    expect(pool.premiumsIn).toBe(10);
  });
  it('quote does not mutate; canCover is false for negative / non-finite and inclusive at the balance', () => {
    const pool = new InsuranceCapitalPool(50);
    expect(pool.quote(rep(1), 1000).premium).toBe(10);
    expect(pool.premiumsIn).toBe(0);
    expect(pool.canCover(50)).toBe(true);
    expect(pool.canCover(0)).toBe(true);
    expect(pool.canCover(50.000001)).toBe(false);
    expect(pool.canCover(-1)).toBe(false);
    expect(pool.canCover(Number.NaN)).toBe(false);
    expect(pool.canCover(Infinity)).toBe(false);
  });
  it('payClaim: exact messages; paying the exact balance is allowed; state reconciles', () => {
    const pool = new InsuranceCapitalPool(50);
    const m = 'payClaim: amount must be a positive finite number';
    for (const bad of [0, -1, Number.NaN, Infinity]) thr(() => pool.payClaim(bad), m);
    thr(() => pool.payClaim(50.5), 'payClaim: insufficient pool capital (need 50.5, have 50)');
    expect(pool.payClaim(20)).toEqual({ initial: 50, premiumsIn: 0, payoutsOut: 20, balance: 30 });
    expect(pool.payClaim(30).balance).toBe(0);
    expect(pool.payoutsOut).toBe(50);
  });
});
