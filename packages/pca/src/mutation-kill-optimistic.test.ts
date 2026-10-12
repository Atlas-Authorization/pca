/**
 * Mutation-kill tests for optimistic.ts. The Policy VM is spied (pass-through by default) so each verdict branch,
 * boundary and exact reason string can be driven with a precisely chosen decision; the claim signature layout, the
 * window validators, every fail-closed branch of the one-shot and multi-round disputes, the substitution of the
 * oracle's value into a COPY of the frozen snapshot, and freezeOpenSnapshot are asserted field-for-field.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_MIN_CHALLENGE_WINDOW_MS,
  DEFAULT_WINDOW_POLICY,
  IRREVERSIBLE_CLASS,
  adjudicateDispute,
  adjudicateDisputeGame,
  challengeWindowEnd,
  claimStatus,
  fileFraudProof,
  freezeOpenSnapshot,
  openOptimistic,
  resolveWindow,
  validateWindow,
  verifyClaim,
  verifyFraudProof,
  withinChallengeWindow,
  type BondedClaim,
  type ChallengeWindowPolicy,
  type DisputableInput,
  type DisputeGame,
  type FraudProof,
  type ObjectiveOracle,
  type OracleResolution,
} from './optimistic';
import { canonicalBytesLenient, utf8 } from './hash';
import { encodeKey, generateKeyPair, verifyB64u } from './keys';
import { mintGrant } from './envelope';
import { buildPCActn, pcactnDigest, type PCActn } from './pcactn';
import { decide, type DecideInput, type PolicyDecision } from './policy-vm';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

vi.mock('./policy-vm', async (importOriginal) => {
  const m = await importOriginal<typeof import('./policy-vm')>();
  return { ...m, decide: vi.fn(m.decide) };
});
// The mock factory built decide as vi.fn(<real decide>), so its initial implementation IS the real decide.
const realDecide = vi.mocked(decide).getMockImplementation()!;
afterEach(() => {
  vi.mocked(decide).mockReset();
  vi.mocked(decide).mockImplementation(realDecide);
});

const P = generateKeyPair();
const A = generateKeyPair();
const pubA = encodeKey(A.publicKey);
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: pubA,
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

function actn(verb = 'revoke_session', reversibility_class = 'reversible'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}
function snapFor(p: PCActn, risk: Partial<DecideInput['risk']> = {}): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0, ...risk },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}
const open = (p: PCActn, claimedR = 0, extra: Record<string, unknown> = {}) =>
  openOptimistic(p, { bondRef: 'bond-1', claimedR, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW, ...extra }, A.secretKey);

/** A hand-built decision (cast: only the fields optimistic.ts reads are meaningful). */
const dec = (o: { rgs?: boolean; r?: number; opt?: boolean; reasons?: string[]; t?: number } = {}): PolicyDecision =>
  ({
    releaseGuardianShare: o.rgs ?? true,
    r: o.r ?? 0,
    admit: true,
    needStepUp: false,
    reasons: o.reasons ?? [],
    requiredThreshold: { optimisticAllowed: o.opt ?? true, t: o.t ?? 1 },
    budget: fresh,
  }) as unknown as PolicyDecision;
const summaryOf = (d: PolicyDecision) => ({ releaseGuardianShare: d.releaseGuardianShare, r: d.r, optimisticAllowed: d.requiredThreshold.optimisticAllowed });

describe('claim signature layout', () => {
  it('signs DOMAIN || canonical(body) under the agent key', () => {
    const p = actn();
    const c = open(p, 0.25);
    const { sig, ...body } = c;
    const msg = new Uint8Array([...utf8('atlas-pca/optimistic/v1\0'), ...canonicalBytesLenient(body)]);
    expect(verifyB64u(pubA, msg, sig)).toBe(true);
    expect(verifyB64u(pubA, canonicalBytesLenient(body), sig)).toBe(false); // not the bare body
    expect(verifyB64u(pubA, new Uint8Array([...utf8('atlas-pca/optimistic/v1\0')]), sig)).toBe(false); // not the prefix alone
    expect(body).toEqual({ pcactn_digest: pcactnDigest(p), bond_ref: 'bond-1', claimed_r: 0.25, reversibility_class: 'reversible', issued_at: NOW, challenge_window_ms: 5000 });
  });
});

describe('resolveWindow / validateWindow', () => {
  const pol: ChallengeWindowPolicy = { minWindowMs: 1000, maxWindowMs: 100_000, defaultWindowMs: 60_000, maxSkewMs: 500 };
  it('resolveWindow: serverNow must be finite; clamps into [max(min,30s), max]', () => {
    expect(() => resolveWindow(pol, Number.NaN)).toThrow(new Error('resolveWindow: serverNow must be finite'));
    expect(() => resolveWindow(pol, Infinity)).toThrow(new Error('resolveWindow: serverNow must be finite'));
    expect(resolveWindow(pol, 7, 1000)).toEqual({ issued_at: 7, challenge_window_ms: DEFAULT_MIN_CHALLENGE_WINDOW_MS });
    expect(resolveWindow(pol, 7, 50_000).challenge_window_ms).toBe(50_000);
    expect(resolveWindow(pol, 7, 5e9).challenge_window_ms).toBe(100_000);
    expect(resolveWindow(pol, 7).challenge_window_ms).toBe(60_000);
    expect(resolveWindow(pol, 7, Number.NaN).challenge_window_ms).toBe(60_000);
    expect(resolveWindow({ ...pol, minWindowMs: 40_000 }, 7, 1000).challenge_window_ms).toBe(40_000);
    expect(resolveWindow({ ...pol, maxWindowMs: 10_000 }, 7, 50_000).challenge_window_ms).toBe(10_000);
  });
  it('validateWindow: exact reasons, inclusive boundaries, null when valid', () => {
    const v = (issued: number, w: number, now = 10_000) => validateWindow(issued, w, now, pol);
    expect(v(10_000, 5000)).toBeNull();
    expect(validateWindow(NOW, 5000, NOW)).toBeNull(); // default policy
    expect(v(10_500, 5000)).toBeNull(); // skew == max is fine
    expect(v(9_500, 5000)).toBeNull();
    expect(v(10_501, 5000)).toBe('issued_at is outside the allowed skew of server time');
    expect(v(9_499, 5000)).toBe('issued_at is outside the allowed skew of server time');
    expect(v(10_000, 1000)).toBeNull(); // window == min is fine
    expect(v(10_000, 999)).toBe('challenge window is below the minimum');
    expect(v(10_000, 100_000)).toBeNull(); // window == max is fine
    expect(v(10_000, 100_001)).toBe('challenge window exceeds the maximum');
    expect(v(10_000, 5000, Number.NaN)).toBe('server time is not finite');
    expect(v(10_000, 5000, Infinity)).toBe('server time is not finite');
    expect(v(Number.NaN, 5000)).toBe('malformed challenge window');
    expect(v(10_000, Number.NaN)).toBe('malformed challenge window');
    expect(v(10_000, Infinity)).toBe('malformed challenge window');
    expect(v(Infinity, 5000)).toBe('malformed challenge window');
  });
});

describe('openOptimistic', () => {
  it('exact refusals', () => {
    const p = actn();
    expect(() => openOptimistic(actn('revoke_session', IRREVERSIBLE_CLASS), { bondRef: 'b', claimedR: 0, serverNow: NOW }, A.secretKey)).toThrow(
      new Error('openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)'),
    );
    for (const bad of [Number.NaN, Infinity, undefined as never]) {
      expect(() => openOptimistic(p, { bondRef: 'b', claimedR: bad, serverNow: NOW }, A.secretKey)).toThrow(new Error('openOptimistic: claimedR must be finite'));
    }
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, serverNow: NOW, issuedAt: NOW + 6000 }, A.secretKey)).toThrow(
      new Error('openOptimistic: issued_at is outside the allowed skew of server time'),
    );
    expect(() => openOptimistic(p, { bondRef: 'b', claimedR: 0, serverNow: NOW, challengeWindowMs: 0 }, A.secretKey)).toThrow(new Error('openOptimistic: challenge window is below the minimum'));
  });
  it('defaults: window = policy default, issued_at = serverNow', () => {
    const c = openOptimistic(actn(), { bondRef: 'b', claimedR: 0, serverNow: NOW }, A.secretKey);
    expect(c.issued_at).toBe(NOW);
    expect(c.challenge_window_ms).toBe(DEFAULT_WINDOW_POLICY.defaultWindowMs);
    const c2 = openOptimistic(actn(), { bondRef: 'b', claimedR: 0, serverNow: NOW, windowPolicy: { ...DEFAULT_WINDOW_POLICY, defaultWindowMs: 9_999 } }, A.secretKey);
    expect(c2.challenge_window_ms).toBe(9_999);
  });
  it("a PCActn with a non-string / missing reversibility_class is recorded as 'unknown' (never throws on a missing action)", () => {
    const p = actn();
    const odd = { ...p, action: { ...p.action, reversibility_class: 5 } } as unknown as PCActn;
    expect(open(odd).reversibility_class).toBe('unknown');
    const noClassAction = { ...p.action } as Record<string, unknown>;
    delete noClassAction.reversibility_class;
    expect(open({ ...p, action: noClassAction } as unknown as PCActn).reversibility_class).toBe('unknown');
    const noAction = { ...p } as Record<string, unknown>;
    delete noAction.action;
    expect(open(noAction as unknown as PCActn).reversibility_class).toBe('unknown');
    expect(open(actn('revoke_session', 'rate_limited')).reversibility_class).toBe('rate_limited');
    // a null PCActn has no action: it is digested as-is and recorded 'unknown' (optional chaining, not a TypeError)
    expect(open(null as never).reversibility_class).toBe('unknown');
    // an undefined PCActn cannot be digested: the failure is the canonicalizer's, not a property-read TypeError
    expect(() => open(undefined as never)).toThrow('canonicalize: unsupported type undefined');
  });
});

describe('verifyClaim', () => {
  const p = actn();
  const vc = (c: unknown, extra: Record<string, unknown> = {}, pc: PCActn = p) => verifyClaim(c as BondedClaim, pc, pubA, { serverNow: NOW, ...extra });
  it('accepts a genuine claim (exactly {ok:true})', () => {
    expect(vc(open(p))).toEqual({ ok: true });
  });
  it('malformed claim', () => {
    expect(vc(null)).toEqual({ ok: false, reason: 'malformed claim' });
    expect(vc(undefined)).toEqual({ ok: false, reason: 'malformed claim' });
    expect(vc('claim')).toEqual({ ok: false, reason: 'malformed claim' });
    expect(vc(7)).toEqual({ ok: false, reason: 'malformed claim' });
  });
  it('irreversible claim, different PCActn, non-finite claimed_r: each with its own reason', () => {
    const c = open(p);
    expect(vc({ ...c, reversibility_class: IRREVERSIBLE_CLASS })).toEqual({ ok: false, reason: 'irreversible action is ineligible for the optimistic path' });
    expect(vc(c, {}, actn('revoke_session', 'rate_limited'))).toEqual({ ok: false, reason: 'claim does not cover this PCActn' });
    expect(vc({ ...c, claimed_r: Number.NaN })).toEqual({ ok: false, reason: 'claimed_r is not finite' });
    expect(vc({ ...c, claimed_r: Infinity })).toEqual({ ok: false, reason: 'claimed_r is not finite' });
  });
  it('window reasons come back verbatim; a custom window policy is honoured', () => {
    const c = open(p);
    expect(vc(c, { serverNow: NOW + 60_000 })).toEqual({ ok: false, reason: 'issued_at is outside the allowed skew of server time' });
    const wide: ChallengeWindowPolicy = { ...DEFAULT_WINDOW_POLICY, maxSkewMs: 100_000 };
    const wc = open(p, 0, { issuedAt: NOW + 50_000, windowPolicy: wide });
    expect(vc(wc, { serverNow: NOW, windowPolicy: wide })).toEqual({ ok: true });
    expect(vc(wc, { serverNow: NOW })).toEqual({ ok: false, reason: 'issued_at is outside the allowed skew of server time' }); // default policy
  });
  it('signature: wrong key / tampered body / missing sig all say "claim signature does not verify"', () => {
    const c = open(p);
    const bad = { ok: false, reason: 'claim signature does not verify' };
    expect(verifyClaim(c, p, encodeKey(generateKeyPair().publicKey), { serverNow: NOW })).toEqual(bad);
    expect(vc({ ...c, claimed_r: 0.5 })).toEqual(bad);
    expect(vc({ ...c, sig: undefined })).toEqual(bad);
    expect(vc({ ...c, sig: 5 })).toEqual(bad);
  });
  it('is total: a throwing input becomes ok:false with the error text (or "unknown" for a non-Error)', () => {
    const r1 = verifyClaim(open(p), { ...p, bad: undefined } as never, pubA, { serverNow: NOW });
    expect(r1.ok).toBe(false);
    expect(r1.reason!.startsWith('claim verification error: ')).toBe(true);
    expect(r1.reason!.length).toBeGreaterThan('claim verification error: '.length);
    const hostile = {
      get reversibility_class(): string {
        throw 'boom';
      },
    };
    expect(vc(hostile)).toEqual({ ok: false, reason: 'claim verification error: unknown' });
    const hostileErr = {
      get reversibility_class(): string {
        throw new Error('kaput');
      },
    };
    expect(vc(hostileErr)).toEqual({ ok: false, reason: 'claim verification error: kaput' });
  });
});

describe('challenge window predicates', () => {
  const c = { issued_at: 1000, challenge_window_ms: 5000 } as BondedClaim;
  it('end is issued_at + window; inclusive; non-finite now is never within', () => {
    expect(challengeWindowEnd(c)).toBe(6000);
    expect(withinChallengeWindow(c, 6000)).toBe(true);
    expect(withinChallengeWindow(c, 6001)).toBe(false);
    expect(withinChallengeWindow(c, Number.NaN)).toBe(false);
    expect(withinChallengeWindow(c, -Infinity)).toBe(false);
    expect(withinChallengeWindow(c, Infinity)).toBe(false);
    expect(claimStatus(c, -Infinity)).toBe('finalized');
    expect(claimStatus(c, 6000)).toBe('open');
    expect(claimStatus(c, 6001)).toBe('finalized');
  });
});

describe('fileFraudProof', () => {
  const p = actn();
  const baseClaim = (over: Partial<BondedClaim> = {}): BondedClaim => ({ ...open(p, 0.25), ...over });
  const snap = snapFor(p, { blastRadius: 0.1 });
  const { grant: _g, ...evidence } = snap;
  void _g;
  const file = (claim: BondedClaim, d: PolicyDecision, extra: Record<string, unknown> = {}, pc: PCActn = p) => {
    vi.mocked(decide).mockReturnValueOnce(d);
    return fileFraudProof({ claim, pcactn: pc, grant: GRANT, openSnapshot: snap, ...extra });
  };
  it('returns null without a snapshot (the decision is never consulted) and for a claim about a different action', () => {
    vi.mocked(decide).mockImplementation(() => dec({ rgs: false }));
    expect(fileFraudProof({ claim: baseClaim(), pcactn: p, grant: GRANT })).toBeNull();
    expect(vi.mocked(decide)).not.toHaveBeenCalled();
    expect(fileFraudProof({ claim: baseClaim({ pcactn_digest: 'someone-else' }), pcactn: p, grant: GRANT, openSnapshot: snap })).toBeNull();
  });
  it('replays decide on the frozen snapshot under the supplied grant (alias decideInput honoured; openSnapshot preferred)', () => {
    vi.mocked(decide).mockReturnValue(dec({ rgs: false }));
    fileFraudProof({ claim: baseClaim(), pcactn: p, grant: GRANT, decideInput: snap });
    expect(vi.mocked(decide).mock.calls[0]![0]).toEqual({ ...snap, grant: GRANT });
    const other = snapFor(p, { blastRadius: 0.7 });
    const proof = fileFraudProof({ claim: baseClaim(), pcactn: p, grant: GRANT, openSnapshot: snap, decideInput: other })!;
    expect(proof.evidence).toEqual(evidence);
  });
  it('compliant claim -> null; boundary r == claimed + margin is compliant, just above is understated', () => {
    expect(file(baseClaim(), dec({ r: 0.25 }))).toBeNull();
    expect(file(baseClaim(), dec({ r: 0.75 }), { rMargin: 0.5 })).toBeNull();
    const pr = file(baseClaim(), dec({ r: 0.76 }), { rMargin: 0.5 })!;
    expect(pr.kind).toBe('risk-understated');
  });
  it('risk-understated: full proof shape and reason', () => {
    const c = baseClaim();
    const pr = file(c, dec({ r: 0.5 }))!;
    expect(pr).toEqual({
      pcactn_digest: c.pcactn_digest,
      bond_ref: 'bond-1',
      claimed_r: 0.25,
      decision: { releaseGuardianShare: true, r: 0.5, optimisticAllowed: true },
      evidence,
      r_margin: 1e-9,
      kind: 'risk-understated',
      reason: 'claimed r=0.25 but real r=0.500',
    });
  });
  it('optimistic-not-allowed (checked before risk-understated) with its reason', () => {
    const pr = file(baseClaim(), dec({ r: 0.5, opt: false, t: 2 }))!;
    expect(pr.kind).toBe('optimistic-not-allowed');
    expect(pr.reason).toBe('optimistic path not allowed at real r=0.500 (t=2)');
    expect(pr.decision).toEqual({ releaseGuardianShare: true, r: 0.5, optimisticAllowed: false });
  });
  it('policy-denied (checked first among decision kinds): reasons joined with "; ", fallback "not compliant"', () => {
    expect(file(baseClaim(), dec({ rgs: false, opt: false, reasons: ['a', 'b'] }))!.reason).toBe('Policy VM denied the action: a; b');
    const pr = file(baseClaim(), dec({ rgs: false, reasons: [] }))!;
    expect(pr.kind).toBe('policy-denied');
    expect(pr.reason).toBe('Policy VM denied the action: not compliant');
  });
  it('irreversible wins over everything: via the claim OR via the PCActn, each on its own', () => {
    const expected = 'irreversible action took the optimistic path';
    const viaClaim = file(baseClaim({ reversibility_class: IRREVERSIBLE_CLASS }), dec({ rgs: false }))!;
    expect(viaClaim.kind).toBe('irreversible');
    expect(viaClaim.reason).toBe(expected);
    const irrP = actn('revoke_session', IRREVERSIBLE_CLASS);
    const viaPc = file(baseClaim({ pcactn_digest: pcactnDigest(irrP) }), dec({ rgs: false }), {}, irrP)!;
    expect(viaPc.kind).toBe('irreversible');
    expect(viaPc.reason).toBe(expected);
    // a PCActn with no action at all does not throw (optional chaining) and falls through to the decision
    const noAction = { ...p } as Record<string, unknown>;
    delete noAction.action;
    const na = noAction as unknown as PCActn;
    const out = file(baseClaim({ pcactn_digest: pcactnDigest(na) }), dec({ rgs: false }), {}, na)!;
    expect(out.kind).toBe('policy-denied');
  });
  it('rMargin: finite values are clamped at >= 0; non-finite falls back to 1e-9', () => {
    expect(file(baseClaim(), dec({ r: 0.5 }), { rMargin: -5 })!.r_margin).toBe(0);
    expect(file(baseClaim(), dec({ r: 0.5 }), { rMargin: 0.125 })!.r_margin).toBe(0.125);
    expect(file(baseClaim(), dec({ r: 0.5 }), { rMargin: Number.NaN })!.r_margin).toBe(1e-9);
    expect(file(baseClaim(), dec({ r: 0.5 }))!.r_margin).toBe(1e-9);
  });
});

describe('verifyFraudProof', () => {
  const p = actn();
  const claim = open(p, 0.25);
  const snap = snapFor(p);
  const proofFor = (d: PolicyDecision, over: Record<string, unknown> = {}): FraudProof =>
    ({
      pcactn_digest: claim.pcactn_digest,
      bond_ref: claim.bond_ref,
      claimed_r: claim.claimed_r,
      kind: 'risk-understated',
      decision: summaryOf(d),
      evidence: {},
      r_margin: 1e-9,
      reason: 'x',
      ...over,
    }) as FraudProof;
  /** Run verify with `decide` returning `d` on the recomputation. */
  const ver = (d: PolicyDecision, proof: FraudProof, cl: BondedClaim = claim, sn: DecideInput = snap) => {
    vi.mocked(decide).mockReturnValueOnce(d);
    return verifyFraudProof(cl, proof, GRANT, sn);
  };
  const NOT = (reason: string) => ({ fraudulent: false, reason });
  const FRAUD = (reason: string) => ({ fraudulent: true, slashBondRef: 'bond-1', reason });

  it('malformed proof / mismatched digest / mismatched bond / missing snapshot', () => {
    expect(verifyFraudProof(claim, null as never, GRANT, snap)).toEqual(NOT('malformed fraud proof'));
    expect(verifyFraudProof(claim, 'p' as never, GRANT, snap)).toEqual(NOT('malformed fraud proof'));
    expect(verifyFraudProof(claim, proofFor(dec(), { pcactn_digest: 'zz' }), GRANT, snap)).toEqual(NOT('fraud proof targets a different PCActn than the claim'));
    expect(verifyFraudProof(claim, proofFor(dec(), { bond_ref: 'zz' }), GRANT, snap)).toEqual(NOT('fraud proof names a different bond than the claim'));
    const msg = 'no frozen open-time snapshot supplied; cannot judge the claim';
    expect(verifyFraudProof(claim, proofFor(dec()), GRANT, undefined as never)).toEqual(NOT(msg));
    expect(verifyFraudProof(claim, proofFor(dec()), GRANT, null as never)).toEqual(NOT(msg));
    expect(verifyFraudProof(claim, proofFor(dec()), GRANT, 'snap' as never)).toEqual(NOT(msg));
  });
  it('the asserted decision must match the recomputation: each of the three fields on its own, 1e-9 inclusive', () => {
    const real = dec({ rgs: true, r: 0.5, opt: true });
    const mismatch = NOT('proof decision does not match an independent recomputation');
    expect(ver(real, proofFor(dec({ rgs: false, r: 0.5, opt: true })))).toEqual(mismatch);
    expect(ver(real, proofFor(dec({ rgs: true, r: 0.5, opt: false })))).toEqual(mismatch);
    expect(ver(real, proofFor(dec({ rgs: true, r: 0.5 + 1e-6, opt: true })))).toEqual(mismatch);
    expect(ver(real, proofFor(dec({ rgs: true, r: 0.5 - 1e-6, opt: true })))).toEqual(mismatch);
    // |diff| == 1e-9 exactly is tolerated (strict >)
    const zero = dec({ r: 0 });
    expect(ver(zero, proofFor(dec({ r: 1e-9 })), claim).reason).not.toBe(mismatch.reason);
  });
  it('compliant under recomputation: bond stands', () => {
    expect(ver(dec({ r: 0.25 }), proofFor(dec({ r: 0.25 })))).toEqual(NOT('claim is compliant under independent recomputation; bond stands'));
  });
  it('risk understated: reason, strict boundary at claimed + margin, margin clamped >= 0 and NaN -> 1e-9', () => {
    expect(ver(dec({ r: 0.5 }), proofFor(dec({ r: 0.5 })))).toEqual(FRAUD('risk understated: claimed 0.25, real 0.500'));
    const exact = ver(dec({ r: 0.75 }), proofFor(dec({ r: 0.75 }), { r_margin: 0.5 }));
    expect(exact.fraudulent).toBe(false); // r == claimed + margin
    expect(ver(dec({ r: 0.76 }), proofFor(dec({ r: 0.76 }), { r_margin: 0.5 })).fraudulent).toBe(true);
    // negative margin is clamped to 0: r == claimed is compliant (a negative margin would flag it)
    expect(ver(dec({ r: 0.25 }), proofFor(dec({ r: 0.25 }), { r_margin: -0.5 })).fraudulent).toBe(false);
    // r just inside the default 1e-9 tolerance (also when margin is non-finite)
    expect(ver(dec({ r: 0.25 + 5e-10 }), proofFor(dec({ r: 0.25 + 5e-10 }), { r_margin: Number.NaN })).fraudulent).toBe(false);
    expect(ver(dec({ r: 0.25 + 5e-9 }), proofFor(dec({ r: 0.25 + 5e-9 }), { r_margin: Number.NaN })).fraudulent).toBe(true);
    // a margin of exactly claimed-r leaves room: r == claimed - margin is certainly compliant
    expect(ver(dec({ r: 0.2 }), proofFor(dec({ r: 0.2 }), { r_margin: 0.1 })).fraudulent).toBe(false);
  });
  it('optimistic path not allowed (r within claim) and policy denial, with their reasons', () => {
    expect(ver(dec({ r: 0.1, opt: false }), proofFor(dec({ r: 0.1, opt: false })))).toEqual(FRAUD('optimistic path not allowed at real r=0.100'));
    expect(ver(dec({ rgs: false, reasons: ['x', 'y'] }), proofFor(dec({ rgs: false })))).toEqual(FRAUD('Policy VM denies the action: x; y'));
    expect(ver(dec({ rgs: false, opt: false, reasons: [] }), proofFor(dec({ rgs: false, opt: false })))).toEqual(FRAUD('Policy VM denies the action: not compliant'));
    // policy denial is judged before the optimistic gate; the gate before the risk comparison
    expect(ver(dec({ rgs: false, opt: false, r: 0.9, reasons: ['d'] }), proofFor(dec({ rgs: false, opt: false, r: 0.9 }))).reason).toBe('Policy VM denies the action: d');
    expect(ver(dec({ opt: false, r: 0.9 }), proofFor(dec({ opt: false, r: 0.9 }))).reason).toBe('optimistic path not allowed at real r=0.900');
  });
  it('irreversible via the claim OR via the snapshot action, each on its own; a snapshot with no action is fine', () => {
    const irr = 'irreversible action is ineligible for the optimistic path';
    const d = dec({ r: 0.25 });
    expect(ver(d, proofFor(d), { ...claim, reversibility_class: IRREVERSIBLE_CLASS })).toEqual(FRAUD(irr));
    const irrSnap = { ...snap, action: { action: { ...snap.action.action, reversibility_class: IRREVERSIBLE_CLASS } } } as DecideInput;
    expect(ver(d, proofFor(d), claim, irrSnap)).toEqual(FRAUD(irr));
    const noAction = { ...snap, action: undefined } as unknown as DecideInput;
    expect(ver(d, proofFor(d), claim, noAction)).toEqual(NOT('claim is compliant under independent recomputation; bond stands'));
    const noInner = { ...snap, action: {} } as unknown as DecideInput;
    expect(ver(d, proofFor(d), claim, noInner)).toEqual(NOT('claim is compliant under independent recomputation; bond stands'));
    // a reversible claim and action are not irreversible
    expect(ver(d, proofFor(d)).fraudulent).toBe(false);
  });
  it('is total: a throwing decide becomes a non-fraud verdict naming the error ("unknown" for a non-Error)', () => {
    vi.mocked(decide).mockImplementationOnce(() => {
      throw new Error('vm exploded');
    });
    expect(verifyFraudProof(claim, proofFor(dec()), GRANT, snap)).toEqual(NOT('fraud-proof verification error: vm exploded'));
    vi.mocked(decide).mockImplementationOnce(() => {
      throw 'str';
    });
    expect(verifyFraudProof(claim, proofFor(dec()), GRANT, snap)).toEqual(NOT('fraud-proof verification error: unknown'));
  });
  it('replays the frozen snapshot under the VERIFIER grant', () => {
    vi.mocked(decide).mockReturnValueOnce(dec({ r: 0.25 }));
    verifyFraudProof(claim, proofFor(dec({ r: 0.25 })), GRANT, snap);
    expect(vi.mocked(decide).mock.calls[0]![0]).toEqual({ ...snap, grant: GRANT });
  });
});

// ---- dispute adjudication -------------------------------------------------------------------------------------

/** A Policy VM stand-in driven by the snapshot's risk fields: r = blastRadius; optimistic needs sd < .5 and a non-irreversible class; release needs reversibility > 0. */
const riskDecide = (di: DecideInput): PolicyDecision => {
  const cls = di.caveatContext?.reversibilityClass ?? di.action?.action?.reversibility_class;
  return dec({ r: di.risk?.blastRadius ?? 0, opt: (di.risk?.semanticDistance ?? 0) < 0.5 && cls !== 'irreversible', rgs: (di.risk?.reversibility ?? 1) > 0 });
};
const WORST = { releaseGuardianShare: false, r: 1, optimisticAllowed: false };

describe('adjudicateDispute', () => {
  const p = actn();
  const claim = open(p, 0.1);
  const snap = snapFor(p, { blastRadius: 0.05 });
  const dispute = (input: DisputableInput | string = 'blastRadius', over: Record<string, unknown> = {}) => ({ pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, input: input as DisputableInput, ...over });
  const numOracle = (value: number | undefined, over: Partial<OracleResolution> = {}): ObjectiveOracle => ({ resolve: (input) => ({ input, valid: true, value, ...over }) });
  const run = (over: Record<string, unknown> = {}) => {
    vi.mocked(decide).mockImplementation(riskDecide);
    return adjudicateDispute({ claim, dispute: dispute() as never, grant: GRANT, openSnapshot: snap, oracle: numOracle(0.9), ...over } as never);
  };
  const indet = (input: DisputableInput, reason: string, extra: Record<string, unknown> = {}) => ({
    outcome: 'indeterminate',
    fraudulent: false,
    slashCounterBond: false,
    input,
    agentValue: undefined,
    oracleValue: undefined,
    baseline: WORST,
    adjudicated: WORST,
    reason,
    ...extra,
  });

  it('agent-fraud: the real r exceeds the claim (full verdict)', () => {
    expect(run()).toEqual({
      outcome: 'agent-fraud',
      fraudulent: true,
      slashBondRef: 'bond-1',
      slashCounterBond: false,
      input: 'blastRadius',
      agentValue: 0.05,
      oracleValue: 0.9,
      baseline: { releaseGuardianShare: true, r: 0.05, optimisticAllowed: true },
      adjudicated: { releaseGuardianShare: true, r: 0.9, optimisticAllowed: true },
      reason: 'understated blastRadius: agent relied on 0.05, oracle says 0.9 — the real r=0.900 exceeds the claimed r=0.1',
    });
  });
  it('agent-fraud via the optimistic gate: "higher threshold" reason', () => {
    const v = run({ dispute: dispute('semanticDistance'), oracle: numOracle(0.7) });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.reason).toBe('understated semanticDistance: agent relied on 0, oracle says 0.7 — the optimistic path is not allowed (higher threshold) at r=0.050');
  });
  it('agent-fraud via policy denial: "denies the action" reason (checked before the gate)', () => {
    const v = run({ dispute: dispute('reversibility'), oracle: numOracle(0) });
    expect(v.reason).toBe('understated reversibility: agent relied on 1, oracle says 0 — the Policy VM denies the action');
  });
  it('claim-upheld: a frivolous dispute (counter-bond marked)', () => {
    expect(run({ oracle: numOracle(0.1) })).toEqual({
      outcome: 'claim-upheld',
      fraudulent: false,
      slashCounterBond: true,
      input: 'blastRadius',
      agentValue: 0.05,
      oracleValue: 0.1,
      baseline: { releaseGuardianShare: true, r: 0.05, optimisticAllowed: true },
      adjudicated: { releaseGuardianShare: true, r: 0.1, optimisticAllowed: true },
      reason: "the objective oracle upholds the agent's blastRadius (0.1); fast-path admission survives — the dispute is frivolous",
    });
  });
  it('margin: r == claimed + margin is upheld; negative margin clamps to 0; NaN margin -> 1e-9', () => {
    const c = open(p, 0.25);
    expect(run({ claim: c, dispute: dispute('blastRadius', { pcactn_digest: c.pcactn_digest }), oracle: numOracle(0.75), rMargin: 0.5 }).outcome).toBe('claim-upheld');
    expect(run({ claim: c, dispute: dispute('blastRadius', { pcactn_digest: c.pcactn_digest }), oracle: numOracle(0.76), rMargin: 0.5 }).outcome).toBe('agent-fraud');
    expect(run({ claim: c, dispute: dispute('blastRadius', { pcactn_digest: c.pcactn_digest }), oracle: numOracle(0.25), rMargin: -0.5 }).outcome).toBe('claim-upheld');
    expect(run({ claim: c, dispute: dispute('blastRadius', { pcactn_digest: c.pcactn_digest }), oracle: numOracle(0.25 + 5e-10), rMargin: Number.NaN }).outcome).toBe('claim-upheld');
    expect(run({ claim: c, dispute: dispute('blastRadius', { pcactn_digest: c.pcactn_digest }), oracle: numOracle(0.25 + 5e-9), rMargin: Number.NaN }).outcome).toBe('agent-fraud');
  });
  it('malformed dispute / unknown input / bound to a different claim / missing snapshot / missing oracle: indeterminate with exact reasons', () => {
    expect(run({ dispute: null })).toEqual(indet('reversibility_class', 'malformed dispute'));
    expect(run({ dispute: 'x' })).toEqual(indet('reversibility_class', 'malformed dispute'));
    expect(run({ dispute: dispute('bogus') })).toEqual(indet('reversibility_class', 'unknown disputed input: bogus'));
    expect(run({ dispute: dispute('blastRadius', { pcactn_digest: 'zz' }) })).toEqual(indet('blastRadius', 'dispute targets a different PCActn than the claim'));
    expect(run({ dispute: dispute('blastRadius', { bond_ref: 'zz' }) })).toEqual(indet('blastRadius', 'dispute names a different bond than the claim'));
    for (const s of [undefined, null, 'snap']) expect(run({ openSnapshot: s })).toEqual(indet('blastRadius', 'no frozen open-time snapshot supplied; cannot adjudicate'));
    for (const o of [undefined, null, {}, { resolve: 5 }]) expect(run({ oracle: o })).toEqual(indet('blastRadius', 'no objective oracle supplied'));
  });
  it('every one of the four disputable inputs is accepted (reaches the binding checks)', () => {
    for (const input of ['reversibility_class', 'reversibility', 'blastRadius', 'semanticDistance'] as const) {
      expect(run({ dispute: dispute(input, { bond_ref: 'zz' }) })).toEqual(indet(input, 'dispute names a different bond than the claim'));
    }
  });
  it('an oracle that cannot resolve: reason (with or without the oracle reason), baseline + agentValue kept', () => {
    const baseline = { releaseGuardianShare: true, r: 0.05, optimisticAllowed: true };
    const kept = { baseline, agentValue: 0.05 };
    expect(run({ oracle: { resolve: () => undefined } })).toEqual(indet('blastRadius', 'objective oracle could not authoritatively resolve blastRadius', kept));
    expect(run({ oracle: { resolve: () => ({ input: 'blastRadius', valid: false, reason: 'no data' }) } })).toEqual(
      indet('blastRadius', 'objective oracle could not authoritatively resolve blastRadius: no data', kept),
    );
    expect(run({ oracle: { resolve: () => ({ input: 'blastRadius', valid: false }) } })).toEqual(indet('blastRadius', 'objective oracle could not authoritatively resolve blastRadius', kept));
    // answers a different input -> same refusal
    expect(run({ oracle: { resolve: () => ({ input: 'reversibility', valid: true, value: 0.9 }) } })).toEqual(
      indet('blastRadius', 'objective oracle could not authoritatively resolve blastRadius', kept),
    );
  });
  it('total: an oracle that throws, or a malformed resolution, yields an error-naming indeterminate on the right input', () => {
    const e = (r: string, input: DisputableInput = 'blastRadius') => indet(input, `dispute adjudication error (fail closed): ${r}`);
    expect(run({ oracle: { resolve: () => { throw new Error('oracle down'); } } })).toEqual(e('oracle down'));
    expect(run({ oracle: { resolve: () => { throw 'str'; } } })).toEqual(e('unknown'));
    expect(run({ oracle: numOracle(undefined) })).toEqual(e('oracle blastRadius resolution carries no finite value'));
    expect(run({ oracle: numOracle(Number.NaN) })).toEqual(e('oracle blastRadius resolution carries no finite value'));
    const clsOracle = (cls?: string): ObjectiveOracle => ({ resolve: (input) => ({ input, valid: true, class: cls }) });
    const cd = dispute('reversibility_class');
    expect(run({ dispute: cd, oracle: clsOracle(undefined) })).toEqual(e('oracle reversibility_class resolution carries no class', 'reversibility_class'));
    expect(run({ dispute: cd, oracle: clsOracle('') })).toEqual(e('oracle reversibility_class resolution carries no class', 'reversibility_class'));
    expect(run({ dispute: cd, oracle: { resolve: () => ({ input: 'reversibility_class', valid: true, class: 5 }) } })).toEqual(
      e('oracle reversibility_class resolution carries no class', 'reversibility_class'),
    );
  });
  it('the error path falls back to reversibility_class when the dispute input cannot be read twice', () => {
    let reads = 0;
    const flaky = {
      pcactn_digest: claim.pcactn_digest,
      bond_ref: claim.bond_ref,
      get input(): DisputableInput {
        reads += 1;
        if (reads === 1) throw new Error('first read fails');
        return undefined as never;
      },
    };
    expect(run({ dispute: flaky })).toEqual(indet('reversibility_class', 'dispute adjudication error (fail closed): first read fails'));
  });

  describe('substitution into a COPY of the frozen snapshot', () => {
    const callArgs = () => vi.mocked(decide).mock.calls.map((c) => c[0]);
    it('numeric input: replaces only that risk field; other fields and the original are untouched', () => {
      const s = snapFor(p, { blastRadius: 0.05, taint: 0.3 });
      const before = JSON.stringify(s);
      run({ openSnapshot: s, oracle: numOracle(0.9) });
      const [base, adj] = callArgs();
      expect(base!.risk).toEqual(s.risk);
      expect(adj!.risk).toEqual({ ...s.risk, blastRadius: 0.9 });
      expect(adj!.grant).toBe(GRANT);
      expect(JSON.stringify(s)).toBe(before);
      expect('caveatContext' in adj!).toBe(false);
    });
    it('blastRadius also overrides caveatContext.blastRadius, but only when the snapshot set one', () => {
      const withCtx = { ...snap, caveatContext: { blastRadius: 0.3, other: 'k' } } as unknown as DecideInput;
      run({ openSnapshot: withCtx, oracle: numOracle(0.9) });
      expect(callArgs()[1]!.caveatContext).toEqual({ blastRadius: 0.9, other: 'k' });
      vi.mocked(decide).mockClear();
      const ctxNoBlast = { ...snap, caveatContext: { other: 'k' } } as unknown as DecideInput;
      run({ openSnapshot: ctxNoBlast, oracle: numOracle(0.9) });
      expect(callArgs()[1]!.caveatContext).toEqual({ other: 'k' });
      expect('blastRadius' in (callArgs()[1]!.caveatContext as object)).toBe(false);
      vi.mocked(decide).mockClear();
      run({ openSnapshot: snap, oracle: numOracle(0.9) });
      expect('caveatContext' in callArgs()[1]!).toBe(false);
      vi.mocked(decide).mockClear();
      run({ openSnapshot: withCtx, dispute: dispute('reversibility'), oracle: numOracle(0.5) });
      expect(callArgs()[1]!.caveatContext).toEqual({ blastRadius: 0.3, other: 'k' }); // a different input leaves it alone
    });
    it('a snapshot with no risk block is handled (agentValue undefined, risk created)', () => {
      const noRisk = { ...snap, risk: undefined } as unknown as DecideInput;
      const v = run({ openSnapshot: noRisk, oracle: numOracle(0.9) });
      expect(v.agentValue).toBeUndefined();
      expect(v.outcome).toBe('agent-fraud');
      expect(callArgs()[1]!.risk).toEqual({ blastRadius: 0.9 });
    });
    it('reversibility_class: replaces the action class; mirrors into caveatContext only when it set one; agentValue prefers the caveat class', () => {
      const cls = (c: string): ObjectiveOracle => ({ resolve: (input) => ({ input, valid: true, class: c }) });
      const d = dispute('reversibility_class');
      const plain = run({ openSnapshot: snap, dispute: d, oracle: cls('irreversible') });
      expect(plain.agentValue).toBe('reversible');
      expect(plain.oracleValue).toBe('irreversible');
      expect(callArgs()[1]!.action.action.reversibility_class).toBe('irreversible');
      expect(callArgs()[1]!.action.action.verb).toBe('revoke_session'); // sibling fields kept
      expect('caveatContext' in callArgs()[1]!).toBe(false);
      vi.mocked(decide).mockClear();
      const withCtx = { ...snap, caveatContext: { reversibilityClass: 'cavclass', blastRadius: 0.2 } } as unknown as DecideInput;
      const v = run({ openSnapshot: withCtx, dispute: d, oracle: cls('irreversible') });
      expect(v.agentValue).toBe('cavclass');
      expect(callArgs()[1]!.caveatContext).toEqual({ reversibilityClass: 'irreversible', blastRadius: 0.2 });
      expect(callArgs()[1]!.action.action.reversibility_class).toBe('irreversible');
      vi.mocked(decide).mockClear();
      const ctxOther = { ...snap, caveatContext: { blastRadius: 0.2 } } as unknown as DecideInput;
      run({ openSnapshot: ctxOther, dispute: d, oracle: cls('irreversible') });
      expect(callArgs()[1]!.caveatContext).toEqual({ blastRadius: 0.2 });
    });
    it('a snapshot with no action at all: agentValue undefined, the class is still substituted', () => {
      const noAction = { ...snap, action: undefined } as unknown as DecideInput;
      const v = run({ openSnapshot: noAction, dispute: dispute('reversibility_class'), oracle: { resolve: (input: DisputableInput) => ({ input, valid: true, class: 'irreversible' }) } });
      expect(v.agentValue).toBeUndefined();
      expect(callArgs()[1]!.action).toEqual({ action: { reversibility_class: 'irreversible' } });
      vi.mocked(decide).mockClear();
      const noInner = { ...snap, action: {} } as unknown as DecideInput;
      const v2 = run({ openSnapshot: noInner, dispute: dispute('reversibility_class'), oracle: { resolve: (input: DisputableInput) => ({ input, valid: true, class: 'irreversible' }) } });
      expect(v2.agentValue).toBeUndefined();
      expect(v2.outcome).toBe('agent-fraud'); // not an indeterminate from a thrown TypeError
    });
  });
});

describe('adjudicateDisputeGame', () => {
  const p = actn();
  const claim = open(p, 0.1);
  const snap = snapFor(p, { blastRadius: 0.05 });
  const steps: DisputableInput[] = ['semanticDistance', 'blastRadius', 'reversibility'];
  const defender = [{ value: 0.1 }, { value: 0.05 }, { value: 1 }];
  const mkGame = (over: Record<string, unknown> = {}): DisputeGame =>
    ({ pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, steps, defender, challenger: [{ value: 0.1 }, { value: 0.9 }, { value: 1 }], ...over }) as DisputeGame;
  const oracleOf = (value: number | undefined) => {
    const resolve = vi.fn((input: DisputableInput, _s: DecideInput): OracleResolution => ({ input, valid: true, value }));
    return { oracle: { resolve } as ObjectiveOracle, resolve };
  };
  const play = (over: Record<string, unknown> = {}, o: ObjectiveOracle = oracleOf(0.9).oracle) => {
    vi.mocked(decide).mockImplementation(riskDecide);
    return adjudicateDisputeGame({ claim, game: mkGame(), grant: GRANT, openSnapshot: snap, oracle: o, ...over } as never);
  };
  const failShape = (reason: string, input: DisputableInput = 'reversibility_class') => ({
    verdict: { outcome: 'indeterminate', fraudulent: false, slashCounterBond: false, input, agentValue: undefined, oracleValue: undefined, baseline: WORST, adjudicated: WORST, reason },
    converged: false,
    contestedStep: -1,
    transcript: [],
    rounds: 0,
  });

  it('bisects to the middle step, folds the agreed prefix into the oracle snapshot, consults the oracle once', () => {
    const { oracle, resolve } = oracleOf(0.9);
    const r = play({}, oracle);
    expect(r.converged).toBe(true);
    expect(r.contestedStep).toBe(1);
    expect(r.contestedInput).toBe('blastRadius');
    expect(r.transcript).toEqual([
      { lo: 0, hi: 3, mid: 1, agreedAtMid: true },
      { lo: 1, hi: 3, mid: 2, agreedAtMid: false },
    ]);
    expect(r.rounds).toBe(2);
    expect(r.verdict.outcome).toBe('agent-fraud');
    expect(r.verdict.slashBondRef).toBe('bond-1');
    expect(resolve).toHaveBeenCalledTimes(1);
    const [input, seen] = resolve.mock.calls[0]!;
    expect(input).toBe('blastRadius');
    expect(seen.risk.semanticDistance).toBe(0.1); // agreed step 0 folded in
    expect(seen.risk.blastRadius).toBe(0.05); // the contested step itself is NOT folded in
    expect(seen.grant).toBe(GRANT);
  });
  it('contested first step / last step transcripts', () => {
    const first = play({ game: mkGame({ challenger: [{ value: 0.9 }, { value: 0.05 }, { value: 1 }] }) }, oracleOf(0.9).oracle);
    expect(first.contestedStep).toBe(0);
    expect(first.contestedInput).toBe('semanticDistance');
    expect(first.transcript).toEqual([{ lo: 0, hi: 3, mid: 1, agreedAtMid: false }]);
    expect(first.verdict.outcome).toBe('agent-fraud');
    const last = play({ game: mkGame({ challenger: [{ value: 0.1 }, { value: 0.05 }, { value: 0 }] }) }, oracleOf(0).oracle);
    expect(last.contestedStep).toBe(2);
    expect(last.contestedInput).toBe('reversibility');
    expect(last.transcript).toEqual([
      { lo: 0, hi: 3, mid: 1, agreedAtMid: true },
      { lo: 1, hi: 3, mid: 2, agreedAtMid: true },
    ]);
    expect(last.rounds).toBe(2);
  });
  it('a single-step game plays zero rounds and rules on the raw snapshot', () => {
    const { oracle, resolve } = oracleOf(0.9);
    const r = play({ game: mkGame({ steps: ['blastRadius'], defender: [{ value: 0.05 }], challenger: [{ value: 0.9 }] }) }, oracle);
    expect(r.converged).toBe(true);
    expect(r.rounds).toBe(0);
    expect(r.transcript).toEqual([]);
    expect(r.contestedStep).toBe(0);
    expect(resolve.mock.calls[0]![1].risk).toEqual({ ...snap.risk });
  });
  it('an honest defender: claim-upheld', () => {
    const r = play({}, oracleOf(0.05).oracle);
    expect(r.converged).toBe(true);
    expect(r.verdict.outcome).toBe('claim-upheld');
    expect(r.verdict.slashCounterBond).toBe(true);
  });
  it('rMargin is forwarded (and clamped / defaulted) to the one-shot referee', () => {
    const c = open(p, 0.25);
    const g = mkGame({ pcactn_digest: c.pcactn_digest, defender: [{ value: 0.1 }, { value: 0.05 }, { value: 1 }], challenger: [{ value: 0.1 }, { value: 0.75 }, { value: 1 }] });
    // challenger final r = 0.75 == claimed + margin -> would be ADMITTED -> no genuine dispute; so use the oracle for the contested step only
    const upheld = play({ claim: c, game: mkGame({ pcactn_digest: c.pcactn_digest, challenger: [{ value: 0.1 }, { value: 0.9 }, { value: 1 }] }), rMargin: 0.5 }, oracleOf(0.75).oracle);
    expect(upheld.verdict.outcome).toBe('claim-upheld'); // 0.75 <= 0.25 + 0.5
    const fraud = play({ claim: c, game: mkGame({ pcactn_digest: c.pcactn_digest, challenger: [{ value: 0.1 }, { value: 0.9 }, { value: 1 }] }), rMargin: 0.5 }, oracleOf(0.76).oracle);
    expect(fraud.verdict.outcome).toBe('agent-fraud');
    const neg = play({ claim: c, game: mkGame({ pcactn_digest: c.pcactn_digest, challenger: [{ value: 0.1 }, { value: 0.9 }, { value: 1 }] }), rMargin: -0.5 }, oracleOf(0.25).oracle);
    expect(neg.verdict.outcome).toBe('claim-upheld');
    void g;
  });

  describe('fail closed', () => {
    it('malformed / mis-bound games', () => {
      expect(play({ game: null })).toEqual(failShape('malformed dispute game'));
      expect(play({ game: 'g' })).toEqual(failShape('malformed dispute game'));
      expect(play({ game: mkGame({ pcactn_digest: 'zz' }) })).toEqual(failShape('dispute game targets a different PCActn than the claim', 'semanticDistance'));
      expect(play({ game: mkGame({ bond_ref: 'zz' }) })).toEqual(failShape('dispute game names a different bond than the claim', 'semanticDistance'));
    });
    it('step list problems (and the reported input falls back to reversibility_class unless steps[0] is disputable)', () => {
      expect(play({ game: mkGame({ steps: [] }) })).toEqual(failShape('dispute game has no steps'));
      expect(play({ game: mkGame({ steps: 'nope' }) })).toEqual(failShape('dispute game has no steps'));
      expect(play({ game: mkGame({ steps: undefined }) })).toEqual(failShape('dispute game has no steps'));
      expect(play({ game: mkGame({ steps: ['bogus'], defender: [{}], challenger: [{}] }) })).toEqual(failShape('unknown disputed input: bogus'));
      expect(play({ game: mkGame({ steps: ['blastRadius', 'bogus'], defender: [{}, {}], challenger: [{}, {}] }) })).toEqual(failShape('unknown disputed input: bogus', 'blastRadius'));
      for (const ok of ['reversibility_class', 'reversibility', 'blastRadius', 'semanticDistance'] as const) {
        expect(play({ game: mkGame({ steps: [ok], defender: [], challenger: [] }) })).toEqual(failShape('party assertions do not cover every step', ok));
      }
    });
    it('both parties must assert every step', () => {
      const msg = 'party assertions do not cover every step';
      expect(play({ game: mkGame({ defender: undefined }) })).toEqual(failShape(msg, 'semanticDistance'));
      expect(play({ game: mkGame({ challenger: undefined }) })).toEqual(failShape(msg, 'semanticDistance'));
      expect(play({ game: mkGame({ defender: defender.slice(1) }) })).toEqual(failShape(msg, 'semanticDistance'));
      expect(play({ game: mkGame({ challenger: [{ value: 0.1 }] }) })).toEqual(failShape(msg, 'semanticDistance'));
      expect(play({ game: mkGame({ defender: [...defender, { value: 1 }] }) })).toEqual(failShape(msg, 'semanticDistance'));
    });
    it('missing snapshot / oracle', () => {
      for (const s of [undefined, null, 'snap']) expect(play({ openSnapshot: s })).toEqual(failShape('no frozen open-time snapshot supplied; cannot adjudicate', 'semanticDistance'));
      for (const o of [undefined, null, {}, { resolve: 1 }]) expect(play({ oracle: o })).toEqual(failShape('no objective oracle supplied', 'semanticDistance'));
    });
    it('no genuine dispute: the defender must still admit and the challenger must not', () => {
      expect(play({ game: mkGame({ defender: [{ value: 0.9 }, { value: 0.05 }, { value: 1 }] }) })).toEqual(
        failShape('defender does not defend the fast-path admission; nothing to adjudicate', 'semanticDistance'),
      );
      expect(play({ game: mkGame({ challenger: defender }) })).toEqual(failShape('the parties do not disagree on admission; no genuine dispute to bisect', 'semanticDistance'));
    });
    it('identical committed traces are refused even if the (stateful) VM disagrees with itself', () => {
      vi.mocked(decide).mockReset();
      vi.mocked(decide).mockReturnValueOnce(dec({ r: 0 })).mockReturnValueOnce(dec({ opt: false }));
      const r = adjudicateDisputeGame({ claim, game: mkGame({ challenger: defender }), grant: GRANT, openSnapshot: snap, oracle: oracleOf(0.9).oracle });
      expect(r).toEqual(failShape('the parties committed identical traces; no contested step to bisect', 'semanticDistance'));
    });
    it('a trace with a hole is "shorter than its step list"; a throwing VM is reported (Error text / unknown)', () => {
      const holey = [{ value: 0.1 }, undefined, { value: 1 }] as never;
      expect(play({ game: mkGame({ defender: holey }) })).toEqual(
        failShape('dispute game adjudication error (fail closed): dispute game trace is shorter than its step list', 'semanticDistance'),
      );
      expect(play({ game: mkGame({ challenger: holey }) })).toEqual(
        failShape('dispute game adjudication error (fail closed): dispute game trace is shorter than its step list', 'semanticDistance'),
      );
      vi.mocked(decide).mockReset();
      vi.mocked(decide).mockImplementation(() => {
        throw new Error('vm down');
      });
      expect(adjudicateDisputeGame({ claim, game: mkGame(), grant: GRANT, openSnapshot: snap, oracle: oracleOf(0.9).oracle })).toEqual(
        failShape('dispute game adjudication error (fail closed): vm down', 'semanticDistance'),
      );
      vi.mocked(decide).mockImplementation(() => {
        throw 'str';
      });
      expect(adjudicateDisputeGame({ claim, game: mkGame(), grant: GRANT, openSnapshot: snap, oracle: oracleOf(0.9).oracle })).toEqual(
        failShape('dispute game adjudication error (fail closed): unknown', 'semanticDistance'),
      );
    });
    it('a malformed assertion (non-finite value) fails closed', () => {
      expect(play({ game: mkGame({ challenger: [{ value: 0.1 }, { value: Number.NaN }, { value: 1 }] }) })).toEqual(
        failShape('dispute game adjudication error (fail closed): oracle blastRadius resolution carries no finite value', 'semanticDistance'),
      );
    });
    it('an oracle that cannot resolve the converged step fails closed via the one-shot referee', () => {
      const r = play({}, { resolve: () => ({ input: 'blastRadius', valid: false, reason: 'no data' }) });
      expect(r.converged).toBe(true);
      expect(r.verdict.outcome).toBe('indeterminate');
      expect(r.verdict.reason).toBe('objective oracle could not authoritatively resolve blastRadius: no data');
    });
  });

  describe('which assertion pairs count as "the same" (first divergence)', () => {
    const cls = (extra: Record<string, unknown>) => ({ class: 'c', ...extra });
    const contestedFor = (a0: Record<string, unknown>, b0: Record<string, unknown>) => {
      const r = play(
        {
          game: {
            pcactn_digest: claim.pcactn_digest,
            bond_ref: claim.bond_ref,
            steps: ['reversibility_class', 'reversibility_class'],
            defender: [a0, { class: 'reversible' }],
            challenger: [b0, { class: 'irreversible' }],
          },
        },
        { resolve: (input: DisputableInput) => ({ input, valid: true, class: 'irreversible' }) },
      );
      return r.contestedStep;
    };
    it('equal class and both values absent -> agree; equal numbers agree', () => {
      expect(contestedFor(cls({}), cls({}))).toBe(1);
      expect(contestedFor(cls({ value: 5 }), cls({ value: 5 }))).toBe(1);
    });
    it('different class, different numbers, or one side missing a value -> diverge at the step', () => {
      expect(contestedFor(cls({}), { class: 'd' })).toBe(0);
      expect(contestedFor(cls({ value: 5 }), cls({ value: 6 }))).toBe(0);
      expect(contestedFor(cls({}), cls({ value: 5 }))).toBe(0);
      expect(contestedFor(cls({ value: 5 }), cls({}))).toBe(0);
    });
    it('non-number values are never "equal" (even identical strings / nulls)', () => {
      expect(contestedFor(cls({ value: 'x' }), cls({ value: 'x' }))).toBe(0);
      expect(contestedFor(cls({ value: null }), cls({ value: null }))).toBe(0);
    });
  });
});

describe('freezeOpenSnapshot', () => {
  it('returns a deep, independent, deeply-frozen JSON clone', () => {
    const p = actn();
    const input = snapFor(p, { blastRadius: 0.2 });
    const before = JSON.stringify(input);
    const out = freezeOpenSnapshot(input);
    expect(out).not.toBe(input);
    expect(JSON.stringify(out)).toBe(before);
    const walk = (o: unknown, path: string): void => {
      if (o && typeof o === 'object') {
        expect(Object.isFrozen(o), `frozen at ${path}`).toBe(true);
        for (const [k, v] of Object.entries(o as Record<string, unknown>)) walk(v, `${path}.${k}`);
      }
    };
    walk(out, '$');
    expect(Object.isFrozen(out.risk)).toBe(true);
    expect(Array.isArray(out.chain) && out.chain.length > 0).toBe(true);
    expect(Object.isFrozen(out.chain)).toBe(true);
    expect(Object.isFrozen(out.chain![0])).toBe(true);
    expect(Object.isFrozen(out.action.action)).toBe(true);
    // independent of the source
    expect(Object.isFrozen(input)).toBe(false);
    expect(Object.isFrozen(input.risk)).toBe(false);
    input.risk.blastRadius = 0.9;
    expect(out.risk.blastRadius).toBe(0.2);
    expect(() => {
      'use strict';
      (out.risk as { blastRadius: number }).blastRadius = 1;
    }).toThrow();
  });
});
