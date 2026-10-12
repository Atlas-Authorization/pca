/** Mutation-kill tests for frost-dkg.ts: exact error / reason strings, boundaries, ordering and per-field assertions. */
import { describe, expect, it } from 'vitest';
import { b64u, unb64u } from './hash';
import { L, bytesToScalar, scalarToBytes } from './frost';
import {
  type DkgComplaint,
  type DkgEcho,
  type DkgParticipantState,
  type DkgReceivedShare,
  type DkgRebuttal,
  type DkgRound1Package,
  dkgCheckEchoes,
  dkgEcho,
  dkgFileComplaint,
  dkgFinalize,
  dkgQualifiedSet,
  dkgRebut,
  dkgResolveBlame,
  dkgRound1,
  dkgRound2,
  dkgSignShare,
  dkgTranscriptDigest,
  dkgVerifyComplaint,
  dkgVerifyRound1,
  dkgVerifyShare,
  frostDkgSimulate,
} from './frost-dkg';

const SID = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const SID2 = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);

const thr = (fn: () => unknown, m: string) => {
  let e: unknown;
  try {
    fn();
  } catch (x) {
    e = x;
  }
  expect(e, 'expected a throw').toBeInstanceOf(Error);
  expect((e as Error).message).toBe(m);
};

function ceremony(t: number, n: number, sid = SID, ids?: number[]) {
  const idl = ids ?? Array.from({ length: n }, (_, i) => i + 1);
  const states = idl.map((id) => dkgRound1(id, t, n, sid).state);
  const pkgs = states.map((s) => s.package);
  const shares = states.flatMap((s) => dkgRound2(s, pkgs));
  const st = (id: number) => states.find((s) => s.identifier === id)!;
  const pk = (id: number) => pkgs.find((p) => p.identifier === id)!;
  const inbox = (id: number): DkgReceivedShare[] =>
    shares.filter((s) => s.to === id).map((s) => ({ from: s.from, sessionId: s.sessionId, share: s.share, sig: s.sig }));
  const sh = (from: number, to: number) => shares.find((s) => s.from === from && s.to === to)!;
  return { states, pkgs, shares, st, pk, inbox, sh };
}

const flip = (b: Uint8Array) => {
  const o = Uint8Array.from(b);
  o[0] = o[0]! ^ 1;
  return o;
};

/** An admissible, justified complaint: `accused` signs a VSS-bad share for `accuser`. */
function badComplaint(c: ReturnType<typeof ceremony>, accused: number, accuser: number): DkgComplaint {
  const bad = flip(c.sh(accused, accuser).share);
  return dkgFileComplaint({
    accused,
    accuser,
    receivedShare: bad,
    shareSig: dkgSignShare(c.st(accused), accuser, bad),
    senderCommitments: c.pk(accused).coefficientCommitments,
    sessionId: SID,
  });
}

/** An inadmissible complaint: a valid signature of another share paired with different revealed bytes. */
function fabricatedComplaint(c: ReturnType<typeof ceremony>, accused: number, accuser: number): DkgComplaint {
  return {
    accused,
    accuser,
    sessionId: b64u(SID),
    revealedShare: b64u(scalarToBytes(5n)),
    shareSig: c.sh(accused, accuser).sig,
  };
}

describe('dkgRound1 validation', () => {
  it('identifier must be a positive integer (exact message, 0 and non-integer)', () => {
    const m = 'dkgRound1: identifier must be a positive integer';
    thr(() => dkgRound1(0, 2, 3, SID), m);
    thr(() => dkgRound1(-1, 2, 3, SID), m);
    thr(() => dkgRound1(1.5, 2, 3, SID), m);
    expect(dkgRound1(1, 2, 3, SID).package.identifier).toBe(1);
  });
  it('t / n validation: exact message, each disjunct isolated, t=1 boundary allowed', () => {
    thr(() => dkgRound1(1, 0, 3, SID), 'dkgRound1: need 1 <= t <= n (got t=0, n=3)');
    thr(() => dkgRound1(1, 4, 3, SID), 'dkgRound1: need 1 <= t <= n (got t=4, n=3)');
    thr(() => dkgRound1(1, 1.5, 3, SID), 'dkgRound1: need 1 <= t <= n (got t=1.5, n=3)');
    thr(() => dkgRound1(1, 1, 2.5, SID), 'dkgRound1: need 1 <= t <= n (got t=1, n=2.5)');
    thr(() => dkgRound1(1, 2, 1.5, SID), 'dkgRound1: need 1 <= t <= n (got t=2, n=1.5)');
    expect(dkgRound1(1, 1, 1, SID).package.coefficientCommitments.length).toBe(1);
    expect(dkgRound1(1, 3, 3, SID).package.coefficientCommitments.length).toBe(3);
  });
  it('coefficients length must equal t', () => {
    const one = [scalarToBytes(3n)];
    thr(() => dkgRound1(1, 2, 3, SID, { coefficients: one }), 'dkgRound1: coefficients.length must equal t (2)');
    thr(() => dkgRound1(1, 1, 3, SID, { coefficients: [scalarToBytes(3n), scalarToBytes(4n)] }), 'dkgRound1: coefficients.length must equal t (1)');
    expect(dkgRound1(1, 2, 3, SID, { coefficients: [scalarToBytes(3n), scalarToBytes(4n)] }).state.coefficients.length).toBe(2);
  });
});

describe('dkgSignShare / commit-vector guard', () => {
  it('rejects an empty or non-array commitment vector with the exact message', () => {
    const c = ceremony(2, 3);
    const mk = (cc: unknown): DkgParticipantState => ({ ...c.st(1), package: { ...c.pk(1), coefficientCommitments: cc as string[] } });
    const m = 'dkg: empty commitment vector';
    thr(() => dkgSignShare(mk([]), 2, scalarToBytes(1n)), m);
    thr(() => dkgSignShare(mk(null), 2, scalarToBytes(1n)), m);
    thr(() => dkgSignShare(mk('abc'), 2, scalarToBytes(1n)), m);
    expect(typeof dkgSignShare(c.st(1), 2, scalarToBytes(1n))).toBe('string');
  });
});

describe('dkgVerifyRound1', () => {
  it('rejects a package whose stamped sessionId differs even if the PoP verifies', () => {
    const c = ceremony(2, 3);
    const p = c.pk(1);
    expect(dkgVerifyRound1(1, p, SID)).toBe(true);
    expect(dkgVerifyRound1(1, { ...p, sessionId: b64u(SID2) }, SID)).toBe(false);
  });
  it('rejects empty commitments, wrong id, wrong session', () => {
    const c = ceremony(2, 3);
    expect(dkgVerifyRound1(1, { ...c.pk(1), coefficientCommitments: [] }, SID)).toBe(false);
    expect(dkgVerifyRound1(2, c.pk(1), SID)).toBe(false);
    expect(dkgVerifyRound1(1, c.pk(1), SID2)).toBe(false);
  });
});

describe('dkgRound2 guards', () => {
  it('exact messages', () => {
    const c = ceremony(2, 3);
    thr(() => dkgRound2(c.st(1), [c.pk(1), c.pk(2), c.pk(2)]), 'dkgRound2: duplicate identifiers in round-1 packages');
    thr(() => dkgRound2(c.st(1), [c.pk(2), c.pk(3)]), 'dkgRound2: my own round-1 package is missing');
    thr(() => dkgRound2(c.st(1), [c.pk(1), { ...c.pk(2), sessionId: b64u(SID2) }, c.pk(3)]), 'dkgRound2: participant 2 round-1 package is from a different session');
    const ok = dkgRound2(c.st(1), [c.pk(1), c.pk(2), c.pk(3)]);
    expect(ok.map((s) => s.to)).toEqual([2, 3]);
  });
});

describe('dkgVerifyShare', () => {
  it('verifies at a negative evaluation point (mod normalises negatives)', () => {
    const c = ceremony(2, 3);
    const coeffs = c.st(1).coefficients.map((b) => bytesToScalar(b));
    const share = scalarToBytes(coeffs[0]! + coeffs[1]! * (L - 1n)); // f(-1)
    const sig = dkgSignShare(c.st(1), -1, share);
    expect(dkgVerifyShare({ from: 1, share, sig }, c.pk(1), -1, SID)).toBe(true);
  });
  it('verifies at evaluation point 0 (zero scalar multiplication maps to identity)', () => {
    const c = ceremony(2, 3);
    const share = c.st(1).coefficients[0]!; // f(0) = a0
    const sig = dkgSignShare(c.st(1), 0, share);
    expect(dkgVerifyShare({ from: 1, share, sig }, c.pk(1), 0, SID)).toBe(true);
  });
  it('verifies a zero share when f(x) = 0 (identity left-hand side)', () => {
    const a0 = 123456789n;
    const st = dkgRound1(2, 2, 3, SID, { coefficients: [scalarToBytes(a0), scalarToBytes(L - a0)] }).state; // f(1) = 0
    const zero = new Uint8Array(32);
    const sig = dkgSignShare(st, 1, zero);
    expect(dkgVerifyShare({ from: 2, share: zero, sig }, st.package, 1, SID)).toBe(true);
  });
  it('returns exactly false (not undefined) when the share bytes are non-canonical / wrong length / not a Uint8Array', () => {
    const c = ceremony(2, 3);
    const short = new Uint8Array(31).fill(1);
    expect(dkgVerifyShare({ from: 1, share: short, sig: dkgSignShare(c.st(1), 2, short) }, c.pk(1), 2, SID)).toBe(false);
    const big = new Uint8Array(32).fill(0xff);
    expect(dkgVerifyShare({ from: 1, share: big, sig: dkgSignShare(c.st(1), 2, big) }, c.pk(1), 2, SID)).toBe(false);
    const good = c.sh(1, 2);
    expect(dkgVerifyShare({ from: 1, share: Array.from(good.share) as unknown as Uint8Array, sig: good.sig }, c.pk(1), 2, SID)).toBe(false);
    expect(dkgVerifyShare(null as never, c.pk(1), 2, SID)).toBe(false);
    expect(dkgVerifyShare({ from: 1, share: good.share, sig: good.sig }, c.pk(1), 2, SID)).toBe(true);
  });
  it('rejects a signature with trailing bytes (length must be exactly 64)', () => {
    const c = ceremony(2, 3);
    const s = c.sh(1, 2);
    const ext = new Uint8Array(65);
    ext.set(unb64u(s.sig));
    expect(dkgVerifyShare({ from: 1, share: s.share, sig: b64u(ext) }, c.pk(1), 2, SID)).toBe(false);
    expect(dkgVerifyShare({ from: 1, share: s.share, sig: b64u(unb64u(s.sig).subarray(0, 63)) }, c.pk(1), 2, SID)).toBe(false);
    expect(dkgVerifyShare({ from: 1, share: s.share, sig: undefined }, c.pk(1), 2, SID)).toBe(false);
  });
  it('requires the sender package itself to carry a valid PoP', () => {
    const c = ceremony(2, 3);
    const s = c.sh(1, 2);
    const p = c.pk(1);
    const tampered: DkgRound1Package = { ...p, proofOfKnowledge: { ...p.proofOfKnowledge, mu: c.pk(2).proofOfKnowledge.mu } };
    expect(dkgVerifyShare(s, p, 2, SID)).toBe(true);
    expect(dkgVerifyShare(s, tampered, 2, SID)).toBe(false);
  });
});

describe('dkgFileComplaint validation', () => {
  const base = (over: Record<string, unknown> = {}) => ({
    accused: 2,
    accuser: 1,
    receivedShare: scalarToBytes(1n),
    shareSig: 'sig',
    senderCommitments: [] as string[],
    sessionId: SID,
    ...over,
  });
  const f = (over: Record<string, unknown>) => () => dkgFileComplaint(base(over) as never);
  it('exact messages and boundaries', () => {
    thr(f({ accused: 0 }), 'dkgFileComplaint: accused must be a positive integer');
    thr(f({ accused: -3 }), 'dkgFileComplaint: accused must be a positive integer');
    thr(f({ accused: 1.5 }), 'dkgFileComplaint: accused must be a positive integer');
    thr(f({ accuser: 0 }), 'dkgFileComplaint: accuser must be a positive integer');
    thr(f({ accuser: -3 }), 'dkgFileComplaint: accuser must be a positive integer');
    thr(f({ accuser: 2.5 }), 'dkgFileComplaint: accuser must be a positive integer');
    thr(f({ accused: 1, accuser: 1 }), 'dkgFileComplaint: cannot file a complaint against yourself');
    thr(f({ shareSig: '' }), 'dkgFileComplaint: shareSig (the accused-signed share) is required');
    thr(f({ shareSig: 5 }), 'dkgFileComplaint: shareSig (the accused-signed share) is required');
    thr(f({ shareSig: undefined }), 'dkgFileComplaint: shareSig (the accused-signed share) is required');
    thr(f({ sessionId: new Uint8Array(0) }), 'dkgFileComplaint: sessionId must be a non-empty byte string');
    thr(f({ sessionId: 'abc' }), 'dkgFileComplaint: sessionId must be a non-empty byte string');
    expect(dkgFileComplaint(base({ accused: 1, accuser: 2 }) as never)).toEqual({
      accused: 1,
      accuser: 2,
      sessionId: b64u(SID),
      revealedShare: b64u(scalarToBytes(1n)),
      shareSig: 'sig',
    });
  });
});

describe('dkgVerifyComplaint verdicts', () => {
  it('no accused package: exact verdict', () => {
    const c = ceremony(2, 3);
    const comp = badComplaint(c, 2, 1);
    expect(dkgVerifyComplaint({ ...comp, accused: 9 }, c.pkgs)).toStrictEqual({
      justified: false,
      reason: 'accused 9 has no round-1 package to adjudicate against',
    });
  });
  it('justified, false accusation, inadmissible: exact verdicts (accused is not the first package)', () => {
    const c = ceremony(2, 3);
    expect(dkgVerifyComplaint(badComplaint(c, 2, 1), c.pkgs)).toStrictEqual({
      justified: true,
      disqualify: 2,
      reason: 'accused non-repudiably signed a share that FAILS VSS against its broadcast commitments',
    });
    const s = c.sh(2, 1);
    const falseAcc = dkgFileComplaint({ accused: 2, accuser: 1, receivedShare: s.share, shareSig: s.sig, senderCommitments: [], sessionId: SID });
    expect(dkgVerifyComplaint(falseAcc, c.pkgs)).toStrictEqual({
      justified: false,
      atFault: 1,
      reason: 'accused-signed share is VALID against the accused commitments — false accusation',
    });
    expect(dkgVerifyComplaint(fabricatedComplaint(c, 2, 1), c.pkgs)).toStrictEqual({
      justified: false,
      atFault: 1,
      reason: 'revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)',
    });
  });
  it('session mismatch exact verdict', () => {
    const c = ceremony(2, 3);
    expect(dkgVerifyComplaint({ ...badComplaint(c, 2, 1), sessionId: b64u(SID2) }, c.pkgs)).toStrictEqual({
      justified: false,
      reason: 'complaint sessionId does not match the accused round-1 package session',
    });
  });
  it('malformed complaints land in the catch with the exact verdict', () => {
    const c = ceremony(2, 3);
    const m = { justified: false, reason: 'malformed complaint' };
    expect(dkgVerifyComplaint(null as never, c.pkgs)).toStrictEqual(m);
    expect(dkgVerifyComplaint({ ...badComplaint(c, 2, 1), revealedShare: 5 as never }, c.pkgs)).toStrictEqual(m);
    // admissible (accused really signed it) but the revealed bytes are not a canonical scalar
    const big = new Uint8Array(32).fill(0xff);
    const comp = { ...badComplaint(c, 2, 1), revealedShare: b64u(big), shareSig: dkgSignShare(c.st(2), 1, big) };
    expect(dkgVerifyComplaint(comp, c.pkgs)).toStrictEqual(m);
  });
  it('an accused package with unparsable commitments makes the complaint inadmissible (not malformed)', () => {
    const c = ceremony(2, 3);
    const garbled = c.pkgs.map((p) => (p.identifier === 2 ? { ...p, coefficientCommitments: ['AAAA', 'AAAA'] } : p));
    const v = dkgVerifyComplaint(badComplaint(c, 2, 1), garbled);
    expect(v.justified).toBe(false);
    expect(v.atFault).toBe(1);
    expect(v.reason).toBe('revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)');
  });
});

describe('dkgRebut', () => {
  it('guards with exact messages', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 1, 2);
    thr(() => dkgRebut(1, comp, c.st(2)), 'dkgRebut: myRound2State is not the accused');
    thr(() => dkgRebut(1, { ...comp, accused: 2 }, c.st(1)), 'dkgRebut: complaint does not name this accused');
    thr(() => dkgRebut(1, { ...comp, sessionId: b64u(SID2) }, c.st(1)), 'dkgRebut: complaint is scoped to a different session than my state');
  });
  it('returns exactly the share + signature dkgRound2 sent', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 3);
    const s = c.sh(2, 3);
    expect(dkgRebut(2, comp, c.st(2))).toEqual({
      accused: 2,
      accuser: 3,
      sessionId: comp.sessionId,
      presentedShare: b64u(s.share),
      shareSig: s.sig,
    });
  });
});

describe('dkgResolveBlame', () => {
  it('no accused package', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    expect(dkgResolveBlame({ ...comp, accused: 9 }, undefined, c.pkgs)).toStrictEqual({
      guilty: 9,
      reason: 'accused 9 has no round-1 package to defend with',
    });
  });
  it('session mismatch', () => {
    const c = ceremony(2, 3);
    const comp = { ...badComplaint(c, 2, 1), sessionId: b64u(SID2) };
    expect(dkgResolveBlame(comp, undefined, c.pkgs)).toStrictEqual({
      guilty: 1,
      reason: 'complaint names a session the accused did not run — inadmissible',
    });
  });
  it('admissible bad share convicts the accused; admissible good share convicts the accuser (accused not first package)', () => {
    const c = ceremony(2, 3);
    expect(dkgResolveBlame(badComplaint(c, 2, 1), undefined, c.pkgs)).toStrictEqual({
      guilty: 2,
      reason: 'accused non-repudiably signed a share that fails VSS',
    });
    const s = c.sh(2, 1);
    const good = dkgFileComplaint({ accused: 2, accuser: 1, receivedShare: s.share, shareSig: s.sig, senderCommitments: [], sessionId: SID });
    expect(dkgResolveBlame(good, undefined, c.pkgs)).toStrictEqual({
      guilty: 1,
      reason: 'accused-signed share is valid against its commitments — false accusation',
    });
  });
  it('inadmissible with no rebuttal', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    const none = {
      guilty: 1,
      reason: 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused',
    };
    expect(dkgResolveBlame(comp, undefined, c.pkgs)).toStrictEqual(none);
  });
  it('inadmissible with a rebuttal that does not match accused / accuser / session is ignored', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    const good = dkgRebut(2, comp, c.st(2));
    const none = {
      guilty: 1,
      reason: 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused',
    };
    expect(dkgResolveBlame(comp, { ...good, accused: 3 }, c.pkgs)).toStrictEqual(none);
    expect(dkgResolveBlame(comp, { ...good, accuser: 3 }, c.pkgs)).toStrictEqual(none);
    expect(dkgResolveBlame(comp, { ...good, sessionId: b64u(SID2) }, c.pkgs)).toStrictEqual(none);
  });
  it('inadmissible with a valid matching rebuttal: refuted', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    expect(dkgResolveBlame(comp, dkgRebut(2, comp, c.st(2)), c.pkgs)).toStrictEqual({
      guilty: 1,
      reason: 'accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted',
    });
  });
  it('inadmissible with an invalid matching rebuttal: accused guilty (each failure mode)', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    const good = dkgRebut(2, comp, c.st(2));
    const guilty = { guilty: 2, reason: 'accused could not present a validly-signed, VSS-correct share on rebuttal' };
    // VSS-correct share, signature over some other share
    expect(dkgResolveBlame(comp, { ...good, shareSig: c.sh(2, 3).sig }, c.pkgs)).toStrictEqual(guilty);
    // validly signed, but VSS-bad share
    const bad = flip(unb64u(good.presentedShare));
    const badReb: DkgRebuttal = { ...good, presentedShare: b64u(bad), shareSig: dkgSignShare(c.st(2), 1, bad) };
    expect(dkgResolveBlame(comp, badReb, c.pkgs)).toStrictEqual(guilty);
    // neither
    expect(dkgResolveBlame(comp, { ...badReb, shareSig: c.sh(2, 3).sig }, c.pkgs)).toStrictEqual(guilty);
  });
  it('malformed complaint lands in the catch', () => {
    const c = ceremony(2, 3);
    const m = { guilty: 1, reason: 'malformed complaint — inadmissible' };
    const big = new Uint8Array(32).fill(0xff);
    const comp = { ...badComplaint(c, 2, 1), revealedShare: b64u(big), shareSig: dkgSignShare(c.st(2), 1, big) };
    expect(dkgResolveBlame(comp, undefined, c.pkgs)).toStrictEqual(m);
    expect(dkgResolveBlame({ ...badComplaint(c, 2, 1), revealedShare: 5 as never }, undefined, c.pkgs)).toStrictEqual(m);
  });
  it('an accused package with unparsable commitments is inadmissible (not the malformed catch)', () => {
    const c = ceremony(2, 3);
    const garbled = c.pkgs.map((p) => (p.identifier === 2 ? { ...p, coefficientCommitments: ['AAAA', 'AAAA'] } : p));
    expect(dkgResolveBlame(badComplaint(c, 2, 1), undefined, garbled)).toStrictEqual({
      guilty: 1,
      reason: 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused',
    });
  });
});

describe('dkgQualifiedSet', () => {
  it('returns ids sorted numerically ascending regardless of input order', () => {
    const c = ceremony(2, 4, SID, [100, 9, 10, 2]);
    expect(dkgQualifiedSet([100, 9, 10, 2], [], c.pkgs)).toEqual([2, 9, 10, 100]);
  });
  it('a single package still qualifies; unknown participants are skipped', () => {
    const c = ceremony(1, 1);
    expect(dkgQualifiedSet([1], [], c.pkgs)).toEqual([1]);
    expect(dkgQualifiedSet([1, 99], [], c.pkgs)).toEqual([1]);
  });
  it('plurality session wins; ties go to the first-seen session', () => {
    const a = ceremony(2, 3, SID);
    const b = ceremony(2, 3, SID2);
    // 1,2 on SID, 3 on SID2 → [1,2]; last-wins mutants would pick SID2
    expect(dkgQualifiedSet([1, 2, 3], [], [a.pk(1), a.pk(2), b.pk(3)])).toEqual([1, 2]);
    // tie: first session seen wins
    expect(dkgQualifiedSet([1, 2], [], [a.pk(1), b.pk(2)])).toEqual([1]);
    expect(dkgQualifiedSet([1, 2], [], [b.pk(2), a.pk(1)])).toEqual([2]);
  });
  it('a package with an invalid PoP does not qualify', () => {
    const c = ceremony(2, 3);
    const bad: DkgRound1Package = { ...c.pk(2), proofOfKnowledge: { ...c.pk(2).proofOfKnowledge, mu: c.pk(1).proofOfKnowledge.mu } };
    expect(dkgQualifiedSet([1, 2, 3], [], [c.pk(1), bad, c.pk(3)])).toEqual([1, 3]);
  });
  it('rebuttals are matched on accused AND accuser AND session', () => {
    const c = ceremony(2, 3);
    const comp = fabricatedComplaint(c, 2, 1);
    const good = dkgRebut(2, comp, c.st(2));
    const bad: DkgRebuttal = { ...good, shareSig: c.sh(2, 3).sig }; // signature does not verify → accused guilty
    const decoys: DkgRebuttal[] = [
      { ...bad, accused: 3 },
      { ...bad, accuser: 3 },
      { ...bad, sessionId: b64u(SID2) },
    ];
    expect(dkgQualifiedSet([1, 2, 3], [comp], c.pkgs, [...decoys, bad])).toEqual([1, 3]);
    // with the valid rebuttal the accused is cleared
    expect(dkgQualifiedSet([1, 2, 3], [comp], c.pkgs, [...decoys, good])).toEqual([1, 2, 3]);
    // without any rebuttal / default rebuttals the inadmissible complaint removes nobody
    expect(dkgQualifiedSet([1, 2, 3], [comp], c.pkgs)).toEqual([1, 2, 3]);
    // a justified complaint removes the accused
    expect(dkgQualifiedSet([1, 2, 3], [badComplaint(c, 2, 1)], c.pkgs)).toEqual([1, 3]);
  });
});

describe('transcript digest binds every field', () => {
  const c = ceremony(2, 3);
  const comps = [badComplaint(c, 2, 1), badComplaint(c, 3, 1)];
  const dig = (over: Partial<Parameters<typeof dkgTranscriptDigest>[0]> = {}) =>
    dkgTranscriptDigest({ round1Packages: c.pkgs, complaints: comps, qualified: [1, 2, 3], sessionId: SID, ...over });
  it('changes with any package field', () => {
    const base = dig();
    const mut = (f: (p: DkgRound1Package) => DkgRound1Package) => dig({ round1Packages: c.pkgs.map((p, i) => (i === 0 ? f(p) : p)) });
    expect(mut((p) => ({ ...p, proofOfKnowledge: { ...p.proofOfKnowledge, R: c.pk(2).proofOfKnowledge.R } }))).not.toBe(base);
    expect(mut((p) => ({ ...p, proofOfKnowledge: { ...p.proofOfKnowledge, mu: c.pk(2).proofOfKnowledge.mu } }))).not.toBe(base);
    expect(mut((p) => ({ ...p, identifier: 77 }))).not.toBe(base);
    expect(mut((p) => ({ ...p, sessionId: 'x' }))).not.toBe(base);
    expect(mut((p) => ({ ...p, coefficientCommitments: [...p.coefficientCommitments].reverse() }))).not.toBe(base);
  });
  it('changes with any complaint field, the qualified set and the session', () => {
    const base = dig();
    const mc = (over: Partial<DkgComplaint>) => dig({ complaints: [{ ...comps[0]!, ...over }, comps[1]!] });
    expect(mc({ accused: 3 })).not.toBe(base);
    expect(mc({ accuser: 3 })).not.toBe(base);
    expect(mc({ sessionId: 'x' })).not.toBe(base);
    expect(mc({ revealedShare: 'x' })).not.toBe(base);
    expect(mc({ shareSig: 'x' })).not.toBe(base);
    expect(dig({ complaints: [] })).not.toBe(base);
    expect(dig({ qualified: [1, 2] })).not.toBe(base);
    expect(dig({ sessionId: SID2 })).not.toBe(base);
  });
  it('is order-independent for packages, complaints and qualified', () => {
    const base = dig();
    expect(dig({ round1Packages: [...c.pkgs].reverse() })).toBe(base);
    expect(dig({ complaints: [...comps].reverse() })).toBe(base);
    expect(dig({ qualified: [3, 1, 2] })).toBe(base);
    expect(dig({ qualified: [10, 9, 100] })).toBe(dig({ qualified: [100, 9, 10] }));
    expect(dig({ qualified: [10, 9, 100] })).not.toBe(dig({ qualified: [10, 9] }));
  });
});

describe('dkgCheckEchoes', () => {
  const c = ceremony(2, 3);
  const echo = (id: number, q = [1, 2, 3]) => dkgEcho({ identifier: id, round1Packages: c.pkgs, complaints: [], qualified: q, sessionId: SID });
  it('agrees and returns the digest', () => {
    const e = [echo(1), echo(2), echo(3)];
    expect(dkgCheckEchoes([1, 2, 3], e, SID)).toEqual({ agreed: true, digest: e[0]!.transcriptDigest });
  });
  it('ignores echoes from non-qualified parties even if cross-session or duplicated', () => {
    const e = [echo(1, [1, 2]), echo(2, [1, 2])];
    const junk1: DkgEcho = { ...echo(3), sessionId: b64u(SID2) };
    expect(dkgCheckEchoes([1, 2], [...e, junk1, junk1], SID).agreed).toBe(true);
  });
  it('cross-session echo from a qualified party: exact reason', () => {
    const e: DkgEcho[] = [echo(1), { ...echo(2), sessionId: b64u(SID2) }, echo(3)];
    expect(dkgCheckEchoes([1, 2, 3], e, SID)).toStrictEqual({ agreed: false, reason: 'echo from 2 is bound to a different session' });
  });
  it('duplicate echo from a qualified party: exact reason', () => {
    expect(dkgCheckEchoes([1, 2, 3], [echo(1), echo(2), echo(2), echo(3)], SID)).toStrictEqual({
      agreed: false,
      reason: 'duplicate echo from qualified participant 2',
    });
  });
  it('missing and divergent echoes: exact reasons', () => {
    expect(dkgCheckEchoes([1, 2, 3], [echo(1), echo(3)], SID)).toStrictEqual({ agreed: false, reason: 'missing echo from qualified participant 2' });
    expect(dkgCheckEchoes([1, 2, 3], [echo(1), echo(2, [1, 2]), echo(3)], SID)).toStrictEqual({
      agreed: false,
      reason: 'qualified participant 2 echoed a DIFFERENT transcript (equivocation detected)',
    });
  });
  it('empty qualified set: nothing to agree on', () => {
    expect(dkgCheckEchoes([], [echo(1)], SID)).toStrictEqual({ agreed: false, reason: 'no qualified echoes to agree on' });
  });
  it('malformed input lands in the catch', () => {
    expect(dkgCheckEchoes([1], null as never, SID)).toStrictEqual({ agreed: false, reason: 'malformed echoes' });
  });
});

describe('dkgFinalize', () => {
  const c = ceremony(2, 3);
  const fin = (me: number, q?: number[], pkgs = c.pkgs, recv = c.inbox(me), agreement?: Parameters<typeof dkgFinalize>[5]) =>
    dkgFinalize(me, c.st(me), recv, pkgs, q, agreement);
  const echoesFor = (q: number[], view = q, complaints: DkgComplaint[] = []) =>
    q.map((id) => dkgEcho({ identifier: id, round1Packages: c.pkgs, complaints, qualified: view, sessionId: SID }));

  it('guards with exact messages', () => {
    thr(() => dkgFinalize(2, c.st(1), c.inbox(2), c.pkgs), 'dkgFinalize: myState.identifier != myIdentifier');
    thr(() => fin(1, undefined, [c.pk(1), c.pk(2), c.pk(2), c.pk(3)]), 'dkgFinalize: duplicate identifiers in commitments');
    thr(() => fin(1, undefined, [c.pk(2), c.pk(3)]), 'dkgFinalize: my own package is missing from allCommitments');
    thr(() => fin(1, undefined, [c.pk(1), { ...c.pk(2), sessionId: b64u(SID2) }, c.pk(3)]), 'dkgFinalize: participant 2 round-1 package is from a different session');
    thr(() => fin(3, [1, 2]), 'dkgFinalize: myIdentifier is not in the qualified set');
    thr(() => fin(1, [1]), 'dkgFinalize: qualified set (1) is smaller than the threshold t=2');
  });
  it('qualified set of exactly t succeeds; unknown ids in `qualified` are filtered out', () => {
    const base = fin(1, [1, 2]);
    expect(base.publicKeyPackage.verifyingShares.map((v) => v.identifier)).toEqual([1, 2]);
    const withJunk = fin(1, [1, 2, 99]);
    expect(withJunk.publicKeyPackage.verifyingShares.map((v) => v.identifier)).toEqual([1, 2]);
    expect(withJunk.groupPublicKey).toEqual(base.groupPublicKey);
    expect(withJunk.signingShare).toEqual(base.signingShare);
  });
  it('coefficient count is checked for qualified packages only', () => {
    const shortPkg = (id: number) => c.pkgs.map((p) => (p.identifier === id ? { ...p, coefficientCommitments: p.coefficientCommitments.slice(0, 1) } : p));
    thr(() => fin(1, [1, 2], shortPkg(2)), 'dkgFinalize: participant 2 committed to 1 coefficients, expected t=2');
    thr(() => fin(1, undefined, shortPkg(3)), 'dkgFinalize: participant 3 committed to 1 coefficients, expected t=2');
    // a disqualified participant's malformed package is ignored
    const ok = fin(1, [1, 2], shortPkg(3));
    expect(ok.groupPublicKey).toEqual(fin(1, [1, 2]).groupPublicKey);
  });
  it('received-share handling: self / disqualified senders ignored, session, duplicate and missing are errors', () => {
    const base = fin(1);
    const sh2 = c.inbox(1).find((r) => r.from === 2)!;
    const sh3 = c.inbox(1).find((r) => r.from === 3)!;
    // a share "from myself" (even with a wrong session) is ignored
    const self = { from: 1, sessionId: b64u(SID2), share: scalarToBytes(5n) };
    expect(fin(1, undefined, c.pkgs, [self, sh2, sh3]).signingShare).toEqual(base.signingShare);
    expect(fin(1, undefined, c.pkgs, [{ ...self, sessionId: b64u(SID) }, sh2, sh3]).signingShare).toEqual(base.signingShare);
    // a share from a disqualified sender (wrong session) is ignored
    expect(fin(1, [1, 2], c.pkgs, [sh2, { ...sh3, sessionId: b64u(SID2) }]).groupPublicKey).toEqual(fin(1, [1, 2]).groupPublicKey);
    thr(() => fin(1, undefined, c.pkgs, [sh2, { ...sh3, sessionId: b64u(SID2) }]), 'dkgFinalize: received share from 3 is from a different session');
    thr(() => fin(1, undefined, c.pkgs, [sh2, sh3, sh3]), 'dkgFinalize: duplicate received share from 3');
    thr(() => fin(1, undefined, c.pkgs, [sh2]), 'dkgFinalize: missing received share from qualified participant 3');
    thr(() => fin(1, undefined, c.pkgs, []), 'dkgFinalize: missing received share from qualified participant 2');
  });
  it('outputs: group commitment bytes, group key = Φ0, consistent verifying shares', () => {
    const k = fin(1);
    expect(k.publicKeyPackage.groupCommitment.length).toBe(2);
    for (const g of k.publicKeyPackage.groupCommitment) {
      expect(g).toBeInstanceOf(Uint8Array);
      expect(g.length).toBe(32);
    }
    expect(k.publicKeyPackage.groupCommitment[0]).toEqual(k.groupPublicKey);
    expect(k.publicKeyPackage.verifyingShares.find((v) => v.identifier === 1)!.publicKey).toEqual(k.verifyingShare);
  });
  it('echo agreement: honest echoes with and without complaints list', () => {
    const q = [1, 2, 3];
    const k = fin(1, q, c.pkgs, c.inbox(1), { echoes: echoesFor(q) });
    expect(k.groupPublicKey).toEqual(fin(1).groupPublicKey);
    const cp = badComplaint(c, 3, 2);
    const k2 = fin(1, q, c.pkgs, c.inbox(1), { echoes: echoesFor(q, q, [cp]), complaints: [cp] });
    expect(k2.groupPublicKey).toEqual(k.groupPublicKey);
    // my view includes a complaint the echoes do not → divergence
    thr(
      () => fin(1, q, c.pkgs, c.inbox(1), { echoes: echoesFor(q), complaints: [cp] }),
      'dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)',
    );
  });
  it('echo agreement: failing agreement reports the first (sorted) offender', () => {
    // qualified passed in descending order; the check must run over the sorted set
    thr(
      () => fin(1, [3, 2, 1], c.pkgs, c.inbox(1), { echoes: [] }),
      'dkgFinalize: echo-broadcast agreement failed — missing echo from qualified participant 1',
    );
    thr(
      () => fin(1, [1, 2, 3], c.pkgs, c.inbox(1), { echoes: [echoesFor([1, 2, 3])[0]!, echoesFor([1, 2], [1, 2])[1]!, echoesFor([1, 2, 3])[2]!] }),
      'dkgFinalize: echo-broadcast agreement failed — qualified participant 2 echoed a DIFFERENT transcript (equivocation detected)',
    );
  });
  it('echo agreement: agreed digest over a different view than mine is rejected', () => {
    thr(
      () => fin(1, [1, 2, 3], c.pkgs, c.inbox(1), { echoes: echoesFor([1, 2, 3], [1, 2]) }),
      'dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)',
    );
  });
});

describe('frostDkgSimulate', () => {
  it('parameter validation: exact messages', () => {
    thr(() => frostDkgSimulate(0, 3), 'frostDkgSimulate: need 1 <= t <= n (got t=0, n=3)');
    thr(() => frostDkgSimulate(4, 3), 'frostDkgSimulate: need 1 <= t <= n (got t=4, n=3)');
    thr(() => frostDkgSimulate(1.5, 3), 'frostDkgSimulate: need 1 <= t <= n (got t=1.5, n=3)');
    thr(() => frostDkgSimulate(1, 2.5), 'frostDkgSimulate: need 1 <= t <= n (got t=1, n=2.5)');
    thr(() => frostDkgSimulate(2, 1.5), 'frostDkgSimulate: need 1 <= t <= n (got t=2, n=1.5)');
    thr(() => frostDkgSimulate(2, 3, { identifiers: [1, 2] }), 'frostDkgSimulate: identifiers.length must equal n');
    thr(() => frostDkgSimulate(2, 3, { identifiers: [1, 1, 2] }), 'frostDkgSimulate: identifiers must be distinct');
    for (const bad of [[0, 1, 2], [-1, 1, 2], [1, 2, 2.5], [1, 2, 0]]) {
      thr(() => frostDkgSimulate(2, 3, { identifiers: bad }), 'frostDkgSimulate: identifiers must be positive integers');
    }
    expect(frostDkgSimulate(1, 1).qualified).toEqual([1]);
    expect(frostDkgSimulate(2, 3, { identifiers: [5, 7, 9] }).qualified).toEqual([5, 7, 9]);
  });
  it('too many cheaters: exact message', () => {
    thr(() => frostDkgSimulate(3, 3, { cheaters: [1] }), 'frostDkgSimulate: only 2 qualified participants (< t=3) after the blame round');
  });
  it('a cheater is disqualified and the honest set finalizes', () => {
    const r = frostDkgSimulate(2, 3, { cheaters: [3] });
    expect(r.qualified).toEqual([1, 2]);
    expect(r.complaints.length).toBe(2);
    expect(r.rebuttals.length).toBe(2);
    expect(r.echoes.length).toBe(2);
  });
  it('equivocation is detected even when the tampered view would otherwise equal the real one (n = 1)', () => {
    expect(() => frostDkgSimulate(1, 1, { equivocateEchoFor: 1 })).toThrow(/diverges from the agreed echo digest/);
    expect(() => frostDkgSimulate(2, 3, { equivocateEchoFor: 2 })).toThrow(/echoed a DIFFERENT transcript/);
  });
});
