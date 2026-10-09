import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { verify } from './keys';
import {
  type FrostCommitment,
  type FrostParticipantShare,
  type FrostSignatureShare,
  frostAggregate,
  frostCommit,
  frostSign,
  frostVerifySigShare,
  scalarToBytes,
} from './frost';
import {
  type DkgEcho,
  type DkgReceivedShare,
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

// =================================================================================================
// NOTE ON VALIDATION BASIS
// ------------------------------------------------------------------------------------------------
// RFC 9591 is SIGNING-ONLY: there is no official FROST DKG test vector, so this suite asserts NO
// published byte-vector for the DKG (unlike frost.test.ts, which is vector-exact for signing).
// Instead the DKG is validated by (a) ROUND-TRIP — its output drives the already-vector-exact
// frostSign/frostAggregate and verify(groupPublicKey,…) must return true for every t-of-n quorum,
// including after a cheater is disqualified and the honest quorum signs under the smaller qualified
// set — and (b) the DKG's own INVARIANTS: proof-of-possession checks, VSS share checks, group-key
// agreement across participants, session binding (anti-replay) and the justified-complaint blame round.
// =================================================================================================

/** A fixed, deterministic session id (any non-empty byte string works). */
function sid(seed = 0xab): Uint8Array {
  const s = new Uint8Array(32);
  s.fill(seed);
  return s;
}

/** Drive the vector-exact signer with a DKG quorum and return the aggregate Ed25519 signature. */
function signWithQuorum(
  shares: Map<number, FrostParticipantShare>,
  groupPublicKey: Uint8Array,
  signerIds: number[],
  message: Uint8Array,
): Uint8Array {
  const commits = signerIds.map((id) => frostCommit(shares.get(id)!));
  const commitments: FrostCommitment[] = commits.map((c) => c.commitment);
  const sigShares: FrostSignatureShare[] = signerIds.map((id, i) =>
    frostSign(
      id,
      shares.get(id)!.share,
      groupPublicKey,
      { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce },
      message,
      commitments,
    ),
  );
  // Each share verifies individually against its DKG verification share (invariant check).
  signerIds.forEach((id, i) => {
    expect(
      frostVerifySigShare({
        identifier: id,
        publicKey: shares.get(id)!.publicKey,
        commitment: commitments[i]!,
        sigShare: sigShares[i]!,
        signingCommitments: commitments,
        groupPublicKey,
        message,
      }),
    ).toBe(true);
  });
  return frostAggregate(message, commitments, sigShares, groupPublicKey);
}

describe('FROST DKG — round-trip into the vector-exact signer', () => {
  it('(2,3) DKG → finalize → every 2-of-3 quorum aggregates to a valid group-key signature', () => {
    const dkg = frostDkgSimulate(2, 3);
    const shares = new Map(dkg.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('transfer 100 to bob — no dealer');
    for (const quorum of [
      [1, 2],
      [1, 3],
      [2, 3],
    ] as const) {
      const sig = signWithQuorum(shares, dkg.groupPublicKey, [...quorum], msg);
      expect(verify(dkg.groupPublicKey, msg, sig)).toBe(true);
    }
  });

  it('(3,5) DKG → finalize → a 3-of-5 quorum aggregates to a valid group-key signature', () => {
    const dkg = frostDkgSimulate(3, 5);
    const shares = new Map(dkg.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('three of five, no dealer');
    const sig = signWithQuorum(shares, dkg.groupPublicKey, [2, 4, 5], msg);
    expect(verify(dkg.groupPublicKey, msg, sig)).toBe(true);
  });

  it('the group public key is independent of which quorum signs (same key, different signers)', () => {
    const dkg = frostDkgSimulate(2, 3);
    const shares = new Map(dkg.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('quorum independence');
    const sigA = signWithQuorum(shares, dkg.groupPublicKey, [1, 2], msg);
    const sigB = signWithQuorum(shares, dkg.groupPublicKey, [2, 3], msg);
    // Both verify under the SAME group key, though signed by different quorums.
    expect(verify(dkg.groupPublicKey, msg, sigA)).toBe(true);
    expect(verify(dkg.groupPublicKey, msg, sigB)).toBe(true);
  });

  it('an insufficient (1-of-2) quorum does NOT verify under a (2,n) DKG group key', () => {
    const dkg = frostDkgSimulate(2, 3);
    const shares = new Map(dkg.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('insufficient');
    // frostAggregate now refuses to return an invalid aggregate.
    expect(() => signWithQuorum(shares, dkg.groupPublicKey, [1], msg)).toThrow(/does not verify/);
  });
});

describe('FROST DKG — invariants', () => {
  it('all participants independently finalize to the SAME group public key and verifying shares', () => {
    // Run the ceremony "by hand" so each participant finalizes independently.
    const ids = [1, 2, 3];
    const t = 2;
    const session = sid();
    const results = ids.map((id) => dkgRound1(id, t, ids.length, session));
    const round1 = results.map((r) => r.package);

    // Everyone checks everyone's PoP.
    for (const pkg of round1) expect(dkgVerifyRound1(pkg.identifier, pkg, session)).toBe(true);

    // Round 2 + private delivery, each recipient verifying its shares.
    const inbox = new Map<number, DkgReceivedShare[]>(ids.map((id) => [id, []]));
    for (const r of results) {
      for (const out of dkgRound2(r.state, round1)) {
        const senderPkg = round1.find((p) => p.identifier === out.from)!;
        expect(dkgVerifyShare(out, senderPkg, out.to, session)).toBe(true);
        inbox.get(out.to)!.push({ from: out.from, sessionId: out.sessionId, share: out.share, sig: out.sig });
      }
    }

    const finals = results.map((r) => dkgFinalize(r.state.identifier, r.state, inbox.get(r.state.identifier)!, round1));

    // Same group key for all.
    const gpk = b64u(finals[0]!.groupPublicKey);
    for (const f of finals) expect(b64u(f.groupPublicKey)).toBe(gpk);

    // Same public-key package (group commitment + verifying shares) for all.
    const refVs = finals[0]!.publicKeyPackage.verifyingShares.map((v) => `${v.identifier}:${b64u(v.publicKey)}`).sort();
    for (const f of finals) {
      const vs = f.publicKeyPackage.verifyingShares.map((v) => `${v.identifier}:${b64u(v.publicKey)}`).sort();
      expect(vs).toEqual(refVs);
    }

    // Each participant's own verifyingShare == its signingShare·B == the matching entry in the package.
    for (const f of finals) {
      const mine = f.publicKeyPackage.verifyingShares.find((v) => v.identifier === f.identifier)!;
      expect(b64u(f.verifyingShare)).toBe(b64u(mine.publicKey));
    }
  });

  it('dkgVerifyShare rejects a tampered share', () => {
    const ids = [1, 2, 3];
    const session = sid();
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const sender = results[0]!; // participant 1
    const outgoing = dkgRound2(sender.state, round1);
    const toTwo = outgoing.find((o) => o.to === 2)!;

    // Honest signed share verifies.
    expect(dkgVerifyShare(toTwo, sender.package, 2, session)).toBe(true);

    // Flip a byte → rejected (the sender signature no longer covers these bytes, and VSS fails).
    const tampered = Uint8Array.from(toTwo.share);
    tampered[0] = tampered[0]! ^ 0x01;
    expect(dkgVerifyShare({ ...toTwo, share: tampered }, sender.package, 2, session)).toBe(false);

    // Right share, wrong recipient id → also rejected (it is f_1(2), not f_1(3); the sig is bound to 2).
    expect(dkgVerifyShare(toTwo, sender.package, 3, session)).toBe(false);

    // A share with NO signature is rejected outright (non-repudiation is required).
    expect(dkgVerifyShare({ from: toTwo.from, share: toTwo.share }, sender.package, 2, session)).toBe(false);
  });

  it('dkgVerifyRound1 rejects a bad proof of possession', () => {
    const session = sid();
    const { package: pkg } = dkgRound1(1, 2, 3, session);
    expect(dkgVerifyRound1(1, pkg, session)).toBe(true);

    // Tamper mu → PoP no longer satisfies mu·B == R + c·C_0.
    const badMu = unb64u(pkg.proofOfKnowledge.mu);
    badMu[0] = badMu[0]! ^ 0x01;
    const pkgBadMu: DkgRound1Package = { ...pkg, proofOfKnowledge: { ...pkg.proofOfKnowledge, mu: b64u(badMu) } };
    expect(dkgVerifyRound1(1, pkgBadMu, session)).toBe(false);

    // Verifying under the wrong identifier → challenge differs → rejected (id is bound into the PoP).
    expect(dkgVerifyRound1(2, pkg, session)).toBe(false);

    // Swapping in another participant's constant-term commitment also breaks it.
    const other = dkgRound1(2, 2, 3, session).package;
    const forged: DkgRound1Package = {
      ...pkg,
      coefficientCommitments: [other.coefficientCommitments[0]!, ...pkg.coefficientCommitments.slice(1)],
    };
    expect(dkgVerifyRound1(1, forged, session)).toBe(false);
  });

  it('a deterministic DKG (injected coefficients) is reproducible and still signs', () => {
    const scalarBytes = (v: number): Uint8Array => {
      const out = new Uint8Array(32);
      out[0] = v;
      return out;
    };
    // Two participants, t=2: each supplies [constant, slope].
    const coeffs = [
      [scalarBytes(11), scalarBytes(3)],
      [scalarBytes(7), scalarBytes(5)],
    ];
    const a = frostDkgSimulate(2, 2, { coefficientsByParticipant: coeffs });
    const b = frostDkgSimulate(2, 2, { coefficientsByParticipant: coeffs });
    // Group secret = 11 + 7 = 18; group key is deterministic across runs (independent of session id).
    expect(b64u(a.groupPublicKey)).toBe(b64u(b.groupPublicKey));

    const shares = new Map(a.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('deterministic dkg');
    const sig = signWithQuorum(shares, a.groupPublicKey, [1, 2], msg);
    expect(verify(a.groupPublicKey, msg, sig)).toBe(true);
  });
});

describe('FROST DKG — session binding (anti-replay)', () => {
  it('a round-1 package from one session is rejected under another session', () => {
    const sessionA = sid(0x11);
    const sessionB = sid(0x22);
    const { package: pkg } = dkgRound1(1, 2, 3, sessionA);

    // Verifies under its own session…
    expect(dkgVerifyRound1(1, pkg, sessionA)).toBe(true);
    // …but a replay into another session is rejected (stamped session mismatch AND PoP challenge differs).
    expect(dkgVerifyRound1(1, pkg, sessionB)).toBe(false);

    // Even if an attacker relabels the stamped sessionId to B, the PoP was bound to A → still rejected.
    const relabeled: DkgRound1Package = { ...pkg, sessionId: b64u(sessionB) };
    expect(dkgVerifyRound1(1, relabeled, sessionB)).toBe(false);
  });

  it('a secret share from one session cannot be replayed into another', () => {
    const sessionA = sid(0x33);
    const sessionB = sid(0x44);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, sessionA));
    const round1A = results.map((r) => r.package);
    const sender = results[0]!;
    const toTwo = dkgRound2(sender.state, round1A).find((o) => o.to === 2)!;

    // Valid in its own session…
    expect(dkgVerifyShare(toTwo, sender.package, 2, sessionA)).toBe(true);
    // …but the (package, share) pair captured from session A fails under session B: the package's PoP
    // does not verify under B, so the commitments the share is checked against are not accepted.
    expect(dkgVerifyShare(toTwo, sender.package, 2, sessionB)).toBe(false);
  });

  it('dkgFinalize refuses a set of packages that do not all name the same session', () => {
    const sessionA = sid(0x55);
    const sessionB = sid(0x66);
    const r1 = dkgRound1(1, 2, 3, sessionA);
    const r2 = dkgRound1(2, 2, 3, sessionA);
    // Participant 3 ran a DIFFERENT session.
    const r3 = dkgRound1(3, 2, 3, sessionB);
    const packages = [r1.package, r2.package, r3.package];
    expect(() => dkgFinalize(1, r1.state, [], packages)).toThrow(/different session/);
  });
});

describe('FROST DKG — complaint / blame round', () => {
  it('a cheating dealer is disqualified and the honest set still produces a working key', () => {
    // (2,3): participant 3 cheats (sends bad shares). After the blame round the honest set {1,2}
    // finalizes a working (2,2) key.
    const dkg = frostDkgSimulate(2, 3, { cheaters: [3] });
    expect(dkg.qualified).toEqual([1, 2]);
    expect(dkg.complaints.length).toBeGreaterThan(0);

    // Every complaint against the cheater is justified and names the cheater to disqualify.
    for (const c of dkg.complaints) {
      const v = dkgVerifyComplaint(c, dkg.round1Packages);
      expect(c.accused).toBe(3);
      expect(v.justified).toBe(true);
      expect(v.disqualify).toBe(3);
    }

    // Only qualified participants hold a usable key.
    expect(dkg.participantShares.map((s) => s.identifier).sort()).toEqual([1, 2]);

    // The honest quorum signs under the group key for the qualified set.
    const shares = new Map(dkg.participantShares.map((s) => [s.identifier, s]));
    const msg = utf8('honest set still signs after a cheater is removed');
    const sig = signWithQuorum(shares, dkg.groupPublicKey, [1, 2], msg);
    expect(verify(dkg.groupPublicKey, msg, sig)).toBe(true);
  });

  it('end-to-end by hand: detect → file complaint → verify → qualified set → finalize → sign', () => {
    const ids = [1, 2, 3];
    const session = sid(0x77);
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    for (const pkg of round1) expect(dkgVerifyRound1(pkg.identifier, pkg, session)).toBe(true);

    const cheater = 1;
    const inbox = new Map<number, DkgReceivedShare[]>(ids.map((id) => [id, []]));
    const complaints = [];
    for (const r of results) {
      for (const out of dkgRound2(r.state, round1)) {
        const senderPkg = round1.find((p) => p.identifier === out.from)!;
        let shareBytes = out.share;
        let shareSig = out.sig;
        if (out.from === cheater) {
          // Cheating dealer: corrupt the share so it is inconsistent with its broadcast commitments,
          // and SIGN the corrupted bytes it actually sends (so the complaint is admissible against it).
          shareBytes = Uint8Array.from(out.share);
          shareBytes[0] = shareBytes[0]! ^ 0x01;
          shareSig = dkgSignShare(r.state, out.to, shareBytes);
        }
        if (dkgVerifyShare({ from: out.from, share: shareBytes, sig: shareSig }, senderPkg, out.to, session)) {
          inbox.get(out.to)!.push({ from: out.from, sessionId: out.sessionId, share: shareBytes, sig: shareSig });
        } else {
          complaints.push(
            dkgFileComplaint({
              accused: out.from,
              accuser: out.to,
              receivedShare: shareBytes,
              shareSig,
              senderCommitments: senderPkg.coefficientCommitments,
              sessionId: session,
            }),
          );
        }
      }
    }

    // Every complaint is justified against the cheater.
    expect(complaints.length).toBeGreaterThan(0);
    for (const c of complaints) {
      const v = dkgVerifyComplaint(c, round1);
      expect(v.justified).toBe(true);
      expect(v.disqualify).toBe(cheater);
    }

    // Qualified set excludes the cheater.
    const qualified = dkgQualifiedSet(ids, complaints, round1);
    expect(qualified).toEqual([2, 3]);

    // The honest participants finalize over the qualified set.
    const finals = qualified.map((id) => {
      const r = results.find((x) => x.state.identifier === id)!;
      return dkgFinalize(id, r.state, inbox.get(id)!, round1, qualified);
    });
    const gpk = b64u(finals[0]!.groupPublicKey);
    for (const f of finals) expect(b64u(f.groupPublicKey)).toBe(gpk);

    // …and a quorum of the qualified set signs a valid group-key signature.
    const shares = new Map<number, FrostParticipantShare>(
      finals.map((f) => [f.identifier, { identifier: f.identifier, share: f.signingShare, publicKey: f.verifyingShare }]),
    );
    const msg = utf8('blame round, by hand');
    const sig = signWithQuorum(shares, finals[0]!.groupPublicKey, qualified, msg);
    expect(verify(finals[0]!.groupPublicKey, msg, sig)).toBe(true);
  });

  it('a FALSE complaint against an honest party is NOT justified (griefer cannot disqualify)', () => {
    const ids = [1, 2, 3];
    const session = sid(0x88);
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);

    // Participant 2 honestly sends participant 1 a VALID share, but 1 maliciously complains anyway.
    const honestSender = results[1]!; // participant 2
    const toOne = dkgRound2(honestSender.state, round1).find((o) => o.to === 1)!;
    expect(dkgVerifyShare(toOne, honestSender.package, 1, session)).toBe(true); // the share is good

    const falseComplaint = dkgFileComplaint({
      accused: 2,
      accuser: 1,
      receivedShare: toOne.share, // reveals the GENUINE (valid) share
      shareSig: toOne.sig, // …with the honest sender's real signature over it
      senderCommitments: honestSender.package.coefficientCommitments,
      sessionId: session,
    });
    const verdict = dkgVerifyComplaint(falseComplaint, round1);
    expect(verdict.justified).toBe(false);
    expect(verdict.disqualify).toBeUndefined();

    // The honest party is NOT removed from the qualified set by the false complaint.
    const qualified = dkgQualifiedSet(ids, [falseComplaint], round1);
    expect(qualified).toEqual([1, 2, 3]);
  });

  it('a complaint scoped to the wrong session does not disqualify', () => {
    const session = sid(0x99);
    const otherSession = sid(0xaa);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const sender = results[0]!;
    const toTwo = dkgRound2(sender.state, round1).find((o) => o.to === 2)!;
    const badShare = Uint8Array.from(toTwo.share);
    badShare[0] = badShare[0]! ^ 0x01;

    // A genuinely-bad share, but the complaint names a DIFFERENT session than the broadcast package.
    const complaint = dkgFileComplaint({
      accused: 1,
      accuser: 2,
      receivedShare: badShare,
      shareSig: dkgSignShare(sender.state, 2, badShare),
      senderCommitments: sender.package.coefficientCommitments,
      sessionId: otherSession,
    });
    const verdict = dkgVerifyComplaint(complaint, round1);
    expect(verdict.justified).toBe(false);
    expect(verdict.reason).toMatch(/session/i);
  });
});

describe('FROST DKG — non-repudiable shares + accused rebuttal', () => {
  it('a round-2 share carries the sender signature, and it survives a round-trip but not tampering', () => {
    const session = sid(0xb1);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const sender = results[0]!;
    const toTwo = dkgRound2(sender.state, round1).find((o) => o.to === 2)!;

    // Every share now has a 64-byte non-repudiable signature from the sender.
    expect(typeof toTwo.sig).toBe('string');
    expect(unb64u(toTwo.sig).length).toBe(64);
    // dkgSignShare reproduces exactly the signature dkgRound2 attached (deterministic, re-presentable).
    expect(dkgSignShare(sender.state, 2, toTwo.share)).toBe(toTwo.sig);
    // The signature is bound to the recipient: it does not verify for a different recipient id.
    expect(dkgVerifyShare({ from: 1, share: toTwo.share, sig: toTwo.sig }, sender.package, 2, session)).toBe(true);
    expect(dkgVerifyShare({ from: 1, share: toTwo.share, sig: toTwo.sig }, sender.package, 3, session)).toBe(false);
  });

  it('a complaint with fabricated (not accused-signed) bytes is INADMISSIBLE — cannot frame', () => {
    const session = sid(0xb2);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const accused = results[0]!; // participant 1 is honest
    const accuser = results[1]!; // participant 2 tries to frame participant 1

    // A bad share the accuser fabricates, "signed" with the ACCUSER's own key (not the accused's C_0).
    const badShare = new Uint8Array(32);
    badShare[0] = 0x09;
    const forgedSig = dkgSignShare(accuser.state, 1, badShare); // signed under participant 2's key
    const framing = dkgFileComplaint({
      accused: 1,
      accuser: 2,
      receivedShare: badShare,
      shareSig: forgedSig,
      senderCommitments: accused.package.coefficientCommitments,
      sessionId: session,
    });

    // Not justified: the share is not validly signed by the accused under its broadcast C_0.
    const verdict = dkgVerifyComplaint(framing, round1);
    expect(verdict.justified).toBe(false);
    expect(verdict.disqualify).toBeUndefined();
    expect(verdict.atFault).toBe(2);
    expect(verdict.reason).toMatch(/not validly signed|inadmissible/i);

    // The honest accused is NOT dropped from the qualified set by the framing attempt.
    expect(dkgQualifiedSet([1, 2, 3], [framing], round1)).toEqual([1, 2, 3]);
  });

  it('dkgResolveBlame convicts the accused for an accused-signed VSS-bad share (no rebuttal saves it)', () => {
    const session = sid(0xb3);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const cheater = results[0]!; // participant 1

    // Cheater signs a VSS-bad share it sends to participant 2.
    const good = dkgRound2(cheater.state, round1).find((o) => o.to === 2)!;
    const bad = Uint8Array.from(good.share);
    bad[0] = bad[0]! ^ 0x01;
    const complaint = dkgFileComplaint({
      accused: 1,
      accuser: 2,
      receivedShare: bad,
      shareSig: dkgSignShare(cheater.state, 2, bad),
      senderCommitments: cheater.package.coefficientCommitments,
      sessionId: session,
    });

    // Even if the cheater rebuts with the GOOD share, the signed bad share convicts it non-repudiably.
    const rebuttal = dkgRebut(1, complaint, cheater.state);
    expect(dkgResolveBlame(complaint, rebuttal, round1)).toMatchObject({ guilty: 1 });
    expect(dkgResolveBlame(complaint, undefined, round1)).toMatchObject({ guilty: 1 });
  });

  it('dkgResolveBlame: a false accusation (accused-signed, VSS-valid share) → accuser guilty', () => {
    const session = sid(0xb4);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const honest = results[1]!; // participant 2 sent a GOOD share to 1
    const toOne = dkgRound2(honest.state, round1).find((o) => o.to === 1)!;
    const complaint = dkgFileComplaint({
      accused: 2,
      accuser: 1,
      receivedShare: toOne.share,
      shareSig: toOne.sig,
      senderCommitments: honest.package.coefficientCommitments,
      sessionId: session,
    });
    expect(dkgResolveBlame(complaint, undefined, round1)).toMatchObject({ guilty: 1 });
  });

  it('dkgResolveBlame: an inadmissible non-receipt complaint is refuted by the accused rebuttal → accuser guilty', () => {
    const session = sid(0xb5);
    const results = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const accused = results[0]!; // participant 1 is honest
    const accuser = results[1]!; // participant 2 claims non-receipt with fabricated bytes

    const badShare = new Uint8Array(32);
    badShare[0] = 0x07;
    const framing = dkgFileComplaint({
      accused: 1,
      accuser: 2,
      receivedShare: badShare,
      shareSig: dkgSignShare(accuser.state, 1, badShare), // signed under the wrong key → inadmissible
      senderCommitments: accused.package.coefficientCommitments,
      sessionId: session,
    });

    // Without a rebuttal the inadmissible complaint already cannot frame the accused.
    expect(dkgResolveBlame(framing, undefined, round1)).toMatchObject({ guilty: 2 });
    // The accused re-presents the signed, VSS-correct share it actually sent → positively refutes it.
    const rebuttal = dkgRebut(1, framing, accused.state);
    expect(dkgResolveBlame(framing, rebuttal, round1)).toMatchObject({ guilty: 2 });

    // And the honest accused is not disqualified even with the framing complaint in the set.
    expect(dkgQualifiedSet([1, 2, 3], [framing], round1, [rebuttal])).toEqual([1, 2, 3]);
  });

  it('frostDkgSimulate returns rebuttals and still convicts a signing cheater', () => {
    const dkg = frostDkgSimulate(2, 3, { cheaters: [3] });
    expect(dkg.qualified).toEqual([1, 2]);
    expect(dkg.complaints.length).toBeGreaterThan(0);
    expect(dkg.rebuttals.length).toBe(dkg.complaints.length);
    // Each complaint resolves with the cheater guilty.
    for (const c of dkg.complaints) {
      const reb = dkg.rebuttals.find((r) => r.accused === c.accused && r.accuser === c.accuser);
      expect(dkgResolveBlame(c, reb, dkg.round1Packages)).toMatchObject({ guilty: 3 });
    }
  });
});

describe('FROST DKG — input validation', () => {
  it('rejects t>n and bad identifiers', () => {
    expect(() => frostDkgSimulate(3, 2)).toThrow();
    expect(() => dkgRound1(0, 2, 3, sid())).toThrow();
    expect(() => dkgRound1(1, 3, 2, sid())).toThrow();
  });

  it('dkgRound1 rejects an empty session id', () => {
    expect(() => dkgRound1(1, 2, 3, new Uint8Array(0))).toThrow(/sessionId/);
  });

  it('dkgFinalize rejects a missing received share', () => {
    const ids = [1, 2, 3];
    const session = sid();
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    // Participant 1 finalizes with an EMPTY inbox (missing shares from 2 and 3).
    expect(() => dkgFinalize(1, results[0]!.state, [], round1)).toThrow();
  });
});

// =================================================================================================
// Hardening (P5-3): full commitment-vector binding, subgroup checks, final consistency
// =================================================================================================
describe('FROST DKG hardening', () => {
  it('the PoP binds the FULL commitment vector: swapping a higher-degree commitment invalidates it', () => {
    const session = sid();
    const a = dkgRound1(1, 3, 3, session).package;
    const other = dkgRound1(2, 3, 3, session).package;
    expect(dkgVerifyRound1(1, a, session)).toBe(true);
    const tampered = { ...a, coefficientCommitments: [a.coefficientCommitments[0]!, other.coefficientCommitments[1]!, a.coefficientCommitments[2]!] };
    expect(dkgVerifyRound1(1, tampered, session)).toBe(false);
    const truncated = { ...a, coefficientCommitments: a.coefficientCommitments.slice(0, 2) };
    expect(dkgVerifyRound1(1, truncated, session)).toBe(false);
  });

  it('a share signature made against one commitment vector fails against a different vector', () => {
    const session = sid();
    const ids = [1, 2, 3];
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const out = dkgRound2(results[0]!.state, round1)[0]!;
    expect(dkgVerifyShare(out, round1[0]!, out.to, session)).toBe(true);
    const forged = { ...round1[0]!, coefficientCommitments: [round1[0]!.coefficientCommitments[0]!, round1[1]!.coefficientCommitments[1]!] };
    expect(dkgVerifyShare(out, forged, out.to, session)).toBe(false);
  });

  it('rejects a round-1 package with a small-order commitment or PoP nonce', () => {
    const session = sid();
    const pkg = dkgRound1(1, 2, 2, session).package;
    const identity = new Uint8Array(32);
    identity[0] = 1;
    expect(dkgVerifyRound1(1, { ...pkg, coefficientCommitments: [b64u(identity), pkg.coefficientCommitments[1]!] }, session)).toBe(false);
    expect(dkgVerifyRound1(1, { ...pkg, coefficientCommitments: [pkg.coefficientCommitments[0]!, b64u(identity)] }, session)).toBe(false);
    expect(dkgVerifyRound1(1, { ...pkg, proofOfKnowledge: { ...pkg.proofOfKnowledge, R: b64u(identity) } }, session)).toBe(false);
  });

  it('dkgFinalize fails the final consistency check when a received share is wrong', () => {
    const session = sid();
    const ids = [1, 2, 3];
    const results = ids.map((id) => dkgRound1(id, 2, 3, session));
    const round1 = results.map((r) => r.package);
    const inbox = new Map<number, DkgReceivedShare[]>(ids.map((id) => [id, []]));
    for (const r of results) {
      for (const out of dkgRound2(r.state, round1)) {
        inbox.get(out.to)!.push({ from: out.from, sessionId: out.sessionId, share: out.share, sig: out.sig });
      }
    }
    // Corrupt one share received by participant 1.
    const bad = inbox.get(1)!.map((s, i) => (i === 0 ? { ...s, share: scalarToBytes(7n) } : s));
    expect(() => dkgFinalize(1, results[0]!.state, bad, round1)).toThrow(/inconsistent/);
    // The honest path still finalizes.
    expect(() => dkgFinalize(1, results[0]!.state, inbox.get(1)!, round1)).not.toThrow();
  });
});

// =================================================================================================
// Echo-broadcast / agreement round (Gennaro-style): every qualified party must confirm it saw the
// IDENTICAL transcript (round-1 packages / complaints / qualified set) before finalizing, so an
// equivocating dealer / network split cannot drive honest parties onto different group keys.
// =================================================================================================
describe('FROST DKG — echo-broadcast agreement round', () => {
  /** Run an honest (t,n) ceremony by hand and return everything finalize needs, including echoes. */
  function honestCeremony(t: number, n: number, session: Uint8Array) {
    const ids = Array.from({ length: n }, (_, i) => i + 1);
    const results = ids.map((id) => dkgRound1(id, t, n, session));
    const round1 = results.map((r) => r.package);
    const inbox = new Map<number, DkgReceivedShare[]>(ids.map((id) => [id, []]));
    for (const r of results) {
      for (const out of dkgRound2(r.state, round1)) {
        inbox.get(out.to)!.push({ from: out.from, sessionId: out.sessionId, share: out.share, sig: out.sig });
      }
    }
    const complaints: never[] = [];
    const qualified = dkgQualifiedSet(ids, complaints, round1);
    const echoes = qualified.map((id) => dkgEcho({ identifier: id, round1Packages: round1, complaints, qualified, sessionId: session }));
    return { ids, results, round1, inbox, complaints, qualified, echoes };
  }

  it('the transcript digest is canonical / order-independent (same view in any order → same digest)', () => {
    const session = sid(0xc1);
    const { round1, qualified } = honestCeremony(2, 3, session);
    const d1 = dkgTranscriptDigest({ round1Packages: round1, complaints: [], qualified, sessionId: session });
    // Reversed package order and reversed qualified order yield the SAME digest.
    const d2 = dkgTranscriptDigest({ round1Packages: [...round1].reverse(), complaints: [], qualified: [...qualified].reverse(), sessionId: session });
    expect(d2).toBe(d1);
    // A DIFFERENT qualified set yields a DIFFERENT digest.
    const d3 = dkgTranscriptDigest({ round1Packages: round1, complaints: [], qualified: qualified.slice(0, 2), sessionId: session });
    expect(d3).not.toBe(d1);
    // A different session yields a different digest.
    const d4 = dkgTranscriptDigest({ round1Packages: round1, complaints: [], qualified, sessionId: sid(0xc2) });
    expect(d4).not.toBe(d1);
  });

  it('honest run: all echoes agree and dkgFinalize derives ONE consistent group key', () => {
    const session = sid(0xc3);
    const { results, round1, inbox, complaints, qualified, echoes } = honestCeremony(2, 3, session);

    // dkgCheckEchoes agrees and reports the common digest.
    const agreement = dkgCheckEchoes(qualified, echoes, session);
    expect(agreement.agreed).toBe(true);
    expect(agreement.digest).toBe(dkgTranscriptDigest({ round1Packages: round1, complaints, qualified, sessionId: session }));

    // Every qualified party finalizes under the agreement and derives the SAME group key.
    const finals = qualified.map((id) => {
      const r = results.find((x) => x.state.identifier === id)!;
      return dkgFinalize(id, r.state, inbox.get(id)!, round1, qualified, { echoes, complaints });
    });
    const gpk = b64u(finals[0]!.groupPublicKey);
    for (const f of finals) expect(b64u(f.groupPublicKey)).toBe(gpk);

    // …and a quorum still signs a valid group-key signature (frost signing path unchanged).
    const shares = new Map<number, FrostParticipantShare>(
      finals.map((f) => [f.identifier, { identifier: f.identifier, share: f.signingShare, publicKey: f.verifyingShare }]),
    );
    const msg = utf8('agreement round — honest');
    const sig = signWithQuorum(shares, finals[0]!.groupPublicKey, [1, 2], msg);
    expect(verify(finals[0]!.groupPublicKey, msg, sig)).toBe(true);
  });

  it('equivocation (by hand): one party echoes a DIFFERENT qualified set → echoes disagree → finalize ABORTS', () => {
    const session = sid(0xc4);
    const { results, round1, inbox, complaints, qualified, echoes } = honestCeremony(2, 3, session);

    // Participant 3 was shown a divergent view: it echoes a qualified set {1,2} instead of {1,2,3}.
    const tamperedEchoes: DkgEcho[] = echoes.map((e) =>
      e.identifier === 3
        ? dkgEcho({ identifier: 3, round1Packages: round1, complaints, qualified: [1, 2], sessionId: session })
        : e,
    );

    // The disagreement is detected: not all qualified parties echoed the same transcript.
    const agreement = dkgCheckEchoes(qualified, tamperedEchoes, session);
    expect(agreement.agreed).toBe(false);
    expect(agreement.reason).toMatch(/different transcript|equivocation/i);

    // Finalize ABORTS rather than committing to an un-agreed transcript.
    const r1 = results.find((x) => x.state.identifier === 1)!;
    expect(() => dkgFinalize(1, r1.state, inbox.get(1)!, round1, qualified, { echoes: tamperedEchoes, complaints })).toThrow(
      /echo-broadcast agreement failed/,
    );
  });

  it('dkgCheckEchoes rejects a missing echo and a cross-session echo', () => {
    const session = sid(0xc5);
    const { qualified, echoes } = honestCeremony(2, 3, session);

    // Drop participant 2's echo → a qualified party has not confirmed the transcript.
    const missing = echoes.filter((e) => e.identifier !== 2);
    expect(dkgCheckEchoes(qualified, missing, session)).toMatchObject({ agreed: false });
    expect(dkgCheckEchoes(qualified, missing, session).reason).toMatch(/missing echo/i);

    // An echo bound to a different session does not count as this run's confirmation.
    const crossSession = echoes.map((e) => (e.identifier === 2 ? { ...e, sessionId: b64u(sid(0xc6)) } : e));
    expect(dkgCheckEchoes(qualified, crossSession, session)).toMatchObject({ agreed: false });
  });

  it('frostDkgSimulate wires the agreement round: honest run agrees, equivocation aborts', () => {
    // Honest: echoes are returned and all agree on the transcript.
    const dkg = frostDkgSimulate(2, 3);
    expect(dkg.echoes.length).toBe(dkg.qualified.length);
    const agree = dkgCheckEchoes(dkg.qualified, dkg.echoes, dkg.sessionId);
    expect(agree.agreed).toBe(true);
    // Exactly one group key was derived (finalize ran under agreement).
    const gpk = b64u(dkg.keyPackages[0]!.groupPublicKey);
    for (const kp of dkg.keyPackages) expect(b64u(kp.groupPublicKey)).toBe(gpk);

    // Equivocation: one party is shown a divergent qualified set → the whole run aborts at finalize.
    expect(() => frostDkgSimulate(2, 3, { equivocateEchoFor: 1 })).toThrow(/echo-broadcast agreement failed/);
  });
});
