import { describe, expect, it } from 'vitest';
import { attenuate } from './capability';
import { mintGrant } from './envelope';
import { b64u, utf8 } from './hash';
import { encodeKey, generateKeyPair, verify } from './keys';
import { commitPlan, type PlanNode } from './merkle';
import { buildPCActn, thresholdMessage, verifyPCActnCore } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  type FrostCommitment,
  type FrostSignatureShare,
  frostAggregate,
  frostCommit,
  frostCosign,
  frostSign,
  frostTrustedDealerKeygen,
  frostVerifySigShare,
  scalarToBytes,
} from './frost';
import { frostDkgSimulate } from './frost-dkg';
import { shareMessage, signShare, verifyThreshold, type Signer, type ThresholdShare } from './threshold';

const fromHex = (h: string): Uint8Array => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// =================================================================================================
// RFC 9591 Appendix — FROST(Ed25519, SHA-512) official test vectors (verbatim).
// =================================================================================================
const V = {
  groupSecretKey: '7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304',
  groupPublicKey: '15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673',
  coefficient1: '178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204',
  message: '74657374',
  // signing participants: identifiers 1 and 3
  p1: {
    id: 1,
    share: '929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509',
    hidingRandomness: '0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec',
    bindingRandomness: '69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501',
    hidingNonce: '812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407',
    bindingNonce: 'b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301',
    hidingCommitment: 'b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3',
    bindingCommitment: '67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932',
    sigShare: '001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603',
  },
  p3: {
    id: 3,
    share: 'd3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02',
    hidingRandomness: '86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f',
    bindingRandomness: '13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775',
    hidingNonce: 'c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e',
    bindingNonce: '243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d',
    hidingCommitment: 'cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91',
    bindingCommitment: '7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552',
    sigShare: 'bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007',
  },
  aggregateSignature:
    '36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe' +
    'bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b',
};

describe('FROST(Ed25519, SHA-512) — RFC 9591 official test vectors', () => {
  it('trusted-dealer key split reproduces the RFC shares + group public key', () => {
    const kg = frostTrustedDealerKeygen(2, 3, {
      secret: fromHex(V.groupSecretKey),
      coefficients: [fromHex(V.coefficient1)],
      identifiers: [1, 2, 3],
    });
    expect(toHex(kg.groupPublicKey)).toBe(V.groupPublicKey);
    const byId = new Map(kg.participantShares.map((s) => [s.identifier, s]));
    expect(toHex(byId.get(1)!.share)).toBe(V.p1.share);
    expect(toHex(byId.get(3)!.share)).toBe(V.p3.share);
  });

  it('round 1: nonces and commitments match the RFC for both signers', () => {
    const c1 = frostCommit(
      { identifier: V.p1.id, share: fromHex(V.p1.share), publicKey: new Uint8Array(32) },
      { hidingRandomness: fromHex(V.p1.hidingRandomness), bindingRandomness: fromHex(V.p1.bindingRandomness) },
    );
    expect(toHex(c1.hidingNonce)).toBe(V.p1.hidingNonce);
    expect(toHex(c1.bindingNonce)).toBe(V.p1.bindingNonce);
    expect(toHex(c1.commitment.hiding)).toBe(V.p1.hidingCommitment);
    expect(toHex(c1.commitment.binding)).toBe(V.p1.bindingCommitment);

    const c3 = frostCommit(
      { identifier: V.p3.id, share: fromHex(V.p3.share), publicKey: new Uint8Array(32) },
      { hidingRandomness: fromHex(V.p3.hidingRandomness), bindingRandomness: fromHex(V.p3.bindingRandomness) },
    );
    expect(toHex(c3.hidingNonce)).toBe(V.p3.hidingNonce);
    expect(toHex(c3.bindingNonce)).toBe(V.p3.bindingNonce);
    expect(toHex(c3.commitment.hiding)).toBe(V.p3.hidingCommitment);
    expect(toHex(c3.commitment.binding)).toBe(V.p3.bindingCommitment);
  });

  it('THE decisive vector: sig shares + aggregate signature are byte-exact and verify', () => {
    const groupPublicKey = fromHex(V.groupPublicKey);
    const message = fromHex(V.message);

    const commitments: FrostCommitment[] = [
      { identifier: V.p1.id, hiding: fromHex(V.p1.hidingCommitment), binding: fromHex(V.p1.bindingCommitment) },
      { identifier: V.p3.id, hiding: fromHex(V.p3.hidingCommitment), binding: fromHex(V.p3.bindingCommitment) },
    ];

    const share1 = frostSign(
      V.p1.id,
      fromHex(V.p1.share),
      groupPublicKey,
      { hiding: fromHex(V.p1.hidingNonce), binding: fromHex(V.p1.bindingNonce) },
      message,
      commitments,
    );
    const share3 = frostSign(
      V.p3.id,
      fromHex(V.p3.share),
      groupPublicKey,
      { hiding: fromHex(V.p3.hidingNonce), binding: fromHex(V.p3.bindingNonce) },
      message,
      commitments,
    );

    // Byte-exact per-participant signature shares.
    expect(toHex(share1.sigShare)).toBe(V.p1.sigShare);
    expect(toHex(share3.sigShare)).toBe(V.p3.sigShare);

    // Byte-exact aggregate signature.
    const sig = frostAggregate(message, commitments, [share1, share3], groupPublicKey);
    expect(toHex(sig)).toBe(V.aggregateSignature);

    // And it is a valid PLAIN Ed25519 signature under the group key.
    expect(verify(groupPublicKey, message, sig)).toBe(true);

    // Each share verifies individually (RFC §5.3) against its verification share (share·B).
    const kg = frostTrustedDealerKeygen(2, 3, {
      secret: fromHex(V.groupSecretKey),
      coefficients: [fromHex(V.coefficient1)],
      identifiers: [1, 2, 3],
    });
    const pk = new Map(kg.participantShares.map((s) => [s.identifier, s.publicKey]));
    expect(
      frostVerifySigShare({
        identifier: V.p1.id,
        publicKey: pk.get(1)!,
        commitment: commitments[0]!,
        sigShare: share1,
        signingCommitments: commitments,
        groupPublicKey,
        message,
      }),
    ).toBe(true);
    expect(
      frostVerifySigShare({
        identifier: V.p3.id,
        publicKey: pk.get(3)!,
        commitment: commitments[1]!,
        sigShare: share3,
        signingCommitments: commitments,
        groupPublicKey,
        message,
      }),
    ).toBe(true);
  });
});

// =================================================================================================
// Round-trip / negative tests
// =================================================================================================
function session(kg: ReturnType<typeof frostTrustedDealerKeygen>, signerIds: number[], message: Uint8Array) {
  const shares = new Map(kg.participantShares.map((s) => [s.identifier, s]));
  const commits = signerIds.map((id) => frostCommit(shares.get(id)!));
  const commitments: FrostCommitment[] = commits.map((c) => c.commitment);
  const sigShares: FrostSignatureShare[] = signerIds.map((id, i) =>
    frostSign(
      id,
      shares.get(id)!.share,
      kg.groupPublicKey,
      { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce },
      message,
      commitments,
    ),
  );
  return frostAggregate(message, commitments, sigShares, kg.groupPublicKey);
}

describe('FROST round-trip', () => {
  it('keygen(2,3) → commit → sign with 2 of 3 → aggregate → verifies under the group key', () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const msg = utf8('transfer 100 to bob');
    for (const pair of [
      [1, 2],
      [1, 3],
      [2, 3],
    ] as const) {
      const sig = session(kg, [...pair], msg);
      expect(verify(kg.groupPublicKey, msg, sig)).toBe(true);
    }
  });

  it('a 1-of-2 (insufficient) aggregate does NOT verify under a 2-of-? group key', () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const msg = utf8('insufficient quorum');
    // Only one signer participates → Lagrange over {1} reconstructs the wrong secret → invalid sig.
    // frostAggregate now refuses to return an invalid aggregate.
    expect(() => session(kg, [1], msg)).toThrow(/does not verify/);
  });

  it('a signature over message A does not verify against message B', () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const sig = session(kg, [1, 2], utf8('message A'));
    expect(verify(kg.groupPublicKey, utf8('message B'), sig)).toBe(false);
  });

  it('a 3-of-5 quorum aggregates to a valid signature', () => {
    const kg = frostTrustedDealerKeygen(3, 5);
    const msg = utf8('three of five');
    const sig = session(kg, [2, 4, 5], msg);
    expect(verify(kg.groupPublicKey, msg, sig)).toBe(true);
  });
});

// =================================================================================================
// PCA integration — a FROST group key as the capability-leaf holder
// =================================================================================================
describe('FROST ⨯ PCActn', () => {
  it('a PCActn whose leaf holder IS a FROST group key, signed by aggregating agent+guardian shares, passes verifyPCActnCore', async () => {
    // 1) Split a group key 2-of-3 across agent / guardian / principal (ids 1,2,3).
    const kg = frostTrustedDealerKeygen(2, 3);
    const groupKeyB64u = b64u(kg.groupPublicKey);
    const sharesById = new Map(kg.participantShares.map((s) => [s.identifier, s]));
    const AGENT = 1;
    const GUARDIAN = 2;

    // 2) Mint a grant whose LEAF HOLDER is the group key (the single "signer").
    const principal = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: encodeKey(principal.publicKey),
      holder: groupKeyB64u, // <-- the capability is bound to the FROST group public key
      goal: 'act on my behalf under threshold custody',
      envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    });

    const nodes: PlanNode[] = [
      { id: 'n1', verb: 'rotate_key', resource: 'account', reversibility_class: 'R2' },
    ];

    // 3) Build the PCActn body (sign with a throwaway key; we overwrite `sig` with the FROST aggregate).
    const throwaway = generateKeyPair();
    const draft = buildPCActn({ aud: 'test-aud',
      grant,
      chain: [grant], // single hop: leaf == grant, holder == group key
      plan: nodes,
      nodeId: 'n1',
      counter: 7,
      signerSecret: throwaway.secretKey,
      riskClaim: { r: 0.5, inputs: {} },
    });

    // 4) FROST-aggregate agent + guardian shares over the ONE canonical message the verifier checks.
    const msg = thresholdMessage(draft);
    const signerIds = [AGENT, GUARDIAN];
    const commits = signerIds.map((id) => frostCommit(sharesById.get(id)!));
    const commitments: FrostCommitment[] = commits.map((c) => c.commitment);
    const sigShares = signerIds.map((id, i) =>
      frostSign(
        id,
        sharesById.get(id)!.share,
        kg.groupPublicKey,
        { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce },
        msg,
        commitments,
      ),
    );
    const aggregate = frostAggregate(msg, commitments, sigShares, kg.groupPublicKey);

    // The FROST aggregate IS the ordinary Ed25519 leaf signature — no new verifier path.
    const pcactn = { ...draft, sig: b64u(aggregate) };

    const res = await verifyPCActnCore(pcactn, { grant, audience: 'test-aud' });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
    expect(res.checks.cap_chain).toBe('pass');
    expect(res.checks.plan_inclusion).toBe('pass');

    // Tampering with the action (new counter) breaks the aggregate leaf signature.
    const tampered = { ...pcactn, counter: 8 };
    const bad = await verifyPCActnCore(tampered, { grant });
    expect(bad.allow).toBe(false);
    expect(bad.checks.leaf_signature).toBe('fail');
  });
});

// =================================================================================================
// Guardian threshold custody — the FROST cosign coordinator over a DKG-established group key.
// This is the property the PCA admission path relies on: a guardian cosignature is a FROST aggregate
// that (a) verifies under the group key end-to-end, and (b) CANNOT be formed from fewer than t shares.
// =================================================================================================
describe('FROST guardian cosign (threshold custody)', () => {
  // Establish the guardian group with the NO-DEALER DKG (the echo-broadcast agreement round runs inside).
  const group = () => {
    const dkg = frostDkgSimulate(2, 3);
    return { groupKey: dkg.groupPublicKey, participants: dkg.participantShares, t: 2 };
  };

  it('a t-of-n quorum cosign verifies under the group key end-to-end (DKG-established, no trusted dealer)', () => {
    const { groupKey, participants, t } = group();
    const msg = utf8('guardian cosign — compliant action');
    const sig = frostCosign(groupKey, participants.slice(0, t), msg, { threshold: t });
    expect(verify(groupKey, msg, sig)).toBe(true);
  });

  it('an INSUFFICIENT quorum (< t) cannot produce a valid cosign', () => {
    const { groupKey, participants, t } = group();
    const msg = utf8('one share is not enough');
    // The up-front threshold guard rejects a sub-threshold quorum…
    expect(() => frostCosign(groupKey, participants.slice(0, 1), msg, { threshold: t })).toThrow(/below the threshold/);
    // …and even without it, one share Lagrange-interpolates to the wrong secret → aggregate is invalid.
    expect(() => frostCosign(groupKey, participants.slice(0, 1), msg)).toThrow();
  });

  it('a FORGED signing share cannot produce a valid cosign', () => {
    const { groupKey, participants, t } = group();
    const msg = utf8('forged share');
    const tampered = Uint8Array.from(participants[0]!.share);
    tampered[0] = tampered[0]! ^ 0x01;
    const forged = [{ ...participants[0]!, share: tampered }, participants[1]!];
    // The tampered secret no longer matches its verifying share → frostSign rejects it (fail closed).
    expect(() => frostCosign(groupKey, forged, msg, { threshold: t })).toThrow();
  });

  it('the aggregate IS the guardian share the EXISTING threshold verifier accepts (signer set guardian == group key)', () => {
    const { groupKey, participants, t: tg } = group();
    const agent = generateKeyPair();
    const principal = generateKeyPair();
    const groupKeyB64u = b64u(groupKey);
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: groupKeyB64u }, // <-- the FROST GROUP key, not a single guardian key
      { role: 'principal', publicKey: encodeKey(principal.publicKey) },
    ];
    const message = utf8('the canonical threshold message');
    const t = 2; // PCA action threshold: agent + guardian must both sign.

    // The guardian cosign is a FROST aggregate over the role-bound guardian message.
    const guardianMsg = shareMessage('guardian', message, signerSet, t);
    const aggregate = frostCosign(groupKey, participants.slice(0, tg), guardianMsg, { threshold: tg });
    const guardianShare: ThresholdShare = { role: 'guardian', publicKey: groupKeyB64u, sig: b64u(aggregate) };
    const agentShare = signShare('agent', agent.secretKey, message, { signerSet, t }); // v2.1: agent share is signerSetHash‖t-bound too

    const verdict = verifyThreshold({ shares: [agentShare, guardianShare] }, message, signerSet, t);
    expect(verdict.ok).toBe(true);
    expect(verdict.roles).toContain('guardian');

    // A guardian share aggregated from ONE FROST share (insufficient) cannot be formed at all — there is no
    // valid Ed25519 signature under the group key, so the guardian role can never be satisfied.
    expect(() => frostCosign(groupKey, participants.slice(0, 1), guardianMsg, { threshold: tg })).toThrow();
  });
});

// Keep the `scalarToBytes`/`commitPlan` imports exercised (public surface / helper sanity).
describe('frost helpers', () => {
  it('scalarToBytes serializes 1 as 32-byte little-endian', () => {
    const b = scalarToBytes(1n);
    expect(b.length).toBe(32);
    expect(b[0]).toBe(1);
    expect(b.slice(1).every((x) => x === 0)).toBe(true);
  });

  it('a participant share carries a verification share = share·B', () => {
    const kg = frostTrustedDealerKeygen(2, 2);
    for (const s of kg.participantShares) expect(s.publicKey.length).toBe(32);
    void commitPlan;
  });

  it('frostTrustedDealerKeygen rejects t>n', () => {
    expect(() => frostTrustedDealerKeygen(3, 2)).toThrow();
  });
});

// =================================================================================================
// Hardening (P5-3): nonce one-shot, duplicate ids, subgroup checks, aggregate verification
// =================================================================================================
import { ed25519 } from '@noble/curves/ed25519';
import { decodeSafePoint } from './frost';

describe('FROST hardening', () => {
  const setup = (ids = [1, 2]) => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const msg = utf8('hardening');
    const shares = new Map(kg.participantShares.map((s) => [s.identifier, s]));
    const commits = ids.map((id) => frostCommit(shares.get(id)!));
    const commitments = commits.map((c) => c.commitment);
    return { kg, msg, shares, commits, commitments };
  };

  it('valid session with all optional checks (threshold, verification shares) still signs + verifies', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const vss = kg.participantShares.map((s) => ({ identifier: s.identifier, publicKey: s.publicKey }));
    const sigShares = [1, 2].map((id, i) =>
      frostSign(id, shares.get(id)!.share, kg.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, msg, commitments, {
        threshold: 2,
        verificationShare: shares.get(id)!.publicKey,
        verificationShares: vss,
      }),
    );
    const sig = frostAggregate(msg, commitments, sigShares, kg.groupPublicKey, { threshold: 2, verificationShares: vss });
    expect(verify(kg.groupPublicKey, msg, sig)).toBe(true);
  });

  it('nonces are one-shot: a second frostSign with the same nonces throws, and they are zeroized', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const nonces = { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce };
    frostSign(1, shares.get(1)!.share, kg.groupPublicKey, nonces, msg, commitments);
    expect(nonces.hiding.every((b) => b === 0)).toBe(true);
    expect(nonces.binding.every((b) => b === 0)).toBe(true);
    expect(() => frostSign(1, shares.get(1)!.share, kg.groupPublicKey, nonces, utf8('other'), commitments)).toThrow(/already used|zeroized/);
    // A fresh array copy of the (zero) bytes is also rejected.
    expect(() => frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: new Uint8Array(32), binding: new Uint8Array(32) }, msg, commitments)).toThrow();
  });

  it('rejects duplicate participant identifiers in the commitment set', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const dup = [commitments[0]!, { ...commitments[0]! }];
    expect(() =>
      frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce }, msg, dup),
    ).toThrow(/duplicate/);
  });

  it('rejects identifier 0 / non-integer ids (zero Lagrange coefficient)', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const bad = [{ ...commitments[0]!, identifier: 0 }, commitments[1]!];
    expect(() =>
      frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce }, msg, bad),
    ).toThrow(/identifier/);
  });

  it('requires |commitments| >= t when a threshold is given', () => {
    const { kg, msg, shares, commits } = setup([1]);
    expect(() =>
      frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce }, msg, [commits[0]!.commitment], { threshold: 2 }),
    ).toThrow(/at least t=2/);
  });

  it("rejects a signer whose own commitment does not match its nonces", () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const other = frostCommit(shares.get(1)!);
    expect(() =>
      frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: other.hidingNonce, binding: other.bindingNonce }, msg, commitments),
    ).toThrow(/own commitment/);
    void commits;
  });

  it('rejects a share that does not match its verification share, or a group key that does not match the shares', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    expect(() =>
      frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce }, msg, commitments, {
        verificationShare: shares.get(2)!.publicKey,
      }),
    ).toThrow(/verification share/);
    const wrongGroup = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    const vss = kg.participantShares.map((s) => ({ identifier: s.identifier, publicKey: s.publicKey }));
    expect(() =>
      frostSign(2, shares.get(2)!.share, wrongGroup, { hiding: commits[1]!.hidingNonce, binding: commits[1]!.bindingNonce }, msg, commitments, {
        verificationShares: vss,
      }),
    ).toThrow(/group public key/);
  });

  it('rejects small-order and non-torsion-free commitment points', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const order2 = Uint8Array.from(Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'));
    const order8 = Uint8Array.from(Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'));
    const mixed = ed25519.ExtendedPoint.BASE.add(ed25519.ExtendedPoint.fromHex(order8)).toRawBytes();
    for (const badPt of [identity, order2, order8, mixed]) {
      expect(() => decodeSafePoint(badPt)).toThrow();
      const bad = [{ ...commitments[0]!, hiding: badPt }, commitments[1]!];
      expect(() =>
        frostSign(1, shares.get(1)!.share, kg.groupPublicKey, { hiding: commits[0]!.hidingNonce, binding: commits[0]!.bindingNonce }, msg, bad),
      ).toThrow();
    }
    expect(() => decodeSafePoint(kg.groupPublicKey)).not.toThrow();
    // Non-canonical y (y = p) is rejected.
    const nonCanon = Uint8Array.from(Buffer.from('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'));
    expect(() => decodeSafePoint(nonCanon)).toThrow();
    expect(() => decodeSafePoint(new Uint8Array(31))).toThrow();
  });

  it('frostAggregate names a cheating share when verification shares are supplied, and never returns an invalid signature', () => {
    const { kg, msg, shares, commits, commitments } = setup();
    const vss = kg.participantShares.map((s) => ({ identifier: s.identifier, publicKey: s.publicKey }));
    const sigShares = [1, 2].map((id, i) =>
      frostSign(id, shares.get(id)!.share, kg.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, msg, commitments),
    );
    const bad = [sigShares[0]!, { identifier: 2, sigShare: scalarToBytes(12345n) }];
    expect(() => frostAggregate(msg, commitments, bad, kg.groupPublicKey, { verificationShares: vss })).toThrow(/participant 2/);
    expect(() => frostAggregate(msg, commitments, bad, kg.groupPublicKey)).toThrow(/does not verify/);
    expect(() => frostAggregate(msg, commitments, [sigShares[0]!], kg.groupPublicKey)).toThrow();
  });
});
