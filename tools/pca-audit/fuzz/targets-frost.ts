/**
 * Fuzz targets for the FROST wire surface: the networked-signing request decoders and signer service (frost-net), the
 * allow-token and signer proof-of-possession verifiers, the DKG protocol verifiers, and the DKG channel envelope and body
 * decoders (frost-dkg-channel). Seeds are real valid messages from a fixed-seed 2-of-3 group and a real DKG transcript (all keys derived from labels, so the corpus is reproducible), so
 * mutation starts from bytes that parse. The contract under test: every one of these is total on hostile input (a typed
 * refusal or a boolean, never an untyped runtime error, a hang or an over-allocation), and a verifier never accepts a
 * mutated message.
 */
import { ed25519 } from '../../../packages/pca/node_modules/@noble/curves/ed25519.js';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { b64u } from '../../../packages/pca/src/hash';
import { frostTrustedDealerKeygen } from '../../../packages/pca/src/frost';
import {
  GuardianSignerService, createSignerPoP, decodeCommitment, decodeCommitments, decodeVerificationShares, issueAllowToken, verifyAllowToken, verifySignerPoP,
  type Round2Request,
} from '../../../packages/pca/src/frost-net';
import {
  dkgCheckEchoes, dkgEcho, dkgFileComplaint, dkgRound1, dkgRound2, dkgVerifyComplaint, dkgVerifyRound1, dkgVerifyShare,
} from '../../../packages/pca/src/frost-dkg';
import {
  DkgInbox, decodeDkgComplaints, decodeDkgEcho, decodeDkgMessage, decodeDkgRebuttals, decodeDkgRound1Package, decodeDkgShareMessage, encodeDkgMessage,
} from '../../../packages/pca/src/frost-dkg-channel';
import { anyTyped, mutateBytes, mutateJson, neverThrows, projectOnto } from './lib';
import type { Target } from './targets-core';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const jsonT = <C>(name: string, seed: () => C, run: (c: C) => unknown, allow: Target['allow'], check?: Target<C>['check']): Target<C> => ({
  name, allow, check, seeds: () => [seed()], mutate: (r, c) => mutateJson(r, c) as C, run,
});
/** A verifier that returns a boolean must only return true for the unmutated message (unknown extra members are tolerated by design). */
const acceptsOnlySeed = <C>(seed: C, what: string): Target<C>['check'] => (c, res) =>
  res === true && JSON.stringify(projectOnto(seed, c)) !== JSON.stringify(seed) ? `${what} ACCEPTED a mutated message` : undefined;

/** Every seed key, nonce and coefficient below is a fixed function of a label, so the seed corpus is byte-reproducible. */
export const det = (label: string): Uint8Array => new Uint8Array(createHash('sha256').update(`pca-fuzz-frost-seed/${label}`).digest());

const ZERO32 = 'A'.repeat(43);
const SID = new TextEncoder().encode('fuzz-dkg-session-0123456789abcdef');

export function frostTargets(): Target<any>[] {
  const t: Target<any>[] = [];
  const kg = frostTrustedDealerKeygen(2, 3, { secret: det('dealer/secret'), coefficients: [det('dealer/a1')] });
  const authority = det('authority');
  const authorityPk = ed25519.getPublicKey(authority);
  const message = new TextEncoder().encode('fuzz message');
  const NOW = 1_700_000_000_000;
  const allow = issueAllowToken(authority, { message, groupPublicKey: kg.groupPublicKey, nonce: 'fuzz', expiresAt: NOW + 60_000 });
  const share1 = kg.participantShares[0]!;
  const wireCommit = (i: number) => ({ identifier: i, hiding: b64u(kg.participantShares[i - 1]!.publicKey), binding: b64u(kg.participantShares[(i % 3)]!.publicKey) });
  const wireVs = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: b64u(p.publicKey) }));

  // ---- frost-net wire decoders ---------------------------------------------------------------------------------------
  t.push(jsonT('frost-net decodeCommitment', () => wireCommit(1), (c) => decodeCommitment(c as never), anyTyped));
  t.push(jsonT('frost-net decodeCommitments', () => [wireCommit(1), wireCommit(2)], (c) => decodeCommitments(c as never), anyTyped));
  t.push(jsonT('frost-net decodeVerificationShares', () => wireVs, (c) => decodeVerificationShares(c as never), anyTyped));
  t.push({
    name: 'frost-net decodeCommitments (oversize list is refused, not decoded)', allow: anyTyped,
    seeds: () => [{ n: 4 }],
    mutate: (r) => ({ n: Math.floor(r() * 3000) }),
    run: (c: { n: number }) => decodeCommitments(Array.from({ length: Math.min(c.n, 5000) }, () => wireCommit(1))),
    check: (c, res) => (c.n > 256 && Array.isArray(res) ? 'decodeCommitments accepted a list above the maximum signing set' : undefined),
  });

  // ---- allow token + signer proof-of-possession verifiers ---------------------------------------------------------------------
  t.push(jsonT('frost-net verifyAllowToken', () => clone(allow), (c) => verifyAllowToken(c, { policyAuthorityPublicKey: authorityPk, groupPublicKey: kg.groupPublicKey, message, now: NOW }).ok, neverThrows, acceptsOnlySeed(clone(allow), 'verifyAllowToken')));
  const pop = createSignerPoP(share1.identifier, share1.share, { groupPublicKey: kg.groupPublicKey, nonce: det('pop-nonce') });
  t.push(jsonT('frost-net verifySignerPoP', () => clone(pop), (c) => verifySignerPoP(c, { groupPublicKey: kg.groupPublicKey }), neverThrows, acceptsOnlySeed(clone(pop), 'verifySignerPoP')));

  // ---- the guardian signer's request validation (round 1 and round 2) -----------------------------------------------------------
  const mkService = () =>
    new GuardianSignerService({ identifier: 1, share: share1.share, groupPublicKey: kg.groupPublicKey, threshold: 2, policyAuthorityPublicKey: authorityPk, now: () => NOW });
  const okShape = (res: unknown): string | undefined =>
    res && typeof res === 'object' && typeof (res as { ok: unknown }).ok === 'boolean' ? undefined : 'signer returned a response without a boolean ok';
  t.push(jsonT('frost-net signer round1 (mutated request)', () => ({ typ: 'pca.frost.round1.v1', session_id: 'fuzz-session' }), (c) => mkService().round1(c as never), neverThrows, (_c, res) => okShape(res)));
  const req2: Round2Request = {
    typ: 'pca.frost.round2.v1', session_id: 'fuzz-session', message: b64u(message), group_pk: b64u(kg.groupPublicKey),
    commitments: [{ identifier: 1, hiding: ZERO32, binding: ZERO32 }, wireCommit(2)], verification_shares: wireVs.slice(0, 2), allow: clone(allow),
  };
  t.push(jsonT('frost-net signer round2 (mutated request)', () => clone(req2), (c) => {
    const svc = mkService();
    const r1 = svc.round1({ typ: 'pca.frost.round1.v1', session_id: 'fuzz-session' });
    if (!r1.ok) throw new Error('fuzz setup: round1 failed');
    // our own commitment is random per run: patch it into the placeholder entry so the mutation, not the setup, decides the outcome
    const req = c as Round2Request;
    if (Array.isArray(req.commitments)) for (const e of req.commitments) if (e && e.hiding === ZERO32 && e.binding === ZERO32) Object.assign(e, r1.commitment);
    return svc.round2(req);
  }, neverThrows, (_c, res) => okShape(res)));

  // ---- DKG protocol verifiers ----------------------------------------------------------------------------------------------------
  const dkgOpts = (i: number) => ({ coefficients: [det(`dkg/${i}/a0`), det(`dkg/${i}/a1`)], popNonce: det(`dkg/${i}/pop`) });
  const pkg1 = clone(dkgRound1(1, 2, 3, SID, dkgOpts(1)).package);
  t.push(jsonT('frost-dkg dkgVerifyRound1', () => clone(pkg1), (c) => dkgVerifyRound1(1, c as never, SID), neverThrows, acceptsOnlySeed(clone(pkg1), 'dkgVerifyRound1')));
  const states = [1, 2, 3].map((i) => dkgRound1(i, 2, 3, SID, dkgOpts(i)));
  const pkgs = states.map((s) => s.package);
  const share = dkgRound2(states[1]!.state, pkgs).find((s) => s.to === 1)!;
  const shareWire = { from: share.from, share: b64u(share.share), sig: share.sig };
  t.push(jsonT('frost-dkg dkgVerifyShare', () => ({ share: shareWire, pkg: clone(pkgs[1]!) }), (c: { share: { from: number; share: string; sig: string }; pkg: never }) => {
    const s = c.share;
    const bytes = typeof s?.share === 'string' ? new Uint8Array(Buffer.from(s.share, 'base64url')) : (s?.share as never);
    return dkgVerifyShare({ ...s, share: bytes }, c.pkg, 1, SID);
  }, neverThrows, acceptsOnlySeed({ share: shareWire, pkg: clone(pkgs[1]!) }, 'dkgVerifyShare')));
  const complaint = dkgFileComplaint({ accused: 2, accuser: 1, receivedShare: share.share, shareSig: share.sig, senderCommitments: pkgs[1]!.coefficientCommitments, sessionId: SID });
  t.push(jsonT('frost-dkg dkgVerifyComplaint (never throws)', () => ({ complaint: clone(complaint), pkgs: clone(pkgs) }), (c: { complaint: never; pkgs: never }) => dkgVerifyComplaint(c.complaint, c.pkgs), neverThrows, (_c, res) => (res && typeof res === 'object' && typeof (res as { justified: unknown }).justified === 'boolean' ? undefined : 'verdict without a boolean justified')));
  const echoes = [1, 2, 3].map((id) => dkgEcho({ identifier: id, round1Packages: pkgs, complaints: [], qualified: [1, 2, 3], sessionId: SID }));
  t.push(jsonT('frost-dkg dkgCheckEchoes (never throws)', () => clone(echoes), (c) => dkgCheckEchoes([1, 2, 3], c as never, SID), neverThrows, (c, res) => ((res as { agreed: boolean }).agreed && JSON.stringify(projectOnto(echoes, c)) !== JSON.stringify(echoes) ? 'dkgCheckEchoes AGREED on a mutated echo set' : undefined)));

  // ---- DKG channel envelope and body decoders ----------------------------------------------------------------------------------
  const wirePkg = clone(pkgs[0]!);
  const envBytes = encodeDkgMessage(SID, 'round1', wirePkg);
  t.push({
    name: 'frost-dkg-channel decodeDkgMessage (mutated envelope bytes)', allow: anyTyped,
    seeds: () => [{ b64: Buffer.from(envBytes).toString('base64') }],
    mutate: (r, c) => ({ b64: Buffer.from(mutateBytes(r, new Uint8Array(Buffer.from(c.b64, 'base64')))).toString('base64') }),
    run: (c: { b64: string }) => decodeDkgMessage(new Uint8Array(Buffer.from(c.b64, 'base64')), SID),
  });
  t.push(jsonT('frost-dkg-channel decodeDkgRound1Package', () => clone(wirePkg), (c) => decodeDkgRound1Package(c, 2), anyTyped));
  t.push(jsonT('frost-dkg-channel decodeDkgShareMessage', () => ({ from: share.from, to: share.to, sessionId: share.sessionId, share: b64u(share.share), sig: share.sig }), decodeDkgShareMessage, anyTyped));
  t.push(jsonT('frost-dkg-channel decodeDkgComplaints / decodeDkgRebuttals', () => ({ complaints: [clone(complaint)], rebuttals: [] }), (c) => [decodeDkgComplaints(c), decodeDkgRebuttals(c)], anyTyped));
  t.push(jsonT('frost-dkg-channel decodeDkgEcho', () => clone(echoes[0]!), decodeDkgEcho, anyTyped));
  t.push({
    name: 'frost-dkg-channel DkgInbox (mutated message: accepted, or a sticky typed peer error)', allow: neverThrows,
    seeds: () => [{ b64: Buffer.from(envBytes).toString('base64') }],
    mutate: (r, c) => ({ b64: Buffer.from(mutateBytes(r, new Uint8Array(Buffer.from(c.b64, 'base64')))).toString('base64') }),
    run: async (c: { b64: string }) => {
      const inbox = new DkgInbox(SID, [2]);
      inbox.accept(2, new Uint8Array(Buffer.from(c.b64, 'base64')));
      inbox.accept(2, new Uint8Array(Buffer.from(c.b64, 'base64'))); // the replay must never be a second accepted message
      try {
        await inbox.collect('round1', [2], 0);
        return 'accepted';
      } catch (e) {
        return (e as { code?: string }).code ?? 'untyped';
      }
    },
    check: (_c, res) => (res === 'accepted' || res === 'untyped' ? `a duplicated message was ${res === 'accepted' ? 'accepted' : 'refused without a typed code'}` : undefined),
  });
  return t;
}
