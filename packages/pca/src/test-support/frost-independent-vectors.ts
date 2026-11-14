/**
 * Deterministic PCA FROST/DKG transcript used by the independent cross-check (tools/pca-frost-xcheck). Test-support
 * only: fixed seeds, never for keys. The committed JSON is produced by `produceVectors()` and re-derived byte for byte in
 * frost-independent.test.ts; the Rust tool re-derives it with frost-ed25519 and curve25519-dalek.
 */
import { sha512 } from '@noble/hashes/sha512';
import { frostAggregate, frostCommit, frostSign, scalarToBytes, bytesToScalar, type FrostCommitment } from '../frost';
import { frostDkgSimulate } from '../frost-dkg';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const seed = (label: string) => sha512(new TextEncoder().encode(`pca-frost-independent/${label}`));
const scalarFrom = (label: string) => scalarToBytes(bytesToScalar(seed(label)));

export interface PcaVector {
  t: number;
  n: number;
  groupPublicKey: string;
  groupCommitment: string[];
  keys: { id: number; signingShare: string; verifyingShare: string }[];
  message: string;
  signers: number[];
  nonces: { id: number; hidingRandomness: string; bindingRandomness: string; hiding: string; binding: string; hidingCommitment: string; bindingCommitment: string }[];
  sigShares: { id: number; share: string }[];
  signature: string;
}

export function produceVector(t: number, n: number): PcaVector {
  const tag = `${t}of${n}`;
  const coefficientsByParticipant = Array.from({ length: n }, (_, p) => Array.from({ length: t }, (_, k) => scalarFrom(`${tag}/coef/${p + 1}/${k}`)));
  const dkg = frostDkgSimulate(t, n, { coefficientsByParticipant, sessionId: seed(`${tag}/session`).slice(0, 32) });
  const msg = new TextEncoder().encode('pca frost independent vector: message');
  const signers = dkg.participantShares.slice(0, t);
  const rnd = signers.map((s) => ({ id: s.identifier, h: seed(`${tag}/nonce-h/${s.identifier}`).slice(0, 32), b: seed(`${tag}/nonce-b/${s.identifier}`).slice(0, 32) }));
  const commits = signers.map((s, i) => frostCommit(s, { hidingRandomness: rnd[i]!.h, bindingRandomness: rnd[i]!.b }));
  const list: FrostCommitment[] = commits.map((c) => c.commitment);
  const verificationShares = dkg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  // keep copies: frostSign zeroizes the nonce arrays in place
  const nonceJson = signers.map((s, i) => ({
    id: s.identifier,
    hidingRandomness: hex(rnd[i]!.h),
    bindingRandomness: hex(rnd[i]!.b),
    hiding: hex(commits[i]!.hidingNonce),
    binding: hex(commits[i]!.bindingNonce),
    hidingCommitment: hex(commits[i]!.commitment.hiding),
    bindingCommitment: hex(commits[i]!.commitment.binding),
  }));
  const shares = signers.map((s, i) =>
    frostSign(s.identifier, s.share, dkg.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, msg, list, { threshold: t, verificationShares }),
  );
  const sig = frostAggregate(msg, list, shares, dkg.groupPublicKey, { threshold: t, verificationShares });
  return {
    t,
    n,
    groupPublicKey: hex(dkg.groupPublicKey),
    groupCommitment: dkg.groupCommitment.map(hex),
    keys: dkg.participantShares.map((p) => ({ id: p.identifier, signingShare: hex(p.share), verifyingShare: hex(p.publicKey) })),
    message: hex(msg),
    signers: signers.map((s) => s.identifier),
    nonces: nonceJson,
    sigShares: shares.map((x) => ({ id: x.identifier, share: hex(x.sigShare) })),
    signature: hex(sig),
  };
}

export const PCA_VECTOR_SHAPES: Array<[number, number]> = [[2, 3], [3, 5]];
export function produceVectors(): { source: string; vectors: PcaVector[] } {
  return { source: 'PCA frost.ts + frost-dkg.ts, fixed seeds (test-support only)', vectors: PCA_VECTOR_SHAPES.map(([t, n]) => produceVector(t, n)) };
}
