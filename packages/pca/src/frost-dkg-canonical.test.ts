/**
 * Canonical-encoding audit of the FROST DKG wire fields. These strings are hashed into the echo-broadcast
 * transcript (`round1PackageDigest` / `complaintDigest`), so each semantic value must have exactly ONE
 * accepted encoding; otherwise one package could be given many accepted forms with different transcript
 * digests (equivocation / dedupe aliasing). Aliases tested: non-canonical base64url trailing bits, and
 * non-reduced scalars (s + L) that `bytesToScalar` silently reduces.
 */
import { describe, expect, it } from 'vitest';
import { b64u, unb64u } from './hash';
import { L } from './frost';
import {
  type DkgRound1Package,
  dkgRound1,
  dkgRound2,
  dkgVerifyRound1,
  dkgVerifyShare,
} from './frost-dkg';

const session = new Uint8Array(32).fill(7);
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Same 32 bytes, different (non-canonical) base64url: flip a trailing pad bit of the last char. */
function aliasTrailingBits(s: string): string {
  const last = B64.indexOf(s[s.length - 1]!);
  return s.slice(0, -1) + B64[last | 1]!; // 43 chars: the low 2 bits of the last char are padding
}
function addL(b: Uint8Array): Uint8Array {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  x += L;
  const o = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) {
    o[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return o;
}

describe('DKG round-1 package: one encoding per value', () => {
  const r = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
  const pkg = r[0]!.package;
  it('baseline verifies', () => expect(dkgVerifyRound1(1, pkg, session)).toBe(true));

  it('rejects a PoP scalar mu + L (non-reduced alias)', () => {
    const bad: DkgRound1Package = { ...pkg, proofOfKnowledge: { ...pkg.proofOfKnowledge, mu: b64u(addL(unb64u(pkg.proofOfKnowledge.mu))) } };
    expect(dkgVerifyRound1(1, bad, session)).toBe(false);
  });
  it('rejects non-canonical base64url trailing bits on commitments, R and mu', () => {
    const c0 = pkg.coefficientCommitments;
    const variants: DkgRound1Package[] = [
      { ...pkg, coefficientCommitments: [aliasTrailingBits(c0[0]!), ...c0.slice(1)] },
      { ...pkg, proofOfKnowledge: { ...pkg.proofOfKnowledge, R: aliasTrailingBits(pkg.proofOfKnowledge.R) } },
      { ...pkg, proofOfKnowledge: { ...pkg.proofOfKnowledge, mu: aliasTrailingBits(pkg.proofOfKnowledge.mu) } },
    ];
    for (const v of variants) {
      expect(dkgVerifyRound1(1, v, session)).toBe(false);
    }
  });
});

describe('DKG share signature: one encoding', () => {
  const r = [1, 2, 3].map((id) => dkgRound1(id, 2, 3, session));
  const pkgs = r.map((x) => x.package);
  const shares = dkgRound2(r[0]!.state, pkgs);
  const s = shares.find((x) => x.to === 2)!;
  it('baseline verifies', () => expect(dkgVerifyShare(s, pkgs[0]!, 2, session)).toBe(true));
  it('rejects a signature scalar s + L', () => {
    const raw = unb64u(s.sig);
    const bad = new Uint8Array(raw);
    bad.set(addL(raw.subarray(32, 64)), 32);
    expect(dkgVerifyShare({ ...s, sig: b64u(bad) }, pkgs[0]!, 2, session)).toBe(false);
  });
  it('rejects a share scalar encoded as share + L (re-signed alias is out of range)', () => {
    expect(dkgVerifyShare({ ...s, share: addL(s.share) }, pkgs[0]!, 2, session)).toBe(false);
  });
});

describe('FROST signing-side scalars: one encoding', () => {
  it('signer PoP rejects s + L; signature share rejects z + L', async () => {
    const { frostTrustedDealerKeygen, frostCommit, frostSign, frostVerifySigShare } = await import('./frost');
    const { createSignerPoP, verifySignerPoP } = await import('./frost-net');
    const kg = frostTrustedDealerKeygen(2, 3);
    const sh = kg.participantShares[0]!;
    const pop = createSignerPoP(sh.identifier, sh.share, { groupPublicKey: kg.groupPublicKey });
    expect(verifySignerPoP(pop, { groupPublicKey: kg.groupPublicKey })).toBe(true);
    expect(verifySignerPoP({ ...pop, s: b64u(addL(unb64u(pop.s))) }, { groupPublicKey: kg.groupPublicKey })).toBe(false);

    const msg = new Uint8Array([1, 2, 3]);
    const parts = kg.participantShares.slice(0, 2);
    const cs = parts.map((x) => frostCommit(x));
    const list = cs.map((x) => x.commitment);
    const z = frostSign(parts[0]!.identifier, parts[0]!.share, kg.groupPublicKey, { hiding: cs[0]!.hidingNonce, binding: cs[0]!.bindingNonce }, msg, list);
    const args = {
      identifier: z.identifier,
      publicKey: parts[0]!.publicKey,
      commitment: list[0]!,
      signingCommitments: list,
      groupPublicKey: kg.groupPublicKey,
      message: msg,
    };
    expect(frostVerifySigShare({ ...args, sigShare: z })).toBe(true);
    expect(frostVerifySigShare({ ...args, sigShare: { ...z, sigShare: addL(z.sigShare) } })).toBe(false);
  });
});

describe('Ed25519 hop signature: one encoding (capHash covers the signature)', () => {
  it('rejects S + L, a sign-flipped R and non-canonical base64url', async () => {
    const { generateKeyPair, sign, verify, verifyB64u } = await import('./keys');
    const kp = generateKeyPair();
    const msg = new Uint8Array([9, 9]);
    const sig = sign(kp.secretKey, msg);
    expect(verify(kp.publicKey, msg, sig)).toBe(true);
    const alias = sig.slice();
    alias.set(addL(sig.subarray(32)), 32);
    expect(verify(kp.publicKey, msg, alias)).toBe(false);
    const sg = b64u(sig);
    expect(verifyB64u(b64u(kp.publicKey), msg, sg)).toBe(true);
    expect(verifyB64u(b64u(kp.publicKey), msg, aliasTrailingBits(sg))).toBe(false);
    expect(verifyB64u(b64u(kp.publicKey), msg, sg + '=')).toBe(false);
  });
});
