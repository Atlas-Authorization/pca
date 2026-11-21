import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { frostAggregate, frostSign, frostVerifyingShare, type FrostCommitment } from './frost';
import { produceVectors, type PcaVector } from './test-support/frost-independent-vectors';

// Vectors from independent implementations. Provenance:
//  - zf-dkg-vectors.json: the Zcash Foundation frost-ed25519 3.0.0 crate ran its OWN DKG (keys::dkg) and a signing round
//    with recorded nonces (tools/pca-frost-xcheck, `gen-zf`). PCA must reproduce its signature shares and aggregate.
//  - pca-dkg-vectors.json: PCA's DKG + signing (fixed seeds). The same tool re-derives it with ZF and curve25519-dalek
//    (`check-pca`): group key == Phi_0, verifying shares == sum Phi_k j^k, ZF shares and aggregate byte-equal.
const dir = resolve(__dirname, '..', 'testdata', 'frost-independent');
const load = (f: string) => JSON.parse(readFileSync(resolve(dir, f), 'utf8'));
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('PCA transcript is reproduced byte for byte', () => {
  it('matches the committed vectors the independent tool checked', () => {
    expect(produceVectors()).toEqual(load('pca-dkg-vectors.json'));
  });
  it('every committed PCA vector verifies as a plain Ed25519 signature under the DKG group key', () => {
    for (const v of load('pca-dkg-vectors.json').vectors as PcaVector[]) {
      expect(ed25519.verify(unhex(v.signature), unhex(v.message), unhex(v.groupPublicKey), { zip215: false })).toBe(true);
    }
  });
});

interface ZfVector {
  t: number; n: number; groupPublicKey: string; message: string; signers: number[]; signature: string;
  keys: { id: number; signingShare: string; verifyingShare: string }[];
  nonces: { id: number; hiding: string; binding: string; hidingCommitment: string; bindingCommitment: string }[];
  sigShares: { id: number; share: string }[];
}
const zf = load('zf-dkg-vectors.json').vectors as ZfVector[];

describe('signing with key material from an independent DKG (frost-ed25519)', () => {
  it('has the expected shapes', () => expect(zf.map((v) => [v.t, v.n])).toEqual([[2, 3], [3, 5]]));
  for (const v of zf) {
    const vss = v.keys.map((k) => ({ identifier: k.id, publicKey: unhex(k.verifyingShare) }));
    const commits = (): FrostCommitment[] => v.nonces.map((n) => ({ identifier: n.id, hiding: unhex(n.hidingCommitment), binding: unhex(n.bindingCommitment) }));
    // Nonces are one-shot (the guard is process-wide and content-based): sign once, reuse the shares.
    let memo: ReturnType<typeof frostSign>[] | undefined;
    const signAll = () => (memo ??= v.nonces.map((n) => {
        const key = v.keys.find((k) => k.id === n.id)!;
        return frostSign(n.id, unhex(key.signingShare), unhex(v.groupPublicKey), { hiding: unhex(n.hiding), binding: unhex(n.binding) }, unhex(v.message), commits(), { threshold: v.t, verificationShares: vss });
      }));
    it(`${v.t}-of-${v.n}: verifying shares are share*B`, () => {
      for (const k of v.keys) expect(hex(frostVerifyingShare(unhex(k.signingShare)))).toBe(k.verifyingShare);
    });
    it(`${v.t}-of-${v.n}: signature shares equal the independent implementation's`, () => {
      expect(signAll().map((s) => ({ id: s.identifier, share: hex(s.sigShare) }))).toEqual(v.sigShares);
    });
    it(`${v.t}-of-${v.n}: aggregate equals the independent signature and verifies as Ed25519`, () => {
      const sig = frostAggregate(unhex(v.message), commits(), signAll(), unhex(v.groupPublicKey), { threshold: v.t, verificationShares: vss });
      expect(hex(sig)).toBe(v.signature);
      expect(ed25519.verify(sig, unhex(v.message), unhex(v.groupPublicKey), { zip215: false })).toBe(true);
    });
    it(`${v.t}-of-${v.n}: a second signing with the same recorded nonces is refused`, () => {
      signAll();
      const n = v.nonces[0]!;
      const key = v.keys.find((k) => k.id === n.id)!;
      expect(() => frostSign(n.id, unhex(key.signingShare), unhex(v.groupPublicKey), { hiding: unhex(n.hiding), binding: unhex(n.binding) }, new TextEncoder().encode('another message'), commits())).toThrow(/already used/);
    });
    it(`${v.t}-of-${v.n}: a flipped bit in any signature share, or a wrong verification share, is refused`, () => {
      const good = signAll();
      const bad = good.map((s, i) => (i === 0 ? { ...s, sigShare: Uint8Array.from(s.sigShare, (b, j) => (j === 0 ? b ^ 1 : b)) } : s));
      expect(() => frostAggregate(unhex(v.message), commits(), bad, unhex(v.groupPublicKey), { threshold: v.t, verificationShares: vss })).toThrow();
      const wrongVss = vss.map((x, i) => (i === 0 ? { ...x, publicKey: vss[1]!.publicKey } : x));
      expect(() => frostAggregate(unhex(v.message), commits(), good.map((s) => s), unhex(v.groupPublicKey), { threshold: v.t, verificationShares: wrongVss })).toThrow();
    });
  }
});
