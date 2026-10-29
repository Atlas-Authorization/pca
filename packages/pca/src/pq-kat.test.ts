import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  mlDsa65Keygen, mlDsa65Sign, mlDsa65Verify,
  mlDsa87Keygen, mlDsa87Sign, mlDsa87Verify,
  slhDsa128fSign, slhDsa128fVerify, slhDsa256sSign, slhDsa256sVerify,
} from './pq';

// Cross-implementation known answers: ML-DSA / SLH-DSA keys and signatures made here must be accepted by OpenSSL (node:crypto) and
// the other way round. (ACVP vectors for ML-DSA-65 are in pca-pq-threshold; this pins the pq.ts seam against a second implementation.)
const msg = new TextEncoder().encode('pca-pq-kat');
const msg2 = new TextEncoder().encode('pca-pq-kat!');
const seed32 = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

describe.each([
  { alg: 'ml-dsa-65', keygen: mlDsa65Keygen, sign: mlDsa65Sign, verify: mlDsa65Verify },
  { alg: 'ml-dsa-87', keygen: mlDsa87Keygen, sign: mlDsa87Sign, verify: mlDsa87Verify },
] as const)('$alg against OpenSSL', ({ alg, keygen, sign, verify }) => {
  const ours = keygen(seed32);
  const nodePriv = crypto.createPrivateKey({ key: seed32, format: 'raw-seed', asymmetricKeyType: alg } as never);
  const nodePub = crypto.createPublicKey(nodePriv);

  it('the same seed derives the same public key', () => {
    expect(Buffer.from((nodePub.export({ format: 'jwk' }) as { pub?: string }).pub!, 'base64url').equals(Buffer.from(ours.publicKey))).toBe(true);
  });
  it('an OpenSSL signature verifies here, and not for another message or a flipped bit', () => {
    const sig = crypto.sign(null, msg, nodePriv);
    expect(verify(ours.publicKey, msg, sig)).toBe(true);
    expect(verify(ours.publicKey, msg2, sig)).toBe(false);
    const bad = Uint8Array.from(sig);
    bad[7] = bad[7]! ^ 1;
    expect(verify(ours.publicKey, msg, bad)).toBe(false);
  });
  it('a signature made here verifies in OpenSSL', () => {
    const sig = sign(ours.secretKey, msg);
    expect(crypto.verify(null, msg, nodePub, sig)).toBe(true);
    expect(crypto.verify(null, msg2, nodePub, sig)).toBe(false);
  });
});

describe.each([
  { alg: 'slh-dsa-sha2-128f', sign: slhDsa128fSign, verify: slhDsa128fVerify, seedLen: 48, kg: () => import('@noble/post-quantum/slh-dsa.js').then((m) => m.slh_dsa_sha2_128f) },
  { alg: 'slh-dsa-sha2-256s', sign: slhDsa256sSign, verify: slhDsa256sVerify, seedLen: 96, kg: () => import('@noble/post-quantum/slh-dsa.js').then((m) => m.slh_dsa_sha2_256s) },
] as const)('$alg against OpenSSL', ({ alg, sign, verify, seedLen, kg }) => {
  const { publicKey: nodePub, privateKey: nodePriv } = crypto.generateKeyPairSync(alg as never) as unknown as { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  const spki = nodePub.export({ format: 'der', type: 'spki' });
  const rawLen = seedLen / 3 * 2; // public key = pk_seed ‖ pk_root
  const header = spki.subarray(0, spki.length - rawLen);

  it('an OpenSSL signature verifies here, and not for another message', () => {
    const rawPub = Uint8Array.from(spki.subarray(spki.length - rawLen));
    const sig = crypto.sign(null, msg, nodePriv);
    expect(verify(rawPub, msg, sig)).toBe(true);
    expect(verify(rawPub, msg2, sig)).toBe(false);
  });
  it('a signature made here verifies in OpenSSL under the same public key bytes', async () => {
    const keys = (await kg()).keygen(Uint8Array.from({ length: seedLen }, (_, i) => (i * 7 + 1) & 0xff));
    const pub = crypto.createPublicKey({ key: Buffer.concat([header, keys.publicKey]), format: 'der', type: 'spki' });
    const sig = sign(keys.secretKey, msg);
    expect(crypto.verify(null, msg, pub, sig)).toBe(true);
    expect(crypto.verify(null, msg2, pub, sig)).toBe(false);
  }, 60_000);
});
