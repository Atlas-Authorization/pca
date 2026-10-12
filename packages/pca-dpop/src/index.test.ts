import { exportJWK, generateKeyPair as joseGenerateKeyPair } from 'jose';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { type PCActn, buildPCActn, encodeKey, generateKeyPair as pcaGenerateKeyPair, mintRoot } from '@atlasauth/pca';
import {
  DpopVerificationError,
  assertPcaDpop,
  athFor,
  bindPcaToDpop,
  createDpopProof,
  jwkThumbprint,
  leafHolderJwk,
  mtlsCnf,
  verifyDpopProof,
} from './index';

const URL1 = 'https://api.atlasauth.net/v1/pca/exec?token=abc#frag';
const METHOD = 'POST';

/** A jose signing keypair for DPoP, plus its public JWK (embedded) and private JWK (signs). */
async function joseKeyMaterial(alg: 'ES256' | 'EdDSA'): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await joseGenerateKeyPair(alg, { extractable: true });
  return { privateJwk: await exportJWK(privateKey), publicJwk: await exportJWK(publicKey) };
}

describe('jwkThumbprint', () => {
  it('matches RFC 7638 for the same key and differs across keys', async () => {
    const a = (await joseKeyMaterial('ES256')).publicJwk;
    const b = (await joseKeyMaterial('ES256')).publicJwk;
    expect(await jwkThumbprint(a)).toBe(await jwkThumbprint(a));
    expect(await jwkThumbprint(a)).not.toBe(await jwkThumbprint(b));
  });
});

describe.each(['ES256', 'EdDSA'] as const)('DPoP round-trip (%s)', (alg) => {
  it('creates and verifies a proof', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial(alg);
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    const res = await verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300 });
    expect(res.claims.htm).toBe('POST');
    // htu is query/fragment-stripped.
    expect(res.claims.htu).toBe('https://api.atlasauth.net/v1/pca/exec');
    expect(res.jkt).toBe(await jwkThumbprint(publicJwk));
    expect(typeof res.claims.jti).toBe('string');
  });

  it('carries + verifies nonce and ath', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial(alg);
    const ath = athFor('access-token-xyz');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk, nonce: 'srv-nonce', ath });
    const res = await verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300 });
    expect(res.claims.nonce).toBe('srv-nonce');
    expect(res.claims.ath).toBe(ath);
  });
});

describe('DPoP verification failures', () => {
  it('rejects htu mismatch', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    await expect(
      verifyDpopProof(proof, { method: METHOD, url: 'https://api.atlasauth.net/v1/OTHER', maxAgeSec: 300 }),
    ).rejects.toMatchObject({ code: 'htu' });
  });

  it('rejects htm mismatch', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    await expect(verifyDpopProof(proof, { method: 'GET', url: URL1, maxAgeSec: 300 })).rejects.toMatchObject({ code: 'htm' });
  });

  it('rejects a stale iat', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const old = Math.floor(Date.now() / 1000) - 1000;
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk, iat: old });
    await expect(verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300 })).rejects.toMatchObject({ code: 'iat_stale' });
  });

  it('rejects an iat in the future', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const future = Math.floor(Date.now() / 1000) + 1000;
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk, iat: future });
    await expect(verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300 })).rejects.toMatchObject({ code: 'iat_future' });
  });

  it('rejects a wrong-key signature (header jwk swapped for a different key)', async () => {
    // Sign with key A but embed key B's public JWK: the signature cannot verify under B.
    const a = await joseKeyMaterial('ES256');
    const b = await joseKeyMaterial('ES256');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: a.privateJwk, publicJwk: b.publicJwk });
    await expect(verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300 })).rejects.toMatchObject({ code: 'signature' });
  });

  it('rejects a jkt mismatch', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const other = await joseKeyMaterial('ES256');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    await expect(
      verifyDpopProof(proof, { method: METHOD, url: URL1, maxAgeSec: 300, expectedJkt: await jwkThumbprint(other.publicJwk) }),
    ).rejects.toMatchObject({ code: 'jkt' });
  });

  it('rejects a replayed jti and accepts a fresh one', async () => {
    const { privateJwk, publicJwk } = await joseKeyMaterial('ES256');
    const seen = new Set<string>();
    const p1 = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    await verifyDpopProof(p1, { method: METHOD, url: URL1, maxAgeSec: 300, seenJti: seen });
    // Same proof again => replay.
    await expect(verifyDpopProof(p1, { method: METHOD, url: URL1, maxAgeSec: 300, seenJti: seen })).rejects.toMatchObject({ code: 'jti_replay' });
    // A fresh proof (new jti) still passes.
    const p2 = await createDpopProof({ method: METHOD, url: URL1, privateKey: privateJwk, publicJwk });
    await expect(verifyDpopProof(p2, { method: METHOD, url: URL1, maxAgeSec: 300, seenJti: seen })).resolves.toBeDefined();
  });

  it('rejects a non-DPoP typ', async () => {
    // A normal JWT (no dpop+jwt typ) must be refused.
    const { privateJwk } = await joseKeyMaterial('ES256');
    const jwt = await new (await import('jose')).SignJWT({ htm: 'POST', htu: 'x', jti: 'j' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .sign(privateJwk);
    await expect(verifyDpopProof(jwt, { method: METHOD, url: URL1, maxAgeSec: 300 })).rejects.toMatchObject({ code: 'typ' });
  });
});

describe('mtlsCnf (RFC 8705)', () => {
  it('produces a stable x5t#S256 for DER and the equivalent PEM', () => {
    const der = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef]);
    const b64 = Buffer.from(der).toString('base64');
    const pem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
    const fromDer = mtlsCnf(der);
    const fromPem = mtlsCnf(pem);
    expect(fromDer['x5t#S256']).toBe(fromPem['x5t#S256']);
    expect(fromDer['x5t#S256']).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url(32 bytes), no pad
    // A different cert yields a different thumbprint.
    expect(mtlsCnf(new Uint8Array([1, 2, 3]))['x5t#S256']).not.toBe(fromDer['x5t#S256']);
  });
});

/** Build a real PCActn whose leaf holder is an Ed25519 key, returning the holder's jose signing JWKs. */
async function pcActnWithHolder(): Promise<{ pcActn: PCActn; holderPrivateJwk: JWK; holderPublicJwk: JWK }> {
  const principal = pcaGenerateKeyPair();
  const holder = pcaGenerateKeyPair();
  const grant = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    caveats: [],
  });
  const pcActn = buildPCActn({
    grant,
    chain: [grant],
    plan: [{ id: 'n1', verb: 'write', resource: 'res://x' }],
    nodeId: 'n1',
    counter: 0,
    signerSecret: holder.secretKey,
    aud: 'ins_test',
  });
  // The leaf-holder Ed25519 key as OKP JWKs: x = b64u(public), d = b64u(secret seed).
  const holderPublicJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: encodeKey(holder.publicKey) };
  const holderPrivateJwk: JWK = { ...holderPublicJwk, d: encodeKey(holder.secretKey) };
  return { pcActn, holderPrivateJwk, holderPublicJwk };
}

describe('PCActn ↔ DPoP binding', () => {
  it('bindPcaToDpop matches the leaf-holder JWK thumbprint', async () => {
    const { pcActn } = await pcActnWithHolder();
    const { jkt } = await bindPcaToDpop(pcActn);
    expect(jkt).toBe(await jwkThumbprint(leafHolderJwk(pcActn)));
  });

  it('assertPcaDpop passes for a proof held by the PCActn bound key', async () => {
    const { pcActn, holderPrivateJwk, holderPublicJwk } = await pcActnWithHolder();
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: holderPrivateJwk, publicJwk: holderPublicJwk });
    const res = await assertPcaDpop(pcActn, proof, { method: METHOD, url: URL1 });
    expect(res.jkt).toBe((await bindPcaToDpop(pcActn)).jkt);
  });

  it('assertPcaDpop fails on a key mismatch (proof held by a different key)', async () => {
    const { pcActn } = await pcActnWithHolder();
    const wrong = await joseKeyMaterial('EdDSA');
    const proof = await createDpopProof({ method: METHOD, url: URL1, privateKey: wrong.privateJwk, publicJwk: wrong.publicJwk });
    await expect(assertPcaDpop(pcActn, proof, { method: METHOD, url: URL1 })).rejects.toBeInstanceOf(DpopVerificationError);
    await expect(assertPcaDpop(pcActn, proof, { method: METHOD, url: URL1 })).rejects.toMatchObject({ code: 'jkt' });
  });
});
