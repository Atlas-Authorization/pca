/** Mutation-kill tests for the DPoP verifier: every error code and message, every boundary, every option forwarded by assertPcaDpop. */
import { SignJWT, decodeProtectedHeader, exportJWK, generateKeyPair as joseGen } from 'jose';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { buildPCActn, encodeKey, generateKeyPair as pcaGen, mintRoot, type PCActn } from '@atlasauth/pca';
import {
  DpopVerificationError,
  assertPcaDpop as assertPcaDpopRaw,
  athFor,
  createDpopProof,
  dpopAlgForJwk,
  leafHolderJwk,
  createDpopNonceIssuer,
  createInMemoryDpopReplayStore,
  mtlsCnf,
  normalizeHtu,
  verifyDpopProof as verifyDpopProofRaw,
} from './index';

// 0.5: a replay store is required by default; these suites mostly exercise other checks, so they opt out explicitly.
const verifyDpopProof: typeof verifyDpopProofRaw = (p, o) => verifyDpopProofRaw(p, { requireReplayStore: false, ...o });
const assertPcaDpop: typeof assertPcaDpopRaw = (p, d, o) => assertPcaDpopRaw(p, d, { requireReplayStore: false, ...o });

const URL1 = 'https://api.example/v1/x';
const NOW = 1_800_000_000;
type Alg = 'EdDSA' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'RS384';
async function keys(alg: Alg) {
  const { privateKey, publicKey } = await joseGen(alg, { extractable: true });
  return { privateKey, privateJwk: await exportJWK(privateKey), publicJwk: await exportJWK(publicKey) };
}
let ED: Awaited<ReturnType<typeof keys>>;
const ed = async () => (ED ??= await keys('EdDSA'));

/** Sign an arbitrary payload/header with the shared Ed25519 key (to forge malformed-claim proofs). */
async function forge(payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const k = await ed();
  return new SignJWT(payload).setProtectedHeader({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: k.publicJwk, ...header }).sign(k.privateKey);
}
const good = { htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' };
const opts = (o: Record<string, unknown> = {}) => ({ method: 'POST', url: URL1, maxAgeSec: 60, nowSec: NOW, ...o });
const fail = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(DpopVerificationError);
    return e as DpopVerificationError;
  }
  throw new Error('expected rejection');
};

describe('DpopVerificationError / dpopAlgForJwk', () => {
  it('carries name, code and message', () => {
    const e = new DpopVerificationError('c1', 'm1');
    expect([e.name, e.code, e.message]).toEqual(['DpopVerificationError', 'c1', 'm1']);
  });
  it('maps each supported key type and rejects the rest with a specific message', () => {
    expect(dpopAlgForJwk({ kty: 'OKP', crv: 'Ed25519' })).toBe('EdDSA');
    expect(dpopAlgForJwk({ kty: 'OKP', crv: 'Ed448' })).toBe('EdDSA');
    expect(dpopAlgForJwk({ kty: 'EC', crv: 'P-256' })).toBe('ES256');
    expect(dpopAlgForJwk({ kty: 'EC', crv: 'P-384' })).toBe('ES384');
    expect(dpopAlgForJwk({ kty: 'EC', crv: 'P-521' })).toBe('ES512');
    expect(dpopAlgForJwk({ kty: 'RSA' })).toBe('PS256');
    const bad = (j: JWK) => {
      try {
        dpopAlgForJwk(j);
      } catch (e) {
        return e as DpopVerificationError;
      }
      throw new Error('no throw');
    };
    for (const [j, msg] of [
      [{ kty: 'OKP', crv: 'X25519' }, "unsupported OKP curve 'X25519' for DPoP"],
      [{ kty: 'EC', crv: 'P-224' }, "unsupported EC curve 'P-224' for DPoP"],
      [{ kty: 'oct' }, "unsupported key type 'oct' for DPoP"],
    ] as [JWK, string][]) {
      const e = bad(j);
      expect([e.code, e.message]).toEqual(['unsupported_key', msg]);
    }
  });
});

describe('createDpopProof embeds only the public members', () => {
  it.each(['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256'] as const)('%s: header jwk has exactly the public members and no private ones', async (alg) => {
    const k = await keys(alg);
    const proof = await createDpopProof({ method: 'post', url: URL1, privateKey: k.privateKey, publicJwk: { ...k.publicJwk, d: 'SECRET', p: 'x', q: 'y' } as JWK });
    const jwk = decodeProtectedHeader(proof).jwk as JWK;
    const pub = Object.fromEntries(Object.entries(k.publicJwk).filter(([n]) => ['kty', 'crv', 'x', 'y', 'n', 'e'].includes(n)));
    expect(jwk).toStrictEqual(pub);
    expect(decodeProtectedHeader(proof).alg).toBe(dpopAlgForJwk(k.publicJwk));
    const v = await verifyDpopProof(proof, { method: 'POST', url: URL1, maxAgeSec: 60 });
    expect(v.claims.htm).toBe('POST');
  });
  it('nonce and ath are written only when given', async () => {
    const k = await ed();
    const base = { method: 'GET', url: URL1, privateKey: k.privateKey, publicJwk: k.publicJwk, iat: NOW, jti: 'jj' };
    const bare = await createDpopProof(base);
    const payload = (p: string) => JSON.parse(Buffer.from(p.split('.')[1] as string, 'base64url').toString());
    expect(Object.keys(payload(bare)).sort()).toEqual(['htm', 'htu', 'iat', 'jti']);
    const full = await createDpopProof({ ...base, nonce: 'n1', ath: 'a1' });
    expect(payload(full)).toMatchObject({ nonce: 'n1', ath: 'a1', jti: 'jj', iat: NOW });
    const noNonce = await createDpopProof({ ...base, ath: 'a1' });
    expect('nonce' in payload(noNonce)).toBe(false);
    const noAth = await createDpopProof({ ...base, nonce: 'n1' });
    expect('ath' in payload(noAth)).toBe(false);
  });
});

describe('verifyDpopProof error codes, messages and boundaries', () => {
  it('malformed, typ, no_jwk, signature', async () => {
    const m = await fail(verifyDpopProof('not.a.jws!', opts()));
    expect(m.code).toBe('malformed');
    expect(m.message.startsWith('not a JWS: ')).toBe(true);
    expect(m.message).not.toBe('not a JWS: undefined');
    expect(m.message.length).toBeGreaterThan('not a JWS: '.length + 3);
    const t = await fail(verifyDpopProof(await forge(good, { typ: 'JWT' }), opts()));
    expect([t.code, t.message]).toEqual(['typ', "header typ must be 'dpop+jwt', got 'JWT'"]);
    const k = await ed();
    const noJwk = await new SignJWT(good).setProtectedHeader({ typ: 'dpop+jwt', alg: 'EdDSA' }).sign(k.privateKey);
    const nj = await fail(verifyDpopProof(noJwk, opts()));
    expect([nj.code, nj.message]).toEqual(['no_jwk', 'proof header has no embedded jwk']);
    const p = (await forge(good)).split('.');
    const tampered = `${p[0]}.${Buffer.from(JSON.stringify({ ...good, jti: 'other' })).toString('base64url')}.${p[2]}`;
    const s = await fail(verifyDpopProof(tampered, opts()));
    expect(s.code).toBe('signature');
    expect(s.message.startsWith('DPoP signature did not verify: ')).toBe(true);
    expect(s.message.length).toBeGreaterThan('DPoP signature did not verify: '.length);
  });
  it('an algorithm outside the allow-list is refused as a signature failure', async () => {
    const k = await keys('RS384');
    const proof = await new SignJWT(good).setProtectedHeader({ typ: 'dpop+jwt', alg: 'RS384', jwk: k.publicJwk }).sign(k.privateKey);
    expect((await fail(verifyDpopProof(proof, opts()))).code).toBe('signature');
    const ok = await keys('RS384').then(() => keys('PS256'));
    const okProof = await new SignJWT(good).setProtectedHeader({ typ: 'dpop+jwt', alg: 'PS256', jwk: ok.publicJwk }).sign(ok.privateKey);
    expect((await verifyDpopProof(okProof, opts())).claims.jti).toBe('j1');
  });
  it('claim type checks', async () => {
    const e = async (payload: Record<string, unknown>) => fail(verifyDpopProof(await forge(payload), opts()));
    let r = await e({ ...good, htm: undefined });
    expect([r.code, r.message]).toEqual(['htm', 'htm is missing or not a string']);
    r = await e({ ...good, htm: 5 });
    expect(r.code).toBe('htm');
    r = await e({ ...good, htu: undefined });
    expect([r.code, r.message]).toEqual(['htu', 'htu is missing or not a string']);
    r = await e({ ...good, htu: 5 });
    expect(r.code).toBe('htu');
    r = await e({ ...good, iat: undefined });
    expect([r.code, r.message]).toEqual(['iat', 'iat is missing or not a number']);
    r = await e({ ...good, jti: undefined });
    expect([r.code, r.message]).toEqual(['jti', 'jti is missing or empty']);
    r = await e({ ...good, jti: '' });
    expect(r.code).toBe('jti');
    r = await e({ ...good, jti: 123 });
    expect(r.code).toBe('jti');
    r = await e({ ...good, jti: ['x'] });
    expect(r.code).toBe('jti');
  });
  it('htm / htu mismatch messages; method compared upper-case; URL normalised (no query/fragment)', async () => {
    const p = await forge({ ...good, htu: `${URL1}` });
    let r = await fail(verifyDpopProof(p, opts({ method: 'GET' })));
    expect([r.code, r.message]).toEqual(['htm', "htm 'POST' does not match request method"]);
    r = await fail(verifyDpopProof(p, opts({ url: 'https://api.example/v1/y' })));
    expect([r.code, r.message]).toEqual(['htu', `htu '${URL1}' does not match request URL`]);
    expect((await verifyDpopProof(p, opts({ method: 'post', url: `${URL1}?q=1#f` }))).claims.htu).toBe(URL1);
    expect(normalizeHtu('HTTPS://API.example:443/a/b?q#f')).toBe('https://api.example/a/b');
    expect(normalizeHtu('http://h.example:8080/p')).toBe('http://h.example:8080/p');
  });
  it('iat window: +5 s of skew is allowed, +6 is future; maxAge is inclusive', async () => {
    const at = (iat: number) => forge({ ...good, iat });
    expect((await verifyDpopProof(await at(NOW + 5), opts())).claims.iat).toBe(NOW + 5);
    const f = await fail(verifyDpopProof(await at(NOW + 6), opts()));
    expect([f.code, f.message]).toEqual(['iat_future', 'iat is in the future']);
    expect((await verifyDpopProof(await at(NOW - 60), opts())).claims.iat).toBe(NOW - 60);
    const s = await fail(verifyDpopProof(await at(NOW - 61), opts()));
    expect([s.code, s.message]).toEqual(['iat_stale', 'proof is older than 60s']);
  });
  it('jkt, nonce, ath and jti replay', async () => {
    const k = await ed();
    const p = await forge({ ...good, nonce: 'n1', ath: athFor('tok') });
    const jkt = (await verifyDpopProof(p, opts())).jkt;
    let r = await fail(verifyDpopProof(p, opts({ expectedJkt: 'x' })));
    expect([r.code, r.message]).toEqual(['jkt', 'embedded key thumbprint does not match expected jkt']);
    expect((await verifyDpopProof(p, opts({ expectedJkt: jkt }))).jkt).toBe(jkt);
    r = await fail(verifyDpopProof(p, opts({ expectedNonce: 'n2' })));
    expect([r.code, r.message]).toEqual(['nonce', 'proof nonce is missing or does not match the expected nonce']);
    r = await fail(verifyDpopProof(await forge(good), opts({ expectedNonce: 'n1' })));
    expect(r.code).toBe('nonce');
    r = await fail(verifyDpopProof(p, opts({ accessToken: 'other' })));
    expect([r.code, r.message]).toEqual(['ath', 'proof ath is missing or does not match the access token']);
    r = await fail(verifyDpopProof(await forge(good), opts({ accessToken: 'tok' })));
    expect(r.code).toBe('ath');
    const ok = await verifyDpopProof(p, opts({ expectedNonce: 'n1', accessToken: 'tok' }));
    expect(ok.claims).toMatchObject({ nonce: 'n1', ath: athFor('tok'), htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' });
    expect(ok.jwk).toStrictEqual(k.publicJwk);
    const seen = new Set<string>();
    await verifyDpopProof(p, opts({ seenJti: seen }));
    expect(seen.has('j1')).toBe(true);
    r = await fail(verifyDpopProof(p, opts({ seenJti: seen })));
    expect([r.code, r.message]).toEqual(['jti_replay', "jti 'j1' has already been seen"]);
  });
  it('a proof that fails a check does not consume its jti', async () => {
    const seen = new Set<string>();
    await fail(verifyDpopProof(await forge(good), opts({ seenJti: seen, expectedNonce: 'zz' })));
    expect(seen.size).toBe(0);
  });
  it('claims omit nonce / ath when the proof has none, and keep extra payload claims', async () => {
    const r = await verifyDpopProof(await forge({ ...good, extra: 'x' }), opts());
    expect('nonce' in r.claims).toBe(false);
    expect('ath' in r.claims).toBe(false);
    expect(r.claims.extra).toBe('x');
    const r2 = await verifyDpopProof(await forge({ ...good, nonce: 'n' }), opts());
    expect(r2.claims.nonce).toBe('n');
    expect('ath' in r2.claims).toBe(false);
  });
});

describe('mtlsCnf', () => {
  it('accepts DER bytes, PEM with armour, and a bare base64 body (no armour)', () => {
    const der = new Uint8Array([1, 2, 3, 4, 5, 250, 251]);
    const b64 = Buffer.from(der).toString('base64');
    const want = mtlsCnf(der)['x5t#S256'];
    expect(mtlsCnf(b64)['x5t#S256']).toBe(want);
    expect(mtlsCnf(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`)['x5t#S256']).toBe(want);
    expect(mtlsCnf(`junk\n-----BEGIN CERTIFICATE-----\n${b64.slice(0, 4)}\r\n  ${b64.slice(4)}\n-----END CERTIFICATE-----\ntrailer`)['x5t#S256']).toBe(want);
  });
});

async function pcActnWithHolder(): Promise<{ pcActn: PCActn; priv: JWK; pub: JWK }> {
  const principal = pcaGen();
  const holder = pcaGen();
  const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(holder.publicKey), caveats: [] });
  const pcActn = buildPCActn({ grant, chain: [grant], plan: [{ id: 'n1', verb: 'write', resource: 'res://x' }], nodeId: 'n1', counter: 0, signerSecret: holder.secretKey, aud: 'ins_test' });
  const pub: JWK = { kty: 'OKP', crv: 'Ed25519', x: encodeKey(holder.publicKey) };
  return { pcActn, priv: { ...pub, d: encodeKey(holder.secretKey) }, pub };
}

describe('assertPcaDpop forwards every option', () => {
  it('empty chain has no bound holder; default max age is 300 s', async () => {
    const { pcActn, priv, pub } = await pcActnWithHolder();
    const e = await fail(assertPcaDpop({ ...pcActn, cap_chain: [] }, 'x', { method: 'POST', url: URL1 }));
    expect([e.code, e.message]).toEqual(['no_leaf', 'PCActn capability chain is empty; no bound holder key']);
    const now = Math.floor(Date.now() / 1000);
    const mk = (age: number) => createDpopProof({ method: 'POST', url: URL1, privateKey: priv, publicJwk: pub, iat: now - age });
    expect((await assertPcaDpop(pcActn, await mk(290), { method: 'POST', url: URL1 })).claims.iat).toBe(now - 290);
    expect((await fail(assertPcaDpop(pcActn, await mk(310), { method: 'POST', url: URL1 }))).code).toBe('iat_stale');
    expect((await fail(assertPcaDpop(pcActn, await mk(30), { method: 'POST', url: URL1, maxAgeSec: 10 }))).code).toBe('iat_stale');
  });
  it('seenJti, nowSec, expectedNonce and accessToken reach the verifier', async () => {
    const { pcActn, priv, pub } = await pcActnWithHolder();
    const mk = (extra: Record<string, unknown> = {}) => createDpopProof({ method: 'POST', url: URL1, privateKey: priv, publicJwk: pub, iat: NOW, jti: 'jx', ...extra });
    const seen = new Set<string>();
    const proof = await mk({ nonce: 'n1', ath: athFor('tok') });
    const args = { method: 'POST', url: URL1, nowSec: NOW, seenJti: seen, expectedNonce: 'n1', accessToken: 'tok' };
    await assertPcaDpop(pcActn, proof, args);
    expect(seen.has('jx')).toBe(true);
    expect((await fail(assertPcaDpop(pcActn, proof, args))).code).toBe('jti_replay');
    expect((await fail(assertPcaDpop(pcActn, proof, { ...args, seenJti: new Set(), expectedNonce: 'n2' }))).code).toBe('nonce');
    expect((await fail(assertPcaDpop(pcActn, proof, { ...args, seenJti: new Set(), accessToken: 'zzz' }))).code).toBe('ath');
    expect((await fail(assertPcaDpop(pcActn, proof, { method: 'POST', url: URL1, nowSec: NOW + 100_000 }))).code).toBe('iat_stale');
    expect(leafHolderJwk(pcActn)).toStrictEqual(pub);
  });
});

describe('assertPcaDpop forwards the replay-store and nonce-issuer options', () => {
  it('replayStore, requireReplayStore and nonceIssuer reach the verifier', async () => {
    const { pcActn, priv, pub } = await pcActnWithHolder();
    const issuer = createDpopNonceIssuer({ secret: new Uint8Array(32).fill(3) });
    const mk = (extra: Record<string, unknown> = {}) => createDpopProof({ method: 'POST', url: URL1, privateKey: priv, publicJwk: pub, iat: NOW, jti: 'jy', ...extra });
    const proof = await mk({ nonce: issuer.issue(NOW) });
    const args = { method: 'POST', url: URL1, nowSec: NOW, replayStore: createInMemoryDpopReplayStore(), nonceIssuer: issuer };
    await assertPcaDpop(pcActn, proof, args);
    expect((await fail(assertPcaDpop(pcActn, proof, args))).code).toBe('jti_replay');
    expect((await fail(assertPcaDpop(pcActn, await mk(), { ...args, replayStore: createInMemoryDpopReplayStore() }))).code).toBe('nonce');
    expect((await fail(assertPcaDpop(pcActn, proof, { method: 'POST', url: URL1, nowSec: NOW, requireReplayStore: true }))).code).toBe('replay_store_required');
  });
});

describe('mtlsCnf against an independent implementation', () => {
  // Self-signed P-256 certificate generated with OpenSSL; the thumbprint is `openssl x509 -fingerprint -sha256`, base64url-encoded.
  const PEM = `-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUJNnxKGIZtm6X50ZPUimg4pELamAwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcGNhLWRwb3AtdGVzdDAgFw0yNjEwMjYwNjI4MjBaGA8yMTI2
MTAwMjA2MjgyMFowGDEWMBQGA1UEAwwNcGNhLWRwb3AtdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABEUMOC7lpXyDyP7zRuzlIFZE2N55fI6t9YeL6hSgmOq2
gAa7VsKCebHufEqQIxGgiLR8UH2a/sBD5P79bqzLUMKjUzBRMB0GA1UdDgQWBBTX
JKwVRMF9HCh+g6yCG8Vapw+EwDAfBgNVHSMEGDAWgBTXJKwVRMF9HCh+g6yCG8Va
pw+EwDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCQ+cwkz3O7
yzv9nWZgdmrTP5wHxp/GZuNWM1CKH52DjwIgC0l6KtM7TWCWzeroer6ShI8cMkuN
FD8Bv16yLKjV0Rg=
-----END CERTIFICATE-----`;
  const OPENSSL_SHA256_HEX = 'aaae4075fed92a7f630ecebf54924c0c036a76f5684bff486164a495908348bf';
  it('matches the OpenSSL SHA-256 fingerprint and Node X509Certificate, for PEM and DER input', async () => {
    const { X509Certificate } = await import('node:crypto');
    const want = Buffer.from(OPENSSL_SHA256_HEX, 'hex').toString('base64url');
    expect(want).toBe('qq5Adf7ZKn9jDs6_VJJMDANqdvVoS_9IYWSklZCDSL8');
    expect(mtlsCnf(PEM)).toEqual({ 'x5t#S256': want });
    expect(mtlsCnf(new Uint8Array(new X509Certificate(PEM).raw))).toEqual({ 'x5t#S256': want });
    expect(new X509Certificate(PEM).fingerprint256.replace(/:/g, '').toLowerCase()).toBe(OPENSSL_SHA256_HEX);
  });
});
