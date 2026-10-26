import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { SignJWT, base64url, exportJWK, generateKeyPair } from 'jose';
import { discoverOidc } from './discovery';
import { createOidcJwks, createOidcJwksFromIssuer } from './jwks';
import { verifyIdToken, type VerifyIdTokenOptions } from './verify';
import { baseClaims, makeIssuer } from './testkit';

const AUD = 'client-abc';
const ISS = 'https://idp.example.com';

/** Settle a verification into a plain value so every row asserts the WHOLE outcome with toEqual. */
async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; name: string; code: string; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    const x = e as { name: string; code?: string; message: string };
    return { ok: false, name: x.name, code: x.code ?? '', message: x.message };
  }
}
const verr = (code: string, message: string) => ({ ok: false, name: 'OidcVerificationError', code, message });
const derr = (message: string) => ({ ok: false, name: 'OidcDiscoveryError', code: '', message });

const json = (b: unknown, init?: ResponseInit) => new Response(typeof b === 'string' ? b : JSON.stringify(b), init);

describe('discovery fail-closed rows', () => {
  const url = `${ISS}/.well-known/openid-configuration`;
  const doc = { issuer: ISS, jwks_uri: 'https://idp.example.com/jwks' };
  const run = (f: () => Promise<Response>, o: object = {}) => settle(discoverOidc(ISS, { fetch: f as never, ...o }));

  it('table', async () => {
    expect(await run(async () => json(doc))).toEqual({ ok: true });
    expect(await run(async () => json({ ...doc, issuer: 'https://evil.example' }))).toEqual(
      derr(`discoverOidc: metadata issuer 'https://evil.example' does not match requested '${ISS}'`),
    );
    expect(await run(async () => json('x'.repeat(50), { headers: { 'content-length': '5000' } }), { maxBytes: 100 })).toEqual(
      derr(`discoverOidc: ${url} response exceeds 100 bytes`),
    );
    expect(await run(async () => json({ ...doc, pad: 'x'.repeat(200) }), { maxBytes: 100 })).toEqual(
      derr(`discoverOidc: ${url} response exceeds 100 bytes`),
    );
    expect(await run(async () => json({ ...doc, jwks_uri: 'http://idp.example.com/jwks' }), { requireHttps: true })).toEqual(
      derr("discoverOidc: jwks_uri 'http://idp.example.com/jwks' is not an https URL"),
    );
    expect(await settle(discoverOidc('http://idp.example.com', { fetch: vi.fn() as never, requireHttps: true }))).toEqual(
      derr("discoverOidc: issuer 'http://idp.example.com' is not an https URL"),
    );
    // http jwks_uri is accepted when requireHttps is not set (compat default)
    expect(await run(async () => json({ ...doc, jwks_uri: 'http://idp.example.com/jwks' }))).toEqual({ ok: true });
  });
  it('the default size cap is 1 MiB', async () => {
    const big = { ...doc, pad: 'x'.repeat(1024 * 1024) };
    expect(await run(async () => json(big))).toEqual(derr(`discoverOidc: ${url} response exceeds ${1024 * 1024} bytes`));
  });
});

describe('JWKS resolver: fail closed on stale / unreachable keys', () => {
  async function setup() {
    const idp = await makeIssuer();
    const t = 1_000_000;
    let clock = t;
    let up = true;
    let jwks: unknown = { keys: [idp.publicJwk] };
    const fetchFn = vi.fn(async () => (up ? json(jwks) : Promise.reject(new Error('unreachable'))));
    const key = createOidcJwks({ jwksUri: 'https://idp.example.com/jwks', fetch: fetchFn as never, now: () => clock, cacheMaxAgeSec: 100, cooldownSec: 10 });
    const verify = async (kid?: string) => {
      const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }), kid ? { kid } : {});
      return settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }));
    };
    return { idp, fetchFn, key, verify, setClock: (s: number) => (clock = t + s * 1000), setUp: (v: boolean) => (up = v), setJwks: (j: unknown) => (jwks = j) };
  }

  it('fresh cache is reused (one fetch for many verifications)', async () => {
    const s = await setup();
    expect(await s.verify()).toEqual({ ok: true });
    s.setClock(99);
    expect(await s.verify()).toEqual({ ok: true });
    expect(s.fetchFn).toHaveBeenCalledTimes(1);
  });
  it('unreachable on first use: refused', async () => {
    const s = await setup();
    s.setUp(false);
    expect(await s.verify()).toEqual(verr('keys', 'could not fetch the issuer signing keys from https://idp.example.com/jwks'));
  });
  it('stale + unreachable: refused, the old key is NOT reused', async () => {
    const s = await setup();
    expect(await s.verify()).toEqual({ ok: true });
    s.setUp(false);
    s.setClock(100);
    expect(await s.verify()).toEqual(verr('keys', 'could not fetch the issuer signing keys from https://idp.example.com/jwks'));
    // and it stays refused until the endpoint is back; then it recovers
    expect(await s.verify()).toEqual(verr('keys', 'could not fetch the issuer signing keys from https://idp.example.com/jwks'));
    s.setUp(true);
    expect(await s.verify()).toEqual({ ok: true });
  });
  it('non-2xx, non-JWKS and oversize key sets are refused', async () => {
    const mk = (f: () => Promise<Response>, o = {}) =>
      createOidcJwks({ jwksUri: 'https://idp.example.com/jwks', fetch: f as never, ...o });
    const idp = await makeIssuer();
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const msg = 'could not fetch the issuer signing keys from https://idp.example.com/jwks';
    for (const f of [async () => json({ keys: [idp.publicJwk] }, { status: 503 }), async () => json({ nokeys: 1 }), async () => json('[]'), async () => json('nope')]) {
      expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: mk(f) }))).toEqual(verr('keys', msg));
    }
    const big = async () => json({ keys: [idp.publicJwk], pad: 'x'.repeat(500) });
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: mk(big, { maxBytes: 100 }) }))).toEqual(verr('keys', msg));
  });
  it('unknown kid: one refetch per cooldown, then picks up a rotated key', async () => {
    const s = await setup();
    expect(await s.verify()).toEqual({ ok: true });
    const rotated = await makeIssuer();
    s.setJwks({ keys: [s.idp.publicJwk, { ...rotated.publicJwk, kid: 'k2' }] });
    // inside the cooldown (t=0 fetch, now t=5): no refetch, key not found
    s.setClock(5);
    const tok = await new SignJWT(baseClaims({ issuer: ISS, audience: AUD })).setProtectedHeader({ alg: 'EdDSA', kid: 'k2' }).sign(rotated.signingKey);
    expect((await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: s.key }))).ok).toBe(false);
    expect(s.fetchFn).toHaveBeenCalledTimes(1);
    s.setClock(11);
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: s.key }))).toEqual({ ok: true });
    expect(s.fetchFn).toHaveBeenCalledTimes(2);
  });
  it('concurrent verifications share one fetch', async () => {
    const s = await setup();
    await Promise.all([s.key({ alg: 'EdDSA', kid: 'test-key-1' }, {} as never), s.key({ alg: 'EdDSA', kid: 'test-key-1' }, {} as never), s.key({ alg: 'EdDSA', kid: 'test-key-1' }, {} as never)]);
    expect(s.fetchFn).toHaveBeenCalledTimes(1);
  });
  it('construction guards and issuer discovery', async () => {
    expect(() => createOidcJwks({ jwksUri: '' })).toThrow('createOidcJwks: jwksUri is required');
    expect(() => createOidcJwks({ jwksUri: 'http://idp.example.com/jwks' })).toThrow(
      'createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)',
    );
    expect(() => createOidcJwks({ jwksUri: 'http://127.0.0.1/jwks', requireHttps: false })).not.toThrow();
    const idp = await makeIssuer();
    const f = vi.fn(async (u: string) => (u.endsWith('openid-configuration') ? json({ issuer: ISS, jwks_uri: 'https://idp.example.com/jwks' }) : json({ keys: [idp.publicJwk] })));
    const key = await createOidcJwksFromIssuer(ISS, { fetch: f as never });
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }))).toEqual({ ok: true });
    const bad = vi.fn(async () => json({ issuer: ISS, jwks_uri: 'http://idp.example.com/jwks' }));
    expect(await settle(createOidcJwksFromIssuer(ISS, { fetch: bad as never }))).toEqual(
      derr("discoverOidc: jwks_uri 'http://idp.example.com/jwks' is not an https URL"),
    );
  });
});

describe('at_hash / c_hash', () => {
  const hashOf = (alg: 'sha256' | 'sha512', v: string) => {
    const d = createHash(alg).update(v, 'ascii').digest();
    return base64url.encode(d.subarray(0, d.length / 2));
  };
  async function es256Token(extra: Record<string, unknown>) {
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const tok = await new SignJWT({ ...baseClaims({ issuer: ISS, audience: AUD }), ...extra }).setProtectedHeader({ alg: 'ES256' }).sign(privateKey);
    return { tok, publicKey };
  }
  const opts = (publicKey: VerifyIdTokenOptions['key'], more: object): VerifyIdTokenOptions => ({ issuer: ISS, audience: AUD, key: publicKey as never, ...more });

  it('reproduces the OpenID Connect Core example pair (RS/ES256: SHA-256 left half)', async () => {
    const at = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
    expect(hashOf('sha256', at)).toBe('77QmUPtjPfzWtF2AnpK9RQ');
    const { tok, publicKey } = await es256Token({ at_hash: '77QmUPtjPfzWtF2AnpK9RQ' });
    expect(await settle(verifyIdToken(tok, opts(publicKey, { accessToken: at })))).toEqual({ ok: true });
  });
  it('rows', async () => {
    const at = 'access-token-1';
    const { tok, publicKey } = await es256Token({ at_hash: hashOf('sha256', at), c_hash: hashOf('sha256', 'code-1') });
    expect(await settle(verifyIdToken(tok, opts(publicKey, { accessToken: at, code: 'code-1' })))).toEqual({ ok: true });
    expect(await settle(verifyIdToken(tok, opts(publicKey, { accessToken: 'other' })))).toEqual(verr('at_hash', 'id token at_hash does not match the supplied value'));
    expect(await settle(verifyIdToken(tok, opts(publicKey, { code: 'other' })))).toEqual(verr('c_hash', 'id token c_hash does not match the supplied value'));
    // not supplied => not checked (opt-in)
    expect(await settle(verifyIdToken(tok, opts(publicKey, {})))).toEqual({ ok: true });
    const none = await es256Token({});
    expect(await settle(verifyIdToken(none.tok, opts(none.publicKey, { accessToken: at })))).toEqual(verr('at_hash', 'id token is missing the expected at_hash'));
    expect(await settle(verifyIdToken(none.tok, opts(none.publicKey, { code: 'c' })))).toEqual(verr('c_hash', 'id token is missing the expected c_hash'));
  });
  it('EdDSA tokens use SHA-512', async () => {
    const idp = await makeIssuer();
    const ok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD, extra: { at_hash: hashOf('sha512', 'at') } }));
    expect(await settle(verifyIdToken(ok, { issuer: ISS, audience: AUD, key: idp.publicKey, accessToken: 'at' }))).toEqual({ ok: true });
    const wrong = await idp.mint(baseClaims({ issuer: ISS, audience: AUD, extra: { at_hash: hashOf('sha256', 'at') } }));
    expect(await settle(verifyIdToken(wrong, { issuer: ISS, audience: AUD, key: idp.publicKey, accessToken: 'at' }))).toEqual(
      verr('at_hash', 'id token at_hash does not match the supplied value'),
    );
  });
  it('returns at_hash / c_hash in the projected claims', async () => {
    const idp = await makeIssuer();
    const t = await idp.mint(baseClaims({ issuer: ISS, audience: AUD, extra: { at_hash: 'a', c_hash: 'c' } }));
    const c = await verifyIdToken(t, { issuer: ISS, audience: AUD, key: idp.publicKey });
    expect([c.at_hash, c.c_hash]).toEqual(['a', 'c']);
  });
});

describe('attacks (exact outcomes)', () => {
  it('alg confusion: HS256 token keyed with the public JWK bytes is refused', async () => {
    const idp = await makeIssuer();
    const secret = new TextEncoder().encode(JSON.stringify(await exportJWK(idp.publicKey)));
    const tok = await new SignJWT(baseClaims({ issuer: ISS, audience: AUD })).setProtectedHeader({ alg: 'HS256' }).sign(secret);
    const r = await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: idp.publicKey }));
    expect(r.ok).toBe(false);
    expect(r).toMatchObject({ name: 'OidcVerificationError', code: 'invalid_token' });
  });
  it('alg "none" is refused', async () => {
    const enc = (o: unknown) => base64url.encode(new TextEncoder().encode(JSON.stringify(o)));
    const idp = await makeIssuer();
    const tok = `${enc({ alg: 'none' })}.${enc(baseClaims({ issuer: ISS, audience: AUD }))}.`;
    const r = await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: idp.publicKey }));
    expect(r.ok).toBe(false);
  });
  it('not-yet-valid (nbf) and replay-irrelevant wrong issuer pin', async () => {
    const idp = await makeIssuer();
    const future = Math.floor(Date.now() / 1000) + 600;
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD, extra: { nbf: future } }));
    const r = await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: idp.publicKey }));
    expect(r).toMatchObject({ ok: false, code: 'not_before' });
    const t2 = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    expect(await settle(verifyIdToken(t2, { issuer: 'https://idp.example.com/', audience: AUD, key: idp.publicKey }))).toMatchObject({ ok: false, code: 'issuer' });
  });
});
