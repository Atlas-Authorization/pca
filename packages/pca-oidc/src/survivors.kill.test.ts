import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { SignJWT, base64url, generateKeyPair } from 'jose';
import { discoverOidc } from './discovery';
import { createOidcJwks } from './jwks';
import { verifyIdToken } from './verify';
import { baseClaims, makeIssuer } from './testkit';

const ISS = 'https://idp.example.com';
const AUD = 'client-abc';
const URI = 'https://idp.example.com/jwks';
const DOC = { issuer: ISS, jwks_uri: URI };

async function caught(p: Promise<unknown> | (() => unknown)): Promise<Error & { code?: string }> {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a rejection');
}

describe('discovery size limits and response shapes', () => {
  const text = JSON.stringify(DOC);
  const len = new TextEncoder().encode(text).length;
  const bare = (body: string, headers?: Record<string, string>) =>
    (async () => ({ ok: true, status: 200, ...(headers ? { headers: new Headers(headers) } : {}), text: async () => body })) as never;

  it('accepts a response without headers', async () => {
    expect(await discoverOidc(ISS, { fetch: bare(text) })).toEqual(DOC);
  });
  it('a declared content-length equal to the limit is accepted, one over is refused', async () => {
    expect(await discoverOidc(ISS, { fetch: bare(text, { 'content-length': String(len) }), maxBytes: len })).toEqual(DOC);
    const e = await caught(discoverOidc(ISS, { fetch: bare(text, { 'content-length': String(len + 1) }), maxBytes: len }));
    expect(e.message).toBe(`discoverOidc: ${ISS}/.well-known/openid-configuration response exceeds ${len} bytes`);
  });
  it('a body exactly at the limit is accepted, one byte over is refused', async () => {
    expect(await discoverOidc(ISS, { fetch: bare(text), maxBytes: len })).toEqual(DOC);
    const e = await caught(discoverOidc(ISS, { fetch: bare(text), maxBytes: len - 1 }));
    expect(e.message).toBe(`discoverOidc: ${ISS}/.well-known/openid-configuration response exceeds ${len - 1} bytes`);
  });
  it('an unparseable issuer is refused as not https', async () => {
    const fetch = vi.fn();
    const e = await caught(discoverOidc('not a url', { fetch: fetch as never }));
    expect(e.message).toBe("discoverOidc: issuer 'not a url' is not an https URL");
    expect(fetch).not.toHaveBeenCalled();
    const e2 = await caught(discoverOidc(ISS, { fetch: bare(JSON.stringify({ issuer: ISS, jwks_uri: 'not a url' })) }));
    expect(e2.message).toBe("discoverOidc: jwks_uri 'not a url' is not an https URL");
  });
});

describe('createOidcJwks construction and fetch failures', () => {
  const resp = (b: string, init?: ResponseInit) => (async () => new Response(b, init)) as never;
  const header = { alg: 'EdDSA', kid: 'k' };
  const fail = async (fetch: unknown, o: object = {}) => caught(createOidcJwks({ jwksUri: URI, fetch: fetch as never, ...o })(header, {} as never));
  const keysMsg = `could not fetch the issuer signing keys from ${URI}`;

  it('requires a string jwksUri', () => {
    expect(() => createOidcJwks({} as never)).toThrow(new TypeError('createOidcJwks: jwksUri is required'));
    expect(() => createOidcJwks({ jwksUri: 5 } as never)).toThrow(new TypeError('createOidcJwks: jwksUri is required'));
  });
  it('the https check is anchored at the start', () => {
    const msg = 'createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)';
    expect(() => createOidcJwks({ jwksUri: 'http://evil.example/?next=https://idp.example.com' })).toThrow(new TypeError(msg));
    expect(() => createOidcJwks({ jwksUri: 'HTTPS://idp.example.com/jwks' })).not.toThrow();
  });
  it('an http status is carried as the cause', async () => {
    const e = await fail(resp('{}', { status: 503 }));
    expect(e).toMatchObject({ name: 'OidcVerificationError', code: 'keys', message: keysMsg });
    expect((e.cause as Error).message).toBe('HTTP 503');
  });
  it('an oversize key set is carried as the cause', async () => {
    const e = await fail(resp(JSON.stringify({ keys: [], pad: 'x'.repeat(200) })), { maxBytes: 100 });
    expect(e.code).toBe('keys');
    expect((e.cause as Error).message).toBe('response exceeds 100 bytes');
  });
  it.each([['null'], ['5'], ['"str"'], ['[]'], ['{"nokeys":1}'], ['{"keys":5}'], ['{"keys":{}}']])('%s is not a JWK Set', async (body) => {
    const e = await fail(resp(body));
    expect(e.code).toBe('keys');
    expect((e.cause as Error).message).toBe('not a JWK Set');
  });
  it('a transport failure keeps its cause, a bad clock has none', async () => {
    const boom = new Error('boom');
    const e = await fail(async () => { throw boom; });
    expect(e.cause).toBe(boom);
    const clock = await caught(createOidcJwks({ jwksUri: URI, now: () => Number.NaN })(header, {} as never));
    expect(clock.message).toBe('the clock returned a non-finite time');
    expect(clock.code).toBe('keys');
    expect('cause' in clock).toBe(false);
  });
});

describe('createOidcJwks refetch triggers', () => {
  async function setup() {
    const idp = await makeIssuer();
    let t = 0;
    const fetch = vi.fn(async () => new Response(JSON.stringify({ keys: [idp.publicJwk] })));
    const key = createOidcJwks({ jwksUri: URI, fetch: fetch as never, now: () => t, cacheMaxAgeSec: 1000, cooldownSec: 10 });
    return { idp, fetch, key, setT: (n: number) => { t = n; } };
  }
  it('a token without a kid never triggers a refetch inside the cache age', async () => {
    const s = await setup();
    await s.key({ alg: 'EdDSA', kid: s.idp.publicJwk.kid }, {} as never);
    s.setT(500);
    await s.key({ alg: 'EdDSA' }, {} as never).catch(() => undefined);
    expect(s.fetch).toHaveBeenCalledTimes(1);
  });
  it('a missing header is not dereferenced for its kid', async () => {
    const s = await setup();
    await s.key({ alg: 'EdDSA', kid: s.idp.publicJwk.kid }, {} as never);
    s.setT(500);
    const e = await caught(s.key(undefined as never, {} as never));
    expect(e.message).not.toMatch(/kid/);
    expect(s.fetch).toHaveBeenCalledTimes(1);
  });
});

describe('verifyIdToken half-hash and key-source details', () => {
  it('an alg that is not a SHA-sized one cannot check at_hash', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256K');
    const tok = await new SignJWT({ ...baseClaims({ issuer: ISS, audience: AUD }), at_hash: 'x' }).setProtectedHeader({ alg: 'ES256K' }).sign(privateKey);
    const e = await caught(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: publicKey as never, algorithms: ['ES256K'], accessToken: 'at' }));
    expect(e).toMatchObject({ name: 'OidcVerificationError', code: 'at_hash', message: 'cannot compute at_hash for alg ES256K' });
    const c = await caught(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: publicKey as never, algorithms: ['ES256K'], code: 'c' }).catch((x) => { throw x; }));
    expect(c).toMatchObject({ code: 'c_hash' });
  });
  it('the hashed value is read as ascii (one byte per char)', async () => {
    const idp = await makeIssuer();
    const at = 'tokén';
    const d = createHash('sha512').update(Buffer.from(at, 'latin1')).digest();
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD, extra: { at_hash: base64url.encode(d.subarray(0, 32)) } }));
    await expect(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: idp.publicKey, accessToken: at })).resolves.toBeDefined();
  });
  it('a refused jwksUri is a config error carrying its cause', async () => {
    const idp = await makeIssuer();
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const e = await caught(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: 'http://idp.example.com/jwks' }));
    expect(e).toMatchObject({ code: 'config' });
    expect(e.message).toBe('verifyIdToken: createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)');
    expect(e.cause).toBeInstanceOf(TypeError);
  });
});
