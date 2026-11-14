import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_JWKS_TIMEOUT_MS, createOidcJwks, createOidcJwksFromIssuer } from './jwks';
import { verifyIdToken } from './verify';
import { baseClaims, makeIssuer } from './testkit';

const AUD = 'client-abc';
const ISS = 'https://idp.example.com';
const JWKS = 'https://idp.example.com/jwks';
const KEYS_MSG = `could not fetch the issuer signing keys from ${JWKS}`;

afterEach(() => vi.unstubAllGlobals());

/** Settle a promise into a plain value so each row asserts the WHOLE outcome with toEqual. */
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

describe('0.5 defaults: https is required for every key source of verifyIdToken', () => {
  it('jwksUri over http is a config error unless requireHttps: false', async () => {
    const idp = await makeIssuer(ISS);
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: 'http://idp.example.com/jwks' }))).toEqual(
      verr('config', 'verifyIdToken: createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)'),
    );
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: '' }))).toEqual(
      verr('config', 'verifyIdToken: createOidcJwks: jwksUri is required'),
    );
  });
  it('discover refuses an http issuer and an http jwks_uri by default', async () => {
    const idp = await makeIssuer('http://idp.example.com');
    const tok = await idp.mint(baseClaims({ issuer: 'http://idp.example.com', audience: AUD }));
    const f = vi.fn(async () => json({ issuer: 'http://idp.example.com', jwks_uri: 'http://idp.example.com/jwks' }));
    expect(await settle(verifyIdToken(tok, { issuer: 'http://idp.example.com', audience: AUD, discover: true, fetch: f as never }))).toEqual(
      derr("discoverOidc: issuer 'http://idp.example.com' is not an https URL"),
    );
    expect(f).not.toHaveBeenCalled();
    const idp2 = await makeIssuer(ISS);
    const tok2 = await idp2.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const g = vi.fn(async () => json({ issuer: ISS, jwks_uri: 'http://idp.example.com/jwks' }));
    expect(await settle(verifyIdToken(tok2, { issuer: ISS, audience: AUD, discover: true, fetch: g as never }))).toEqual(
      derr("discoverOidc: jwks_uri 'http://idp.example.com/jwks' is not an https URL"),
    );
  });
  it('a jwksUri goes through the fail-closed resolver with the global fetch (refused with code keys, never a jose network error)', async () => {
    const idp = await makeIssuer(ISS);
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const calls: unknown[][] = [];
    vi.stubGlobal('fetch', async (...args: unknown[]) => {
      calls.push(args);
      return json({ keys: [idp.publicJwk] });
    });
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: JWKS }))).toEqual({ ok: true });
    expect(calls.map((c) => c[0])).toEqual([JWKS]);
    vi.stubGlobal('fetch', async () => json({ keys: [idp.publicJwk] }, { status: 500 }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: JWKS }))).toEqual(verr('keys', KEYS_MSG));
    vi.stubGlobal('fetch', async () => json({ keys: [1] }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, jwksUri: JWKS }))).toEqual(verr('keys', KEYS_MSG));
  });
  it('requireHttps: false reaches discovery and the resolver (local test issuer)', async () => {
    const LOCAL = 'http://127.0.0.1:9';
    const idp = await makeIssuer(LOCAL);
    const tok = await idp.mint(baseClaims({ issuer: LOCAL, audience: AUD }));
    const f = vi.fn(async () => json({ issuer: LOCAL, jwks_uri: `${LOCAL}/jwks` }));
    vi.stubGlobal('fetch', async () => json({ keys: [idp.publicJwk] }));
    expect(await settle(verifyIdToken(tok, { issuer: LOCAL, audience: AUD, discover: true, fetch: f as never, requireHttps: false }))).toEqual({ ok: true });
    expect(f).toHaveBeenCalledTimes(1);
    const key = await createOidcJwksFromIssuer(LOCAL, { fetch: (async (u: string) => (u.endsWith('openid-configuration') ? json({ issuer: LOCAL, jwks_uri: `${LOCAL}/jwks` }) : json({ keys: [idp.publicJwk] }))) as never, requireHttps: false });
    expect(await settle(verifyIdToken(tok, { issuer: LOCAL, audience: AUD, key }))).toEqual({ ok: true });
    expect(await settle(createOidcJwksFromIssuer(LOCAL, { fetch: f as never }))).toEqual(derr(`discoverOidc: issuer '${LOCAL}' is not an https URL`));
  });
});

describe('JWKS resolver: request shape, timeout, configuration and clock', () => {
  it('the default timeout is 5 s', () => {
    expect(DEFAULT_JWKS_TIMEOUT_MS).toBe(5000);
  });
  it('sends accept: application/json and a live abort signal', async () => {
    const idp = await makeIssuer(ISS);
    const seen: Array<{ url: unknown; headers: unknown; signal: unknown; aborted: boolean }> = [];
    const f = async (url: string, init: RequestInit) => {
      seen.push({ url, headers: init.headers, signal: init.signal, aborted: init.signal?.aborted ?? true });
      return json({ keys: [idp.publicJwk] });
    };
    const key = createOidcJwks({ jwksUri: JWKS, fetch: f as never });
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }))).toEqual({ ok: true });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(JWKS);
    expect(seen[0]!.headers).toEqual({ accept: 'application/json' });
    expect(seen[0]!.signal).toBeInstanceOf(AbortSignal);
    expect(seen[0]!.aborted).toBe(false);
  });
  it('a key-set request that never answers is aborted and the token refused', async () => {
    const idp = await makeIssuer(ISS);
    const hang = (_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)));
    const key = createOidcJwks({ jwksUri: JWKS, fetch: hang as never, timeoutMs: 1 });
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }))).toEqual(verr('keys', KEYS_MSG));
  });
  it('a NaN, negative or infinite age, cooldown, size or timeout is refused at construction; 0 is accepted', () => {
    for (const name of ['cacheMaxAgeSec', 'cooldownSec', 'maxBytes', 'timeoutMs'] as const) {
      for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY]) {
        expect(() => createOidcJwks({ jwksUri: JWKS, [name]: bad } as never)).toThrow(new TypeError(`createOidcJwks: ${name} must be a finite number >= 0`));
      }
      expect(() => createOidcJwks({ jwksUri: JWKS, [name]: 0 } as never)).not.toThrow();
    }
  });
  it('a clock that returns a non-finite time refuses (no key set is served)', async () => {
    const idp = await makeIssuer(ISS);
    const f = vi.fn(async () => json({ keys: [idp.publicJwk] }));
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    for (const t of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const key = createOidcJwks({ jwksUri: JWKS, fetch: f as never, now: () => t });
      expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }))).toEqual(verr('keys', 'the clock returned a non-finite time'));
    }
    expect(f).not.toHaveBeenCalled();
  });
  it('defaults: a key set is reused for 600 s and refetched at 600 s', async () => {
    const idp = await makeIssuer(ISS);
    let clock = 1_000_000;
    const f = vi.fn(async () => json({ keys: [idp.publicJwk] }));
    const key = createOidcJwks({ jwksUri: JWKS, fetch: f as never, now: () => clock });
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const v = () => settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key }));
    expect(await v()).toEqual({ ok: true });
    clock += 599_999;
    expect(await v()).toEqual({ ok: true });
    expect(f).toHaveBeenCalledTimes(1);
    clock += 1;
    expect(await v()).toEqual({ ok: true });
    expect(f).toHaveBeenCalledTimes(2);
  });
  it('defaults: an unknown kid refetches at most once per 30 s', async () => {
    const idp = await makeIssuer(ISS);
    let clock = 1_000_000;
    const f = vi.fn(async () => json({ keys: [idp.publicJwk] }));
    const key = createOidcJwks({ jwksUri: JWKS, fetch: f as never, now: () => clock });
    const good = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const unknown = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }), { kid: 'rotated' });
    expect(await settle(verifyIdToken(good, { issuer: ISS, audience: AUD, key }))).toEqual({ ok: true });
    clock += 29_999;
    expect((await settle(verifyIdToken(unknown, { issuer: ISS, audience: AUD, key }))).ok).toBe(false);
    expect(f).toHaveBeenCalledTimes(1);
    clock += 1;
    expect((await settle(verifyIdToken(unknown, { issuer: ISS, audience: AUD, key }))).ok).toBe(false);
    expect(f).toHaveBeenCalledTimes(2);
  });
  it('defaults: a key set of exactly 1 MiB is accepted, one byte more is refused', async () => {
    const idp = await makeIssuer(ISS);
    const tok = await idp.mint(baseClaims({ issuer: ISS, audience: AUD }));
    const MiB = 1024 * 1024;
    const sized = (n: number) => {
      const shell = JSON.stringify({ keys: [idp.publicJwk], pad: '' });
      return JSON.stringify({ keys: [idp.publicJwk], pad: 'x'.repeat(n - shell.length) });
    };
    expect(sized(MiB).length).toBe(MiB);
    const at = (n: number) => createOidcJwks({ jwksUri: JWKS, fetch: (async () => json(sized(n))) as never });
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: at(MiB) }))).toEqual({ ok: true });
    expect(await settle(verifyIdToken(tok, { issuer: ISS, audience: AUD, key: at(MiB + 1) }))).toEqual(verr('keys', KEYS_MSG));
  });
});
