import { afterEach, describe, expect, it, vi } from 'vitest';
import { base64url } from 'jose';
import { OIDC_SUBJECT_CAVEAT, isOidcSubjectCaveat, oidcPrincipal } from './principal';
import { OidcDiscoveryError, discoverOidc, discoveryUrl } from './discovery';
import type { OidcIdTokenClaims } from './verify';

afterEach(() => vi.unstubAllGlobals());

const KEY = base64url.encode(new Uint8Array(32).map((_, i) => i + 1));
const KEY2 = base64url.encode(new Uint8Array(32).map((_, i) => 200 - i));
const claims = (o: Record<string, unknown> = {}): OidcIdTokenClaims =>
  ({ iss: 'https://i', sub: 'u1', aud: 'a', iat: 1, exp: 2, ...o }) as OidcIdTokenClaims;
const cnfOf = (jwk: unknown) => ({ jwk }) as never;
const okp = (x: unknown, extra: Record<string, unknown> = {}) => ({ kty: 'OKP', crv: 'Ed25519', x, ...extra });

describe('oidcPrincipal', () => {
  it('constant', () => expect(OIDC_SUBJECT_CAVEAT).toBe('oidc_subject'));
  it('requires iss then sub', () => {
    expect(() => oidcPrincipal(claims({ iss: '' }))).toThrow(new TypeError('oidcPrincipal: claims.iss is required'));
    expect(() => oidcPrincipal(claims({ iss: 5 }))).toThrow('claims.iss is required');
    expect(() => oidcPrincipal(claims({ sub: '' }))).toThrow(new TypeError('oidcPrincipal: claims.sub is required'));
    expect(() => oidcPrincipal(claims({ sub: undefined }))).toThrow('claims.sub is required');
    expect(() => oidcPrincipal(claims({ iss: '', sub: '' }))).toThrow('claims.iss is required');
  });
  it('minimal descriptor has exactly these keys', () => {
    const c = claims();
    const p = oidcPrincipal(c);
    expect(p).toStrictEqual({
      iss: 'https://i', sub: 'u1', principalId: 'https://i#u1',
      subjectCaveat: { type: 'oidc_subject', iss: 'https://i', sub: 'u1' }, claims: c,
    });
    expect(p.claims).toBe(c);
  });
  it('projects every optional field, including falsy values', () => {
    const p = oidcPrincipal(claims({ email: 'e', email_verified: false, name: 'n', preferred_username: 'pu', auth_time: 0 }));
    expect(p.email).toBe('e');
    expect(p.emailVerified).toBe(false);
    expect(p.name).toBe('n');
    expect(p.preferredUsername).toBe('pu');
    expect(p.authTime).toBe(0);
    const q = oidcPrincipal(claims({ email_verified: true }));
    expect(Object.keys(q).sort()).toEqual(['claims', 'emailVerified', 'iss', 'principalId', 'sub', 'subjectCaveat']);
  });
  it('principalPublic from cnf', () => {
    expect(oidcPrincipal(claims({ cnf: cnfOf(okp(KEY)) })).principalPublic).toBe(KEY);
  });
  it('ignores non-Ed25519 / malformed cnf keys', () => {
    const bad: unknown[] = [
      undefined, null, 'x', 5, okp(KEY, { kty: 'EC' }), okp(KEY, { crv: 'Ed448' }), okp(5), okp(undefined), okp(''),
      okp(base64url.encode(new Uint8Array(31))), okp(base64url.encode(new Uint8Array(33))), okp(KEY + '='), okp(KEY.replace(/.$/, (ch) => (ch === 'A' ? 'B' : 'A'))),
    ];
    for (const jwk of bad) expect('principalPublic' in oidcPrincipal(claims({ cnf: cnfOf(jwk) }))).toBe(false);
    expect('principalPublic' in oidcPrincipal(claims({ cnf: {} as never }))).toBe(false);
    expect('principalPublic' in oidcPrincipal(claims())).toBe(false);
  });
  it('rejects non-canonical spellings of a 32-byte key (alternate tail bits, standard alphabet)', () => {
    const raw = new Uint8Array(32).fill(0xfb);
    const canon = base64url.encode(raw);
    expect(canon).toContain('-');
    expect('principalPublic' in oidcPrincipal(claims({ cnf: cnfOf(okp(canon)) }))).toBe(true);
    const std = canon.replace(/-/g, '+').replace(/_/g, '/');
    expect('principalPublic' in oidcPrincipal(claims({ cnf: cnfOf(okp(std)) }))).toBe(false);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(canon[canon.length - 1]!);
    const alt = canon.slice(0, -1) + alphabet[last ^ 1];
    expect('principalPublic' in oidcPrincipal(claims({ cnf: cnfOf(okp(alt)) }))).toBe(false);
  });
  it('opts.principalPublic', () => {
    expect(oidcPrincipal(claims(), { principalPublic: KEY }).principalPublic).toBe(KEY);
    expect(oidcPrincipal(claims({ cnf: cnfOf(okp(KEY)) }), { principalPublic: KEY }).principalPublic).toBe(KEY);
    const msg = 'oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key';
    for (const bad of ['', 'abc', KEY + '=', base64url.encode(new Uint8Array(31)), 5 as never]) {
      expect(() => oidcPrincipal(claims(), { principalPublic: bad })).toThrow(new TypeError(msg));
    }
    expect(() => oidcPrincipal(claims({ cnf: cnfOf(okp(KEY)) }), { principalPublic: KEY2 })).toThrow(
      'oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token',
    );
    // a malformed cnf key is "absent", so a valid provided key is accepted
    expect(oidcPrincipal(claims({ cnf: cnfOf(okp('zz')) }), { principalPublic: KEY2 }).principalPublic).toBe(KEY2);
    // invalid provided key is rejected even when cnf has a valid one
    expect(() => oidcPrincipal(claims({ cnf: cnfOf(okp(KEY)) }), { principalPublic: 'bad' })).toThrow(msg);
  });
});

describe('isOidcSubjectCaveat', () => {
  it('accepts and rejects precisely', () => {
    expect(isOidcSubjectCaveat({ type: 'oidc_subject', iss: 'a', sub: 'b' })).toBe(true);
    expect(isOidcSubjectCaveat({ type: 'oidc_subject', iss: 'a', sub: 'b', more: 1 })).toBe(true);
    for (const bad of [
      null, undefined, 'x', 5, {}, { type: 'other', iss: 'a', sub: 'b' }, { type: 'oidc_subject', iss: '', sub: 'b' },
      { type: 'oidc_subject', iss: 'a', sub: '' }, { type: 'oidc_subject', iss: 1, sub: 'b' }, { type: 'oidc_subject', iss: 'a', sub: 2 },
      { type: 'oidc_subject', sub: 'b' }, { type: 'oidc_subject', iss: 'a' },
    ]) expect(isOidcSubjectCaveat(bad)).toBe(false);
  });
});

describe('discoveryUrl', () => {
  it('normalises exactly one trailing slash', () => {
    expect(discoveryUrl('https://x')).toBe('https://x/.well-known/openid-configuration');
    expect(discoveryUrl('https://x/')).toBe('https://x/.well-known/openid-configuration');
    expect(discoveryUrl('https://x//')).toBe('https://x//.well-known/openid-configuration');
    expect(discoveryUrl('https://x/t/a')).toBe('https://x/t/a/.well-known/openid-configuration');
    expect(discoveryUrl('https://x/t/a/')).toBe('https://x/t/a/.well-known/openid-configuration');
    expect(discoveryUrl('')).toBe('/.well-known/openid-configuration');
  });
});

describe('discoverOidc', () => {
  const ISS = 'https://idp.example';
  const respond = (body: unknown, init?: ResponseInit) => async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), init);
  const run = (body: unknown, init?: ResponseInit) => discoverOidc(ISS, { fetch: respond(body, init) as never });
  const err = async (p: Promise<unknown>) => {
    try {
      await p;
    } catch (e) {
      expect(e).toBeInstanceOf(OidcDiscoveryError);
      expect((e as Error).name).toBe('OidcDiscoveryError');
      return e as OidcDiscoveryError;
    }
    throw new Error('expected rejection');
  };

  it('issuer guard', async () => {
    for (const i of ['', 5, null]) expect((await err(discoverOidc(i as never, { fetch: vi.fn() as never }))).message).toBe('discoverOidc: issuer must be a non-empty string');
  });
  it('no fetch available', async () => {
    vi.stubGlobal('fetch', undefined);
    expect((await err(discoverOidc(ISS))).message).toBe('discoverOidc: no fetch implementation available (pass opts.fetch)');
    expect((await err(discoverOidc(ISS, { fetch: 'x' as never }))).message).toContain('no fetch implementation');
  });
  it('uses the global fetch by default and the injected one when given', async () => {
    const g = vi.fn(async () => new Response(JSON.stringify({ issuer: ISS, jwks_uri: 'https://j' })));
    vi.stubGlobal('fetch', g);
    await discoverOidc(ISS);
    expect(g).toHaveBeenCalledTimes(1);
    const f = vi.fn(async () => new Response(JSON.stringify({ issuer: ISS, jwks_uri: 'https://j' })));
    await discoverOidc(ISS, { fetch: f as never });
    expect(f).toHaveBeenCalledTimes(1);
    expect(g).toHaveBeenCalledTimes(1);
  });
  it('request shape', async () => {
    const f = vi.fn(async (_url: string, _init?: RequestInit) => new Response(JSON.stringify({ issuer: ISS + '/', jwks_uri: 'https://j' })));
    await discoverOidc(ISS + '/', { fetch: f as never });
    expect(f.mock.calls[0]).toStrictEqual([`${ISS}/.well-known/openid-configuration`, { headers: { accept: 'application/json' } }]);
    const ac = new AbortController();
    await discoverOidc(ISS + '/', { fetch: f as never, signal: ac.signal });
    expect(f.mock.calls[1]![1]).toStrictEqual({ headers: { accept: 'application/json' }, signal: ac.signal });
  });
  it('network failure carries cause', async () => {
    const cause = new Error('down');
    const e = await err(discoverOidc(ISS, { fetch: (async () => { throw cause; }) as never }));
    expect(e.message).toBe(`discoverOidc: fetch of ${ISS}/.well-known/openid-configuration failed`);
    expect(e.cause).toBe(cause);
  });
  it('non-2xx', async () => {
    const e = await err(run({}, { status: 503 }));
    expect(e.message).toBe(`discoverOidc: ${ISS}/.well-known/openid-configuration returned HTTP 503`);
    await expect(run({ issuer: ISS, jwks_uri: 'https://j' }, { status: 299 })).resolves.toBeDefined();
  });
  it('invalid JSON', async () => {
    const e = await err(run('{nope'));
    expect(e.message).toBe(`discoverOidc: ${ISS}/.well-known/openid-configuration did not return valid JSON`);
    expect(e.cause).toBeDefined();
  });
  it('metadata shape checks', async () => {
    for (const b of ['null', '[]', '"s"', '5']) expect((await err(run(b))).message).toBe('discoverOidc: metadata is not a JSON object');
    for (const i of [undefined, '', 5]) {
      expect((await err(run({ issuer: i, jwks_uri: 'https://j' }))).message).toBe('discoverOidc: metadata is missing a string "issuer"');
    }
    for (const j of [undefined, '', 5]) {
      expect((await err(run({ issuer: ISS, jwks_uri: j }))).message).toBe('discoverOidc: metadata is missing a string "jwks_uri"');
    }
    // issuer shape error wins over jwks shape error
    expect((await err(run({}))).message).toContain('"issuer"');
  });
  it('issuer mismatch (checked after shape)', async () => {
    const e = await err(run({ issuer: 'https://evil', jwks_uri: 'https://j' }));
    expect(e.message).toBe(`discoverOidc: metadata issuer 'https://evil' does not match requested '${ISS}'`);
    expect((await err(run({ issuer: ISS + '/', jwks_uri: 'https://j' }))).message).toContain('does not match');
  });
  it('returns the required members plus every extra member, unchanged', async () => {
    const body = { issuer: ISS, jwks_uri: 'https://j', token_endpoint: 't', id_token_signing_alg_values_supported: ['ES256'], custom: { a: 1 } };
    const m = await run(body);
    expect(m).toStrictEqual(body);
    expect(Object.keys(m)).toEqual(['issuer', 'jwks_uri', 'token_endpoint', 'id_token_signing_alg_values_supported', 'custom']);
  });
});
