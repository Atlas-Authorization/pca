import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { SignJWT, errors as joseErrors } from 'jose';
import { DEFAULT_ID_TOKEN_ALGS, OidcVerificationError, verifyIdToken, type OidcVerificationErrorCode } from './verify';
import { baseClaims, makeIssuer, type LocalIssuer } from './testkit';

const AUD = 'client-abc';
let idp: LocalIssuer;
beforeAll(async () => {
  idp = await makeIssuer();
});
afterEach(() => vi.useRealTimers());

async function fail(p: Promise<unknown>): Promise<OidcVerificationError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(OidcVerificationError);
    return e as OidcVerificationError;
  }
  throw new Error('expected rejection');
}
async function expectErr(p: Promise<unknown>, code: OidcVerificationErrorCode, msg?: string | RegExp) {
  const e = await fail(p);
  expect(e.code).toBe(code);
  expect(e.name).toBe('OidcVerificationError');
  if (typeof msg === 'string') expect(e.message).toBe(msg);
  else if (msg) expect(e.message).toMatch(msg);
  return e;
}
const mk = (extra: Record<string, unknown> = {}, o: Record<string, unknown> = {}) =>
  idp.mint({ ...baseClaims({ issuer: idp.issuer, audience: AUD }), ...extra, ...o });
const opts = () => ({ issuer: idp.issuer, audience: AUD, key: idp.publicKey });

describe('verifyIdToken argument guards', () => {
  it('idToken', async () => {
    for (const t of ['', 5, null, undefined]) {
      await expectErr(verifyIdToken(t as never, opts()), 'invalid_token', 'verifyIdToken: idToken must be a non-empty string');
    }
    // idToken checked before opts
    await expectErr(verifyIdToken('', null as never), 'invalid_token');
  });
  it('opts', async () => {
    const t = await mk();
    for (const o of [null, 'x', 5, undefined]) await expectErr(verifyIdToken(t, o as never), 'config', 'verifyIdToken: opts is required');
    await expectErr(verifyIdToken(t, { ...opts(), issuer: '' }), 'config', 'verifyIdToken: opts.issuer is required');
    await expectErr(verifyIdToken(t, { ...opts(), issuer: 3 as never }), 'config', 'verifyIdToken: opts.issuer is required');
    await expectErr(verifyIdToken(t, { ...opts(), audience: undefined as never }), 'config', 'verifyIdToken: opts.audience is required');
    await expectErr(verifyIdToken(t, { ...opts(), audience: 5 as never }), 'config', 'verifyIdToken: opts.audience is required');
    // issuer is checked before audience
    await expectErr(verifyIdToken(t, { issuer: '', audience: undefined as never, key: idp.publicKey }), 'config', /issuer/);
    // array audience and empty-string audience pass the guard (jose then judges)
    await expect(verifyIdToken(t, { ...opts(), audience: [AUD] })).resolves.toBeDefined();
  });
  it('non-canonical JWS is refused before any key source is resolved', async () => {
    const t = await mk();
    const e = await fail(verifyIdToken(t + '=', { issuer: idp.issuer, audience: AUD }));
    expect(e.code).toBe('invalid_token');
    expect(e.message).not.toMatch(/no key source/);
  });
  it('no key source', async () => {
    const t = await mk();
    await expectErr(
      verifyIdToken(t, { issuer: idp.issuer, audience: AUD }),
      'config',
      'verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)',
    );
    await expectErr(verifyIdToken(t, { issuer: idp.issuer, audience: AUD, discover: false }), 'config', /no key source/);
  });
});

describe('key sources', () => {
  let srv: Server;
  let base: string;
  let hits: string[] = [];
  beforeAll(async () => {
    srv = createServer((req, res) => {
      hits.push(req.url ?? '');
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ keys: [idp.publicJwk] }));
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));

  it('jwksUri is used when no key is given; key wins over jwksUri', async () => {
    const t = await mk();
    hits = [];
    const c = await verifyIdToken(t, { issuer: idp.issuer, audience: AUD, jwksUri: `${base}/jwks`, requireHttps: false });
    expect(c.sub).toBe('user-123');
    expect(hits).toEqual(['/jwks']);
    hits = [];
    await verifyIdToken(t, { ...opts(), jwksUri: `${base}/jwks`, requireHttps: false });
    expect(hits).toEqual([]);
    // jwksUri wins over discover
    const f = vi.fn();
    await verifyIdToken(t, { issuer: idp.issuer, audience: AUD, jwksUri: `${base}/j2`, discover: true, fetch: f as never, requireHttps: false });
    expect(f).not.toHaveBeenCalled();
  });
  it('discover resolves jwks_uri via the injected fetch', async () => {
    const t = await mk();
    const f = vi.fn(async () => new Response(JSON.stringify({ issuer: idp.issuer, jwks_uri: `${base}/disc-jwks` })));
    hits = [];
    const c = await verifyIdToken(t, { issuer: idp.issuer, audience: AUD, discover: true, fetch: f as never, requireHttps: false });
    expect(c.iss).toBe(idp.issuer);
    expect(f).toHaveBeenCalledTimes(1);
    expect((f.mock.calls[0] as unknown[])[0]).toBe(`${idp.issuer}/.well-known/openid-configuration`);
    expect(hits).toEqual(['/disc-jwks']);
  });
});

describe('algorithms', () => {
  it('default list is the asymmetric set', () => {
    expect([...DEFAULT_ID_TOKEN_ALGS]).toEqual(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);
  });
  it('custom algorithms replace the default; default accepts EdDSA; HS256 never', async () => {
    const t = await mk();
    await expectErr(verifyIdToken(t, { ...opts(), algorithms: ['RS256'] }), 'invalid_token');
    await expect(verifyIdToken(t, { ...opts(), algorithms: ['EdDSA'] })).resolves.toBeDefined();
    const secret = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
    const hs = await new SignJWT(baseClaims({ issuer: idp.issuer, audience: AUD })).setProtectedHeader({ alg: 'HS256' }).sign(secret);
    await expectErr(verifyIdToken(hs, { issuer: idp.issuer, audience: AUD, key: secret }), 'invalid_token');
    await expect(verifyIdToken(hs, { issuer: idp.issuer, audience: AUD, key: secret, algorithms: ['HS256'] })).resolves.toBeDefined();
  });
});

describe('time claims', () => {
  const NOW = 1_800_000_000;
  const at = () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW * 1000);
  };
  it('exp boundary, with and without clock tolerance', async () => {
    at();
    const base = { iat: NOW - 100 };
    await expectErr(verifyIdToken(await mk({ ...base, exp: NOW }), opts()), 'expired', 'id token has expired');
    await expect(verifyIdToken(await mk({ ...base, exp: NOW + 1 }), opts())).resolves.toBeDefined();
    const t5 = await mk({ ...base, exp: NOW - 5 });
    await expectErr(verifyIdToken(t5, opts()), 'expired');
    await expectErr(verifyIdToken(t5, { ...opts(), clockToleranceSec: 0 }), 'expired');
    await expectErr(verifyIdToken(t5, { ...opts(), clockToleranceSec: 5 }), 'expired');
    await expect(verifyIdToken(t5, { ...opts(), clockToleranceSec: 6 })).resolves.toBeDefined();
  });
  it('expired carries the jose cause', async () => {
    at();
    const e = await expectErr(verifyIdToken(await mk({ iat: NOW - 100, exp: NOW - 10 }), opts()), 'expired');
    expect(e.cause).toBeInstanceOf(joseErrors.JWTExpired);
  });
  it('nbf', async () => {
    at();
    const t = await mk({ iat: NOW - 10, exp: NOW + 100, nbf: NOW + 3 });
    const e = await expectErr(verifyIdToken(t, opts()), 'not_before');
    expect(e.cause).toBeInstanceOf(joseErrors.JWTClaimValidationFailed);
    await expect(verifyIdToken(t, { ...opts(), clockToleranceSec: 3 })).resolves.toBeDefined();
  });
  it('maxTokenAgeSec', async () => {
    at();
    const t = await mk({ iat: NOW - 100, exp: NOW + 100 });
    const e = await expectErr(verifyIdToken(t, { ...opts(), maxTokenAgeSec: 50 }), 'issued_at', 'id token is older than the maximum accepted age');
    expect(e.cause).toBeInstanceOf(joseErrors.JWTExpired);
    await expect(verifyIdToken(t, { ...opts(), maxTokenAgeSec: 200 })).resolves.toBeDefined();
    await expect(verifyIdToken(t, opts())).resolves.toBeDefined();
    // maxTokenAge with a missing iat is an iat claim failure
    const noIat = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, exp: NOW + 100 });
    await expectErr(verifyIdToken(noIat, { ...opts(), maxTokenAgeSec: 50 }), 'issued_at');
  });
  it('missing / non-numeric iat and exp', async () => {
    at();
    const noIat = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, exp: NOW + 100 });
    await expectErr(verifyIdToken(noIat, opts()), 'issued_at', 'id token is missing a numeric "iat" claim');
    const strIat = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, exp: NOW + 100, iat: 'x' as never });
    await expectErr(verifyIdToken(strIat, opts()), 'issued_at', '"iat" claim must be a number');
    const noExp = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, iat: NOW });
    await expectErr(verifyIdToken(noExp, opts()), 'expired', 'id token is missing a numeric "exp" claim');
    // iat 0 is a valid number
    const iat0 = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, iat: 0, exp: NOW + 100 });
    expect((await verifyIdToken(iat0, opts())).iat).toBe(0);
  });
  it('other jose claim failures map to "claims"', async () => {
    at();
    const t = await idp.mint({ iss: idp.issuer, sub: 's', aud: AUD, iat: NOW, exp: 'soon' as never });
    await expectErr(verifyIdToken(t, opts()), 'claims');
  });
});

describe('error mapping', () => {
  it('issuer / audience', async () => {
    const e1 = await expectErr(verifyIdToken(await mk(), { ...opts(), issuer: 'https://other' }), 'issuer');
    expect(e1.cause).toBeInstanceOf(joseErrors.JWTClaimValidationFailed);
    expect(e1.message).toBe((e1.cause as Error).message);
    const e2 = await expectErr(verifyIdToken(await mk(), { ...opts(), audience: 'zzz' }), 'audience');
    expect(e2.message).toBe((e2.cause as Error).message);
    await expectErr(verifyIdToken(await idp.mint({ iss: idp.issuer, sub: 's', iat: 1, exp: 4e9 }), opts()), 'audience');
    await expectErr(verifyIdToken(await idp.mint({ sub: 's', aud: AUD, iat: 1, exp: 4e9 }), opts()), 'issuer');
  });
  it('signature', async () => {
    const other = await makeIssuer();
    const e = await expectErr(verifyIdToken(await mk(), { ...opts(), key: other.publicKey }), 'signature', 'id token signature verification failed');
    expect(e.cause).toBeInstanceOf(joseErrors.JWSSignatureVerificationFailed);
  });
  it('malformed token is invalid_token with the jose message', async () => {
    const e = await expectErr(verifyIdToken('a.b.c', opts()), 'invalid_token');
    expect(e.message.length).toBeGreaterThan(0);
  });
  it('JOSEError from a key resolver keeps its message', async () => {
    const e = await expectErr(
      verifyIdToken(await mk(), { ...opts(), key: (async () => { throw new joseErrors.JWKSNoMatchingKey(); }) as never }),
      'invalid_token',
    );
    expect(e.message).toBe(new joseErrors.JWKSNoMatchingKey().message);
    expect(e.cause).toBeInstanceOf(joseErrors.JWKSNoMatchingKey);
  });
  it('non-jose resolver errors get a generic message and cause', async () => {
    const boom = new Error('boom');
    const e = await expectErr(
      verifyIdToken(await mk(), { ...opts(), key: (async () => { throw boom; }) as never }),
      'invalid_token',
      'id token verification failed',
    );
    expect(e.cause).toBe(boom);
  });
  it('an OidcVerificationError from a resolver passes through unchanged', async () => {
    const mine = new OidcVerificationError('azp', 'mine');
    const e = await fail(verifyIdToken(await mk(), { ...opts(), key: (async () => { throw mine; }) as never }));
    expect(e).toBe(mine);
  });
  it('error class', () => {
    const c = new Error('c');
    const e = new OidcVerificationError('nonce', 'm', { cause: c });
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('OidcVerificationError');
    expect(e.code).toBe('nonce');
    expect(e.message).toBe('m');
    expect(e.cause).toBe(c);
  });
});

describe('claim checks and projection', () => {
  it('sub is required and non-empty', async () => {
    for (const sub of [undefined, '', 5]) {
      const t = await idp.mint({ iss: idp.issuer, aud: AUD, iat: 1, exp: 4e9, ...(sub !== undefined ? { sub: sub as never } : {}) });
      await expectErr(verifyIdToken(t, opts()), 'claims', 'id token is missing the "sub" claim');
    }
  });
  it('nonce binding', async () => {
    await expectErr(verifyIdToken(await mk(), { ...opts(), nonce: 'n1' }), 'nonce', 'id token is missing the expected nonce');
    await expectErr(verifyIdToken(await mk({ nonce: '' }), { ...opts(), nonce: '' }), 'nonce', 'id token is missing the expected nonce');
    await expectErr(verifyIdToken(await mk({ nonce: 'n2' }), { ...opts(), nonce: 'n1' }), 'nonce', 'id token nonce does not match the expected value');
    await expectErr(verifyIdToken(await mk({ nonce: 5 }), { ...opts(), nonce: 'n1' }), 'nonce', 'id token is missing the expected nonce');
    expect((await verifyIdToken(await mk({ nonce: 'n1' }), { ...opts(), nonce: 'n1' })).nonce).toBe('n1');
    // no expected nonce: token nonce is still reported
    expect((await verifyIdToken(await mk({ nonce: 'zz' }), opts())).nonce).toBe('zz');
    expect('nonce' in (await verifyIdToken(await mk(), opts()))).toBe(false);
  });
  it('azp rules', async () => {
    const multi = { aud: [AUD, 'other'] };
    const audArr = { ...opts(), audience: [AUD, 'other'] };
    await expectErr(verifyIdToken(await mk(multi), audArr), 'azp', 'id token has multiple audiences but no azp (authorized party)');
    await expectErr(verifyIdToken(await mk({ ...multi, azp: '' }), audArr), 'azp', /multiple audiences/);
    // single-element aud array needs no azp
    expect((await verifyIdToken(await mk({ aud: [AUD] }), opts())).aud).toEqual([AUD]);
    // multi aud with azp, expected party unknown (array audience, no authorizedParty): any azp passes
    expect((await verifyIdToken(await mk({ ...multi, azp: 'whoever' }), audArr)).azp).toBe('whoever');
    // string audience defaults expected azp
    await expectErr(verifyIdToken(await mk({ azp: 'bad' }), opts()), 'azp', 'id token azp does not match the authorized party');
    expect((await verifyIdToken(await mk({ azp: AUD }), opts())).azp).toBe(AUD);
    // multi aud + string audience option: azp must equal the audience
    await expectErr(verifyIdToken(await mk({ aud: [AUD, 'x'], azp: 'x' }), { ...opts(), audience: AUD }), 'azp', /does not match/);
    // authorizedParty overrides the default
    expect((await verifyIdToken(await mk({ azp: 'ap' }), { ...opts(), authorizedParty: 'ap' })).azp).toBe('ap');
    await expectErr(verifyIdToken(await mk({ azp: AUD }), { ...opts(), authorizedParty: 'ap' }), 'azp', /does not match/);
    // authorizedParty with array audience is enforced
    await expectErr(verifyIdToken(await mk({ ...multi, azp: 'q' }), { ...audArr, authorizedParty: 'p' }), 'azp', /does not match/);
    expect((await verifyIdToken(await mk({ ...multi, azp: 'p' }), { ...audArr, authorizedParty: 'p' })).azp).toBe('p');
    // non-string azp is treated as absent
    expect('azp' in (await verifyIdToken(await mk({ azp: 7 }), opts()))).toBe(false);
  });
  it('exact projection of every optional claim', async () => {
    const cnf = { jwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' }, jkt: 'tp', extra: 1 };
    const c = await verifyIdToken(
      await mk({
        nonce: 'n', azp: AUD, auth_time: 0, email: 'a@b', email_verified: false, name: 'N', preferred_username: 'pu',
        given_name: 'G', family_name: 'F', picture: 'http://p', cnf, unknown_claim: 1,
      }, { iat: 1_000, exp: 4_000_000_000 }),
      { ...opts(), nonce: 'n' },
    );
    expect(c).toStrictEqual({
      iss: idp.issuer, sub: 'user-123', aud: AUD, iat: 1000, exp: 4_000_000_000, nonce: 'n', azp: AUD, auth_time: 0,
      email: 'a@b', email_verified: false, name: 'N', preferred_username: 'pu', given_name: 'G', family_name: 'F',
      picture: 'http://p', cnf,
    });
  });
  it('minimal token has only the required keys', async () => {
    const c = await verifyIdToken(await mk({}, { iat: 5, exp: 4_000_000_000 }), opts());
    expect(Object.keys(c).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'sub']);
  });
  it('wrong-typed optional claims are dropped', async () => {
    const c = await verifyIdToken(
      await mk({
        email: 5, email_verified: 'true', auth_time: 'x', name: '', preferred_username: 1, given_name: {}, family_name: [], picture: false,
        cnf: 'str',
      }),
      opts(),
    );
    expect(Object.keys(c).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'sub']);
    for (const bad of [null, [1], 5]) {
      const d = await verifyIdToken(await mk({ cnf: bad }), opts());
      expect('cnf' in d).toBe(false);
    }
    const e = await verifyIdToken(await mk({ cnf: {} }), opts());
    expect(e.cnf).toStrictEqual({});
  });
});
