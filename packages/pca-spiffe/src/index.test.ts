import { describe, it, expect } from 'vitest';
import { SignJWT, generateKeyPair as joseGenerateKeyPair, exportJWK, createLocalJWKSet, type KeyLike } from 'jose';
import { b64u, generateKeyPair, mintRoot, verifyChain } from '@atlasauth/pca';
import {
  parseSpiffeId,
  verifyJwtSvid,
  parseX509Svid,
  svidToHolder,
  holderToSpiffeId,
  SpiffeError,
  type SpiffeHolder,
} from './index';

// ---------------------------------------------------------------------------------------------------
// X.509-SVID fixtures (self-signed, generated with openssl; EC P-256).
// ---------------------------------------------------------------------------------------------------

/** URI SAN: spiffe://example.org/workload/db */
const SVID_SINGLE_URI = `-----BEGIN CERTIFICATE-----
MIIBfzCCASWgAwIBAgIUZ924oqfEXaujUSSiK1QN4thUKN8wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEc3ZpZDAeFw0yNjEwMDgwMzI1MzRaFw0zNjEwMDUwMzI1MzRa
MA8xDTALBgNVBAMMBHN2aWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARqDqRb
TWIhYBdO+by416vD4+kA9MFE1WWKHYXbniDpPwYFAGIscVJMOZaQuWS+ALL8qmPm
FxqCYITyPzWxbYODo18wXTAdBgNVHQ4EFgQUTZdiuJWtTrv71EGQOzAWt8Dv+NMw
DwYDVR0TAQH/BAUwAwEB/zArBgNVHREEJDAihiBzcGlmZmU6Ly9leGFtcGxlLm9y
Zy93b3JrbG9hZC9kYjAKBggqhkjOPQQDAgNIADBFAiB2q22lfiaVzNde7rbHdo5n
vuatwfLuJhT5lsu9ijt2PQIhAN37SvsH7V8qYQBui9bl61VqRwEV2UK5hVt9TlTb
Qw5F
-----END CERTIFICATE-----`;

/** SAN: DNS:example.org only — no URI SAN. */
const SVID_NO_URI = `-----BEGIN CERTIFICATE-----
MIIBbzCCARSgAwIBAgIUO92fiqgm2fD9RNGobQnH2EDCrVMwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGbm9zdmlkMB4XDTI2MTAwODAzMjUzNFoXDTM2MTAwNTAzMjUz
NFowETEPMA0GA1UEAwwGbm9zdmlkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
z2Tj8QjfO38TrqcZkGBRZqmav2Q69kSn53bNC7W3iXHRlGr1PlyAqiCalOoL9sOR
4GSrLsQL75QzsL9J8hbimaNKMEgwHQYDVR0OBBYEFKpuFCgHXDAFFRLtoiPoInar
uVYpMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILZXhhbXBsZS5vcmcwCgYI
KoZIzj0EAwIDSQAwRgIhAIsBTzqBtl3eKNIqbhS2XTmCARtrwkWT/QGGyzF6f1yy
AiEAwMXib5I4adrnED1mzRE0xCkAZwAhefbNGhQFzC1eM4U=
-----END CERTIFICATE-----`;

/** Two URI SANs: spiffe://example.org/a and spiffe://example.org/b. */
const SVID_MULTI_URI = `-----BEGIN CERTIFICATE-----
MIIBmDCCAT2gAwIBAgIUG6M6aIcOwKJpARSg47nBg/ThscQwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbXVsdGlzdmlkMB4XDTI2MTAwODAzMjUzNFoXDTM2MTAwNTAz
MjUzNFowFDESMBAGA1UEAwwJbXVsdGlzdmlkMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEoslAMsKAjDAsGWkzjxMyOhnu3e1IjMe1GwzVqDKBCo8/EzRrssHOYIGd
5HnEueIRw9s6c8Zrr/jXqB9Y4uPP86NtMGswHQYDVR0OBBYEFHCawYia7vcVknCW
kh1e6S9D4RuFMA8GA1UdEwEB/wQFMAMBAf8wOQYDVR0RBDIwMIYWc3BpZmZlOi8v
ZXhhbXBsZS5vcmcvYYYWc3BpZmZlOi8vZXhhbXBsZS5vcmcvYjAKBggqhkjOPQQD
AgNJADBGAiEA+LceSPiLOuO3snWsD38PzbbPQ4nKWjaaG3ziYHv0GHACIQD5Rc2K
dtDu4k4paen6dI0g9qh7tbNTTrm/8LZIrF15qA==
-----END CERTIFICATE-----`;

// ---------------------------------------------------------------------------------------------------
// parseSpiffeId
// ---------------------------------------------------------------------------------------------------

describe('parseSpiffeId', () => {
  it('parses a full SPIFFE ID with a path', () => {
    const id = parseSpiffeId('spiffe://example.org/workload/db');
    expect(id.id).toBe('spiffe://example.org/workload/db');
    expect(id.trustDomain).toBe('example.org');
    expect(id.path).toBe('/workload/db');
  });

  it('parses a bare trust-domain ID (no path)', () => {
    const id = parseSpiffeId('spiffe://example.org');
    expect(id.trustDomain).toBe('example.org');
    expect(id.path).toBe('');
  });

  it('accepts the permitted path-segment charset', () => {
    const id = parseSpiffeId('spiffe://trust-domain_1.example/a-b_c.d/SEG2');
    expect(id.trustDomain).toBe('trust-domain_1.example');
    expect(id.path).toBe('/a-b_c.d/SEG2');
  });

  it.each([
    ['', 'empty string'],
    ['https://example.org/x', 'wrong scheme'],
    ['SPIFFE://example.org/x', 'uppercase scheme'],
    ['spiffe:///workload', 'empty trust domain'],
    ['spiffe://Example.org/x', 'uppercase in trust domain'],
    ['spiffe://exa mple.org/x', 'space in trust domain'],
    ['spiffe://example.org/', 'trailing slash'],
    ['spiffe://example.org//db', 'empty path segment'],
    ['spiffe://example.org/./db', 'dot segment'],
    ['spiffe://example.org/../db', 'dot-dot segment'],
    ['spiffe://example.org/wor kload', 'space in path'],
    ['spiffe://example.org/wörkload', 'non-ascii in path'],
  ])('rejects %s (%s)', (input) => {
    expect(() => parseSpiffeId(input)).toThrow(SpiffeError);
  });

  it('rejects an ID longer than 2048 bytes', () => {
    const huge = 'spiffe://example.org/' + 'a'.repeat(2048);
    expect(() => parseSpiffeId(huge)).toThrow(SpiffeError);
  });

  it('rejects a trust domain longer than 255 bytes', () => {
    const td = 'a'.repeat(256);
    expect(() => parseSpiffeId(`spiffe://${td}/x`)).toThrow(/trust domain exceeds/);
  });
});

// ---------------------------------------------------------------------------------------------------
// verifyJwtSvid
// ---------------------------------------------------------------------------------------------------

const AUD = 'spiffe://example.org/server';
const SUB = 'spiffe://example.org/workload/db';

async function mintJwtSvid(opts: {
  privateKey: KeyLike;
  sub?: string;
  aud?: string;
  exp?: string | number;
  setExp?: boolean;
}): Promise<string> {
  const jwt = new SignJWT({}).setProtectedHeader({ alg: 'ES256' }).setIssuedAt();
  if (opts.sub !== undefined) jwt.setSubject(opts.sub);
  if (opts.aud !== undefined) jwt.setAudience(opts.aud);
  if (opts.setExp !== false) jwt.setExpirationTime(opts.exp ?? '1h');
  return jwt.sign(opts.privateKey);
}

describe('verifyJwtSvid', () => {
  it('verifies a valid JWT-SVID (single key)', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });

    const svid = await verifyJwtSvid(token, { audience: AUD, key: publicKey });
    expect(svid.spiffeId.id).toBe(SUB);
    expect(svid.spiffeId.trustDomain).toBe('example.org');
    expect(svid.audience).toContain(AUD);
    expect(svid.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('verifies via an injected JWKS resolver (getKey function path)', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);
    jwk.alg = 'ES256';
    const jwks = createLocalJWKSet({ keys: [jwk] });
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });

    const svid = await verifyJwtSvid(token, { audience: AUD, key: jwks });
    expect(svid.spiffeId.id).toBe(SUB);
  });

  it('enforces an optional trust-domain pin', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });

    await expect(
      verifyJwtSvid(token, { audience: AUD, key: publicKey, trustDomain: 'other.org' }),
    ).rejects.toMatchObject({ code: 'trust_domain_mismatch' });

    await expect(
      verifyJwtSvid(token, { audience: AUD, key: publicKey, trustDomain: 'example.org' }),
    ).resolves.toBeTruthy();
  });

  it('rejects a token with no audience claim', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB }); // no aud
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects a token whose audience does not match', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: 'spiffe://example.org/someone-else' });
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects when the caller provides an empty audience', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    await expect(verifyJwtSvid(token, { audience: '', key: publicKey })).rejects.toMatchObject({
      code: 'missing_audience',
    });
  });

  it('rejects a token whose sub is not a valid SPIFFE ID', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: 'not-a-spiffe-id', aud: AUD });
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'invalid_subject',
    });
  });

  it('rejects a token with no sub claim', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, aud: AUD }); // no sub
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'invalid_subject',
    });
  });

  it('rejects a token with no exp claim', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD, setExp: false });
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'missing_exp',
    });
  });

  it('rejects an expired token', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD, exp: past });
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects a token signed by the wrong key', async () => {
    const { privateKey } = await joseGenerateKeyPair('ES256');
    const other = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    await expect(verifyJwtSvid(token, { audience: AUD, key: other.publicKey })).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------------------------------
// parseX509Svid
// ---------------------------------------------------------------------------------------------------

describe('parseX509Svid', () => {
  it('extracts the SPIFFE ID from the single URI SAN (PEM)', () => {
    const svid = parseX509Svid(SVID_SINGLE_URI);
    expect(svid.spiffeId.id).toBe('spiffe://example.org/workload/db');
    expect(svid.spiffeId.trustDomain).toBe('example.org');
    expect(svid.publicKeyDer.length).toBeGreaterThan(0);
  });

  it('accepts DER bytes as well as PEM', () => {
    const der = pemToDer(SVID_SINGLE_URI);
    const svid = parseX509Svid(der);
    expect(svid.spiffeId.id).toBe('spiffe://example.org/workload/db');
  });

  it('rejects a certificate with no URI SAN', () => {
    expect(() => parseX509Svid(SVID_NO_URI)).toThrow(SpiffeError);
    expect(() => parseX509Svid(SVID_NO_URI)).toThrowError(/no URI SAN/);
  });

  it('rejects a certificate with multiple URI SANs', () => {
    try {
      parseX509Svid(SVID_MULTI_URI);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(SpiffeError);
      expect((err as SpiffeError).code).toBe('multiple_uri_san');
    }
  });
});

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

// ---------------------------------------------------------------------------------------------------
// svidToHolder / holderToSpiffeId  (integration with the core capability holder)
// ---------------------------------------------------------------------------------------------------

describe('svidToHolder / holderToSpiffeId', () => {
  it('round-trips a SPIFFE ID through a holder', () => {
    const { publicKey } = generateKeyPair();
    const holder = svidToHolder(SUB, publicKey);
    expect(holder.spiffeId).toBe(SUB);
    expect(holder.trustDomain).toBe('example.org');
    expect(holder.path).toBe('/workload/db');
    expect(holderToSpiffeId(holder)).toBe(SUB);
  });

  it('accepts a b64u holder key and raw bytes equivalently', () => {
    const { publicKey } = generateKeyPair();
    const fromBytes = svidToHolder(SUB, publicKey);
    const fromB64u = svidToHolder(SUB, b64u(publicKey));
    expect(fromB64u.holder).toBe(fromBytes.holder);
  });

  it('accepts a pre-parsed SpiffeId object', () => {
    const { publicKey } = generateKeyPair();
    const parsed = parseSpiffeId(SUB);
    const holder = svidToHolder(parsed, publicKey);
    expect(holder.spiffeId).toBe(SUB);
  });

  it('rejects an invalid holder key', () => {
    expect(() => svidToHolder(SUB, new Uint8Array(31))).toThrow(SpiffeError);
    expect(() => svidToHolder(SUB, 'not-base64url!!')).toThrow(SpiffeError);
  });

  it('rejects a malformed SPIFFE ID', () => {
    const { publicKey } = generateKeyPair();
    expect(() => svidToHolder('https://example.org/x', publicKey)).toThrow(SpiffeError);
  });

  it('bridges an X.509-SVID identity to a usable PCA capability holder', () => {
    // A SPIRE-attested workload: its SPIFFE ID comes from the SVID; its PCA holder key signs PCActns.
    const svid = parseX509Svid(SVID_SINGLE_URI);
    const principal = generateKeyPair();
    const workloadKey = generateKeyPair();

    const holder: SpiffeHolder = svidToHolder(svid.spiffeId, workloadKey.publicKey);

    // The holder plugs straight into the real core capability APIs.
    const root = mintRoot({
      principalSecret: principal.secretKey,
      principalPublic: b64u(principal.publicKey),
      holder: holder.holder,
      caveats: [],
    });
    expect(root.holder).toBe(holder.holder);
    expect(verifyChain([root], b64u(principal.publicKey)).ok).toBe(true);
    expect(holderToSpiffeId(holder)).toBe('spiffe://example.org/workload/db');
  });
});
