import { execFileSync } from 'node:child_process';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { SignJWT, generateKeyPair as joseGenerateKeyPair, exportJWK, createLocalJWKSet, type KeyLike } from 'jose';
import { b64u, generateKeyPair, mintRoot, spiffeIdError, verifyChain } from '@atlasauth/pca';
import {
  parseSpiffeId,
  verifyJwtSvid,
  parseX509Svid,
  svidToHolder,
  holderToSpiffeId,
  holderBindingMessage,
  spiffeIdForHolder,
  workloadDischargePin,
  verifyX509Svid,
  SpiffeError,
  type SpiffeHolder,
} from './index';

// ---------------------------------------------------------------------------------------------------
// X.509-SVID fixtures: proper SVID leaves (CA:FALSE, digitalSignature) from fixtures/generate-pki.sh.
// ---------------------------------------------------------------------------------------------------

const pki = (name: string): string => readFileSync(resolve(__dirname, '..', 'fixtures', 'generated', `${name}.pem`), 'utf8');

/** URI SAN: spiffe://example.org/workload/db */
const SVID_SINGLE_URI = pki('leaf');
/** SAN: DNS:example.org only, no URI SAN. */
const SVID_NO_URI = pki('leaf-dns-only');
/** Two URI SANs: spiffe://example.org/a and spiffe://example.org/b. */
const SVID_MULTI_URI = pki('leaf-two-uri');

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

    const svid = await verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey });
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

    const svid = await verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: jwks });
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
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects a token whose audience does not match', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: 'spiffe://example.org/someone-else' });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects when the caller provides an empty audience', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: '', key: publicKey })).rejects.toMatchObject({
      code: 'missing_audience',
    });
  });

  it('rejects a token whose sub is not a valid SPIFFE ID', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: 'not-a-spiffe-id', aud: AUD });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'invalid_subject',
    });
  });

  it('rejects a token with no sub claim', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, aud: AUD }); // no sub
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'invalid_subject',
    });
  });

  it('rejects a token with no exp claim', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD, setExp: false });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toMatchObject({
      code: 'missing_exp',
    });
  });

  it('rejects an expired token', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD, exp: past });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey })).rejects.toThrow();
  });

  it('rejects a token signed by the wrong key', async () => {
    const { privateKey } = await joseGenerateKeyPair('ES256');
    const other = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    await expect(verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: other.publicKey })).rejects.toThrow();
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

describe('svidToHolder / holderToSpiffeId (R3-18: only a VERIFIED SVID binds)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'spiffe-bind-'));
  const sh = (...a: string[]): void => void execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
  let haveOpenssl = true;
  try {
    sh('req', '-x509', '-newkey', 'ed25519', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-subj', '/CN=root', '-days', '30',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    writeFileSync(join(dir, 'ext'), 'subjectAltName=URI:spiffe://example.org/workload/db\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n');
    sh('genpkey', '-algorithm', 'ed25519', '-out', 'ed.key');
    sh('req', '-new', '-key', 'ed.key', '-subj', '/CN=ed', '-out', 'ed.csr');
    sh('x509', '-req', '-in', 'ed.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'ed.pem', '-days', '10', '-extfile', 'ext');
    sh('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ec.key');
    sh('req', '-new', '-key', 'ec.key', '-subj', '/CN=ec', '-out', 'ec.csr');
    sh('x509', '-req', '-in', 'ec.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'ec.pem', '-days', '10', '-extfile', 'ext');
  } catch {
    haveOpenssl = false;
  }
  // Read the clock AFTER openssl issued the certificates: notBefore is the issuing second, so a clock read before a
  // slow issuance can fall before it (exact RFC 5280 validity then refuses the chain as not yet valid).
  const NOW = new Date();
  const rd = (f: string): string => readFileSync(join(dir, f), 'utf8');
  const verified = (f: string) => verifyX509Svid(rd(f), { trustDomain: 'example.org', roots: [rd('root.pem')], now: NOW });

  it('rejects a string, a parsed ID, a hand-built object and a parse-only SVID', () => {
    const { publicKey } = generateKeyPair();
    expect(() => svidToHolder(SUB as never, publicKey)).toThrow(/verifyJwtSvid/);
    expect(() => svidToHolder(parseSpiffeId(SUB) as never, publicKey)).toThrow(SpiffeError);
    expect(() => svidToHolder({ spiffeId: parseSpiffeId(SUB), claims: {}, audience: [], expiresAt: 1 } as never, publicKey)).toThrow(SpiffeError);
    expect(() => svidToHolder(parseX509Svid(SVID_SINGLE_URI) as never, publicKey)).toThrow(/verifyJwtSvid|verifyX509Svid/);
  });

  it('verifyJwtSvid requires a trustDomain pin', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    await expect(verifyJwtSvid(token, { audience: AUD, key: publicKey } as never)).rejects.toMatchObject({ code: 'missing_trust_domain' });
  });

  it('JWT-SVID: needs a matching cnf.jwk unless acceptUnboundJwtHolder is set', async () => {
    const { privateKey, publicKey } = await joseGenerateKeyPair('ES256');
    const hk = generateKeyPair();
    const token = await mintJwtSvid({ privateKey, sub: SUB, aud: AUD });
    const svid = await verifyJwtSvid(token, { trustDomain: 'example.org', audience: AUD, key: publicKey });
    expect(() => svidToHolder(svid, hk.publicKey)).toThrow(/cnf/);
    const h = svidToHolder(svid, hk.publicKey, { acceptUnboundJwtHolder: true });
    expect(h.spiffeId).toBe(SUB);
    expect(h.trustDomain).toBe('example.org');
    expect(h.path).toBe('/workload/db');
    expect(holderToSpiffeId(h)).toBe(SUB);
    expect(svidToHolder(svid, b64u(hk.publicKey), { acceptUnboundJwtHolder: true }).holder).toBe(h.holder);
    expect(() => svidToHolder(svid, new Uint8Array(31), { acceptUnboundJwtHolder: true })).toThrow(SpiffeError);
    expect(() => svidToHolder(svid, 'not-base64url!!', { acceptUnboundJwtHolder: true })).toThrow(SpiffeError);
    // a cnf.jwk binding is honoured
    const jwt = new SignJWT({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(hk.publicKey) } } }).setProtectedHeader({ alg: 'ES256' }).setSubject(SUB).setAudience(AUD).setExpirationTime('1h');
    const t2 = await jwt.sign(privateKey);
    const s2 = await verifyJwtSvid(t2, { trustDomain: 'example.org', audience: AUD, key: publicKey });
    expect(svidToHolder(s2, hk.publicKey).holder).toBe(b64u(hk.publicKey));
    expect(() => svidToHolder(s2, generateKeyPair().publicKey)).toThrow(/cnf/);
  });

  it.runIf(haveOpenssl)('X.509-SVID with an Ed25519 key: the holder is derived from the certificate; a different key needs a proof', () => {
    const svid = verified('ed.pem');
    const h = svidToHolder(svid);
    expect(h.spiffeId).toBe(SUB);
    const stranger = generateKeyPair();
    expect(() => svidToHolder(svid, stranger.publicKey)).toThrow(/proof/);
    expect(svidToHolder(svid, h.holder).holder).toBe(h.holder);
    const priv = createPrivateKey(rd('ed.key'));
    const sig = b64u(nodeSign(null, holderBindingMessage(SUB, b64u(stranger.publicKey)), priv));
    expect(svidToHolder(svid, stranger.publicKey, { proof: sig }).holder).toBe(b64u(stranger.publicKey));
    // a proof for another holder or ID does not transfer
    expect(() => svidToHolder(svid, generateKeyPair().publicKey, { proof: sig })).toThrow(/does not verify/);
  });

  it.runIf(haveOpenssl)('X.509-SVID with an EC key: holder key REQUIRES a proof by the SVID key', () => {
    const svid = verified('ec.pem');
    const hk = generateKeyPair();
    expect(() => svidToHolder(svid)).toThrow(SpiffeError);
    expect(() => svidToHolder(svid, hk.publicKey)).toThrow(/proof/);
    const priv = createPrivateKey(rd('ec.key'));
    const good = b64u(nodeSign('sha256', holderBindingMessage(SUB, b64u(hk.publicKey)), { key: priv, dsaEncoding: 'ieee-p1363' }));
    const holder: SpiffeHolder = svidToHolder(svid, hk.publicKey, { proof: good });
    expect(() => svidToHolder(svid, hk.publicKey, { proof: 'AAAA' })).toThrow(/does not verify/);

    // The holder plugs straight into the real core capability APIs.
    const principal = generateKeyPair();
    const root = mintRoot({ principalSecret: principal.secretKey, principalPublic: b64u(principal.publicKey), holder: holder.holder, caveats: [] });
    expect(root.holder).toBe(holder.holder);
    expect(verifyChain([root], b64u(principal.publicKey)).ok).toBe(true);
    expect(holderToSpiffeId(holder)).toBe(SUB);
  });

  it.runIf(haveOpenssl)('K1: spiffeIdForHolder returns the ID only for the key the SVID is bound to; workloadDischargePin pins its Ed25519 key', () => {
    const svid = verified('ed.pem');
    const h = svidToHolder(svid);
    expect(spiffeIdForHolder(svid, h.holder)).toBe(SUB);
    expect(() => spiffeIdForHolder(svid, b64u(generateKeyPair().publicKey))).toThrow(/proof/);
    expect(() => spiffeIdForHolder(SUB as never, h.holder)).toThrow(SpiffeError);
    expect(workloadDischargePin('runtime', svid)).toEqual({ label: 'runtime', class: 'workload', pk: h.holder, spiffe_id: SUB });
    expect(() => workloadDischargePin('runtime', verified('ec.pem'))).toThrow(SpiffeError);
  });
});

describe('K1 SPIFFE ID syntax agrees with parseSpiffeId', () => {
  const ids = ['spiffe://example.org', 'spiffe://example.org/', 'spiffe://example.org/a/b', 'spiffe://Example.org/a', 'spiffe://example.org/a/../b', 'spiffe://example.org/a//b', 'spiffe://example.org/a b', 'spiffe://example.org/a?x', 'spiffe://ex_am-ple.d/x.y', 'spiffe://', 'spiffe:///a', 'http://example.org/a', '', `spiffe://example.org/${'a'.repeat(2030)}`, `spiffe://example.org/${'a'.repeat(2040)}`];
  it.each(ids.map((i) => [i.length > 50 ? `${i.slice(0, 30)}... (${i.length})` : i, i] as const))('%s', (_n, id) => {
    let ok = true;
    try { parseSpiffeId(id); } catch { ok = false; }
    expect(spiffeIdError(id) === null).toBe(ok);
  });
});
