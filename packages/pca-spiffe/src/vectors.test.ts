/**
 * External-vector and cross-implementation tests for pca-spiffe.
 *  - go-spiffe v2 (spiffe/go-spiffe @ 77c6d2e0): the SPIFFE-ID character rules from spiffeid/id_test.go (the
 *    exhaustive 0..255 character sweep is reproduced here) and the X.509-SVID certificates in
 *    svid/x509svid/testdata, with the failure each one is meant to trigger.
 *  - py-spiffe 0.3.2 + PyJWT 2.10.1: SPIFFE-ID verdicts and JWT-SVID verdicts (fixtures/pyspiffe.json).
 *  - OpenSSL 4.0.3 `openssl verify` + Python cryptography 50.0.2 x509 verifier: chain verdicts for the
 *    generated PKI (fixtures/pki-crosscheck.json).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SignJWT, generateKeyPair, importJWK, type JWK, type KeyLike } from 'jose';
import { describe, expect, it } from 'vitest';
import { SpiffeError, parseSpiffeId, parseX509Svid, verifyJwtSvid, verifyX509Svid } from './index';

const fixtures = (...p: string[]): string => resolve(__dirname, '..', 'fixtures', ...p);
const pem = (dir: string, name: string): string => readFileSync(fixtures(dir, `${name}.pem`), 'utf8');
const gen = (name: string): string => pem('generated', name);
const gs = (name: string): string => pem('go-spiffe', name);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function jsonFixture(name: string): Record<string, unknown> {
  const raw: unknown = JSON.parse(readFileSync(fixtures(name), 'utf8'));
  if (!isRecord(raw)) throw new Error(`bad fixture ${name}`);
  return raw;
}
/** True when lower-casing the scheme and trust domain makes `s` a valid ID (the only py-spiffe leniency). */
function parseSpiffeIdLower(s: string): boolean {
  const lowered = s.replace(/^[^/]*\/\/[^/]*/, (m) => m.toLowerCase());
  try {
    parseSpiffeId(lowered);
    return true;
  } catch {
    return false;
  }
}
/** True when `s` exceeds the standard's length limits (whole ID 2048, trust domain 255). */
function overLimit(s: string): boolean {
  const td = /^spiffe:\/\/([^/]*)/.exec(s)?.[1] ?? '';
  return s.length > 2048 || td.length > 255;
}
function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof SpiffeError) return e.code;
    throw e;
  }
  return 'ok';
}
async function asyncCodeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    return e instanceof SpiffeError ? e.code : e instanceof Error ? `jose:${e.name}` : 'unknown';
  }
  return 'ok';
}
const certsIn = (text: string): string[] => text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];

// ---------------------------------------------------------------------------------------------
describe('SPIFFE ID: go-spiffe id_test.go rules', () => {
  const lower = /^[a-z]$/;
  const upper = /^[A-Z]$/;
  const digit = /^[0-9]$/;
  const special = new Set(['.', '-', '_']);
  const tdChar = (c: string): boolean => lower.test(c) || digit.test(c) || special.has(c);
  const pathChar = (c: string): boolean => lower.test(c) || upper.test(c) || digit.test(c) || special.has(c);

  it('accepts exactly the allowed characters for every code point 0..255 (trust domain and path)', () => {
    for (let i = 0; i < 256; i++) {
      if (i === 0x2f) continue; // '/' is the delimiter
      const c = String.fromCharCode(i);
      const td = codeOf(() => parseSpiffeId(`spiffe://trustdomain${c}/path`));
      expect(td === 'ok', `trust domain char ${i.toString(16)}`).toBe(tdChar(c));
      const path = codeOf(() => parseSpiffeId(`spiffe://trustdomain/path${c}`));
      expect(path === 'ok', `path char ${i.toString(16)}`).toBe(pathChar(c));
    }
  });

  it('reports the specific error code for bad scheme, missing trust domain, empty and dot segments', () => {
    const c = (s: string): string => codeOf(() => parseSpiffeId(s));
    expect(c('')).toBe('malformed_spiffe_id');
    expect(c('s')).toBe('malformed_spiffe_id');
    expect(c('spiffe:/')).toBe('malformed_spiffe_id');
    expect(c('Spiffe://')).toBe('malformed_spiffe_id');
    expect(c('spiffe://')).toBe('empty_trust_domain');
    expect(c('spiffe:///')).toBe('empty_trust_domain');
    expect(c('spiffe://trustdomain/')).toBe('invalid_path');
    expect(c('spiffe://trustdomain//')).toBe('invalid_path');
    expect(c('spiffe://trustdomain//path')).toBe('invalid_path');
    expect(c('spiffe://trustdomain/path/')).toBe('invalid_path');
    for (const dot of ['/.', '/./path', '/path/./other', '/path/..', '/..', '/../path', '/path/../other']) {
      expect(c(`spiffe://trustdomain${dot}`), dot).toBe('invalid_path');
    }
    for (const ok of ['/.path', '/..path', '/...']) expect(c(`spiffe://trustdomain${ok}`), ok).toBe('ok');
    expect(c('spiffe://trustdomain')).toBe('ok'); // the path is optional
    // percent-encoding is never decoded
    expect(c('spiffe://%F0%9F%A4%AF/path')).toBe('invalid_trust_domain');
    expect(c('spiffe://trustdomain/%F0%9F%A4%AF')).toBe('invalid_path');
    expect(c('spiffe://%62%61%64/path')).toBe('invalid_trust_domain');
    expect(c('spiffe://trustdomain/%62%61%64')).toBe('invalid_path');
  });

  it('enforces the length limits (trust domain 255, whole ID 2048)', () => {
    expect(codeOf(() => parseSpiffeId(`spiffe://${'a'.repeat(255)}/x`))).toBe('ok');
    expect(codeOf(() => parseSpiffeId(`spiffe://${'a'.repeat(256)}/x`))).toBe('trust_domain_too_long');
    expect(codeOf(() => parseSpiffeId(`spiffe://td/${'a'.repeat(2048)}`))).toBe('id_too_long');
  });

  it('agrees with py-spiffe on all 545 candidate strings, except its case-insensitive scheme and trust domain', () => {
    const ids = jsonFixture('pyspiffe.json').ids;
    if (!Array.isArray(ids)) throw new Error('bad fixture');
    let compared = 0;
    for (const entry of ids) {
      if (!isRecord(entry)) throw new Error('bad entry');
      const s = String(entry.id);
      const ours = codeOf(() => parseSpiffeId(s)) === 'ok';
      const theirs = entry.py_valid === true;
      // Documented py-spiffe leniencies: it ignores the 2048-byte and 255-byte limits and is case-insensitive about
      // the scheme and trust domain, while the SPIFFE-ID standard and go-spiffe require them lowercase; and it accepts a
      // newline at the end of a segment (a regular-expression `$` quirk), which the standard forbids.
      if (theirs && !ours && (overLimit(s) || parseSpiffeIdLower(s) || s.includes('\n'))) continue;
      expect(ours, JSON.stringify(s.slice(0, 60))).toBe(theirs);
      compared++;
    }
    expect(compared).toBeGreaterThan(500);
  });
});

// ---------------------------------------------------------------------------------------------
describe('X.509-SVID: go-spiffe testdata', () => {
  // The files were issued in 2020; verify "as of" a moment inside every certificate's validity.
  const AT_CHAIN = new Date('2020-03-24T14:30:00Z');

  it('parses the good leaf and the leaf of a leaf-and-intermediate bundle', () => {
    expect(parseX509Svid(gs('good-leaf-only')).spiffeId.id).toBe('spiffe://example.org/workload-1');
    expect(parseX509Svid(gs('good-leaf-and-intermediate')).spiffeId.id).toBe('spiffe://example.org/workload-1');
  });

  it('rejects each wrong leaf with the specific rule it violates', () => {
    expect(codeOf(() => parseX509Svid(gs('wrong-leaf-ca-true')))).toBe('leaf_is_ca');
    expect(codeOf(() => parseX509Svid(gs('wrong-leaf-cert-sign')))).toBe('leaf_cert_sign');
    expect(codeOf(() => parseX509Svid(gs('wrong-leaf-crl-sign')))).toBe('leaf_crl_sign');
    expect(codeOf(() => parseX509Svid(gs('wrong-leaf-no-digital-signature')))).toBe('leaf_no_digital_signature');
    expect(codeOf(() => parseX509Svid(gs('wrong-leaf-empty-id')))).toBe('no_uri_san');
  });

  it('verifies the good leaf-and-intermediate chain against its signing certificate as the bundle', () => {
    const [leaf, ca] = certsIn(gs('good-leaf-and-intermediate'));
    const svid = verifyX509Svid(gs('good-leaf-and-intermediate'), { trustDomain: 'example.org', roots: [ca!], now: AT_CHAIN });
    expect(svid.spiffeId.id).toBe('spiffe://example.org/workload-1');
    // the leaf alone, with the signer as the bundle, verifies too
    expect(verifyX509Svid([leaf!], { trustDomain: 'example.org', roots: [ca!], now: AT_CHAIN }).spiffeId.path).toBe('/workload-1');
  });

  it('rejects the go-spiffe signing certificates that lack CA:TRUE or keyCertSign', () => {
    const noCa = gs('wrong-intermediate-no-ca');
    const noKcs = gs('wrong-intermediate-no-key-cert-sign');
    const at = new Date('2022-01-01T00:00:00Z');
    expect(codeOf(() => verifyX509Svid(noCa, { trustDomain: 'example.org', roots: [certsIn(noCa)[1]!], now: at }))).toBe('chain_not_ca');
    expect(codeOf(() => verifyX509Svid(noKcs, { trustDomain: 'example.org', roots: [certsIn(noKcs)[1]!], now: at }))).toBe('chain_no_key_cert_sign');
  });

  it('rejects the good chain when verified after expiry, before issuance, or against the wrong trust domain or bundle', () => {
    const [, ca] = certsIn(gs('good-leaf-and-intermediate'));
    const chain = gs('good-leaf-and-intermediate');
    const base = { trustDomain: 'example.org', roots: [ca!] };
    expect(codeOf(() => verifyX509Svid(chain, { ...base, now: new Date('2020-03-24T16:00:00Z') }))).toBe('chain_expired');
    expect(codeOf(() => verifyX509Svid(chain, { ...base, now: new Date('2020-03-24T13:00:00Z') }))).toBe('chain_expired');
    expect(codeOf(() => verifyX509Svid(chain, { ...base, trustDomain: 'other.org', now: AT_CHAIN }))).toBe('chain_trust_domain_mismatch');
    expect(codeOf(() => verifyX509Svid(chain, { ...base, roots: [gen('root')], now: AT_CHAIN }))).toBe('chain_untrusted_root');
  });
});

// ---------------------------------------------------------------------------------------------
describe('X.509-SVID: generated PKI (OpenSSL), chain verification', () => {
  const NOW = new Date('2027-06-01T00:00:00Z');
  const opts = { trustDomain: 'example.org', roots: [gen('root')], now: NOW };

  it('accepts a leaf under an intermediate, and a leaf signed directly by the root', () => {
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], opts).spiffeId.id).toBe('spiffe://example.org/workload/db');
    expect(verifyX509Svid([gen('leaf-direct')], opts).spiffeId.path).toBe('/workload/db');
    expect(verifyX509Svid(gen('leaf') + gen('inter0'), opts).spiffeId.path).toBe('/workload/db'); // one PEM, two certificates
  });

  it('accepts the chain when the bundle lists the intermediate itself', () => {
    expect(verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [gen('inter0')] }).spiffeId.path).toBe('/workload/db');
  });

  it('rejects the SPIFFE-specific leaf violations', () => {
    const c = (n: string): string => codeOf(() => verifyX509Svid([gen(n), gen('inter0')], opts));
    expect(c('leaf-is-ca')).toBe('leaf_is_ca');
    expect(c('leaf-cert-sign')).toBe('leaf_cert_sign');
    expect(c('leaf-crl-sign')).toBe('leaf_crl_sign');
    expect(c('leaf-no-digital-signature')).toBe('leaf_no_digital_signature');
    expect(c('leaf-no-key-usage')).toBe('leaf_no_digital_signature');
    expect(c('leaf-root-path')).toBe('leaf_root_path');
    expect(c('leaf-two-uri')).toBe('multiple_uri_san');
    expect(c('leaf-dns-only')).toBe('no_uri_san');
    expect(c('leaf-unknown-critical')).toBe('unsupported_critical_extension');
    expect(c('leaf-other-td')).toBe('chain_trust_domain_mismatch');
  });

  it('rejects bad chains with the specific reason, matching OpenSSL and Python cryptography', () => {
    const cross = jsonFixture('pki-crosscheck.json').cases;
    if (!Array.isArray(cross)) throw new Error('bad fixture');
    const reasons: Record<string, string> = {
      'leaf via inter0 to root': 'ok',
      'leaf signed directly by root': 'ok',
      'leaf under inter-under-inter0 (pathlen 0 exceeded)': 'chain_path_len',
      'leaf under inter without keyCertSign': 'chain_no_key_cert_sign',
      'leaf under inter that is not a CA': 'chain_not_ca',
      'expired leaf': 'chain_expired',
      'chain to an unrelated root': 'chain_untrusted_root',
      'missing intermediate': 'chain_untrusted_root',
      'before validity starts': 'chain_expired',
    };
    expect(cross.length).toBe(Object.keys(reasons).length);
    for (const c of cross) {
      if (!isRecord(c)) throw new Error('bad case');
      const read = (n: unknown): string => gen(String(n).replace(/\.pem$/, ''));
      const roots = (c.roots as string[]).map(read);
      const chain = [read(c.leaf), ...(c.untrusted as string[]).map(read)];
      const ours = codeOf(() => verifyX509Svid(chain, { trustDomain: 'example.org', roots, now: new Date(String(c.at)) }));
      expect(ours === 'ok', String(c.name)).toBe(c.openssl === true);
      expect(c.openssl).toBe(c.cryptography);
      expect(ours, String(c.name)).toBe(reasons[String(c.name)]);
    }
  });

  it('rejects an empty chain, an over-long chain and an empty bundle', () => {
    expect(codeOf(() => verifyX509Svid([], opts))).toBe('chain_empty');
    expect(codeOf(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, maxChainLength: 1 }))).toBe('chain_too_long');
    expect(codeOf(() => verifyX509Svid([gen('leaf'), gen('inter0')], { ...opts, roots: [] }))).toBe('chain_untrusted_root');
  });

  it('refuses a leaf that is presented as its own trust anchor', () => {
    expect(codeOf(() => verifyX509Svid([gen('leaf')], { ...opts, roots: [gen('leaf')] }))).toBe('chain_untrusted_root');
  });

  it('rejects a tampered certificate (flipped signature byte)', () => {
    const der = Buffer.from(gen('leaf').replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
    der[der.length - 1] = (der[der.length - 1] ?? 0) ^ 1;
    expect(codeOf(() => verifyX509Svid([new Uint8Array(der), gen('inter0')], opts))).toBe('chain_signature');
  });
});

// ---------------------------------------------------------------------------------------------
describe('JWT-SVID: py-spiffe verdicts on PyJWT-signed tokens', () => {
  const cases = jsonFixture('pyspiffe.json').jwt;
  if (!Array.isArray(cases)) throw new Error('bad fixture');

  const expectedReason: Record<string, string> = {
    'wrong audience': 'jose:JWTClaimValidationFailed',
    expired: 'jose:JWTExpired',
    'missing exp': 'missing_exp',
    'missing aud': 'jose:JWTClaimValidationFailed',
    'sub is not a SPIFFE ID': 'invalid_subject',
    'sub with trailing slash': 'invalid_subject',
    'signed by another key': 'jose:JWSSignatureVerificationFailed',
    'typ is not JWT': 'invalid_typ',
    'trust domain of another bundle': 'trust_domain_mismatch',
  };

  for (const raw of cases) {
    if (!isRecord(raw)) throw new Error('bad case');
    const name = String(raw.name);
    it(`${name}: same verdict as py-spiffe, with the reason`, async () => {
      const key = (await importJWK(raw.jwk as JWK, String(raw.alg))) as KeyLike;
      const res = await asyncCodeOf(() =>
        verifyJwtSvid(String(raw.token), { audience: String(raw.audience), key, trustDomain: 'example.org' }),
      );
      expect(res === 'ok', `${name} -> ${res}`).toBe(raw.py_valid === true);
      if (raw.py_valid !== true) expect(res, name).toBe(expectedReason[name]);
    });
  }
});

describe('JWT-SVID: algorithm policy', () => {
  async function token(alg: string, key: KeyLike | Uint8Array): Promise<string> {
    return new SignJWT({ sub: 'spiffe://example.org/w' })
      .setProtectedHeader({ alg, typ: 'JWT' })
      .setAudience('rs')
      .setExpirationTime('1h')
      .sign(key);
  }

  it('rejects an HS256 token when the verifier is handed raw key bytes (algorithm confusion)', async () => {
    const secret = new Uint8Array(32).fill(7);
    const t = await token('HS256', secret);
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: secret }))).toBe('jose:JOSEAlgNotAllowed');
  });

  it('refuses to be configured with HMAC or none, and rejects EdDSA unless explicitly allowed', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA');
    const t = await token('EdDSA', privateKey);
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey }))).toBe('jose:JOSEAlgNotAllowed');
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey, algorithms: ['EdDSA'] }))).toBe('ok');
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey, algorithms: ['HS256'] }))).toBe('forbidden_algorithm');
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey, algorithms: ['none'] }))).toBe('forbidden_algorithm');
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey, algorithms: [] }))).toBe('forbidden_algorithm');
  });

  it('rejects an unsigned (alg none) token', async () => {
    const b = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
    const t = `${b({ alg: 'none', typ: 'JWT' })}.${b({ sub: 'spiffe://example.org/w', aud: 'rs', exp: 4102444800 })}.`;
    const { publicKey } = await generateKeyPair('ES256');
    expect(await asyncCodeOf(() => verifyJwtSvid(t, { audience: 'rs', key: publicKey }))).not.toBe('ok');
  });
});
