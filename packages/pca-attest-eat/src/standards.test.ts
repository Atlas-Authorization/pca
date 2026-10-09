/**
 * Standards conformance for the EAT-as-JWT layer.
 *
 *  - Official vectors (fixtures/standards-vectors.json; provenance and sha256 in fixtures/PROVENANCE.json):
 *    RFC 7515 A.3 (ES256) and RFC 8037 A.4 (Ed25519) signature vectors, the RFC 7519 6.1 unsecured JWT,
 *    and the RFC 9711 Appendix A JSON claims sets and HS256 JWT example.
 *  - Cross-implementation: tokens built here are verified by `jose` and tokens signed by `jose` are
 *    verified here, for both EdDSA and ES256 (exact jose version in package.json).
 *  - Negative cases assert the failure REASON, not just that something threw.
 *
 * Not covered: CWT / COSE (RFC 8392, RFC 9711 A.2.1). This package emits and consumes the JWT form only.
 */
import { createHash, createHmac, createPublicKey, generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SignJWT, compactVerify, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  EAT_TYP,
  appraise,
  buildEAT,
  deriveChannelCnf,
  generateEatKeyPair,
  verifyChannelBinding,
  verifyEAT,
  verifyFreshness,
  type EatAlg,
} from './index';

const FIX = join(__dirname, '..', 'fixtures');
interface Vectors {
  rfc7515_appendixA3_ES256: { jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }; compactJws: string };
  rfc8037_appendixA4_Ed25519: { jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }; compactJws: string };
  rfc7519_section6_1_unsecuredJwt: { compactJws: string };
  rfc9711_appendixA16_attestationResultsJson: Record<string, unknown>;
  rfc9711_appendixA17_jsonTokenWithSubmodules: Record<string, unknown>;
  rfc9711_appendixA23_hs256Jwt: { compactJws: string; hmacKeyAscii: string };
  rfc9782_section6_4_mediaType: { type: string; subtype: string };
}
const V = JSON.parse(readFileSync(join(FIX, 'standards-vectors.json'), 'utf8')) as Vectors;

const NOW_MS = 1_800_000_000_000;
const ISS = 'https://attester.example';

function throwsWith(fn: () => unknown, re: RegExp): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  expect(caught, 'expected a throw').toBeInstanceOf(Error);
  expect((caught as Error).message).toMatch(re);
}

const b64u = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');
function tamperSig(jws: string): string {
  const [h, p, s] = jws.split('.') as [string, string, string];
  const raw = Buffer.from(s, 'base64url');
  raw[0] = (raw[0] ?? 0) ^ 0x01;
  return `${h}.${p}.${raw.toString('base64url')}`;
}

describe('fixtures', () => {
  it('match the sha256 recorded in PROVENANCE.json', () => {
    const prov = JSON.parse(readFileSync(join(FIX, 'PROVENANCE.json'), 'utf8')) as { files: { file: string; sha256: string; kind: string; sources: { rfc: number; url: string; sha256: string }[] }[] };
    for (const f of prov.files) {
      expect(createHash('sha256').update(readFileSync(join(FIX, f.file))).digest('hex')).toBe(f.sha256);
      expect(f.kind).toBe('official-rfc-examples');
      expect(f.sources.map((s) => s.rfc)).toEqual([7515, 8037, 7519, 9711, 9782]);
    }
  });
});

describe('official JWS signature vectors through verifyEAT', () => {
  it('RFC 7515 A.3 (ES256): the signature verifies; only the missing iat stops the token', () => {
    const { jwk, compactJws } = V.rfc7515_appendixA3_ES256;
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    // The vector has no `typ` and no `iat` (it is a plain JWS). Passing the signature check and then
    // failing on `iat` proves the ES256 (raw r||s) verification path accepted the official signature.
    throwsWith(() => verifyEAT(compactJws, key, { requireTyp: false }), /missing or non-numeric `iat`/);
    // The same vector verifies independently in jose, so the vector is good.
    return compactVerify(compactJws, key).then((r) => {
      expect(JSON.parse(Buffer.from(r.payload).toString('utf8'))).toMatchObject({ iss: 'joe', exp: 1300819380 });
    });
  });

  it('RFC 7515 A.3: any bit-flip in the signature or payload is reported as a signature failure', () => {
    const { jwk, compactJws } = V.rfc7515_appendixA3_ES256;
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    throwsWith(() => verifyEAT(tamperSig(compactJws), key, { requireTyp: false }), /signature does not verify/);
    const [h, p, s] = compactJws.split('.') as [string, string, string];
    const altered = Buffer.from(p, 'base64url').toString('utf8').replace('joe', 'jan');
    throwsWith(() => verifyEAT(`${h}.${b64u(altered)}.${s}`, key, { requireTyp: false }), /signature does not verify/);
  });

  it('RFC 8037 A.4 (Ed25519): the signature verifies; the non-JSON payload is the next failure', () => {
    const { jwk, compactJws } = V.rfc8037_appendixA4_Ed25519;
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    throwsWith(() => verifyEAT(compactJws, key, { requireTyp: false }), /payload is not valid JSON/);
    throwsWith(() => verifyEAT(tamperSig(compactJws), key, { requireTyp: false }), /signature does not verify/);
  });

  it('a vector is rejected under the wrong key type or the wrong key (never accepted)', () => {
    const es = V.rfc7515_appendixA3_ES256;
    const ed = V.rfc8037_appendixA4_Ed25519;
    const esKey = createPublicKey({ key: es.jwk, format: 'jwk' });
    const edKey = createPublicKey({ key: ed.jwk, format: 'jwk' });
    // Algorithm/key confusion: an ES256 token under an Ed25519 key and vice versa must throw.
    expect(() => verifyEAT(es.compactJws, edKey, { requireTyp: false })).toThrow(Error);
    expect(() => verifyEAT(ed.compactJws, esKey, { requireTyp: false })).toThrow(Error);
    // Right type, wrong key.
    const other = generateKeyPairSync('ed25519').publicKey;
    throwsWith(() => verifyEAT(ed.compactJws, other, { requireTyp: false }), /signature does not verify/);
  });

  it('RFC 7519 6.1 unsecured JWT (alg none) is refused', () => {
    const key = generateEatKeyPair('EdDSA').publicKey;
    throwsWith(() => verifyEAT(V.rfc7519_section6_1_unsecuredJwt.compactJws, key, { requireTyp: false }), /empty JWS segment/);
    // And with a non-empty signature segment, the algorithm itself is refused.
    const [h, p] = V.rfc7519_section6_1_unsecuredJwt.compactJws.split('.') as [string, string];
    throwsWith(() => verifyEAT(`${h}.${p}.AAAA`, key, { requireTyp: false }), /missing or unsupported `alg`/);
  });

  it('the RFC 9711 A.2.3 HS256 JWT is refused (HMAC is not a supported EAT algorithm here), even with the right shared key', () => {
    const { compactJws, hmacKeyAscii } = V.rfc9711_appendixA23_hs256Jwt;
    // Confirm the vector itself is a valid HS256 JWT with the documented key "xxxxxx".
    const [h, p, s] = compactJws.split('.') as [string, string, string];
    expect(createHmac('sha256', hmacKeyAscii).update(`${h}.${p}`).digest('base64url')).toBe(s);
    const anyKey = generateEatKeyPair('EdDSA').publicKey;
    throwsWith(() => verifyEAT(compactJws, anyKey, { requireTyp: false }), /missing or unsupported `alg`/);
  });

  it('structural rejects: wrong segment count, empty segment, non-JSON header, non-string token', () => {
    const key = generateEatKeyPair('EdDSA').publicKey;
    throwsWith(() => verifyEAT('a.b', key), /expected a compact JWS/);
    throwsWith(() => verifyEAT('a.b.c.d', key), /expected a compact JWS/);
    throwsWith(() => verifyEAT('a..c', key), /empty JWS segment/);
    throwsWith(() => verifyEAT('!!.b.c', key), /header is not valid JSON/);
    throwsWith(() => verifyEAT(undefined as unknown as string, key), /not a string/);
  });
});

describe('cross-implementation with jose', () => {
  const algs: EatAlg[] = ['EdDSA', 'ES256'];

  for (const alg of algs) {
    it(`${alg}: a token built by this package verifies in jose, with the header and claims intact`, async () => {
      const { publicKey, privateKey } = generateEatKeyPair(alg);
      const token = buildEAT({ issuer: ISS, key: privateKey, alg, nonce: 'n-123', channelId: 'chan-1', dbgstat: 'disabled', ueid: 'AZj1Ck_2wFhhyIYNE6Y4', oemid: 'iUWt', now: NOW_MS });
      const r = await jwtVerify(token, publicKey, { typ: EAT_TYP, issuer: ISS, currentDate: new Date(NOW_MS) });
      expect(r.protectedHeader).toEqual({ alg, typ: EAT_TYP });
      expect(r.payload).toMatchObject({ iss: ISS, iat: NOW_MS / 1000, eat_nonce: 'n-123', dbgstat: 'disabled', ueid: 'AZj1Ck_2wFhhyIYNE6Y4', oemid: 'iUWt' });
      expect((r.payload as { cnf: { tls_exporter: string } }).cnf.tls_exporter).toBe(deriveChannelCnf('chan-1').tls_exporter);
    });

    it(`${alg}: a token signed by jose verifies here, and the parsed claims match`, async () => {
      const { publicKey, privateKey } = generateEatKeyPair(alg);
      const cnf = deriveChannelCnf('chan-2');
      const token = await new SignJWT({ eat_nonce: 'n-456', cnf, dbgstat: 'disabled-since-boot', ueid: 'AJj1Ck_2wFhhyIYNE6Y46g==', oemid: 'iUWt' })
        .setProtectedHeader({ alg, typ: EAT_TYP })
        .setIssuer(ISS)
        .setIssuedAt(NOW_MS / 1000)
        .sign(privateKey);
      const claims = verifyEAT(token, publicKey, { issuer: ISS });
      expect(claims).toMatchObject({ iss: ISS, iat: NOW_MS / 1000, eat_nonce: 'n-456', dbgstat: 'disabled-since-boot', oemid: 'iUWt', ueid: 'AJj1Ck_2wFhhyIYNE6Y46g==' });
      expect(claims.cnf?.tls_exporter).toBe(cnf.tls_exporter);
      expect(verifyChannelBinding(claims, { channelId: 'chan-2' }).ok).toBe(true);
      expect(verifyFreshness(claims, { expectedNonce: 'n-456', maxAgeMs: 60_000, now: NOW_MS + 1000 }).ok).toBe(true);
    });

    it(`${alg}: signatures from the two implementations are byte-compatible in length (JWS: 64 raw bytes)`, () => {
      const { privateKey } = generateEatKeyPair(alg);
      const token = buildEAT({ issuer: ISS, key: privateKey, alg, nonce: 'n', channelId: 'c', now: NOW_MS });
      expect(Buffer.from(token.split('.')[2] ?? '', 'base64url').length).toBe(64);
    });

    it(`${alg}: jose rejects a token from this package after tampering, and so does verifyEAT (same reason class)`, async () => {
      const { publicKey, privateKey } = generateEatKeyPair(alg);
      const token = tamperSig(buildEAT({ issuer: ISS, key: privateKey, alg, nonce: 'n', channelId: 'c', now: NOW_MS }));
      await expect(jwtVerify(token, publicKey)).rejects.toThrow(/signature verification failed/);
      throwsWith(() => verifyEAT(token, publicKey), /signature does not verify/);
    });
  }

  it('a token whose alg claims ES256 but was signed with DER-encoded ECDSA (the common mistake) is rejected', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const h = b64u(JSON.stringify({ alg: 'ES256', typ: EAT_TYP }));
    const p = b64u(JSON.stringify({ iss: ISS, iat: NOW_MS / 1000 }));
    const der = createSignatureDer(privateKey, `${h}.${p}`);
    throwsWith(() => verifyEAT(`${h}.${p}.${der}`, publicKey), /signature does not verify/);
  });

  it('alg restriction is enforced: an EdDSA token is refused when only ES256 is allowed', () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    const token = buildEAT({ issuer: ISS, key: privateKey, nonce: 'n', channelId: 'c', now: NOW_MS });
    throwsWith(() => verifyEAT(token, publicKey, { algorithms: ['ES256'] }), /alg EdDSA not in the allowed set/);
  });
});

function createSignatureDer(privateKey: KeyObject, input: string): string {
  // Node's default ECDSA encoding is DER; that is what a mis-implemented JWS signer would emit.
  return nodeSign('sha256', Buffer.from(input, 'utf8'), privateKey).toString('base64url');
}

describe('known gap: non-canonical base64url in the signature segment', () => {
  it('padding or embedded whitespace is tolerated by verifyEAT (Node\'s lenient decoder); jose refuses padding', async () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    const token = buildEAT({ issuer: ISS, key: privateKey, nonce: 'n', channelId: 'c', now: NOW_MS });
    const padded = `${token}=`;
    // The signature bytes are unchanged, so authenticity still holds, but the token string is malleable:
    // do not use the raw token text as a replay identifier.
    expect(verifyEAT(padded, publicKey).iss).toBe(ISS);
    expect(verifyEAT(`${token}\n`, publicKey).iss).toBe(ISS);
    expect(verifyEAT(`${token.slice(0, -10)} ${token.slice(-10)}`, publicKey).iss).toBe(ISS);
    // RFC 7515 base64url has no padding; jose enforces that for '='.
    await expect(jwtVerify(padded, publicKey)).rejects.toThrow(/base64url decode/);
  });
});

describe('RFC 9711 Appendix A claims sets as the JWT payload', () => {
  // The appendix claims sets carry no `iss` (it is a JWT claim, not an EAT-specific one), so the verifier
  // that wraps them supplies it. `iat` is supplied for A.1.6; A.1.7 carries its own.
  async function signed(claims: Record<string, unknown>, extra: Record<string, unknown> = {}): Promise<{ token: string; key: KeyObject }> {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    const token = await new SignJWT({ ...claims, ...extra }).setProtectedHeader({ alg: 'EdDSA', typ: EAT_TYP }).sign(privateKey);
    return { token, key: publicKey };
  }

  it('A.1.6 (attestation results): eat_nonce, dbgstat, oemid and ueid are parsed exactly as the RFC writes them', async () => {
    const a16 = V.rfc9711_appendixA16_attestationResultsJson;
    const { token, key } = await signed(a16, { iss: ISS, iat: NOW_MS / 1000 });
    const claims = verifyEAT(token, key);
    expect(claims.eat_nonce).toBe(a16.eat_nonce);
    expect(claims.dbgstat).toBe('disabled-since-boot');
    expect(claims.oemid).toBe('iUWt');
    expect(claims.ueid).toBe('AZj1Ck_2wFhhyIYNE6Y4');
    // The RFC example verifier output has no cnf: the channel-binding gate must refuse it (fail closed).
    const r = verifyChannelBinding(claims, { channelId: 'chan' });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/carries no channel\/key binding \(cnf\)/);
    // And freshness against the RFC's own nonce succeeds only for that exact nonce.
    expect(verifyFreshness(claims, { expectedNonce: 'jkd8KL-8xQk', maxAgeMs: 60_000, now: NOW_MS }).ok).toBe(true);
    expect(verifyFreshness(claims, { expectedNonce: 'jkd8KL-8xQj', maxAgeMs: 60_000, now: NOW_MS }).reason).toMatch(/does not match the server-issued challenge/);
  });

  it('A.1.6 appraises: debug disabled and the endorsed oemid yield an affirming result; a different oemid is rejected', async () => {
    const a16 = V.rfc9711_appendixA16_attestationResultsJson;
    const { token, key } = await signed(a16, { iss: ISS, iat: NOW_MS / 1000 });
    const claims = verifyEAT(token, key);
    const ok = appraise(claims, { requireDebugDisabled: true }, { oemids: ['iUWt'] });
    expect(ok.trustworthy).toBe(true);
    const bad = appraise(claims, { requireDebugDisabled: true }, { oemids: ['AAAA'] });
    expect(bad.tier).toBe('rejected');
    expect(bad.reasons.join(' ')).toMatch(/oemid absent or not endorsed/);
  });

  it('A.1.7 (JSON token): dbgstat "disabled-permanently" and the embedded iat are honoured; submodules are not interpreted', async () => {
    const a17 = V.rfc9711_appendixA17_jsonTokenWithSubmodules;
    const { token, key } = await signed(a17, { iss: ISS });
    const claims = verifyEAT(token, key);
    expect(claims.iat).toBe(1526542894);
    expect(claims.dbgstat).toBe('disabled-permanently');
    expect(claims.ueid).toBe('AJj1Ck_2wFhhyIYNE6Y46g==');
    expect(Object.keys(claims)).not.toContain('submods');
    // A 2018 iat is far outside any sane freshness window.
    expect(verifyFreshness(claims, { expectedNonce: 'lI-IYNE6Rj6O', maxAgeMs: DAY, now: NOW_MS }).reason).toMatch(/stale/);
  });

  it('claims the package does not model are dropped or refused rather than half-trusted', async () => {
    const { token, key } = await signed(V.rfc9711_appendixA16_attestationResultsJson, {
      iss: ISS,
      iat: NOW_MS / 1000,
      oemid: 75000, // RFC 9711 allows a PEN integer oemid in JSON; unsupported here => dropped
      dbgstat: 'Disabled', // not an RFC value (case) => dropped
      eat_nonce: ['jkd8KL-8xQk', 'second'], // RFC 9711 allows an array of nonces => not understood
    });
    const claims = verifyEAT(token, key);
    expect(claims.oemid).toBeUndefined();
    expect(claims.dbgstat).toBeUndefined();
    expect(claims.eat_nonce).toBeUndefined();
    // Dropped claims fail closed downstream.
    expect(verifyFreshness(claims, { expectedNonce: 'jkd8KL-8xQk', maxAgeMs: 60_000, now: NOW_MS }).reason).toMatch(/no eat_nonce/);
    expect(appraise(claims, { requireDebugDisabled: true }, { issuers: [ISS] }).trustworthy).toBe(false);
  });

  it('a token with no iss is refused even though RFC 9711 does not require one (documented stricter profile)', async () => {
    const { token, key } = await signed(V.rfc9711_appendixA16_attestationResultsJson, { iat: NOW_MS / 1000 });
    throwsWith(() => verifyEAT(token, key), /missing or non-string `iss`/);
  });
});

const DAY = 24 * 3_600_000;

describe('media type (RFC 9782 section 6.4, RFC 7515 4.1.9)', () => {
  it('the typ header value is the registered application/eat+jwt subtype', () => {
    expect(V.rfc9782_section6_4_mediaType).toEqual({ type: 'application', subtype: 'eat+jwt' });
    expect(EAT_TYP).toBe(V.rfc9782_section6_4_mediaType.subtype);
  });

  it('a token with the wrong typ is refused with the typ reason', async () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    const token = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' }).setIssuer(ISS).setIssuedAt().sign(privateKey);
    throwsWith(() => verifyEAT(token, publicKey), /typ JWT is not eat\+jwt/);
  });

  it('RFC 7515 4.1.9: short and full typ forms are equivalent, compared case-insensitively', async () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    for (const typ of ['eat+jwt', 'application/eat+jwt', 'APPLICATION/EAT+JWT', 'Eat+JWT']) {
      const token = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', typ }).setIssuer(ISS).setIssuedAt().sign(privateKey);
      expect(verifyEAT(token, publicKey).iss).toBe(ISS);
    }
  });

  it('other typ values stay refused (wrong subtype, wrong top-level type, parameters, non-string, absent)', async () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    for (const typ of ['application/jwt', 'text/eat+jwt', 'application/eat+jwt; x=1', 'eat+jwt ', '/eat+jwt', 'application/', '', 'JWT']) {
      const token = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', typ }).setIssuer(ISS).setIssuedAt().sign(privateKey);
      throwsWith(() => verifyEAT(token, publicKey), /typ .* is not eat\+jwt/);
    }
    const none = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA' }).setIssuer(ISS).setIssuedAt().sign(privateKey);
    throwsWith(() => verifyEAT(none, publicKey), /is not eat\+jwt/);
  });

  it('an explicit opts.typ is compared with the same equivalence', async () => {
    const { publicKey, privateKey } = generateEatKeyPair('EdDSA');
    const token = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', typ: 'application/eat+jwt' }).setIssuer(ISS).setIssuedAt().sign(privateKey);
    expect(verifyEAT(token, publicKey, { typ: 'application/eat+jwt' })).toBeDefined();
    throwsWith(() => verifyEAT(token, publicKey, { typ: 'application/other' }), /is not application\/other/);
  });
});
