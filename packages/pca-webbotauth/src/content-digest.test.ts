import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { contentDigestHeader, parseContentDigest, verifyContentDigest, signRequest, verifySignedRequest, buildKeyDirectory, jwkThumbprint } from './index';
import { generateKeyPair } from '@atlasauth/pca';

// RFC 9530 §2 example content: the JSON body `{"hello": "world"}` (no trailing newline).
const BODY = '{"hello": "world"}';
// Known answers from RFC 9530 §2 / Appendix B (also the body digest of the RFC 9421 Appendix B.2 test request).
// Cross-checked below against node:crypto so a typo here cannot pass silently.
const SHA256 = 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';
const SHA512 = 'WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==';

describe('RFC 9530 Content-Digest', () => {
  it('known answers agree with node:crypto', () => {
    expect(createHash('sha256').update(BODY).digest('base64')).toBe(SHA256);
    expect(createHash('sha512').update(BODY).digest('base64')).toBe(SHA512);
  });

  it('builds the dictionary field for sha-256 and sha-512', () => {
    expect(contentDigestHeader(BODY)).toBe(`sha-256=:${SHA256}:`);
    expect(contentDigestHeader(BODY, ['sha-512'])).toBe(`sha-512=:${SHA512}:`);
    expect(contentDigestHeader(new TextEncoder().encode(BODY), ['sha-256', 'sha-512', 'sha-256'])).toBe(`sha-256=:${SHA256}:, sha-512=:${SHA512}:`);
    expect(() => contentDigestHeader(BODY, [])).toThrow();
    expect(() => contentDigestHeader(BODY, ['md5' as never])).toThrow(/unsupported/);
  });

  it('verifies a matching field and reports the matched algorithms', () => {
    expect(verifyContentDigest(`sha-512=:${SHA512}:`, BODY)).toEqual({ valid: true, matched: ['sha-512'] });
    expect(verifyContentDigest(`sha-256=:${SHA256}:, sha-512=:${SHA512}:`, BODY).matched).toEqual(['sha-256', 'sha-512']);
  });

  it('ignores unsupported algorithms but needs at least one supported one', () => {
    expect(verifyContentDigest(`md5=:AAAAAAAAAAAAAAAAAAAAAA==:, sha-256=:${SHA256}:`, BODY).valid).toBe(true);
    const r = verifyContentDigest('md5=:AAAAAAAAAAAAAAAAAAAAAA==:', BODY);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/no supported/);
  });

  it('fails closed on any mismatch, a missing required algorithm, or a malformed field', () => {
    expect(verifyContentDigest(`sha-256=:${SHA256}:`, BODY + ' ').valid).toBe(false);
    // one good and one bad member: the whole field fails
    expect(verifyContentDigest(`sha-256=:${SHA256}:, sha-512=:${SHA256}:`, BODY).valid).toBe(false);
    expect(verifyContentDigest(`sha-256=:${SHA256}:`, BODY, { require: ['sha-512'] }).reason).toMatch(/required sha-512/);
    for (const bad of [undefined, '', 'sha-256', `sha-256=${SHA256}`, `sha-256=:${SHA256}:;p=1`, `sha-256=:${SHA256}:, sha-256=:${SHA256}:`, 'sha-256=:abc:', `SHA-256=:${SHA256}:`]) {
      expect(verifyContentDigest(bad, BODY).valid).toBe(false);
    }
  });

  it('parseContentDigest returns the raw bytes', () => {
    const m = parseContentDigest(`sha-256=:${SHA256}:`);
    expect(Buffer.from(m.get('sha-256')!).toString('base64')).toBe(SHA256);
  });

  it('a covered content-digest binds the body to an RFC 9421 signature', async () => {
    const key = generateKeyPair();
    const keyid = jwkThumbprint(key.publicKey);
    const jwks = buildKeyDirectory([{ publicKey: key.publicKey, keyid }]);
    const url = 'https://api.example.com/v1/orders';
    const headers = { 'content-digest': contentDigestHeader(BODY) };
    const signed = signRequest({ method: 'POST', url, headers, key, keyid, coverHeaders: ['content-digest'] });
    const all = { ...headers, ...signed.headers };
    expect((await verifySignedRequest({ method: 'POST', url, headers: all }, { jwks })).valid).toBe(true);
    expect(verifyContentDigest(all['content-digest'], BODY).valid).toBe(true);
    // A swapped body with a recomputed digest breaks the signature.
    const swapped = { ...all, 'content-digest': contentDigestHeader('{"hello": "mallory"}') };
    expect((await verifySignedRequest({ method: 'POST', url, headers: swapped }, { jwks })).valid).toBe(false);
  });
});
