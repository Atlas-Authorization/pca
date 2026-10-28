import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { gnapContentDigest, signGnapRequest, verifyGnapRequest } from './index';

// The one signed jwsd example RFC 9635 publishes (section 7.3.3). It is RS256, which this package does not accept, so the
// vector is used three ways: (1) its signature is verified independently with node:crypto, proving the example is genuine;
// (2) the package refuses it with the exact reason; (3) its header fields and content are re-signed with an Ed25519 key and
// the package must accept that, with the payload equal to an independently computed SHA-256 of the content.

interface Fixture {
  detachedJws: string;
  rsaPublicKey: { kty: 'RSA'; e: string; n: string };
  content: string;
  contentLength: number;
}
const fx = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'rfc9635-example.json'), 'utf8')) as Fixture;
const [h64, mid, sig] = fx.detachedJws.split('.') as [string, string, string];
const header = JSON.parse(Buffer.from(h64, 'base64url').toString('utf8')) as Record<string, unknown>;

describe('RFC 9635 7.3.3 example', () => {
  it('is the published header, with the digest spelled out in the middle segment', () => {
    expect(header).toEqual({
      alg: 'RS256',
      created: 1618884475,
      htm: 'POST',
      kid: 'gnap-rsa',
      typ: 'gnap-binding+jwsd',
      uri: 'https://server.example.com/gnap',
    });
    expect(mid).toBe('PGiVuOZUcN1tRtUS6tx2b4cBgw9mPgXG3IPB3wY7ctc');
    expect(Buffer.from(fx.content, 'utf8').length).toBe(fx.contentLength);
  });

  it('its RS256 signature verifies independently over header.digest', () => {
    const key = createPublicKey({ key: fx.rsaPublicKey, format: 'jwk' });
    expect(verify('sha256', Buffer.from(`${h64}.${mid}`), key, Buffer.from(sig, 'base64url'))).toBe(true);
    expect(verify('sha256', Buffer.from(`${h64}.${mid}x`), key, Buffer.from(sig, 'base64url'))).toBe(false);
  });

  it('is refused by this package: the digest in the middle segment is not the digest of the content it is given', async () => {
    const k = generateKeyPair();
    const r = await verifyGnapRequest({
      detachedJws: fx.detachedJws,
      body: fx.content,
      holder: b64u(k.publicKey),
      htm: 'POST',
      uri: 'https://server.example.com/gnap',
      now: 1618884475 * 1000,
      replayCheck: 'unchecked',
    });
    expect(r).toEqual({ ok: false, reason: 'not a DETACHED compact JWS' });
  });

  it('the same request signed with Ed25519 verifies, and its payload is the independent SHA-256 of the content', async () => {
    const k = generateKeyPair();
    const s = await signGnapRequest({ body: fx.content, key: k, htm: 'POST', uri: 'https://server.example.com/gnap', created: 1618884475, kid: 'gnap-ed' });
    const independent = createHash('sha256').update(Buffer.from(fx.content, 'utf8')).digest();
    expect(Buffer.from(gnapContentDigest(fx.content)).equals(independent)).toBe(true);
    const [sh, smid] = s.detachedJws.split('.') as [string, string];
    expect(smid).toBe('');
    // RFC-style spelling (digest in the middle) is accepted as the same proof
    const spelled = `${sh}.${independent.toString('base64url')}.${s.detachedJws.split('.')[2]}`;
    for (const jws of [s.detachedJws, spelled]) {
      const r = await verifyGnapRequest({ detachedJws: jws, body: fx.content, holder: s.holder, htm: 'POST', uri: 'https://server.example.com/gnap', now: 1618884475 * 1000, replayCheck: 'unchecked' });
      expect(r.ok).toBe(true);
    }
    const edited = await verifyGnapRequest({ detachedJws: s.detachedJws, body: fx.content + ' ', holder: s.holder, htm: 'POST', uri: 'https://server.example.com/gnap', now: 1618884475 * 1000, replayCheck: 'unchecked' });
    expect(edited).toEqual({ ok: false, reason: 'jwsd signature does not verify under the holder key (or body was tampered)' });
  });

  it('a request with no content signs an empty payload (RFC 9635 7.3.3)', async () => {
    expect(gnapContentDigest(undefined).length).toBe(0);
    const k = generateKeyPair();
    const s = await signGnapRequest({ body: undefined, key: k, htm: 'GET', uri: 'https://server.example.com/gnap/x', created: 1618884475 });
    const r = await verifyGnapRequest({ detachedJws: s.detachedJws, body: undefined, holder: s.holder, htm: 'GET', uri: 'https://server.example.com/gnap/x', now: 1618884475 * 1000, replayCheck: 'unchecked' });
    expect(r.ok).toBe(true);
  });
});
