import { beforeAll, describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair, type KeyLike } from 'jose';
import { IdJagVerificationError, MAX_ID_JAG_CHARS, verifyIdJag } from './index';

const ISS = 'https://idp.example.com';
const AUD = 'https://resource.example.com';
const TYP = 'oauth-id-jag+jwt';
let priv: KeyLike;
let pub: KeyLike;
beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  priv = kp.privateKey;
  pub = kp.publicKey;
});
const mint = (over: Record<string, unknown> = {}, typ: string | undefined = TYP) => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: ISS, sub: 'u', aud: AUD, iat: now, exp: now + 300, jti: 'j1', client_id: 'rc', act: { sub: 'ag' }, scope: 'a', ...over })
    .setProtectedHeader({ alg: 'EdDSA', ...(typ !== undefined ? { typ } : {}) }).sign(priv);
};
const settle = (p: Promise<unknown>) => p.then(() => 'ok', (e: IdJagVerificationError) => `${e.code}: ${e.message}`);
const full = { issuer: ISS, audience: AUD, clientId: 'rc', consumeJti: () => true };

describe('strict draft mode is the default', () => {
  it('a conforming grant verifies with no strictDraft option', async () => {
    expect(await settle(verifyIdJag(await mint(), { ...full, key: pub }))).toBe('ok');
  });
  it('no consumeJti is a config error, not a silent loose mode', async () => {
    expect(await settle(verifyIdJag(await mint(), { issuer: ISS, audience: AUD, clientId: 'rc', key: pub })))
      .toBe('config: verifyIdJag: strictDraft requires opts.consumeJti (single-use store)');
  });
  it('no clientId is a config error', async () => {
    expect(await settle(verifyIdJag(await mint(), { issuer: ISS, audience: AUD, consumeJti: () => true, key: pub })))
      .toBe('config: verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)');
  });
  it('a loose-shaped grant (no typ, client_id or jti) is refused by default', async () => {
    expect(await settle(verifyIdJag(await mint({}, undefined), { ...full, key: pub }))).toBe('grant: ID-JAG header typ must be "oauth-id-jag+jwt"');
    expect(await settle(verifyIdJag(await mint({ client_id: undefined }), { ...full, key: pub }))).toBe('grant: ID-JAG is missing "client_id"');
    expect(await settle(verifyIdJag(await mint({ jti: undefined }), { ...full, key: pub }))).toBe('grant: ID-JAG is missing "jti"');
  });
  it('only the literal false opts out; undefined, null and 0 stay strict', async () => {
    const loose = await mint({ client_id: undefined, jti: undefined }, undefined);
    expect(await settle(verifyIdJag(loose, { issuer: ISS, audience: AUD, key: pub, strictDraft: false }))).toBe('ok');
    for (const v of [undefined, null, 0, '']) {
      expect((await settle(verifyIdJag(loose, { issuer: ISS, audience: AUD, key: pub, strictDraft: v as never }))).startsWith('config:')).toBe(true);
    }
  });
  it('a jti is consumed once and a second presentation is refused', async () => {
    const seen = new Set<string>();
    const consumeJti = (j: string) => (seen.has(j) ? false : (seen.add(j), true));
    const jwt = await mint();
    expect(await settle(verifyIdJag(jwt, { ...full, consumeJti, key: pub }))).toBe('ok');
    expect(await settle(verifyIdJag(jwt, { ...full, consumeJti, key: pub }))).toBe('grant: ID-JAG jti was already used or the single-use store failed');
  });
  it('the jti is consumed last: a grant refused for any other reason never burns it', async () => {
    const seen: string[] = [];
    const consumeJti = (j: string) => { seen.push(j); return true; };
    await settle(verifyIdJag(await mint({ act: undefined }), { ...full, consumeJti, key: pub }));
    await settle(verifyIdJag(await mint({ scope: undefined }), { ...full, consumeJti, key: pub }));
    await settle(verifyIdJag(await mint({ client_id: 'other' }), { ...full, consumeJti, key: pub }));
    expect(seen).toEqual([]);
  });
  it('an oversize token is refused before parsing; the limit is exact', async () => {
    expect(MAX_ID_JAG_CHARS).toBe(16384);
    expect(await settle(verifyIdJag('a'.repeat(MAX_ID_JAG_CHARS + 1), { ...full, key: pub }))).toBe('invalid_token: verifyIdJag: jwt exceeds the size limit');
    expect(await settle(verifyIdJag('a'.repeat(MAX_ID_JAG_CHARS), { ...full, key: pub }))).not.toBe('invalid_token: verifyIdJag: jwt exceeds the size limit');
  });
  it('a multi-audience grant, a missing act and a missing scope are refused in strict mode too', async () => {
    expect((await settle(verifyIdJag(await mint({ aud: [AUD, 'https://x.example.com'], azp: 'rc' }), { ...full, key: pub }))).startsWith('audience:')).toBe(true);
    expect((await settle(verifyIdJag(await mint({ act: undefined }), { ...full, key: pub }))).startsWith('actor:')).toBe(true);
    expect((await settle(verifyIdJag(await mint({ scope: undefined }), { ...full, key: pub }))).startsWith('scope:')).toBe(true);
  });
});
