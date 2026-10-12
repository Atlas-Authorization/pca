import { compactJwsAliases } from '@atlasauth/pca';
import { SignJWT, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { verifyJwtSvid } from './index';

describe('canonical-spelling gate (re-encoded JWT-SVID strings are rejected)', () => {
  it('rejects every alias with code malformed_token; the original passes', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const token = await new SignJWT({}).setProtectedHeader({ alg: 'ES256' }).setSubject('spiffe://example.org/ns/a').setAudience('aud').setIssuedAt().setExpirationTime('1h').sign(privateKey);
    await verifyJwtSvid(token, { trustDomain: 'example.org', audience: 'aud', key: publicKey });
    const aliases = compactJwsAliases(token);
    expect(aliases.length).toBeGreaterThanOrEqual(7);
    for (const a of aliases) await expect(verifyJwtSvid(a.token, { trustDomain: 'example.org', audience: 'aud', key: publicKey }), a.name).rejects.toMatchObject({ code: 'malformed_token' });
  });
});
