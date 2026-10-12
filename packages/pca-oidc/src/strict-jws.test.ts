import { compactJwsAliases } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { verifyIdToken } from './verify';
import { baseClaims, makeIssuer } from './testkit';

describe('canonical-spelling gate (re-encoded ID token strings are rejected)', () => {
  it('rejects every alias with code invalid_token; the original passes', async () => {
    const idp = await makeIssuer();
    const token = await idp.mint(baseClaims({ issuer: idp.issuer, audience: 'c' }));
    const opts = { issuer: idp.issuer, audience: 'c', key: idp.publicKey };
    await verifyIdToken(token, opts);
    const aliases = compactJwsAliases(token);
    expect(aliases.length).toBeGreaterThanOrEqual(7);
    for (const a of aliases) {
      await expect(verifyIdToken(a.token, opts), a.name).rejects.toMatchObject({ code: 'invalid_token', message: expect.stringMatching(/non-canonical compact JWS/) });
    }
  });
});
