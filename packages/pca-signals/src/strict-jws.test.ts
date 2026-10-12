import { compactJwsAliases } from '@atlasauth/pca';
import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { EVENT_TYPES, buildSET, verifySET } from './index';

describe('canonical-spelling gate (re-encoded SET strings are rejected)', () => {
  it('rejects every alias; the original passes', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const set = await buildSET({ issuer: 'https://i', audience: 'a', subject: 'u', key: privateKey, events: { [EVENT_TYPES.grantRevoked]: { grant_ref: 'g', reason: 'r', event_timestamp: 1 } } });
    await verifySET(set, publicKey, { issuer: 'https://i', audience: 'a' });
    for (const al of compactJwsAliases(set)) await expect(verifySET(al.token, publicKey, { issuer: 'https://i', audience: 'a' }), al.name).rejects.toThrow(/non-canonical compact JWS/);
  });
});
