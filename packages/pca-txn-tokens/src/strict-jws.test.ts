import { agent, compactJwsAliases, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { fromTransactionToken, toTransactionToken } from './index';

describe('canonical-spelling gate (re-encoded Transaction Token strings are rejected)', () => {
  it('rejects every alias; the original passes', async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, aud: 'https://api.acme.com' });
    const tts = generateKeyPair();
    const jwt = await toTransactionToken({ chain: a.chain, action: { verb: 'stripe.refund', resource: 'c', aud: 'https://api.acme.com' }, issuerKey: tts.secretKey, issuer: 'iss' });
    await fromTransactionToken(jwt, tts.publicKey);
    const aliases = compactJwsAliases(jwt);
    expect(aliases.length).toBeGreaterThanOrEqual(7);
    for (const al of aliases) await expect(fromTransactionToken(al.token, tts.publicKey), al.name).rejects.toThrow(/non-canonical compact JWS/);
  });
});
