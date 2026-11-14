import { generateKeyPairSync } from 'node:crypto';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { buildPCActn, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { merchantAllowCaveat, mintDelegatedPaymentToken, spendCapCaveat, verifyDelegatedPaymentToken } from './index';
import { settlementResponseProblems } from './x402-http';

const NOW = 1_800_000_000_000;

describe('delegated payment token with plain JWK keys', () => {
  it('signs with a private JWK and verifies with the public JWK', async () => {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: encodeKey(agent.publicKey), caveats: [spendCapCaveat(500, 'USD'), merchantAllowCaveat(['acme'])] });
    const pcActn = buildPCActn({
      grant,
      chain: [grant],
      plan: [{ id: 'pay', verb: 'pay', resource: 'checkout/sess-1', reversibility_class: 'R2' }],
      nodeId: 'pay',
      counter: 1,
      signerSecret: agent.secretKey,
      aud: 'rs-acme',
      now: NOW,
    });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const token = await mintDelegatedPaymentToken(pcActn, {
      amount: 100,
      merchant: 'acme',
      currency: 'USD',
      session: 'sess-1',
      signingKey: privateKey.export({ format: 'jwk' }) as JWK,
      paymentMethod: { type: 'shared_payment_token', token: 'spt_abc' },
      now: NOW,
      expiresAt: NOW + 600_000,
    });
    const res = await verifyDelegatedPaymentToken(token, { strict: false, expectedMerchant: 'acme', amount: 100, verifyKey: publicKey.export({ format: 'jwk' }) as JWK, now: NOW });
    expect(res.ok).toBe(true);
    // a JWK is imported as a key first: a private JWK given as the verify key verifies with its public half
    const viaPrivate = await verifyDelegatedPaymentToken(token, { strict: false, expectedMerchant: 'acme', amount: 100, verifyKey: privateKey.export({ format: 'jwk' }) as JWK, now: NOW });
    expect(viaPrivate.ok, String(viaPrivate.reason)).toBe(true);
  });
});

describe('settlement network', () => {
  it('an array that stringifies to a CAIP-2 id is still not a string network', () => {
    expect(settlementResponseProblems({ success: true, transaction: '0xabc', network: ['eip155:84532'] })).toEqual(['network must be a CAIP-2 identifier']);
  });
});
