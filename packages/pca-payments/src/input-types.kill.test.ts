/** Inputs of the wrong JavaScript type are refused even when a lenient reading of them would verify. */
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { bindNetworkToken, verifyNetworkTokenBinding } from './network-token';
import { signStripePayload, verifyStripeSignature } from './rails-stripe';

const T = 1_700_000_000;
const body = '{"a":1}';

describe('verifyStripeSignature input types', () => {
  it('an empty secret never verifies, even over a header signed with the empty key', () => {
    expect(verifyStripeSignature(body, signStripePayload(body, '', T), '', T)).toBe(false);
  });
  it('a non-string secret never verifies, even when it is a usable key', () => {
    const secret = 'whsec_kill';
    const header = signStripePayload(body, secret, T);
    expect(verifyStripeSignature(body, header, secret, T)).toBe(true);
    expect(verifyStripeSignature(body, header, Buffer.from(secret) as unknown as string, T)).toBe(false);
  });
  it('a non-string header never verifies, even when it splits into a valid one', () => {
    const secret = 'whsec_kill';
    const v1 = createHmac('sha256', secret).update(`${T}.${body}`, 'utf8').digest('hex');
    const lookalike = { split: () => [`t=${T}`, `v1=${v1}`] };
    expect(verifyStripeSignature(body, lookalike as unknown as string, secret, T)).toBe(false);
    expect(verifyStripeSignature(body, `t=${T},v1=${v1}`, secret, T)).toBe(true);
  });
});

describe('verifyNetworkTokenBinding input types', () => {
  it('a function carrying a valid binding is malformed, not valid', () => {
    const holder = generateKeyPair();
    const grant = { id: 'g1' };
    const nonce = 'n'.repeat(16);
    const b = bindNetworkToken({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant, issuerNonce: nonce, holderSecret: holder.secretKey, holderPublic: holder.publicKey });
    const exp = { grant, holder: encodeKey(holder.publicKey), issuerNonce: nonce };
    expect(verifyNetworkTokenBinding(b, exp)).toBeNull();
    expect(verifyNetworkTokenBinding(Object.assign(() => undefined, b), exp)).toBe('binding_malformed');
  });
});
