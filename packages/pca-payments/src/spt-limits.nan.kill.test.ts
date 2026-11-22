import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { buildPaymentMandate } from './mandate';
import { sharedPaymentTokenLimits } from './spt-limits';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['m1'],
  currency: 'USD',
  perTransactionCap: 100,
  autoApproveThreshold: 50,
  cumulativeCap: 500,
  now: NOW,
});

describe('sharedPaymentTokenLimits with a non-finite period end never admits', () => {
  // pre-fix: `now >= NaN` was false, so a NaN period end never ended; +Infinity was emitted as expires_at: null
  it.each([Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY])('periodEnd of %s is refused', (periodEnd) => {
    const m = { ...mandate, terms: { ...mandate.terms, periodEnd } };
    expect(() => sharedPaymentTokenLimits(m, NOW)).toThrow('periodEnd must be an epoch-ms time');
  });
});
