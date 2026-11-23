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
  // pre-fix: `now >= NaN` was false, so a mandate whose period end is NaN never ended
  it('NaN periodEnd reads as ended', () => {
    const m = { ...mandate, terms: { ...mandate.terms, periodEnd: Number.NaN } };
    expect(() => sharedPaymentTokenLimits(m, NOW)).toThrow('the mandate period has ended');
  });
  it('-Infinity periodEnd reads as ended', () => {
    const m = { ...mandate, terms: { ...mandate.terms, periodEnd: Number.NEGATIVE_INFINITY } };
    expect(() => sharedPaymentTokenLimits(m, NOW)).toThrow('the mandate period has ended');
  });
});
