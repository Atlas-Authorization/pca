/**
 * Regression for the 2026-10-12 JavaScript-semantics audit: only an ABSENT charge currency defaults to the mandate's.
 * `??` used to read `currency: null` as absent, so a null currency was silently replaced and the charge authorized.
 */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate } from './mandate';
import { authorizeCharge, chargeActionContext, type Charge } from './authorize';
import { chargeParams } from './charge-action';

const principal = generateKeyPair();
const agent = generateKeyPair();
const NOW = 1_700_000_000_000;
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['openai'],
  categories: ['saas'],
  currency: 'USD',
  perTransactionCap: 500,
  autoApproveThreshold: 200,
  cumulativeCap: 1000,
  now: NOW,
});
const charge = (over: Record<string, unknown> = {}): Charge => ({ merchant: 'openai', amount: 50, category: 'saas', now: NOW, ...over }) as Charge;

describe('charge currency: null is not absent', () => {
  it('an absent currency still defaults to the mandate currency and is authorized', () => {
    expect(chargeActionContext(mandate, charge()).action.params?.currency).toBe('USD');
    expect(chargeParams(mandate, charge()).currency).toBe('USD');
    expect(authorizeCharge(mandate, charge(), mandate.grant).outcome).toBe('auto');
  });
  it('a null currency is carried as null (both in the decision context and in the committed params) and denied', () => {
    expect(chargeActionContext(mandate, charge({ currency: null })).action.params?.currency).toBeNull();
    expect(chargeParams(mandate, charge({ currency: null })).currency).toBeNull();
    expect(authorizeCharge(mandate, charge({ currency: null }), mandate.grant).outcome).toBe('deny');
  });
});
