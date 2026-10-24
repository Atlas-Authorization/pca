import { describe, expect, it } from 'vitest';
import { b64u, buildDiscoveryDocument, generateKeyPair } from '@atlasauth/pca';
import { planAgentRequest } from './index';

const pk = b64u(generateKeyPair().publicKey);
const base = buildDiscoveryDocument({ audience: 'shop.example' });
const v2 = { ...base, intent: { versions: [1, 2], schema_keys: [{ kid: 'k', alg: 'ed25519', pk }], question_relay: true, tiers: { 'shop.buy': 3, 'shop.refund': 4, 'shop.cart': 2 } } };
const v1 = { ...base, intent: { versions: [1], schema_keys: [], question_relay: false, tiers: { 'shop.cart': 2 } } };
const caps = { haveWebBotAuthKey: true, haveIntentSession: true };

describe('planAgentRequest (graceful degradation)', () => {
  it('a v2 site gets intent_session for an intent-bound verb', () => {
    const p = planAgentRequest(v2, 'shop.buy', caps);
    expect(p).toMatchObject({ tier: 3, requiredTier: 3, canMeetRequiredTier: true, sendPcaction: true, sendIntent: true, sendIntentSession: true, signWebBotAuth: true });
    expect(p.warnPrincipal).toBeUndefined();
  });
  it('a v1-only site still works: v1 intent, no intent_session', () => {
    const p = planAgentRequest(v1, 'shop.cart', caps);
    expect(p).toMatchObject({ tier: 2, sendPcaction: true, sendIntent: true, sendIntentSession: false, canMeetRequiredTier: true, warnPrincipal: 'site_cannot_verify_intent_session' });
  });
  it('a PCA site with no intent block: plain PCActn, no intent_session', () => {
    const p = planAgentRequest(base, 'shop.cart', caps);
    expect(p.sendIntentSession).toBe(false);
    expect(p.tier).toBe(2);
  });
  it('a site without PCA: Tier 1 when it accepts Web Bot Auth, otherwise a visitor; the principal is warned either way', () => {
    expect(planAgentRequest(null, 'x', { ...caps, siteAcceptsWebBotAuth: true })).toMatchObject({ tier: 1, signWebBotAuth: true, sendPcaction: false, warnPrincipal: 'site_does_not_verify_pca' });
    expect(planAgentRequest(null, 'x', caps)).toMatchObject({ tier: 0, signWebBotAuth: false, sendPcaction: false, warnPrincipal: 'site_does_not_verify_pca' });
    expect(planAgentRequest(null, 'x', { ...caps, haveWebBotAuthKey: false, siteAcceptsWebBotAuth: true }).tier).toBe(0);
  });
  it('a required tier the agent cannot reach is flagged, never attempted silently', () => {
    expect(planAgentRequest(v2, 'shop.refund', caps)).toMatchObject({ canMeetRequiredTier: false, warnPrincipal: 'required_tier_unreachable' });
    expect(planAgentRequest(v2, 'shop.buy', { ...caps, haveIntentSession: false })).toMatchObject({ tier: 2, canMeetRequiredTier: false });
  });
  it('a malformed intent block degrades to plain PCA', () => {
    const p = planAgentRequest({ ...base, intent: { versions: 'two' } }, 'shop.buy', caps);
    expect(p).toMatchObject({ tier: 2, sendIntentSession: false });
  });
});
