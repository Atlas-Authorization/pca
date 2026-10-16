import { intentBlockOf, type IntentDiscoveryBlock } from './discovery';
import type { AccessTier } from './tiers';

/**
 * AGENT-SIDE TIER SELECTION AND GRACEFUL DEGRADATION (docs/specs/pca-intent-layer-v2.md §3.15, principle 7 "degrade,
 * don't break"). The agent reads the site's discovery document first and sends only what the site can verify:
 *  - no PCA at the site: Tier 1 if the site accepts Web Bot Auth and the agent has a key, otherwise it browses as a
 *    visitor; either way the wallet must tell the principal that no verifiable intent protects this site (the agent's
 *    own grant still constrains what it attempts; the site just cannot check it);
 *  - a site with v1 intent only: the PCActn with the v1 `intent` member and NO `intent_session` (v1 verifiers refuse
 *    unknown top-level members);
 *  - a v2 site (`intent.versions` contains 2): `intent_session` too, when the agent holds a session.
 */

export type PrincipalWarning = 'site_does_not_verify_pca' | 'site_cannot_verify_intent_session' | 'required_tier_unreachable';

export interface AgentRequestPlan {
  /** The tier the request will prove. */
  tier: AccessTier;
  /** The tier the site says the verb needs (from discovery), when known. */
  requiredTier?: AccessTier;
  /** false when the plan cannot reach `requiredTier` (the agent should not attempt the action). */
  canMeetRequiredTier: boolean;
  sendPcaction: boolean;
  /** Send the v1 `envelope.intent` member. */
  sendIntent: boolean;
  /** Send the v2 signed `intent_session` member. */
  sendIntentSession: boolean;
  /** Sign the request with RFC 9421 (web-bot-auth profile); when a PCActn is sent, `PCA-Action` is a covered component. */
  signWebBotAuth: boolean;
  /** Something the wallet must show the principal. */
  warnPrincipal?: PrincipalWarning;
}

export interface AgentCapabilities {
  haveWebBotAuthKey: boolean;
  haveIntentSession: boolean;
  /** For a site without PCA discovery: whether it is known to accept Web Bot Auth (from its key directory, out of band). */
  siteAcceptsWebBotAuth?: boolean;
  /** The agent's PCActn carries an `intent` binding (its root grant was minted from an Intent Map). Default true. */
  haveIntentBinding?: boolean;
}

/** `discovery` is the raw `/.well-known/pca-configuration` JSON, or null when the site has none (no PCA). */
export function planAgentRequest(discovery: unknown, verb: string, caps: AgentCapabilities): AgentRequestPlan {
  if (discovery === null || discovery === undefined) {
    const t1 = caps.haveWebBotAuthKey && caps.siteAcceptsWebBotAuth === true;
    return { tier: t1 ? 1 : 0, canMeetRequiredTier: true, sendPcaction: false, sendIntent: false, sendIntentSession: false, signWebBotAuth: t1, warnPrincipal: 'site_does_not_verify_pca' };
  }
  let block: IntentDiscoveryBlock | null;
  try {
    block = intentBlockOf(discovery);
  } catch {
    // A malformed intent block is treated as absent: the agent falls back to what a plain PCA site verifies.
    block = null;
  }
  const versions = block?.versions ?? [];
  const requiredTier = block?.tiers[verb];
  const binding = caps.haveIntentBinding ?? true;
  const sendIntent = binding;
  const sendIntentSession = versions.includes(2) && caps.haveIntentSession && binding;
  const tier: AccessTier = sendIntentSession ? 3 : 2;
  const canMeet = requiredTier === undefined || requiredTier <= tier;
  let warnPrincipal: PrincipalWarning | undefined;
  if (!canMeet) warnPrincipal = 'required_tier_unreachable';
  else if (!versions.includes(2) && caps.haveIntentSession) warnPrincipal = 'site_cannot_verify_intent_session';
  return {
    tier,
    ...(requiredTier !== undefined ? { requiredTier } : {}),
    canMeetRequiredTier: canMeet,
    sendPcaction: true,
    sendIntent,
    sendIntentSession,
    signWebBotAuth: caps.haveWebBotAuthKey,
    ...(warnPrincipal ? { warnPrincipal } : {}),
  };
}
