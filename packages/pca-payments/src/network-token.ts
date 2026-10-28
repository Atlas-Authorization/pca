// network-token.ts - agent payment network tokens (K4, C-280..C-283).
//
// A `NetworkTokenBinding` ties a PCA grant holder to an OPAQUE network-token reference (never a PAN) and carries the PCActn digest
// onto the charge so the card-network record joins the PCA ledger entry. The provider surface is generic:
// `NetworkTokenProvider {issue, suspend}` plus `controls` derived from the rail limits (the network is a SECOND enforcement point;
// PCA remains the policy source and never relaxes because the network would have blocked).
//
// SOURCES (fetched 2026-10) and their status:
//  - Visa Intelligent Commerce: https://developer.visa.com/capabilities/visa-intelligent-commerce/overview (token provisioning and
//    lifecycle, step-up verification, passkey management, enroll agentic token / retrieve credentials) and the Cybersource guide
//    https://developer.cybersource.com/docs/cybs/en-us/intelligent-commerce/developer/all/rest/intelligent-commerce.html .
//    The endpoint-level reference is PARTNER-GATED: field names below are NOT taken from it.
//  - Mastercard Agent Pay: Agentic Tokens extend MDES tokenization with an agent identifier and a session-scope object (limits,
//    merchant categories, expiry). Seen only in secondary sources; the MDES reference needs a Mastercard developer agreement.
// So `visaIntelligentCommerceAdapter` and `mastercardAgentPayAdapter` are GENERIC, MOCK-TESTED mappings of PCA controls onto a
// neutral control shape. They make no network call. To go live each needs partner access to the real API; swap the `transport`.
//
// Heuristic-free: every check is exact. Any malformed input is a refusal.

import { decodeKey, encodeKey, hashCanonical, pcactnDigest, sign, verify, type PCActn, type PlanNode } from '@atlasauth/pca';
import { chargeToPCActn, type ChargePCActnOpts } from './charge-action';
import type { Charge } from './authorize';
import type { PaymentMandate } from './mandate';
import type { RailLimits } from './rails';

export const NETWORK_TOKEN_BINDING_KIND = 'pca.network_token_binding';

/** `token_ref` is an opaque handle: 8..128 chars of [A-Za-z0-9_.:-]. A PAN-shaped (13..19 digit, Luhn-valid) value is refused anywhere in it. */
const REF_RE = /^[A-Za-z0-9_.:-]{8,128}$/;

function luhn(d: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (dbl) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only: no sliding windows. */
export function looksLikePan(s: string): boolean {
  return (s.replace(/[\s-]/g, '').match(/[0-9]+/g) ?? []).some((r) => r.length >= 13 && r.length <= 19 && luhn(r));
}

export function tokenRefError(ref: unknown): string | null {
  if (typeof ref !== 'string' || !REF_RE.test(ref)) return 'token_ref_malformed';
  if (looksLikePan(ref)) return 'token_ref_looks_like_pan';
  return null;
}

export interface NetworkTokenBinding {
  kind: typeof NETWORK_TOKEN_BINDING_KIND;
  /** Provider id, e.g. 'visa_ic', 'mastercard_agent_pay', 'generic'. */
  provider: string;
  token_ref: string;
  /** `hashCanonical(grant)`: the grant this token is bound to. */
  grant_digest: string;
  /** Issuer-chosen nonce (anti-replay of the proof). */
  issuer_nonce: string;
  /** Ed25519 public key (b64u) of the grant holder. */
  holder: string;
  /** b64u signature by the holder over the binding digest. */
  binding_proof: string;
}

const bodyOf = (b: Pick<NetworkTokenBinding, 'provider' | 'token_ref' | 'grant_digest' | 'issuer_nonce' | 'holder'>) =>
  ({ kind: NETWORK_TOKEN_BINDING_KIND, v: 1, provider: b.provider, token_ref: b.token_ref, grant_digest: b.grant_digest, issuer_nonce: b.issuer_nonce, holder: b.holder });

/** The exact bytes the holder signs: utf8 of the canonical-JSON digest of the body (domain-separated by `kind`). */
export const bindingMessage = (b: Parameters<typeof bodyOf>[0]): Uint8Array => new TextEncoder().encode(hashCanonical(bodyOf(b)));

export function bindNetworkToken(opts: { provider: string; tokenRef: string; grant: unknown; issuerNonce: string; holderSecret: Uint8Array; holderPublic: Uint8Array }): NetworkTokenBinding {
  const e = tokenRefError(opts.tokenRef);
  if (e !== null) throw new RangeError(`bindNetworkToken: ${e}`);
  if (opts.issuerNonce.length < 16) throw new RangeError('bindNetworkToken: issuer nonce must be at least 16 chars');
  const core = { provider: opts.provider, token_ref: opts.tokenRef, grant_digest: hashCanonical(opts.grant), issuer_nonce: opts.issuerNonce, holder: encodeKey(opts.holderPublic) };
  return { kind: NETWORK_TOKEN_BINDING_KIND, ...core, binding_proof: encodeKey(sign(opts.holderSecret, bindingMessage(core))) };
}

/** Total. null = valid. The grant is the one the caller verified; the holder is the key the caller expects (the grant's leaf holder). */
export function verifyNetworkTokenBinding(b: unknown, expect: { grant: unknown; holder: string; issuerNonce: string; provider?: string }): string | null {
  try {
    const x = b as NetworkTokenBinding;
    if (x === null || typeof x !== 'object' || x.kind !== NETWORK_TOKEN_BINDING_KIND) return 'binding_malformed';
    const e = tokenRefError(x.token_ref);
    if (e !== null) return e;
    if (typeof x.provider !== 'string' || x.provider.length === 0 || (expect.provider !== undefined && x.provider !== expect.provider)) return 'provider_mismatch';
    if (x.grant_digest !== hashCanonical(expect.grant)) return 'grant_digest_mismatch';
    if (x.holder !== expect.holder) return 'holder_mismatch';
    if (x.issuer_nonce !== expect.issuerNonce) return 'issuer_nonce_mismatch';
    return verify(decodeKey(x.holder), bindingMessage(x), decodeKey(x.binding_proof)) ? null : 'binding_proof_invalid';
  } catch {
    return 'binding_malformed';
  }
}

// ---- controls + provider interface --------------------------------------------------------------------------------------

/** The network-side controls, the neutral shape. Always an upper-bounded copy of the rail limits. */
export interface NetworkTokenControls {
  currency: string;
  perAuthorizationMax: number;
  totalMax: number;
  categories: string[];
  merchants: string[];
  expiresAt?: number;
  /** Echoed on every network transaction record so settlement joins the PCA ledger. */
  metadata: { grant_digest: string; pcactn_digest?: string };
}

export function controlsFromLimits(limits: RailLimits, grant: unknown): NetworkTokenControls {
  return { currency: limits.currency, perAuthorizationMax: limits.perAuthorizationMax, totalMax: limits.totalMax, categories: [...limits.categories], merchants: [...limits.merchants], ...(limits.expiresAt !== undefined ? { expiresAt: limits.expiresAt } : {}), metadata: { grant_digest: hashCanonical(grant) } };
}

export interface NetworkTokenProvider {
  readonly id: string;
  /** Issue/activate a token whose own controls equal `controls`. Returns the opaque reference. */
  issue(req: { controls: NetworkTokenControls; agentId: string }): Promise<{ token_ref: string }>;
  /** Suspend the token (grant revoked). Must be idempotent. */
  suspend(tokenRef: string, reason: string): Promise<void>;
}

/**
 * Issuance gate: PCA authorises an issuance only when the binding verifies and the requested controls are no wider than the rail limits.
 * Returns the controls actually sent. Refuses a provider response whose token_ref is malformed or PAN-shaped.
 */
export async function issueBoundNetworkToken(opts: {
  provider: NetworkTokenProvider; limits: RailLimits; grant: unknown; agentId: string; holderSecret: Uint8Array; holderPublic: Uint8Array; issuerNonce: string;
}): Promise<{ binding: NetworkTokenBinding; controls: NetworkTokenControls }> {
  const controls = controlsFromLimits(opts.limits, opts.grant);
  const { token_ref } = await opts.provider.issue({ controls, agentId: opts.agentId });
  const binding = bindNetworkToken({ provider: opts.provider.id, tokenRef: token_ref, grant: opts.grant, issuerNonce: opts.issuerNonce, holderSecret: opts.holderSecret, holderPublic: opts.holderPublic });
  return { binding, controls };
}

/** Grant revoked => suspend. Provider errors propagate (the caller must retry; a failed suspend is not a success). */
export const suspendOnRevoke = (provider: NetworkTokenProvider, b: NetworkTokenBinding): Promise<void> => provider.suspend(b.token_ref, 'grant_revoked');

// ---- the charge carries the PCActn digest -------------------------------------------------------------------------------

/** The metadata a charge/authorization carries. Keys are fixed; values are digests (no PII, no PAN). */
export function settlementMetadata(b: NetworkTokenBinding, pcactnDigest: string): { pca_grant: string; pca_pcactn: string; pca_token_ref: string } {
  return { pca_grant: b.grant_digest, pca_pcactn: pcactnDigest, pca_token_ref: b.token_ref };
}

export type SettlementJoin = { ok: true } | { ok: false; reasons: string[] };

/**
 * The one way to start a network-token charge: builds the signed PCActn for the charge and returns the metadata for the network
 * request, derived from THAT PCActn's digest. There is no overload that takes a digest string, so a charge cannot carry a digest that
 * is not of a PCActn this call built. The caller appends `pcactn` to its ledger and sends `metadata` with the network authorization.
 */
export function chargeWithNetworkToken(binding: NetworkTokenBinding, mandate: PaymentMandate, charge: Charge, opts: ChargePCActnOpts): { pcactn: PCActn; node: PlanNode; metadata: ReturnType<typeof settlementMetadata>; pcactnDigest: string } {
  if (tokenRefError(binding.token_ref) !== null) throw new RangeError('chargeWithNetworkToken: bad binding');
  if (binding.grant_digest !== hashCanonical(mandate.grant)) throw new RangeError('chargeWithNetworkToken: binding is for another grant');
  const { pcactn, node } = chargeToPCActn(mandate, charge, opts);
  const digest = pcactnDigest(pcactn);
  return { pcactn, node, metadata: settlementMetadata(binding, digest), pcactnDigest: digest };
}

/** A network settlement record joins the ledger entry only if all three echoed values match exactly. */
export function reconcileNetworkSettlement(expected: { grantDigest: string; pcactnDigest: string; tokenRef: string }, record: { metadata?: Record<string, unknown> }): SettlementJoin {
  const m = record?.metadata ?? {};
  const reasons: string[] = [];
  // a settlement without the PCActn digest never joins, even if the expectation is empty too
  if (typeof m.pca_pcactn !== 'string' || m.pca_pcactn.length === 0 || expected.pcactnDigest.length === 0) reasons.push('pcactn_digest_missing');
  if (m.pca_grant !== expected.grantDigest) reasons.push('grant_digest_mismatch');
  if (m.pca_pcactn !== expected.pcactnDigest) reasons.push('pcactn_digest_mismatch');
  if (m.pca_token_ref !== expected.tokenRef) reasons.push('token_ref_mismatch');
  return reasons.length === 0 ? { ok: true } : { ok: false, reasons };
}

// ---- generic partner-gated adapters (NO network calls) ------------------------------------------------------------------

export interface PartnerTransport {
  post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>>;
}

/**
 * LABEL: GENERIC MAPPING, NOT THE PARTNER WIRE FORMAT. The path and body names are placeholders chosen by this package; replace them
 * with the partner's documented ones once access exists. The control VALUES are exact copies of PCA's limits.
 */
function partnerAdapter(id: string, scopeKey: string): (transport: PartnerTransport) => NetworkTokenProvider {
  return (t) => ({
    id,
    async issue({ controls, agentId }) {
      const r = await t.post('/tokens', {
        agent_id: agentId,
        [scopeKey]: { currency: controls.currency, per_authorization_max: controls.perAuthorizationMax, total_max: controls.totalMax, merchant_categories: controls.categories, merchants: controls.merchants, ...(controls.expiresAt !== undefined ? { expires_at: controls.expiresAt } : {}) },
        metadata: controls.metadata,
      });
      const ref = r.token_ref;
      const e = tokenRefError(ref);
      if (e !== null) throw new Error(`${id}: provider returned ${e}`);
      return { token_ref: ref as string };
    },
    async suspend(tokenRef, reason) {
      await t.post(`/tokens/${encodeURIComponent(tokenRef)}/suspend`, { reason });
    },
  });
}

/** Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names). */
export const visaIntelligentCommerceAdapter = partnerAdapter('visa_ic', 'instructions');
/** Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names). */
export const mastercardAgentPayAdapter = partnerAdapter('mastercard_agent_pay', 'session_scope');
