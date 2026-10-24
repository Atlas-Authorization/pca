import {
  artifactRef,
  artifactSuiteError,
  closedMembers,
  isBoundedString,
  isDigest,
  isPlainObject,
  isSafeInt,
  isClock,
  isScalar,
  pinPqOk,
  resolveParamPath,
  scalarEq,
  SUITE_MEMBERS,
  signArtifact,
  verifyArtifactSig,
  type WireScalar,
} from './intent-artifacts';
import type { SignerSuiteOpts } from './pq';

/**
 * SIGNED OFFER SETS AND THE OPTIMALITY DIMENSION `excess` (Intent Layer v2 §2.6, §3.13 item 2, T25; conformance
 * rule 16, step 6).
 *
 * A site that answers a search returns a site-signed list of offers O for a query q, bound to the session, with a
 * declared ranking. The verifier turns "cheapest matching" into a numeric dimension of Ω̃:
 *
 *     excess(ω) = price(chosen offer) − min{ price(o) : o ∈ O, o ⊨ F.offer }
 *
 * where F is the INTENT FILTER (the principal's slot constraints, evaluated deterministically), split into the part
 * that constrains the SEARCH (`F.query`) and the part that constrains an OFFER (`F.offer`). Two checks make the
 * number mean something:
 *   - COVERAGE (search not narrowed): every constraint of q is one of F.query with the same value
 *     (keys(q) ⊆ keys(F.query), q[k] = F.query[k]). A query with an extra constraint ("stops = 0", "seller = X")
 *     returns a narrower set whose minimum could be the planted option, so it is refused. A broader query is fine:
 *     its minimum can only be lower, which makes the agent's choice look worse, never better (T25).
 *   - COMPLETENESS: the site must declare `complete: true` (O is every offer it has for q). A partial page cannot
 *     underwrite "cheapest".
 * The chosen offer is the one whose `offer_id` the action names (at the schema-declared parameter path); its price
 * is the SITE-SIGNED price, never an agent-supplied number. It must itself satisfy F.offer.
 *
 * WIRE `pca-offer-set` v1 (closed member set):
 *   v: 1, kind: "pca-offer-set", site (the verifier audience, <= 256 B), session (b64u 32), query {k: scalar}
 *   (<= 32 keys), rank: "price_asc", complete: boolean, offers [1..256] of { offer_id (string <= 128 B, unique),
 *   price (safe integer >= 0), <attr>: scalar … (<= 32 attrs) }, issued_at (safe integer >= 0, ms), kid (string
 *   <= 64 B), sig (b64u, 64 B).
 * Signature domain `atlas-pca/offer-set/v1\0`; reference domain `atlas-pca/offer-set-ref/v1`, slot `o`
 * (see `intent-artifacts.ts`).
 */

export const OFFER_SET_DOMAIN = 'atlas-pca/offer-set/v1\0';
export const OFFER_SET_REF_DOMAIN = 'atlas-pca/offer-set-ref/v1';
export const MAX_OFFERS = 256;
export const MAX_OFFER_ATTRS = 32;
export const MAX_QUERY_KEYS = 32;

export interface Offer {
  offer_id: string;
  price: number;
  [attr: string]: WireScalar;
}

export interface PcaOfferSet {
  v: 1;
  kind: 'pca-offer-set';
  site: string;
  session: string;
  query: Record<string, WireScalar>;
  rank: 'price_asc';
  complete: boolean;
  offers: Offer[];
  issued_at: number;
  kid: string;
  alg?: string;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

/** The intent filter F: constraints on the search and on an acceptable offer (equality on scalars). */
export interface IntentFilter {
  query: Record<string, WireScalar>;
  offer: Record<string, WireScalar>;
}

/** Verifier-side optimality policy (one per verb that declares an offer-set read). */
export interface OfferPolicy {
  /** The world-dimension name the excess is written to (`env.world.<name>`). */
  name: string;
  /** Pinned site signing keys: {kid, pk (b64u Ed25519)}. */
  site_keys: { kid: string; pk: string; pq_pk?: string }[];
  /** Maximum age of the offer set at action time (ms). */
  max_age_ms: number;
  /** The `action.params.*` path naming the chosen offer id. */
  offer_param: string;
  filter: IntentFilter;
}

const OFFER_SET_FIELDS = ['v', 'kind', 'site', 'session', 'query', 'rank', 'complete', 'offers', 'issued_at', 'kid', 'sig'] as const;

/** Wire validation of an offer set. Null = well-formed. */
export function validateOfferSetWire(o: unknown): string | null {
  if (!isPlainObject(o)) return 'offer set must be an object';
  const m = closedMembers(o, OFFER_SET_FIELDS, SUITE_MEMBERS, 'offer_set');
  if (m) return m;
  if (o.v !== 1 || o.kind !== 'pca-offer-set') return 'offer set must be {v: 1, kind: "pca-offer-set"}';
  if (!isBoundedString(o.site, 256)) return "'offer_set.site' must be a non-empty string (<= 256 bytes)";
  if (!isDigest(o.session)) return "'offer_set.session' must be canonical base64url (32 bytes)";
  if (!isPlainObject(o.query) || Object.keys(o.query).length > MAX_QUERY_KEYS) return `'offer_set.query' must be an object with <= ${MAX_QUERY_KEYS} keys`;
  for (const [k, v] of Object.entries(o.query)) if (!isBoundedString(k, 64) || !isScalar(v)) return `'offer_set.query.${k}' must be a scalar`;
  if (o.rank !== 'price_asc') return "'offer_set.rank' must be \"price_asc\"";
  if (typeof o.complete !== 'boolean') return "'offer_set.complete' must be a boolean";
  if (!Array.isArray(o.offers) || o.offers.length === 0 || o.offers.length > MAX_OFFERS) return `'offer_set.offers' must hold 1..${MAX_OFFERS} offers`;
  const ids = new Set<string>();
  for (let i = 0; i < o.offers.length; i++) {
    const of = o.offers[i];
    if (!isPlainObject(of)) return `offer ${i} must be an object`;
    if (!isBoundedString(of.offer_id, 128)) return `offer ${i}: 'offer_id' must be a non-empty string (<= 128 bytes)`;
    if (ids.has(of.offer_id)) return `offer ${i}: duplicate offer_id`;
    ids.add(of.offer_id);
    if (!isSafeInt(of.price) || of.price < 0) return `offer ${i}: 'price' must be a non-negative safe integer`;
    const attrs = Object.keys(of).filter((k) => k !== 'offer_id' && k !== 'price');
    if (attrs.length > MAX_OFFER_ATTRS) return `offer ${i}: more than ${MAX_OFFER_ATTRS} attributes`;
    for (const k of attrs) if (!isBoundedString(k, 64) || !isScalar(of[k])) return `offer ${i}: attribute '${k}' must be a scalar`;
  }
  if (!isSafeInt(o.issued_at) || o.issued_at < 0) return "'offer_set.issued_at' must be a non-negative safe integer";
  if (!isBoundedString(o.kid, 64)) return "'offer_set.kid' must be a non-empty string (<= 64 bytes)";
  if (typeof o.sig !== 'string') return "'offer_set.sig' must be a string";
  return null;
}

/** Sign an offer set (site side). */
export function signOfferSet(body: Omit<PcaOfferSet, 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>, secretKey: Uint8Array, suite?: SignerSuiteOpts): PcaOfferSet {
  return signArtifact(OFFER_SET_DOMAIN, body as unknown as Record<string, unknown>, secretKey, suite) as unknown as PcaOfferSet;
}

/** The content address committed in `intent_session.offer_set`. */
export function offerSetRef(o: PcaOfferSet): string {
  return artifactRef(OFFER_SET_REF_DOMAIN, 'o', o);
}

/** Does an offer satisfy the offer part of the intent filter (every key present and scalar-equal)? */
export function offerMatches(offer: Record<string, unknown>, f: Record<string, WireScalar>): boolean {
  if (!isPlainObject(offer) || !isPlainObject(f)) return false;
  for (const [k, v] of Object.entries(f)) if (!Object.prototype.hasOwnProperty.call(offer, k) || !scalarEq(offer[k], v)) return false;
  return true;
}

/** Coverage: the query constrains nothing the filter does not (keys(q) ⊆ keys(F.query), equal values). */
export function queryCovers(query: Record<string, unknown>, fq: Record<string, WireScalar>): boolean {
  if (!isPlainObject(query) || !isPlainObject(fq)) return false;
  for (const [k, v] of Object.entries(query)) if (!Object.prototype.hasOwnProperty.call(fq, k) || !scalarEq(fq[k], v)) return false;
  return true;
}

/** Policy sanity for an offer policy (null = well-formed). */
export function validateOfferPolicy(p: unknown): string | null {
  if (!isPlainObject(p)) return 'offers policy must be an object';
  const cm = closedMembers(p, ['name', 'site_keys', 'max_age_ms', 'offer_param', 'filter'], [], 'offers');
  if (cm) return cm;
  if (typeof p.name !== 'string') return 'offers policy needs a name';
  if (!Array.isArray(p.site_keys) || p.site_keys.length === 0) return 'offers policy needs at least one pinned site key';
  const kids = new Set<string>();
  for (const k of p.site_keys) {
    if (!isPlainObject(k) || closedMembers(k, ['kid', 'pk'], ['pq_pk'], 'site_key') !== null || !isBoundedString(k.kid, 64) || !isDigest(k.pk) || !pinPqOk(k.pq_pk) || kids.has(k.kid)) return 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk';
    kids.add(k.kid);
  }
  if (!isSafeInt(p.max_age_ms) || p.max_age_ms < 0) return 'offers policy: max_age_ms must be a non-negative safe integer';
  if (typeof p.offer_param !== 'string' || !p.offer_param.startsWith('action.params.')) return 'offers policy: offer_param must be an action.params.* path';
  const f = p.filter;
  if (!isPlainObject(f) || closedMembers(f, ['query', 'offer'], [], 'filter') !== null || !isPlainObject(f.query) || !isPlainObject(f.offer)) return 'offers policy: filter must be exactly {query: {}, offer: {}}';
  for (const v of [...Object.values(f.query), ...Object.values(f.offer)]) if (!isScalar(v)) return 'offers policy: filter values must be scalars';
  return null;
}

export type OfferDecision = { ok: true; excess: number; chosen_price: number; min_price: number } | { ok: false; reason: string };

/**
 * Rule 16 step 6. First failure wins (a policy that fails {@link validateOfferPolicy} or a non-object input is refused
 * first):
 *   a. `committed` (intent_session.offer_set) is present; the offer set is supplied and its reference equals it;
 *   b. wire shape; the suite members (`unsupported_suite` for a suite this verifier does not implement); the signer kid
 *      is pinned and the signature verifies under the pinned signer (PQ only under the pinned `pq_pk`);
 *   c. `site` equals the verifier audience and `session` equals the session;
 *   d. freshness: `now` is a safe integer (else stale), issued_at <= now + skew_ms and now − issued_at <= max_age_ms;
 *   e. complete === true;
 *   f. coverage (the search was not narrowed);
 *   g. the action's offer id (a string at `offer_param`) names an offer of O;
 *   h. that offer satisfies F.offer;
 *   i. excess = chosen.price − min price over the offers satisfying F.offer.
 * Total: never throws.
 */
export function decideOfferSet(input: {
  policy: OfferPolicy;
  committed: string | undefined;
  offerSet: unknown;
  params: unknown;
  aud: string;
  session: string;
  now: number;
  skewMs: number;
}): OfferDecision {
  try {
    if (!isPlainObject(input)) return { ok: false, reason: 'offers: input must be an object' };
    return decideOfferSetInner(input);
  } catch (e) {
    return { ok: false, reason: `offers: evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

function decideOfferSetInner(input: Parameters<typeof decideOfferSet>[0]): OfferDecision {
  const { policy, committed, offerSet: o, params, aud, session, now, skewMs } = input;
  const pe = validateOfferPolicy(policy);
  if (pe) return { ok: false, reason: `offers: policy misconfigured (fail closed): ${pe}` };
  if (committed === undefined) return { ok: false, reason: 'offers: the PCActn commits no offer set but the policy requires one' };
  if (o === undefined) return { ok: false, reason: 'offers: the committed offer set was not supplied' };
  const w = validateOfferSetWire(o);
  if (w) return { ok: false, reason: `offers: ${w}` };
  const os = o as PcaOfferSet;
  let ref: string;
  try {
    ref = offerSetRef(os);
  } catch {
    return { ok: false, reason: 'offers: the offer set is not strictly canonical' };
  }
  if (ref !== committed) return { ok: false, reason: 'offers: the supplied offer set does not match the committed reference' };
  const se = artifactSuiteError(os as unknown as Record<string, unknown>);
  if (se) return { ok: false, reason: `offers: signature suite: ${se}` };
  const key = policy.site_keys.find((k) => k.kid === os.kid);
  if (!key) return { ok: false, reason: `offers: signing key '${os.kid}' is not pinned` };
  if (!verifyArtifactSig(OFFER_SET_DOMAIN, os as unknown as Record<string, unknown>, key)) return { ok: false, reason: 'offers: bad site signature' };
  if (os.site !== aud) return { ok: false, reason: 'offers: the offer set was issued for another audience' };
  if (os.session !== session) return { ok: false, reason: 'offers: the offer set is bound to another session' };
  if (!isClock(now) || !isSafeInt(skewMs)) return { ok: false, reason: 'offers: no usable clock (now must be a safe integer): the offer set counts as stale' };
  if (os.issued_at > now + skewMs) return { ok: false, reason: 'offers: the offer set is issued in the future' };
  if (now - os.issued_at > policy.max_age_ms) return { ok: false, reason: 'offers: the offer set is stale' };
  if (os.complete !== true) return { ok: false, reason: 'offers: the offer set is not declared complete' };
  if (!queryCovers(os.query, policy.filter.query)) return { ok: false, reason: 'offers: the search was narrowed beyond the intent filter (coverage)' };
  const id = resolveParamPath(params, policy.offer_param);
  if (!id.found || typeof id.value !== 'string') return { ok: false, reason: 'offers: the action names no offer id at the declared parameter' };
  const chosen = os.offers.find((x) => x.offer_id === id.value);
  if (!chosen) return { ok: false, reason: 'offers: the chosen offer is not in the signed offer set' };
  if (!offerMatches(chosen, policy.filter.offer)) return { ok: false, reason: 'offers: the chosen offer does not satisfy the intent filter' };
  let min = chosen.price;
  for (const x of os.offers) if (offerMatches(x, policy.filter.offer) && x.price < min) min = x.price;
  return { ok: true, excess: chosen.price - min, chosen_price: chosen.price, min_price: min };
}
