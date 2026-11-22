import { canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { type ActionSchemaKey } from './action-schema';
import { type PqPinPolicy, type SignerSuiteOpts, type SigAlg, resolveSigAlg, signSuiteArtifact, suiteKeysOf, verifyPinnedSuite } from './pq';
import { suiteCapabilityError } from './intent-strict';

const suiteErr = (alg: unknown) => suiteCapabilityError(alg, (a) => resolveSigAlg(a) !== null);

/**
 * LAZY ELICITATION ON THE WIRE (PCA Intent Layer v2, milestone V3; docs/specs/pca-intent-layer-v2.md §3.3 steps 2–3,
 * §4.3 M5, §8 "intent_required").
 *
 * When the cell c = cell(lift(ξ, ω, t)) of an attempted action is UNCERTAIN (0 < p(c) < τ, inside every ceiling, not
 * vetoed) the site answers HTTP 403 with `WWW-Authenticate: PCA error="intent_required", session=..., question=...` and an
 * RFC 9457 `application/problem+json` body whose `pca` member is a SITE-SIGNED `pca-intent-required` v1 object: the
 * session, the map and schema digests, the PCActn and action digests, the cell as COORDINATES (inclusive cell-index ranges
 * for numeric dimensions, value sets for categorical ones; never text), the question id, the friction tier and an expiry.
 * The site delivers it straight to the session's question endpoint whenever it can; the agent receives the same body and
 * waits, and may only relay it unchanged (the wallet checks the site signature against the discovery `schema_keys` and
 * re-derives the cell itself). The other outcomes are terminal: `schema-violation` (⊠), `ceiling` (outside
 * G^org ∩ G^site ∩ G^std: the principal cannot widen it) and `intent-denied` (vetoed, or p(c) = 0).
 */

export const PROBLEM_BASE = 'https://atlasauth.net/pca/problems/';
export type IntentProblemKind = 'intent-required' | 'intent-denied' | 'schema-violation' | 'ceiling';
export const INTENT_PROBLEM_KINDS: readonly IntentProblemKind[] = ['intent-required', 'intent-denied', 'schema-violation', 'ceiling'];
const TITLES: Record<IntentProblemKind, string> = {
  'intent-required': 'Principal confirmation required for this action',
  'intent-denied': 'The principal does not intend this action',
  'schema-violation': 'The action does not conform to the site action schema',
  ceiling: 'The action is outside a ceiling the principal cannot widen',
};
const ERRORS: Record<IntentProblemKind, string> = {
  'intent-required': 'intent_required',
  'intent-denied': 'intent_denied',
  'schema-violation': 'schema_violation',
  ceiling: 'ceiling',
};

export const INTENT_REQUIRED_DOMAIN = 'atlas-pca/intent-required/v1\0';
export const INTENT_ACTION_DOMAIN = 'atlas-pca/intent-action/v1';
export type Friction = 'tap' | 'hold' | 'typed' | 'device';
export const FRICTIONS: readonly Friction[] = ['tap', 'hold', 'typed', 'device'];

/** A cell of Ω̃ as coordinates: dimension path -> [lo, hi] cell indices (numeric) or a value set (categorical). */
export type CellCoords = Record<string, [number, number] | string[]>;

export interface IntentRequiredBody {
  v: 1;
  kind: 'pca-intent-required';
  session: string;
  map_digest: string;
  schema: string;
  pcactn_digest: string;
  action_digest: string;
  cell: { verb: string; coords: CellCoords };
  reason: 'uncertain';
  question_id: string;
  friction: Friction;
  delivered_to: 'wallet' | 'agent';
  expires_at: number;
}
export interface SignedIntentRequired extends IntentRequiredBody {
  /** Same structure as the action schema signature: the suite is pinned by the discovery key entry `kid`. */
  sig: { alg: SigAlg; kid: string; value: string; pq_value?: string };
}

/** The action digest a JIT consent is bound to: H({d, action}) over the PCActn's signed `action`. */
export function intentActionDigest(action: { verb: string; resource: string; params_digest: string; reversibility_class: string }): string {
  return hashCanonical({ d: INTENT_ACTION_DOMAIN, action: { verb: action.verb, resource: action.resource, params_digest: action.params_digest, reversibility_class: action.reversibility_class } });
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const b32 = (v: unknown) => decodeB64uStrict(v, 32) !== null;
const BODY_KEYS = ['v', 'kind', 'session', 'map_digest', 'schema', 'pcactn_digest', 'action_digest', 'cell', 'reason', 'question_id', 'friction', 'delivered_to', 'expires_at', 'sig'];

export function cellCoordsError(c: unknown): string | null {
  if (!isObj(c) || Object.keys(c).length === 0 || Object.keys(c).length > 64) return 'coords must be an object of 1..64 dimensions';
  for (const [k, v] of Object.entries(c)) {
    if (k.length === 0 || k.length > 256) return 'a coordinate path must be 1..256 characters';
    if (Array.isArray(v) && v.length === 2 && v.every(isInt)) {
      if (!((v[0] as number) >= 0 && (v[0] as number) <= (v[1] as number))) return `coords '${k}': need 0 <= lo <= hi`;
    } else if (Array.isArray(v) && v.length >= 1 && v.length <= 256 && v.every((x) => typeof x === 'string')) {
      if (new Set(v).size !== v.length) return `coords '${k}': values must be distinct`;
    } else return `coords '${k}': an index range [lo, hi] or a value set`;
  }
  return null;
}

export function intentRequiredShapeError(b: unknown, opts: { signed?: boolean } = {}): string | null {
  if (!isObj(b)) return 'not an object';
  for (const k of Object.keys(b)) if (!BODY_KEYS.includes(k)) return `unknown member '${k}'`;
  if (b.v !== 1 || b.kind !== 'pca-intent-required') return 'not a pca-intent-required v1';
  for (const k of ['session', 'map_digest', 'schema', 'pcactn_digest', 'action_digest']) if (!b32(b[k])) return `${k} must be canonical base64url (32 bytes)`;
  if (!isObj(b.cell) || Object.keys(b.cell).sort().join() !== 'coords,verb' || typeof b.cell.verb !== 'string' || b.cell.verb.length === 0) return 'cell must be {verb, coords}';
  const ce = cellCoordsError(b.cell.coords);
  if (ce) return ce;
  if (b.reason !== 'uncertain') return "reason must be 'uncertain'";
  if (typeof b.question_id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(b.question_id)) return 'question_id must match [A-Za-z0-9_-]{1,64}';
  if (!FRICTIONS.includes(b.friction as Friction)) return 'unknown friction tier';
  if (b.delivered_to !== 'wallet' && b.delivered_to !== 'agent') return "delivered_to must be 'wallet' or 'agent'";
  if (!(isInt(b.expires_at) && b.expires_at >= 0)) return 'expires_at must be a non-negative safe integer';
  if (opts.signed !== false) {
    const s = b.sig;
    if (isObj(s) && suiteErr(s.alg)) return `sig.alg: ${suiteErr(s.alg)}`;
    if (isObj(s) && s.pq_value !== undefined && typeof s.pq_value !== 'string') return 'sig.pq_value must be a string';
    if (!isObj(s) || Object.keys(s).some((k) => !['alg', 'kid', 'value', 'pq_value'].includes(k)) || resolveSigAlg(s.alg) === null || typeof s.kid !== 'string' || typeof s.value !== 'string') return 'sig must be {alg, kid, value, pq_value?}';
  } else if (b.sig !== undefined) return 'an unsigned body must not carry sig';
  return null;
}

function message(b: IntentRequiredBody): Uint8Array {
  const { sig: _s, ...body } = b as SignedIntentRequired;
  void _s;
  const dom = utf8(INTENT_REQUIRED_DOMAIN);
  const m = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + m.length);
  out.set(dom);
  out.set(m, dom.length);
  return out;
}

export function signIntentRequired(body: IntentRequiredBody, kid: string, siteSecret: Uint8Array, suite?: SignerSuiteOpts): SignedIntentRequired {
  const e = intentRequiredShapeError(body, { signed: false });
  if (e) throw new Error(`signIntentRequired: ${e}`);
  const parts = signSuiteArtifact(suite?.alg, suiteKeysOf(siteSecret, suite), message(body));
  return { ...body, sig: { alg: resolveSigAlg(suite?.alg ?? 'ed25519')!.alg as SigAlg, kid, value: parts.sig, ...(parts.pq_sig !== undefined ? { pq_value: parts.pq_sig } : {}) } };
}

/**
 * Verify a site-signed body against the site's discovery keys (the same key list as the action schema). The clock is REQUIRED
 * (0.5, B16): a `now` that is missing or not a safe integer is refused, never coerced, so expiry can never be skipped.
 */
export function verifyIntentRequired(b: unknown, keys: readonly ActionSchemaKey[], now: number): { ok: true } | { ok: false; reason: string } {
  try {
    if (!(typeof now === 'number' && Number.isSafeInteger(now))) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    const e = intentRequiredShapeError(b);
    if (e) return { ok: false, reason: e };
    const s = b as SignedIntentRequired;
    if (!Array.isArray(keys)) return { ok: false, reason: 'the site keys must be an array' };
    const key = keys.find((k) => k !== null && typeof k === 'object' && k.kid === s.sig.kid);
    if (!key) return { ok: false, reason: `no site key with kid '${s.sig.kid}'` };
    const kse = suiteErr(key.alg);
    if (kse) return { ok: false, reason: `site key: ${kse}` };
    if (resolveSigAlg(key.alg)?.alg !== resolveSigAlg(s.sig.alg)?.alg) return { ok: false, reason: 'sig.alg does not match the pinned key suite' };
    const pin: PqPinPolicy = key.pq_pk !== undefined ? { pqPins: { [key.pk]: key.pq_pk } } : {};
    if (!verifyPinnedSuite(key.alg, key.pk, key.pq_pk, message(s), { sig: s.sig.value, pq_sig: s.sig.pq_value }, pin)) return { ok: false, reason: 'site signature invalid' };
    if (!(now <= s.expires_at)) return { ok: false, reason: 'the question has expired' };
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `malformed intent_required: ${(err as Error).message}` };
  }
}

/** {@link verifyIntentRequired} with the clock REQUIRED: a missing or non-integer `now` is a denial, so expiry can never be skipped. */
export function verifyIntentRequiredAt(b: unknown, keys: readonly ActionSchemaKey[], now: number): { ok: true } | { ok: false; reason: string } {
  if (!(typeof now === 'number' && Number.isSafeInteger(now))) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
  return verifyIntentRequired(b, keys, now);
}

/** The RFC 9457 response for an Intent Layer outcome (status 403; `pca` carries the signed body for intent_required). */
export function intentProblem(
  kind: IntentProblemKind,
  opts: { detail?: string; body?: SignedIntentRequired } = {},
): { status: 403; headers: Record<string, string>; body: Record<string, unknown> } {
  const params = [`error="${ERRORS[kind]}"`];
  if (kind === 'intent-required') {
    if (!opts.body) throw new Error('intentProblem: intent-required needs the signed body');
    params.push(`session="${opts.body.session}"`, `question="${opts.body.question_id}"`);
  }
  return {
    status: 403,
    headers: { 'WWW-Authenticate': `PCA ${params.join(', ')}`, 'Content-Type': 'application/problem+json' },
    body: {
      type: PROBLEM_BASE + kind,
      title: TITLES[kind],
      status: 403,
      ...(opts.detail !== undefined ? { detail: opts.detail } : {}),
      ...(opts.body ? { pca: opts.body } : {}),
    },
  };
}
