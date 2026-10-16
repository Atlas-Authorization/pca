import {
  b64u,
  bindSuiteFields,
  canonicalBytesStrict,
  checkSessionRevocation,
  decodeB64uStrict,
  hashCanonical,
  predicateMatches,
  profileRevocationId,
  profileRevocationScope,
  publicKeyOf,
  resolveSigAlg,
  signSuiteArtifact,
  suiteKeysOf,
  suitePqPublicKey,
  utf8,
  verifyPinnedSuite,
  type ActionContext,
  type PqPinPolicy,
  type Predicate,
  type SessionRevocationEvidence,
  type SignerSuiteOpts,
  type SigAlg,
} from '@atlasauth/pca';
import { cellOf, type Omega } from './omega';
import { outcomeToAction } from './policy';

/**
 * PORTABLE, REVOCABLE INTENT PROFILES (PCA Intent Layer v2 §3.9; milestone V10, T22, T23, T24).
 *
 * A profile (`pca-intent-profile` v1) is the principal's own, signed, versioned record of standing rules and prior
 * answers: `{v, kind, profile_id, version, owner, scope, standing: {deny, permit}, prior: {observations, maps},
 * expires_at, revocation: {epoch_uri}, prev?}`. Versions are APPEND-ONLY: version n > 1 names the digest of version
 * n − 1 in `prev`, the owner and id never change, and each version is anchored (intent anchor log, kind `profile`).
 *
 * USE (T24, never raises R):
 *   - `standing.deny` is part of G^std: an action any in-scope deny rule matches is outside the standing layer
 *     (deny anywhere wins; the verifier answers `ceiling`, never a question);
 *   - `standing.permit` is an EXPLICIT principal-signed permission layer, scoped and expiring: the only way a profile
 *     admits anything;
 *   - `prior.observations` with y = 0 are imported as VETOES (cells denied for the session); y = 1 observations only
 *     shape question choice and are never fed to the learner as answers, so at τ = 1 a profile changes nothing that is
 *     admitted (T23).
 * REVOCATION: a profile version is revoked through the principal's revocation set (`profileRevocationId(id, version)`);
 * sites check non-membership against an epoch at most Δ_rev old (rule 13 step 7 for the version a session uses).
 */

export const INTENT_PROFILE_KIND = 'pca-intent-profile';
export const INTENT_PROFILE_SIG_DOMAIN = 'atlas-pca/intent-profile/v1\0';
export const INTENT_PROFILE_REF_DOMAIN = 'atlas-pca/intent-profile-ref/v1';
export const MAX_PROFILE_RULES = 256;
export const MAX_PROFILE_OBSERVATIONS = 2_000;

export interface ProfileScope {
  /** Audiences (site `aud`) the profile applies to; absent = every site. */
  sites?: string[];
  verbs?: string[];
  semantic_types?: string[];
}

export interface ProfileObservation {
  verb: string;
  values: Record<string, number | string>;
  y: 0 | 1;
  /** epoch ms of the original answer. */
  at: number;
}

export interface IntentProfileBody {
  v: 1;
  kind: typeof INTENT_PROFILE_KIND;
  profile_id: string;
  version: number;
  /** b64u Ed25519 identity of the principal who owns (and signs) the profile. */
  owner: string;
  scope: ProfileScope;
  standing: { deny: Predicate[]; permit: Predicate[] };
  prior: { observations: ProfileObservation[]; maps: string[] };
  expires_at: number;
  /** Where the profile's revocation epochs are published and, optionally, the authority that signs them (default: owner). */
  revocation: { epoch_uri: string; key?: string };
  /** Digest of version − 1 (required exactly when version > 1). */
  prev?: string;
}
export interface IntentProfile extends IntentProfileBody {
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const strList = (v: unknown, max = 256) => Array.isArray(v) && v.length <= max && v.every((x) => typeof x === 'string' && x.length > 0);
const predOk = (p: unknown) => isObj(p) && (typeof p.verb === 'string' || (Array.isArray(p.verb) && p.verb.every((x) => typeof x === 'string')));
const KEYS = ['v', 'kind', 'profile_id', 'version', 'owner', 'scope', 'standing', 'prior', 'expires_at', 'revocation', 'prev', 'alg', 'pq_pk', 'sig', 'pq_sig'];

export function intentProfileShapeError(p: unknown, opts: { signed?: boolean } = {}): string | null {
  try {
    if (!isObj(p)) return 'profile is not an object';
    for (const k of Object.keys(p)) if (!KEYS.includes(k)) return `profile: unknown member '${k}'`;
    if (p.v !== 1 || p.kind !== INTENT_PROFILE_KIND) return 'not a pca-intent-profile v1';
    if (typeof p.profile_id !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(p.profile_id)) return 'profile_id must match [A-Za-z0-9_.-]{1,128}';
    if (!(isInt(p.version) && p.version >= 1)) return 'version must be a safe integer >= 1';
    if (decodeB64uStrict(p.owner, 32) === null) return 'owner must be canonical base64url (32 bytes)';
    if (!isObj(p.scope) || Object.keys(p.scope).some((k) => !['sites', 'verbs', 'semantic_types'].includes(k))) return 'scope must be {sites?, verbs?, semantic_types?}';
    for (const k of ['sites', 'verbs', 'semantic_types'] as const) if (p.scope[k] !== undefined && !strList(p.scope[k])) return `scope.${k} must be a list of strings`;
    if (!isObj(p.standing) || Object.keys(p.standing).sort().join() !== 'deny,permit') return 'standing must be {deny, permit}';
    for (const k of ['deny', 'permit'] as const) {
      const r = p.standing[k];
      if (!Array.isArray(r) || r.length > MAX_PROFILE_RULES || !r.every(predOk)) return `standing.${k} must be at most ${MAX_PROFILE_RULES} predicates`;
    }
    if (!isObj(p.prior) || Object.keys(p.prior).sort().join() !== 'maps,observations') return 'prior must be {observations, maps}';
    if (!Array.isArray(p.prior.observations) || p.prior.observations.length > MAX_PROFILE_OBSERVATIONS) return `prior.observations must be at most ${MAX_PROFILE_OBSERVATIONS}`;
    for (const o of p.prior.observations) {
      if (!isObj(o) || Object.keys(o).sort().join() !== 'at,values,verb,y' || typeof o.verb !== 'string' || !isObj(o.values) || (o.y !== 0 && o.y !== 1) || !(isInt(o.at) && o.at >= 0)) return 'prior.observations entries are {verb, values, y, at}';
    }
    if (!Array.isArray(p.prior.maps) || !p.prior.maps.every((m) => decodeB64uStrict(m, 32) !== null)) return 'prior.maps must be 32-byte digests';
    if (!(isInt(p.expires_at) && p.expires_at >= 0)) return 'expires_at must be a non-negative safe integer';
    if (!isObj(p.revocation) || Object.keys(p.revocation).some((k) => k !== 'epoch_uri' && k !== 'key') || typeof p.revocation.epoch_uri !== 'string' || p.revocation.epoch_uri.length === 0) return 'revocation must be {epoch_uri, key?}';
    if (p.revocation.key !== undefined && decodeB64uStrict(p.revocation.key, 32) === null) return 'revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)';
    if ((p.version === 1) !== (p.prev === undefined)) return 'prev is required exactly when version > 1';
    if (p.prev !== undefined && decodeB64uStrict(p.prev, 32) === null) return 'prev must be canonical base64url (32 bytes)';
    if (opts.signed !== false) {
      if (p.alg !== undefined && typeof p.alg !== 'string') return 'alg must be a string';
      const suite = resolveSigAlg(p.alg);
      if (suite === null) return `alg: unsupported_suite: '${String(p.alg)}'`;
      if (suite.alg === 'ed25519' && (p.pq_pk !== undefined || p.pq_sig !== undefined)) return 'an ed25519 profile must not carry pq_pk / pq_sig';
      if (typeof p.sig !== 'string') return 'sig must be a string';
    }
    canonicalBytesStrict(profileBody(p as unknown as IntentProfileBody));
    return null;
  } catch (e) {
    return `malformed profile: ${(e as Error).message}`;
  }
}

function profileBody(p: IntentProfileBody): IntentProfileBody {
  return {
    v: p.v, kind: p.kind, profile_id: p.profile_id, version: p.version, owner: p.owner, scope: p.scope, standing: p.standing,
    prior: p.prior, expires_at: p.expires_at, revocation: p.revocation, ...(p.prev !== undefined ? { prev: p.prev } : {}),
  };
}
function message(body: Record<string, unknown>): Uint8Array {
  const d = utf8(INTENT_PROFILE_SIG_DOMAIN);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(d.length + b.length);
  out.set(d);
  out.set(b, d.length);
  return out;
}

/** Sign a profile version as its owner (the owner identity must be the signer's Ed25519 key). */
export function signIntentProfile(body: Omit<IntentProfileBody, 'owner'> & { owner?: string }, ownerSecret: Uint8Array, suite?: SignerSuiteOpts): IntentProfile {
  const owner = b64u(publicKeyOf(ownerSecret));
  if (body.owner !== undefined && body.owner !== owner) throw new Error('signIntentProfile: owner does not match the signing key');
  const b = profileBody({ ...body, owner } as IntentProfileBody);
  const bad = intentProfileShapeError(b, { signed: false });
  if (bad) throw new Error(`signIntentProfile: ${bad}`);
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(ownerSecret, suite), message(bindSuiteFields(b as unknown as Record<string, unknown>, suite?.alg, pqPk)));
  return { ...b, ...fields } as IntentProfile;
}

export function verifyIntentProfile(p: unknown, pin?: PqPinPolicy): { ok: true } | { ok: false; reason: string } {
  try {
    const bad = intentProfileShapeError(p);
    if (bad) return { ok: false, reason: bad };
    const r = p as IntentProfile;
    if (!verifyPinnedSuite(r.alg, r.owner, r.pq_pk, message(bindSuiteFields(profileBody(r) as unknown as Record<string, unknown>, r.alg, r.pq_pk)), { sig: r.sig, pq_sig: r.pq_sig }, pin)) return { ok: false, reason: 'profile signature invalid' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed profile: ${(e as Error).message}` };
  }
}

/** The content address of a signed profile version (what S.layers.std.digest and the next version's `prev` carry). */
export function intentProfileDigest(p: IntentProfile): string {
  return hashCanonical({ d: INTENT_PROFILE_REF_DOMAIN, p });
}

/** Append-only succession: same id and owner, version + 1, `prev` = digest(previous). */
export function verifyProfileSuccession(prev: IntentProfile, next: IntentProfile): { ok: true } | { ok: false; reason: string } {
  for (const [x, n] of [[prev, 'previous'], [next, 'next']] as const) {
    const v = verifyIntentProfile(x);
    if (!v.ok) return { ok: false, reason: `${n} version: ${v.reason}` };
  }
  if (next.profile_id !== prev.profile_id || next.owner !== prev.owner) return { ok: false, reason: 'a profile version cannot change its id or owner' };
  if (next.version !== prev.version + 1) return { ok: false, reason: 'versions are append-only: next.version must be previous + 1' };
  if (next.prev !== intentProfileDigest(prev)) return { ok: false, reason: 'next.prev is not the digest of the previous version' };
  return { ok: true };
}

export interface ProfileUse {
  aud: string;
  verb: string;
  now: number;
  /** Semantic types of the verb's parameters (for `scope.semantic_types`). */
  semantics?: string[];
}

/** Is the profile in scope (and unexpired) for this action? */
export function profileApplies(p: IntentProfileBody, u: ProfileUse): boolean {
  if (!(u.now < p.expires_at)) return false;
  if (p.scope.sites && !p.scope.sites.includes(u.aud)) return false;
  if (p.scope.verbs && !p.scope.verbs.includes(u.verb)) return false;
  if (p.scope.semantic_types && !(u.semantics ?? []).some((s) => p.scope.semantic_types!.includes(s))) return false;
  return true;
}

/** G^std membership: an in-scope action is OUTSIDE the standing layer iff a deny rule matches it (deny wins). */
export function standingAdmits(p: IntentProfileBody, u: ProfileUse, action: ActionContext): boolean {
  if (!profileApplies(p, u)) return true; // out of scope: the profile says nothing (it can never widen)
  return !p.standing.deny.some((r) => predicateMatches(r, action));
}

/** The explicit standing-permission layer: true iff an in-scope permit rule matches (the only positive import). */
export function standingPermits(p: IntentProfileBody, u: ProfileUse, action: ActionContext): boolean {
  return profileApplies(p, u) && p.standing.permit.some((r) => predicateMatches(r, action));
}

/** The cells of Ω̃ that the profile's negative observations veto (T24: importing them never raises R). */
export function profileVetoCells(p: IntentProfileBody, omega: Omega): { verb: string; cell: number[] }[] {
  const out: { verb: string; cell: number[] }[] = [];
  const seen = new Set<string>();
  for (const o of p.prior.observations) {
    if (o.y !== 0) continue;
    const vs = omega.verbs.find((v) => v.verb === o.verb);
    const cell = vs ? cellOf(vs, { verb: o.verb, values: o.values }) : null;
    if (!vs || !cell) continue;
    const k = `${o.verb}|${cell.join(',')}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push({ verb: o.verb, cell });
    }
  }
  return out;
}

/** A ceiling function (for `decideVisit`) from a profile's standing deny rules over Ω̃ outcomes. */
export function profileCeiling(p: IntentProfileBody, u: Omit<ProfileUse, 'verb'>) {
  return (vs: Omega['verbs'][number], o: { verb: string; values: Record<string, number | string> }): boolean => {
    const a = outcomeToAction(vs, o);
    return standingAdmits(p, { ...u, verb: o.verb }, { action: { verb: a.verb, resource: a.resource, params: a.params }, ...(a.env ? { env: a.env } : {}), ...(a.subject ? { subject: a.subject } : {}) });
  };
}

/**
 * Is this profile version usable now: signed, unexpired, and NOT revoked per a fresh epoch of its revocation authority (T22)?
 * The epoch's scope is the profile (`grant_ref` = `pca-intent-profile:<id>`), its signer `revocation.key` (absent: the owner);
 * with `last` (the tracked previous epoch) the sequence must be append-only.
 */
export function profileUsable(p: IntentProfile, c: { now: number; maxAgeMs: number; revocation?: SessionRevocationEvidence; last?: SessionRevocationEvidence; pin?: PqPinPolicy }): { ok: true } | { ok: false; reason: string } {
  const v = verifyIntentProfile(p, c.pin);
  if (!v.ok) return v;
  if (!(c.now < p.expires_at)) return { ok: false, reason: 'the profile has expired' };
  // the session-revocation check with the profile as its scope (same epoch format, same T22 bound)
  const r = checkSessionRevocation(c.revocation, { session: p.profile_id, scope: profileRevocationScope(p.profile_id), authority: p.revocation.key ?? p.owner, ids: [profileRevocationId(p.profile_id, p.version)], now: c.now, maxAgeMs: c.maxAgeMs, ...(c.pin ? { pin: c.pin } : {}), ...(c.last ? { last: c.last } : {}) });
  return r.ok ? { ok: true } : { ok: false, reason: `profile revocation: ${r.reason}` };
}
