import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite, type SignerSuiteOpts } from './pq';
import { suiteCapabilityError } from './intent-strict';

/**
 * Shared plumbing for the Intent Layer v2 W-B artifacts (docs/specs/pca-intent-layer-v2.md §8, conformance rules
 * 16-18): oracle facts (`pca-fact`), offer sets (`pca-offer-set`), label receipts (`pca-labels`) and classifier
 * verdicts (`pca-intent-classification`).
 *
 * Every one of them follows the SAME rules, so a native verifier implements them once:
 *   SUITE      optional `alg` (absent = ed25519; a non-string is malformed; a suite this verifier does not implement is
 *              refused with `unsupported_suite`), optional `pq_pk` / `pq_sig` (strings; both absent for ed25519). Every
 *              registry suite is allowed (`pq.ts`).
 *   SIGNATURE  the suite's signature (`sig`, plus `pq_sig` for a hybrid) over
 *                utf8(domain) || strictCanonical(body)
 *              where `body` is the artifact WITHOUT `sig` and `pq_sig` (so `alg` and `pq_pk` are signed; the
 *              action-schema rule of §3.2). The Ed25519 key always comes from the VERIFIER's pins, never from the
 *              artifact; a post-quantum or hybrid signature verifies only when the artifact's `pq_pk` equals the PQ key
 *              the verifier PINNED for that signer (`pq_pk` of the pin entry): the artifact's own `pq_pk` alone never
 *              authorises it.
 *   REFERENCE  the content address committed in the signed PCActn `intent_session` member is
 *                base64url(sha256(strictCanonical({ d: <ref domain>, <slot>: <artifact WITH sig> })))
 *              (the `atlas-pca/action-schema-ref/v1` pattern of §3.2), so a committed digest pins the exact signed
 *              bytes, signature included.
 */

/** Names of world / relational / offer dimensions and classifier ids: they become `env.*` path segments. */
export const INTENT_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
/** A data class (`pii.contact`, `payment.instrument_meta`, `public`). */
export const DATA_CLASS_RE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/;
/** One segment of an `action.params.*` path (the prototype-polluting names are refused separately). */
export const PARAM_SEGMENT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
/** A usable path segment: matches {@link PARAM_SEGMENT_RE} and is not `__proto__` / `constructor` / `prototype`. */
export const isPathSegment = (s: string): boolean => PARAM_SEGMENT_RE.test(s) && !FORBIDDEN_SEGMENTS.has(s);

export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
export const isSafeInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
export const utf8Len = (s: string): number => utf8(s).length;
/** Non-empty string of at most `max` UTF-8 bytes. */
export const isBoundedString = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && utf8Len(v) <= max;
export const isDigest = (v: unknown): v is string => decodeB64uStrict(v, 32) !== null;

/** A wire scalar: a string, a safe integer or a boolean. */
export type WireScalar = string | number | boolean;
export const isScalar = (v: unknown): v is WireScalar => typeof v === 'string' || typeof v === 'boolean' || isSafeInt(v);
/** Scalar equality: same JSON type and value (no coercion: `1 !== "1"`, `true !== 1`). */
export const scalarEq = (a: unknown, b: unknown): boolean => typeof a === typeof b && a === b;

/** Closed member set check: null when `o` has exactly the `required` members plus any of `optional`. */
export function closedMembers(o: Record<string, unknown>, required: readonly string[], optional: readonly string[] = [], where = 'object'): string | null {
  for (const k of Object.keys(o)) if (!required.includes(k) && !optional.includes(k)) return `unknown member '${where}.${k}'`;
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(o, k)) return `missing member '${where}.${k}'`;
  return null;
}

/** The optional suite members every W-B artifact may carry. */
export const SUITE_MEMBERS = ['alg', 'pq_pk', 'pq_sig'] as const;

/** A pinned signer: the Ed25519 key and, for a post-quantum or hybrid suite, the PQ key the trusted side pins. */
export interface PinnedSigner {
  pk: string;
  pq_pk?: string;
}

/** Validate a pin's optional `pq_pk` (absent, or a non-empty string; JSON null is malformed). */
export const pinPqOk = (v: unknown): boolean => v === undefined || (typeof v === 'string' && v.length > 0);

/**
 * Suite capability and shape of an artifact's suite members. Null = usable. A non-string `alg` and non-string
 * `pq_pk` / `pq_sig` are malformed; an `alg` this verifier does not implement yields a reason containing
 * `unsupported_suite`; an ed25519 artifact (alg absent or "ed25519") must carry neither `pq_pk` nor `pq_sig`.
 */
export function artifactSuiteError(a: Record<string, unknown>): string | null {
  if (!isPlainObject(a)) return 'artifact must be an object';
  const e = suiteCapabilityError(a.alg, (x) => resolveSigAlg(x) !== null);
  if (e) return e;
  for (const k of ['pq_pk', 'pq_sig'] as const) if (a[k] !== undefined && typeof a[k] !== 'string') return `${k} must be a string`;
  if (resolveSigAlg(a.alg)!.alg === 'ed25519' && (a.pq_pk !== undefined || a.pq_sig !== undefined)) return 'an ed25519 artifact must not carry pq_pk / pq_sig';
  return null;
}

/** The exact bytes an artifact signature covers: utf8(domain) || strictCanonical(body without `sig` / `pq_sig`). Throws on a non-canonical body. */
export function artifactMessage(domain: string, artifact: Record<string, unknown>): Uint8Array {
  const { sig: _sig, pq_sig: _pqSig, ...body } = artifact;
  const d = utf8(domain);
  const b = canonicalBytesStrict(body);
  const m = new Uint8Array(d.length + b.length);
  m.set(d);
  m.set(b, d.length);
  return m;
}

/**
 * Sign an artifact body under a suite (default ed25519): a non-default suite adds `alg` and `pq_pk` to the signed body,
 * and a hybrid also returns `pq_sig`. Throws on an unknown suite or missing key material (fail closed).
 */
export function signArtifact<T extends Record<string, unknown>>(domain: string, body: T, secretKey: Uint8Array, suite?: SignerSuiteOpts): T & { sig: string } {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new Error(`signArtifact: unknown signature alg '${String(suite?.alg)}'`);
  const full: Record<string, unknown> = resolved.alg === 'ed25519' ? { ...body } : { ...body, alg: resolved.alg, pq_pk: suitePqPublicKey(suite?.alg, suite) };
  const f = signSuiteArtifact(suite?.alg, suiteKeysOf(secretKey, suite), artifactMessage(domain, full));
  return { ...full, sig: f.sig, ...(f.pq_sig !== undefined ? { pq_sig: f.pq_sig } : {}) } as T & { sig: string };
}

/**
 * Verify an artifact's signature under a PINNED signer (the caller has checked {@link artifactSuiteError}). Ed25519
 * under `pin.pk`; any other suite only when the artifact's `pq_pk` equals `pin.pq_pk`. Total: false on any malformed input.
 */
export function verifyArtifactSig(domain: string, artifact: Record<string, unknown>, pin: PinnedSigner | string): boolean {
  try {
    const p: PinnedSigner = typeof pin === 'string' ? { pk: pin } : pin;
    if (typeof artifact.sig !== 'string' || typeof p.pk !== 'string') return false;
    const pqPins = typeof p.pq_pk === 'string' ? { [p.pk]: p.pq_pk } : {};
    return verifyPinnedSuite(artifact.alg, p.pk, artifact.pq_pk, artifactMessage(domain, artifact), { sig: artifact.sig, pq_sig: artifact.pq_sig }, { pqPins });
  } catch {
    return false;
  }
}

/** Content address of an artifact (signature included): b64u(sha256(strictCanonical({d, [slot]: artifact}))). */
export function artifactRef(refDomain: string, slot: string, artifact: unknown): string {
  return hashCanonical({ d: refDomain, [slot]: artifact });
}

/** b64u public key of a secret key (convenience for issuers and tests). */
export const publicKeyB64u = (secretKey: Uint8Array): string => b64u(publicKeyOf(secretKey));

/**
 * Resolve an `action.params.<a>.<b>…` path inside `params` (own properties only). `found: false` when the path is
 * malformed or absent.
 */
export function resolveParamPath(params: unknown, path: string): { found: boolean; value?: unknown } {
  if (typeof path !== 'string' || !path.startsWith('action.params.')) return { found: false };
  const segs = path.slice('action.params.'.length).split('.');
  let cur: unknown = params;
  for (const s of segs) {
    if (!isPathSegment(s) || !isPlainObject(cur) || !Object.prototype.hasOwnProperty.call(cur, s)) return { found: false };
    cur = cur[s];
  }
  return { found: true, value: cur };
}

/**
 * A prototype-free record: keys such as `constructor`, `toString`, `valueOf`, `hasOwnProperty` or `__proto__` are
 * ordinary keys (a plain `{}` would read inherited members for them, and `__proto__` would set its prototype). Every
 * tally and keyed output in the W-B modules uses one.
 */
export function nullRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

/** Own-property lookup that never reads inherited members. */
export const ownGet = <T>(o: Record<string, T> | null | undefined, k: string): T | undefined =>
  o !== null && o !== undefined && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;

/** A usable clock value: a safe integer (anything else makes every freshness bound fail, i.e. stale). */
export const isClock = (v: unknown): v is number => isSafeInt(v);

/** True iff `path` is a well-formed `action.params.*` path (1..8 segments). */
export function isParamPath(path: unknown): path is string {
  if (typeof path !== 'string' || !path.startsWith('action.params.')) return false;
  const segs = path.slice('action.params.'.length).split('.');
  return segs.length >= 1 && segs.length <= 8 && segs.every(isPathSegment);
}

/**
 * Set `value` at the nested position of a dotted `path` under `root`. Returns false (and changes nothing) when the
 * path collides with an existing leaf or subtree (one path a prefix of another).
 */
export function setNested(root: Record<string, unknown>, path: string, value: unknown): boolean {
  const segs = path.split('.');
  let cur = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const k = segs[i]!;
    if (!Object.prototype.hasOwnProperty.call(cur, k)) cur[k] = Object.create(null) as Record<string, unknown>;
    const next = cur[k];
    if (!isPlainObject(next)) return false;
    cur = next;
  }
  const last = segs[segs.length - 1]!;
  if (Object.prototype.hasOwnProperty.call(cur, last)) return false;
  cur[last] = value;
  return true;
}

