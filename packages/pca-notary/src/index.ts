/**
 * @atlasauth/pca-notary — external-fact attestation for proof-carrying actions (the zkTLS / TLSNotary
 * direction).
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  Goal: let an agent prove an EXTERNAL FACT — "the order API returned status: shipped" — INSIDE   │
 * │  its proof-carrying action, so a policy can gate on what the outside world actually said, not on │
 * │  what the agent CLAIMS it said.                                                                  │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * HOW IT WORKS. A NOTARY witnesses one HTTP request/response and signs a canonical record of it: the
 * method, the URL, a digest of the request headers, the response status, and a *commitment* to the
 * response body. The body commitment is a salted Merkle tree over the body's fields (for JSON) or chunks
 * (for text), so the agent can later DISCLOSE one field with an inclusion proof while every other field
 * stays hidden — and hidden means hiding-secure, because each leaf carries a random salt (a low-entropy
 * field such as a boolean cannot be brute-forced from its hash). The disclosure, the notary signature and
 * the body root are then BOUND to a specific PCActn, so the proof-carrying action carries a verifiable
 * "the external source returned X".
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 * THE HONEST TRUST BOUNDARY (read this before you ship).
 *
 * This primitive relies on a TRUSTED / SEMI-TRUSTED NOTARY: a party that actually observed the TLS
 * session and signs what it saw. The relying party trusts that the notary (a) reported the response
 * faithfully and (b) is not colluding with the agent to fabricate a response. In exchange you get a
 * cheap, standalone, broadly-deployable building block — no protocol changes at the origin server, no
 * MPC round trips — with real cryptographic selective redaction and a verifiable binding into the action.
 *
 * Full zkTLS / TLSNotary REMOVES that trust: the origin's TLS session key is split between the agent and
 * the notary via secure multi-party computation (MPC-TLS), so the notary attests to a transcript it could
 * never have forged and never saw in the clear, and the agent proves facts about it in zero knowledge.
 * That is the documented frontier and is deliberately OUT OF SCOPE for a package (it needs an MPC-TLS
 * handshake runtime). What this module provides is the realistic, genuinely-useful rung below it: a
 * notarized, selectively-redactable, PCActn-bound external fact. The notary is the trust assumption; it is
 * stated here so no one mistakes this for trustless zkTLS.
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 *
 * Everything FAILS CLOSED: a wrong/absent notary key, a tampered session, a tampered root, a lie about a
 * disclosed field's value, or a fact bound to a different PCActn is rejected — never silently trusted.
 *
 * Built on `@atlasauth/pca` (Ed25519 keys + signatures, the salted-Merkle commitment, the strict canonical
 * form, and `pcactnDigest`) and `node:crypto` (salt randomness) only.
 */

import { randomBytes } from 'node:crypto';
import {
  type InclusionProof,
  type KeyPair,
  type PCActn,
  b64u,
  canonicalBytes,
  compareUtf8,
  decodeB64uStrict,
  hashCanonical,
  merkleProof,
  merkleRoot,
  pcactnDigest,
  sha256,
  sign,
  utf8,
  verifyB64u,
  verifyInclusion,
} from '@atlasauth/pca';

// ===================================================================================================
// Field paths + canonical helpers
// ===================================================================================================

/** One step in a response-body path: an object key (string) or an array index / chunk index (number). */
export type PathSegment = string | number;
/** A path to a leaf of the committed response body, e.g. `['order', 'status']` or `['#chunk', 0]`. */
export type FieldPath = PathSegment[];

/** True iff `v` is a plain JSON object (not null, not an array, prototype Object.prototype or null). */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Canonical equality over JSON values (same strict canonical bytes). Fails closed (false) on any error. */
function canonicalEqual(a: unknown, b: unknown): boolean {
  try {
    return hashCanonical(a) === hashCanonical(b);
  } catch {
    return false;
  }
}

/** Normalize a disclosure path: an array is used as-is; a bare string is a single top-level key. */
function normalizePath(path: FieldPath | string): FieldPath {
  return typeof path === 'string' ? [path] : path.slice();
}

// ===================================================================================================
// Session + body commitment
// ===================================================================================================

/** The HTTP request the notary witnessed. Headers are committed only as a digest (never disclosed). */
export interface NotarizedRequest {
  method: string;
  url: string;
  headers?: Record<string, string | string[]>;
}

/**
 * The HTTP response the notary witnessed. `body` is the PARSED value (a JSON object/array/primitive) and
 * is committed as a salted Merkle tree over its fields; a string `body` with `textChunkSize` set is
 * committed as chunks instead. `undefined` is treated as a `null` body (a single leaf).
 */
export interface NotarizedResponse {
  status: number;
  body: unknown;
}

/** Algorithm tag for the body commitment (salted RFC-6962-shape Merkle tree over SHA-256). */
export const BODY_COMMIT_ALG = 'salted-merkle-sha256-v1' as const;

/** A commitment to the response body: the Merkle root over the (salted) field/chunk leaves. */
export interface ResponseBodyCommit {
  alg: typeof BODY_COMMIT_ALG;
  /** b64u SHA-256 Merkle root. */
  root: string;
  /** Number of committed leaves (fields or chunks). Binds `InclusionProof.size`. */
  size: number;
}

/** The canonical, signed record of one witnessed request/response. Carries NO plaintext body. */
export interface NotarySession {
  v: 1;
  /** Upper-cased HTTP method. */
  method: string;
  url: string;
  /** `hashCanonical` of the lower-cased, key-sorted request headers (`{}` when none). */
  requestHeadersDigest: string;
  responseStatus: number;
  responseBodyCommit: ResponseBodyCommit;
  /** Epoch milliseconds the notary observed the session. */
  observedAt: number;
}

/** One committed leaf with its hiding salt. Held PRIVATELY by the prover (the opening material). */
export interface SaltedLeaf {
  path: FieldPath;
  value: unknown;
  /** b64u random salt (16 bytes) — makes the leaf commitment hiding. */
  salt: string;
}

/**
 * The full observed session the prover holds: the public `session` PLUS the per-leaf openings needed to
 * disclose fields. This is `discloseField`'s second argument. It is NOT shared with a verifier.
 */
export interface NotaryWitness {
  session: NotarySession;
  leaves: SaltedLeaf[];
}

// ---- body flattening -------------------------------------------------------------------------------

interface BareLeaf {
  path: FieldPath;
  value: unknown;
}

/** Flatten a JSON value into ordered terminal leaves (empty object/array is itself a leaf). */
function flattenValue(value: unknown, prefix: FieldPath): BareLeaf[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return [{ path: prefix, value: [] }];
    const out: BareLeaf[] = [];
    for (let i = 0; i < value.length; i++) out.push(...flattenValue(value[i], [...prefix, i]));
    return out;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort(compareUtf8);
    if (keys.length === 0) return [{ path: prefix, value: {} }];
    const out: BareLeaf[] = [];
    for (const k of keys) out.push(...flattenValue(value[k], [...prefix, k]));
    return out;
  }
  return [{ path: prefix, value: value ?? null }];
}

/** Split a string into `size`-character chunks (never splits a surrogate pair). */
function chunkString(s: string, size: number): BareLeaf[] {
  const chars = Array.from(s); // iterate by code point, not UTF-16 unit
  if (chars.length === 0) return [{ path: ['#chunk', 0], value: '' }];
  const out: BareLeaf[] = [];
  for (let i = 0, idx = 0; i < chars.length; i += size, idx++) {
    out.push({ path: ['#chunk', idx], value: chars.slice(i, i + size).join('') });
  }
  return out;
}

/** The object committed per leaf. A disclosed leaf is re-derived from exactly these three fields. */
function leafObject(leaf: SaltedLeaf): Record<string, unknown> {
  return { p: leaf.path, v: leaf.value, s: leaf.salt };
}

function newSalt(): string {
  return b64u(randomBytes(16));
}

/** Lower-case + sort request headers, then `hashCanonical`. Undefined/none => digest of `{}`. */
function requestHeadersDigest(headers: Record<string, string | string[]> | undefined): string {
  const norm: Record<string, string | string[]> = {};
  for (const [k, val] of Object.entries(headers ?? {})) norm[k.toLowerCase()] = val;
  return hashCanonical(norm);
}

// ===================================================================================================
// Attestation + binding
// ===================================================================================================

/** The notary's signature binding this attested fact to a specific PCActn (via its digest). */
export interface FactBinding {
  /** `pcactnDigest(pcActn)` — the action this fact is declared to be FOR. */
  pcactn_digest: string;
}

/**
 * A signed notary attestation: the public session + the signer's identity + the Ed25519 signature over
 * the canonical session, optionally bound to a PCActn.
 */
export interface NotaryAttestation {
  session: NotarySession;
  /** b64u Ed25519 public key of the notary that signed. */
  notary: string;
  /** b64u Ed25519 signature over `notaryMessage(session)`. */
  sig: string;
  /** Present once `bindFactToPcActn` has tied this fact to an action. */
  fact_binding?: FactBinding;
}

/** A redactable disclosure of ONE response field: the opened leaf + its Merkle inclusion proof. */
export interface FieldDisclosure {
  path: FieldPath;
  value: unknown;
  salt: string;
  proof: InclusionProof;
}

const NOTARY_DOMAIN = 'atlas-pca/notary/v1\0';

/** The canonical bytes the notary signs: `NOTARY_DOMAIN ‖ sha256(canonical(session))`. */
export function notaryMessage(session: NotarySession): Uint8Array {
  const d = sha256(canonicalBytes(session));
  const pre = utf8(NOTARY_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

/** Normalize a public-key input to its b64u form. */
function toPubB64u(key: string | Uint8Array | KeyPair): string {
  if (typeof key === 'string') return key;
  if (key instanceof Uint8Array) return b64u(key);
  return b64u(key.publicKey);
}

// ===================================================================================================
// notarizeResponse
// ===================================================================================================

/** Options for {@link notarizeResponse}. */
export interface NotarizeOptions {
  /** The notary's signing key pair (its public key becomes `attestation.notary`). */
  notaryKey: KeyPair;
  /** Epoch ms the notary observed the session (default `Date.now()`). */
  observedAt?: number;
  /** When set and the body is a string, commit it as `textChunkSize`-character chunks instead of one leaf. */
  textChunkSize?: number;
}

/** Result of {@link notarizeResponse}: the shareable attestation + the prover's private opening witness. */
export interface NotarizeResult {
  attestation: NotaryAttestation;
  /** The full observed session incl. per-field openings. Pass this to {@link discloseField}. Keep private. */
  witness: NotaryWitness;
}

/**
 * Witness a request/response and produce a signed {@link NotaryAttestation} (over the canonical session +
 * the response-body Merkle root) plus the {@link NotaryWitness} the prover keeps to disclose fields later.
 */
export function notarizeResponse(
  input: { request: NotarizedRequest; response: NotarizedResponse },
  opts: NotarizeOptions,
): NotarizeResult {
  const { request, response } = input;
  if (typeof request.method !== 'string' || request.method.length === 0) throw new TypeError('notarizeResponse: request.method is required');
  if (typeof request.url !== 'string' || request.url.length === 0) throw new TypeError('notarizeResponse: request.url is required');
  if (!Number.isSafeInteger(response.status)) throw new TypeError('notarizeResponse: response.status must be an integer');

  const bare =
    typeof response.body === 'string' && typeof opts.textChunkSize === 'number' && opts.textChunkSize > 0
      ? chunkString(response.body, Math.floor(opts.textChunkSize))
      : flattenValue(response.body, []);

  const leaves: SaltedLeaf[] = bare.map((l) => ({ path: l.path, value: l.value, salt: newSalt() }));
  const root = merkleRoot(leaves.map(leafObject));

  const session: NotarySession = {
    v: 1,
    method: request.method.toUpperCase(),
    url: request.url,
    requestHeadersDigest: requestHeadersDigest(request.headers),
    responseStatus: response.status,
    responseBodyCommit: { alg: BODY_COMMIT_ALG, root, size: leaves.length },
    observedAt: opts.observedAt ?? Date.now(),
  };

  const attestation: NotaryAttestation = {
    session,
    notary: b64u(opts.notaryKey.publicKey),
    sig: b64u(sign(opts.notaryKey.secretKey, notaryMessage(session))),
  };
  return { attestation, witness: { session, leaves } };
}

// ===================================================================================================
// discloseField
// ===================================================================================================

/**
 * Produce a redactable disclosure revealing ONE response field (by `path`) with its Merkle inclusion
 * proof, keeping every other field hidden. Throws if `path` names no committed leaf.
 */
export function discloseField(_attestation: NotaryAttestation, witness: NotaryWitness, path: FieldPath | string): FieldDisclosure {
  void _attestation; // the proof binds to the attested root via verifyDisclosedField; witness holds the openings
  const want = normalizePath(path);
  const idx = witness.leaves.findIndex((l) => canonicalEqual(l.path, want));
  if (idx < 0) throw new Error(`discloseField: no committed field at path ${JSON.stringify(want)}`);
  const leaf = witness.leaves[idx]!;
  const proof = merkleProof(witness.leaves.map(leafObject), idx);
  return { path: leaf.path, value: leaf.value, salt: leaf.salt, proof };
}

// ===================================================================================================
// Verification (fail closed)
// ===================================================================================================

/** Structural check of a `ResponseBodyCommit`. */
function validCommit(c: unknown): c is ResponseBodyCommit {
  if (c === null || typeof c !== 'object') return false;
  const r = c as Record<string, unknown>;
  return (
    r.alg === BODY_COMMIT_ALG &&
    typeof r.root === 'string' &&
    decodeB64uStrict(r.root, 32) !== null &&
    Number.isSafeInteger(r.size) &&
    (r.size as number) >= 1
  );
}

/** Structural check of a `NotarySession`. */
function validSession(s: unknown): s is NotarySession {
  if (s === null || typeof s !== 'object') return false;
  const r = s as Record<string, unknown>;
  return (
    r.v === 1 &&
    typeof r.method === 'string' &&
    typeof r.url === 'string' &&
    typeof r.requestHeadersDigest === 'string' &&
    Number.isSafeInteger(r.responseStatus) &&
    Number.isSafeInteger(r.observedAt) &&
    validCommit(r.responseBodyCommit)
  );
}

/**
 * Verify the notary signature AND the session's structural integrity. `notaryKey` is the TRUSTED notary's
 * public key (b64u string, raw bytes, or key pair); the attestation's recorded signer must equal it and
 * the signature must verify over the canonical session. Fails closed (false) on any deviation.
 */
export function verifyNotaryAttestation(attestation: NotaryAttestation, opts: { notaryKey: string | Uint8Array | KeyPair }): boolean {
  try {
    if (attestation === null || typeof attestation !== 'object') return false;
    if (!validSession(attestation.session)) return false;
    if (typeof attestation.notary !== 'string' || typeof attestation.sig !== 'string') return false;
    const expected = toPubB64u(opts.notaryKey);
    if (attestation.notary !== expected) return false; // the recorded signer must be the trusted notary
    return verifyB64u(attestation.notary, notaryMessage(attestation.session), attestation.sig);
  } catch {
    return false;
  }
}

/**
 * Verify a disclosed field: the notary attestation is authentic AND the disclosed leaf is included under
 * the attested response-body root at a position consistent with the committed size. A lie about the
 * field's value (or path, or salt) breaks inclusion. Fails closed (false) on any deviation.
 */
export function verifyDisclosedField(
  attestation: NotaryAttestation,
  disclosure: FieldDisclosure,
  opts: { notaryKey: string | Uint8Array | KeyPair },
): boolean {
  try {
    if (!verifyNotaryAttestation(attestation, opts)) return false;
    if (disclosure === null || typeof disclosure !== 'object') return false;
    if (!Array.isArray(disclosure.path) || typeof disclosure.salt !== 'string') return false;
    const proof = disclosure.proof;
    if (proof === null || typeof proof !== 'object' || !Array.isArray(proof.path)) return false;
    const commit = attestation.session.responseBodyCommit;
    if (proof.size !== commit.size) return false; // bind the proof to the committed leaf count
    const leaf = leafObject({ path: disclosure.path, value: disclosure.value, salt: disclosure.salt });
    return verifyInclusion(commit.root, proof, leaf);
  } catch {
    return false;
  }
}

// ===================================================================================================
// PCA binding
// ===================================================================================================

/**
 * A stable digest identifying this attested FACT (independent of any PCActn binding). The agent places
 * this in its PCActn's `provenance.trusted_refs` so the action COMMITS to the fact it relies on; that is
 * one half of the two-way binding checked by {@link factMatchesPcActn}.
 */
export function factRef(attestation: NotaryAttestation): string {
  return hashCanonical({ fact: 'atlas-pca-notary/v1', session: attestation.session, notary: attestation.notary, sig: attestation.sig });
}

/**
 * Bind an attested fact to a specific PCActn by stamping the action's digest into the attestation. This is
 * the fact side of the binding ("I am for THIS action"); the action side is the agent including
 * {@link factRef} in the PCActn's `provenance.trusted_refs`. Returns a new attestation (input untouched).
 */
export function bindFactToPcActn(attestation: NotaryAttestation, pcActn: PCActn): NotaryAttestation {
  return { ...attestation, fact_binding: { pcactn_digest: pcactnDigest(pcActn) } };
}

/**
 * True iff the fact is bound to `pcActn` in BOTH directions, so neither can be swapped:
 *   1. the fact names the action — `fact_binding.pcactn_digest === pcactnDigest(pcActn)`; AND
 *   2. the action commits to the fact — `pcActn.provenance.trusted_refs` includes `factRef(attestation)`.
 * Fails closed (false) if either side is missing. Changing the PCActn breaks (1); swapping the fact breaks (2).
 */
export function factMatchesPcActn(attestation: NotaryAttestation, pcActn: PCActn): boolean {
  try {
    const binding = attestation.fact_binding;
    if (!binding || typeof binding.pcactn_digest !== 'string') return false;
    if (binding.pcactn_digest !== pcactnDigest(pcActn)) return false;
    const refs = pcActn.provenance?.trusted_refs;
    if (!Array.isArray(refs)) return false;
    return refs.includes(factRef(attestation));
  } catch {
    return false;
  }
}

// ===================================================================================================
// Policy caveat: REQUIRE an attested external fact
// ===================================================================================================

/** Caveat type tag for "this action is admitted only if a notarized external fact holds". */
export const ATTESTED_FACT_CAVEAT = 'attested_fact' as const;

/**
 * A policy caveat that admits an action only when the agent discloses a notarized response field equal to
 * `equals` (e.g. "only refund if the notarized order status == 'shipped'"). The caveat names the trusted
 * notary, the required field path, and the required value — and optionally the exact URL the fact must
 * come from.
 */
export interface AttestedFactCaveat {
  type: typeof ATTESTED_FACT_CAVEAT;
  /** b64u public key of the notary whose attestation is accepted. */
  notary: string;
  /** The response-body path that must be disclosed. */
  path: FieldPath;
  /** The value the disclosed field must canonically equal. */
  equals: unknown;
  /** Optional: require `session.url` to equal this exact URL. */
  url?: string;
  /** Optional: require the fact to be bound to the PCActn under evaluation (two-way binding). */
  bindToPcActn?: boolean;
}

/** Build an {@link AttestedFactCaveat}. `notary` may be a b64u string, raw bytes, or a key pair. */
export function requireAttestedFact(opts: {
  notary: string | Uint8Array | KeyPair;
  path: FieldPath;
  equals: unknown;
  url?: string;
  bindToPcActn?: boolean;
}): AttestedFactCaveat {
  return {
    type: ATTESTED_FACT_CAVEAT,
    notary: toPubB64u(opts.notary),
    path: opts.path.slice(),
    equals: opts.equals,
    ...(opts.url !== undefined ? { url: opts.url } : {}),
    ...(opts.bindToPcActn !== undefined ? { bindToPcActn: opts.bindToPcActn } : {}),
  };
}

/** The evidence a verifier supplies to discharge an {@link AttestedFactCaveat}. */
export interface AttestedFactEvidence {
  attestation: NotaryAttestation;
  disclosure: FieldDisclosure;
  /** The action being authorized — required when the caveat sets `bindToPcActn`. */
  pcActn?: PCActn;
}

/** Result of evaluating an {@link AttestedFactCaveat}. */
export interface AttestedFactEvaluation {
  ok: boolean;
  reason?: string;
}

/**
 * Evaluate an {@link AttestedFactCaveat} against disclosed evidence. Admits (`ok: true`) only when, fail
 * closed at every step:
 *   1. the notary attestation is authentic under the caveat's `notary` key;
 *   2. (if `url` set) the attested session URL matches;
 *   3. the disclosed field verifies (notary-signed + included under the attested body root);
 *   4. the disclosed `path` equals the caveat's `path`;
 *   5. the disclosed `value` canonically equals the caveat's `equals`;
 *   6. (if `bindToPcActn`) the fact is two-way-bound to the supplied PCActn.
 */
export function evaluateAttestedFactCaveat(caveat: AttestedFactCaveat, evidence: AttestedFactEvidence): AttestedFactEvaluation {
  try {
    if (caveat === null || typeof caveat !== 'object' || caveat.type !== ATTESTED_FACT_CAVEAT) {
      return { ok: false, reason: 'not an attested_fact caveat' };
    }
    if (typeof caveat.notary !== 'string' || !Array.isArray(caveat.path)) {
      return { ok: false, reason: 'caveat is malformed (notary/path)' };
    }
    const { attestation, disclosure, pcActn } = evidence;
    if (!verifyNotaryAttestation(attestation, { notaryKey: caveat.notary })) {
      return { ok: false, reason: 'notary attestation does not verify (fail closed)' };
    }
    if (caveat.url !== undefined && attestation.session.url !== caveat.url) {
      return { ok: false, reason: 'attested session URL does not match the caveat' };
    }
    if (!verifyDisclosedField(attestation, disclosure, { notaryKey: caveat.notary })) {
      return { ok: false, reason: 'disclosed field does not verify under the attested root' };
    }
    if (!canonicalEqual(disclosure.path, caveat.path)) {
      return { ok: false, reason: 'disclosed field is not the path the caveat requires' };
    }
    if (!canonicalEqual(disclosure.value, caveat.equals)) {
      return { ok: false, reason: 'disclosed field value does not satisfy the caveat' };
    }
    if (caveat.bindToPcActn) {
      if (!pcActn) return { ok: false, reason: 'caveat requires PCActn binding but no PCActn was supplied' };
      if (!factMatchesPcActn(attestation, pcActn)) return { ok: false, reason: 'fact is not bound to this PCActn' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `attested_fact evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

/** Type guard: a bare caveat object is an {@link AttestedFactCaveat}. */
export function isAttestedFactCaveat(cv: unknown): cv is AttestedFactCaveat {
  return (
    cv !== null &&
    typeof cv === 'object' &&
    (cv as { type?: unknown }).type === ATTESTED_FACT_CAVEAT &&
    typeof (cv as { notary?: unknown }).notary === 'string' &&
    Array.isArray((cv as { path?: unknown }).path)
  );
}
