import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type PqPinPolicy,
  type SignerSuiteOpts,
  type SigAlg,
  bindSuiteFields,
  resolveSigAlg,
  signSuiteArtifact,
  suiteKeysOf,
  suitePqPublicKey,
  verifyPinnedSuite,
} from './pq';
import { type SignedTreeHead, verifyLedgerInclusion, verifyTreeHead } from './ledger';
import type { InclusionProof } from './merkle';

/**
 * PCA Intent Layer artifacts (docs/specs/pca-intent-layer.md §4.1, §4.3, §8): the signed IntentStatement, the
 * Intent Map content address + a detached signed map attestation, and the signed runtime observation that feeds the
 * trust ramp (L5). Every signature is SUITE-AGILE exactly like the other PCA artifacts (revocation epochs, beacons,
 * ...): absent `alg` == Ed25519 (byte-identical to the M0 prototype); any other registered suite (`ml-dsa-65`,
 * `hybrid-ed25519-ml-dsa-65`, ...) binds `alg` + `pq_pk` into the signed body, and verification goes through
 * `verifyPinnedSuite`, so a PQ key is accepted only when pinned (`pqPins[signer]`) or under the legacy
 * `allowUnboundPq` opt-out (fail closed otherwise).
 *
 * The Intent Map's REPLAY verification (rebuild the learner, re-derive every number) needs the learner and lives in
 * `@atlasauth/pca-intent` (`verifyIntentMap`); this module owns only what every party (server, relying party, native
 * verifier) can check without it: the content addresses and the signatures.
 */

export const INTENT_SIG_DOMAIN = 'atlas-pca/intent/v1\0';
export const INTENT_REF_DOMAIN = 'atlas-pca/intent-ref/v1';
export const INTENT_MAP_DOMAIN = 'atlas-pca/intent-map/v1';
export const INTENT_MAP_SIG_DOMAIN = 'atlas-pca/intent-map-sig/v1\0';
export const INTENT_OBS_SIG_DOMAIN = 'atlas-pca/intent-obs/v1\0';

export type IntentSourceKind = 'conversation' | 'ticket' | 'document' | 'form' | 'other';
export const INTENT_SOURCE_KINDS: readonly IntentSourceKind[] = ['conversation', 'ticket', 'document', 'form', 'other'];

export interface IntentSource {
  kind: IntentSourceKind;
  /** Optional locator (URL, ticket id). Not interpreted. */
  uri?: string;
  /** b64u SHA-256 of the exact source bytes (the transcript excerpt, the ticket body). */
  digest: string;
}

/** The principal's request: own words + structured reading (`slots`, typed by `@atlasauth/pca-intent`) + provenance. */
export interface IntentStatement<S = unknown> {
  v: 1;
  /** b64u Ed25519 public key of the principal (the signer identity; PQ keys are pinned against it). */
  principal: string;
  text: string;
  slots: S;
  sources: IntentSource[];
  /** epoch ms */
  created_at: number;
  /** b64u random nonce (makes two identical requests distinct statements). */
  nonce: string;
}

/** A signed statement: the body plus its suite fields (`alg`/`pq_pk` signed, absent for Ed25519) and signature(s). */
export interface SignedIntentStatement<S = unknown> extends IntentStatement<S> {
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

/** Verification options shared by every intent artifact. */
export interface IntentVerifyOptions extends PqPinPolicy {
  /** When set, the artifact's signer must equal it. */
  expectedSigner?: string;
}

export type IntentVerdict = { ok: true } | { ok: false; reason: string };

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** Suite fields must be consistent: unknown `alg` refused; an Ed25519 artifact carries no `pq_pk` / `pq_sig` (unsigned malleability). */
function suiteFieldsError(a: { alg?: unknown; pq_pk?: unknown; pq_sig?: unknown }): string | null {
  const suite = resolveSigAlg(a.alg);
  if (suite === null) return 'unknown signature suite';
  if (suite.alg === 'ed25519' && (a.pq_pk !== undefined || a.pq_sig !== undefined)) return 'an ed25519 artifact must not carry pq_pk / pq_sig';
  return null;
}

function domainMessage(domain: string, body: unknown): Uint8Array {
  const dom = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom, 0);
  out.set(b, dom.length);
  return out;
}

function statementBody<S>(s: IntentStatement<S>): IntentStatement<S> {
  return plain({ v: s.v, principal: s.principal, text: s.text, slots: s.slots, sources: s.sources, created_at: s.created_at, nonce: s.nonce });
}

/** Content address of an intent statement: suite fields and signatures excluded (the ref names the CONTENT). */
export function intentRef(s: IntentStatement<unknown>): string {
  return hashCanonical({ d: INTENT_REF_DOMAIN, s: statementBody(s) });
}

function statementShapeError(s: unknown): string | null {
  if (!isObj(s)) return 'intent statement is not an object';
  if (s.v !== 1) return 'unsupported intent statement version';
  if (decodeB64uStrict(s.principal, 32) === null) return 'principal is not canonical base64url (32 bytes)';
  if (typeof s.text !== 'string' || s.text.length === 0) return 'text must be a non-empty string';
  if (!isObj(s.slots)) return 'slots must be an object';
  if (!Array.isArray(s.sources)) return 'sources must be an array';
  for (const [i, src] of s.sources.entries()) {
    if (!isObj(src) || !INTENT_SOURCE_KINDS.includes(src.kind as IntentSourceKind)) return `sources[${i}] has an unknown kind`;
    if (src.uri !== undefined && typeof src.uri !== 'string') return `sources[${i}].uri must be a string`;
    if (decodeB64uStrict(src.digest, 32) === null) return `sources[${i}].digest is not canonical base64url (32 bytes)`;
  }
  if (!isInt(s.created_at) || s.created_at < 0) return 'created_at must be a non-negative safe integer (epoch ms)';
  if (typeof s.nonce !== 'string' || s.nonce.length === 0) return 'nonce must be a non-empty string';
  return null;
}

/** Sign a statement as its principal. `principal` defaults to the Ed25519 key of `principalSecret` (must match if given). */
export function signIntentStatement<S>(
  s: Omit<IntentStatement<S>, 'principal'> & { principal?: string },
  principalSecret: Uint8Array,
  suite?: SignerSuiteOpts,
): SignedIntentStatement<S> {
  const principal = b64u(publicKeyOf(principalSecret));
  if (s.principal !== undefined && s.principal !== principal) throw new Error('signIntentStatement: principal key mismatch');
  const body = statementBody({ ...s, principal } as IntentStatement<S>);
  const bad = statementShapeError(body);
  if (bad) throw new Error(`signIntentStatement: ${bad}`);
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const signed = bindSuiteFields(body, suite?.alg, pqPk);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(principalSecret, suite), domainMessage(INTENT_SIG_DOMAIN, signed));
  return { ...body, ...fields };
}

/** Verify a signed statement (shape, signer, suite signature). Never throws. */
export function verifyIntentStatement(s: unknown, opts: IntentVerifyOptions = {}): IntentVerdict {
  try {
    const bad = statementShapeError(s);
    if (bad) return { ok: false, reason: bad };
    const st = s as unknown as SignedIntentStatement;
    if (opts.expectedSigner !== undefined && st.principal !== opts.expectedSigner) return { ok: false, reason: 'principal mismatch' };
    const se = suiteFieldsError(st);
    if (se) return { ok: false, reason: se };
    const msg = domainMessage(INTENT_SIG_DOMAIN, bindSuiteFields(statementBody(st), st.alg, st.pq_pk));
    if (!verifyPinnedSuite(st.alg, st.principal, st.pq_pk, msg, { sig: st.sig, pq_sig: st.pq_sig }, opts)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed intent statement: ${(e as Error).message}` };
  }
}

// ---- Intent Map: content address + detached signed attestation -------------------------------------------

/** Minimal structural view of an Intent Map (the full schema is `IntentMap` in `@atlasauth/pca-intent`). */
export interface IntentMapLike {
  v: 1;
  kind: 'pca-intent-map';
  intent_ref: string | null;
  metrics: { fidelity_est_ppm: number; residual_risk_ppm: number } & Record<string, unknown>;
  [k: string]: unknown;
}

/** Content address of an Intent Map (strict canonical, ppm integers, so it is language-portable). */
export function intentMapDigest(m: unknown): string {
  return hashCanonical({ d: INTENT_MAP_DOMAIN, m: plain(m) });
}

/** Structural check of an Intent Map (does NOT replay it; see `verifyIntentMap` in `@atlasauth/pca-intent`). */
export function intentMapShapeError(m: unknown): string | null {
  if (!isObj(m) || m.v !== 1 || m.kind !== 'pca-intent-map') return 'not an intent map v1';
  if (m.intent_ref !== null && decodeB64uStrict(m.intent_ref, 32) === null) return 'intent_ref must be null or canonical base64url (32 bytes)';
  const mt = m.metrics;
  if (!isObj(mt)) return 'metrics must be an object';
  if (!isInt(mt.fidelity_est_ppm) || mt.fidelity_est_ppm < 0 || mt.fidelity_est_ppm > 1_000_000) return 'metrics.fidelity_est_ppm must be an integer in [0, 1e6]';
  if (!isInt(mt.residual_risk_ppm) || mt.residual_risk_ppm < 0) return 'metrics.residual_risk_ppm must be a non-negative integer';
  return null;
}

/** A detached signature over an Intent Map's digest (who vouches for the map: the synthesiser, the principal, ...). */
export interface IntentMapAttestation {
  v: 1;
  map_digest: string;
  intent_ref: string | null;
  /** b64u Ed25519 identity of the signer. */
  signer: string;
  /** epoch ms */
  signed_at: number;
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

function mapAttBody(a: Pick<IntentMapAttestation, 'v' | 'map_digest' | 'intent_ref' | 'signer' | 'signed_at'>) {
  return { v: a.v, map_digest: a.map_digest, intent_ref: a.intent_ref, signer: a.signer, signed_at: a.signed_at };
}

export function signIntentMapAttestation(map: IntentMapLike, signerSecret: Uint8Array, signedAt: number, suite?: SignerSuiteOpts): IntentMapAttestation {
  const bad = intentMapShapeError(map);
  if (bad) throw new Error(`signIntentMapAttestation: ${bad}`);
  if (!isInt(signedAt) || signedAt < 0) throw new Error('signIntentMapAttestation: signedAt must be a non-negative safe integer');
  const body = mapAttBody({ v: 1, map_digest: intentMapDigest(map), intent_ref: map.intent_ref, signer: b64u(publicKeyOf(signerSecret)), signed_at: signedAt });
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(signerSecret, suite), domainMessage(INTENT_MAP_SIG_DOMAIN, bindSuiteFields(body, suite?.alg, pqPk)));
  return { ...body, ...fields };
}

/** Verify a map attestation: well-formed, signature valid, and (when `map` is given) its digest and intent_ref match. */
export function verifyIntentMapAttestation(a: unknown, map?: unknown, opts: IntentVerifyOptions = {}): IntentVerdict {
  try {
    if (!isObj(a) || a.v !== 1) return { ok: false, reason: 'not an intent map attestation v1' };
    const at = a as unknown as IntentMapAttestation;
    if (decodeB64uStrict(at.map_digest, 32) === null) return { ok: false, reason: 'map_digest is not canonical base64url (32 bytes)' };
    if (at.intent_ref !== null && decodeB64uStrict(at.intent_ref, 32) === null) return { ok: false, reason: 'intent_ref must be null or canonical base64url (32 bytes)' };
    if (decodeB64uStrict(at.signer, 32) === null) return { ok: false, reason: 'signer is not canonical base64url (32 bytes)' };
    if (!isInt(at.signed_at) || at.signed_at < 0) return { ok: false, reason: 'signed_at must be a non-negative safe integer' };
    if (opts.expectedSigner !== undefined && at.signer !== opts.expectedSigner) return { ok: false, reason: 'signer mismatch' };
    const se = suiteFieldsError(at);
    if (se) return { ok: false, reason: se };
    if (map !== undefined) {
      const bad = intentMapShapeError(map);
      if (bad) return { ok: false, reason: bad };
      if (intentMapDigest(map) !== at.map_digest) return { ok: false, reason: 'map digest mismatch' };
      if ((map as IntentMapLike).intent_ref !== at.intent_ref) return { ok: false, reason: 'intent_ref mismatch' };
    }
    const msg = domainMessage(INTENT_MAP_SIG_DOMAIN, bindSuiteFields(mapAttBody(at), at.alg, at.pq_pk));
    if (!verifyPinnedSuite(at.alg, at.signer, at.pq_pk, msg, { sig: at.sig, pq_sig: at.pq_sig }, opts)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed intent map attestation: ${(e as Error).message}` };
  }
}

// ---- runtime observations (L5 trust ramp / drift) ----------------------------------------------------------

export type IntentObservationSource = 'runtime' | 'witness' | 'elicitation' | 'import';
export const INTENT_OBSERVATION_SOURCES: readonly IntentObservationSource[] = ['runtime', 'witness', 'elicitation', 'import'];

/**
 * A labelled outcome against a map (spec §8 "Runtime observation"): `y = 0` says the outcome should NOT have been
 * allowed (a divergence: it vetoes the cell on replay), `y = 1` confirms it. Signed by whoever observed it.
 */
export interface IntentObservation {
  v: 1;
  map_digest: string;
  verb: string;
  values: Record<string, number | string>;
  y: 0 | 1;
  source: IntentObservationSource;
  /** epoch ms */
  observed_at: number;
  /** Optional digest of the PCActn the observation is about (b64u 32). */
  pcactn_digest?: string;
  /** b64u Ed25519 identity of the observer. */
  signer: string;
}

export interface SignedIntentObservation extends IntentObservation {
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

function obsBody(o: IntentObservation): IntentObservation {
  return plain({
    v: o.v,
    map_digest: o.map_digest,
    verb: o.verb,
    values: o.values,
    y: o.y,
    source: o.source,
    observed_at: o.observed_at,
    ...(o.pcactn_digest !== undefined ? { pcactn_digest: o.pcactn_digest } : {}),
    signer: o.signer,
  });
}

function obsShapeError(o: unknown): string | null {
  if (!isObj(o) || o.v !== 1) return 'not an intent observation v1';
  if (decodeB64uStrict(o.map_digest, 32) === null) return 'map_digest is not canonical base64url (32 bytes)';
  if (typeof o.verb !== 'string' || o.verb.length === 0) return 'verb must be a non-empty string';
  if (!isObj(o.values) || !Object.values(o.values).every((x) => typeof x === 'string' || (typeof x === 'number' && Number.isFinite(x)))) return 'values must map paths to numbers or strings';
  if (o.y !== 0 && o.y !== 1) return 'y must be 0 or 1';
  if (!INTENT_OBSERVATION_SOURCES.includes(o.source as IntentObservationSource)) return 'unknown observation source';
  if (!isInt(o.observed_at) || o.observed_at < 0) return 'observed_at must be a non-negative safe integer';
  if (o.pcactn_digest !== undefined && decodeB64uStrict(o.pcactn_digest, 32) === null) return 'pcactn_digest is not canonical base64url (32 bytes)';
  if (decodeB64uStrict(o.signer, 32) === null) return 'signer is not canonical base64url (32 bytes)';
  return null;
}

export function signIntentObservation(o: Omit<IntentObservation, 'v' | 'signer'>, signerSecret: Uint8Array, suite?: SignerSuiteOpts): SignedIntentObservation {
  const body = obsBody({ ...o, v: 1, signer: b64u(publicKeyOf(signerSecret)) });
  const bad = obsShapeError(body);
  if (bad) throw new Error(`signIntentObservation: ${bad}`);
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(signerSecret, suite), domainMessage(INTENT_OBS_SIG_DOMAIN, bindSuiteFields(body, suite?.alg, pqPk)));
  return { ...body, ...fields };
}

export function verifyIntentObservation(o: unknown, opts: IntentVerifyOptions = {}): IntentVerdict {
  try {
    const bad = obsShapeError(o);
    if (bad) return { ok: false, reason: bad };
    const ob = o as unknown as SignedIntentObservation;
    if (opts.expectedSigner !== undefined && ob.signer !== opts.expectedSigner) return { ok: false, reason: 'signer mismatch' };
    const se = suiteFieldsError(ob);
    if (se) return { ok: false, reason: se };
    const msg = domainMessage(INTENT_OBS_SIG_DOMAIN, bindSuiteFields(obsBody(ob), ob.alg, ob.pq_pk));
    if (!verifyPinnedSuite(ob.alg, ob.signer, ob.pq_pk, msg, { sig: ob.sig, pq_sig: ob.pq_sig }, opts)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed intent observation: ${(e as Error).message}` };
  }
}

// ---- ledger anchoring ---------------------------------------------------------------------------------------

/**
 * Every intent artifact a server stores is ANCHORED in an append-only transparency log (RFC 9162 Merkle tree, the
 * same construction as the PCActn ledger), one log per instance named {@link INTENT_ANCHOR_LOG}, whose heads the
 * instance guardian signs (`signTreeHead`, `principal` = the log name). A leaf commits to the artifact kind and its
 * content address, so a relying party holding a statement / map / observation can prove it was published, and an
 * operator cannot later swap it for a different one under the same reference without forking the signed log.
 */
export const INTENT_ANCHOR_DOMAIN = 'atlas-pca/intent-anchor/v1';
export const INTENT_ANCHOR_LOG = 'pca-intent:v1';
/** v2 kinds: `schema` (site action schemas, §3.2), `session` (session roots), `delta` (delta grants), `receipt`
 *  (accumulator reservation receipts, §3.1), `profile` (intent profile versions, §3.9), `evidence` (dispute evidence
 *  bundles, §3.11). */
export type IntentAnchorKind = 'statement' | 'map' | 'observation' | 'schema' | 'session' | 'delta' | 'receipt' | 'profile' | 'evidence';
export const INTENT_ANCHOR_KINDS: readonly IntentAnchorKind[] = ['statement', 'map', 'observation', 'schema', 'session', 'delta', 'receipt', 'profile', 'evidence'];

/** The log leaf for an anchored artifact: H({d, kind, digest}). */
export function intentAnchorCommit(kind: IntentAnchorKind, digest: string): string {
  return hashCanonical({ d: INTENT_ANCHOR_DOMAIN, kind, digest });
}

/** An anchoring receipt: where the artifact sits in the log, under which signed head. */
export interface IntentAnchorReceipt {
  kind: IntentAnchorKind;
  digest: string;
  index: number;
  proof: InclusionProof;
  signed_tree_head: SignedTreeHead;
}

/**
 * Verify a receipt: the head is signed by `guardianPublic` for the intent log of `instanceId`, and the artifact's leaf
 * is included at `index` under the head's root and size. Never throws.
 */
export function verifyIntentAnchor(r: IntentAnchorReceipt, guardianPublic: string, instanceId: string, pin?: PqPinPolicy): IntentVerdict {
  try {
    if (!INTENT_ANCHOR_KINDS.includes(r.kind)) return { ok: false, reason: 'unknown anchor kind' };
    if (decodeB64uStrict(r.digest, 32) === null) return { ok: false, reason: 'digest is not canonical base64url (32 bytes)' };
    const h = r.signed_tree_head;
    if (h.principal !== INTENT_ANCHOR_LOG || h.instance_id !== instanceId) return { ok: false, reason: 'not a head of this instance intent log' };
    if (!verifyTreeHead(h, guardianPublic, undefined, pin)) return { ok: false, reason: 'tree head signature invalid' };
    if (r.proof.index !== r.index || r.proof.size !== h.size) return { ok: false, reason: 'proof does not match the head' };
    if (!verifyLedgerInclusion(h.root, r.proof, intentAnchorCommit(r.kind, r.digest))) return { ok: false, reason: 'artifact is not included under the signed head' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed anchor receipt: ${(e as Error).message}` };
  }
}
