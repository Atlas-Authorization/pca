/**
 * @atlasauth/pca-agentcard — signed agent card + AgentFacts attestor for PCA.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  The fix for the spoofable self-declared agent card: PCA becomes the THIRD-PARTY ATTESTOR whose  │
 * │  card + AgentFacts point at LIVE, VERIFIABLE proof-of-authority instead of a self-assertion.     │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * The agent-discovery world today has two surfaces that both separate "what an agent says about
 * itself" from "what a third party will vouch for":
 *
 *   • A2A 1.0 Agent Cards (`/.well-known/agent-card.json`) carry an `AgentCardSignature` — a JWS over
 *     the canonicalized card — so a consumer can tell a signed card from an unsigned, forgeable one.
 *   • NANDA AgentFacts is a metadata document that explicitly splits SELF-ASSERTED claims from
 *     third-party ATTESTATIONS (each a signed statement by a named attestor, with a validity window).
 *
 * Both schemes answer "is this card authentic?" — they do NOT answer "does this agent actually hold
 * the authority it advertises?". That is exactly PCA's job. This package makes PCA the third-party
 * attestor: it signs the agent's AgentFacts attestation block, and it builds a signed Agent Card whose
 * metadata points at the agent's PCA passport AND a live proof-verification endpoint, so a relying party
 * resolves verifiable proof-of-authority (a PCActn) instead of trusting the card's word.
 *
 * WIRE COMPATIBILITY. The Signed-Agent-Card surface here is byte-identical to the one in
 * `@atlasauth/pca-a2a` (A2A 1.0 `AgentCardSignature`): the SAME canonical signing bytes (the card minus
 * its `signatures`), the SAME detached-payload JWS (`b64:false`, `crit:['b64']`), the SAME `pca_passport`
 * protected-header commitment, and the SAME `signatures[]` shape. A card issued here verifies under
 * `@atlasauth/pca-a2a`'s `verifyAgentCard` and vice-versa — this module does not define a divergent
 * scheme, it hosts the A2A card signer and layers AgentFacts + the attestor + the well-known hosting on
 * top. (It builds only on `@atlasauth/pca` and `jose`, the same two primitives that card signer uses.)
 *
 * Everything here FAILS CLOSED: a missing signature, an unresolvable key, a tampered body, a bad/expired
 * attestation, or an attestation about a different subject is rejected — never silently trusted.
 */

import { type AgentPassport, canonicalBytes } from '@atlasauth/pca';
import {
  FlattenedSign,
  createLocalJWKSet,
  flattenedVerify,
  importJWK,
  type FlattenedJWSInput,
  type JSONWebKeySet,
  type JWK,
  type KeyLike,
} from 'jose';

// ===================================================================================================
// Keys + detached-JWS core (the A2A AgentCardSignature signing primitive, shared by card + facts)
// ===================================================================================================

/** A key usable to sign. A plain JWK is imported for the given alg; other forms are passed through. */
export type SignKeyInput = KeyLike | Uint8Array | JWK;
/** A key usable to verify. A plain JWK is imported for the given alg; other forms are passed through. */
export type VerifyKeyInput = KeyLike | Uint8Array | JWK;

/** Default JWS algorithm for card + attestation signatures. */
export const DEFAULT_ALG = 'EdDSA' as const;

/**
 * A detached-payload JWS, per A2A 1.0's `AgentCardSignature`: `protected` is the base64url JWS protected
 * header, `signature` the base64url signature. The payload is NOT carried (it is recomputed — the
 * canonical bytes of the thing being signed — on verify). Reused verbatim for AgentFacts attestations.
 */
export interface AgentCardSignature {
  protected: string;
  signature: string;
  header?: Record<string, unknown>;
}

function isJwk(k: VerifyKeyInput): k is JWK {
  return typeof k === 'object' && k !== null && !(k instanceof Uint8Array) && 'kty' in k;
}

interface SignDetachedOptions {
  alg?: string;
  kid?: string;
  /** Extra protected-header members covered by the signature (e.g. the `pca_passport` commitment). */
  header?: Record<string, unknown>;
}

/** Produce a detached-payload JWS over `payload` (the canonical bytes of the signed object). */
async function signDetached(
  payload: Uint8Array,
  signingKey: SignKeyInput,
  opts: SignDetachedOptions,
): Promise<AgentCardSignature> {
  const alg = opts.alg ?? DEFAULT_ALG;
  const key: KeyLike | Uint8Array = isJwk(signingKey) ? await importJWK(signingKey, alg) : signingKey;
  const protectedHeader: Record<string, unknown> = {
    alg,
    b64: false,
    crit: ['b64'],
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    ...(opts.header ?? {}),
  };
  const jws = await new FlattenedSign(payload).setProtectedHeader(protectedHeader).sign(key);
  if (jws.protected === undefined) {
    throw new Error('signDetached: produced JWS is missing its protected header');
  }
  return { protected: jws.protected, signature: jws.signature };
}

type KeyResolver = KeyLike | Uint8Array | ReturnType<typeof createLocalJWKSet>;

/** Options shared by the verify surfaces: either a JWKS (kid-resolved) or a single key. */
export interface VerifyKeyOptions {
  /** A JWKS to resolve the signing key from (matched by the JWS `kid` / `alg`). */
  jwks?: JSONWebKeySet;
  /** A single verification key (JWK, raw secret, or a crypto key). */
  key?: VerifyKeyInput;
  /** Expected JWS algorithm for `importJWK` of a plain JWK `key` (default `'EdDSA'`). */
  alg?: string;
}

type ResolveOutcome = { resolver: KeyResolver } | { error: string };

async function resolveVerifyKey(opts: VerifyKeyOptions): Promise<ResolveOutcome> {
  try {
    if (opts.jwks) return { resolver: createLocalJWKSet(opts.jwks) };
    if (opts.key !== undefined) {
      return { resolver: isJwk(opts.key) ? await importJWK(opts.key, opts.alg ?? DEFAULT_ALG) : opts.key };
    }
    return { error: 'no verification key or JWKS supplied' };
  } catch (e) {
    return { error: `could not resolve verification key: ${(e as Error).message}` };
  }
}

type VerifyDetachedResult =
  | { ok: true; protectedHeader: Record<string, unknown> }
  | { ok: false; reason: string };

/** Verify a detached-payload JWS over `payload`. Never throws; returns a fail-closed result. */
async function verifyDetached(
  payload: Uint8Array,
  sig: AgentCardSignature,
  resolver: KeyResolver,
): Promise<VerifyDetachedResult> {
  if (typeof sig.protected !== 'string' || typeof sig.signature !== 'string') {
    return { ok: false, reason: 'signature is malformed' };
  }
  const input: FlattenedJWSInput = { protected: sig.protected, payload, signature: sig.signature };
  try {
    // Split so each branch binds a single flattenedVerify overload (key-resolver vs. concrete key).
    const verified =
      typeof resolver === 'function'
        ? await flattenedVerify(input, resolver)
        : await flattenedVerify(input, resolver);
    return { ok: true, protectedHeader: verified.protectedHeader ?? {} };
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
}

// ===================================================================================================
// Passport reference + proof pointer
// ===================================================================================================

/** A reference to the agent's PCA passport (see `@atlasauth/pca` `AgentPassport`). */
export interface PassportRef {
  /** The content-addressed passport id (`AgentPassport.id`). */
  id: string;
  /** Optional URL where the full, verifiable passport can be resolved. */
  uri?: string;
}

/**
 * A live proof-of-authority pointer embedded in the signed card. This is what turns the card from a
 * self-declaration into a pointer at verifiable authority: a relying party presents the agent's PCA
 * proof (a PCActn) to `verificationEndpoint` and only trusts the agent once that proof verifies.
 */
export interface PcaProofRef {
  /** The HTTP endpoint that verifies a presented PCA proof (PCActn) for this agent. */
  verificationEndpoint: string;
  /** Optional reference/digest of a representative or most-recent proof. */
  proofRef?: string;
  /** The resource server / Atlas instance id the agent's proofs are audience-bound to. */
  aud?: string;
}

const PCA_PASSPORT_HEADER = 'pca_passport';

function passportRefFrom(p: AgentPassport | PassportRef, uri?: string): PassportRef {
  if ('model_id' in p) return { id: p.id, ...(uri !== undefined ? { uri } : {}) };
  return { id: p.id, ...(p.uri !== undefined ? { uri: p.uri } : uri !== undefined ? { uri } : {}) };
}

// ===================================================================================================
// 1. Signed Agent Card (A2A 1.0) — build + sign + verify
// ===================================================================================================

/** An A2A Agent Card skill entry. Structural only; real cards carry more fields, all preserved + signed. */
export interface AgentSkill {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  [k: string]: unknown;
}

/** A minimal, permissive A2A Agent Card. Real cards carry many more fields; all are preserved + signed. */
export interface AgentCard {
  name: string;
  description?: string;
  url?: string;
  version?: string;
  skills?: AgentSkill[];
  /** The PCA passport this card's authority is rooted in (embedded + covered by the signature). */
  pcaPassport?: PassportRef;
  /** The live proof-verification pointer (embedded + covered by the signature). */
  pcaProof?: PcaProofRef;
  signatures?: AgentCardSignature[];
  [k: string]: unknown;
}

export interface BuildAgentCardOptions {
  /** The agent's human name (A2A `name`). */
  name: string;
  /** The agent's advertised skills. */
  skills?: AgentSkill[];
  /** The agent's A2A service URL. */
  url?: string;
  description?: string;
  version?: string;
  /** Where/whether the full passport can be resolved (becomes `pcaPassport.uri`). */
  passportUri?: string;
  /** The live proof-of-authority pointer embedded in the card. */
  pcaProofRef?: PcaProofRef;
}

/**
 * Build an (unsigned) A2A Agent Card from a PCA passport. The card's metadata points at the PCA passport
 * (`pcaPassport`) and, when given, the live proof-verification endpoint (`pcaProof`) — so once signed it
 * is a pointer at verifiable authority rather than a self-declaration. Sign it with {@link issueSignedAgentCard}.
 */
export function buildAgentCard(passport: AgentPassport, opts: BuildAgentCardOptions): AgentCard {
  const card: AgentCard = {
    name: opts.name,
    ...(opts.description !== undefined ? { description: opts.description } : {}),
    ...(opts.url !== undefined ? { url: opts.url } : {}),
    ...(opts.version !== undefined ? { version: opts.version } : {}),
    ...(opts.skills !== undefined ? { skills: opts.skills } : {}),
    pcaPassport: passportRefFrom(passport, opts.passportUri),
    ...(opts.pcaProofRef !== undefined ? { pcaProof: opts.pcaProofRef } : {}),
  };
  return card;
}

/** The canonical bytes a card signature covers: the card with `signatures` removed (everything else kept). */
function cardSigningBytes(card: AgentCard): Uint8Array {
  const { signatures: _signatures, ...rest } = card;
  void _signatures;
  return canonicalBytes(rest);
}

export interface IssueAgentCardOptions {
  /** JWS algorithm for the signature. Default `'EdDSA'`. */
  alg?: string;
  /** A passport reference to embed if the card does not already carry one. */
  passport?: PassportRef | { id: string };
  /** Optional JWS `kid` (set it when verifiers resolve the key from a JWKS). */
  kid?: string;
}

/**
 * Sign an A2A Agent Card. Ensures a PCA passport reference is embedded (`pcaPassport`) and committed in
 * the JWS protected header (`pca_passport`), then signs the canonicalized card (minus `signatures`) and
 * appends the detached-payload `AgentCardSignature`. Wire-identical to `@atlasauth/pca-a2a`.
 */
export async function issueSignedAgentCard(
  card: AgentCard,
  signingKey: SignKeyInput,
  opts: IssueAgentCardOptions = {},
): Promise<AgentCard> {
  const passport: PassportRef | undefined = opts.passport
    ? {
        id: opts.passport.id,
        ...('uri' in opts.passport && opts.passport.uri !== undefined ? { uri: opts.passport.uri } : {}),
      }
    : card.pcaPassport;

  // Embed the passport reference BEFORE signing so the signature covers it.
  const toSign: AgentCard = { ...card, ...(passport ? { pcaPassport: passport } : {}) };
  const payload = cardSigningBytes(toSign);

  const signature = await signDetached(payload, signingKey, {
    ...(opts.alg !== undefined ? { alg: opts.alg } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    ...(passport ? { header: { [PCA_PASSPORT_HEADER]: passport.id } } : {}),
  });

  const existing = toSign.signatures ?? [];
  return { ...toSign, signatures: [...existing, signature] };
}

/** The outcome of validating a signed Agent Card. */
export interface AgentCardVerification {
  ok: boolean;
  reason?: string;
  /** The passport id recovered from a verified signature's protected header (proof-of-authority pointer). */
  passportRef?: string;
  /** The passport reference embedded in the (verified) card body, when present. */
  passport?: PassportRef;
  /** The live proof pointer from the (verified) card body, when present. */
  pcaProof?: PcaProofRef;
}

/**
 * Validate an A2A Agent Card against its `AgentCardSignature`(s). Fail-closed: a card with no signatures,
 * an unresolvable key, or ANY signature that does not verify over the canonicalized card (minus
 * `signatures`) is rejected. On success, returns the PCA passport id the signature commits to plus the
 * live proof pointer, so a caller can resolve + check them against a `PassportRegistry` / verify endpoint.
 */
export async function verifyAgentCard(
  card: AgentCard,
  opts: VerifyKeyOptions,
): Promise<AgentCardVerification> {
  const signatures = card.signatures;
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return { ok: false, reason: 'agent card carries no signatures' };
  }

  const resolved = await resolveVerifyKey(opts);
  if ('error' in resolved) return { ok: false, reason: resolved.error };

  const payload = cardSigningBytes(card);
  let passportRef: string | undefined;

  for (let i = 0; i < signatures.length; i++) {
    const sig = signatures[i];
    if (!sig) return { ok: false, reason: `signature ${i} is missing` };
    const res = await verifyDetached(payload, sig, resolved.resolver);
    if (!res.ok) return { ok: false, reason: `signature ${i} did not verify: ${res.reason}` };
    const ref = res.protectedHeader[PCA_PASSPORT_HEADER];
    if (typeof ref === 'string' && passportRef === undefined) passportRef = ref;
  }

  return {
    ok: true,
    ...(passportRef !== undefined ? { passportRef } : {}),
    ...(card.pcaPassport ? { passport: card.pcaPassport } : {}),
    ...(card.pcaProof ? { pcaProof: card.pcaProof } : {}),
  };
}

// ===================================================================================================
// 2. AgentFacts — self-asserted vs third-party-attested claims (PCA is the attestor)
// ===================================================================================================

/**
 * JSON-LD contexts for an AgentFacts document. The DID context plus the AgentFacts vocabulary (the second
 * entry is a placeholder for the canonical NANDA AgentFacts context URL — replace before production).
 */
export const AGENT_FACTS_CONTEXT: readonly string[] = [
  'https://www.w3.org/ns/did/v1',
  'https://nanda.ai/agentfacts/v1',
];

/**
 * One third-party attestation inside an AgentFacts doc: a NAMED attestor (`issuer`) vouches, over a
 * signature, for a set of claims (`attests`) ABOUT a subject (`subject`) within a validity window. PCA
 * is the issuer; the signature is a detached JWS over the canonical statement (see {@link issueAgentFacts}).
 */
export interface AgentFactsAttestation {
  /** The attestor's identifier (e.g. a DID). PCA's attestor id when PCA signs it. */
  issuer: string;
  /** The agent this statement is ABOUT — MUST equal the enclosing doc's `id` (checked on verify). */
  subject: string;
  /** The claims this attestor vouches for (third-party-verified, as opposed to self-asserted). */
  attests: Record<string, unknown>;
  /** Validity window start (ISO 8601). */
  validFrom: string;
  /** Validity window end (ISO 8601), if the attestation expires. */
  validUntil?: string;
  /** Detached JWS over the canonicalized statement (issuer + subject + attests + validity). */
  signature: AgentCardSignature;
}

/**
 * An AgentFacts document: the agent's id (DID / passport ref), its SELF-ASSERTED claims (unverified — the
 * agent's own word), and a list of third-party ATTESTATIONS, each a signed statement. The split is the
 * whole point: a relying party can tell what the agent merely claims from what a named attestor vouches for.
 */
export interface AgentFacts {
  '@context': readonly string[];
  /** The agent's DID / passport reference. */
  id: string;
  type: 'AgentFacts';
  /** Claims the agent declares about itself — NOT verified; trust at your own risk. */
  selfAsserted: Record<string, unknown>;
  /** Third-party attestations, each independently verifiable + fail-closed. */
  attestations: AgentFactsAttestation[];
}

/** The canonical statement bytes an AgentFacts attestation signature covers (everything but the sig). */
function attestationStatementBytes(a: Omit<AgentFactsAttestation, 'signature'>): Uint8Array {
  return canonicalBytes({
    d: 'atlas-pca/agentfacts/attestation/v1',
    issuer: a.issuer,
    subject: a.subject,
    attests: a.attests,
    validFrom: a.validFrom,
    validUntil: a.validUntil ?? null,
  });
}

/** Default attestor identity used when PCA signs an AgentFacts attestation. */
export const PCA_ATTESTOR_ID = 'did:atlas:pca-attestor' as const;

export interface IssueAgentFactsOptions {
  /** The agent's self-declared claims (echoed verbatim; never signed). */
  selfAsserted?: Record<string, unknown>;
  /** The PCA attestor's signing key. */
  attestorKey: SignKeyInput;
  /** The claims PCA (the third party) vouches for about this agent. */
  attests: Record<string, unknown>;
  /** The attestor identifier recorded on the attestation. Default {@link PCA_ATTESTOR_ID}. */
  attestorId?: string;
  /** Override the agent id / DID (default: the passport id). */
  agentId?: string;
  /** JWS algorithm. Default `'EdDSA'`. */
  alg?: string;
  /** Optional JWS `kid` so a JWKS verifier can resolve the attestor key. */
  kid?: string;
  /** Validity window start (ISO). Default: now. */
  validFrom?: string;
  /** Validity window end (ISO). */
  validUntil?: string;
  /** Clock for the default `validFrom` (epoch ms). Default `Date.now()`. */
  now?: number;
  /** Override the JSON-LD `@context`. */
  context?: readonly string[];
}

/** Sign one attestation statement with the attestor key (shared by issue + add). */
async function signAttestation(
  statement: Omit<AgentFactsAttestation, 'signature'>,
  key: SignKeyInput,
  opts: { alg?: string; kid?: string },
): Promise<AgentFactsAttestation> {
  const signature = await signDetached(attestationStatementBytes(statement), key, {
    ...(opts.alg !== undefined ? { alg: opts.alg } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    header: { attestor: statement.issuer },
  });
  return { ...statement, signature };
}

/**
 * Issue an AgentFacts document for a PCA passport, with PCA as the THIRD-PARTY ATTESTOR. The agent's own
 * `selfAsserted` claims are carried verbatim and left unsigned; the `attests` claims are wrapped in a
 * statement (issuer + subject + validity) and signed with `attestorKey`. A verifier can then tell exactly
 * which claims a named third party vouches for. The resulting doc is served at `/.well-known/agent-facts.json`.
 */
export async function issueAgentFacts(
  passport: AgentPassport,
  opts: IssueAgentFactsOptions,
): Promise<AgentFacts> {
  const agentId = opts.agentId ?? passport.id;
  const validFrom = opts.validFrom ?? new Date(opts.now ?? Date.now()).toISOString();
  const statement: Omit<AgentFactsAttestation, 'signature'> = {
    issuer: opts.attestorId ?? PCA_ATTESTOR_ID,
    subject: agentId,
    attests: opts.attests,
    validFrom,
    ...(opts.validUntil !== undefined ? { validUntil: opts.validUntil } : {}),
  };
  const attestation = await signAttestation(statement, opts.attestorKey, {
    ...(opts.alg !== undefined ? { alg: opts.alg } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
  });
  return {
    '@context': opts.context ?? AGENT_FACTS_CONTEXT,
    id: agentId,
    type: 'AgentFacts',
    selfAsserted: opts.selfAsserted ?? {},
    attestations: [attestation],
  };
}

export interface AddAttestationOptions {
  attestorKey: SignKeyInput;
  attests: Record<string, unknown>;
  attestorId?: string;
  alg?: string;
  kid?: string;
  validFrom?: string;
  validUntil?: string;
  now?: number;
}

/**
 * Append another third-party attestation to an existing AgentFacts doc (returns a copy; input unmutated).
 * Lets several independent attestors each vouch for a different subset of claims.
 */
export async function addAttestation(facts: AgentFacts, opts: AddAttestationOptions): Promise<AgentFacts> {
  const validFrom = opts.validFrom ?? new Date(opts.now ?? Date.now()).toISOString();
  const statement: Omit<AgentFactsAttestation, 'signature'> = {
    issuer: opts.attestorId ?? PCA_ATTESTOR_ID,
    subject: facts.id,
    attests: opts.attests,
    validFrom,
    ...(opts.validUntil !== undefined ? { validUntil: opts.validUntil } : {}),
  };
  const attestation = await signAttestation(statement, opts.attestorKey, {
    ...(opts.alg !== undefined ? { alg: opts.alg } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
  });
  return { ...facts, attestations: [...facts.attestations, attestation] };
}

/** Per-attestation verification outcome. */
export interface AttestationCheck {
  issuer: string;
  ok: boolean;
  reason?: string;
  /** The attested claims (present only when this attestation verified). */
  attests?: Record<string, unknown>;
}

/** Whether a claim in the resolved view is third-party attested or merely self-asserted. */
export type ClaimProvenance = 'attested' | 'self-asserted';

/** The outcome of verifying an AgentFacts document. */
export interface AgentFactsVerification {
  ok: boolean;
  reason?: string;
  agentId: string;
  /** One entry per attestation in the doc, in order. */
  attestations: AttestationCheck[];
  /** The union of claims from every VERIFIED attestation (third-party backed). */
  attested: Record<string, unknown>;
  /** The agent's self-declared claims, echoed (unverified — flagged as self-asserted). */
  selfAsserted: Record<string, unknown>;
  /** Provenance of every claim name seen across self-asserted + attested (attested wins on overlap). */
  claims: Record<string, ClaimProvenance>;
}

export interface VerifyAgentFactsOptions extends VerifyKeyOptions {
  /** Verification clock for the attestations' validity windows (epoch ms). Default `Date.now()`. */
  now?: number;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Verify an AgentFacts document. Fail-closed throughout:
 *   • an attestation whose `subject` is not this doc's `id` is rejected;
 *   • an attestation outside its validity window (or with a malformed window) is rejected;
 *   • an attestation whose detached JWS does not verify under the supplied key/JWKS is rejected;
 *   • if ANY present attestation fails, the whole document verification returns `ok:false`.
 * On success, the result marks which claims are third-party ATTESTED and which are merely SELF-ASSERTED
 * (flagged, never promoted). A doc with zero attestations verifies, but attests nothing.
 */
export async function verifyAgentFacts(
  facts: AgentFacts,
  opts: VerifyAgentFactsOptions,
): Promise<AgentFactsVerification> {
  const selfAsserted = isPlainObject(facts.selfAsserted) ? facts.selfAsserted : {};
  const now = opts.now ?? Date.now();

  const base: AgentFactsVerification = {
    ok: false,
    agentId: facts.id,
    attestations: [],
    attested: {},
    selfAsserted,
    claims: {},
  };

  const list = facts.attestations;
  if (!Array.isArray(list)) {
    return { ...base, reason: 'agent facts has no attestations array' };
  }

  // Resolve the key once, but only insist on one when there is an attestation to verify.
  let resolver: KeyResolver | undefined;
  if (list.length > 0) {
    const resolved = await resolveVerifyKey(opts);
    if ('error' in resolved) {
      return { ...base, reason: resolved.error, attestations: list.map(mkMissingCheck) };
    }
    resolver = resolved.resolver;
  }

  const checks: AttestationCheck[] = [];
  const attested: Record<string, unknown> = {};
  let allOk = true;

  for (const a of list) {
    const check = await verifyOneAttestation(a, facts.id, now, resolver);
    checks.push(check);
    if (!check.ok) {
      allOk = false;
      continue;
    }
    if (check.attests) for (const [k, v] of Object.entries(check.attests)) attested[k] = v;
  }

  const claims: Record<string, ClaimProvenance> = {};
  for (const k of Object.keys(selfAsserted)) claims[k] = 'self-asserted';
  for (const k of Object.keys(attested)) claims[k] = 'attested'; // attested wins on overlap

  return {
    ok: allOk,
    ...(allOk ? {} : { reason: 'one or more attestations did not verify' }),
    agentId: facts.id,
    attestations: checks,
    attested,
    selfAsserted,
    claims,
  };
}

function mkMissingCheck(a: AgentFactsAttestation): AttestationCheck {
  const issuer = a && typeof a.issuer === 'string' ? a.issuer : '<unknown>';
  return { issuer, ok: false, reason: 'no verification key or JWKS supplied' };
}

async function verifyOneAttestation(
  a: AgentFactsAttestation,
  docId: string,
  now: number,
  resolver: KeyResolver | undefined,
): Promise<AttestationCheck> {
  const issuer = a && typeof a.issuer === 'string' ? a.issuer : '<unknown>';
  if (!a || typeof a.subject !== 'string' || !isPlainObject(a.attests) || typeof a.validFrom !== 'string') {
    return { issuer, ok: false, reason: 'attestation is malformed' };
  }
  if (a.subject !== docId) {
    return { issuer, ok: false, reason: `attestation subject '${a.subject}' does not match agent id '${docId}'` };
  }

  const from = Date.parse(a.validFrom);
  if (!Number.isFinite(from)) return { issuer, ok: false, reason: 'attestation validFrom is not a valid date' };
  if (now < from) return { issuer, ok: false, reason: 'attestation is not yet valid' };
  if (a.validUntil !== undefined) {
    const until = Date.parse(a.validUntil);
    if (!Number.isFinite(until)) return { issuer, ok: false, reason: 'attestation validUntil is not a valid date' };
    if (now > until) return { issuer, ok: false, reason: 'attestation has expired' };
  }

  if (!resolver) return { issuer, ok: false, reason: 'no verification key or JWKS supplied' };

  const statement: Omit<AgentFactsAttestation, 'signature'> = {
    issuer: a.issuer,
    subject: a.subject,
    attests: a.attests,
    validFrom: a.validFrom,
    ...(a.validUntil !== undefined ? { validUntil: a.validUntil } : {}),
  };
  const res = await verifyDetached(attestationStatementBytes(statement), a.signature, resolver);
  if (!res.ok) return { issuer, ok: false, reason: `signature did not verify: ${res.reason}` };
  return { issuer, ok: true, attests: a.attests };
}

// ===================================================================================================
// 3. Well-known hosting layer (framework-agnostic)
// ===================================================================================================

/** The A2A well-known path a signed Agent Card is served at. */
export const WELL_KNOWN_AGENT_CARD_PATH = '/.well-known/agent-card.json' as const;
/** The well-known path an AgentFacts document is served at. */
export const WELL_KNOWN_AGENT_FACTS_PATH = '/.well-known/agent-facts.json' as const;

/** A minimal, framework-agnostic HTTP response the handlers emit. */
export interface HostedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * A path handler: given a request path, return the response for the resource it serves, or `undefined`
 * when the path is not this handler's — so it composes in a router (fall through to the next handler).
 */
export type PathHandler = (path: string) => HostedResponse | undefined;

function jsonResponse(value: unknown): HostedResponse {
  return {
    status: 200,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    body: JSON.stringify(value),
  };
}

function normalizePath(path: string): string {
  const q = path.indexOf('?');
  const noQuery = q === -1 ? path : path.slice(0, q);
  // Drop a single trailing slash (but keep the root "/").
  return noQuery.length > 1 && noQuery.endsWith('/') ? noQuery.slice(0, -1) : noQuery;
}

/** Serve a signed Agent Card at {@link WELL_KNOWN_AGENT_CARD_PATH}; `undefined` for any other path. */
export function agentCardHandler(card: AgentCard, path: string = WELL_KNOWN_AGENT_CARD_PATH): PathHandler {
  const target = normalizePath(path);
  const response = jsonResponse(card);
  return (reqPath: string): HostedResponse | undefined =>
    normalizePath(reqPath) === target ? response : undefined;
}

/** Serve an AgentFacts document at {@link WELL_KNOWN_AGENT_FACTS_PATH}; `undefined` for any other path. */
export function agentFactsHandler(facts: AgentFacts, path: string = WELL_KNOWN_AGENT_FACTS_PATH): PathHandler {
  const target = normalizePath(path);
  const response = jsonResponse(facts);
  return (reqPath: string): HostedResponse | undefined =>
    normalizePath(reqPath) === target ? response : undefined;
}

// ===================================================================================================
// 4. Registry publication (A2A registry / NANDA index) — structural
// ===================================================================================================

/**
 * A structural entry for publishing an agent to an A2A registry / NANDA index: the identity + discovery
 * fields a registry indexes, plus the signed card, the AgentFacts doc, and the derived split of which
 * advertised claim names are third-party ATTESTED vs merely SELF-ASSERTED (so an index can rank/flag them).
 */
export interface RegistryEntry {
  /** The agent id / DID (the AgentFacts `id`). */
  id: string;
  name: string;
  url?: string;
  version?: string;
  skills?: AgentSkill[];
  /** The PCA passport the card commits to. */
  passport?: PassportRef;
  /** The live proof-verification pointer. */
  pcaProof?: PcaProofRef;
  /** The signed Agent Card (verbatim). */
  card: AgentCard;
  /** The well-known URL the card is served at, derived from `card.url` when present. */
  agentCardUrl?: string;
  /** The AgentFacts document (verbatim). */
  facts: AgentFacts;
  /** Claim names a third party attests (union across attestations). */
  attestedClaims: string[];
  /** Claim names the agent only self-asserts (not covered by any attestation). */
  selfAssertedClaims: string[];
}

function wellKnownUrlFrom(serviceUrl: string | undefined, path: string): string | undefined {
  if (serviceUrl === undefined) return undefined;
  try {
    return new URL(path, serviceUrl).toString();
  } catch {
    return undefined;
  }
}

/**
 * Shape a {@link RegistryEntry} from a signed card + an AgentFacts doc for submission to an A2A registry /
 * NANDA index. Purely structural: it does NOT re-verify (a registry re-verifies on ingest) — it derives
 * the attested-vs-self-asserted claim split from the doc so the index can surface what a third party backs.
 */
export function toRegistryEntry(card: AgentCard, facts: AgentFacts): RegistryEntry {
  const attestedSet = new Set<string>();
  for (const a of facts.attestations ?? []) {
    if (a && isPlainObject(a.attests)) for (const k of Object.keys(a.attests)) attestedSet.add(k);
  }
  const selfAssertedOnly = Object.keys(isPlainObject(facts.selfAsserted) ? facts.selfAsserted : {}).filter(
    (k) => !attestedSet.has(k),
  );
  const agentCardUrl = wellKnownUrlFrom(card.url, WELL_KNOWN_AGENT_CARD_PATH);

  return {
    id: facts.id,
    name: card.name,
    ...(card.url !== undefined ? { url: card.url } : {}),
    ...(card.version !== undefined ? { version: card.version } : {}),
    ...(card.skills !== undefined ? { skills: card.skills } : {}),
    ...(card.pcaPassport ? { passport: card.pcaPassport } : {}),
    ...(card.pcaProof ? { pcaProof: card.pcaProof } : {}),
    card,
    ...(agentCardUrl !== undefined ? { agentCardUrl } : {}),
    facts,
    attestedClaims: [...attestedSet],
    selfAssertedClaims: selfAssertedOnly,
  };
}
