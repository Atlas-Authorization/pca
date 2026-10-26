/**
 * @atlasauth/pca-a2a — A2A (Agent2Agent) adapter for PCA.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  PCA GOVERNS. A2A is the agent-to-agent delegation + task wire. AP2 carries the payment mandate. │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * A2A (Agent2Agent — originated at Google, donated to the Linux Foundation; v1.0 GA Apr 2026) is the
 * open protocol for how autonomous agents discover one another (the Agent Card at
 * `/.well-known/agent-card.json`), hand each other work (Tasks carrying Messages), and settle payment
 * (the AP2 payment profile). A2A says HOW agents talk; it does not, on its own, prove that a request an
 * agent relays is actually AUTHORIZED by the principal behind it. That is exactly the gap PCA closes.
 *
 * This adapter binds PCA's proof-carrying authority onto A2A's three surfaces, FAIL-CLOSED throughout:
 *
 *   1. Proof-carrying A2A Tasks — a PCActn (a signed, single-action proof of authority with its
 *      attenuating capability chain) rides on a Task's metadata. A receiving agent re-verifies it before
 *      acting, so a relayed task cannot exceed what the principal actually delegated.
 *   2. Signed Agent Cards — an A2A Agent Card is validated against an `AgentCardSignature` (a JWS over
 *      the card, per A2A 1.0) via `jose`, and an issued card embeds a reference to the agent's PCA
 *      passport, so the card points at verifiable proof-of-authority instead of being a self-declaration.
 *   3. AP2 payment profile — a PCActn maps to an AP2 Payment Mandate whose authority is carried by
 *      reference to the proof (the mandate is PCA-verifiable: resolve the referenced PCActn and verify it).
 *
 * The full AP2 Intent→Cart→Payment VDC chain, its non-amplifying-narrowing verifier and the settlement
 * rails live in `@atlasauth/pca-ap2`; this module does NOT duplicate them. It emits only the single
 * Payment-Mandate profile an A2A payment Task needs, using the SAME field vocabulary (`amount`,
 * `payment_method`, `human_present`, `merchant`, namespaced `x_pca`) so the two stay wire-compatible.
 * When `@atlasauth/pca-ap2` is on the dependency path, prefer composing with its full chain + settlement
 * backends and treat this profile as the A2A-task envelope around a verified PCActn.
 */

import {
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PcaContext,
  type PcaVerdict,
  type SigAlg,
  type Signer,
  type VerifyHooks,
  DEFAULT_REQUIRED_CHECKS,
  canonicalBytes,
  createThresholdVerifier,
  hashCanonical,
  pcactnDigest,
  verifyPCActn,
} from '@atlasauth/pca';
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
import { assertCanonicalJwsSegments } from '@atlasauth/pca';

// ===================================================================================================
// Extension identifier
// ===================================================================================================

/**
 * The URI-namespaced A2A extension key a PCActn rides under on a Task's / Message's `metadata`. A2A
 * extensions are identified by URI and carried in `metadata`, so a non-PCA-aware peer simply ignores it.
 */
export const PCA_A2A_EXTENSION_URI = 'https://atlasauth.net/a2a/ext/pca/v2' as const;

// ===================================================================================================
// Minimal structural A2A object model (permissive — real peers carry many more fields)
// ===================================================================================================

/** An A2A message part (text / file / data). Structural only; `kind` discriminates in the wild. */
export interface A2APart {
  kind: string;
  [k: string]: unknown;
}

/** An A2A Message — a turn exchanged within a Task. */
export interface A2AMessage {
  role: 'user' | 'agent';
  parts: A2APart[];
  messageId?: string;
  kind?: 'message';
  taskId?: string;
  contextId?: string;
  metadata?: Record<string, unknown>;
}

/** An A2A Task status. */
export interface A2ATaskStatus {
  state: string;
  message?: A2AMessage;
  timestamp?: string;
}

/** An A2A Task — the unit of work one agent hands another. */
export interface A2ATask {
  id: string;
  contextId?: string;
  kind?: 'task';
  status: A2ATaskStatus;
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

// ===================================================================================================
// 1. Proof-carrying A2A Tasks
// ===================================================================================================

function withPca(metadata: Record<string, unknown> | undefined, pcActn: PCActn): Record<string, unknown> {
  return { ...(metadata ?? {}), [PCA_A2A_EXTENSION_URI]: pcActn };
}

/** Read a PCActn out of a metadata bag (fail-closed: a missing / non-object value yields `undefined`). */
function readPca(metadata: Record<string, unknown> | undefined): PCActn | undefined {
  if (!metadata) return undefined;
  const v = metadata[PCA_A2A_EXTENSION_URI];
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) return v as PCActn;
  return undefined;
}

/** Attach a PCActn to a Task (returns a copy; the input is not mutated). */
export function attachPcaToA2ATask(task: A2ATask, pcActn: PCActn): A2ATask {
  return { ...task, metadata: withPca(task.metadata, pcActn) };
}

/** Attach a PCActn to a single Message (returns a copy; the input is not mutated). */
export function attachPcaToA2AMessage(message: A2AMessage, pcActn: PCActn): A2AMessage {
  return { ...message, metadata: withPca(message.metadata, pcActn) };
}

/**
 * Extract the PCActn carried on a Task. Looks, in order, at the Task metadata, the current
 * `status.message` metadata, then the most recent history message's metadata. Returns `undefined`
 * when no well-formed proof is present (the verify step then fails closed).
 */
export function extractPca(task: A2ATask): PCActn | undefined {
  // Total over hostile shapes: a missing `status` used to throw, and a non-array `history` with a large own `length`
  // (`{"length": 1e9}`) was walked index by index.
  if (task === null || task === undefined) return undefined;
  const onTask = readPca(task.metadata);
  if (onTask) return onTask;
  const status: unknown = task.status;
  const onStatus = status !== null && typeof status === 'object' ? readPca((status as A2ATaskStatus).message?.metadata) : undefined;
  if (onStatus) return onStatus;
  const history: unknown = task.history;
  if (Array.isArray(history) && history.length > 0) {
    for (let i = history.length - 1; i >= 0; i--) {
      const m = history[i];
      const onMsg = readPca(m?.metadata);
      if (onMsg) return onMsg;
    }
  }
  return undefined;
}

/** Extract the PCActn carried on a single Message (fail-closed). */
export function extractPcaFromMessage(message: A2AMessage): PCActn | undefined {
  return message === null || message === undefined ? undefined : readPca(message.metadata);
}

/** Options shared by every PCActn verification surface in this module. */
export interface PcaVerifyOptions {
  /** This resource server / Atlas instance id. Compared against the PCActn's signed `aud` (fail-closed). */
  aud: string;
  /** Verification clock (epoch ms). Default `Date.now()`. */
  now?: number;
  /**
   * The grant from YOUR store (by the PCActn's grant_ref): the chain root must be byte-identical to it. One of `grant` /
   * `expectedRootIssuer` is REQUIRED ({@link A2AAuthorityError} otherwise): the chain alone proves nothing.
   */
  grant?: Capability;
  /**
   * The principal the chain must be rooted at (b64u). Without `grant`, the chain root is accepted only when its issuer is
   * this principal; an Ed25519 root is then self-authenticating, and a post-quantum / hybrid root also needs `pqPins`.
   */
  expectedRootIssuer?: string;
  /** Verifier-side `issuer -> pq_pk` pins (the `pq_pin` check). Required for a non-Ed25519 root accepted via `expectedRootIssuer`. */
  pqPins?: Readonly<Record<string, string>>;
  /** Signature suites accepted for the leaf and every hop (default: every registered suite with holder-bound PQ keys). */
  allowedSuites?: readonly SigAlg[];
  /** Verification hooks (revocation, threshold, attestation, ...) handed to `verifyPCActn`. */
  hooks?: VerifyHooks;
  /** The resource server's view of the action: params, its own plan + planAuthorized, budget, risk (static or per PCActn). */
  context?: PcaContext | ((pcActn: PCActn) => PcaContext | Promise<PcaContext>);
  /** Checks that must PASS (default-deny). Default `DEFAULT_REQUIRED_CHECKS`. */
  requireChecks?: readonly string[];
}

/** Thrown when an A2A verifier is configured without any authority (`grant` or `expectedRootIssuer`). */
export class A2AAuthorityError extends Error {
  readonly code = 'authority_required' as const;
  constructor() {
    super('pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority');
    this.name = 'A2AAuthorityError';
  }
}

function assertAuthority(opts: Partial<PcaVerifyOptions> | undefined): void {
  const hasGrant = !!opts && opts.grant !== undefined && opts.grant !== null && typeof opts.grant === 'object';
  const hasIssuer = !!opts && typeof opts.expectedRootIssuer === 'string' && opts.expectedRootIssuer.length > 0;
  if (!hasGrant && !hasIssuer) throw new A2AAuthorityError();
}

/** The result of verifying a proof-carrying A2A artifact. */
export interface A2AVerification {
  ok: boolean;
  reason?: string;
  /** The full verifier's verdict (present once a PCActn was found and evaluated); `reason` joins its reasons on a deny. */
  result?: PcaVerdict & { reason?: string };
  /** The extracted PCActn (present when one was carried). */
  pcActn?: PCActn;
}

function chainRoot(chain: CapabilityChain | undefined): Capability | undefined {
  if (!Array.isArray(chain) || chain.length === 0) return undefined;
  return chain[0];
}

/**
 * PCActn AUTHORIZATION shared by the Task and payment-mandate surfaces: the full server verifier (`verifyPCActn`) under a
 * known authority (the stored grant, or the chain root only when its issuer is the expected principal), with the grant's
 * predicates, limits, caveats, plan authorization, budget, threshold, allowedSuites and pqPins. Fail-closed.
 */
async function verifyPcActn(pcActn: PCActn, opts: PcaVerifyOptions): Promise<A2AVerification> {
  assertAuthority(opts);
  if (pcActn === null || typeof pcActn !== 'object') return { ok: false, reason: 'PCActn is not an object' };
  const root = chainRoot(pcActn.cap_chain);
  if (!root) return { ok: false, reason: 'PCActn carries no capability chain', pcActn };

  if (opts.expectedRootIssuer !== undefined && root.issuer !== opts.expectedRootIssuer) {
    return {
      ok: false,
      reason: 'chain root issuer does not match the expected principal',
      pcActn,
    };
  }

  // Without a stored grant, the root is admitted only under the pinned principal; a non-Ed25519 root then needs a PQ pin
  // (pqPins defaults to none, so the `pq_pin` check fails closed).
    // pca-unsafe-root: allow without a stored grant the root is admitted only when its issuer is the pinned expectedRootIssuer, and a non-Ed25519 root also needs pqPins (pq_pin, fail closed)
  const grant = opts.grant ?? root;
  const pqPins = opts.grant === undefined ? (opts.pqPins ?? {}) : opts.pqPins;
  const context = typeof opts.context === 'function' ? await opts.context(pcActn) : (opts.context ?? {});
  const verdict = await verifyPCActn(pcActn, {
    grant,
    audience: opts.aud,
    now: opts.now ?? Date.now(),
    context,
    ...(opts.hooks ? { hooks: opts.hooks } : {}),
    ...(opts.allowedSuites ? { allowedSuites: opts.allowedSuites } : {}),
    ...(pqPins ? { pqPins } : {}),
    require: [...(opts.requireChecks ?? DEFAULT_REQUIRED_CHECKS)],
  });
  const reason = verdict.allow ? undefined : verdict.reasons.join('; ') || 'PCActn verification failed';
  const result = { ...verdict, ...(reason !== undefined ? { reason } : {}) };
  return verdict.allow ? { ok: true, result, pcActn } : { ok: false, reason, result, pcActn };
}

/**
 * Verify the proof-carrying action on an A2A Task. Fail-closed: a Task with no attached PCActn, or one
 * whose PCActn does not verify (bad signature, wrong audience, expired, out-of-plan, tampered chain …),
 * is rejected.
 */
export async function verifyA2ATask(task: A2ATask, opts: PcaVerifyOptions): Promise<A2AVerification> {
  assertAuthority(opts);
  const pcActn = extractPca(task);
  if (!pcActn) return { ok: false, reason: 'no proof-carrying action attached to this task' };
  return verifyPcActn(pcActn, opts);
}

/** Configuration for the server-side A2A guard. */
export interface PcaA2AMiddlewareOptions extends PcaVerifyOptions {
  /**
   * When `true` (the default), a Task MUST carry a valid PCActn or it is rejected. When `false`, a Task
   * with NO proof is allowed through — but a Task that DOES carry a proof must still verify (a present
   * but invalid/tampered proof is always rejected; this guard never fails open on tampering).
   */
  require?: boolean;
}

/** The per-Task guard returned by {@link pcaA2AMiddleware}. */
export type PcaA2AGuard = (task: A2ATask) => Promise<A2AVerification>;

/**
 * Build a server guard that verifies the proof-carrying action on each incoming A2A Task and rejects
 * unauthorized ones. Framework-agnostic: wire the returned function into your JSON-RPC `message/send` /
 * `tasks/send` handler and reject when `ok` is false.
 */
export function pcaA2AMiddleware(opts: PcaA2AMiddlewareOptions): PcaA2AGuard {
  assertAuthority(opts);
  const require = opts.require ?? true;
  return async (task: A2ATask): Promise<A2AVerification> => {
    const pcActn = extractPca(task);
    if (!pcActn) {
      return require
        ? { ok: false, reason: 'proof-carrying action required but none attached to task' }
        : { ok: true };
    }
    return verifyPcActn(pcActn, opts);
  };
}

// ===================================================================================================
// 2. Signed Agent Cards (A2A 1.0 AgentCardSignature, JWS via jose)
// ===================================================================================================

/** A reference to the agent's PCA passport (see `@atlasauth/pca` `AgentPassport`). */
export interface A2APassportRef {
  /** The content-addressed passport id (`AgentPassport.id`). */
  id: string;
  /** Optional URL where the full, verifiable passport can be resolved. */
  uri?: string;
}

/**
 * An A2A Agent Card signature: a detached JWS (JWS JSON serialization) over the canonicalized card with
 * its `signatures` removed, per A2A 1.0. `protected` is the base64url JWS protected header; `signature`
 * is the base64url signature. The payload is detached (recomputed from the card on verify).
 */
export interface AgentCardSignature {
  protected: string;
  signature: string;
  header?: Record<string, unknown>;
}

/** A minimal, permissive A2A Agent Card. Real cards carry many more fields; all are preserved + signed. */
export interface AgentCard {
  name: string;
  description?: string;
  url?: string;
  version?: string;
  /** The PCA passport this card's authority is rooted in (embedded + signed by {@link issueSignedAgentCard}). */
  pcaPassport?: A2APassportRef;
  signatures?: AgentCardSignature[];
  [k: string]: unknown;
}

/** A key usable to verify a card signature. A plain JWK is imported; other forms are passed through. */
export type VerifyKeyInput = KeyLike | Uint8Array | JWK;
/** A key usable to sign a card. A plain JWK is imported; other forms are passed through. */
export type SignKeyInput = KeyLike | Uint8Array | JWK;

const PCA_PASSPORT_HEADER = 'pca_passport';

function isJwk(k: VerifyKeyInput): k is JWK {
  return typeof k === 'object' && k !== null && !(k instanceof Uint8Array) && 'kty' in k;
}

/** The canonical bytes a card signature covers: the card with `signatures` removed (everything else kept). */
function cardSigningBytes(card: AgentCard): Uint8Array {
  const { signatures: _signatures, ...rest } = card;
  void _signatures;
  return canonicalBytes(rest);
}

/** JWS payload member for `protectedB64`: raw bytes under `b64:false` (legacy detached profile), else the base64url text (A2A 1.0). */
function payloadFor(protectedB64: string, payload: Uint8Array): Uint8Array | string {
  try {
    const h = JSON.parse(Buffer.from(protectedB64, 'base64url').toString('utf8')) as { b64?: unknown };
    return h !== null && typeof h === 'object' && h.b64 === false ? payload : Buffer.from(payload).toString('base64url');
  } catch {
    return payload; // unparsable header: jose rejects it
  }
}

export interface IssueAgentCardOptions {
  /** JWS algorithm for the signature. Default `'EdDSA'`. */
  alg?: string;
  /** The PCA passport reference to embed so the card points at verifiable proof-of-authority. */
  passport?: A2APassportRef | { id: string };
  /** Optional JWS `kid` (set it when verifiers resolve the key from a JWKS). Required for the `'a2a-1.0'` profile. */
  kid?: string;
  /**
   * `'pca-detached'` (default, unchanged): unencoded detached payload (`b64:false`). `'a2a-1.0'`: the signing input
   * of A2A 1.0 section 8.4 (`BASE64URL(header) . BASE64URL(payload)`, header carries `alg`, `kid`, `typ:"JOSE"`), so
   * any A2A 1.0 verifier can check the card. Needs `kid` (the spec makes it mandatory) or it throws.
   */
  profile?: 'pca-detached' | 'a2a-1.0';
}

/**
 * Issue a signed A2A Agent Card. Embeds the PCA passport reference into the card (`pcaPassport`) AND into
 * the signed JWS protected header, then signs the canonicalized card (minus `signatures`) with `jose`,
 * appending the detached-payload `AgentCardSignature`. Because the passport reference is covered by the
 * signature, the card is a verifiable pointer to proof-of-authority — not a self-declaration.
 */
export async function issueSignedAgentCard(
  card: AgentCard,
  signingKey: SignKeyInput,
  opts: IssueAgentCardOptions = {},
): Promise<AgentCard> {
  const alg = opts.alg ?? 'EdDSA';
  const passport: A2APassportRef | undefined = opts.passport
    ? { id: opts.passport.id, ...('uri' in opts.passport && opts.passport.uri !== undefined ? { uri: opts.passport.uri } : {}) }
    : card.pcaPassport;

  // Embed the passport reference BEFORE signing so the signature covers it.
  const toSign: AgentCard = { ...card, ...(passport ? { pcaPassport: passport } : {}) };
  const payload = cardSigningBytes(toSign);

  const key: KeyLike | Uint8Array = isJwk(signingKey) ? await importJWK(signingKey, alg) : signingKey;
  if (opts.profile === 'a2a-1.0' && (typeof opts.kid !== 'string' || opts.kid.length === 0)) {
    throw new Error("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid");
  }
  const protectedHeader: Record<string, unknown> = {
    alg,
    ...(opts.profile === 'a2a-1.0' ? { typ: 'JOSE' } : { b64: false, crit: ['b64'] }),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    ...(passport ? { [PCA_PASSPORT_HEADER]: passport.id } : {}),
  };
  const jws = await new FlattenedSign(payload).setProtectedHeader(protectedHeader).sign(key);
  if (jws.protected === undefined) throw new Error('issueSignedAgentCard: JWS is missing its protected header');

  const signature: AgentCardSignature = { protected: jws.protected, signature: jws.signature };
  const existing = toSign.signatures ?? [];
  return { ...toSign, signatures: [...existing, signature] };
}

export interface VerifyAgentCardOptions {
  /** A JWKS to resolve the signing key from (matched by the JWS `kid` / `alg`). */
  jwks?: JSONWebKeySet;
  /** A single verification key (JWK, raw secret, or a crypto key). */
  key?: VerifyKeyInput;
  /** Expected JWS algorithm for `importJWK` of a plain JWK `key` (default `'EdDSA'`). */
  alg?: string;
}

/** The outcome of validating a signed Agent Card. */
export interface AgentCardVerification {
  ok: boolean;
  reason?: string;
  /** The passport id recovered from a verified signature's protected header (proof-of-authority pointer). */
  passportRef?: string;
  /** The passport reference embedded in the (verified) card body, when present. */
  passport?: A2APassportRef;
}

type KeyResolver = KeyLike | Uint8Array | ReturnType<typeof createLocalJWKSet>;

/**
 * Validate an A2A Agent Card against its `AgentCardSignature`(s). Fail-closed: a card with no signatures,
 * an unresolvable key, or ANY signature that does not verify is rejected. Every present signature must
 * verify over the canonicalized card (minus `signatures`). On success, returns the PCA passport id the
 * signature commits to so a caller can resolve + check it against a `PassportRegistry`.
 */
export async function verifyAgentCard(
  card: AgentCard,
  opts: VerifyAgentCardOptions,
): Promise<AgentCardVerification> {
  if (card === null || typeof card !== 'object') return { ok: false, reason: 'agent card is not an object' };
  const signatures = card.signatures;
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return { ok: false, reason: 'agent card carries no signatures' };
  }

  let resolver: KeyResolver;
  try {
    if (opts.jwks) {
      resolver = createLocalJWKSet(opts.jwks);
    } else if (opts.key !== undefined) {
      resolver = isJwk(opts.key) ? await importJWK(opts.key, opts.alg ?? 'EdDSA') : opts.key;
    } else {
      return { ok: false, reason: 'no verification key or JWKS supplied' };
    }
  } catch (e) {
    return { ok: false, reason: `could not resolve verification key: ${(e as Error).message}` };
  }

  // A card value with no strict canonical form (a float like 1e21, a lone surrogate, ...) is a refusal, not an exception.
  let payload: Uint8Array;
  try {
    payload = cardSigningBytes(card);
  } catch (e) {
    return { ok: false, reason: `agent card has no canonical form: ${(e as Error).message}` };
  }
  let passportRef: string | undefined;

  for (let i = 0; i < signatures.length; i++) {
    const sig = signatures[i];
    if (!sig || typeof sig.protected !== 'string' || typeof sig.signature !== 'string') {
      return { ok: false, reason: `signature ${i} is malformed` };
    }
    const input: FlattenedJWSInput = { protected: sig.protected, payload: payloadFor(sig.protected, payload) as never, signature: sig.signature };
    try {
      assertCanonicalJwsSegments(sig.protected, sig.signature); // canonical-spelling gate BEFORE jose
      // Split the call so each branch matches a single flattenedVerify overload (key vs. key-resolver).
      const verified =
        typeof resolver === 'function'
          ? await flattenedVerify(input, resolver)
          : await flattenedVerify(input, resolver);
      const ref = verified.protectedHeader?.[PCA_PASSPORT_HEADER];
      if (typeof ref === 'string' && passportRef === undefined) passportRef = ref;
    } catch (e) {
      return { ok: false, reason: `signature ${i} did not verify: ${(e as Error).message}` };
    }
  }

  return {
    ok: true,
    ...(passportRef !== undefined ? { passportRef } : {}),
    ...(card.pcaPassport ? { passport: card.pcaPassport } : {}),
  };
}

// ===================================================================================================
// 3. AP2 payment profile (the A2A payment-Task envelope — PCA-verifiable by reference)
// ===================================================================================================

/**
 * `@context` of the PCA payment-mandate envelope. This is a PCA-DEFINED envelope, NOT an AP2 credential:
 * AP2 mandates are SD-JWTs (see `@atlasauth/pca-ap2`) and AP2 publishes no JSON-LD context. The second entry is
 * an identifier this package chose and nobody resolves; do not treat the envelope as AP2 wire format.
 */
export const A2A_AP2_CONTEXT: readonly string[] = [
  'https://www.w3.org/2018/credentials/v1',
  'https://ap2-protocol.org/context/v0.2',
];

/** ISO-4217 currency + `value` in INTEGER MINOR UNITS (cents). Non-integer or unsafe values are refused (no float drift). */
export interface A2AMonetaryAmount {
  currency: string;
  value: number;
}

/** The payment instrument an AP2 Payment Mandate authorizes (never a raw PAN). */
export interface A2APaymentMethod {
  type: string;
  display?: string;
  token?: string;
}

/**
 * The PCA-native binding carried inside the Payment Mandate's `x_pca` extension. It makes the mandate
 * PCA-VERIFIABLE: a verifier resolves `pcactn_digest` to the referenced PCActn and verifies that proof,
 * rather than trusting the mandate on its own. NON-STANDARD by construction (namespaced `x_pca`).
 */
export interface PcaPaymentBinding {
  /** `pcactnDigest()` of the PCActn whose authority backs this mandate. */
  pcactn_digest: string;
  /** The resource server / instance the backing PCActn is audience-bound to. */
  aud: string;
  /** The backing action's verb / resource / params digest (from the PCActn's committed plan node). */
  verb: string;
  resource: string;
  params_digest: string;
  /** The grant the backing PCActn's chain is rooted at. */
  grant_ref: string;
  /** The acting (leaf) holder key, b64u — the agent the authority was ultimately delegated to. */
  leaf_holder: string;
}

/** AP2 Payment Mandate contents (credentialSubject). Mirrors `@atlasauth/pca-ap2`'s field vocabulary. */
export interface A2APaymentMandateContents {
  amount: A2AMonetaryAmount;
  payment_method: A2APaymentMethod;
  /**
   * The AP2 human-present modality. `true` only when the builder VERIFIED a principal co-signature
   * (`humanSignerSet`) or the caller asserted it explicitly (`humanPresent`). The mere presence of a `threshold`
   * field is never evidence: it sits outside the signed body (R2-03).
   */
  human_present: boolean;
  merchant?: string;
  /** The PCA-verifiable backreference (see {@link PcaPaymentBinding}). */
  x_pca: PcaPaymentBinding;
}

/** An AP2 Payment Mandate VDC carrying a PCA-verifiable backreference. */
export interface A2APaymentMandate {
  '@context': readonly string[];
  type: readonly ['VerifiableCredential', 'PaymentMandate'];
  /** Issuer (payer / acting agent) public key, b64u. Defaults to the PCActn's leaf holder. */
  issuer: string;
  issuanceDate: string;
  credentialSubject: A2APaymentMandateContents;
}

function leafHolderOf(chain: CapabilityChain | undefined): string | undefined {
  if (!Array.isArray(chain) || chain.length === 0) return undefined;
  const leaf = chain[chain.length - 1];
  return leaf?.holder;
}

function verifiedHumanPresent(pcActn: PCActn, signerSet: Signer[]): boolean {
  try {
    const grant = { id: pcActn.grant_ref } as unknown as Capability;
    const r = createThresholdVerifier({ signerSet, t: 3 })({ pcactn: pcActn, grant }) as { enforced: boolean; ok?: boolean; t?: number };
    return r.enforced === true && r.ok === true && typeof r.t === 'number' && r.t >= 3;
  } catch {
    return false;
  }
}

export interface PaymentMandateOptions {
  /** The amount to authorize. */
  amount: A2AMonetaryAmount;
  /** The payment instrument. */
  paymentMethod: A2APaymentMethod;
  /** The merchant, if constrained. */
  merchant?: string;
  /** Assert the human-present modality (YOU are responsible for having verified the co-sign). Default false. */
  humanPresent?: boolean;
  /**
   * Derive human-present by VERIFYING the PCActn's threshold shares against this signer set at t=3 (agent + guardian +
   * principal; i.e. a verified principal share). Ignored when `humanPresent` is given. A forged or unverifiable share yields `false`.
   */
  humanSignerSet?: Signer[];
  /** Override the VDC issuer (defaults to the PCActn's leaf holder key). */
  issuerPublic?: string;
  /** Issuance clock (epoch ms). Default `Date.now()`. */
  now?: number;
}

/**
 * Map a PCA proof (a PCActn) to an AP2 Payment Mandate so an A2A payment Task can carry it. The mandate's
 * authority is carried BY REFERENCE: `x_pca.pcactn_digest` binds it to the PCActn, and the mandate is
 * verified by resolving + verifying that proof (see {@link verifyA2APaymentMandate}).
 */
export function a2aPaymentMandateFromPca(pcActn: PCActn, opts: PaymentMandateOptions): A2APaymentMandate {
  const leaf = leafHolderOf(pcActn.cap_chain);
  const issuer = opts.issuerPublic ?? leaf;
  if (issuer === undefined) {
    throw new Error('a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain');
  }
  if (!Number.isSafeInteger(opts.amount.value) || opts.amount.value < 0) {
    throw new Error('a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units');
  }
  const humanPresent = opts.humanPresent ?? (opts.humanSignerSet ? verifiedHumanPresent(pcActn, opts.humanSignerSet) : false);
  const now = opts.now ?? Date.now();

  const x_pca: PcaPaymentBinding = {
    pcactn_digest: pcactnDigest(pcActn),
    aud: pcActn.aud,
    verb: pcActn.action.verb,
    resource: pcActn.action.resource,
    params_digest: pcActn.action.params_digest,
    grant_ref: pcActn.grant_ref,
    leaf_holder: leaf ?? issuer,
  };

  const contents: A2APaymentMandateContents = {
    amount: { ...opts.amount },
    payment_method: { ...opts.paymentMethod },
    human_present: humanPresent,
    ...(opts.merchant !== undefined ? { merchant: opts.merchant } : {}),
    x_pca,
  };

  return {
    '@context': A2A_AP2_CONTEXT,
    type: ['VerifiableCredential', 'PaymentMandate'],
    issuer,
    issuanceDate: new Date(now).toISOString(),
    credentialSubject: contents,
  };
}

/** Read the PCA binding back out of an AP2 Payment Mandate (the round-trip of `x_pca`). */
export function pcaBindingFromA2APaymentMandate(mandate: A2APaymentMandate): PcaPaymentBinding {
  return { ...mandate.credentialSubject.x_pca };
}

/** Options for {@link verifyA2APaymentMandate}: the shared verifier options plus the human-present evidence. */
export interface PaymentMandateVerifyOptions extends PcaVerifyOptions {
  /**
   * The signer set (agent + guardian + principal) a `human_present: true` mandate is checked against: the PCActn's threshold
   * shares must verify at t=3. Without it a mandate claiming `human_present: true` is refused (the claim is unsigned).
   */
  humanSignerSet?: Signer[];
}

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The fields of an (unsigned) Payment Mandate that the PCActn must authorize, checked against the PCActn and against the
 * params it commits to (`params`, already opened against `action.params_digest` by the caller). Returns the first
 * mismatch, or undefined.
 */
function mandateBindingError(m: A2APaymentMandateContents, pcActn: PCActn, params: Record<string, unknown>, opts: PaymentMandateVerifyOptions): string | undefined {
  const x = m.x_pca as unknown;
  if (!isRecord(x)) return 'payment mandate carries no x_pca binding';
  const chain = pcActn.cap_chain;
  const leaf: unknown = Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : undefined;
  const leafHolder = isRecord(leaf) ? leaf.holder : undefined;
  const bound: [string, unknown][] = [
    ['aud', pcActn.aud],
    ['verb', pcActn.action?.verb],
    ['resource', pcActn.action?.resource],
    ['params_digest', pcActn.action?.params_digest],
    ['grant_ref', pcActn.grant_ref],
    ['leaf_holder', leafHolder],
  ];
  for (const [k, v] of bound) if (!own(x, k) || typeof x[k] !== 'string' || x[k] !== v) return `payment mandate x_pca.${k} is not the PCActn's`;
  // amount + currency: the authorized params MUST carry both, and the mandate must state exactly them
  const amt = m.amount as unknown;
  if (!isRecord(amt) || !Number.isSafeInteger(amt.value) || (amt.value as number) < 0 || typeof amt.currency !== 'string') return 'payment mandate amount is malformed (value must be a non-negative integer in minor units)';
  if (!own(params, 'amount') || !Number.isSafeInteger(params.amount) || (params.amount as number) < 0) return 'the PCActn params carry no integer minor-unit amount to bind the mandate amount to';
  if (!own(params, 'currency') || typeof params.currency !== 'string') return 'the PCActn params carry no currency to bind the mandate currency to';
  if (amt.value !== params.amount || amt.currency !== params.currency) return 'payment mandate amount / currency differ from the authorized PCActn params';
  // payee and instrument: bound whenever either side names one (a mandate cannot widen or drop what the action fixed)
  const merchant = own(m, 'merchant') ? m.merchant : undefined;
  const pMerchant = own(params, 'merchant') ? params.merchant : undefined;
  if (merchant !== pMerchant) return 'payment mandate merchant differs from the authorized PCActn params';
  if (own(params, 'payment_method')) {
    let same = false;
    try {
      same = hashCanonical(m.payment_method) === hashCanonical(params.payment_method);
    } catch {
      same = false;
    }
    if (!same) return 'payment mandate payment_method differs from the authorized PCActn params';
  }
  // human_present is an unsigned claim: true only with a verified t=3 principal co-signature on the PCActn
  if (typeof m.human_present !== 'boolean') return 'payment mandate human_present must be a boolean';
  if (m.human_present && !(Array.isArray(opts.humanSignerSet) && verifiedHumanPresent(pcActn, opts.humanSignerSet))) {
    return 'payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)';
  }
  return undefined;
}

/**
 * Verify an AP2 Payment Mandate against the PCActn it references. The mandate is NOT signed: every field a payer acts on
 * must be authorized by the PCActn. Fail-closed:
 *  - `x_pca.pcactn_digest` equals `pcactnDigest(pcActn)`, and every other `x_pca` field (`aud`, `verb`, `resource`,
 *    `params_digest`, `grant_ref`, `leaf_holder`) equals the PCActn's own;
 *  - the verifier's `context.params` (the action's plaintext params) is REQUIRED and must open `action.params_digest`
 *    (the `params_digest` check is required on this path);
 *  - `amount.value` / `amount.currency` equal the params' own `amount` / `currency` exactly (both required in the params);
 *  - `merchant` equals the params' own `merchant` (both absent is the only other accepted case); when the params carry a
 *    `payment_method`, the mandate's equals it canonically;
 *  - `human_present: true` needs `humanSignerSet` and a PCActn whose threshold shares verify at t=3;
 *  - the PCActn itself verifies with the full verifier (signature, audience, validity, chain, plan, policy, ...).
 */
export async function verifyA2APaymentMandate(
  mandate: A2APaymentMandate,
  pcActn: PCActn,
  opts: PaymentMandateVerifyOptions,
): Promise<A2AVerification> {
  assertAuthority(opts);
  // A malformed mandate (no credentialSubject / x_pca) or a PCActn with no strict canonical form is a refusal, not an exception.
  let bound: unknown;
  let digest: string;
  try {
    bound = mandate.credentialSubject.x_pca.pcactn_digest;
    digest = pcactnDigest(pcActn);
  } catch (e) {
    return { ok: false, reason: `malformed payment mandate or PCActn: ${(e as Error).message}` };
  }
  if (bound !== digest) {
    return { ok: false, reason: 'payment mandate is not bound to this PCActn (pcactn_digest mismatch)', pcActn };
  }
  if (pcActn === null || typeof pcActn !== 'object') return { ok: false, reason: 'PCActn is not an object' };
  const context = typeof opts.context === 'function' ? await opts.context(pcActn) : (opts.context ?? {});
  const params: unknown = context.params;
  if (!isRecord(params)) return { ok: false, reason: 'context.params (the PCActn params plaintext) is required to bind the payment mandate', pcActn };
  const why = mandateBindingError(mandate.credentialSubject, pcActn, params, opts);
  if (why !== undefined) return { ok: false, reason: why, pcActn };
  const require = [...(opts.requireChecks ?? DEFAULT_REQUIRED_CHECKS)];
  if (!require.includes('params_digest')) require.push('params_digest');
  return verifyPcActn(pcActn, { ...opts, context, requireChecks: require });
}
