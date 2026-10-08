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
  type VerifyResult,
  canonicalBytes,
  pcactnDigest,
  verifyPCActnCore,
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
  const onTask = readPca(task.metadata);
  if (onTask) return onTask;
  const onStatus = readPca(task.status.message?.metadata);
  if (onStatus) return onStatus;
  const history = task.history;
  if (history && history.length > 0) {
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
  return readPca(message.metadata);
}

/** Options shared by every PCActn verification surface in this module. */
export interface PcaVerifyOptions {
  /** This resource server / Atlas instance id. Compared against the PCActn's signed `aud` (fail-closed). */
  aud: string;
  /** Verification clock (epoch ms). Default `Date.now()`. */
  now?: number;
  /**
   * The trusted root grant (capability). When omitted, the grant is taken from the embedded chain root
   * (`cap_chain[0]`); the full chain cryptography is still verified either way, but pinning `grant` (or
   * `expectedRootIssuer`) is what ties the proof to a KNOWN principal rather than whatever the chain claims.
   */
  grant?: Capability;
  /** When set, the chain root's issuer MUST equal this principal key (b64u), else verification fails. */
  expectedRootIssuer?: string;
}

/** The result of verifying a proof-carrying A2A artifact. */
export interface A2AVerification {
  ok: boolean;
  reason?: string;
  /** The underlying PCA core verification result (present once a PCActn was found and evaluated). */
  result?: VerifyResult;
  /** The extracted PCActn (present when one was carried). */
  pcActn?: PCActn;
}

function chainRoot(chain: CapabilityChain | undefined): Capability | undefined {
  if (!Array.isArray(chain) || chain.length === 0) return undefined;
  return chain[0];
}

/** Core PCActn verification shared by the Task and payment-mandate surfaces. Fail-closed. */
async function verifyPcActn(pcActn: PCActn, opts: PcaVerifyOptions): Promise<A2AVerification> {
  const root = chainRoot(pcActn.cap_chain);
  if (!root) return { ok: false, reason: 'PCActn carries no capability chain', pcActn };

  if (opts.expectedRootIssuer !== undefined && root.issuer !== opts.expectedRootIssuer) {
    return {
      ok: false,
      reason: 'chain root issuer does not match the expected principal',
      pcActn,
    };
  }

  const grant = opts.grant ?? root;
  const result = await verifyPCActnCore(pcActn, {
    grant,
    audience: opts.aud,
    ...(opts.now !== undefined ? { nowEpoch: opts.now } : {}),
  });
  return result.allow
    ? { ok: true, result, pcActn }
    : { ok: false, reason: result.reason ?? 'PCActn verification failed', result, pcActn };
}

/**
 * Verify the proof-carrying action on an A2A Task. Fail-closed: a Task with no attached PCActn, or one
 * whose PCActn does not verify (bad signature, wrong audience, expired, out-of-plan, tampered chain …),
 * is rejected.
 */
export async function verifyA2ATask(task: A2ATask, opts: PcaVerifyOptions): Promise<A2AVerification> {
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

export interface IssueAgentCardOptions {
  /** JWS algorithm for the signature. Default `'EdDSA'`. */
  alg?: string;
  /** The PCA passport reference to embed so the card points at verifiable proof-of-authority. */
  passport?: A2APassportRef | { id: string };
  /** Optional JWS `kid` (set it when verifiers resolve the key from a JWKS). */
  kid?: string;
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
  const protectedHeader: Record<string, unknown> = {
    alg,
    b64: false,
    crit: ['b64'],
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

  const payload = cardSigningBytes(card);
  let passportRef: string | undefined;

  for (let i = 0; i < signatures.length; i++) {
    const sig = signatures[i];
    if (!sig || typeof sig.protected !== 'string' || typeof sig.signature !== 'string') {
      return { ok: false, reason: `signature ${i} is malformed` };
    }
    const input: FlattenedJWSInput = { protected: sig.protected, payload, signature: sig.signature };
    try {
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
 * JSON-LD contexts for the AP2 VDC envelope — the SAME values `@atlasauth/pca-ap2` uses, so this profile
 * is wire-compatible with the full AP2 chain. The second entry is a placeholder for the canonical AP2
 * context URL (replace before production).
 */
export const A2A_AP2_CONTEXT: readonly string[] = [
  'https://www.w3.org/2018/credentials/v1',
  'https://ap2-protocol.org/context/v0.2',
];

/** ISO-4217 currency + decimal value (use minor units in production to avoid float drift). */
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
   * The AP2 human-present modality. MAPPING: a PCActn carrying a risk-adaptive `threshold` (a
   * guardian/principal co-signature) ⇒ `human_present = true`; an agent-only (t=1) action ⇒ `false`.
   * Override explicitly via `humanPresent`.
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

export interface PaymentMandateOptions {
  /** The amount to authorize. */
  amount: A2AMonetaryAmount;
  /** The payment instrument. */
  paymentMethod: A2APaymentMethod;
  /** The merchant, if constrained. */
  merchant?: string;
  /** Override the human-present modality (else derived from whether the PCActn carries a `threshold`). */
  humanPresent?: boolean;
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
  const humanPresent = opts.humanPresent ?? pcActn.threshold !== undefined;
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

/**
 * Verify an AP2 Payment Mandate against the PCActn it references. Fail-closed: the mandate's
 * `x_pca.pcactn_digest` MUST equal `pcactnDigest(pcActn)` (so the mandate is bound to THIS proof), and
 * the PCActn itself must verify (signature, audience, validity, chain, plan inclusion). This is what makes
 * the AP2 payment mandate PCA-verifiable rather than a bare assertion.
 */
export async function verifyA2APaymentMandate(
  mandate: A2APaymentMandate,
  pcActn: PCActn,
  opts: PcaVerifyOptions,
): Promise<A2AVerification> {
  const bound = mandate.credentialSubject.x_pca.pcactn_digest;
  if (bound !== pcactnDigest(pcActn)) {
    return { ok: false, reason: 'payment mandate is not bound to this PCActn (pcactn_digest mismatch)', pcActn };
  }
  return verifyPcActn(pcActn, opts);
}
