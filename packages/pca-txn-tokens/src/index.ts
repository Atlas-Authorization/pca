/**
 * OAuth-standards chain-of-custody PROFILE of a Proof-Carrying Authority (PCA) capability chain.
 *
 * This package is a BRIDGE, not a replacement. The cryptographic authority for an agent action remains
 * the PCActn's signed, hash-linked, attenuating capability chain (`@atlasauth/pca` `capability.ts`):
 * every hop is signed by the key the parent is bound to, caveats are append-only, and widening is
 * impossible by construction. A verifier (`@atlasauth/pca` `requirePCA` / the adjudicator) checks
 * THAT, default-deny. What enterprise agent-auth infrastructure already knows how to read, however, is
 * the OAuth delegation idiom: a token whose `sub`/`act` claims spell out "who invoked whom". So we
 * PROJECT the PCA chain into that idiom — compose, don't replace. The Transaction Token minted here is
 * the interop envelope that carries the chain-of-custody; it is NOT a bearer credential that authorizes
 * anything on its own. The PCActn's signed capability chain stays the credential.
 *
 * Specs implemented (cited per export):
 *  - RFC 8693 — OAuth 2.0 Token Exchange (https://www.rfc-editor.org/rfc/rfc8693). §4.1 defines the
 *    nestable `act` (actor) claim: a composite claim whose inner `sub` identifies an acting party, and
 *    whose own nested `act` identifies a further party in the delegation chain. We map one `act` level
 *    per PCA delegation hop, descending the chain of custody.
 *  - draft-ietf-oauth-transaction-tokens — Transaction Tokens
 *    (https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/). A Transaction Token (typ
 *    `txn_token+jwt`) is a short-lived, signed, immutable token that carries an invariant request
 *    context through a call chain so every downstream workload authorizes against the SAME context. We
 *    carry the PCA action as the transaction context (`tctx`) and the capability chain as `sub`/`act`.
 *  - Its AGENT extension — the emerging profile that puts the delegated-agent call chain (the
 *    "who invoked whom" of an agent swarm) into a Transaction Token's `act` claim so agent-auth infra
 *    reads the custody chain natively. Here, the PCA capability chain IS that call chain.
 *
 * `subActChain` is pure (no crypto). `toTransactionToken` / `fromTransactionToken` sign and verify an
 * EdDSA (Ed25519) JWT with `jose`. Signing accepts a raw 32-byte Ed25519 secret seed (the shape
 * `@atlasauth/pca` `KeyPair.secretKey` uses) or a pre-imported `jose` key; verification likewise accepts
 * a raw 32-byte Ed25519 public key or a `jose` key.
 */

import { randomUUID } from 'node:crypto';
import { SignJWT, importJWK, jwtVerify } from 'jose';
import type { JWK, JWTPayload, KeyLike } from 'jose';
import { assertCanonicalCompactJws } from '@atlasauth/pca';
import { b64u, publicKeyOf, type CapabilityChain } from '@atlasauth/pca';

// ---- RFC 8693 §4.1 nested actor claim -------------------------------------------------------------

/**
 * One level of the RFC 8693 `act` (actor) chain of custody. `sub` is the actor identity at this level
 * (a PCA capability's issuer/holder public key, b64u); `act`, when present, is the next actor DOWN the
 * delegation chain (the party this actor delegated to). Both the top-level sub/act of a Transaction
 * Token and every nested level share this shape.
 */
export interface ActClaim {
  /** RFC 8693 §4.1 actor identity for this delegation level (b64u public key). */
  sub: string;
  /** The next (descendant) actor this one delegated to, if any. */
  act?: ActClaim;
}

/** The root `{ sub, act }` chain-of-custody object (same recursive shape as a nested `act`). */
export type SubActClaim = ActClaim;

/** Alias for the reconstructed chain-of-custody returned by {@link fromTransactionToken}. */
export type SubActChain = ActClaim;

/** The PCA action projected as a Transaction Token transaction context (`tctx`). */
export interface TxnAction {
  /** Fully-qualified verb, e.g. `stripe.refund`. */
  verb: string;
  /** Target resource identifier, e.g. `charge:ch_123`. */
  resource: string;
  /** Audience: the resource server / instance id this action is bound to. */
  aud: string;
}

/**
 * Map a PCA {@link CapabilityChain} to the RFC 8693 §4.1 nested-actor idiom, descending the chain of
 * custody: `sub` is the ROOT principal (`chain[0].issuer`, the longest-lived key that rooted the grant),
 * then one nested `act` level per delegation hop — `act.sub` is the first holder (`chain[0].holder`),
 * `act.act.sub` is `chain[1].holder`, and so on down to the leaf actor. The nesting therefore reads
 * top-down as "principal invoked holder0 invoked holder1 invoked …". Pure: no signing, no I/O.
 *
 * (RFC 8693's own worked examples place the most recent actor outermost; this profile instead descends
 * in delegation order so the envelope mirrors the PCA chain's own root→leaf direction. The direction is
 * fixed and self-describing — {@link fromTransactionToken} reconstructs the identical structure.)
 */
export function subActChain(chain: CapabilityChain): SubActClaim {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new TypeError('subActChain: chain must be a non-empty CapabilityChain');
  }
  const root = chain[0]!;
  // Build innermost-first so each hop nests the one below it.
  let act: ActClaim | undefined;
  for (let i = chain.length - 1; i >= 0; i--) {
    const holder = chain[i]!.holder;
    if (typeof holder !== 'string' || holder.length === 0) {
      throw new TypeError(`subActChain: hop ${i} has no holder`);
    }
    act = act ? { sub: holder, act } : { sub: holder };
  }
  if (typeof root.issuer !== 'string' || root.issuer.length === 0) {
    throw new TypeError('subActChain: root hop has no issuer (principal)');
  }
  return act ? { sub: root.issuer, act } : { sub: root.issuer };
}

/**
 * Delegation depth of a sub/act chain-of-custody: the number of nested `act` levels (one per PCA
 * delegation hop). The top-level `sub` is the root principal and does not count — so for a chain built
 * by `agent()` + N `subAgent()` calls, `actDepth === chain.length` (the root grant hop plus N).
 */
export function actDepth(claim: SubActClaim): number {
  if (claim === null || typeof claim !== 'object') {
    throw new TypeError('actDepth: expected a sub/act claim object');
  }
  let depth = 0;
  let cur: ActClaim | undefined = claim.act;
  while (cur) {
    depth++;
    cur = cur.act;
  }
  return depth;
}

// ---- Transaction Token (draft-ietf-oauth-transaction-tokens) --------------------------------------

/** A signing key: a raw 32-byte Ed25519 secret seed, or a pre-imported `jose` asymmetric key. */
export type IssuerKey = Uint8Array | KeyLike;

/** A verification key: a raw 32-byte Ed25519 public key, or a pre-imported `jose` asymmetric key. */
export type VerifyKey = Uint8Array | KeyLike;

/** The claim set of a minted Transaction Token (standard JWT claims plus the PCA profile claims). */
export interface TransactionTokenClaims extends JWTPayload {
  /** The transaction context: the PCA action this token is immutably bound to. */
  tctx?: TxnAction;
  /** RFC 8693 §4.1 nested actor chain of custody (descendants of `sub`). */
  act?: ActClaim;
  /** draft-11 transaction identifier. */
  txn?: string;
  /** draft-11 scope. */
  scope?: string;
  /** draft-11 requesting workload. */
  req_wl?: string;
}

export interface FromTransactionTokenOptions {
  /** `draft-11` (default; strict: header typ `txntoken+jwt`; `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, `req_wl` required, and `audience` REQUIRED) or `legacy` (this package's original shape; explicit opt-in). */
  profile?: TxnProfile;
  /** The trust domain / audience this verifier serves; `aud` MUST contain it. REQUIRED for `draft-11`. */
  audience?: string;
  /** Clock tolerance in seconds (default 0). */
  clockToleranceSec?: number;
  /** Clock override (verification time). */
  now?: Date;
  /**
   * Replay hook: called with the token's `txn` (draft-11) or `jti` (legacy) and its `exp`; return true when the
   * value was already seen. A seen value is refused. REQUIRED unless `replayCheck: 'unchecked'` is set: a call
   * with neither throws {@link TxnTokenError} (`replay_store_required`). Back it with a shared durable store.
   */
  seenTxn?: (id: string, exp: number) => boolean | Promise<boolean>;
  /**
   * Explicit opt-out of the replay check, for a deployment that relies on a short lifetime alone (the draft
   * itself says a Txn-Token is not replay resistant). Has no effect when `seenTxn` is supplied.
   */
  replayCheck?: 'unchecked';
}

/** Stable classification of a configuration failure of this package. */
export type TxnTokenErrorCode = 'replay_store_required';

/** Thrown when a verifier is configured without a required security component. */
export class TxnTokenError extends Error {
  override readonly name = 'TxnTokenError';
  readonly code: TxnTokenErrorCode;
  constructor(code: TxnTokenErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Which token profile to emit / require.
 *  - `legacy` (explicit opt-in): header `typ` `txn_token+jwt`, a `jti`, the PCA `tctx`.
 *  - `draft-11` (default): draft-ietf-oauth-transaction-tokens-11 — header `typ` `txntoken+jwt`, REQUIRED `iat`, `aud`
 *    (the trust domain), `exp`, `txn`, `sub`, `scope`, `req_wl`; `tctx` carries the PCA action. The `act`
 *    chain is this package's extension (the draft defines no `act` claim; it is ignored by readers that do
 *    not know it).
 */
export type TxnProfile = 'legacy' | 'draft-11';

export interface ToTransactionTokenArgs {
  /** Token profile (default `draft-11`). */
  profile?: TxnProfile;
  /** draft-11: REQUIRED `scope` (the narrowest purpose of the transaction). */
  scope?: string;
  /** draft-11: REQUIRED `req_wl`, the workload that requested the token. */
  reqWl?: string;
  /** draft-11: the `txn` transaction identifier (default a random UUID). */
  txn?: string;
  /** draft-11: the trust domain placed in `aud` (default `action.aud`). */
  trustDomain?: string;
  /** The PCA capability chain to project (root grant first). */
  chain: CapabilityChain;
  /** The action to bind as the transaction context. */
  action: TxnAction;
  /** Ed25519 secret seed (32 bytes) OR a `jose` signing key. */
  issuerKey: IssuerKey;
  /** `iss` claim: the Transaction Token Service / issuer identifier. */
  issuer: string;
  /** Token lifetime in seconds (default 120 — Transaction Tokens are short-lived). */
  ttlSec?: number;
}

/** draft-ietf-oauth-transaction-tokens: the Transaction Token JWT media type. */
const TXN_TOKEN_TYP = 'txn_token+jwt';
/** draft-ietf-oauth-transaction-tokens-11 header `typ`. */
export const TXN_TOKEN_TYP_DRAFT_11 = 'txntoken+jwt';
const DEFAULT_TTL_SEC = 120;
/** Upper bound on an accepted token string (adversarial-size guard, checked before any parsing). */
export const MAX_TOKEN_CHARS = 16384;
const EDDSA = 'EdDSA';

/** Build the `jose` signing key: import a raw 32-byte Ed25519 seed as an OKP key, else pass through. */
async function toSigningKey(key: IssuerKey): Promise<KeyLike | Uint8Array> {
  if (key instanceof Uint8Array) {
    if (key.length !== 32) {
      throw new TypeError('toTransactionToken: a raw Ed25519 secret key must be 32 bytes');
    }
    const jwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: b64u(publicKeyOf(key)), d: b64u(key) };
    return importJWK(jwk, EDDSA);
  }
  return key;
}

/** Build the `jose` verification key: import a raw 32-byte Ed25519 public key, else pass through. */
async function toVerificationKey(key: VerifyKey): Promise<KeyLike | Uint8Array> {
  if (key instanceof Uint8Array) {
    if (key.length !== 32) {
      throw new TypeError('fromTransactionToken: a raw Ed25519 public key must be 32 bytes');
    }
    const jwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: b64u(key) };
    return importJWK(jwk, EDDSA);
  }
  return key;
}

/**
 * Mint a signed Transaction Token (draft-ietf-oauth-transaction-tokens, typ `txn_token+jwt`) that
 * carries the PCA capability chain's chain of custody (`sub`/`act`, per RFC 8693 §4.1) and the action
 * as its immutable transaction context (`tctx`). EdDSA (Ed25519) signed via `jose`.
 *
 * This is the interop ENVELOPE around a PCA action, not a substitute credential: a resource server still
 * verifies the PCActn's signed capability chain. The token's signature here binds the custody chain and
 * the action together so agent-auth infrastructure can read "who invoked whom" over a standard JWT.
 */
export async function toTransactionToken(args: ToTransactionTokenArgs): Promise<string> {
  const { chain, action, issuer } = args;
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new TypeError('toTransactionToken: `issuer` is required');
  }
  if (
    action === null ||
    typeof action !== 'object' ||
    typeof action.verb !== 'string' ||
    typeof action.resource !== 'string' ||
    typeof action.aud !== 'string'
  ) {
    throw new TypeError('toTransactionToken: `action` must have string verb, resource and aud');
  }
  const custody = subActChain(chain);
  const ttl = args.ttlSec ?? DEFAULT_TTL_SEC;
  if (!Number.isFinite(ttl) || ttl <= 0) throw new RangeError('toTransactionToken: ttlSec must be > 0');
  const nowSec = Math.floor(Date.now() / 1000);
  const key = await toSigningKey(args.issuerKey);
  const draft = (args.profile ?? 'draft-11') === 'draft-11';
  if (args.profile !== undefined && args.profile !== 'legacy' && !draft) {
    throw new TypeError('toTransactionToken: profile must be legacy or draft-11');
  }
  if (draft) {
    if (typeof args.scope !== 'string' || args.scope.length === 0) throw new TypeError('toTransactionToken: draft-11 requires `scope`');
    if (typeof args.reqWl !== 'string' || args.reqWl.length === 0) throw new TypeError('toTransactionToken: draft-11 requires `reqWl`');
    const td = args.trustDomain ?? action.aud;
    if (typeof td !== 'string' || td.length === 0) throw new TypeError('toTransactionToken: draft-11 requires a non-empty trust domain (aud)');
    const claims: TransactionTokenClaims = {
      tctx: { verb: action.verb, resource: action.resource, aud: action.aud },
      ...(custody.act ? { act: custody.act } : {}),
      txn: args.txn ?? randomUUID(),
      scope: args.scope,
      req_wl: args.reqWl,
    };
    return new SignJWT(claims)
      .setProtectedHeader({ alg: EDDSA, typ: TXN_TOKEN_TYP_DRAFT_11 })
      .setIssuedAt(nowSec)
      .setIssuer(issuer)
      .setSubject(custody.sub)
      .setAudience(td)
      .setExpirationTime(nowSec + ttl)
      .sign(key);
  }

  const tctx: TxnAction = { verb: action.verb, resource: action.resource, aud: action.aud };
  const payload: TransactionTokenClaims = custody.act ? { tctx, act: custody.act } : { tctx };

  return new SignJWT(payload)
    .setProtectedHeader({ alg: EDDSA, typ: TXN_TOKEN_TYP })
    .setIssuedAt(nowSec)
    .setIssuer(issuer)
    .setSubject(custody.sub)
    .setAudience(action.aud)
    .setExpirationTime(nowSec + ttl)
    .setJti(randomUUID())
    .sign(key);
}

/** Validate + normalize an untrusted nested `act` claim (jose verifies the signature, not the shape). */
function normalizeAct(node: unknown): ActClaim | undefined {
  if (node === undefined) return undefined;
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    throw new Error('transaction token: malformed `act` claim');
  }
  const obj = node as Record<string, unknown>;
  if (typeof obj.sub !== 'string' || obj.sub.length === 0) {
    throw new Error('transaction token: `act.sub` must be a non-empty string');
  }
  const inner = normalizeAct(obj.act);
  return inner ? { sub: obj.sub, act: inner } : { sub: obj.sub };
}

/**
 * Verify a Transaction Token's EdDSA signature and parse out the chain of custody + transaction context.
 * Throws on an invalid signature, a wrong key, an expired token, or a malformed claim set.
 *
 * Returns the reconstructed RFC 8693 `sub`/`act` custody chain, the `tctx` action, and the full verified
 * claim set. This recovers the interop envelope only; authority to act still rests on verifying the
 * PCActn's signed PCA capability chain downstream.
 */
export async function fromTransactionToken(
  jwt: string,
  verifyKey: VerifyKey,
  opts: FromTransactionTokenOptions = {},
): Promise<{ chain: SubActChain; action: TxnAction | undefined; tctx: Record<string, unknown>; claims: TransactionTokenClaims }> {
  const draft = (opts.profile ?? 'draft-11') === 'draft-11';
  if (opts.profile !== undefined && opts.profile !== 'legacy' && !draft) {
    throw new TypeError('fromTransactionToken: profile must be legacy or draft-11');
  }
  if (draft && (typeof opts.audience !== 'string' || opts.audience.length === 0)) {
    throw new TypeError('fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)');
  }
  if (typeof opts.seenTxn !== 'function' && opts.replayCheck !== 'unchecked') {
    throw new TxnTokenError('replay_store_required', "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'");
  }
  if (typeof jwt === 'string' && jwt.length > MAX_TOKEN_CHARS) {
    throw new Error('transaction token: token exceeds the size limit');
  }
  assertCanonicalCompactJws(jwt); // canonical-spelling gate BEFORE jose (one accepted string form)
  const key = await toVerificationKey(verifyKey);
  const { payload } = await jwtVerify<TransactionTokenClaims>(jwt, key, {
    typ: draft ? TXN_TOKEN_TYP_DRAFT_11 : TXN_TOKEN_TYP,
    algorithms: [EDDSA],
    requiredClaims: draft ? ['iat', 'exp', 'aud', 'sub', 'txn', 'scope', 'req_wl'] : ['exp'],
    ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    ...(opts.clockToleranceSec !== undefined ? { clockTolerance: opts.clockToleranceSec } : {}),
    ...(opts.now !== undefined ? { currentDate: opts.now } : {}),
  });
  if (draft) {
    for (const k of ['txn', 'scope', 'req_wl'] as const) {
      if (typeof payload[k] !== 'string' || payload[k].length === 0) {
        throw new Error(`transaction token: \`${k}\` must be a non-empty string`);
      }
    }
  }
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('transaction token: missing `sub` (root principal)');
  }
  const { tctx, action } = readTctx(payload.tctx, draft);
  if (draft && payload.rctx !== undefined && !isPlainObject(payload.rctx)) {
    throw new Error('transaction token: malformed `rctx`');
  }
  const act = normalizeAct(payload.act);
  // Consume the identifier last: a token refused for any other reason never burns its transaction id.
  if (opts.seenTxn !== undefined) {
    const id = draft ? payload.txn : payload.jti;
    if (typeof id !== 'string' || id.length === 0) throw new Error('transaction token: no transaction identifier to check for replay');
    if (await opts.seenTxn(id, payload.exp as number)) throw new Error('transaction token: replayed (transaction identifier already seen)');
  }
  const chain: SubActChain = act ? { sub: payload.sub, act } : { sub: payload.sub };
  return { chain, action, tctx, claims: payload };
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

const PCA_ACTION_KEYS = ['verb', 'resource', 'aud'] as const;

/**
 * Parse the transaction context. The draft's `tctx` is a free-form JSON object, so the draft profile accepts
 * any object; when it uses any of the PCA action keys (`verb`, `resource`, `aud`) it must use all three as
 * strings (they are reserved for the PCA action, never half-present). The legacy profile requires the PCA
 * action. `action` is undefined only for a free-form draft `tctx`.
 */
function readTctx(raw: unknown, draft: boolean): { tctx: Record<string, unknown>; action: TxnAction | undefined } {
  if (!isPlainObject(raw)) throw new Error('transaction token: missing or malformed `tctx`');
  const usesPca = PCA_ACTION_KEYS.some((k) => Object.prototype.hasOwnProperty.call(raw, k));
  if (!draft || usesPca) {
    const { verb, resource, aud } = raw;
    if (typeof verb !== 'string' || typeof resource !== 'string' || typeof aud !== 'string') {
      throw new Error('transaction token: missing or malformed `tctx`');
    }
    return { tctx: raw, action: { verb, resource, aud } };
  }
  return { tctx: raw, action: undefined };
}

/**
 * RFC 8693 §4.1 ordering of an `act` chain: the MOST RECENT actor outermost. This package's own projection
 * (`subActChain`) descends in delegation order (root holder outermost); use this to emit the RFC order to a
 * consumer that expects it. Pure; the `sub` is unchanged.
 */
export function toRfc8693Act(claim: SubActClaim): SubActClaim {
  const actors: string[] = [];
  for (let c: ActClaim | undefined = claim.act; c; c = c.act) actors.push(c.sub);
  let act: ActClaim | undefined;
  for (const sub of actors) act = act ? { sub, act } : { sub };
  return act ? { sub: claim.sub, act } : { sub: claim.sub };
}
