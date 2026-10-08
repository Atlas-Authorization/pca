/**
 * OAuth-standards chain-of-custody PROFILE of a Proof-Carrying Authority (PCA) capability chain.
 *
 * This package is a BRIDGE, not a replacement. The cryptographic authority for an agent action remains
 * the PCActn's signed, hash-linked, attenuating capability chain (`@atlasauth/pca` `capability.ts`):
 * every hop is signed by the key the parent is bound to, caveats are append-only, and widening is
 * impossible by construction. A verifier (`@atlasauth/backend` `requirePCA` / the adjudicator) checks
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
}

export interface ToTransactionTokenArgs {
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
const DEFAULT_TTL_SEC = 120;
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
): Promise<{ chain: SubActChain; action: TxnAction; claims: TransactionTokenClaims }> {
  const key = await toVerificationKey(verifyKey);
  const { payload } = await jwtVerify<TransactionTokenClaims>(jwt, key, { typ: TXN_TOKEN_TYP });

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('transaction token: missing `sub` (root principal)');
  }
  const tctx = payload.tctx;
  if (
    tctx === undefined ||
    tctx === null ||
    typeof tctx !== 'object' ||
    typeof tctx.verb !== 'string' ||
    typeof tctx.resource !== 'string' ||
    typeof tctx.aud !== 'string'
  ) {
    throw new Error('transaction token: missing or malformed `tctx`');
  }
  const act = normalizeAct(payload.act);
  const chain: SubActChain = act ? { sub: payload.sub, act } : { sub: payload.sub };
  const action: TxnAction = { verb: tctx.verb, resource: tctx.resource, aud: tctx.aud };
  return { chain, action, claims: payload };
}
