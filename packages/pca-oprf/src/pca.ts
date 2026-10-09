/**
 * The PCA layer on top of the RFC 9497 OPRF core (`oprf.ts`).
 *
 * Two Proof-Carrying Authority use-cases, both of which need a server to answer a membership / counting
 * question about a client secret WITHOUT learning that secret:
 *
 *  1. **Private revocation check.** PCA capability ids are content-addressed strings (see
 *     `@atlasauth/pca` `capability.ts`: `Capability.id`). A naive revocation check leaks *which*
 *     capability a resource server (or a shared revocation service) is asked about. Here the revocation
 *     service precomputes the OPRF output of every revoked cap id into a published set, and a client
 *     checks membership obliviously: it blinds its cap id, gets a blind-evaluation, finalizes to the
 *     OPRF output, and tests set membership. The service sees only a blinded group element and learns
 *     nothing about the cap id; the client learns only in/out of the set.
 *
 *     This MIRRORS `@atlasauth/pca-revoke`'s registry notion structurally (a published set of revoked
 *     identifiers consulted on every action) but keeps the identifier private; it does not import it.
 *
 *  2. **Private rate-limiting.** A per-`(identifier, window)` token lets a server count and cap usage
 *     without ever seeing the raw identifier (an agent holder key, a principal, an API key). The token
 *     is a POPRF output: the rate WINDOW is the PUBLIC `info` tag the server sees and proves it used,
 *     while the identifier stays hidden. Same `(identifier, window)` always yields the same token
 *     (so counts aggregate); a new window yields an unlinkable token (so the count resets).
 */

import {
  type EvaluateResult,
  blind,
  blindEvaluate,
  blindEvaluatePoprf,
  blindPoprf,
  evaluate,
  evaluatePoprf,
  finalize,
  finalizePoprf,
  publicKeyFor,
  toHex,
} from './oprf';

const te = new TextEncoder();

// ---------------------------------------------------------------------------------------------
// Private revocation check
// ---------------------------------------------------------------------------------------------

/** The revocation mode: base OPRF, or verifiable VOPRF (the client checks the service used its key). */
export type RevocationMode = 'oprf' | 'voprf';

/**
 * A published private-revocation set: the OPRF outputs of the revoked capability ids, as lowercase-hex
 * strings. It reveals nothing about the cap ids beyond their count (the OPRF output is pseudorandom and
 * only computable with the service key). For `voprf` it also carries the service public key so clients
 * can verify each blind-evaluation.
 */
export interface RevocationSet {
  /** Lowercase-hex OPRF outputs of the revoked cap ids. */
  outputs: ReadonlySet<string>;
  /** Which OPRF mode produced the outputs (and which the client must use to check). */
  mode: RevocationMode;
  /** The service public key (`voprf` only), for client-side DLEQ verification. */
  publicKey?: Uint8Array;
}

/** A server blind-evaluation oracle: the only thing that crosses the client→service boundary. */
export type BlindEvaluator = (blindedElement: Uint8Array) => EvaluateResult;

/**
 * Server side: precompute the private-revocation set from the secret key and the revoked cap ids.
 * Each entry is `OPRF.Evaluate(sk, capId)` rendered as hex. Republish whenever the revocation list
 * changes (mirrors a `@atlasauth/pca-revoke` registry snapshot, but the ids are never exposed).
 */
export function buildRevocationSet(
  secretKey: Uint8Array,
  revokedCapIds: readonly string[],
  mode: RevocationMode = 'oprf',
): RevocationSet {
  const outputs = new Set<string>();
  for (const id of revokedCapIds) {
    outputs.add(toHex(evaluate(secretKey, te.encode(id), mode)));
  }
  const set: RevocationSet = { outputs, mode };
  if (mode === 'voprf') set.publicKey = publicKeyFor(secretKey);
  return set;
}

/**
 * Server side: build the blind-evaluation oracle the revocation service exposes. It takes a blinded
 * element and returns the evaluated element (plus a DLEQ proof for `voprf`). It CANNOT recover the cap
 * id — a blinded element is `blind * HashToGroup(capId)` for a secret `blind`, i.e. a uniformly random
 * group element from the service's view.
 */
export function makeRevocationEvaluator(
  secretKey: Uint8Array,
  mode: RevocationMode = 'oprf',
): BlindEvaluator {
  const publicKey = mode === 'voprf' ? publicKeyFor(secretKey) : undefined;
  return (blindedElement: Uint8Array): EvaluateResult =>
    blindEvaluate(secretKey, blindedElement, mode, publicKey);
}

/**
 * Client side: is `capId` in the published revocation set, learned obliviously? Blinds the cap id,
 * sends ONLY the blinded element through `blindEval`, finalizes to the OPRF output, and tests
 * membership. For a `voprf` set the blind-evaluation's DLEQ proof is verified (a lying service is
 * rejected rather than silently making every cap look non-revoked).
 */
export function isRevokedPrivate(
  capId: string,
  args: { blindEval: BlindEvaluator; revokedSet: RevocationSet },
): boolean {
  const input = te.encode(capId);
  const mode = args.revokedSet.mode;
  const b = blind(input, mode);
  const res = args.blindEval(b.blindedElement);
  let output: Uint8Array;
  if (mode === 'voprf') {
    const publicKey = args.revokedSet.publicKey;
    if (res.proof === undefined || publicKey === undefined) {
      throw new Error('isRevokedPrivate(voprf): missing DLEQ proof or service public key');
    }
    output = finalize(input, b.blind, res.evaluatedElement, 'voprf', {
      proof: res.proof,
      publicKey,
      blindedElement: b.blindedElement,
    });
  } else {
    output = finalize(input, b.blind, res.evaluatedElement, 'oprf');
  }
  return args.revokedSet.outputs.has(toHex(output));
}

// ---------------------------------------------------------------------------------------------
// Private rate-limiting (POPRF: identifier hidden, window public)
// ---------------------------------------------------------------------------------------------

/** A POPRF blind-evaluation oracle for rate tokens: the window is the public `info` tag. */
export type RateBlindEvaluator = (blindedElement: Uint8Array, window: string) => EvaluateResult;

/**
 * Server side (reference): the deterministic rate token for `(identifier, window)` computed directly
 * from the secret key — `POPRF.Evaluate(sk, identifier, info = window)`. A server that already holds
 * the identifier can compute this; the private client flow below yields the SAME token without the
 * server ever seeing the identifier.
 */
export function rateToken(secretKey: Uint8Array, identifier: string, window: string): Uint8Array {
  return evaluatePoprf(secretKey, te.encode(identifier), te.encode(window));
}

/** Lowercase-hex of {@link rateToken} — a stable, identifier-free counting key. */
export function rateTokenHex(secretKey: Uint8Array, identifier: string, window: string): string {
  return toHex(rateToken(secretKey, identifier, window));
}

/**
 * Server side: the POPRF blind-evaluation oracle. Takes a blinded element and the PUBLIC window, folds
 * the window into the key, and returns the evaluated element plus a DLEQ proof binding the window. The
 * server learns the window (by design) but not the identifier.
 */
export function makeRateEvaluator(secretKey: Uint8Array): RateBlindEvaluator {
  return (blindedElement: Uint8Array, window: string): EvaluateResult =>
    blindEvaluatePoprf(secretKey, blindedElement, te.encode(window));
}

/**
 * Client side: obtain the rate token for `(identifier, window)` WITHOUT revealing the identifier. The
 * identifier is blinded; only the blinded element and the public window cross the boundary. The
 * server's DLEQ proof (that it used the key for this window) is verified during finalize. The result
 * equals {@link rateToken} for the same arguments and key.
 */
export function privateRateToken(
  identifier: string,
  window: string,
  args: { blindEval: RateBlindEvaluator; publicKey: Uint8Array },
): Uint8Array {
  const input = te.encode(identifier);
  const info = te.encode(window);
  const b = blindPoprf(input, info, args.publicKey);
  const res = args.blindEval(b.blindedElement, window);
  if (res.proof === undefined) {
    throw new Error('privateRateToken: POPRF blind-evaluation did not return a DLEQ proof');
  }
  return finalizePoprf(input, b.blind, res.evaluatedElement, info, {
    proof: res.proof,
    blindedElement: b.blindedElement,
    tweakedKey: b.tweakedKey,
  });
}

/**
 * A tiny in-memory counter over rate tokens. A server records tokens and enforces a per-token cap,
 * counting and limiting usage per `(identifier, window)` while only ever handling the opaque token —
 * never the identifier. Swap in Redis/DB for a fleet; this is the reference.
 */
export class RateWindowCounter {
  private readonly counts = new Map<string, number>();

  constructor(private readonly limit: number) {
    if (!Number.isInteger(limit) || limit < 1) {
      throw new TypeError('RateWindowCounter: limit must be a positive integer');
    }
  }

  /**
   * Record one use of `token` and report whether it is still within the limit. Returns the new count
   * and `allowed = count <= limit`. The token is the only thing stored; the identifier stays private.
   */
  hit(token: Uint8Array): { count: number; allowed: boolean } {
    const key = toHex(token);
    const count = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, count);
    return { count, allowed: count <= this.limit };
  }

  /** The current count for a token (0 if unseen). */
  count(token: Uint8Array): number {
    return this.counts.get(toHex(token)) ?? 0;
  }

  /** Drop all counts (e.g. when rotating to a brand-new window namespace). */
  reset(): void {
    this.counts.clear();
  }
}
