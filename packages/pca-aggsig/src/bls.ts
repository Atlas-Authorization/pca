import {
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  aggregateVerify as rawAggregateVerify,
  fastAggregateVerify as rawFastAggregateVerify,
  keyValidate,
  popVerify,
} from './core';

/**
 * ROGUE-KEY-SAFE AGGREGATION, by construction.
 *
 * `fastAggregateVerify` (same message, many keys) is only sound if every key was admitted with a verified
 * proof of possession (PoP): without it, an adversary registers pk_adv = g^x - sum(honest keys) and forges an
 * aggregate that "verifies" for the whole honest set. A caller-discipline rule ("remember to popVerify") is
 * how that bug ships, so here the safe path is the ONLY path:
 *
 *  - {@link RegisteredKey} is an opaque class. Its constructor is guarded by a module-private token, and every
 *    instance is recorded in a module-private `WeakSet`. A cast object, a prototype-forged object, a
 *    `structuredClone` or JSON round trip is not in the set and is refused.
 *  - The only producers are {@link registerKey} and {@link KeyRegistry.register}, and both run `popVerify`
 *    (KeyValidate + PoP-DST signature by the key over itself) first.
 *  - {@link aggregateVerify} and {@link fastAggregateVerify} take `RegisteredKey[]`, never raw bytes. The raw
 *    verifiers live in the internal `./core` module, which is not exported from the package index and is
 *    blocked by `package.json` `exports`.
 *
 * The aggregation scheme itself is the draft-irtf-cfrg-bls-signature POP ciphersuite
 * (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`), the draft's rogue-key defence; this module adds the
 * enforcement that the draft leaves to the application.
 */

const TOKEN = Symbol('atlas-pca-aggsig/registered-key');
const REGISTERED = new WeakSet<object>();

/** A public key whose proof of possession has been verified. Construct only via {@link registerKey}. */
export class RegisteredKey {
  readonly #bytes: Uint8Array;

  /** @internal Use {@link registerKey}; direct construction throws. */
  constructor(token: symbol, bytes: Uint8Array) {
    if (token !== TOKEN) throw new TypeError('RegisteredKey cannot be constructed directly; use registerKey(publicKey, pop)');
    this.#bytes = Uint8Array.from(bytes);
    REGISTERED.add(this);
    Object.freeze(this);
  }

  /** A copy of the 48-byte compressed G1 public key. */
  get bytes(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }
}

export type RegisterResult = { ok: true; key: RegisteredKey } | { ok: false; reason: string };

/**
 * Admit a public key: it must pass KeyValidate and carry a valid PoP (a PoP-DST signature by the key over its
 * own bytes). The ONLY way to obtain a {@link RegisteredKey}. Never throws.
 */
export function registerKey(publicKey: Uint8Array, pop: Uint8Array): RegisterResult {
  if (!(publicKey instanceof Uint8Array) || !(pop instanceof Uint8Array)) return { ok: false, reason: 'public key and proof of possession must be Uint8Arrays' };
  if (!keyValidate(publicKey)) return { ok: false, reason: 'public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)' };
  if (pop.length !== SIGNATURE_LENGTH) return { ok: false, reason: 'proof of possession is not a 96-byte compressed G2 signature' };
  if (!popVerify(publicKey, pop)) return { ok: false, reason: 'proof of possession does not verify for this key' };
  return { ok: true, key: new RegisteredKey(TOKEN, publicKey) };
}

/** True only for instances produced by {@link registerKey}. */
export function isRegisteredKey(x: unknown): x is RegisteredKey {
  return typeof x === 'object' && x !== null && REGISTERED.has(x);
}

/**
 * A verifier's pinned set of admitted keys, indexed by key bytes. Use it where keys arrive as bytes/strings
 * (a capability chain's issuers, a witness list) and each must already have been admitted.
 */
export class KeyRegistry {
  readonly #keys = new Map<string, RegisteredKey>();

  /** Verify the PoP and admit the key. Re-registering the same key is idempotent. */
  register(publicKey: Uint8Array, pop: Uint8Array): RegisterResult {
    const r = registerKey(publicKey, pop);
    if (r.ok) this.#keys.set(hex(publicKey), r.key);
    return r;
  }

  /** The registered key for these bytes, or `undefined` if it was never admitted. */
  get(publicKey: Uint8Array): RegisteredKey | undefined {
    return publicKey instanceof Uint8Array && publicKey.length === PUBLIC_KEY_LENGTH ? this.#keys.get(hex(publicKey)) : undefined;
  }

  has(publicKey: Uint8Array): boolean {
    return this.get(publicKey) !== undefined;
  }

  get size(): number {
    return this.#keys.size;
  }
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/** Why `keys` cannot be used for aggregate verification, or `null` if every element is a genuine {@link RegisteredKey}. */
export function checkRegistered(keys: unknown): string | null {
  if (!Array.isArray(keys)) return 'keys must be an array of RegisteredKey';
  if (keys.length === 0) return 'no keys';
  for (let i = 0; i < keys.length; i++) {
    if (!isRegisteredKey(keys[i])) return `key ${i} is not a registered key: it was not admitted through registerKey (proof of possession)`;
  }
  return null;
}

function rawOf(keys: readonly RegisteredKey[]): Uint8Array[] {
  return keys.map((k) => k.bytes);
}

/**
 * AggregateVerify (draft §3.1.1) over distinct messages, restricted to registered keys. Never throws; `false`
 * on any unregistered key, length mismatch, repeated message, or failed pairing check.
 */
export function aggregateVerify(keys: readonly RegisteredKey[], msgs: Uint8Array[], aggSig: Uint8Array): boolean {
  if (checkRegistered(keys) !== null) return false;
  return rawAggregateVerify(rawOf(keys), msgs, aggSig);
}

/**
 * FastAggregateVerify (draft §3.3.4): one message, many signers, restricted to registered keys (so the
 * rogue-key attack cannot be run through this API). Never throws.
 */
export function fastAggregateVerify(keys: readonly RegisteredKey[], msg: Uint8Array, aggSig: Uint8Array): boolean {
  if (checkRegistered(keys) !== null) return false;
  // One signer may not be counted twice (RT-13): s+s+s over [k,k,k] would pass as "3 signers".
  const seen = new Set<string>();
  for (const k of keys) {
    const h = hex(k.bytes);
    if (seen.has(h)) return false;
    seen.add(h);
  }
  return rawFastAggregateVerify(rawOf(keys), msg, aggSig);
}

// Re-exports of the primitives that are safe on their own (single-key checks, signature-only aggregation).
export {
  SIG_DST,
  POP_DST,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  type BlsKeyPair,
  keyGen,
  publicKeyOf,
  keyValidate,
  sign,
  verify,
  aggregate,
  popProve,
} from './core';
