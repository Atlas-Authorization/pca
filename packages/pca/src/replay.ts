/**
 * Anti-replay primitives for a resource server that verifies PCActns itself (not through the Atlas API).
 *
 * WHAT THIS IS. `verifyPCActnCore` is a pure, stateless structural verifier: it checks `aud` / `iat` / `exp`
 * and that `counter` is a non-negative safe integer, but it cannot know whether an action was already
 * accepted. One-time use is the verifier's STATE job. This module defines the two stores a verifier needs
 * and a guard that composes them with the wire-level freshness rules, plus a reference in-memory
 * implementation. The Atlas API's own implementation of the same contract is Postgres-backed
 * (see docs/pca/reference/anti-replay.md).
 *
 * THE CONTRACT (normative).
 *  1. ATOMIC. `consumeOnce` / `advance` are single atomic read-modify-write operations across EVERY verifier
 *     instance that accepts actions for the same audience. Two concurrent calls with the same key: exactly one
 *     sees `true`.
 *  2. DURABLE FOR THE WHOLE VALIDITY WINDOW. A consumed key MUST be remembered at least until `retainUntilMs`
 *     (the guard passes `exp + clock skew`). A store may forget a key only after that instant. A restart that
 *     loses state before that instant resurrects the nonce: that is a violation of the contract, so an
 *     in-memory store is only correct for a single process whose lifetime covers the action lifetime.
 *  3. FAIL CLOSED. If a store cannot decide (unreachable, timeout, full) it MUST throw / reject. The guard
 *     converts that into a denial; it never treats a failure as "unseen".
 *  4. BYTE-EXACT KEYS. Nonces are compared as the exact UTF-8 bytes of the signed string. There is NO Unicode
 *     normalization (NFC/NFD, case folding): two visually identical strings with different bytes are
 *     different nonces (consistent with the wire spec, which signs the exact bytes and bounds them in UTF-8
 *     bytes). A nonce containing a lone surrogate (not valid UTF-8) is malformed and refused.
 *  5. NAMESPACED. The key binds the audience, the grant and the leaf holder with a length-prefixed encoding,
 *     so the same nonce under a different audience / grant / holder never collides or cross-consumes, and no
 *     choice of field contents can make two different tuples encode identically.
 */
import { replayDecide, replayNonceStage, replayPre, type ReplayFacts } from '@atlasauth/pca-verified-core';
import { b64u, hasLoneSurrogate, sha256, utf8 } from './hash';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS, type PCActn } from './pcactn';
import { MAX_AUD_LEN, MAX_NONCE_LEN } from './wire';

/** Upper bound (UTF-8 bytes) accepted for a grant ref / holder key / stream key component. */
export const MAX_REPLAY_COMPONENT_LEN = 512;

/**
 * Minimum time a consumed nonce must be retained after being consumed: the longest action lifetime plus the
 * clock-skew allowance in both directions. A pruning horizon below this can free a still-valid nonce.
 */
export const REPLAY_MIN_RETENTION_MS = PCACTN_MAX_LIFETIME_MS + 2 * PCACTN_MAX_SKEW_MS;

/** One-time-use store for opaque keys. See the module contract: atomic, durable until `retainUntilMs`, fail closed. */
export interface ReplayStore {
  /**
   * Record `key` as consumed. Resolves `true` iff this call is the first to consume it (no live record).
   * MUST remember the key until at least `retainUntilMs`. MUST reject (never resolve `true`) when it cannot
   * decide, including when `retainUntilMs` is not in the future relative to `nowMs`.
   */
  consumeOnce(key: string, retainUntilMs: number, nowMs: number): Promise<boolean>;
}

/** Strictly-monotonic counter store, one stream per key. Resolves `true` iff `counter` > the stored value. */
export interface CounterStore {
  advance(streamKey: string, counter: number): Promise<boolean>;
}

/** Length-prefixed, injective encoding of the parts, hashed to a fixed-size key. */
export function replayKey(namespace: string, ...parts: readonly string[]): string {
  const chunks: Uint8Array[] = [];
  for (const part of [namespace, ...parts]) {
    const bytes = utf8(part);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    chunks.push(len, bytes);
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  return `${namespace}:${b64u(sha256(buf))}`;
}

export type ReplayDenyCode = 'malformed' | 'audience' | 'not_yet_valid' | 'expired' | 'replay' | 'store_unavailable';
export type ReplayVerdict = { ok: true } | { ok: false; code: ReplayDenyCode; reason: string };

export interface GuardOptions {
  /** The audience this verifier answers for; compared byte-exactly with `pcactn.aud`. */
  aud: string;
  /** Verifier clock, epoch ms. */
  now: number;
  /** Clock skew tolerated in both directions between verifier instances (default and ceiling: PCACTN_MAX_SKEW_MS). */
  clockSkewMs?: number;
  /** When true (default) a PCActn without a `nonce` is refused; when false it is guarded by the counter alone. */
  requireNonce?: boolean;
  /** Per-(aud, grant, leaf holder) monotonic counter stream; when given the counter is advanced after the nonce. */
  counters?: CounterStore;
}

const isSafeNonNegInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
const u8len = (s: string): number => utf8(s).length;

/**
 * Decide whether a (signature-verified) PCActn may be accepted ONCE. Run it AFTER the PCActn verified:
 * consuming a nonce for an unauthenticated action would let anyone burn another party's nonces.
 *
 * ORDERING IS A SECURITY REQUIREMENT, not only a courtesy. The keys below embed `p.grant_ref`, and the guard does
 * NOT check it against the capability chain (that is `verifyPCActnCore`'s `grant_ref_bound` check: grant_ref MUST
 * equal cap_chain[0].id). A caller that consults the guard for an action that has not passed verification lets the
 * holder pick a fresh, empty (aud, grant_ref, holder) namespace per action and replay a counter / nonce freely.
 * Verify first; only on `allow` call the guard (see grant-ref-binding.test.ts).
 * Never throws: every failure, including a store failure, is a denial.
 */
export async function guardPCActnReplay(store: ReplayStore, p: PCActn, opts: GuardOptions): Promise<ReplayVerdict> {
  // TRUSTED GLUE + VERIFIED DECISION. The shape / primitive facts are evaluated here; the machine-proved replay decision
  // (formal/dafny/Replay.dfy: Pre, NonceStage, RetainUntil, Decide) fixes the check ORDER (no store call before every
  // pre-check passed), the nonce plan (consume-once) and the verdict. The store calls themselves stay here. See
  // docs/pca/security/verified-core.md. `scripts/check-verified-core.sh` fails if these calls are removed.
  const deny = (code: ReplayDenyCode, reason: string): ReplayVerdict => ({ ok: false, code, reason });
  const skew = Math.min(
    Number.isFinite(opts.clockSkewMs) && (opts.clockSkewMs as number) >= 0 ? (opts.clockSkewMs as number) : PCACTN_MAX_SKEW_MS,
    PCACTN_MAX_SKEW_MS,
  );
  const chain = p && typeof p === 'object' ? p.cap_chain : undefined;
  const leaf = Array.isArray(chain) ? chain[chain.length - 1] : undefined;
  const objectOk = !!p && typeof p === 'object';
  const leafOk = !!leaf && typeof leaf.holder === 'string' && typeof p.grant_ref === 'string';
  const componentsOk = leafOk && [p.grant_ref, leaf!.holder].every((c) => !(c.length === 0 || hasLoneSurrogate(c) || u8len(c) > MAX_REPLAY_COMPONENT_LEN));
  const hasNonce = objectOk && p.nonce !== undefined;
  const nonceOk = hasNonce && typeof p.nonce === 'string' && p.nonce.length !== 0 && u8len(p.nonce) <= MAX_NONCE_LEN && !hasLoneSurrogate(p.nonce);
  const facts: ReplayFacts = {
    nowOk: Number.isSafeInteger(opts.now),
    verifierAudOk: typeof opts.aud === 'string' && opts.aud.length !== 0 && u8len(opts.aud) <= MAX_AUD_LEN,
    isObject: objectOk,
    audMatches: objectOk && typeof p.aud === 'string' && p.aud === opts.aud,
    iatOk: objectOk && isSafeNonNegInt(p.iat),
    expOk: objectOk && isSafeNonNegInt(p.exp),
    iat: objectOk ? (p.iat as number) : 0,
    exp: objectOk ? (p.exp as number) : 0,
    now: opts.now,
    // iat/now are integers, so `iat > now + skew` is equivalent for the fractional skew and its floor; retention below uses the exact skew.
    skew: Math.floor(skew),
    leafOk,
    componentsOk,
    counterOk: objectOk && isSafeNonNegInt(p.counter),
    hasNonce,
    nonceOk,
    requireNonce: opts.requireNonce !== false,
    hasCounters: !!opts.counters,
  };
  const pre = replayPre(facts);
  if (pre !== undefined) return deny(pre, preReason(pre, facts));
  // The store contract takes the horizon as a JS number. exp + skew above 2^53-1 would round (a rounded horizon could free a
  // live nonce early), so refuse BEFORE any store call. Matches the Dafny model's exact `exp + skew` for every representable value.
  if (BigInt(p.exp) + BigInt(Math.ceil(skew)) > BigInt(Number.MAX_SAFE_INTEGER)) {
    return deny('malformed', 'exp + clock skew exceeds the safe-integer range (retention horizon not representable)');
  }
  const retainUntil = p.exp + skew;
  try {
    const stage = replayNonceStage(facts);
    let consumed = true;
    if (stage === 'deny') {
      return deny('malformed', hasNonce ? 'nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes' : 'a nonce is required');
    }
    if (stage === 'consume') {
      consumed = await store.consumeOnce(replayKey('pca-nonce/v1', opts.aud, p.grant_ref, leaf!.holder, p.nonce!), retainUntil, opts.now);
      if (replayDecide(facts, consumed, true) !== undefined) return deny('replay', 'nonce already consumed');
    }
    if (opts.counters) {
      const advanced = await opts.counters.advance(replayKey('pca-counter/v1', opts.aud, p.grant_ref, leaf!.holder), p.counter);
      if (replayDecide(facts, consumed, advanced) !== undefined) return deny('replay', 'counter is not greater than the last accepted');
    }
  } catch (e) {
    return deny('store_unavailable', `replay store failed closed: ${e instanceof Error ? e.message : 'error'}`);
  }
  return { ok: true };
}

function preReason(code: string, f: ReplayFacts): string {
  switch (code) {
    case 'audience':
      return 'the PCActn is for another audience';
    case 'not_yet_valid':
      return 'iat is in the future beyond the clock-skew allowance';
    case 'expired':
      return 'the PCActn has expired';
    default:
      if (!f.nowOk) return 'verifier clock is not an integer epoch-ms';
      if (!f.verifierAudOk) return 'verifier audience is invalid';
      if (!f.isObject) return 'not a PCActn';
      if (!(f.iatOk && f.expOk && f.exp > f.iat && f.exp - f.iat <= PCACTN_MAX_LIFETIME_MS)) return 'iat / exp are not a valid bounded window';
      if (!f.leafOk) return 'no leaf holder / grant';
      if (!f.componentsOk) return 'grant / holder is not a bounded string';
      return 'counter is not a non-negative safe integer';
  }
}

export interface InMemoryReplayStoreOptions {
  /** Hard cap on live entries; when full of live entries, `consumeOnce` REJECTS (fail closed) rather than evict. Default 100_000. */
  maxEntries?: number;
}

/**
 * Reference store. Correct ONLY for a single verifier process whose lifetime covers the action lifetime
 * (state is lost on restart, and it is not shared between instances). Atomic because JS is single-threaded
 * and `consumeOnce` has no await between check and set.
 */
export class InMemoryReplayStore implements ReplayStore, CounterStore {
  private readonly seen = new Map<string, number>();
  private readonly streams = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(opts: InMemoryReplayStoreOptions = {}) {
    this.maxEntries = opts.maxEntries ?? 100_000;
  }

  /** Number of live (unpruned) entries. */
  get size(): number {
    return this.seen.size;
  }

  /** Drop only entries whose retention has fully elapsed (`retainUntil < now`). Never frees a still-valid key. */
  prune(nowMs: number): number {
    let n = 0;
    for (const [k, until] of this.seen) {
      if (until < nowMs) {
        this.seen.delete(k);
        n += 1;
      }
    }
    return n;
  }

  consumeOnce(key: string, retainUntilMs: number, nowMs: number): Promise<boolean> {
    if (typeof key !== 'string' || key.length === 0 || !Number.isFinite(retainUntilMs) || !Number.isFinite(nowMs) || retainUntilMs < nowMs) {
      return Promise.reject(new RangeError('consumeOnce: invalid key or retention horizon'));
    }
    const until = this.seen.get(key);
    if (until !== undefined && until >= nowMs) return Promise.resolve(false);
    if (until === undefined && this.seen.size >= this.maxEntries) {
      this.prune(nowMs);
      if (this.seen.size >= this.maxEntries) return Promise.reject(new Error('replay store full of live entries'));
    }
    this.seen.set(key, Math.max(retainUntilMs, until ?? 0));
    return Promise.resolve(true);
  }

  advance(streamKey: string, counter: number): Promise<boolean> {
    if (typeof streamKey !== 'string' || streamKey.length === 0 || !isSafeNonNegInt(counter)) {
      return Promise.reject(new RangeError('advance: invalid stream or counter'));
    }
    const last = this.streams.get(streamKey);
    if (last !== undefined && !(counter > last)) return Promise.resolve(false);
    this.streams.set(streamKey, counter);
    return Promise.resolve(true);
  }
}
