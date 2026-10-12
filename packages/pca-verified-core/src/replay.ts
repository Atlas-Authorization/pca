import { Replay, bn, dstr, emptyDafnyMap } from './bridge';

export type ReplayDenyCode = 'malformed' | 'audience' | 'not_yet_valid' | 'expired' | 'replay' | 'store_unavailable';
const DENY: Array<[string, ReplayDenyCode]> = [
  ['is_Malformed', 'malformed'],
  ['is_Audience', 'audience'],
  ['is_NotYetValid', 'not_yet_valid'],
  ['is_Expired', 'expired'],
  ['is_Replay', 'replay'],
  ['is_StoreUnavailable', 'store_unavailable'],
];
const denyOf = (d: Record<string, boolean>): ReplayDenyCode => DENY.find(([f]) => d[f])![1];

/** Pre-evaluated facts for the replay guard decision (all primitive/shape checks done by the glue). */
export interface ReplayFacts {
  /** verifier clock is a safe integer. */
  nowOk: boolean;
  /** verifier audience is a non-empty bounded string. */
  verifierAudOk: boolean;
  isObject: boolean;
  /** typeof p.aud === 'string' && p.aud === verifier audience. */
  audMatches: boolean;
  iatOk: boolean;
  expOk: boolean;
  iat: number;
  exp: number;
  now: number;
  /** clock skew allowance in whole ms (0..60000). */
  skew: number;
  leafOk: boolean;
  componentsOk: boolean;
  counterOk: boolean;
  hasNonce: boolean;
  nonceOk: boolean;
  requireNonce: boolean;
  hasCounters: boolean;
}

function toFacts(f: ReplayFacts): unknown {
  const safe = (n: number, ok: boolean) => bn(ok && Number.isSafeInteger(n) ? n : 0);
  return Replay.Facts.create_Facts(
    f.nowOk, f.verifierAudOk, f.isObject, f.audMatches, f.iatOk, f.expOk,
    safe(f.iat, f.iatOk), safe(f.exp, f.expOk), safe(f.now, f.nowOk), bn(f.skew),
    f.leafOk, f.componentsOk, f.counterOk, f.hasNonce, f.nonceOk, f.requireNonce, f.hasCounters,
  );
}

/** Everything before the first store call (formal/dafny/Replay.dfy: Pre). `undefined` == proceed. */
export function replayPre(f: ReplayFacts): ReplayDenyCode | undefined {
  const r = Replay.__default.Pre(toFacts(f));
  return r.is_Some ? denyOf(r.dtor_v) : undefined;
}
/** What to do about the nonce once Pre passed. */
export function replayNonceStage(f: ReplayFacts): 'skip' | 'consume' | 'deny' {
  const s = Replay.__default.NonceStage(toFacts(f));
  return s.is_SkipNonce ? 'skip' : s.is_ConsumeNonce ? 'consume' : 'deny';
}
/** `exp + skew`: the retention horizon to hand to the store. */
export function replayRetainUntilExact(f: ReplayFacts): bigint {
  return BigInt(Replay.__default.RetainUntil(toFacts(f)).toFixed());
}
/**
 * `exp + skew` as a JS number. Exact for every safe-integer result; if the sum leaves the safe range (exp within `skew` of
 * 2^53) a doubles result would silently round, so this THROWS a RangeError instead. Use {@link replayRetainUntilExact} for the bigint.
 */
export function replayRetainUntil(f: ReplayFacts): number {
  const r = replayRetainUntilExact(f);
  if (r > BigInt(Number.MAX_SAFE_INTEGER) || r < BigInt(Number.MIN_SAFE_INTEGER)) {
    throw new RangeError(`pca-verified-core: retention horizon ${r} is outside the safe-integer range`);
  }
  return Number(r);
}
/** Full decision given the store answers for the calls the plan makes (consumedFirst: consumeOnce, advanced: counter). */
export function replayDecide(f: ReplayFacts, consumedFirst: boolean, advanced: boolean): ReplayDenyCode | undefined {
  const r = Replay.__default.Decide(toFacts(f), consumedFirst, advanced);
  return r.is_Some ? denyOf(r.dtor_v) : undefined;
}

/**
 * The verified reference model of the in-memory replay store (formal/dafny/Replay.dfy: ConsumeOnce / PruneMap /
 * AdvanceCounter). Immutable-state functions behind a mutable facade; used for differential testing of
 * `InMemoryReplayStore` and as an executable specification of the store contract.
 */
export class VerifiedReplayStoreModel {
  private s: any;
  constructor(maxEntries = 100_000) {
    this.s = Replay.Store.create_Store(emptyDafnyMap(), emptyDafnyMap(), bn(maxEntries));
  }
  /** 'accepted' (first consumption), 'dup' (still live), 'rejected' (invalid args or full of live entries). */
  consumeOnce(key: string, retainUntil: number, now: number): 'accepted' | 'dup' | 'rejected' {
    const [s2, out] = Replay.__default.ConsumeOnce(this.s, dstr(key), bn(retainUntil), bn(now));
    this.s = s2;
    return out.is_Accepted ? 'accepted' : out.is_Dup ? 'dup' : 'rejected';
  }
  prune(now: number): void {
    this.s = Replay.__default.Apply(this.s, Replay.Op.create_Prune(bn(now)))[0];
  }
  advance(stream: string, counter: number): 'accepted' | 'dup' | 'rejected' {
    const [s2, out] = Replay.__default.AdvanceCounter(this.s, dstr(stream), bn(counter));
    this.s = s2;
    return out.is_Accepted ? 'accepted' : out.is_Dup ? 'dup' : 'rejected';
  }
  get size(): number {
    return this.s.dtor_seen.length;
  }
}
