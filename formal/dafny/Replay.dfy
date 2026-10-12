// Replay.dfy - replay-guard decision (replay.ts: guardPCActnReplay) and the replay-store contract
// (InMemoryReplayStore) as verified pure functions.
//
// Trusted base: the real store's atomicity/durability (a distributed store is NOT modelled here); the glue's
// evaluation of string-shape facts (UTF-8 lengths, lone surrogates).  Proved: the exact deny order, that an
// accept implies every precondition and every required store result, and -- for the reference store model --
// replay freedom of nonces under every interleaving of consume/prune/advance with a non-decreasing clock, and
// strict monotonicity of accepted counters.
include "Common.dfy"
module Replay {
  import opened Common

  const MaxLifetimeMs: int := 3600000
  const MaxSkewMs: int := 60000

  datatype Deny = Malformed | Audience | NotYetValid | Expired | Replay | StoreUnavailable

  datatype Facts = Facts(
    nowOk: bool,          // verifier clock is a safe integer
    verifierAudOk: bool,  // verifier audience is a non-empty bounded string
    isObject: bool,       // PCActn is an object
    audMatches: bool,     // typeof p.aud === 'string' && p.aud === opts.aud
    iatOk: bool, expOk: bool,   // safe non-negative integers
    iat: int, exp: int, now: int, skew: int,
    leafOk: bool,         // leaf holder and grant_ref are strings
    componentsOk: bool,   // non-empty, no lone surrogate, bounded
    counterOk: bool,
    hasNonce: bool, nonceOk: bool, requireNonce: bool, hasCounters: bool)

  function WindowOk(f: Facts): bool {
    f.iatOk && f.expOk && f.exp > f.iat && f.exp - f.iat <= MaxLifetimeMs
  }

  // Everything before the first store call, in the normative order.
  function Pre(f: Facts): Option<Deny> {
    if !f.nowOk then Some(Malformed)
    else if !f.verifierAudOk then Some(Malformed)
    else if !f.isObject then Some(Malformed)
    else if !f.audMatches then Some(Audience)
    else if !WindowOk(f) then Some(Malformed)
    else if f.iat > f.now + f.skew then Some(NotYetValid)
    else if f.now > f.exp then Some(Expired)
    else if !f.leafOk then Some(Malformed)
    else if !f.componentsOk then Some(Malformed)
    else if !f.counterOk then Some(Malformed)
    else None
  }

  datatype NonceAct = SkipNonce | ConsumeNonce | DenyNonce

  function NonceStage(f: Facts): NonceAct {
    if f.hasNonce then (if f.nonceOk then ConsumeNonce else DenyNonce)
    else if f.requireNonce then DenyNonce
    else SkipNonce
  }

  function RetainUntil(f: Facts): int { f.exp + f.skew }

  // The full decision, given the results the store returned for the calls that the plan makes.
  function Decide(f: Facts, consumedFirst: bool, advanced: bool): Option<Deny> {
    match Pre(f) {
      case Some(d) => Some(d)
      case None =>
        match NonceStage(f) {
          case DenyNonce => Some(Malformed)
          case ConsumeNonce =>
            if !consumedFirst then Some(Replay)
            else if f.hasCounters && !advanced then Some(Replay) else None
          case SkipNonce =>
            if f.hasCounters && !advanced then Some(Replay) else None
        }
    }
  }

  // THEOREM (guard soundness): accept => all preconditions, and every required store call returned true.
  lemma GuardSound(f: Facts, c: bool, a: bool)
    requires Decide(f, c, a).None?
    ensures Pre(f).None?
    ensures f.nowOk && f.verifierAudOk && f.isObject && f.audMatches && WindowOk(f)
    ensures f.iat <= f.now + f.skew && f.now <= f.exp
    ensures f.leafOk && f.componentsOk && f.counterOk
    ensures NonceStage(f) != DenyNonce
    ensures NonceStage(f) == ConsumeNonce ==> c
    ensures f.hasCounters ==> a
  {}

  // THEOREM (audience binding, expiry, not-yet-valid are independent hard failures).
  lemma GuardHardFailures(f: Facts, c: bool, a: bool)
    ensures f.nowOk && f.verifierAudOk && f.isObject && !f.audMatches ==> Decide(f, c, a) == Some(Audience)
    ensures Pre(f).None? ==> f.now <= f.exp
    ensures Pre(f).None? ==> f.iat <= f.now + f.skew
  {}

  // THEOREM (determinism / extensionality): same facts and store answers => same verdict.
  lemma GuardDeterministic(f: Facts, c: bool, a: bool) ensures Decide(f, c, a) == Decide(f, c, a) {}

  // THEOREM (no store call before pre-checks): the nonce/counter stage is only reached when Pre passed.
  lemma NoStoreBeforePre(f: Facts, c: bool, a: bool)
    ensures Pre(f).Some? ==> Decide(f, c, a) == Pre(f)
  {}

  // =============================================================================================
  // Reference replay store (mirror of InMemoryReplayStore) and its contract
  // =============================================================================================
  datatype Store = Store(seen: map<string, int>, streams: map<string, int>, maxEntries: nat)
  datatype Op =
    | Consume(key: string, retain: int, now: int)
    | Prune(now: int)
    | Advance(stream: string, counter: int)

  datatype Out = Accepted | Dup | Rejected

  function PruneMap(m: map<string, int>, now: int): map<string, int> {
    map k | k in m && m[k] >= now :: m[k]
  }

  function ConsumeOnce(s: Store, key: string, retain: int, now: int): (Store, Out) {
    if |key| == 0 || retain < now then (s, Rejected)
    else if key in s.seen && s.seen[key] >= now then (s, Dup)
    else
      var s1 := if key !in s.seen && |s.seen| >= s.maxEntries then Store(PruneMap(s.seen, now), s.streams, s.maxEntries) else s;
      if key !in s1.seen && |s1.seen| >= s1.maxEntries then (s1, Rejected)
      else
        var until := if key in s1.seen then s1.seen[key] else 0;
        (Store(s1.seen[key := if retain >= until then retain else until], s1.streams, s1.maxEntries), Accepted)
  }

  function AdvanceCounter(s: Store, stream: string, c: int): (Store, Out) {
    if |stream| == 0 || c < 0 then (s, Rejected)
    else if stream in s.streams && !(c > s.streams[stream]) then (s, Dup)
    else (Store(s.seen, s.streams[stream := c], s.maxEntries), Accepted)
  }

  function Apply(s: Store, op: Op): (Store, Out) {
    match op {
      case Consume(k, r, n) => ConsumeOnce(s, k, r, n)
      case Prune(n) => (Store(PruneMap(s.seen, n), s.streams, s.maxEntries), Accepted)
      case Advance(st, c) => AdvanceCounter(s, st, c)
    }
  }

  function Run(s: Store, ops: seq<Op>): Store
    decreases |ops|
  {
    if |ops| == 0 then s else Run(Apply(s, ops[0]).0, ops[1..])
  }

  function OpTime(op: Op): Option<int> {
    match op { case Consume(_, _, n) => Some(n) case Prune(n) => Some(n) case Advance(_, _) => None }
  }

  // Every op in ops that carries a clock reads a time <= r.
  ghost predicate TimesAtMost(ops: seq<Op>, r: int) {
    forall i :: 0 <= i < |ops| ==> OpTime(ops[i]).Some? ==> OpTime(ops[i]).v <= r
  }

  // Key k is held at least until r.
  ghost predicate Held(s: Store, k: string, r: int) { k in s.seen && s.seen[k] >= r }

  lemma ApplyKeepsHeld(s: Store, op: Op, k: string, r: int)
    requires Held(s, k, r)
    requires OpTime(op).Some? ==> OpTime(op).v <= r
    ensures Held(Apply(s, op).0, k, r)
  {
    match op {
      case Prune(n) => { }
      case Advance(_, _) => { }
      case Consume(k2, r2, n) => {
        if |k2| != 0 && r2 >= n {
          var (s2, o) := ConsumeOnce(s, k2, r2, n);
          if !(k2 in s.seen && s.seen[k2] >= n) {
            // not a duplicate: possibly prune (keeps entries >= n; k has value >= r >= n), then maybe set k2
            assert s.seen[k] >= r >= n;
          }
        }
      }
    }
  }

  lemma RunKeepsHeld(s: Store, ops: seq<Op>, k: string, r: int)
    requires Held(s, k, r) && TimesAtMost(ops, r)
    ensures Held(Run(s, ops), k, r)
    decreases |ops|
  {
    if |ops| > 0 {
      ApplyKeepsHeld(s, ops[0], k, r);
      assert TimesAtMost(ops[1..], r) by {
        forall i | 0 <= i < |ops[1..]| ensures OpTime(ops[1..][i]).Some? ==> OpTime(ops[1..][i]).v <= r { assert ops[1..][i] == ops[i + 1]; }
      }
      RunKeepsHeld(Apply(s, ops[0]).0, ops[1..], k, r);
    }
  }

  // After an accepted Consume(k, retain r, now n), the key is held until r.
  lemma AcceptedHeld(s: Store, k: string, r: int, n: int)
    requires ConsumeOnce(s, k, r, n).1 == Accepted
    ensures Held(ConsumeOnce(s, k, r, n).0, k, r)
  {}

  // THEOREM (nonce replay freedom, every interleaving): if Consume(k, r, n) was Accepted, then after ANY
  // sequence of operations whose clock readings are all <= r (which a non-decreasing clock guarantees for every
  // operation made no later than r), a further Consume of k at time n2 <= r is NEVER Accepted.
  lemma NoDoubleAccept(s: Store, k: string, r: int, n: int, ops: seq<Op>, r2: int, n2: int)
    requires ConsumeOnce(s, k, r, n).1 == Accepted
    requires TimesAtMost(ops, r) && n2 <= r
    ensures ConsumeOnce(Run(ConsumeOnce(s, k, r, n).0, ops), k, r2, n2).1 != Accepted
  {
    AcceptedHeld(s, k, r, n);
    RunKeepsHeld(ConsumeOnce(s, k, r, n).0, ops, k, r);
    var s2 := Run(ConsumeOnce(s, k, r, n).0, ops);
    assert k in s2.seen && s2.seen[k] >= r >= n2;
  }

  // THEOREM (pruning is safe): Prune(n) never drops an entry still live at n (until >= n).
  lemma PruneKeepsLive(s: Store, n: int, k: string)
    requires k in s.seen && s.seen[k] >= n
    ensures k in PruneMap(s.seen, n) && PruneMap(s.seen, n)[k] == s.seen[k]
  {}

  // ---- counters: strictly increasing accepted values per stream ----
  lemma ApplyStreamMonotone(s: Store, op: Op, st: string)
    requires st in s.streams
    ensures st in Apply(s, op).0.streams && Apply(s, op).0.streams[st] >= s.streams[st]
  {}

  lemma RunStreamMonotone(s: Store, ops: seq<Op>, st: string)
    requires st in s.streams
    ensures st in Run(s, ops).streams && Run(s, ops).streams[st] >= s.streams[st]
    decreases |ops|
  {
    if |ops| > 0 { ApplyStreamMonotone(s, ops[0], st); RunStreamMonotone(Apply(s, ops[0]).0, ops[1..], st); }
  }

  // THEOREM (counter strictly increasing): once counter c is Accepted on a stream, any later Advance of that stream
  // with c2 <= c is never Accepted, whatever happened in between.
  lemma CounterStrict(s: Store, st: string, c: int, ops: seq<Op>, c2: int)
    requires |st| != 0 && c >= 0 && AdvanceCounter(s, st, c).1 == Accepted
    requires c2 <= c
    ensures AdvanceCounter(Run(AdvanceCounter(s, st, c).0, ops), st, c2).1 != Accepted
  {
    var s1 := AdvanceCounter(s, st, c).0;
    assert st in s1.streams && s1.streams[st] == c;
    RunStreamMonotone(s1, ops, st);
  }

  // THEOREM (store fail-closed): an invalid key or a retention horizon before `now` is never Accepted.
  lemma ConsumeFailClosed(s: Store, k: string, r: int, n: int)
    ensures (|k| == 0 || r < n) ==> ConsumeOnce(s, k, r, n).1 == Rejected
    ensures ConsumeOnce(s, k, r, n).1 == Accepted ==> |k| != 0 && r >= n
  {}
}
