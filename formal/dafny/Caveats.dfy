// Caveats.dfy - a concrete caveat algebra instantiating Chain's abstract attenuation theorem:
// verb pins, resource pins and expiry (min along the chain).
include "Common.dfy"
include "Chain.dfy"
module Caveats {
  import opened Common
  import opened Chain

  datatype Caveat =
    | VerbIn(verbs: set<string>)
    | ResIn(resources: set<string>)
    | ExpiresAt(t: int)
    | Opaque(id: string)

  datatype Act = Act(verb: string, resource: string, now: int)

  function Allows(c: Caveat, a: Act): bool {
    match c {
      case VerbIn(vs) => a.verb in vs
      case ResIn(rs) => a.resource in rs
      case ExpiresAt(t) => a.now <= t
      case Opaque(_) => true
    }
  }

  // Structural equality is the strictest possible caveat equality; the glue's canonical-hash equality
  // must imply it (the trusted contract).
  function Same(x: Caveat, y: Caveat): bool { x == y }

  lemma SameSound() ensures EqSound<Caveat, Act>(Same, Allows) {
    forall x: Caveat, y: Caveat, a: Act | Same(x, y) ensures Allows(x, a) == Allows(y, a) {}
  }

  // Effective expiry: min of every ExpiresAt; None = unbounded.
  function MinOpt(a: Option<int>, b: Option<int>): Option<int> {
    match a {
      case None => b
      case Some(x) => match b { case None => a case Some(y) => if x <= y then a else b }
    }
  }

  function EffExpiry(cs: seq<Caveat>): Option<int>
    decreases |cs|
  {
    if |cs| == 0 then None
    else MinOpt(match cs[0] { case ExpiresAt(t) => Some(t) case _ => None }, EffExpiry(cs[1..]))
  }

  // a is no later than b (None = +infinity)
  predicate NoLater(a: Option<int>, b: Option<int>) {
    match b {
      case None => true
      case Some(y) => a.Some? && a.v <= y
    }
  }

  lemma ExpiryMonotone(p: seq<Caveat>, c: seq<Caveat>)
    requires |p| <= |c| && c[..|p|] == p
    ensures NoLater(EffExpiry(c), EffExpiry(p))
    decreases |p|
  {
    if |p| > 0 {
      assert c[1..][..|p| - 1] == p[1..];
      ExpiryMonotone(p[1..], c[1..]);
      assert c[0] == p[0];
    } else {
      assert EffExpiry(p) == None;
    }
  }

  lemma AllowsImpliesBeforeExpiry(cs: seq<Caveat>, a: Act)
    requires Eff(cs, Allows, a)
    ensures EffExpiry(cs).Some? ==> a.now <= EffExpiry(cs).v
    decreases |cs|
  {
    if |cs| > 0 {
      assert Eff(cs[1..], Allows, a) by {
        forall k | 0 <= k < |cs[1..]| ensures Allows(cs[1..][k], a) { assert cs[1..][k] == cs[k + 1]; }
      }
      AllowsImpliesBeforeExpiry(cs[1..], a);
      assert Allows(cs[0], a);
    }
  }

  // Structural-prefix form of IsPrefixBy for Same
  lemma SamePrefix(p: seq<Caveat>, c: seq<Caveat>)
    requires IsPrefixBy(p, c, Same)
    ensures |p| <= |c| && c[..|p|] == p
  {
    assert forall j :: 0 <= j < |p| ==> c[j] == p[j];
    assert c[..|p|] == p;
  }

  // THEOREM (verbs/resources subset): in any accepted chain, if the action is permitted at hop i, it is
  // permitted at every ancestor hop j <= i; in particular its verb lies in every verb pin and its resource in
  // every resource pin carried by any ancestor, and it is not past any ancestor's expiry.
  lemma VerbResourceSubset<M>(hops: seq<Hop<M, Caveat>>, alloc: () -> Res<M>, a: Act, i: nat, j: nat, k: nat)
    requires VerifyChain(hops, Same, alloc) == ChainOk
    requires j <= i < |hops|
    requires Eff(hops[i].caveats, Allows, a)
    requires k < |hops[j].caveats|
    ensures hops[j].caveats[k].VerbIn? ==> a.verb in hops[j].caveats[k].verbs
    ensures hops[j].caveats[k].ResIn? ==> a.resource in hops[j].caveats[k].resources
    ensures hops[j].caveats[k].ExpiresAt? ==> a.now <= hops[j].caveats[k].t
  {
    SameSound();
    ChainAttenuates(hops, Same, alloc, Allows, a, i, j);
    assert Allows(hops[j].caveats[k], a);
  }

  // THEOREM (expiry = min): along an accepted chain the effective expiry never moves later.
  lemma ChainExpiryMonotone<M>(hops: seq<Hop<M, Caveat>>, alloc: () -> Res<M>, j: nat, i: nat)
    requires VerifyChain(hops, Same, alloc) == ChainOk
    requires j <= i < |hops|
    ensures NoLater(EffExpiry(hops[i].caveats), EffExpiry(hops[j].caveats))
    decreases i - j
  {
    ChainSound(hops, Same, alloc);
    if j < i {
      SamePrefix(hops[i - 1].caveats, hops[i].caveats);
      ExpiryMonotone(hops[i - 1].caveats, hops[i].caveats);
      ChainExpiryMonotone(hops, alloc, j, i - 1);
      NoLaterTrans(EffExpiry(hops[i].caveats), EffExpiry(hops[i - 1].caveats), EffExpiry(hops[j].caveats));
    }
  }

  lemma NoLaterTrans(a: Option<int>, b: Option<int>, c: Option<int>)
    requires NoLater(a, b) && NoLater(b, c)
    ensures NoLater(a, c)
  {}
}
