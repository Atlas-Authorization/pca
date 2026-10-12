// Common.dfy - shared vocabulary for the verified PCA decision core.
// Everything here is total, pure, and proved (no assume, no {:axiom}, no extern).
module Common {
  datatype Option<T> = None | Some(v: T)

  // Outcome of a lazily evaluated primitive or sub-check. `Err` carries an opaque diagnostic `m`
  // that the Dafny code never inspects (the TypeScript glue renders it).
  datatype Res<M> = Ok | Err(m: M)

  datatype Status = Pass | Fail | NotEnforced

  // ---------------------------------------------------------------------------------------------
  // Ordered check map: insertion-ordered association list with last-write-wins on the value but
  // first-insertion position (this is exactly the semantics of assigning to a JS object property).
  // ---------------------------------------------------------------------------------------------
  type Checks<N> = seq<(N, Status)>

  function Get<N(==)>(cs: Checks<N>, n: N): Option<Status>
    decreases |cs|
  {
    if |cs| == 0 then None
    else if cs[0].0 == n then Some(cs[0].1)
    else Get(cs[1..], n)
  }

  function Set<N(==)>(cs: Checks<N>, n: N, s: Status): Checks<N>
    decreases |cs|
  {
    if |cs| == 0 then [(n, s)]
    else if cs[0].0 == n then [(n, s)] + cs[1..]
    else [cs[0]] + Set(cs[1..], n, s)
  }

  function HasFail<N>(cs: Checks<N>): bool
    decreases |cs|
  {
    if |cs| == 0 then false else cs[0].1 == Fail || HasFail(cs[1..])
  }

  lemma GetSet<N(==)>(cs: Checks<N>, n: N, m: N, s: Status)
    ensures Get(Set(cs, n, s), n) == Some(s)
    ensures m != n ==> Get(Set(cs, n, s), m) == Get(cs, m)
    decreases |cs|
  {
    if |cs| > 0 && cs[0].0 != n { GetSet(cs[1..], n, m, s); }
  }

  lemma HasFailIff<N>(cs: Checks<N>)
    ensures HasFail(cs) <==> exists k :: 0 <= k < |cs| && cs[k].1 == Fail
    decreases |cs|
  {
    if |cs| > 0 {
      HasFailIff(cs[1..]);
      if cs[0].1 != Fail && HasFail(cs[1..]) {
        var k :| 0 <= k < |cs[1..]| && cs[1..][k].1 == Fail;
        assert cs[k+1].1 == Fail;
      }
    }
  }
}
