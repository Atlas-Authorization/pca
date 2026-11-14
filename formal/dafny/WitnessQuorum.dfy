// WitnessQuorum.dfy - the witness-quorum rule of ledger.ts `verifyWitnessCosignatures`, at code level, and the quorum
// intersection argument behind "no split view". Standalone (no includes).
//
// The code counts a cosignature only if it is valid, its key is in the trusted set, and the key was not counted before
// (a Set); the head is accepted iff the number of counted keys is at least the threshold. Counted(...) is that loop.
//   * CountedTrusted      : only trusted keys are ever counted;
//   * CountedHasValid     : every counted key has a valid cosignature in the list;
//   * DuplicateAddsNothing: repeating a key (even with a valid signature) does not raise the count;
//   * AcceptNeedsDistinct : acceptance implies at least `threshold` DISTINCT trusted keys with valid cosignatures;
//   * QuorumsShareHonest  : two accepting key sets out of n trusted witnesses, with f faulty and f + n < 2k, share a
//                           non-faulty key (so, with honest witnesses cosigning one consistent view, no split view).
// No assume, no axiom, no extern.
module WitnessQuorum {
  datatype Cosig = Cosig(key: int, valid: bool)

  function Counted(trusted: set<int>, cs: seq<Cosig>): set<int>
    decreases |cs|
  {
    if |cs| == 0 then {}
    else
      var last := cs[|cs| - 1];
      Counted(trusted, cs[..|cs| - 1]) + (if last.valid && last.key in trusted then {last.key} else {})
  }

  predicate Accept(trusted: set<int>, cs: seq<Cosig>, threshold: nat)
  {
    threshold >= 1 && |Counted(trusted, cs)| >= threshold
  }

  lemma CountedTrusted(trusted: set<int>, cs: seq<Cosig>)
    ensures Counted(trusted, cs) <= trusted
    decreases |cs|
  {
    if |cs| > 0 { CountedTrusted(trusted, cs[..|cs| - 1]); }
  }

  lemma CountedHasValid(trusted: set<int>, cs: seq<Cosig>, k: int)
    requires k in Counted(trusted, cs)
    ensures exists i :: 0 <= i < |cs| && cs[i].key == k && cs[i].valid
    decreases |cs|
  {
    var last := cs[|cs| - 1];
    if k in Counted(trusted, cs[..|cs| - 1]) {
      CountedHasValid(trusted, cs[..|cs| - 1], k);
      var i :| 0 <= i < |cs| - 1 && cs[..|cs| - 1][i].key == k && cs[..|cs| - 1][i].valid;
      assert cs[i] == cs[..|cs| - 1][i];
    } else {
      assert k == last.key && last.valid;
      assert cs[|cs| - 1].key == k && cs[|cs| - 1].valid;
    }
  }

  lemma DuplicateAddsNothing(trusted: set<int>, cs: seq<Cosig>, c: Cosig)
    requires c.key in Counted(trusted, cs)
    ensures Counted(trusted, cs + [c]) == Counted(trusted, cs)
  {
    assert (cs + [c])[..|cs + [c]| - 1] == cs;
    assert (cs + [c])[|cs + [c]| - 1] == c;
    CountedTrusted(trusted, cs);
  }

  lemma AcceptNeedsDistinct(trusted: set<int>, cs: seq<Cosig>, threshold: nat)
    requires Accept(trusted, cs, threshold)
    ensures exists S: set<int> :: S <= trusted && |S| >= threshold &&
              forall k :: k in S ==> exists i :: 0 <= i < |cs| && cs[i].key == k && cs[i].valid
  {
    var S := Counted(trusted, cs);
    CountedTrusted(trusted, cs);
    forall k | k in S
      ensures exists i :: 0 <= i < |cs| && cs[i].key == k && cs[i].valid
    { CountedHasValid(trusted, cs, k); }
  }

  lemma SubsetCard<T>(X: set<T>, Y: set<T>)
    requires X <= Y
    ensures |X| <= |Y|
  {
    if X != {} {
      var x :| x in X;
      SubsetCard(X - {x}, Y - {x});
    }
  }

  lemma UnionInter<T>(A: set<T>, B: set<T>)
    ensures |A + B| + |A * B| == |A| + |B|
  {
    if A == {} {
      assert A + B == B;
      assert A * B == {};
    } else {
      var x :| x in A;
      var A' := A - {x};
      UnionInter(A', B);
      assert A == A' + {x};
      if x in B {
        assert A + B == A' + B;
        assert A * B == A' * B + {x};
        assert x !in A' * B;
      } else {
        assert A + B == (A' + B) + {x};
        assert x !in A' + B;
        assert A * B == A' * B;
      }
    }
  }

  lemma QuorumsShareHonest(trusted: set<int>, A: set<int>, B: set<int>, faulty: set<int>, k: nat, f: nat)
    requires A <= trusted && B <= trusted
    requires |A| >= k && |B| >= k
    requires faulty <= trusted && |faulty| <= f
    requires f + |trusted| < 2 * k
    ensures exists w :: w in A && w in B && w !in faulty
  {
    UnionInter(A, B);
    SubsetCard(A + B, trusted);
    var I := A * B;
    assert |I| > f;
    if forall w :: w in I ==> w in faulty {
      assert I <= faulty;
      SubsetCard(I, faulty);
      assert false;
    }
    var w :| w in I && w !in faulty;
  }
}
