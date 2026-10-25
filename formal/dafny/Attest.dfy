// Attest.dfy - verified decision procedures for the ATTESTATION result-combination layer of PCA.
// Standalone (no includes); built by formal/dafny/build-ext.sh Attest.  No assume / {:axiom} / extern anywhere.
//
// Everything here is a PURE decision over abstract evidence: values compared for equality are interned to integers by the
// TypeScript adapter (0 is "empty / not a non-empty string" where stated), booleans stand for primitive evaluations
// (signature checks, regex shape checks, ...) which the glue performs, and opaque reasons are rendered by the glue.
//
//   A. MultiRoot   - createMultiRootVerifier: N-of-M corroboration, required roots, malformed results, identity reconciliation
//   B. Binding     - matchAgentBinding / requiresAttestation
//   C. Verify      - verifyAttestation stage order (first failure wins), nonce-age / validity-window arithmetic
//   D. Hook+Nonce  - createAttestationVerifier nonce-consume rule; memoryNonceStore model (single use within retention, never evicts live)
//   E. Allowlist   - verifyAllowlistManifest ordering + rollback; durable high-water machine; anchored-feed scan
module Attest {
  datatype Option<T> = None | Some(v: T)
  type Id = int

  // ==============================================================================================
  // A. MULTI-ROOT N-of-M
  // ==============================================================================================
  // A measured identity with each string field interned to an Id; 0 == "not a non-empty string" (the TS treats a
  // non-string or empty value as "this root says nothing about the field").
  datatype Ident = Ident(f0: Id, f1: Id, f2: Id, f3: Id, f4: Id, f5: Id, weightsMeasured: bool)
  // field order is the TS order: 0 model_id, 1 weights_digest, 2 runtime_measurement, 3 operator,
  // 4 system_prompt_digest, 5 tool_manifest_digest
  function Field(m: Ident, f: int): Id
  {
    if f == 0 then m.f0 else if f == 1 then m.f1 else if f == 2 then m.f2
    else if f == 3 then m.f3 else if f == 4 then m.f4 else m.f5
  }

  // What one root's verifier produced.
  //   `NullRes`   = null / undefined / non-object result: a FAILED root (skipped when optional, a denial when required).
  //   `Malformed` = reading the result itself threw (a hostile getter on `.ok` etc.) -> the outer catch of the TS (whole check fails).
  // A thrown verifier is already turned into `Res(ok := false, ..)` by the TS inner try/catch.
  datatype RootRes = Malformed | NullRes | Res(ok: bool, bound: bool, hasMeasured: bool, m: Ident)

  predicate Passes(r: RootRes) { r.Res? && r.ok && r.bound && r.hasMeasured }
  // A failed (non-aborting) root: a null result or a result that does not pass.
  predicate Failed(r: RootRes) { !r.Malformed? && !Passes(r) }

  datatype MFail = RequiredFailed(idx: int) | ErrorCaught | BelowThreshold(count: int) | Conflict(field: int, first: int, second: int)
  datatype MOut = MOk(m: Ident, idxs: seq<int>) | MFail(f: MFail)

  datatype St = Running(passed: seq<(int, Ident)>) | Done(f: MFail)

  function Step(st: St, i: int, req: bool, r: RootRes): St
  {
    match st
    case Done(_) => st
    case Running(p) =>
      if r.Malformed? then Done(ErrorCaught)
      else if Passes(r) then Running(p + [(i, r.m)])
      else if req then Done(RequiredFailed(i))
      else st
  }

  function Fold(reqs: seq<bool>, rs: seq<RootRes>, st: St, k: nat): St
    requires |reqs| == |rs| && k <= |rs|
    decreases |rs| - k
  {
    if k == |rs| then st else Fold(reqs, rs, Step(st, k, reqs[k], rs[k]), k + 1)
  }

  // ---- identity reconciliation (first non-empty wins; two different non-empty values conflict) ----
  datatype PickRes = Picked(v: Id) | Conflicted(who: int, at2: int)

  function PickRec(p: seq<(int, Ident)>, f: int, chosen: Id, wh: int): PickRes
    decreases |p|
  {
    if |p| == 0 then Picked(chosen)
    else
      var v := Field(p[0].1, f);
      if v == 0 then PickRec(p[1..], f, chosen, wh)
      else if chosen == 0 then PickRec(p[1..], f, v, p[0].0)
      else if chosen != v then Conflicted(wh, p[0].0)
      else PickRec(p[1..], f, chosen, wh)
  }

  predicate Compat(p: seq<(int, Ident)>, f: int, chosen: Id)
  {
    (forall a :: 0 <= a < |p| && Field(p[a].1, f) != 0 && chosen != 0 ==> Field(p[a].1, f) == chosen) &&
    (forall a, b :: 0 <= a < |p| && 0 <= b < |p| && Field(p[a].1, f) != 0 && Field(p[b].1, f) != 0 ==> Field(p[a].1, f) == Field(p[b].1, f))
  }

  predicate ConflictFree(p: seq<(int, Ident)>)
  {
    forall f :: 0 <= f <= 5 ==> Compat(p, f, 0)
  }

  predicate AllZero(p: seq<(int, Ident)>, f: int) { forall a :: 0 <= a < |p| ==> Field(p[a].1, f) == 0 }

  lemma PickSpec(p: seq<(int, Ident)>, f: int, chosen: Id, wh: int)
    ensures PickRec(p, f, chosen, wh).Picked? <==> Compat(p, f, chosen)
    ensures PickRec(p, f, chosen, wh).Picked? ==>
      var w := PickRec(p, f, chosen, wh).v;
      (chosen != 0 ==> w == chosen) &&
      (chosen == 0 && w != 0 ==> exists a :: 0 <= a < |p| && Field(p[a].1, f) == w) &&
      (chosen == 0 && w == 0 ==> AllZero(p, f))
    decreases |p|
  {
    if |p| == 0 {
    } else {
      var v := Field(p[0].1, f);
      PickSpec(p[1..], f, chosen, wh);
      if v == 0 {
        PickSpec(p[1..], f, chosen, wh);
        assert Compat(p, f, chosen) <==> Compat(p[1..], f, chosen) by {
          if Compat(p[1..], f, chosen) {
            forall a, b | 0 <= a < |p| && 0 <= b < |p| && Field(p[a].1, f) != 0 && Field(p[b].1, f) != 0
              ensures Field(p[a].1, f) == Field(p[b].1, f) {
              assert a >= 1 && b >= 1;
              assert p[1..][a-1] == p[a] && p[1..][b-1] == p[b];
            }
            forall a | 0 <= a < |p| && Field(p[a].1, f) != 0 && chosen != 0 ensures Field(p[a].1, f) == chosen {
              assert a >= 1; assert p[1..][a-1] == p[a];
            }
          }
          if Compat(p, f, chosen) {
            forall a, b | 0 <= a < |p[1..]| && 0 <= b < |p[1..]| && Field(p[1..][a].1, f) != 0 && Field(p[1..][b].1, f) != 0
              ensures Field(p[1..][a].1, f) == Field(p[1..][b].1, f) {
              assert p[1..][a] == p[a+1] && p[1..][b] == p[b+1];
            }
            forall a | 0 <= a < |p[1..]| && Field(p[1..][a].1, f) != 0 && chosen != 0 ensures Field(p[1..][a].1, f) == chosen {
              assert p[1..][a] == p[a+1];
            }
          }
        }
        assert AllZero(p, f) <==> AllZero(p[1..], f) by {
          if AllZero(p[1..], f) { forall a | 0 <= a < |p| ensures Field(p[a].1, f) == 0 { if a >= 1 { assert p[1..][a-1] == p[a]; } } }
          if AllZero(p, f) { forall a | 0 <= a < |p[1..]| ensures Field(p[1..][a].1, f) == 0 { assert p[1..][a] == p[a+1]; } }
        }
        if PickRec(p, f, chosen, wh).Picked? && PickRec(p, f, chosen, wh).v != 0 && chosen == 0 {
          var a :| 0 <= a < |p[1..]| && Field(p[1..][a].1, f) == PickRec(p, f, chosen, wh).v;
          assert p[1..][a] == p[a+1];
        }
      } else if chosen == 0 {
        PickSpec(p[1..], f, v, p[0].0);
        assert Compat(p, f, 0) <==> Compat(p[1..], f, v) by {
          if Compat(p, f, 0) {
            forall a | 0 <= a < |p[1..]| && Field(p[1..][a].1, f) != 0 ensures Field(p[1..][a].1, f) == v {
              assert p[1..][a] == p[a+1];
            }
            forall a, b | 0 <= a < |p[1..]| && 0 <= b < |p[1..]| && Field(p[1..][a].1, f) != 0 && Field(p[1..][b].1, f) != 0
              ensures Field(p[1..][a].1, f) == Field(p[1..][b].1, f) {
              assert p[1..][a] == p[a+1] && p[1..][b] == p[b+1];
            }
          }
          if Compat(p[1..], f, v) {
            forall a, b | 0 <= a < |p| && 0 <= b < |p| && Field(p[a].1, f) != 0 && Field(p[b].1, f) != 0
              ensures Field(p[a].1, f) == Field(p[b].1, f) {
              if a >= 1 { assert p[1..][a-1] == p[a]; }
              if b >= 1 { assert p[1..][b-1] == p[b]; }
            }
          }
        }
        if PickRec(p, f, chosen, wh).Picked? {
          var w := PickRec(p, f, chosen, wh).v;
          assert w == v || (exists a :: 0 <= a < |p[1..]| && Field(p[1..][a].1, f) == w) || true;
          // PickRec(p[1..], f, v, ..) returns v when chosen' != 0 (second ensures of the recursive call)
          assert w == v;
          assert Field(p[0].1, f) == w;
        }
      } else if chosen != v {
        assert !Compat(p, f, chosen) by {
          assert 0 < |p| && Field(p[0].1, f) != 0 && chosen != 0 && Field(p[0].1, f) != chosen;
        }
      } else {
        assert Compat(p, f, chosen) <==> Compat(p[1..], f, chosen) by {
          if Compat(p[1..], f, chosen) {
            forall a, b | 0 <= a < |p| && 0 <= b < |p| && Field(p[a].1, f) != 0 && Field(p[b].1, f) != 0
              ensures Field(p[a].1, f) == Field(p[b].1, f) {
              if a >= 1 { assert p[1..][a-1] == p[a]; }
              if b >= 1 { assert p[1..][b-1] == p[b]; }
            }
            forall a | 0 <= a < |p| && Field(p[a].1, f) != 0 && chosen != 0 ensures Field(p[a].1, f) == chosen {
              if a >= 1 { assert p[1..][a-1] == p[a]; }
            }
          }
          if Compat(p, f, chosen) {
            forall a, b | 0 <= a < |p[1..]| && 0 <= b < |p[1..]| && Field(p[1..][a].1, f) != 0 && Field(p[1..][b].1, f) != 0
              ensures Field(p[1..][a].1, f) == Field(p[1..][b].1, f) {
              assert p[1..][a] == p[a+1] && p[1..][b] == p[b+1];
            }
            forall a | 0 <= a < |p[1..]| && Field(p[1..][a].1, f) != 0 && chosen != 0 ensures Field(p[1..][a].1, f) == chosen {
              assert p[1..][a] == p[a+1];
            }
          }
        }
      }
    }
  }

  datatype Recon = Merged(m: Ident) | Clash(field: int, first: int, second: int)

  function Reconcile(p: seq<(int, Ident)>): Recon
  {
    var r0 := PickRec(p, 0, 0, -1);
    if r0.Conflicted? then Clash(0, r0.who, r0.at2) else
    var r1 := PickRec(p, 1, 0, -1);
    if r1.Conflicted? then Clash(1, r1.who, r1.at2) else
    var r2 := PickRec(p, 2, 0, -1);
    if r2.Conflicted? then Clash(2, r2.who, r2.at2) else
    var r3 := PickRec(p, 3, 0, -1);
    if r3.Conflicted? then Clash(3, r3.who, r3.at2) else
    var r4 := PickRec(p, 4, 0, -1);
    if r4.Conflicted? then Clash(4, r4.who, r4.at2) else
    var r5 := PickRec(p, 5, 0, -1);
    if r5.Conflicted? then Clash(5, r5.who, r5.at2) else
    Merged(Ident(r0.v, r1.v, r2.v, r3.v, r4.v, r5.v, WeightsMeasuredOf(p, r1.v)))
  }

  // weights_measured is true only when the chosen non-empty weights digest came from a root that itself measured it.
  predicate WeightsMeasuredOf(p: seq<(int, Ident)>, w: Id)
  {
    w != 0 && exists a :: 0 <= a < |p| && p[a].1.weightsMeasured && p[a].1.f1 == w
  }

  lemma ReconcileIff(p: seq<(int, Ident)>)
    ensures Reconcile(p).Merged? <==> ConflictFree(p)
    ensures Reconcile(p).Merged? ==>
      forall f :: 0 <= f <= 5 ==>
        (forall a :: 0 <= a < |p| && Field(p[a].1, f) != 0 ==> Field(p[a].1, f) == Field(Reconcile(p).m, f)) &&
        (Field(Reconcile(p).m, f) != 0 ==> exists a :: 0 <= a < |p| && Field(p[a].1, f) == Field(Reconcile(p).m, f)) &&
        (Field(Reconcile(p).m, f) == 0 ==> AllZero(p, f))
    ensures Reconcile(p).Merged? ==> (Reconcile(p).m.weightsMeasured <==> WeightsMeasuredOf(p, Reconcile(p).m.f1))
  {
    forall f | 0 <= f <= 5 { PickSpec(p, f, 0, -1); }
    if ConflictFree(p) {
      assert PickRec(p, 0, 0, -1).Picked? && PickRec(p, 1, 0, -1).Picked? && PickRec(p, 2, 0, -1).Picked?;
      assert PickRec(p, 3, 0, -1).Picked? && PickRec(p, 4, 0, -1).Picked? && PickRec(p, 5, 0, -1).Picked?;
    }
    if Reconcile(p).Merged? {
      assert PickRec(p, 0, 0, -1).Picked? && PickRec(p, 1, 0, -1).Picked? && PickRec(p, 2, 0, -1).Picked?;
      assert PickRec(p, 3, 0, -1).Picked? && PickRec(p, 4, 0, -1).Picked? && PickRec(p, 5, 0, -1).Picked?;
      forall f | 0 <= f <= 5 ensures Compat(p, f, 0) {}
      var m := Reconcile(p).m;
      forall f | 0 <= f <= 5 {
        assert Field(m, f) == PickRec(p, f, 0, -1).v;
      }
    }
  }

  function Collect(rs: seq<RootRes>, k: nat): seq<(int, Ident)>
    requires k <= |rs|
    decreases |rs| - k
  {
    if k == |rs| then []
    else (if Passes(rs[k]) then [(k, rs[k].m)] else []) + Collect(rs, k + 1)
  }

  function FirstBad(reqs: seq<bool>, rs: seq<RootRes>, k: nat): Option<MFail>
    requires |reqs| == |rs| && k <= |rs|
    decreases |rs| - k
  {
    if k == |rs| then None
    else if rs[k].Malformed? then Some(ErrorCaught)
    else if reqs[k] && !Passes(rs[k]) then Some(RequiredFailed(k))
    else FirstBad(reqs, rs, k + 1)
  }

  lemma FoldDone(reqs: seq<bool>, rs: seq<RootRes>, f: MFail, k: nat)
    requires |reqs| == |rs| && k <= |rs|
    ensures Fold(reqs, rs, Done(f), k) == Done(f)
    decreases |rs| - k
  {
    if k < |rs| { FoldDone(reqs, rs, f, k + 1); }
  }

  lemma FoldIs(reqs: seq<bool>, rs: seq<RootRes>, p: seq<(int, Ident)>, k: nat)
    requires |reqs| == |rs| && k <= |rs|
    ensures Fold(reqs, rs, Running(p), k) ==
      (match FirstBad(reqs, rs, k) case Some(f) => Done(f) case None => Running(p + Collect(rs, k)))
    decreases |rs| - k
  {
    if k < |rs| {
      var st := Step(Running(p), k, reqs[k], rs[k]);
      if rs[k].Malformed? {
        FoldDone(reqs, rs, ErrorCaught, k + 1);
      } else if Passes(rs[k]) {
        FoldIs(reqs, rs, p + [(k, rs[k].m)], k + 1);
        assert p + Collect(rs, k) == (p + [(k, rs[k].m)]) + Collect(rs, k + 1);
      } else if reqs[k] {
        FoldDone(reqs, rs, RequiredFailed(k), k + 1);
      } else {
        FoldIs(reqs, rs, p, k + 1);
      }
    }
  }

  function Idxs(p: seq<(int, Ident)>): seq<int> { seq(|p|, i requires 0 <= i < |p| => p[i].0) }

  function Finish(thr: int, st: St): MOut
  {
    match st
    case Done(f) => MFail(f)
    case Running(p) =>
      if |p| < thr then MFail(BelowThreshold(|p|))
      else
        match Reconcile(p)
        case Clash(f, a, b) => MFail(Conflict(f, a, b))
        case Merged(m) => MOk(m, Idxs(p))
  }

  // The verifier. reqs[i] == roots[i].required === true; thr == policy.threshold.
  function Run(reqs: seq<bool>, rs: seq<RootRes>, thr: int): MOut
    requires |reqs| == |rs|
  {
    Finish(thr, Fold(reqs, rs, Running([]), 0))
  }

  // Specification of acceptance, independent of the order of the roots.
  predicate NoBad(reqs: seq<bool>, rs: seq<RootRes>)
    requires |reqs| == |rs|
  {
    forall i :: 0 <= i < |rs| ==> !rs[i].Malformed? && (reqs[i] ==> Passes(rs[i]))
  }

  predicate OkSpec(reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires |reqs| == |rs|
  {
    NoBad(reqs, rs) && |Collect(rs, 0)| >= thr && ConflictFree(Collect(rs, 0))
  }

  lemma FirstBadNone(reqs: seq<bool>, rs: seq<RootRes>, k: nat)
    requires |reqs| == |rs| && k <= |rs|
    ensures FirstBad(reqs, rs, k).None? <==> forall i :: k <= i < |rs| ==> !rs[i].Malformed? && (reqs[i] ==> Passes(rs[i]))
    decreases |rs| - k
  {
    if k < |rs| { FirstBadNone(reqs, rs, k + 1); }
  }

  // THEOREM (soundness + completeness): the verifier accepts iff no result is malformed, every required root passed,
  // at least `thr` roots passed, and the passing identities do not contradict each other.
  lemma RunIff(reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires |reqs| == |rs|
    ensures Run(reqs, rs, thr).MOk? <==> OkSpec(reqs, rs, thr)
  {
    FoldIs(reqs, rs, [], 0);
    FirstBadNone(reqs, rs, 0);
    assert [] + Collect(rs, 0) == Collect(rs, 0);
    if FirstBad(reqs, rs, 0).None? {
      ReconcileIff(Collect(rs, 0));
    }
  }

  // Collected entries really are the passing roots, in index order, each index at most once.
  lemma CollectSpec(rs: seq<RootRes>, k: nat)
    requires k <= |rs|
    ensures forall a :: 0 <= a < |Collect(rs, k)| ==>
      k <= Collect(rs, k)[a].0 < |rs| && Passes(rs[Collect(rs, k)[a].0]) && rs[Collect(rs, k)[a].0].m == Collect(rs, k)[a].1
    ensures forall a, b :: 0 <= a < b < |Collect(rs, k)| ==> Collect(rs, k)[a].0 < Collect(rs, k)[b].0
    ensures forall i :: k <= i < |rs| && Passes(rs[i]) ==> exists a :: 0 <= a < |Collect(rs, k)| && Collect(rs, k)[a].0 == i
    ensures |Collect(rs, k)| <= |rs| - k
    decreases |rs| - k
  {
    if k < |rs| {
      CollectSpec(rs, k + 1);
      if Passes(rs[k]) {
        var c := Collect(rs, k);
        assert c == [(k, rs[k].m)] + Collect(rs, k + 1);
        forall i | k <= i < |rs| && Passes(rs[i]) ensures exists a :: 0 <= a < |c| && c[a].0 == i {
          if i == k { assert c[0].0 == k; } else {
            var a :| 0 <= a < |Collect(rs, k + 1)| && Collect(rs, k + 1)[a].0 == i;
            assert c[a + 1] == Collect(rs, k + 1)[a];
          }
        }
        forall a, b | 0 <= a < b < |c| ensures c[a].0 < c[b].0 {
          if a == 0 { assert c[b] == Collect(rs, k + 1)[b - 1]; } else {
            assert c[a] == Collect(rs, k + 1)[a - 1] && c[b] == Collect(rs, k + 1)[b - 1];
          }
        }
        forall a | 0 <= a < |c| ensures k <= c[a].0 < |rs| && Passes(rs[c[a].0]) && rs[c[a].0].m == c[a].1 {
          if a > 0 { assert c[a] == Collect(rs, k + 1)[a - 1]; }
        }
      } else {
        assert Collect(rs, k) == Collect(rs, k + 1);
      }
    }
  }

  // THEOREM (fail closed / no double count): any accept has these properties.
  lemma RunSound(reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires |reqs| == |rs|
    ensures Run(reqs, rs, thr).MOk? ==>
      // no malformed or missing evidence anywhere, every required root passed
      (forall i :: 0 <= i < |rs| ==> !rs[i].Malformed?) &&
      (forall i :: 0 <= i < |rs| && reqs[i] ==> Passes(rs[i])) &&
      // the counted roots are distinct roots (strictly increasing indices), each one really passing, and there are >= thr
      var o := Run(reqs, rs, thr);
      |o.idxs| >= thr &&
      (forall a :: 0 <= a < |o.idxs| ==> 0 <= o.idxs[a] < |rs| && Passes(rs[o.idxs[a]])) &&
      (forall a, b :: 0 <= a < b < |o.idxs| ==> o.idxs[a] < o.idxs[b]) &&
      |o.idxs| <= |rs| &&
      // every passing root is counted
      (forall i :: 0 <= i < |rs| && Passes(rs[i]) ==> i in o.idxs) &&
      // no accepted identity conflicts with the reconciled one; the reconciled one invents nothing
      (forall a, f :: 0 <= a < |o.idxs| && 0 <= f <= 5 && Field(rs[o.idxs[a]].m, f) != 0 ==> Field(rs[o.idxs[a]].m, f) == Field(o.m, f)) &&
      (forall f :: 0 <= f <= 5 && Field(o.m, f) != 0 ==> exists a :: 0 <= a < |o.idxs| && Field(rs[o.idxs[a]].m, f) == Field(o.m, f)) &&
      (o.m.weightsMeasured ==> o.m.f1 != 0 && exists a :: 0 <= a < |o.idxs| && rs[o.idxs[a]].m.weightsMeasured && rs[o.idxs[a]].m.f1 == o.m.f1)
  {
    RunIff(reqs, rs, thr);
    if Run(reqs, rs, thr).MOk? {
      var p := Collect(rs, 0);
      CollectSpec(rs, 0);
      ReconcileIff(p);
      var o := Run(reqs, rs, thr);
      FoldIs(reqs, rs, [], 0);
      FirstBadNone(reqs, rs, 0);
      assert [] + Collect(rs, 0) == Collect(rs, 0);
      assert Fold(reqs, rs, Running([]), 0) == Running(p);
      assert |p| >= thr;
      assert o == MOk(Reconcile(p).m, Idxs(p));
      forall i | 0 <= i < |rs| && Passes(rs[i]) ensures i in o.idxs {
        var a :| 0 <= a < |p| && p[a].0 == i;
        assert o.idxs[a] == i;
      }
      forall a, f | 0 <= a < |o.idxs| && 0 <= f <= 5 && Field(rs[o.idxs[a]].m, f) != 0 ensures Field(rs[o.idxs[a]].m, f) == Field(o.m, f) {
        assert p[a].1 == rs[p[a].0].m;
      }
      forall f | 0 <= f <= 5 && Field(o.m, f) != 0 ensures exists a :: 0 <= a < |o.idxs| && Field(rs[o.idxs[a]].m, f) == Field(o.m, f) {
        var a :| 0 <= a < |p| && Field(p[a].1, f) == Field(o.m, f);
        assert p[a].1 == rs[p[a].0].m;
      }
      if o.m.weightsMeasured {
        var a :| 0 <= a < |p| && p[a].1.weightsMeasured && p[a].1.f1 == o.m.f1;
        assert p[a].1 == rs[p[a].0].m;
        assert rs[o.idxs[a]].m.weightsMeasured;
      }
    }
  }

  // THEOREM (fail closed, explicit forms)
  lemma RunFailsClosed(reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires |reqs| == |rs|
    ensures (exists i :: 0 <= i < |rs| && rs[i].Malformed?) ==> Run(reqs, rs, thr).MFail?
    ensures (exists i :: 0 <= i < |rs| && reqs[i] && !Passes(rs[i])) ==> Run(reqs, rs, thr).MFail?
    ensures |Collect(rs, 0)| < thr ==> Run(reqs, rs, thr).MFail?
    ensures !ConflictFree(Collect(rs, 0)) ==> Run(reqs, rs, thr).MFail?
    ensures thr > |rs| ==> Run(reqs, rs, thr).MFail?
  {
    RunIff(reqs, rs, thr);
    CollectSpec(rs, 0);
  }

  // Constructor validation (the TS throws at construction): ids non-empty & distinct, 1 <= thr <= |ids|.
  predicate ValidPolicy(ids: seq<Id>, thr: int)
  {
    |ids| >= 1 && 1 <= thr <= |ids| && (forall i :: 0 <= i < |ids| ==> ids[i] != 0) &&
    (forall i, j :: 0 <= i < j < |ids| ==> ids[i] != ids[j])
  }

  // THEOREM (duplicates do not double count): under a valid policy the roots counted by an accept have pairwise distinct ids.
  lemma CountedIdsDistinct(ids: seq<Id>, reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires ValidPolicy(ids, thr) && |ids| == |rs| && |reqs| == |rs|
    ensures Run(reqs, rs, thr).MOk? ==>
      forall a, b :: 0 <= a < b < |Run(reqs, rs, thr).idxs| ==> 0 <= Run(reqs, rs, thr).idxs[a] < |ids| && 0 <= Run(reqs, rs, thr).idxs[b] < |ids| && ids[Run(reqs, rs, thr).idxs[a]] != ids[Run(reqs, rs, thr).idxs[b]]
  {
    RunSound(reqs, rs, thr);
    if Run(reqs, rs, thr).MOk? {
      var o := Run(reqs, rs, thr);
      forall a, b | 0 <= a < b < |o.idxs| ensures ids[o.idxs[a]] != ids[o.idxs[b]] {
        assert 0 <= o.idxs[a] < |rs| && 0 <= o.idxs[b] < |rs| && o.idxs[a] < o.idxs[b];
      }
    }
  }

  // ---- monotonicity ----
  lemma CollectAppend(rs: seq<RootRes>, x: RootRes, k: nat)
    requires k <= |rs|
    ensures Collect(rs + [x], k) == Collect(rs, k) + (if Passes(x) then [(|rs|, x.m)] else [])
    decreases |rs| - k
  {
    if k < |rs| {
      assert (rs + [x])[k] == rs[k];
      CollectAppend(rs, x, k + 1);
      assert (rs + [x])[..|rs|] == rs;
    } else {
      assert (rs + [x])[|rs|] == x;
      assert Collect(rs + [x], k + 1) == [];
    }
  }

  lemma NoBadAppend(reqs: seq<bool>, rs: seq<RootRes>, b: bool, x: RootRes)
    requires |reqs| == |rs|
    ensures NoBad(reqs + [b], rs + [x]) <==> NoBad(reqs, rs) && !x.Malformed? && (b ==> Passes(x))
  {
    if NoBad(reqs, rs) && !x.Malformed? && (b ==> Passes(x)) {
      forall i | 0 <= i < |rs| + 1 ensures !(rs + [x])[i].Malformed? && ((reqs + [b])[i] ==> Passes((rs + [x])[i])) {
        if i < |rs| { assert (rs + [x])[i] == rs[i] && (reqs + [b])[i] == reqs[i]; } else { assert (rs + [x])[i] == x && (reqs + [b])[i] == b; }
      }
    }
    if NoBad(reqs + [b], rs + [x]) {
      assert (rs + [x])[|rs|] == x && (reqs + [b])[|rs|] == b;
      forall i | 0 <= i < |rs| ensures !rs[i].Malformed? && (reqs[i] ==> Passes(rs[i])) {
        assert (rs + [x])[i] == rs[i] && (reqs + [b])[i] == reqs[i];
      }
    }
  }

  lemma ConflictFreeSubseq(p: seq<(int, Ident)>, q: seq<(int, Ident)>)
    ensures ConflictFree(p + q) ==> ConflictFree(p)
  {
    if ConflictFree(p + q) {
      forall f | 0 <= f <= 5 ensures Compat(p, f, 0) {
        assert Compat(p + q, f, 0);
        forall a, b | 0 <= a < |p| && 0 <= b < |p| && Field(p[a].1, f) != 0 && Field(p[b].1, f) != 0 ensures Field(p[a].1, f) == Field(p[b].1, f) {
          assert (p + q)[a] == p[a] && (p + q)[b] == p[b];
        }
      }
    }
  }

  // THEOREM: appending a root whose verifier FAILED (non-required) changes nothing; appending a malformed result or a failing
  // REQUIRED root can never produce an accept.
  lemma AppendFailing(reqs: seq<bool>, rs: seq<RootRes>, x: RootRes, thr: int)
    requires |reqs| == |rs| && 0 <= thr
    ensures Failed(x) ==> (OkSpec(reqs + [false], rs + [x], thr) <==> OkSpec(reqs, rs, thr))
    ensures Failed(x) ==> Run(reqs + [false], rs + [x], thr) == Run(reqs, rs, thr)
    ensures x.Malformed? ==> !OkSpec(reqs + [false], rs + [x], thr) && !OkSpec(reqs + [true], rs + [x], thr)
    ensures Failed(x) ==> !OkSpec(reqs + [true], rs + [x], thr)
  {
    CollectAppend(rs, x, 0);
    NoBadAppend(reqs, rs, false, x);
    NoBadAppend(reqs, rs, true, x);
    if Failed(x) {
      assert Collect(rs + [x], 0) == Collect(rs, 0);
      FoldIs(reqs + [false], rs + [x], [], 0);
      FoldIs(reqs, rs, [], 0);
      FirstBadNone(reqs + [false], rs + [x], 0);
      FirstBadNone(reqs, rs, 0);
      RunIff(reqs + [false], rs + [x], thr);
      RunIff(reqs, rs, thr);
      if OkSpec(reqs, rs, thr) {
        assert Run(reqs, rs, thr).MOk?;
      }
      RunSameOutcome(reqs, rs, x, thr);
    }
  }

  // Appending a failing optional root yields the identical output (not just the same accept/reject).
  lemma RunSameOutcome(reqs: seq<bool>, rs: seq<RootRes>, x: RootRes, thr: int)
    requires |reqs| == |rs| && Failed(x)
    ensures Run(reqs + [false], rs + [x], thr) == Run(reqs, rs, thr)
  {
    FoldAppendOptional(reqs, rs, x, Running([]), 0);
    FoldAppendOptionalDone(reqs, rs, x);
  }

  lemma FoldAppendOptionalDone(reqs: seq<bool>, rs: seq<RootRes>, x: RootRes) {}

  lemma FoldAppendOptional(reqs: seq<bool>, rs: seq<RootRes>, x: RootRes, st: St, k: nat)
    requires |reqs| == |rs| && k <= |rs| && Failed(x)
    ensures Fold(reqs + [false], rs + [x], st, k) == Fold(reqs, rs, st, k)
    decreases |rs| - k
  {
    if k < |rs| {
      assert (reqs + [false])[k] == reqs[k] && (rs + [x])[k] == rs[k];
      FoldAppendOptional(reqs, rs, x, Step(st, k, reqs[k], rs[k]), k + 1);
    } else {
      assert (rs + [x])[|rs|] == x;
      assert Step(st, |rs|, false, x) == st;
    }
  }

  // THEOREM (reject -> accept only by reaching the threshold): adding a root can turn a reject into an accept only when the
  // base had no malformed/required failure, was merely BELOW the threshold, and the added root itself passes. A reject caused
  // by a malformed result, a failed required root or an identity conflict is permanent under appending.
  lemma RejectToAccept(reqs: seq<bool>, rs: seq<RootRes>, b: bool, x: RootRes, thr: int)
    requires |reqs| == |rs|
    ensures !OkSpec(reqs, rs, thr) && OkSpec(reqs + [b], rs + [x], thr) ==>
      NoBad(reqs, rs) && |Collect(rs, 0)| < thr && Passes(x) && ConflictFree(Collect(rs, 0))
  {
    CollectAppend(rs, x, 0);
    NoBadAppend(reqs, rs, b, x);
    if !OkSpec(reqs, rs, thr) && OkSpec(reqs + [b], rs + [x], thr) {
      ConflictFreeSubseq(Collect(rs, 0), if Passes(x) then [(|rs|, x.m)] else []);
    }
  }

  // THEOREM (adding a passing root never turns an accept into a reject EXCEPT through the identity-conflict rule): if the base
  // accepts and the new root passes, the result is an accept iff the new identity is compatible with every counted one.
  lemma AppendPassing(reqs: seq<bool>, rs: seq<RootRes>, b: bool, x: RootRes, thr: int)
    requires |reqs| == |rs| && Passes(x)
    ensures OkSpec(reqs, rs, thr) ==> (OkSpec(reqs + [b], rs + [x], thr) <==> ConflictFree(Collect(rs, 0) + [(|rs|, x.m)]))
  {
    CollectAppend(rs, x, 0);
    NoBadAppend(reqs, rs, b, x);
    assert |Collect(rs + [x], 0)| == |Collect(rs, 0)| + 1;
  }

  // THEOREM: raising the threshold never turns a reject into an accept.
  lemma ThresholdAntitone(reqs: seq<bool>, rs: seq<RootRes>, t1: int, t2: int)
    requires |reqs| == |rs| && t1 <= t2
    ensures OkSpec(reqs, rs, t2) ==> OkSpec(reqs, rs, t1)
  {}

  // THEOREM (a null result is a failed root, not an abort): replacing a root's result by `NullRes` gives EXACTLY the output of
  // replacing it by any non-passing result. In particular a null optional root never aborts the N-of-M check, and a null
  // required root is a `RequiredFailed` denial (fail closed).
  lemma NullIsFailedRoot(reqs: seq<bool>, rs: seq<RootRes>, i: int, y: RootRes, thr: int)
    requires |reqs| == |rs| && 0 <= i < |rs| && Failed(y)
    ensures Run(reqs, rs[i := NullRes], thr) == Run(reqs, rs[i := y], thr)
  {
    FoldReplaceFailed(reqs, rs[i := NullRes], rs[i := y], Running([]), 0);
  }
  lemma FoldReplaceFailed(reqs: seq<bool>, a: seq<RootRes>, b: seq<RootRes>, st: St, k: nat)
    requires |reqs| == |a| == |b| && k <= |a|
    requires forall j :: 0 <= j < |a| ==> a[j] == b[j] || (Failed(a[j]) && Failed(b[j]))
    ensures Fold(reqs, a, st, k) == Fold(reqs, b, st, k)
    decreases |a| - k
  {
    if k < |a| {
      assert Step(st, k, reqs[k], a[k]) == Step(st, k, reqs[k], b[k]);
      FoldReplaceFailed(reqs, a, b, Step(st, k, reqs[k], a[k]), k + 1);
    }
  }
  // THEOREM: null results alone can never make the check accept, and with no hostile (throwing) result the verdict is never
  // the abort `ErrorCaught`.
  lemma NullNeverAborts(reqs: seq<bool>, rs: seq<RootRes>, thr: int)
    requires |reqs| == |rs| && forall i :: 0 <= i < |rs| ==> !rs[i].Malformed?
    ensures Run(reqs, rs, thr) != MFail(ErrorCaught)
    ensures (forall i :: 0 <= i < |rs| ==> rs[i].NullRes?) && thr >= 1 ==> Run(reqs, rs, thr).MFail?
  {
    FoldIs(reqs, rs, [], 0);
    FirstBadNoErr(reqs, rs, 0);
    if forall i :: 0 <= i < |rs| ==> rs[i].NullRes? {
      CollectSpec(rs, 0);
      CollectNone(rs, 0);
      RunFailsClosed(reqs, rs, thr);
    }
  }
  lemma FirstBadNoErr(reqs: seq<bool>, rs: seq<RootRes>, k: nat)
    requires |reqs| == |rs| && k <= |rs| && forall i :: 0 <= i < |rs| ==> !rs[i].Malformed?
    ensures FirstBad(reqs, rs, k) != Some(ErrorCaught)
    decreases |rs| - k
  {
    if k < |rs| { FirstBadNoErr(reqs, rs, k + 1); }
  }
  lemma CollectNone(rs: seq<RootRes>, k: nat)
    requires k <= |rs| && forall i :: 0 <= i < |rs| ==> !Passes(rs[i])
    ensures Collect(rs, k) == []
    decreases |rs| - k
  {
    if k < |rs| { CollectNone(rs, k + 1); }
  }

  // ==============================================================================================
  // B. AGENT-BINDING MATCH (matchAgentBinding) and requiresAttestation
  // ==============================================================================================
  // min_measurement as the glue evaluated it: none / equality pin / monotone svn ladder / MALFORMED constraint.
  // The glue maps an absent min_measurement or "" to NoMin; a non-empty string to EqPin; `{svn: n}` with n a safe non-negative integer
  // JSON number to Svn (the measured runtime_measurement must be a canonical decimal integer string, else SvnNotInteger); ANY other
  // present value (a string / fractional / negative / non-finite / -0 svn, an object without svn, a number, an array, null) to MinBad,
  // which fails closed (0.4.2: it used to be NoMin, i.e. it enforced nothing).
  datatype SvnCheck = SvnNotInteger | SvnBelow | SvnOk
  datatype MinM = NoMin | EqPin(matches: bool) | Svn(parse: SvnCheck) | MinBad

  datatype BIdent = BIdent(model: Id, weights: Id, weightsMeasured: bool, hasSys: bool, sys: Id, hasTool: bool, tool: Id, operatorMatches: bool)
  datatype Binding = Binding(
    modelAllow: seq<Id>, minM: MinM, operatorPinned: bool, requireMeasured: bool,
    weightsAllow: seq<Id>, sysAllow: seq<Id>, toolAllow: seq<Id>)

  datatype BFail = BModel | BMinBad | BMinEq | BMinSvnNotInt | BMinSvnBelow | BOperator | BNotMeasured | BWeights | BSys | BTool

  predicate Incl(s: seq<Id>, x: Id) { x in s }

  function MatchBinding(id: BIdent, b: Binding): Option<BFail>
  {
    if |b.modelAllow| > 0 && !Incl(b.modelAllow, id.model) then Some(BModel)
    else if b.minM.MinBad? then Some(BMinBad)
    else if b.minM.EqPin? && !b.minM.matches then Some(BMinEq)
    else if b.minM.Svn? && b.minM.parse.SvnNotInteger? then Some(BMinSvnNotInt)
    else if b.minM.Svn? && b.minM.parse.SvnBelow? then Some(BMinSvnBelow)
    else if b.operatorPinned && !id.operatorMatches then Some(BOperator)
    else if b.requireMeasured && !id.weightsMeasured then Some(BNotMeasured)
    else if |b.weightsAllow| > 0 && !Incl(b.weightsAllow, id.weights) then Some(BWeights)
    else if |b.sysAllow| > 0 && (!id.hasSys || !Incl(b.sysAllow, id.sys)) then Some(BSys)
    else if |b.toolAllow| > 0 && (!id.hasTool || !Incl(b.toolAllow, id.tool)) then Some(BTool)
    else None
  }

  predicate BindingHolds(id: BIdent, b: Binding)
  {
    (|b.modelAllow| > 0 ==> id.model in b.modelAllow) &&
    !b.minM.MinBad? &&
    (b.minM.EqPin? ==> b.minM.matches) &&
    (b.minM.Svn? ==> b.minM.parse.SvnOk?) &&
    (b.operatorPinned ==> id.operatorMatches) &&
    (b.requireMeasured ==> id.weightsMeasured) &&
    (|b.weightsAllow| > 0 ==> id.weights in b.weightsAllow) &&
    (|b.sysAllow| > 0 ==> id.hasSys && id.sys in b.sysAllow) &&
    (|b.toolAllow| > 0 ==> id.hasTool && id.tool in b.toolAllow)
  }

  // THEOREM: accept iff every pinned constraint holds (sound and complete). A pinned digest that the measured identity does not
  // carry fails closed.
  lemma MatchIff(id: BIdent, b: Binding)
    ensures MatchBinding(id, b).None? <==> BindingHolds(id, b)
  {}

  // THEOREM (0.4.2): a malformed min_measurement constraint is never satisfied, whatever the identity: fail closed.
  lemma MalformedMinFailsClosed(id: BIdent, b: Binding)
    requires b.minM.MinBad?
    ensures MatchBinding(id, b).Some? && !BindingHolds(id, b)
  {}

  function NoBinding(): Binding { Binding([], NoMin, false, false, [], [], []) }

  // THEOREM: with no constraint pinned, anything matches; any single pinned list excludes an identity outside it.
  lemma EmptyBindingAccepts(id: BIdent)
    ensures MatchBinding(id, NoBinding()).None?
  {}

  lemma PinnedAbsentDigestFails(id: BIdent, b: Binding)
    ensures |b.sysAllow| > 0 && !id.hasSys ==> MatchBinding(id, b).Some?
    ensures |b.toolAllow| > 0 && !id.hasTool ==> MatchBinding(id, b).Some?
    ensures b.requireMeasured && !id.weightsMeasured ==> MatchBinding(id, b).Some?
  {}

  // Tightening a binding (more constraints, i.e. each list narrowed / flag raised) can only reject more.
  predicate AllowNarrower(a: seq<Id>, b: seq<Id>)  // `a` is at least as strict as `b`
  {
    |b| == 0 || (|a| > 0 && forall x :: x in a ==> x in b)
  }

  lemma TighteningRejects(id: BIdent, b1: Binding, b2: Binding)
    requires AllowNarrower(b2.modelAllow, b1.modelAllow) && AllowNarrower(b2.weightsAllow, b1.weightsAllow)
    requires AllowNarrower(b2.sysAllow, b1.sysAllow) && AllowNarrower(b2.toolAllow, b1.toolAllow)
    requires b1.requireMeasured ==> b2.requireMeasured
    requires b1.operatorPinned ==> b2.operatorPinned
    requires b1.minM == b2.minM
    ensures MatchBinding(id, b2).None? ==> MatchBinding(id, b1).None?
  {}

  // requiresAttestation: is anything pinned?
  datatype BindingFlags = BindingFlags(modelAllowNonEmpty: bool, hasMin: bool, operatorNonEmpty: bool, weightsNonEmpty: bool,
                                       sysNonEmpty: bool, toolNonEmpty: bool, requireHw: bool, requireMeasured: bool)
  function RequiresAttestation(f: BindingFlags): bool
  {
    f.modelAllowNonEmpty || f.hasMin || f.operatorNonEmpty || f.weightsNonEmpty || f.sysNonEmpty || f.toolNonEmpty || f.requireHw || f.requireMeasured
  }
  // THEOREM: a binding that matchAgentBinding can reject on, requires an attestation (so the "no document" case is a deny).
  lemma ConstrainingBindingRequiresAttestation(f: BindingFlags)
    ensures !RequiresAttestation(f) ==> !f.modelAllowNonEmpty && !f.hasMin && !f.operatorNonEmpty && !f.weightsNonEmpty && !f.sysNonEmpty && !f.toolNonEmpty && !f.requireHw && !f.requireMeasured
  {}

  // ==============================================================================================
  // C. VERIFYATTESTATION: stage order (first failure wins) + arithmetic
  // ==============================================================================================
  datatype Kind =
    | KPresent | KBindingConstructible | KGrantRef | KEpoch | KQuote | KDocNonce | KReqHwVerifier | KReqHwMode
    | KHwNonceAge | KHwOk | KHwBound | KHwMeasured
    | KSoftMode | KAttestorTrusted | KAlgKnown | KSigOk | KBindingPresent | KBindingEq | KWindowWellFormed | KNotYetValid | KExpired | KSoftNonceAge
    | KAgentBinding

  datatype VFacts = VFacts(
    present: bool, bindingConstructible: bool, grantRefOk: bool, epochOk: bool, quoteOk: bool, docNonceOk: bool,
    requireHw: bool, hasHwVerifier: bool, docIsHardware: bool,
    hwNonceAgeOk: bool, hwOk: bool, hwBound: bool, hwHasMeasured: bool,
    docIsSoftware: bool, attestorTrusted: bool, algKnown: bool, sigOk: bool, bindingPresent: bool, bindingEq: bool,
    windowWellFormed: bool, notYetValid: bool, expired: bool, hasNonceIssuedAt: bool, softNonceAgeOk: bool,
    agentBindingOk: bool)

  // The ordered list of stages for a run; the route (hardware vs software) depends only on hasHwVerifier.
  function Order(hasHw: bool): seq<Kind>
  {
    [KPresent, KBindingConstructible, KGrantRef, KEpoch, KQuote, KDocNonce, KReqHwVerifier, KReqHwMode] +
    (if hasHw then [KHwNonceAge, KHwOk, KHwBound, KHwMeasured]
     else [KSoftMode, KAttestorTrusted, KAlgKnown, KSigOk, KBindingPresent, KBindingEq, KWindowWellFormed, KNotYetValid, KExpired, KSoftNonceAge]) +
    [KAgentBinding]
  }

  predicate Holds(f: VFacts, k: Kind)
  {
    match k
    case KPresent => f.present
    case KBindingConstructible => f.bindingConstructible
    case KGrantRef => f.grantRefOk
    case KEpoch => f.epochOk
    case KQuote => f.quoteOk
    case KDocNonce => f.docNonceOk
    case KReqHwVerifier => !f.requireHw || f.hasHwVerifier
    case KReqHwMode => !f.requireHw || f.docIsHardware
    case KHwNonceAge => f.hwNonceAgeOk
    case KHwOk => f.hwOk
    case KHwBound => f.hwBound
    case KHwMeasured => f.hwHasMeasured
    case KSoftMode => f.docIsSoftware
    case KAttestorTrusted => f.attestorTrusted
    case KAlgKnown => f.algKnown
    case KSigOk => f.sigOk
    case KBindingPresent => f.bindingPresent
    case KBindingEq => f.bindingEq
    case KWindowWellFormed => f.windowWellFormed
    case KNotYetValid => !f.notYetValid
    case KExpired => !f.expired
    case KSoftNonceAge => !f.hasNonceIssuedAt || f.softNonceAgeOk
    case KAgentBinding => f.agentBindingOk
  }

  // One gate step (what the adapter calls, lazily, per stage): the first failing stage sticks.
  function GateStep(acc: Option<Kind>, k: Kind, holds: bool): Option<Kind>
  {
    if acc.Some? then acc else if holds then None else Some(k)
  }

  function GateFrom(f: VFacts, ks: seq<Kind>, acc: Option<Kind>): Option<Kind>
    decreases |ks|
  {
    if |ks| == 0 then acc else GateFrom(f, ks[1..], GateStep(acc, ks[0], Holds(f, ks[0])))
  }

  function Verify(f: VFacts): Option<Kind>   // None == accepted
  {
    GateFrom(f, Order(f.hasHwVerifier), None)
  }

  lemma GateFromSpec(f: VFacts, ks: seq<Kind>, acc: Option<Kind>)
    ensures acc.Some? ==> GateFrom(f, ks, acc) == acc
    ensures acc.None? ==> (GateFrom(f, ks, acc).None? <==> forall i :: 0 <= i < |ks| ==> Holds(f, ks[i]))
    ensures acc.None? && GateFrom(f, ks, acc).Some? ==>
      exists j :: 0 <= j < |ks| && ks[j] == GateFrom(f, ks, acc).v && !Holds(f, ks[j]) && (forall i :: 0 <= i < j ==> Holds(f, ks[i]))
    decreases |ks|
  {
    if |ks| > 0 {
      var nx := GateStep(acc, ks[0], Holds(f, ks[0]));
      GateFromSpec(f, ks[1..], nx);
      if acc.Some? {
      } else if Holds(f, ks[0]) {
        assert nx.None?;
        forall i | 0 <= i < |ks| - 1 { assert ks[1..][i] == ks[i + 1]; }
        if GateFrom(f, ks, acc).Some? {
          var j :| 0 <= j < |ks[1..]| && ks[1..][j] == GateFrom(f, ks, acc).v && !Holds(f, ks[1..][j]) && (forall i :: 0 <= i < j ==> Holds(f, ks[1..][i]));
          assert ks[1..][j] == ks[j + 1];
          forall i | 0 <= i < j + 1 ensures Holds(f, ks[i]) {
            if i == 0 {} else { assert ks[1..][i - 1] == ks[i]; }
          }
        }
      } else {
        assert nx == Some(ks[0]);
      }
    }
  }

  // THEOREM (accept iff every stage on the route holds; first failing stage wins; never accepted on missing evidence).
  lemma VerifyIff(f: VFacts)
    ensures Verify(f).None? <==> forall i :: 0 <= i < |Order(f.hasHwVerifier)| ==> Holds(f, Order(f.hasHwVerifier)[i])
    ensures Verify(f).Some? ==> exists j :: 0 <= j < |Order(f.hasHwVerifier)| && Order(f.hasHwVerifier)[j] == Verify(f).v &&
              !Holds(f, Order(f.hasHwVerifier)[j]) && (forall i :: 0 <= i < j ==> Holds(f, Order(f.hasHwVerifier)[i]))
  {
    GateFromSpec(f, Order(f.hasHwVerifier), None);
  }

  lemma InOrder(hasHw: bool, k: Kind)
    ensures k == KPresent ==> k in Order(hasHw)
    ensures k == KAgentBinding ==> k in Order(hasHw)
    ensures (k == KDocNonce || k == KReqHwVerifier || k == KReqHwMode || k == KGrantRef || k == KEpoch || k == KQuote) ==> k in Order(hasHw)
    ensures (k == KHwOk || k == KHwBound || k == KHwMeasured || k == KHwNonceAge) ==> (k in Order(hasHw) <==> hasHw)
    ensures (k == KSigOk || k == KSoftMode || k == KAttestorTrusted) ==> (k in Order(hasHw) <==> !hasHw)
  {
    var o := Order(hasHw);
    assert o[0] == KPresent && o[1] == KBindingConstructible && o[2] == KGrantRef && o[3] == KEpoch && o[4] == KQuote && o[5] == KDocNonce && o[6] == KReqHwVerifier && o[7] == KReqHwMode;
    assert o[|o| - 1] == KAgentBinding;
  }

  // THEOREM (what an accept means): present, the PCActn commits to the expected grant / epoch / nonce, the document nonce
  // equals the server nonce, require_hardware => hardware verifier + hardware document, a hardware route needs
  // ok + bound + a measured identity, a software route needs a trusted attestor, known alg, verifying signature and a binding
  // equal to the expected one, the agent_binding match passed.
  lemma VerifySound(f: VFacts)
    requires Verify(f).None?
    ensures f.present && f.bindingConstructible && f.grantRefOk && f.epochOk && f.quoteOk && f.docNonceOk
    ensures f.requireHw ==> f.hasHwVerifier && f.docIsHardware
    ensures f.hasHwVerifier ==> f.hwNonceAgeOk && f.hwOk && f.hwBound && f.hwHasMeasured
    ensures !f.hasHwVerifier ==> f.docIsSoftware && f.attestorTrusted && f.algKnown && f.sigOk && f.bindingPresent && f.bindingEq
                                 && f.windowWellFormed && !f.notYetValid && !f.expired && (!f.hasNonceIssuedAt || f.softNonceAgeOk)
    ensures !f.hasHwVerifier ==> !f.requireHw          // a software attestation can never satisfy require_hardware
    ensures f.agentBindingOk
  {
    VerifyIff(f);
    var o := Order(f.hasHwVerifier);
    assert o[0] == KPresent && o[1] == KBindingConstructible && o[2] == KGrantRef && o[3] == KEpoch && o[4] == KQuote && o[5] == KDocNonce && o[6] == KReqHwVerifier && o[7] == KReqHwMode;
    assert Holds(f, o[0]) && Holds(f, o[1]) && Holds(f, o[2]) && Holds(f, o[3]) && Holds(f, o[4]) && Holds(f, o[5]) && Holds(f, o[6]) && Holds(f, o[7]);
    assert o[|o| - 1] == KAgentBinding && Holds(f, o[|o| - 1]);
    if f.hasHwVerifier {
      assert o[8] == KHwNonceAge && o[9] == KHwOk && o[10] == KHwBound && o[11] == KHwMeasured;
      assert Holds(f, o[8]) && Holds(f, o[9]) && Holds(f, o[10]) && Holds(f, o[11]);
    } else {
      assert o[8] == KSoftMode && o[9] == KAttestorTrusted && o[10] == KAlgKnown && o[11] == KSigOk && o[12] == KBindingPresent
        && o[13] == KBindingEq && o[14] == KWindowWellFormed && o[15] == KNotYetValid && o[16] == KExpired && o[17] == KSoftNonceAge;
      assert Holds(f, o[8]) && Holds(f, o[9]) && Holds(f, o[10]) && Holds(f, o[11]) && Holds(f, o[12]) && Holds(f, o[13])
        && Holds(f, o[14]) && Holds(f, o[15]) && Holds(f, o[16]) && Holds(f, o[17]);
    }
  }

  // ---- arithmetic: nonce age and validity windows (integers; the glue floors a fractional skew, which is exact for integer
  //      operands) ----
  const MaxAttestationAgeMs: int := 300000

  // maxAge = min(maxNonceAgeMs if finite and > 0 else the cap, the cap)
  function EffMaxAge(has: bool, v: int): int
  {
    var m := if has && v > 0 then v else MaxAttestationAgeMs;
    if m < MaxAttestationAgeMs then m else MaxAttestationAgeMs
  }
  lemma EffMaxAgeBounds(has: bool, v: int)
    ensures 0 < EffMaxAge(has, v) <= MaxAttestationAgeMs
    ensures has && 0 < v <= MaxAttestationAgeMs ==> EffMaxAge(has, v) == v
    ensures !(has && v > 0) ==> EffMaxAge(has, v) == MaxAttestationAgeMs
  {}

  datatype AgeRes = AgeUnknown | AgeFuture | AgeStale | AgeFresh
  function NonceAge(hasIssued: bool, issued: int, now: int, skew: int, maxAge: int): AgeRes
    requires skew >= 0
  {
    if !hasIssued then AgeUnknown
    else if now + skew < issued then AgeFuture
    else if now - issued > maxAge + skew then AgeStale
    else AgeFresh
  }
  // THEOREM: fresh <=> an issue time exists and  issued - skew <= now <= issued + maxAge + skew  (so never older than
  // maxAge + skew, i.e. at most 5 min + skew, whatever the caller configured).
  lemma NonceAgeSound(hasIssued: bool, issued: int, now: int, skew: int, mx: bool, mv: int)
    requires skew >= 0
    ensures NonceAge(hasIssued, issued, now, skew, EffMaxAge(mx, mv)).AgeFresh? <==>
      hasIssued && issued - skew <= now && now <= issued + EffMaxAge(mx, mv) + skew
    ensures NonceAge(hasIssued, issued, now, skew, EffMaxAge(mx, mv)).AgeFresh? ==> now - issued <= MaxAttestationAgeMs + skew
    ensures !hasIssued ==> !NonceAge(hasIssued, issued, now, skew, EffMaxAge(mx, mv)).AgeFresh?
  {
    EffMaxAgeBounds(mx, mv);
  }

  datatype WinRes = WinMalformed | WinNotYet | WinExpired | WinValid
  function Window(now: int, skew: int, iat: int, exp: int): WinRes
    requires skew >= 0
  {
    if exp < iat then WinMalformed
    else if now + skew < iat then WinNotYet
    else if now - skew > exp then WinExpired
    else WinValid
  }
  lemma WindowSound(now: int, skew: int, iat: int, exp: int)
    requires skew >= 0
    ensures Window(now, skew, iat, exp).WinValid? <==> iat <= exp && iat - skew <= now && now <= exp + skew
    ensures Window(now, skew, iat, exp).WinValid? && skew == 0 ==> iat <= now <= exp
  {}

  // ==============================================================================================
  // D. HOOK NONCE RULE and nonce-store model
  // ==============================================================================================
  datatype HookOut = HookOk | HookVerdictFail | HookReplay
  // consume is consulted only for an ok+bound verdict with a store configured.
  function NeedsConsume(vOk: bool, vBound: bool, hasStore: bool): bool { vOk && vBound && hasStore }
  function HookFinal(vOk: bool, vBound: bool, hasStore: bool, consumed: bool): HookOut
  {
    if NeedsConsume(vOk, vBound, hasStore) then (if consumed then HookOk else HookReplay)
    else if vOk then HookOk else HookVerdictFail
  }
  // THEOREM: the hook accepts only with an ok verdict; with a store configured and a bound verdict it ALSO required the store's
  // single-use answer to be true. (An ok-but-unbound verdict does not consult the store; verifyAttestation never produces one.)
  lemma HookSound(vOk: bool, vBound: bool, hasStore: bool, consumed: bool)
    ensures HookFinal(vOk, vBound, hasStore, consumed) == HookOk ==> vOk && (hasStore && vBound ==> consumed)
    ensures !consumed && NeedsConsume(vOk, vBound, hasStore) ==> HookFinal(vOk, vBound, hasStore, consumed) == HookReplay
    ensures !vOk ==> HookFinal(vOk, vBound, hasStore, consumed) != HookOk
  {}

  // memoryNonceStore(max, { retentionMs, now }): an insertion-ordered map nonce -> time consumed (a JS Map; re-inserting a key
  // after delete appends it). consume(n) at clock t:
  //   1. n present and live (t - at < ret)            -> reject, state unchanged
  //   2. n present but aged out                        -> delete it, continue as new
  //   3. full (|items| >= max): delete the oldest entries WHILE they are aged out (stop at the first live one)
  //   4. still full                                     -> reject (fail closed; nothing is evicted that is live)
  //   5. else append (n, t), accept.
  // Times and retention are integers (the adapter requires safe-integer clock values; Date.now() is).
  datatype MS = MS(items: seq<(int, int)>, max: int, ret: int)

  function IndexOf(xs: seq<(int, int)>, n: int): int
    ensures -1 <= IndexOf(xs, n) < |xs|
    ensures IndexOf(xs, n) >= 0 ==> xs[IndexOf(xs, n)].0 == n
    ensures IndexOf(xs, n) == -1 ==> forall j :: 0 <= j < |xs| ==> xs[j].0 != n
    decreases |xs|
  {
    if |xs| == 0 then -1
    else if xs[0].0 == n then 0
    else var r := IndexOf(xs[1..], n); if r < 0 then -1 else r + 1
  } by method {
    // compiled form: one index loop (the recursive form above copies the tail and recurses once per entry: quadratic, and it
    // exhausts the stack once the store holds a few thousand nonces)
    var j := 0;
    while j < |xs| && xs[j].0 != n
      invariant 0 <= j <= |xs| && forall q :: 0 <= q < j ==> xs[q].0 != n
      decreases |xs| - j
    { j := j + 1; }
    IndexOfFirst(xs, n);
    return if j < |xs| then j else -1;
  }
  // IndexOf is the FIRST matching index
  lemma IndexOfFirst(xs: seq<(int, int)>, n: int)
    ensures forall q :: 0 <= q < IndexOf(xs, n) ==> xs[q].0 != n
    decreases |xs|
  {
    if |xs| > 0 && xs[0].0 != n {
      IndexOfFirst(xs[1..], n);
      forall q | 0 < q < IndexOf(xs, n) ensures xs[q].0 != n { assert xs[1..][q - 1] == xs[q]; }
    }
  }
  function RemoveAt(xs: seq<(int, int)>, i: int): seq<(int, int)>
    requires 0 <= i < |xs|
  { xs[..i] + xs[i + 1..] }

  predicate Live(e: (int, int), t: int, ret: int) { t - e.1 < ret }

  // step 3: drop the aged-out prefix
  function DropAged(xs: seq<(int, int)>, t: int, ret: int): seq<(int, int)>
    decreases |xs|
  {
    if |xs| == 0 || Live(xs[0], t, ret) then xs else DropAged(xs[1..], t, ret)
  } by method {
    // compiled form: find the first live entry, then ONE slice (the tail-recursive form above copies the tail per dropped entry)
    var k := 0;
    while k < |xs| && !Live(xs[k], t, ret)
      invariant 0 <= k <= |xs| && DropAged(xs, t, ret) == DropAged(xs[k..], t, ret)
      decreases |xs| - k
    { assert xs[k..][1..] == xs[k + 1..]; k := k + 1; }
    return xs[k..];
  }

  function MsConsume(s: MS, n: int, t: int): (MS, bool)
  {
    var i := IndexOf(s.items, n);
    if i >= 0 && Live(s.items[i], t, s.ret) then (s, false)
    else
      var it := if i >= 0 then RemoveAt(s.items, i) else s.items;
      var it2 := if |it| >= s.max then DropAged(it, t, s.ret) else it;
      if |it2| >= s.max then (MS(it2, s.max, s.ret), false)
      else (MS(it2 + [(n, t)], s.max, s.ret), true)
  }
  // Construction requires max >= 1 and ret >= 1 (the TS throws a TypeError otherwise).
  predicate ValidStore(max: int, ret: int) { max >= 1 && ret >= 1 }
  function MsEmpty(max: int, ret: int): MS requires ValidStore(max, ret) { MS([], max, ret) }

  predicate Distinct(xs: seq<(int, int)>) { forall a, b :: 0 <= a < b < |xs| ==> xs[a].0 != xs[b].0 }
  predicate Wf(s: MS) { ValidStore(s.max, s.ret) && |s.items| <= s.max && Distinct(s.items) }

  // how many leading entries DropAged removes
  function DropCount(xs: seq<(int, int)>, t: int, ret: int): nat
    ensures DropCount(xs, t, ret) <= |xs|
    decreases |xs|
  {
    if |xs| == 0 || Live(xs[0], t, ret) then 0 else 1 + DropCount(xs[1..], t, ret)
  }
  lemma DropAgedSuffix(xs: seq<(int, int)>, t: int, ret: int)
    ensures DropAged(xs, t, ret) == xs[DropCount(xs, t, ret)..]
    ensures forall j {:trigger xs[j]} :: 0 <= j < DropCount(xs, t, ret) ==> !Live(xs[j], t, ret)
    decreases |xs|
  {
    if |xs| > 0 && !Live(xs[0], t, ret) {
      var tl := xs[1..];
      DropAgedSuffix(tl, t, ret);
      var k := DropCount(tl, t, ret);
      assert tl[k..] == xs[k + 1..];
      forall j | 0 <= j < k + 1 ensures !Live(xs[j], t, ret) { if j > 0 { assert xs[j] == tl[j - 1]; } }
    }
  }

  lemma DistinctSub(xs: seq<(int, int)>, k: int)
    requires Distinct(xs) && 0 <= k <= |xs|
    ensures Distinct(xs[k..])
  {
    forall a, b | 0 <= a < b < |xs[k..]| ensures xs[k..][a].0 != xs[k..][b].0 { assert xs[k..][a] == xs[k + a] && xs[k..][b] == xs[k + b]; }
  }
  lemma DistinctRemove(xs: seq<(int, int)>, i: int)
    requires Distinct(xs) && 0 <= i < |xs|
    ensures Distinct(RemoveAt(xs, i))
    ensures forall e :: e in RemoveAt(xs, i) ==> e in xs
    ensures forall j :: 0 <= j < |xs| && j != i ==> xs[j] in RemoveAt(xs, i)
    ensures |RemoveAt(xs, i)| == |xs| - 1
  {
    var r := RemoveAt(xs, i);
    forall a, b | 0 <= a < b < |r| ensures r[a].0 != r[b].0 {
      var a' := if a < i then a else a + 1;
      var b' := if b < i then b else b + 1;
      assert r[a] == xs[a'] && r[b] == xs[b'] && a' < b';
    }
    forall j | 0 <= j < |xs| && j != i ensures xs[j] in r { if j < i { assert r[j] == xs[j]; } else { assert r[j - 1] == xs[j]; } }
    forall e | e in r ensures e in xs { var a :| 0 <= a < |r| && r[a] == e; if a < i { assert r[a] == xs[a]; } else { assert r[a] == xs[a + 1]; } }
  }

  // THEOREM (well-formedness): distinct nonces, never more than `max` entries.
  lemma ConsumeWf(s: MS, n: int, t: int)
    requires Wf(s)
    ensures Wf(MsConsume(s, n, t).0)
  {
    var i := IndexOf(s.items, n);
    if !(i >= 0 && Live(s.items[i], t, s.ret)) {
      var it := if i >= 0 then RemoveAt(s.items, i) else s.items;
      if i >= 0 { DistinctRemove(s.items, i); }
      assert Distinct(it);
      assert forall j :: 0 <= j < |it| ==> it[j].0 != n by {
        if i >= 0 {
          forall j | 0 <= j < |it| ensures it[j].0 != n {
            if j < i { assert it[j] == s.items[j]; } else { assert it[j] == s.items[j + 1]; }
          }
        }
      }
      var it2 := if |it| >= s.max then DropAged(it, t, s.ret) else it;
      DropAgedSuffix(it, t, s.ret);
      if |it| >= s.max {
        var k := DropCount(it, t, s.ret);
        DistinctSub(it, k);
        forall j | 0 <= j < |it2| ensures it2[j].0 != n { assert it2[j] == it[k + j]; }
      }
      assert Distinct(it2);
      if |it2| < s.max {
        var r := it2 + [(n, t)];
        forall a, b | 0 <= a < b < |r| ensures r[a].0 != r[b].0 {
          if b == |it2| { assert r[a] == it2[a] && r[b] == (n, t); } else { assert r[a] == it2[a] && r[b] == it2[b]; }
        }
      }
    }
  }

  // THEOREM (a live nonce is never evicted): if (n, t0) is in the store and the consume happens at a time t at which it is still
  // live (t - t0 < ret), the entry (n, t0) is still there afterwards, whatever nonce x is consumed (x == n included).
  lemma LiveNeverEvicted(s: MS, n: int, t0: int, x: int, t: int)
    requires Wf(s) && (n, t0) in s.items && t - t0 < s.ret
    ensures (n, t0) in MsConsume(s, x, t).0.items
  {
    var j :| 0 <= j < |s.items| && s.items[j] == (n, t0);
    var i := IndexOf(s.items, x);
    if !(i >= 0 && Live(s.items[i], t, s.ret)) {
      // the entry removed in step 2 is x's own, aged out; (n, t0) is live, so it is not that one
      assert i >= 0 ==> i != j;
      var it := if i >= 0 then RemoveAt(s.items, i) else s.items;
      if i >= 0 { DistinctRemove(s.items, i); }
      assert (n, t0) in it;
      var jt :| 0 <= jt < |it| && it[jt] == (n, t0);
      DropAgedSuffix(it, t, s.ret);
      var it2 := if |it| >= s.max then DropAged(it, t, s.ret) else it;
      if |it| >= s.max {
        var k := DropCount(it, t, s.ret);
        assert Live(it[jt], t, s.ret);
        assert !(jt < k);
        assert it2[jt - k] == (n, t0);
      }
      assert (n, t0) in it2;
      if |it2| < s.max {
        var q :| 0 <= q < |it2| && it2[q] == (n, t0);
        assert (it2 + [(x, t)])[q] == (n, t0);
      }
    }
  }

  // A live resident nonce is rejected (state unchanged).
  lemma LiveRejected(s: MS, n: int, t0: int, t: int)
    requires Wf(s) && (n, t0) in s.items && t - t0 < s.ret
    ensures MsConsume(s, n, t) == (s, false)
  {
    var j :| 0 <= j < |s.items| && s.items[j] == (n, t0);
    var i := IndexOf(s.items, n);
    assert i >= 0;
    assert s.items[i].0 == n == s.items[j].0;
    assert i == j;
  }

  function MsApply(s: MS, ops: seq<(int, int)>): (MS, int)   // final state, number of accepted consumes; ops = (nonce, time)
    decreases |ops|
  {
    if |ops| == 0 then (s, 0)
    else
      var r := MsConsume(s, ops[0].0, ops[0].1);
      var rest := MsApply(r.0, ops[1..]);
      (rest.0, rest.1 + (if r.1 then 1 else 0))
  }

  lemma ApplyKeepsLive(s: MS, n: int, t0: int, ops: seq<(int, int)>)
    requires Wf(s) && (n, t0) in s.items
    requires forall j :: 0 <= j < |ops| ==> ops[j].1 - t0 < s.ret
    ensures Wf(MsApply(s, ops).0) && (n, t0) in MsApply(s, ops).0.items && MsApply(s, ops).0.ret == s.ret
    decreases |ops|
  {
    if |ops| > 0 {
      LiveNeverEvicted(s, n, t0, ops[0].0, ops[0].1);
      ConsumeWf(s, ops[0].0, ops[0].1);
      var s1 := MsConsume(s, ops[0].0, ops[0].1).0;
      assert s1.ret == s.ret;
      ApplyKeepsLive(s1, n, t0, ops[1..]);
    }
  }

  // THEOREM (single use within the retention window, ANY number of other nonces): after n is accepted at time t0, for every
  // sequence of later consumes (of any nonces, any count, n included) at times t with t - t0 < retention, n stays in the store and
  // every re-presentation of n inside the window is rejected.
  lemma SingleUse(s: MS, n: int, t0: int, ops: seq<(int, int)>, t: int)
    requires Wf(s) && MsConsume(s, n, t0).1
    requires forall j :: 0 <= j < |ops| ==> ops[j].1 - t0 < s.ret
    requires t - t0 < s.ret
    ensures var s1 := MsConsume(s, n, t0).0;
            (n, t0) in MsApply(s1, ops).0.items && !MsConsume(MsApply(s1, ops).0, n, t).1
  {
    var s1 := MsConsume(s, n, t0).0;
    ConsumeWf(s, n, t0);
    assert s1.items[|s1.items| - 1] == (n, t0);
    ApplyKeepsLive(s1, n, t0, ops);
    LiveRejected(MsApply(s1, ops).0, n, t0, t);
  }

  // THEOREM (fail closed when full): a store full of live entries refuses a new nonce and evicts nothing.
  lemma FullOfLiveRefuses(s: MS, n: int, t: int)
    requires Wf(s) && |s.items| == s.max && forall j :: 0 <= j < |s.items| ==> Live(s.items[j], t, s.ret)
    requires IndexOf(s.items, n) == -1
    ensures MsConsume(s, n, t) == (s, false)
  {
    assert s.items != [] ;
    assert DropAged(s.items, t, s.ret) == s.items;
  }

  // An aged-out nonce may be accepted again: exactly the retention rule (the freshness check bounds a quote to <= 5 min + skew,
  // so retention must exceed that; the TS default is 1 h).
  lemma AgedOutReaccepted()
    ensures var s := MsEmpty(1, 10);
            var a := MsConsume(s, 7, 0);
            var b := MsConsume(a.0, 7, 9);
            var c := MsConsume(b.0, 7, 10);
            a.1 && !b.1 && c.1
  {}

  // ==============================================================================================
  // E. ALLOWLIST: verifyAllowlistManifest ordering, durable high-water mark, anchored-feed scan
  // ==============================================================================================
  datatype AKind = ASshape | AUnknownIssuer | AAlgMismatch | AIssuerExpired | ABadSig | AOptions | ANotYet | AExpired | ALifetime | ABelowMin | ARollback | AConflict

  datatype AFacts = AFacts(
    shapeOk: bool, issuerKnown: bool, algMatches: bool, issuerLive: bool, sigOk: bool,
    // optionsOk: every numeric option the caller supplied is valid (clockSkewMs / maxLifetimeMs finite numbers, minVersion /
    // lastSeenVersion safe integers). The glue computes it; when false the numeric fields below are meaningless.
    optionsOk: bool,
    now: int, skew: int, notBefore: int, expiresAt: int,
    hasMaxLife: bool, maxLife: int, hasMin: bool, minV: int,
    version: int, hasLast: bool, lastV: int, hasLastDigest: bool, lastDigest: Id, digest: Id)

  const AOrder: seq<AKind> := [ASshape, AUnknownIssuer, AAlgMismatch, AIssuerExpired, ABadSig, AOptions, ANotYet, AExpired, ALifetime, ABelowMin, ARollback, AConflict]

  predicate AHolds(f: AFacts, k: AKind)
  {
    match k
    case ASshape => f.shapeOk
    case AUnknownIssuer => f.issuerKnown
    case AAlgMismatch => f.algMatches
    case AIssuerExpired => f.issuerLive
    case ABadSig => f.sigOk
    case AOptions => f.optionsOk
    case ANotYet => !(f.now + f.skew < f.notBefore)
    case AExpired => !(f.now - f.skew > f.expiresAt)
    case ALifetime => !(f.hasMaxLife && f.expiresAt - f.notBefore > f.maxLife)
    case ABelowMin => !(f.hasMin && f.version < f.minV)
    case ARollback => !(f.hasLast && f.version < f.lastV)
    case AConflict => !(f.hasLast && f.version == f.lastV && f.hasLastDigest && f.lastDigest != f.digest)
  }

  function AGateFrom(f: AFacts, ks: seq<AKind>, acc: Option<AKind>): Option<AKind>
    decreases |ks|
  {
    if |ks| == 0 then acc
    else AGateFrom(f, ks[1..], if acc.Some? then acc else if AHolds(f, ks[0]) then None else Some(ks[0]))
  }
  function AllowVerify(f: AFacts): Option<AKind> { AGateFrom(f, AOrder, None) }

  lemma AGateSpec(f: AFacts, ks: seq<AKind>, acc: Option<AKind>)
    ensures acc.Some? ==> AGateFrom(f, ks, acc) == acc
    ensures acc.None? ==> (AGateFrom(f, ks, acc).None? <==> forall i :: 0 <= i < |ks| ==> AHolds(f, ks[i]))
    decreases |ks|
  {
    if |ks| > 0 {
      var nx := if acc.Some? then acc else if AHolds(f, ks[0]) then None else Some(ks[0]);
      AGateSpec(f, ks[1..], nx);
      forall i | 0 <= i < |ks| - 1 { assert ks[1..][i] == ks[i + 1]; }
    }
  }

  // THEOREM (what an accepted manifest satisfies; in particular: a version below the last seen one is NEVER accepted, and the
  // same version with a different digest is never accepted; the validity window with the given skew holds).
  lemma AllowSound(f: AFacts)
    ensures AllowVerify(f).None? <==> forall i :: 0 <= i < |AOrder| ==> AHolds(f, AOrder[i])
    ensures AllowVerify(f).None? ==>
      f.shapeOk && f.issuerKnown && f.algMatches && f.issuerLive && f.sigOk && f.optionsOk &&
      f.notBefore - f.skew <= f.now && f.now <= f.expiresAt + f.skew &&
      (f.hasMaxLife ==> f.expiresAt - f.notBefore <= f.maxLife) &&
      (f.hasMin ==> f.version >= f.minV) &&
      (f.hasLast ==> f.version >= f.lastV) &&
      (f.hasLast && f.version == f.lastV && f.hasLastDigest ==> f.lastDigest == f.digest)
    ensures f.hasLast && f.version < f.lastV ==> AllowVerify(f).Some?
    ensures f.hasLast && f.version == f.lastV && f.hasLastDigest && f.lastDigest != f.digest ==> AllowVerify(f).Some?
    ensures !f.optionsOk ==> AllowVerify(f).Some?
  {
    AGateSpec(f, AOrder, None);
    if AllowVerify(f).None? {
      assert AOrder[0] == ASshape && AOrder[1] == AUnknownIssuer && AOrder[2] == AAlgMismatch && AOrder[3] == AIssuerExpired && AOrder[4] == ABadSig;
      assert AOrder[5] == AOptions && AOrder[6] == ANotYet && AOrder[7] == AExpired && AOrder[8] == ALifetime && AOrder[9] == ABelowMin && AOrder[10] == ARollback && AOrder[11] == AConflict;
    }
    if f.hasLast && f.version < f.lastV { assert AOrder[10] == ARollback && !AHolds(f, AOrder[10]); }
    if f.hasLast && f.version == f.lastV && f.hasLastDigest && f.lastDigest != f.digest { assert AOrder[11] == AConflict && !AHolds(f, AOrder[11]); }
    if !f.optionsOk { assert AOrder[5] == AOptions && !AHolds(f, AOrder[5]); }
  }

  // THEOREM (invalid options fail closed, right after the signature): with an authentic manifest (all earlier stages hold) and an
  // invalid numeric option the verdict is exactly `AOptions`, whatever the (meaningless) numbers are, so a NaN / Infinity skew
  // can never open the validity window.
  lemma OptionsFailClosed(f: AFacts)
    requires f.shapeOk && f.issuerKnown && f.algMatches && f.issuerLive && f.sigOk && !f.optionsOk
    ensures AllowVerify(f) == Some(AOptions)
  {
    AGateFirstFail(f, AOrder, 5);
  }
  lemma AGateFirstFail(f: AFacts, ks: seq<AKind>, j: int)
    requires 0 <= j < |ks| && (forall i :: 0 <= i < j ==> AHolds(f, ks[i])) && !AHolds(f, ks[j])
    ensures AGateFrom(f, ks, None) == Some(ks[j])
    decreases |ks|
  {
    if j == 0 { AGateSpec(f, ks[1..], Some(ks[0])); }
    else {
      assert AHolds(f, ks[0]);
      forall i | 0 <= i < j - 1 ensures AHolds(f, ks[1..][i]) { assert ks[1..][i] == ks[i + 1]; }
      AGateFirstFail(f, ks[1..], j - 1);
    }
  }

  // ---- the durable high-water mark (verifyAllowlistDurable) ----
  datatype KV = KMissing | KCorrupt | KVal(v: int, d: Id)
  function KvVersion(k: KV): int { if k.KVal? then k.v else 0 }

  // updater run inside kv.update: leave corrupt records alone; versions are APPEND-ONLY, so a record whose version is already >=
  // ours is kept as stored (equal version + same digest: nothing to do; equal version + other digest: reported as a conflict).
  function UpdateFn(cur: KV, v: int, d: Id): KV
  {
    if cur.KCorrupt? then cur
    else if cur.KVal? && cur.v >= v then cur
    else KVal(v, d)
  }

  datatype DOut = DAccept | DMalformed | DVerifyFail | DRollback | DConflict

  // One durable verification. `read` is what the first kv.get returned (possibly stale), `now` the record at update time.
  // `verifyOk` is the full verifyAllowlistManifest result for the (v, d) manifest against `read`.
  function DurableStep(read: KV, now: KV, verifyOk: bool, v: int, d: Id): (DOut, KV)
  {
    if read.KCorrupt? then (DMalformed, now)
    else if !verifyOk then (DVerifyFail, now)
    else
      var after := UpdateFn(now, v, d);
      if !after.KVal? then (DRollback, after)
      else if after.v > v then (DRollback, after)
      else if after.v == v && after.d != d then (DConflict, after)
      else (DAccept, after)
  }

  // THEOREM (rollback freedom under concurrency): whatever stale `read` was used, an accept leaves the store EXACTLY at (v, d),
  // which implies the store held nothing newer at the moment of the atomic update; and the stored version never decreases.
  lemma DurableSound(read: KV, now: KV, verifyOk: bool, v: int, d: Id)
    ensures DurableStep(read, now, verifyOk, v, d).0 == DAccept ==> DurableStep(read, now, verifyOk, v, d).1 == KVal(v, d) && verifyOk && !read.KCorrupt?
    ensures DurableStep(read, now, verifyOk, v, d).0 == DAccept ==> now.KMissing? || (now.KVal? && now.v <= v)
    ensures now.KVal? ==> KvVersion(DurableStep(read, now, verifyOk, v, d).1) >= now.v && DurableStep(read, now, verifyOk, v, d).1.KVal?
    ensures now.KCorrupt? ==> DurableStep(read, now, verifyOk, v, d).0 != DAccept
  {}

  // THEOREM (equal version, other digest = conflict, store untouched): a manifest racing a stored record of the SAME version with a
  // different digest is a `conflict` and the stored record is not overwritten (whatever the stale first read said).
  lemma EqualVersionConflict(read: KV, v: int, d0: Id, d: Id)
    requires !read.KCorrupt? && d0 != d
    ensures DurableStep(read, KVal(v, d0), true, v, d) == (DConflict, KVal(v, d0))
  {}
  // THEOREM (writes strictly increase the version): the updater writes only into a missing slot or over a STRICTLY older version;
  // otherwise the store is left exactly as it was.
  lemma WritesStrictlyIncrease(read: KV, now: KV, verifyOk: bool, v: int, d: Id)
    ensures var after := DurableStep(read, now, verifyOk, v, d).1;
            after == now || (after == KVal(v, d) && (now.KMissing? || (now.KVal? && now.v < v)))
  {}

  // Sequences of arbitrary (concurrent, stale-read) operations: accepted versions never go backwards.
  datatype DOp = DOp(read: KV, verifyOk: bool, v: int, d: Id)
  function DRun(st: KV, ops: seq<DOp>): (KV, seq<(int, Id)>)   // final store, accepted (version, digest) in order
    decreases |ops|
  {
    if |ops| == 0 then (st, [])
    else
      var r := DurableStep(ops[0].read, st, ops[0].verifyOk, ops[0].v, ops[0].d);
      var rest := DRun(r.1, ops[1..]);
      (rest.0, (if r.0 == DAccept then [(ops[0].v, ops[0].d)] else []) + rest.1)
  }
  lemma DRunMonotone(st: KV, ops: seq<DOp>)
    requires !st.KCorrupt? && forall i :: 0 <= i < |ops| ==> ops[i].v >= 0
    ensures (forall a, b :: 0 <= a < b < |DRun(st, ops).1| ==> DRun(st, ops).1[a].0 <= DRun(st, ops).1[b].0)
    ensures forall a :: 0 <= a < |DRun(st, ops).1| ==> DRun(st, ops).1[a].0 >= KvVersion(st)
    ensures KvVersion(DRun(st, ops).0) >= KvVersion(st) && !DRun(st, ops).0.KCorrupt?
    decreases |ops|
  {
    if |ops| > 0 {
      var r := DurableStep(ops[0].read, st, ops[0].verifyOk, ops[0].v, ops[0].d);
      DurableSound(ops[0].read, st, ops[0].verifyOk, ops[0].v, ops[0].d);
      assert !r.1.KCorrupt?;
      DRunMonotone(r.1, ops[1..]);
      var rest := DRun(r.1, ops[1..]);
      if r.0 == DAccept {
        assert r.1 == KVal(ops[0].v, ops[0].d);
        assert KvVersion(st) <= ops[0].v;
        forall a, b | 0 <= a < b < |rest.1| + 1 ensures ([(ops[0].v, ops[0].d)] + rest.1)[a].0 <= ([(ops[0].v, ops[0].d)] + rest.1)[b].0 {
          if a == 0 { assert ([(ops[0].v, ops[0].d)] + rest.1)[b] == rest.1[b - 1]; }
          else { assert ([(ops[0].v, ops[0].d)] + rest.1)[a] == rest.1[a - 1] && ([(ops[0].v, ops[0].d)] + rest.1)[b] == rest.1[b - 1]; }
        }
        forall a | 0 <= a < |rest.1| + 1 ensures ([(ops[0].v, ops[0].d)] + rest.1)[a].0 >= KvVersion(st) {
          if a > 0 { assert ([(ops[0].v, ops[0].d)] + rest.1)[a] == rest.1[a - 1]; }
        }
      } else {
        assert KvVersion(r.1) >= KvVersion(st);
      }
    }
  }

  // ---- anchored-feed scan (verifyAllowlistAnchored) ----
  datatype AEntry = AEntry(issuer: Id, version: int, digest: Id)

  predicate FeedConflict(es: seq<AEntry>, issuer: Id)
  {
    exists a, b :: 0 <= a < |es| && 0 <= b < |es| && es[a].issuer == issuer && es[b].issuer == issuer && es[a].version == es[b].version && es[a].digest != es[b].digest
  }
  function Highest(es: seq<AEntry>, issuer: Id): int
    decreases |es|
  {
    if |es| == 0 then 0
    else
      var h := Highest(es[1..], issuer);
      if es[0].issuer == issuer && es[0].version > h then es[0].version else h
  }
  predicate HasEntry(es: seq<AEntry>, e: AEntry) { e in es }

  datatype AnchorFail = ALogConflict | AAnchoredRollback | ANotAnchored
  // The decision after the proof checks: the order of the TS.
  function AnchorScan(es: seq<AEntry>, mine: AEntry): Option<AnchorFail>
  {
    if FeedConflict(es, mine.issuer) then Some(ALogConflict)
    else if mine.version < Highest(es, mine.issuer) then Some(AAnchoredRollback)
    else if !(exists a :: 0 <= a < |es| && es[a].issuer == mine.issuer && es[a].version == mine.version && es[a].digest == mine.digest) then Some(ANotAnchored)
    else None
  }

  lemma HighestSpec(es: seq<AEntry>, issuer: Id)
    ensures forall a :: 0 <= a < |es| && es[a].issuer == issuer ==> es[a].version <= Highest(es, issuer) || es[a].version <= 0
    ensures Highest(es, issuer) >= 0
    ensures Highest(es, issuer) > 0 ==> exists a :: 0 <= a < |es| && es[a].issuer == issuer && es[a].version == Highest(es, issuer)
    decreases |es|
  {
    if |es| > 0 {
      HighestSpec(es[1..], issuer);
      forall a | 0 <= a < |es| && es[a].issuer == issuer ensures es[a].version <= Highest(es, issuer) || es[a].version <= 0 {
        if a > 0 { assert es[1..][a - 1] == es[a]; }
      }
      if Highest(es, issuer) > 0 {
        if es[0].issuer == issuer && es[0].version > Highest(es[1..], issuer) { assert es[0].version == Highest(es, issuer); }
        else {
          var a :| 0 <= a < |es[1..]| && es[1..][a].issuer == issuer && es[1..][a].version == Highest(es[1..], issuer);
          assert es[1..][a] == es[a + 1];
        }
      }
    }
  }

  // THEOREM (anchored rollback freedom): an accept means the log holds no two digests for any version of this issuer, the
  // manifest's version is >= every version the log anchors for the issuer (so it IS the highest), and the manifest's own
  // (issuer, version, digest) is in the log.
  lemma AnchorSound(es: seq<AEntry>, mine: AEntry)
    requires mine.version >= 1
    ensures AnchorScan(es, mine).None? ==>
      !FeedConflict(es, mine.issuer) &&
      (forall a :: 0 <= a < |es| && es[a].issuer == mine.issuer ==> es[a].version <= mine.version) &&
      (exists a :: 0 <= a < |es| && es[a] == mine) &&
      Highest(es, mine.issuer) <= mine.version
    ensures AnchorScan(es, mine).None? ==> (forall a :: 0 <= a < |es| && es[a].issuer == mine.issuer && es[a].version == mine.version ==> es[a].digest == mine.digest)
    ensures (exists a :: 0 <= a < |es| && es[a].issuer == mine.issuer && es[a].version > mine.version) ==> AnchorScan(es, mine).Some?
  {
    HighestSpec(es, mine.issuer);
    if AnchorScan(es, mine).None? {
      forall a | 0 <= a < |es| && es[a].issuer == mine.issuer && es[a].version == mine.version ensures es[a].digest == mine.digest {
        var w :| 0 <= w < |es| && es[w].issuer == mine.issuer && es[w].version == mine.version && es[w].digest == mine.digest;
        assert !(es[a].digest != es[w].digest);
      }
    }
  }

  // ---- cache/consistency stage ----
  datatype CacheOut = CacheNone | CacheRollback | CacheSplitView | CacheNeedConsistency | CacheOk
  function CacheStage(hasCached: bool, headSize: int, cachedSize: int, rootsEqual: bool): CacheOut
  {
    if !hasCached then CacheNone
    else if headSize < cachedSize then CacheRollback
    else if headSize == cachedSize then (if rootsEqual then CacheOk else CacheSplitView)
    else CacheNeedConsistency
  }
  // THEOREM: with a pinned cached head, a smaller head is a rollback, an equal size with a different root is a split view, and
  // a larger head is acceptable only after a consistency proof.
  lemma CacheSound(hasCached: bool, headSize: int, cachedSize: int, rootsEqual: bool)
    ensures hasCached && headSize < cachedSize ==> CacheStage(hasCached, headSize, cachedSize, rootsEqual).CacheRollback?
    ensures hasCached && headSize == cachedSize && !rootsEqual ==> CacheStage(hasCached, headSize, cachedSize, rootsEqual).CacheSplitView?
    ensures hasCached && headSize > cachedSize ==> CacheStage(hasCached, headSize, cachedSize, rootsEqual).CacheNeedConsistency?
    ensures CacheStage(hasCached, headSize, cachedSize, rootsEqual).CacheOk? ==> hasCached && headSize == cachedSize && rootsEqual
  {}

  // head freshness (integers). `optionsOk`: clockSkewMs / maxHeadAgeMs, when supplied, are finite numbers (glue fact); checked
  // FIRST (the TS checks them right before the freshness comparisons), so a NaN / Infinity can never disable the window.
  datatype HeadAge = HeadBadOptions | HeadFuture | HeadStale | HeadFresh
  function HeadFreshness(optionsOk: bool, ts: int, now: int, skew: int, maxAge: int): HeadAge
  {
    if !optionsOk then HeadBadOptions
    else if ts > now + (if skew >= 0 then skew else 0) then HeadFuture else if now - ts > maxAge then HeadStale else HeadFresh
  }
  lemma HeadFreshnessSound(optionsOk: bool, ts: int, now: int, skew: int, maxAge: int)
    requires skew >= 0
    ensures HeadFreshness(optionsOk, ts, now, skew, maxAge).HeadFresh? <==> optionsOk && ts <= now + skew && now - ts <= maxAge
    ensures !optionsOk ==> HeadFreshness(optionsOk, ts, now, skew, maxAge).HeadBadOptions?
  {}
}
