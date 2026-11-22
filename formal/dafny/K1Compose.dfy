// K1Compose.dfy - the caveat language (track K1) composes with the verified policy VM as a PURE CONJUNCTION. Includes PolicyVm.dfy;
// verified, not extracted. No assume / axiom / extern.
//
// The TypeScript glue takes the K1 caveat types (needs_discharge, sealed, max_uses, derive, spiffe_bound) out of the lists the proved
// VM sees, evaluates them with the caveat language, and feeds `vmOk && k1Ok` to the proved `DecideCore` as the delegated-caveat input.
// What the proofs below give:
//   SplitConjunction    evaluating a list with a per-caveat evaluator that sends K1 caveats to `k1` and the rest to `vm` holds
//                       exactly when the filtered rest holds under `vm` AND the filtered K1 caveats hold under `k1`
//                       (so the take-out step loses nothing and adds nothing).
//   UnknownTypeUnsatisfied  a caveat whose type the VM does not implement is unsatisfied by the VM: a K1 caveat left in the VM's
//                       input would refuse, never pass (a stale glue fails closed).
//   K1RefusalNeverReleases  a K1 failure (k1Ok false) never releases, and k1Ok true leaves the release exactly as the VM decided it.
include "PolicyVm.dfy"
module K1Compose {
  import opened PolicyVm

  predicate AllOk<T>(cs: seq<T>, ev: T -> bool) { forall i :: 0 <= i < |cs| ==> ev(cs[i]) }

  function Keep<T>(cs: seq<T>, p: T -> bool): seq<T> decreases cs {
    if |cs| == 0 then [] else (if p(cs[0]) then [cs[0]] else []) + Keep(cs[1..], p)
  }

  lemma AllOkCons<T>(cs: seq<T>, ev: T -> bool)
    requires |cs| > 0
    ensures AllOk(cs, ev) <==> (ev(cs[0]) && AllOk(cs[1..], ev))
  {
    if AllOk(cs, ev) {
      forall i | 0 <= i < |cs[1..]| ensures ev(cs[1..][i]) { assert cs[1..][i] == cs[i + 1]; }
    }
    if ev(cs[0]) && AllOk(cs[1..], ev) {
      forall i | 0 <= i < |cs| ensures ev(cs[i]) { if i > 0 { assert cs[i] == cs[1..][i - 1]; } }
    }
  }

  lemma SplitConjunction<T>(cs: seq<T>, isK1: T -> bool, k1: T -> bool, vm: T -> bool)
    ensures AllOk(cs, (c: T) => if isK1(c) then k1(c) else vm(c))
        <==> (AllOk(Keep(cs, (c: T) => !isK1(c)), vm) && AllOk(Keep(cs, isK1), k1))
    decreases cs
  {
    if |cs| > 0 {
      var ev := (c: T) => if isK1(c) then k1(c) else vm(c);
      SplitConjunction(cs[1..], isK1, k1, vm);
      AllOkCons(cs, ev);
      var rest := cs[1..];
      var restVm := Keep(rest, (c: T) => !isK1(c));
      var restK1 := Keep(rest, isK1);
      if isK1(cs[0]) {
        assert Keep(cs, (c: T) => !isK1(c)) == restVm;
        assert Keep(cs, isK1) == [cs[0]] + restK1;
        AllOkCons([cs[0]] + restK1, k1);
        assert ([cs[0]] + restK1)[1..] == restK1;
      } else {
        assert Keep(cs, (c: T) => !isK1(c)) == [cs[0]] + restVm;
        assert Keep(cs, isK1) == restK1;
        AllOkCons([cs[0]] + restVm, vm);
        assert ([cs[0]] + restVm)[1..] == restVm;
      }
    }
  }

  // A caveat whose type is none of the names the VM implements is unsatisfied by the VM (the K1 names are such names).
  lemma UnknownTypeUnsatisfied(cv: Value, ctx: Value, rx: Rx, fl: Fl, tool: ToolEv)
    requires Field(cv, S("type")).VStr?
    requires Field(cv, S("type")) != VStr(S("tool_schema")) && Field(cv, S("type")) != VStr(S("predicates")) && Field(cv, S("type")) != VStr(S("max_spend"))
    requires Field(cv, S("type")).s != S("expires") && Field(cv, S("type")).s != S("not_before") && Field(cv, S("type")).s != S("rate")
    requires Field(cv, S("type")).s != S("max_blast_radius") && Field(cv, S("type")).s != S("reversibility_max")
    requires Field(cv, S("type")).s != S("delegation_depth") && Field(cv, S("type")).s != S("budget_alloc") && Field(cv, S("type")).s != S("intent_session")
    ensures !AgentEv(cv, ctx, rx, fl, tool)
  {
  }

  // A K1 failure never releases; a K1 pass leaves the VM's own release untouched.
  lemma K1RefusalNeverReleases(prOk: bool, cvOk: bool, dcvOk: bool, chainOk: bool, rt: Thr, adm: Adm)
    ensures !DecideCore(prOk, cvOk, dcvOk && false, chainOk, rt, adm).release
    ensures DecideCore(prOk, cvOk, dcvOk && true, chainOk, rt, adm) == DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm)
    ensures !DecideCore(prOk, cvOk, dcvOk && false, chainOk, rt, adm).admit
  {
  }
}
