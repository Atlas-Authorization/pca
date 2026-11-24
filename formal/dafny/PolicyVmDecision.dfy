// PolicyVmDecision.dfy - Unknown never yields Allow (goal-to-decision G-T4). Includes PolicyVm.dfy; verified, not extracted.
include "PolicyVm.dfy"
module PolicyVmDecision {
  import opened PolicyVm
  datatype Dec = DDeny | DEscalate | DAllow
  // decision of a conjunction of leaf results: all TT -> allow; any TF -> deny; else (some TU, none TF) -> escalate
  function DecOf(ts: seq<Tri>): Dec {
    if AllT(ts) == TT then DAllow else if AllT(ts) == TF then DDeny else DEscalate
  }
  lemma UnknownNeverAllows(ts: seq<Tri>) requires TU in ts ensures DecOf(ts) != DAllow {
    if AllT(ts) == TT { AllTrueIff(ts); var i :| 0 <= i < |ts| && ts[i] == TU; assert ts[i] == TT; }
  }
  lemma AllowIffAllTrue(ts: seq<Tri>) ensures DecOf(ts) == DAllow <==> (forall i :: 0 <= i < |ts| ==> ts[i] == TT) { AllTrueIff(ts); }
  lemma FalseDenies(ts: seq<Tri>) requires TF in ts ensures DecOf(ts) == DDeny {}
  lemma EscalateHasUnknownNoFalse(ts: seq<Tri>) requires DecOf(ts) == DEscalate ensures TU in ts && !(TF in ts) {}
}
