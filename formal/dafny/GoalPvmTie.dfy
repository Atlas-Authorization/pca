// GoalPvmTie.dfy - the Kleene operators of the Goal semantics (GoalIr: ranked integers, meet = min, join = max) are exactly the
// operators of the proved PolicyVm model (`Tri`, AllT, AnyT, NotT). Verification only (never extracted): it includes PolicyVm.dfy.
// No assume / axiom / extern.
include "GoalIr.dfy"
include "PolicyVm.dfy"
module GoalPvmTie {
  import G = GoalIr
  import P = PolicyVm

  function ToPvm(t: G.Tri): P.Tri { if t == 2 then P.TT else if t == 1 then P.TU else P.TF }

  lemma NotTie(x: G.Tri) ensures ToPvm(G.NotK(x)) == P.NotT(ToPvm(x)) {}

  lemma AndTie(x: G.Tri, y: G.Tri) ensures ToPvm(G.AndK(x, y)) == P.AllT([ToPvm(x), ToPvm(y)]) {
    var a := ToPvm(x); var b := ToPvm(y);
    assert a in [a, b] && b in [a, b];
    if x == 0 || y == 0 { assert P.TF in [a, b]; }
    else if x == 1 || y == 1 { assert P.TF !in [a, b]; assert P.TU in [a, b]; }
    else { assert P.TF !in [a, b] && P.TU !in [a, b]; }
  }

  lemma OrTie(x: G.Tri, y: G.Tri) ensures ToPvm(G.OrK(x, y)) == P.AnyT([ToPvm(x), ToPvm(y)]) {
    var a := ToPvm(x); var b := ToPvm(y);
    assert a in [a, b] && b in [a, b];
    if x == 2 || y == 2 { assert P.TT in [a, b]; }
    else if x == 1 || y == 1 { assert P.TT !in [a, b]; assert P.TU in [a, b]; }
    else { assert P.TT !in [a, b] && P.TU !in [a, b]; }
  }
}
