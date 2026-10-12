(* SigUniq.ec -- Corollary C-1b (uniqueness of the accepted byte string) of proofs/01-core.md.
   For a DETERMINISTIC signature scheme (Ed25519: dsig sk m = dunit (sig sk m)), a forger that outputs two
   DISTINCT valid signatures on one message gives a SUF-CMA forger:
        Pr[Distinct(F)]  <=  Pr[SUF(B(F))]
   B runs F, asks its own oracle for the honest signature s0 on the message, and outputs whichever of the two
   forged signatures differs from s0. *)
require import AllCore List Distr.
require Sig.

type msg.
clone Sig.Scheme as S with type msg <- msg.

op sg : S.sk -> msg -> S.sg.
axiom det : forall sk m, S.dsig sk m = dunit (sg sk m).

module type F2 (O : S.Orcl) = {
  proc forge(pk : S.pk) : msg * S.sg * S.sg { O.sign }
}.

module Distinct (F : F2) = {
  var sk : S.sk
  module O : S.Orcl = {
    proc sign(m : msg) : S.sg = {
      var s : S.sg;
      s <$ S.dsig sk m;
      return s;
    }
  }
  proc main() : bool = {
    var k : S.pk * S.sk; var m : msg; var s1 : S.sg; var s2 : S.sg;
    k <$ S.dkey;
    sk <- k.`2;
    (m, s1, s2) <@ F(O).forge(k.`1);
    return S.ver k.`1 m s1 /\ S.ver k.`1 m s2 /\ s1 <> s2;
  }
}.

module B (F : F2) (O : S.Orcl) = {
  proc forge(pk : S.pk) : msg * S.sg = {
    var m : msg; var s1 : S.sg; var s2 : S.sg; var s0 : S.sg;
    (m, s1, s2) <@ F(O).forge(pk);
    s0 <@ O.sign(m);
    return (m, if s1 = s0 then s2 else s1);
  }
}.

section.
declare module F <: F2 {-Distinct, -S.SUF}.

lemma c1b &m : Pr[Distinct(F).main() @ &m : res] <= Pr[S.SUF(B(F)).main() @ &m : res].
proof.
byequiv (_ : ={glob F} ==> res{1} => res{2}) => //.
proc; inline *.
wp.
rnd{2}.
wp.
call (_ : Distinct.sk{1} = S.SUF.sk{2}
          /\ (forall m' x, (m', x) \in S.SUF.qs{2} => x = sg S.SUF.sk{2} m')).
+ proc; inline *; auto => /> &2 hinv s hs m' x; rewrite det supp_dunit in hs; smt().
wp; rnd; wp; skip => />.
smt(det supp_dunit dunit_ll).
qed.
end section.
