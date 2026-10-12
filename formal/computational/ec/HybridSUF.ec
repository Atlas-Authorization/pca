(* HybridSUF.ec -- strong unforgeability of the AND-combiner (Theorem H-2 of
   docs/pca/security/proofs/02-threshold-hybrid.md, CORRECTED).

   The original statement (no assumption on the components) is false for randomised components: from two
   answers (a1,b1), (a2,b2) on the same message the pair (a1,b2) is a valid, never-returned pair
   ("mix and match") although neither component was forged.  The correct statement needs one component to be
   deterministic (Ed25519 is):

     h2 :  Pr[SUF_AND(A)] <= Pr[SUF_S1(B1(A))] + Pr[SUF_S2(B2(A))]        when S1 is deterministic,

   with the same reductions B1, B2 as in Hybrid.ec (H-1).  Proof: a winning forgery (m,(s1,s2)) either has
   (m,s1) not returned by the S1-oracle (B1 wins), or (m,s1) was returned, so s1 = sig1(m); then (m,s2) not
   returned by the S2-oracle (else the pair (s1,s2) would have been returned for the same query, since all
   answers on m share s1), so B2 wins. *)
require import AllCore List Distr.
require import Hybrid.

op sig1 : S1.sk -> msg -> S1.sg.
axiom det1 : forall sk m, S1.dsig sk m = dunit (sig1 sk m).

module SUFAnd(A : AF) = {
  var sk1 : S1.sk
  var sk2 : S2.sk
  var qs : (msg * (S1.sg * S2.sg)) list
  var e1 : bool
  var e2 : bool

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <$ S2.dsig sk2 m;
      qs <- (m, (s1, s2)) :: qs;
      return (s1, s2);
    }
  }

  proc main() : bool = {
    var k1 : S1.pk * S1.sk;
    var k2 : S2.pk * S2.sk;
    var m : msg;
    var s : S1.sg * S2.sg;
    k1 <$ S1.dkey;
    k2 <$ S2.dkey;
    sk1 <- k1.`2;
    sk2 <- k2.`2;
    qs <- [];
    (m, s) <@ A(O).forge((k1.`1, k2.`1));
    e1 <- S1.ver k1.`1 m s.`1 /\ !((m, s.`1) \in map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`1)) qs);
    e2 <- S2.ver k2.`1 m s.`2 /\ !((m, s.`2) \in map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`2)) qs);
    return S1.ver k1.`1 m s.`1 /\ S2.ver k2.`1 m s.`2 /\ !((m, s) \in qs);
  }
}.

lemma split_pure (qs : (msg * (S1.sg * S2.sg)) list) (sk : S1.sk) (m : msg) (s : S1.sg * S2.sg) :
  (forall q, q \in qs => q.`2.`1 = sig1 sk q.`1) =>
  !((m, s) \in qs) =>
  (m, s.`1) \in map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`1)) qs =>
  (m, s.`2) \in map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`2)) qs => false.
proof.
move=> hq hn /mapP [q1 [hq1 e1]] /mapP [q2 [hq2 e2]].
have h1 := hq q1 hq1.
have h2 := hq q2 hq2.
have : (m, s) \in qs.
+ have -> : (m, s) = q2 by smt().
  exact hq2.
done.
qed.

section.
declare module A <: AF {-SUFAnd, -S1.SUF, -S2.SUF, -B1, -B2}.

(* determinism: a winning pair is caught by e1 or e2 *)
lemma h2_split &m :
  Pr[SUFAnd(A).main() @ &m : res] <= Pr[SUFAnd(A).main() @ &m : SUFAnd.e1 \/ SUFAnd.e2].
proof.
byequiv (_ : ={glob A} ==> res{1} => (SUFAnd.e1 \/ SUFAnd.e2){2}) => //.
proc.
wp.
call (_ : ={SUFAnd.sk1, SUFAnd.sk2, SUFAnd.qs}
          /\ (forall q, q \in SUFAnd.qs{1} => q.`2.`1 = sig1 SUFAnd.sk1{1} q.`1)).
+ proc; wp; rnd; rnd; skip => /> &2 hinv s1 hs1 s2 hs2 q.
  rewrite det1 supp_dunit in hs1.
  by rewrite hs1; smt().
wp; rnd; rnd; skip; smt(split_pure).
qed.

lemma h2_first &m :
  Pr[SUFAnd(A).main() @ &m : SUFAnd.e1] <= Pr[S1.SUF(B1(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> SUFAnd.e1{1} => res{2}) => //.
proc.
inline *.
wp.
call (_ : SUFAnd.sk1{1} = S1.SUF.sk{2} /\ SUFAnd.sk2{1} = B1.sk2{2}
          /\ S1.SUF.qs{2} = map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`1)) SUFAnd.qs{1}).
+ proc; inline *; swap{2} 5 -2; wp; rnd; rnd; wp; skip => /> *.
auto => /> *; smt().
qed.

lemma h2_second &m :
  Pr[SUFAnd(A).main() @ &m : SUFAnd.e2] <= Pr[S2.SUF(B2(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> SUFAnd.e2{1} => res{2}) => //.
proc.
inline *.
swap{1} 1 1.
wp.
call (_ : SUFAnd.sk1{1} = B2.sk1{2} /\ SUFAnd.sk2{1} = S2.SUF.sk{2}
          /\ S2.SUF.qs{2} = map (fun (q : msg * (S1.sg * S2.sg)) => (q.`1, q.`2.`2)) SUFAnd.qs{1}).
+ proc; inline *; wp; rnd; wp; rnd; wp; skip => /> *.
auto => /> *; smt().
qed.

(* H-2 (corrected): the AND-combiner with a deterministic first component is SUF-CMA secure if both are *)
lemma h2 &m :
  Pr[SUFAnd(A).main() @ &m : res]
  <= Pr[S1.SUF(B1(A)).main() @ &m : res] + Pr[S2.SUF(B2(A)).main() @ &m : res].
proof.
have h := h2_split &m.
have h1 := h2_first &m.
have h2 := h2_second &m.
have h3 : Pr[SUFAnd(A).main() @ &m : SUFAnd.e1 \/ SUFAnd.e2]
          <= Pr[SUFAnd(A).main() @ &m : SUFAnd.e1] + Pr[SUFAnd(A).main() @ &m : SUFAnd.e2].
+ by rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

end section.
