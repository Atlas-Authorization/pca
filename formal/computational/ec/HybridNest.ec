(* HybridNest.ec -- Theorem H-3 of proofs/02-threshold-hybrid.md: the NESTED combiner.
   S1 signs m, S2 signs the pair (m, sigma1).
        Adv^euf_nest <= Adv^euf_S1(B1)   and   Adv^euf_nest <= Adv^euf_S2(B2)        (so <= min)
        Adv^suf_nest <= Adv^suf_S2(B2)                                                  (no determinism needed)
   The message of S2 is (m, s1); freshness of (m', s1') for S2 follows from freshness of m', and a
   never-returned pair ((m',s1'),s2') for S2 gives a never-returned triple for the nested scheme. *)
require import AllCore List Distr.
require Sig.

type msg.
clone Sig.Scheme as S1 with type msg <- msg.
clone Sig.Scheme as S2 with type msg <- msg * S1.sg.

module type NOrcl = { proc sign(m : msg) : S1.sg * S2.sg }.
module type NF (O : NOrcl) = { proc forge(pk : S1.pk * S2.pk) : msg * (S1.sg * S2.sg) { O.sign } }.

module EUFNest (A : NF) = {
  var sk1 : S1.sk
  var sk2 : S2.sk
  var qm : msg list
  module O : NOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg; var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <$ S2.dsig sk2 (m, s1);
      qm <- m :: qm;
      return (s1, s2);
    }
  }
  proc main() : bool = {
    var k1 : S1.pk * S1.sk; var k2 : S2.pk * S2.sk; var m : msg; var s : S1.sg * S2.sg;
    k1 <$ S1.dkey;
    k2 <$ S2.dkey;
    sk1 <- k1.`2;
    sk2 <- k2.`2;
    qm <- [];
    (m, s) <@ A(O).forge((k1.`1, k2.`1));
    return S1.ver k1.`1 m s.`1 /\ S2.ver k2.`1 (m, s.`1) s.`2 /\ !(m \in qm);
  }
}.

module SUFNest (A : NF) = {
  var sk1 : S1.sk
  var sk2 : S2.sk
  var qs : (msg * (S1.sg * S2.sg)) list
  module O : NOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg; var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <$ S2.dsig sk2 (m, s1);
      qs <- (m, (s1, s2)) :: qs;
      return (s1, s2);
    }
  }
  proc main() : bool = {
    var k1 : S1.pk * S1.sk; var k2 : S2.pk * S2.sk; var m : msg; var s : S1.sg * S2.sg;
    k1 <$ S1.dkey;
    k2 <$ S2.dkey;
    sk1 <- k1.`2;
    sk2 <- k2.`2;
    qs <- [];
    (m, s) <@ A(O).forge((k1.`1, k2.`1));
    return S1.ver k1.`1 m s.`1 /\ S2.ver k2.`1 (m, s.`1) s.`2 /\ !((m, s) \in qs);
  }
}.

(* reduction to S2 (EUF and SUF): simulate S1 locally, forward S2's signing to the oracle *)
module B2 (A : NF) (O2 : S2.Orcl) = {
  var sk1 : S1.sk
  module O : NOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg; var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <@ O2.sign((m, s1));
      return (s1, s2);
    }
  }
  proc forge(pk2 : S2.pk) : (msg * S1.sg) * S2.sg = {
    var k1 : S1.pk * S1.sk; var m : msg; var s : S1.sg * S2.sg;
    k1 <$ S1.dkey;
    sk1 <- k1.`2;
    (m, s) <@ A(O).forge((k1.`1, pk2));
    return ((m, s.`1), s.`2);
  }
}.

(* reduction to S1 (EUF) *)
module B1 (A : NF) (O1 : S1.Orcl) = {
  var sk2 : S2.sk
  module O : NOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg; var s2 : S2.sg;
      s1 <@ O1.sign(m);
      s2 <$ S2.dsig sk2 (m, s1);
      return (s1, s2);
    }
  }
  proc forge(pk1 : S1.pk) : msg * S1.sg = {
    var k2 : S2.pk * S2.sk; var m : msg; var s : S1.sg * S2.sg;
    k2 <$ S2.dkey;
    sk2 <- k2.`2;
    (m, s) <@ A(O).forge((pk1, k2.`1));
    return (m, s.`1);
  }
}.

section.
declare module A <: NF {-EUFNest, -SUFNest, -S1.EUF, -S2.EUF, -S2.SUF, -B1, -B2}.

lemma h3_euf_s1 &m : Pr[EUFNest(A).main() @ &m : res] <= Pr[S1.EUF(B1(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline *.
wp.
call (_ : EUFNest.sk1{1} = S1.EUF.sk{2} /\ EUFNest.sk2{1} = B1.sk2{2} /\ EUFNest.qm{1} = S1.EUF.qm{2}).
+ proc; inline *; swap{1} 3 -1; auto => />.
auto => />.
qed.

lemma h3_euf_s2 &m : Pr[EUFNest(A).main() @ &m : res] <= Pr[S2.EUF(B2(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline *.
swap{1} 1 1.
wp.
call (_ : EUFNest.sk1{1} = B2.sk1{2} /\ EUFNest.sk2{1} = S2.EUF.sk{2}
          /\ (forall x, x \in S2.EUF.qm{2} => x.`1 \in EUFNest.qm{1})).
+ proc; inline *; wp; rnd; wp; rnd; skip => />; smt().
wp; rnd; wp; rnd; wp; skip => />.
smt().
qed.

lemma h3_suf_s2 &m : Pr[SUFNest(A).main() @ &m : res] <= Pr[S2.SUF(B2(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline *.
swap{1} 1 1.
wp.
call (_ : SUFNest.sk1{1} = B2.sk1{2} /\ SUFNest.sk2{1} = S2.SUF.sk{2}
          /\ (forall x, x \in S2.SUF.qs{2} => exists q, q \in SUFNest.qs{1} /\ x.`1 = (q.`1, q.`2.`1) /\ x.`2 = q.`2.`2)).
+ proc; inline *; wp; rnd; wp; rnd; skip => />; smt().
wp; rnd; wp; rnd; wp; skip => />.
smt().
qed.
end section.
