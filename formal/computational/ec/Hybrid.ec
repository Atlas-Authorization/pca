(* Hybrid.ec -- the AND-combiner of two signature schemes (Theorem H-1 of
   docs/pca/security/proofs/02-threshold-hybrid.md), and the negative result H-4
   (an UNPINNED second key gives exactly the security of the first scheme).

   Scheme combination (procedural, so no distribution algebra is needed):
     KeyGen : (pk1,sk1) <- KG1 ; (pk2,sk2) <- KG2 ; pk=(pk1,pk2), sk=(sk1,sk2)
     Sign   : s1 <- Sign1 sk1 m ; s2 <- Sign2 sk2 m ; (s1,s2)
     Verify : Ver1 pk1 m s1  /\  Ver2 pk2 m s2

   H-1 : for every EUF-CMA adversary A against the combiner there are forgers
         B1 (against S1) and B2 (against S2), each running A once, with
            Pr[EUF_AND(A)] <= Pr[EUF_S1(B1(A))]   and   Pr[EUF_AND(A)] <= Pr[EUF_S2(B2(A))]
         so Adv_AND <= min(Adv_S1, Adv_S2) : secure if EITHER component is. *)
require import AllCore List Distr.
require Sig.

type msg.

clone Sig.Scheme as S1 with type msg <- msg.
clone Sig.Scheme as S2 with type msg <- msg.

module type AOrcl = { proc sign(m : msg) : S1.sg * S2.sg }.

module type AF(O : AOrcl) = {
  proc forge(pk : S1.pk * S2.pk) : msg * (S1.sg * S2.sg) {O.sign}
}.

module EUFAnd(A : AF) = {
  var sk1 : S1.sk
  var sk2 : S2.sk
  var qm : msg list

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <$ S2.dsig sk2 m;
      qm <- m :: qm;
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
    qm <- [];
    (m, s) <@ A(O).forge((k1.`1, k2.`1));
    return S1.ver k1.`1 m s.`1 /\ S2.ver k2.`1 m s.`2 /\ !(m \in qm);
  }
}.

(* reduction to the first component: B1 generates the second key pair itself *)
module B1(A : AF, O1 : S1.Orcl) = {
  var sk2 : S2.sk

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <@ O1.sign(m);
      s2 <$ S2.dsig sk2 m;
      return (s1, s2);
    }
  }

  proc forge(pk1 : S1.pk) : msg * S1.sg = {
    var k2 : S2.pk * S2.sk;
    var m : msg;
    var s : S1.sg * S2.sg;
    k2 <$ S2.dkey;
    sk2 <- k2.`2;
    (m, s) <@ A(O).forge((pk1, k2.`1));
    return (m, s.`1);
  }
}.

(* reduction to the second component *)
module B2(A : AF, O2 : S2.Orcl) = {
  var sk1 : S1.sk

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <@ O2.sign(m);
      return (s1, s2);
    }
  }

  proc forge(pk2 : S2.pk) : msg * S2.sg = {
    var k1 : S1.pk * S1.sk;
    var m : msg;
    var s : S1.sg * S2.sg;
    k1 <$ S1.dkey;
    sk1 <- k1.`2;
    (m, s) <@ A(O).forge((k1.`1, pk2));
    return (m, s.`2);
  }
}.

section.

declare module A <: AF {-EUFAnd, -S1.EUF, -S2.EUF, -B1, -B2}.

lemma h1_first &m :
  Pr[EUFAnd(A).main() @ &m : res] <= Pr[S1.EUF(B1(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc.
inline *.
wp.
call (_ : EUFAnd.sk1{1} = S1.EUF.sk{2} /\ EUFAnd.sk2{1} = B1.sk2{2} /\ EUFAnd.qm{1} = S1.EUF.qm{2}).
+ proc; inline *; swap{1} 3 -1; wp; rnd; wp; rnd; wp; skip => /> *.
auto => /> *; smt().
qed.

lemma h1_second &m :
  Pr[EUFAnd(A).main() @ &m : res] <= Pr[S2.EUF(B2(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc.
inline *.
swap{1} 1 1.
wp.
call (_ : EUFAnd.sk1{1} = B2.sk1{2} /\ EUFAnd.sk2{1} = S2.EUF.sk{2} /\ EUFAnd.qm{1} = S2.EUF.qm{2}).
+ proc; inline *; wp; rnd; wp; rnd; wp; skip => /> *.
auto => /> *; smt().
qed.

(* H-1 : the AND-combiner is EUF-CMA secure if EITHER component is. *)
lemma h1_min &m :
  Pr[EUFAnd(A).main() @ &m : res] <=
  if Pr[S1.EUF(B1(A)).main() @ &m : res] <= Pr[S2.EUF(B2(A)).main() @ &m : res]
  then Pr[S1.EUF(B1(A)).main() @ &m : res] else Pr[S2.EUF(B2(A)).main() @ &m : res].
proof. by have h1 := h1_first &m; have h2 := h1_second &m; smt(). qed.

end section.

(* ------------------------------------------------------------------ *)
(* H-4 : the implemented leaf/hop hybrid has the security of S1 alone.   *)
(* In the implementation the second (post-quantum) public key and its   *)
(* signature are fields of the artifact being verified, so the          *)
(* adversary supplies them.  Verification is then                        *)
(*      Ver1 pk1 m s1  /\  Ver2 pk2' m s2'      with (pk2', s2') chosen by the forger *)

(* correctness of the second scheme: honestly generated signatures verify *)
axiom corr2 : forall (k : S2.pk * S2.sk) m s,
  k \in S2.dkey => s \in S2.dsig k.`2 m => S2.ver k.`1 m s.

module type UF(O : AOrcl) = {
  proc forge(pk1 : S1.pk) : msg * S1.sg * S2.pk * S2.sg {O.sign}
}.

module EUFUnpinned(A : UF) = {
  var sk1 : S1.sk
  var sk2 : S2.sk
  var qm : msg list

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <$ S1.dsig sk1 m;
      s2 <$ S2.dsig sk2 m;
      qm <- m :: qm;
      return (s1, s2);
    }
  }

  proc main() : bool = {
    var k1 : S1.pk * S1.sk;
    var k2 : S2.pk * S2.sk;
    var m : msg;
    var s1 : S1.sg;
    var pk2 : S2.pk;
    var s2 : S2.sg;
    k1 <$ S1.dkey;
    k2 <$ S2.dkey;
    sk1 <- k1.`2;
    sk2 <- k2.`2;
    qm <- [];
    (m, s1, pk2, s2) <@ A(O).forge(k1.`1);
    return S1.ver k1.`1 m s1 /\ S2.ver pk2 m s2 /\ !(m \in qm);
  }
}.

(* (i) upper bound: a forger against the unpinned hybrid is a forger against S1 *)
module BU(A : UF, O1 : S1.Orcl) = {
  var sk2 : S2.sk

  module O : AOrcl = {
    proc sign(m : msg) : S1.sg * S2.sg = {
      var s1 : S1.sg;
      var s2 : S2.sg;
      s1 <@ O1.sign(m);
      s2 <$ S2.dsig sk2 m;
      return (s1, s2);
    }
  }

  proc forge(pk1 : S1.pk) : msg * S1.sg = {
    var k2 : S2.pk * S2.sk;
    var m : msg;
    var s1 : S1.sg;
    var pk2 : S2.pk;
    var s2 : S2.sg;
    k2 <$ S2.dkey;
    sk2 <- k2.`2;
    (m, s1, pk2, s2) <@ A(O).forge(pk1);
    return (m, s1);
  }
}.

(* (ii) lower bound: any S1 forger B yields an unpinned-hybrid forger with the same success *)
module type F1(O : S1.Orcl) = {
  proc forge(pk : S1.pk) : msg * S1.sg {O.sign}
}.

module AU(B : F1, O : AOrcl) = {
  module O1 : S1.Orcl = {
    proc sign(m : msg) : S1.sg = {
      var s : S1.sg * S2.sg;
      s <@ O.sign(m);
      return s.`1;
    }
  }

  proc forge(pk1 : S1.pk) : msg * S1.sg * S2.pk * S2.sg = {
    var m : msg;
    var s1 : S1.sg;
    var k2 : S2.pk * S2.sk;
    var s2 : S2.sg;
    (m, s1) <@ B(O1).forge(pk1);
    k2 <$ S2.dkey;
    s2 <$ S2.dsig k2.`2 m;
    return (m, s1, k2.`1, s2);
  }
}.

section.

declare module U <: UF {-EUFUnpinned, -S1.EUF, -BU}.

lemma h4_upper &m :
  Pr[EUFUnpinned(U).main() @ &m : res] <= Pr[S1.EUF(BU(U)).main() @ &m : res].
proof.
byequiv (_ : ={glob U} ==> res{1} => res{2}) => //.
proc.
inline *.
wp.
call (_ : EUFUnpinned.sk1{1} = S1.EUF.sk{2} /\ EUFUnpinned.sk2{1} = BU.sk2{2} /\ EUFUnpinned.qm{1} = S1.EUF.qm{2}).
+ proc; inline *; swap{1} 3 -1; wp; rnd; wp; rnd; wp; skip => /> *.
auto => /> *; smt().
qed.

end section.

section.

declare module B <: F1 {-EUFUnpinned, -S1.EUF, -AU}.

(* Pr[forge S1] <= Pr[forge unpinned hybrid]: the PQ half adds NOTHING against an S1 forger. *)
lemma h4_lower &m :
  Pr[S1.EUF(B).main() @ &m : res] <= Pr[EUFUnpinned(AU(B)).main() @ &m : res].
proof.
byequiv (_ : ={glob B} ==> res{1} => res{2}) => //.
proc.
inline *.
wp.
rnd{2}; rnd{2}.
wp.
call (_ : S1.EUF.sk{1} = EUFUnpinned.sk1{2} /\ S1.EUF.qm{1} = EUFUnpinned.qm{2}).
+ proc; inline *; wp; rnd{2}; wp; rnd; wp; skip => /> *.
  smt(S2.dsig_ll).
wp; rnd{2}; rnd; skip => /> *.
smt(S2.dkey_ll S2.dsig_ll corr2).
qed.

end section.
