(* MU.ec -- generic multi-user unforgeability with a hash-collision escape.

   World: n honest key pairs (pk_i, sk_i), i in [0,n).  The adversary sees all
   public keys, then statically corrupts a set cs of indices (gets those secret keys),
   and gets a signing oracle  sign(i, c)  that signs  msgof c  under sk_i and logs (i,c).
   It outputs `out`; a pure function `claims` reads from `out` the list of
   (verification key, context, signature) triples that the verifier would check.

   The event ev is: there is an UNCORRUPTED honest index i and a claim
   (pk_i, c, s) whose signature verifies on msgof c although (i, c) was never
   submitted to the oracle.

   Theorem mu_bound (below):
        Pr[ev]  <=  Pr[CR(CA(A))]  +  n * eps
   where eps bounds the EUF-CMA advantage of the reduction BR(A) (one key embedded
   at a guessed index).  The hash enters only through the explicit hypothesis
   msgof_coll: two different contexts with the same message yield an explicit
   pair of different byte strings with equal hash. *)
require import AllCore List Distr FMap Int Real.
require import StdBigop StdOrder.
import RealOrder.
import Bigreal.BRA.
require Sig.

abstract theory MultiUser.

clone include Sig.Scheme.

type bytes.
type dig.
op H : bytes -> dig.

type ctx.
type out.

op msgof : ctx -> msg.

(* collision extraction: this is where "canonical encoding injectivity" and
   "domain separation" are consumed.  It is an hypothesis of the theory and is
   DISCHARGED at each instantiation (see Core.ec / Multisig.ec). *)
op cx : ctx -> ctx -> bytes * bytes.
axiom msgof_coll (c c' : ctx) :
  c <> c' => msgof c = msgof c' =>
  (cx c c').`1 <> (cx c c').`2 /\ H (cx c c').`1 = H (cx c c').`2.

const n : int.
axiom n_pos : 0 < n.

op claims : out -> (pk * ctx * sg) list.

(* ---------------------------------------------------------------- *)
(* the multi-user game                                               *)

module type MOrcl = {
  proc sign(i : int, c : ctx) : sg
}.

module type MAdv(O : MOrcl) = {
  proc corrupt(pks : pk list) : int list {O.sign}
  proc attack(pks : pk list, cks : (int * sk) list) : out {O.sign}
}.

type tr = {
  trcs  : int list;
  trpk  : pk list;
  trlog : (int * ctx) list;
  trout : out;
}.

op pkl (ks : (int, pk * sk) fmap) : pk list =
  map (fun j => (oget ks.[j]).`1) (iota_ 0 n).

op ckl (ks : (int, pk * sk) fmap) (cs : int list) : (int * sk) list =
  map (fun j => (j, (oget ks.[j]).`2)) cs.

module MG(A : MAdv) = {
  var ks : (int, pk * sk) fmap
  var cs : int list
  var lg : (int * ctx) list

  module O : MOrcl = {
    proc sign(i : int, c : ctx) : sg = {
      var s : sg;
      s <- witness;
      if (0 <= i /\ i < n) {
        s <$ dsig (oget ks.[i]).`2 (msgof c);
        lg <- (i, c) :: lg;
      }
      return s;
    }
  }

  proc main() : tr = {
    var j : int;
    var x : pk * sk;
    var o : out;
    ks <- empty;
    j <- 0;
    while (j < n) {
      x <$ dkey;
      ks.[j] <- x;
      j <- j + 1;
    }
    lg <- [];
    cs <@ A(O).corrupt(pkl ks);
    o <@ A(O).attack(pkl ks, ckl ks cs);
    return {| trcs = cs; trpk = pkl ks; trlog = lg; trout = o |};
  }
}.

(* ---------------------------------------------------------------- *)
(* events                                                            *)

op qmsgs (i : int) (lg : (int * ctx) list) : msg list =
  map (fun (x : int * ctx) => msgof x.`2) (filter (fun (x : int * ctx) => x.`1 = i) lg).

pred good_claim (t : tr) (i : int) (cl : pk * ctx * sg) =
  cl \in claims t.`trout /\ cl.`1 = nth witness t.`trpk i /\
  ver cl.`1 (msgof cl.`2) cl.`3 /\ !((i, cl.`2) \in t.`trlog).

pred fev (i : int) (t : tr) =
  0 <= i /\ i < n /\ !(i \in t.`trcs) /\ exists cl, good_claim t i cl.

pred evt (t : tr) = exists i, fev i t.

(* a collision between an unlogged claimed context and a logged one *)
pred colliding (t : tr) =
  exists i cl c', cl \in claims t.`trout /\ (i, c') \in t.`trlog /\
                  c' <> cl.`2 /\ msgof c' = msgof cl.`2.

op cpair (t : tr) : bytes * bytes =
  choiceb (fun (xy : bytes * bytes) => xy.`1 <> xy.`2 /\ H xy.`1 = H xy.`2) witness.

lemma cpair_ok (t : tr) :
  colliding t => (cpair t).`1 <> (cpair t).`2 /\ H (cpair t).`1 = H (cpair t).`2.
proof.
move=> [i cl c' [h1 [h2 [h3 h4]]]].
have hc : exists (xy : bytes * bytes), xy.`1 <> xy.`2 /\ H xy.`1 = H xy.`2.
+ by exists (cx c' cl.`2); apply (msgof_coll c' cl.`2).
by have := choicebP (fun (xy : bytes * bytes) => xy.`1 <> xy.`2 /\ H xy.`1 = H xy.`2) witness hc.
qed.

op fcl (i : int) (t : tr) : pk * ctx * sg =
  choiceb (good_claim t i) witness.

op fm (i : int) (t : tr) : msg * sg =
  ((msgof (fcl i t).`2), (fcl i t).`3).

lemma fm_ok (i : int) (t : tr) :
  fev i t => !colliding t =>
  ver (nth witness t.`trpk i) (fm i t).`1 (fm i t).`2 /\
  !((fm i t).`1 \in qmsgs i t.`trlog).
proof.
move=> [hi0 [hin [hnc [cl hg]]]] hncol.
have hex : exists c, good_claim t i c by exists cl.
have hfc : good_claim t i (fcl i t) by rewrite /fcl; exact (choicebP (good_claim t i) witness hex).
move: hfc; rewrite /good_claim => -[h1 [h2 [h3 h4]]].
split.
+ by rewrite /fm /= -h2.
rewrite /fm /= /qmsgs; apply/negP => hin2.
move: hin2; rewrite mapP => -[x [hx hxe]].
have [hx1 hx2] : x.`1 = i /\ x \in t.`trlog by move: hx; rewrite mem_filter /#.
apply hncol; rewrite /colliding; exists i; exists (fcl i t); exists x.`2; do! split => //.
+ by have -> : (i, x.`2) = x by smt(). 
+ by apply/negP => h; apply h4; rewrite -h; smt().
+ by rewrite hxe.
qed.

(* ---------------------------------------------------------------- *)
(* reduction to collision resistance                                 *)

module type Coll = { proc find() : bytes * bytes }.

module CR(C : Coll) = {
  proc main() : bool = {
    var x : bytes;
    var y : bytes;
    (x, y) <@ C.find();
    return x <> y /\ H x = H y;
  }
}.

module CA(A : MAdv) = {
  proc find() : bytes * bytes = {
    var t : tr;
    t <@ MG(A).main();
    return cpair t;
  }
}.

(* ---------------------------------------------------------------- *)
(* the EUF reduction: embed the challenge key at a given index       *)

module type AForger(O : Orcl) = {
  proc forge(pk : pk, a : int) : msg * sg {O.sign}
}.

module EUFA(F : AForger) = {
  var sk : sk
  var pk : pk
  var qm : msg list

  module O : Orcl = {
    proc sign(m : msg) : sg = {
      var s : sg;
      s <$ dsig sk m;
      qm <- m :: qm;
      return s;
    }
  }

  proc main(a : int) : bool = {
    var k : pk * sk;
    var m : msg;
    var s : sg;
    k <$ dkey;
    sk <- k.`2;
    pk <- k.`1;
    qm <- [];
    (m, s) <@ F(O).forge(pk, a);
    return ver pk m s /\ !(m \in qm);
  }
}.

module SUFA(F : AForger) = {
  var sk : sk
  var pk : pk
  var qs : (msg * sg) list

  module O : Orcl = {
    proc sign(m : msg) : sg = {
      var s : sg;
      s <$ dsig sk m;
      qs <- (m, s) :: qs;
      return s;
    }
  }

  proc main(a : int) : bool = {
    var k : pk * sk;
    var m : msg;
    var s : sg;
    k <$ dkey;
    sk <- k.`2;
    pk <- k.`1;
    qs <- [];
    (m, s) <@ F(O).forge(pk, a);
    return ver pk m s /\ !((m, s) \in qs);
  }
}.

section.
declare module F <: AForger {-EUFA, -SUFA}.

(* SUF-CMA advantage dominates EUF-CMA advantage (forger with advice). *)
lemma euf_a_le_suf_a (a : int) &m :
  Pr[EUFA(F).main(a) @ &m : res] <= Pr[SUFA(F).main(a) @ &m : res].
proof.
byequiv (_ : ={glob F, arg} ==> res{1} => res{2}) => //.
proc.
inline *.
wp.
call (_ : EUFA.sk{1} = SUFA.sk{2} /\ (forall m s, (m, s) \in SUFA.qs{2} => m \in EUFA.qm{1})).
+ proc; inline *; auto => /> *; smt().
auto => /> *; smt().
qed.
end section.

module BR(A : MAdv, O : Orcl) = {
  var ks : (int, pk * sk) fmap
  var cs : int list
  var lg : (int * ctx) list
  var idx : int

  module O' : MOrcl = {
    proc sign(i : int, c : ctx) : sg = {
      var s : sg;
      s <- witness;
      if (0 <= i /\ i < n) {
        if (i = idx) {
          s <@ O.sign(msgof c);
        } else {
          s <$ dsig (oget ks.[i]).`2 (msgof c);
        }
        lg <- (i, c) :: lg;
      }
      return s;
    }
  }

  proc forge(pkc : pk, a : int) : msg * sg = {
    var j : int;
    var x : pk * sk;
    var o : out;
    var r : msg * sg;
    idx <- a;
    ks <- empty;
    j <- 0;
    while (j < a) {
      x <$ dkey;
      ks.[j] <- x;
      j <- j + 1;
    }
    ks.[a] <- (pkc, witness);
    j <- a + 1;
    while (j < n) {
      x <$ dkey;
      ks.[j] <- x;
      j <- j + 1;
    }
    lg <- [];
    cs <@ A(O').corrupt(pkl ks);
    r <- witness;
    if (!(a \in cs)) {
      o <@ A(O').attack(pkl ks, ckl ks cs);
      r <- fm a {| trcs = cs; trpk = pkl ks; trlog = lg; trout = o |};
    }
    return r;
  }
}.

pred invo (ks1 ks2 : (int, pk * sk) fmap) (sk0 : sk) (lg1 lg2 : (int * ctx) list) (qm : msg list) (i : int) =
  lg1 = lg2 /\ qm = qmsgs i lg1 /\ (forall l, l <> i => ks1.[l] = ks2.[l]) /\
  exists p, ks2.[i] = Some (p, witness) /\ ks1.[i] = Some (p, sk0).

lemma qmsgs_nil (i : int) : qmsgs i [] = [] by rewrite /qmsgs.

lemma qmsgs_cons (i j : int) (c : ctx) (lg : (int * ctx) list) :
  qmsgs i ((j, c) :: lg) = if j = i then msgof c :: qmsgs i lg else qmsgs i lg.
proof. by rewrite /qmsgs /= /#. qed.

lemma pkl_nth (ks : (int, pk * sk) fmap) (i : int) :
  0 <= i => i < n => nth witness (pkl ks) i = (oget ks.[i]).`1.
proof.
move=> h0 h1; rewrite /pkl (nth_map 0) 1:size_iota; first smt().
by rewrite nth_iota //=; smt().
qed.

lemma pkl_eq (ks1 ks2 : (int, pk * sk) fmap) :
  (forall l, 0 <= l => l < n => (oget ks1.[l]).`1 = (oget ks2.[l]).`1) => pkl ks1 = pkl ks2.
proof.
move=> h; rewrite /pkl; apply eq_in_map => l; rewrite mem_iota /#.
qed.

lemma ckl_eq (ks1 ks2 : (int, pk * sk) fmap) (cs : int list) :
  (forall l, l \in cs => (oget ks1.[l]).`2 = (oget ks2.[l]).`2) => ckl ks1 cs = ckl ks2 cs.
proof.
move=> h; rewrite /ckl; apply eq_in_map => l hl /=; rewrite (h l hl) //.
qed.

lemma invo_init (ks1 ks2 : (int, pk * sk) fmap) (sk0 : sk) (p : pk) (qm : msg list) (i : int) :
  ks1.[i] = Some (p, sk0) => ks2.[i] = Some (p, witness) => qm = [] =>
  (forall l, l <> i => ks1.[l] = ks2.[l]) =>
  invo ks1 ks2 sk0 [] [] qm i.
proof.
move=> h1 h2 h3 h4; rewrite /invo h3 qmsgs_nil /=; split; first by smt().
by exists p.
qed.

lemma invo_pkl (ks1 ks2 : (int, pk * sk) fmap) (sk0 : sk) (lg1 lg2 : (int * ctx) list) (qm : msg list) (i : int) :
  invo ks1 ks2 sk0 lg1 lg2 qm i => pkl ks1 = pkl ks2.
proof.
move=> [h1 [h2 [h3 [p [h4 h5]]]]]; apply pkl_eq => l _ _.
by case (l = i) => [-> | hl]; [rewrite h4 h5 /= | rewrite (h3 l hl)].
qed.


section.

declare module A <: MAdv {-MG, -BR, -EUFA}.

declare axiom A_attack_ll (O <: MOrcl {-A}) :
  islossless O.sign => islossless A(O).attack.

local lemma mg_sign_ll : islossless MG(A).O.sign.
proof.
proc; sp; if.
+ by wp; rnd; skip => />; smt(dsig_ll).
by skip.
qed.

local lemma mg_attack_ll : islossless A(MG(A).O).attack.
proof. by apply (A_attack_ll (<: MG(A).O) mg_sign_ll). qed.

local lemma mg_eq :
  equiv[MG(A).main ~ MG(A).main : ={glob A} ==> ={res}].
proof. by proc; sim. qed.

lemma coll_le &m :
  Pr[MG(A).main() @ &m : colliding res] <= Pr[CR(CA(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> colliding res{1} => res{2}) => //.
proc*.
inline CR(CA(A)).main CA(A).find.
wp.
call mg_eq.
auto => /> *.
smt(cpair_ok).
qed.

local lemma sign_eq (i0 : int) :
  equiv[MG(A).O.sign ~ BR(A, EUFA(BR(A)).O).O'.sign :
    ={arg} /\ BR.idx{2} = i0 /\
    invo MG.ks{1} BR.ks{2} EUFA.sk{2} MG.lg{1} BR.lg{2} EUFA.qm{2} i0 /\
    BR.ks{2}.[i0] = Some (EUFA.pk{2}, witness)
    ==> ={res} /\ BR.idx{2} = i0 /\
    invo MG.ks{1} BR.ks{2} EUFA.sk{2} MG.lg{1} BR.lg{2} EUFA.qm{2} i0 /\
    BR.ks{2}.[i0] = Some (EUFA.pk{2}, witness)].
proof.
proc.
sp.
if => //.
+ wp.
  if{2}.
  + inline *; wp; rnd; wp; skip => /> *; smt(qmsgs_cons).
  + wp; rnd; wp; skip => /> *; smt(qmsgs_cons).
qed.

lemma red_le (i : int) &m :
  0 <= i < n =>
  Pr[MG(A).main() @ &m : fev i res /\ !colliding res] <= Pr[EUFA(BR(A)).main(i) @ &m : res].
proof.
move=> hi.
byequiv (_ : ={glob A} /\ a{2} = i ==> (fev i res /\ !colliding res){1} => res{2}) => //.
proc.
inline BR(A, EUFA(BR(A)).O).forge.
swap{2} 6 -5.
swap{2} [7..10] -5.
splitwhile{1} 3 : (j < i).
seq 3 5 : (={glob A} /\ MG.ks{1} = BR.ks{2} /\ j{1} = i /\ j{2} = i /\ a0{2} = i /\ BR.idx{2} = i).
+ wp.
  while (={glob A} /\ MG.ks{1} = BR.ks{2} /\ j{1} = j{2} /\ a0{2} = i /\ j{1} <= i).
  + wp; rnd; skip; smt().
  by wp; skip; smt().
unroll{1} 1.
rcondt{1} 1; first by auto; smt().
seq 3 7 : (={glob A} /\ j{1} = j{2} /\ j{1} = i + 1 /\ MG.ks{1}.[i] = Some k{2} /\
           BR.ks{2}.[i] = Some (EUFA.pk{2}, witness) /\ EUFA.pk{2} = k{2}.`1 /\ BR.idx{2} = i /\ a0{2} = i /\
           EUFA.sk{2} = k{2}.`2 /\ EUFA.qm{2} = [] /\
           (forall l, l <> i => MG.ks{1}.[l] = BR.ks{2}.[l])).
+ wp; rnd; skip => /> *; smt(get_setE).
seq 1 1 : (={glob A} /\ MG.ks{1}.[i] = Some k{2} /\
           BR.ks{2}.[i] = Some (EUFA.pk{2}, witness) /\ EUFA.pk{2} = k{2}.`1 /\ BR.idx{2} = i /\ a0{2} = i /\
           EUFA.sk{2} = k{2}.`2 /\ EUFA.qm{2} = [] /\
           (forall l, l <> i => MG.ks{1}.[l] = BR.ks{2}.[l])).
+ while (={glob A} /\ j{1} = j{2} /\ i < j{1} /\ MG.ks{1}.[i] = Some k{2} /\
           BR.ks{2}.[i] = Some (EUFA.pk{2}, witness) /\ EUFA.pk{2} = k{2}.`1 /\ BR.idx{2} = i /\ a0{2} = i /\
           EUFA.sk{2} = k{2}.`2 /\ EUFA.qm{2} = [] /\
           (forall l, l <> i => MG.ks{1}.[l] = BR.ks{2}.[l])).
  + wp; rnd; skip => /> *; smt(get_setE).
  by wp; skip => /> *; smt().
seq 2 3 : (={glob A} /\ MG.cs{1} = BR.cs{2} /\ a0{2} = i /\ BR.idx{2} = i /\
           invo MG.ks{1} BR.ks{2} EUFA.sk{2} MG.lg{1} BR.lg{2} EUFA.qm{2} i /\
           EUFA.sk{2} = k{2}.`2 /\ BR.ks{2}.[i] = Some (EUFA.pk{2}, witness)).
+ wp.
  call (_ : BR.idx{2} = i /\ invo MG.ks{1} BR.ks{2} EUFA.sk{2} MG.lg{1} BR.lg{2} EUFA.qm{2} i /\ BR.ks{2}.[i] = Some (EUFA.pk{2}, witness)).
  + by conseq (sign_eq i) => /#.
  wp; skip.
  move=> &1 &2 [hg [hk1 [hk2 [hpk [hidx [ha0 [hsk [hqm hneq]]]]]]]].
  have hk1' : MG.ks{1}.[i] = Some (EUFA.pk{2}, EUFA.sk{2}) by rewrite hk1 hpk hsk; smt().
  have hinv := invo_init MG.ks{1} BR.ks{2} EUFA.sk{2} EUFA.pk{2} EUFA.qm{2} i hk1' hk2 hqm hneq.
  split.
  + split; first exact (invo_pkl _ _ _ _ _ _ _ hinv).
    by smt().
  by move=> *; smt().
case (i \in MG.cs{1}).
+ rcondf{2} 1; first by auto => /> /#.
  call{1} mg_attack_ll.
  wp; skip => /> *.
rcondt{2} 1; first by auto => /> /#.
wp.
call (_ : BR.idx{2} = i /\ invo MG.ks{1} BR.ks{2} EUFA.sk{2} MG.lg{1} BR.lg{2} EUFA.qm{2} i /\ BR.ks{2}.[i] = Some (EUFA.pk{2}, witness)).
+ by conseq (sign_eq i) => /#.
wp; skip.
move=> &1 &2 [[hg [hcs [ha0 [hidx [hinv [hsk hks]]]]]] hncs].
split.
+ have hckl : ckl MG.ks{1} MG.cs{1} = ckl BR.ks{2} BR.cs{2}.
  + rewrite -hcs; apply ckl_eq => l hl.
    have hli : l <> i by smt().
    move: hinv; rewrite /invo => -[_ [_ [h3 _]]].
    by rewrite (h3 l hli).
  have hpkl := invo_pkl _ _ _ _ _ _ _ hinv.
  by rewrite /=; smt().
move=> _ r1 r2 A1 lg1 A2 lg2 qm2 [hr [hA [hidx2 [hinv2 hks2]]]].
have hpk := invo_pkl _ _ _ _ _ _ _ hinv.
move: hinv2; rewrite /invo => -[hl [hq [h3 _]]].
move=> /= [hfev hncol].
rewrite ha0 -hcs -hpk -hl -hr.
have hok := fm_ok i {| trcs = MG.cs{1}; trpk = pkl MG.ks{1}; trlog = lg1; trout = r1 |} hfev hncol.
have hn1 : nth witness (pkl MG.ks{1}) i = EUFA.pk{2}.
+ by rewrite hpk (pkl_nth _ i) 1,2:/# hks2.
move: hok => /= [hv hn].
rewrite hn1 in hv.
split => //.
by rewrite hq /#.
qed.

local lemma union_bound (l : int list) &m (P : int -> tr -> bool) :
  Pr[MG(A).main() @ &m : exists i, i \in l /\ P i res] <=
  Bigreal.BRA.big predT (fun i => Pr[MG(A).main() @ &m : P i res]) l.
proof.
elim: l.
+ rewrite big_nil.
  have : Pr[MG(A).main() @ &m : exists i, i \in [] /\ P i res] <= Pr[MG(A).main() @ &m : false].
  + by rewrite Pr[mu_sub] // => &hr /#.
  have h0 : Pr[MG(A).main() @ &m : false] = 0%r by rewrite Pr[mu_false].
  smt().
move=> x l ih.
rewrite big_consT.
have e : (fun (i : int) => Pr[MG(A).main() @ &m : P i res]) x = Pr[MG(A).main() @ &m : P x res] by done.
have h1 : Pr[MG(A).main() @ &m : exists i, i \in x :: l /\ P i res] <=
          Pr[MG(A).main() @ &m : P x res \/ exists i, i \in l /\ P i res].
+ by rewrite Pr[mu_sub] // => &hr /#.
have h2 : Pr[MG(A).main() @ &m : P x res \/ exists i, i \in l /\ P i res] <=
          Pr[MG(A).main() @ &m : P x res] + Pr[MG(A).main() @ &m : exists i, i \in l /\ P i res].
+ rewrite Pr[mu_or].
  have : 0%r <= Pr[MG(A).main() @ &m : P x res /\ exists i, i \in l /\ P i res].
  + by rewrite Pr[mu_ge0].
  smt().
rewrite e.
apply (ler_trans _ _ _ h1).
apply (ler_trans _ _ _ h2).
by apply ler_add.
qed.

lemma mu_bound &m (eps : real) :
  (forall i &m', 0 <= i => i < n => Pr[EUFA(BR(A)).main(i) @ &m' : res] <= eps) =>
  Pr[MG(A).main() @ &m : evt res] <=
  Pr[CR(CA(A)).main() @ &m : res] + n%r * eps.
proof.
move=> heps.
have h1 : Pr[MG(A).main() @ &m : evt res] <=
  Pr[MG(A).main() @ &m : colliding res \/ exists i, i \in iota_ 0 n /\ (fev i res /\ !colliding res)].
+ rewrite Pr[mu_sub] // => &hr.
  rewrite /evt => -[i hi]; case (colliding res{hr}) => [hc | hnc]; first by left.
  right; exists i; rewrite mem_iota; smt().
have h2 : Pr[MG(A).main() @ &m : colliding res \/ exists i, i \in iota_ 0 n /\ (fev i res /\ !colliding res)] <=
  Pr[MG(A).main() @ &m : colliding res] +
  Pr[MG(A).main() @ &m : exists i, i \in iota_ 0 n /\ (fev i res /\ !colliding res)].
+ rewrite Pr[mu_or].
  have : 0%r <= Pr[MG(A).main() @ &m : colliding res /\ exists i, i \in iota_ 0 n /\ (fev i res /\ !colliding res)].
  + by rewrite Pr[mu_ge0].
  smt().
have h3 : Pr[MG(A).main() @ &m : exists i, i \in iota_ 0 n /\ (fev i res /\ !colliding res)] <=
  Bigreal.BRA.big predT (fun i => Pr[MG(A).main() @ &m : fev i res /\ !colliding res]) (iota_ 0 n)
  by apply (union_bound (iota_ 0 n) &m (fun i t => fev i t /\ !colliding t)).
have h4 : Bigreal.BRA.big predT (fun i => Pr[MG(A).main() @ &m : fev i res /\ !colliding res]) (iota_ 0 n) <=
          Bigreal.BRA.big predT (fun i => eps) (iota_ 0 n).
+ apply Bigreal.ler_sum_seq => i hi _ /=.
  move: hi; rewrite mem_iota => -[hi0 hi1].
  have := red_le i &m _; first smt().
  have := heps i &m _ _; [smt() | smt() | smt()].
have h5 := coll_le &m.
rewrite Bigreal.BRA.sumr_const count_predT size_iota in h4.
have hmax : max 0 n = n by smt(n_pos).
have hi : RField.intmul eps (max 0 n) = n%r * eps.
+ by rewrite hmax RField.intmulr; ring.
apply (ler_trans _ _ _ h1).
apply (ler_trans _ _ _ h2).
apply ler_add; first exact h5.
apply (ler_trans _ _ _ h3).
by rewrite -hi.
qed.

end section.

end MultiUser.
