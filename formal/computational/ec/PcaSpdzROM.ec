(* PcaSpdzROM.ec -- the SPDZ MAC-check game with SHA-256-style commitments in the RANDOM-ORACLE MODEL,
   adversary and honest parties as oracle-aided MODULES.  Scaffolding. *)
require import AllCore Int Real List Distr DProd DList FMap StdOrder.
require import PcaSpdz.
import PcaSpdz.F PcaSpdz.F.ZModpField PcaSpdz.F.DZmodP.
import RealOrder.
require import PcaSpdzProto.
require PcaCommitReveal PcaRomCollision.

(* structural parameters of the oracle (the commitment hash) *)
op dcm : cm distr.
op pmax : real.
axiom dn_ll' : is_lossless dn.
axiom dcm_ll' : is_lossless dcm.
axiom pmax_ge0' : 0%r <= pmax.
axiom dn_pmax' (r : nonce) : mu1 dn r <= pmax.

clone PcaCommitReveal.TW as CR with
  type msg1 <- seed,
  type msg2 <- gmsg,
  type nonce <- nonce,
  type cm <- cm,
  op dn <- dn,
  op dcm <- dcm,
  op pmax <- pmax
proof *.
realize dn_ll by exact dn_ll'.
realize dcm_ll by exact dcm_ll'.
realize pmax_ge0 by exact pmax_ge0'.
realize dn_pmax by exact dn_pmax'.



(* binding side: the same oracle viewed through the library random-oracle theory *)
op pc : real.
axiom pc_ge0' : 0%r <= pc.
axiom dcm_pc' (y : cm) : mu1 dcm y <= pc.

clone PcaRomCollision.RC as RC with
  type pt <- CR.key,
  type cm <- cm,
  op dcm <- dcm,
  op pc <- pc
proof *.
realize pc_ge0 by exact pc_ge0'.
realize dcm_pc by exact dcm_pc'.

(* ------------------------------------------------------------------ *)
(* the protocol as an oracle-aided program                                *)

module type MA (O : CR.Oracle) = {
  proc setup() : sdata                                                     { O.o }
  proc sc(cH : cm) : seed * nonce                                          { O.o }
  proc so(cH : cm, sH : seed, nH : nonce) : seed * nonce                   { O.o }
  proc gc(cH : cm, sH : seed, nH : nonce, r : seed, cGH : cm) : gmsg * nonce { O.o }
  proc go(cH : cm, sH : seed, nH : nonce, r : seed, cGH : cm, sg : fe * fe, nGo : nonce) : gmsg * nonce { O.o }
}.

module Proto (A : MA) (O : CR.Oracle) = {
  var d : sdata
  var sH : seed
  var aH : fe * fe
  var cH : cm
  var cGH : cm
  var y1 : cm
  var y2 : cm
  var y3 : cm
  var y4 : cm
  var nH : nonce
  var nGo : nonce
  var mA : seed
  var nA : nonce
  var mo : seed * nonce
  var r : seed
  var sg : fe * fe
  var gA : gmsg
  var nGA : nonce
  var g2 : gmsg
  var ng2 : nonce
  var winR : bool
  var winC : bool
  var collS : bool
  var collG : bool

  proc setup0() : unit = {
    d <@ A(O).setup();
  }

  proc smpH() : unit = {
    sH <$ dsH;
  }

  proc p0() : seed = {
    setup0();
    smpH();
    return sH;
  }

  proc p1(c : cm) : unit = {
    var x : seed * nonce;
    cH <- c;
    x <@ A(O).sc(c);
    mA <- x.`1;
    nA <- x.`2;
  }

  proc so0(n : nonce) : unit = {
    nH <- n;
    mo <@ A(O).so(cH, sH, nH);
    r <- chal sH mo.`1;
  }

  proc smpA() : unit = {
    aH <$ dkey2;
    sg <- (sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 r.`1, sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 r.`2);
  }

  proc p2(n : nonce) : gmsg = {
    so0(n);
    smpA();
    return sg;
  }

  proc p3(c : cm) : unit = {
    var x : gmsg * nonce;
    cGH <- c;
    x <@ A(O).gc(cH, sH, nH, r, c);
    gA <- x.`1;
    nGA <- x.`2;
  }

  proc go0(n : nonce) : unit = {
    var x : gmsg * nonce;
    nGo <- n;
    x <@ A(O).go(cH, sH, nH, r, cGH, sg, n);
    g2 <- x.`1;
    ng2 <- x.`2;
    y1 <@ O.o(CR.K1 (mo.`1, mo.`2));
    y2 <@ O.o(CR.K1 (mA, nA));
    y3 <@ O.o(CR.K2 (g2, ng2));
    y4 <@ O.o(CR.K2 (gA, nGA));
  }

  proc evalC() : bool = {
    var rC : seed; var rO : seed; var sgO : fe * fe;
    collS <- mo.`1 <> mA /\ y1 = y2;
    collG <- g2 <> gA /\ y3 = y4;
    rO <- chal sH mo.`1;
    sgO <- (sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 rO.`1, sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 rO.`2);
    winR <- valid d /\ nzv d.`dl /\ y1 = y2 /\ y3 = y4 /\ sgO.`1 + g2.`1 = zero /\ sgO.`2 + g2.`2 = zero;
    rC <- chal sH mA;
    winC <- valid d /\ nzv d.`dl
            /\ sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 rC.`1 + gA.`1 = zero
            /\ sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 rC.`2 + gA.`2 = zero;
    return winC;
  }

  proc p4(n : nonce) : bool = {
    var b : bool;
    go0(n);
    b <@ evalC();
    return b;
  }
}.

lemma fcoll_of (m : (CR.key, cm) fmap) (a b : CR.key) (ya yb : cm) :
  m.[a] = Some ya => m.[b] = Some yb => a <> b => ya = yb => fcoll (fun (z : cm) => z) m.
proof. by move=> h1 h2 h3 h4; rewrite /fcoll; exists a b; smt(domE). qed.

lemma k1_ne (x y : seed) (n1 n2 : nonce) : x <> y => CR.K1 (x, n1) <> CR.K1 (y, n2).
proof. by smt(). qed.

lemma k2_ne (x y : gmsg) (n1 n2 : nonce) : x <> y => CR.K2 (x, n1) <> CR.K2 (y, n2).
proof. by smt(). qed.

module Adp (O : RC.R.RO) : CR.Oracle = {
  proc o(x : CR.key) : cm = {
    var y : cm;
    y <@ O.get(x);
    return y;
  }
}.

(* the whole protocol run against an arbitrary commitment oracle; adversary-side queries are logged *)
module RunP (A : MA) (O : CR.Oracle) = {
  var r1 : nonce
  var r2 : nonce
  var t1 : CR.key
  var t2 : CR.key
  var c1 : cm
  var c2 : cm

  proc run() : bool = {
    var m1 : seed; var m2 : gmsg; var rs : bool;
    CR.Log.qs <- [];
    m1 <@ Proto(A, CR.Log(O)).p0();
    r1 <$ dn;
    t1 <- CR.K1 (m1, r1);
    c1 <@ O.o(t1);
    Proto(A, CR.Log(O)).p1(c1);
    m2 <@ Proto(A, CR.Log(O)).p2(r1);
    r2 <$ dn;
    t2 <- CR.K2 (m2, r2);
    c2 <@ O.o(t2);
    Proto(A, CR.Log(O)).p3(c2);
    rs <@ Proto(A, CR.Log(O)).p4(r2);
    return rs;
  }
}.

module RunR (A : MA) = {
  proc main() : bool = {
    var rs : bool;
    CR.RO.init();
    rs <@ RunP(A, CR.RO).run();
    return rs;
  }
}.

module DS (A : MA) (O : RC.R.ROmap) = {
  proc distinguish(u : unit) : bool = {
    var rs : bool;
    rs <@ RunP(A, Adp(O)).run();
    return Proto.collS;
  }
}.

module DW (A : MA) (O : RC.R.ROmap) = {
  proc distinguish(u : unit) : bool = {
    var rs : bool;
    rs <@ RunP(A, Adp(O)).run();
    return rs;
  }
}.

module DG (A : MA) (O : RC.R.ROmap) = {
  proc distinguish(u : unit) : bool = {
    var rs : bool;
    rs <@ RunP(A, Adp(O)).run();
    return Proto.collG;
  }
}.

(* ------------------------------------------------------------------ *)
(* the reordered ideal game: honest values sampled as late as possible    *)

module G (A : MA) = {
  proc stA() : unit = {
    CR.Id.bad1 <- false;
    CR.Id.bad2 <- false;
    CR.RO.init();
    CR.Log.qs <- [];
    Proto(A, CR.Log(CR.RO)).setup0();
    CR.Id.c1 <$ dcm;
    Proto(A, CR.Log(CR.RO)).p1(CR.Id.c1);
  }

  proc stB1() : unit = {
    Proto(A, CR.Log(CR.RO)).smpH();
  }

  proc stB2() : unit = {
    CR.Id.r1 <$ dn;
    CR.Id.t1 <- CR.K1 (Proto.sH, CR.Id.r1);
    CR.Id.n1 <- size CR.Log.qs;
    CR.Id.bad1 <- CR.Id.t1 \in CR.Log.qs;
    if (!CR.Id.bad1) { CR.RO.m.[CR.Id.t1] <- CR.Id.c1; }
  }

  proc stC() : unit = {
    Proto(A, CR.Log(CR.RO)).so0(CR.Id.r1);
    CR.Id.c2 <$ dcm;
    Proto(A, CR.Log(CR.RO)).p3(CR.Id.c2);
  }

  proc stD1() : unit = {
    Proto(A, CR.Log(CR.RO)).smpA();
  }

  proc stD2() : unit = {
    CR.Id.r2 <$ dn;
    CR.Id.t2 <- CR.K2 (Proto.sg, CR.Id.r2);
    CR.Id.n2 <- size CR.Log.qs;
    CR.Id.bad2 <- CR.Id.t2 \in CR.Log.qs;
    if (!CR.Id.bad2) { CR.RO.m.[CR.Id.t2] <- CR.Id.c2; }
  }

  proc stE() : bool = {
    var b : bool;
    b <@ Proto(A, CR.Log(CR.RO)).p4(CR.Id.r2);
    return b;
  }

  proc t3() : bool = {
    var b : bool;
    stD2();
    b <@ stE();
    return b;
  }

  proc t2() : bool = {
    var b : bool;
    stD1();
    b <@ t3();
    return b;
  }

  proc bc() : unit = {
    stB2();
    stC();
  }

  proc t1() : bool = {
    var b : bool;
    bc();
    b <@ t2();
    return b;
  }

  proc main() : bool = {
    var b : bool;
    stA();
    stB1();
    b <@ t1();
    return b;
  }
}.


(* ------------------------------------------------------------------ *)
(* the event of the ideal game and its algebra                           *)

op Vo (d : sdata) : bool = valid d /\ nzv d.`dl.
op S1o (d : sdata) (sH mA : seed) : fe = dot (chal sH mA).`1 d.`dl.
op S2o (d : sdata) (sH mA : seed) : fe = dot (chal sH mA).`2 d.`dl.
op T1o (d : sdata) (sH mA : seed) (gA : gmsg) : fe =
  (d.`aA.`1 * dot (chal sH mA).`1 d.`xs - dot (chal sH mA).`1 d.`ga1) + gA.`1.
op T2o (d : sdata) (sH mA : seed) (gA : gmsg) : fe =
  (d.`aA.`2 * dot (chal sH mA).`2 d.`xs - dot (chal sH mA).`2 d.`ga2) + gA.`2.

op EVo (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) : bool =
  Vo d
  /\ sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 (chal sH mA).`1 + gA.`1 = zero
  /\ sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 (chal sH mA).`2 + gA.`2 = zero.

lemma ev_split (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) :
  EVo d sH mA aH gA =>
     (Vo d /\ S1o d sH mA = zero /\ S2o d sH mA = zero)
  \/ (Vo d /\ S1o d sH mA = zero /\ S2o d sH mA <> zero /\ aH.`2 * S2o d sH mA = T2o d sH mA gA)
  \/ (Vo d /\ S1o d sH mA <> zero /\ S2o d sH mA = zero /\ aH.`1 * S1o d sH mA = T1o d sH mA gA)
  \/ (Vo d /\ S1o d sH mA <> zero /\ S2o d sH mA <> zero
      /\ aH.`1 * S1o d sH mA = T1o d sH mA gA /\ aH.`2 * S2o d sH mA = T2o d sH mA gA).
proof.
rewrite /EVo /Vo => -[[hv hn] [e1 e2]].
move: hv; rewrite /valid /= => -[hx [h1 [h2 hl]]].
have s1 : size d.`xs = size d.`ga1 by smt().
have s2 : size d.`xs = size d.`ga2 by smt().
have s3 : size d.`xs = size d.`dl by smt().
have f1 := sigH_form d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 (chal sH mA).`1 s1 s3.
have f2 := sigH_form d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 (chal sH mA).`2 s2 s3.
move: e1; rewrite f1 => e1.
move: e2; rewrite f2 => e2.
have p1 := pin_alg _ _ _ _ e1.
have p2 := pin_alg _ _ _ _ e2.
rewrite /S1o /S2o /T1o /T2o /valid /Vo /=.
smt().
qed.


op Q1o (d : sdata) (sH mA : seed) : bool = Vo d /\ S1o d sH mA = zero /\ S2o d sH mA <> zero.
op Q2o (d : sdata) (sH mA : seed) : bool = Vo d /\ S1o d sH mA <> zero /\ S2o d sH mA = zero.
op Q0o (d : sdata) (sH mA : seed) : bool = Vo d /\ S1o d sH mA <> zero /\ S2o d sH mA <> zero.
op Ev2o (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) : bool =
  Q1o d sH mA /\ aH.`2 * S2o d sH mA = T2o d sH mA gA.
op Ev3o (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) : bool =
  Q2o d sH mA /\ aH.`1 * S1o d sH mA = T1o d sH mA gA.
op Ev4o (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) : bool =
  Q0o d sH mA /\ aH.`1 * S1o d sH mA = T1o d sH mA gA /\ aH.`2 * S2o d sH mA = T2o d sH mA gA.

op Zo (d : sdata) (sH mA : seed) : bool = Vo d /\ S1o d sH mA = zero /\ S2o d sH mA = zero.
op Eo (d : sdata) (sH mA : seed) (aH : fe * fe) (gA : gmsg) : bool =
  Zo d sH mA \/ (Ev2o d sH mA aH gA \/ (Ev3o d sH mA aH gA \/ Ev4o d sH mA aH gA)).

section.
declare module A <: MA {-CR.RO, -CR.Log, -CR.Rl, -CR.IdE, -CR.Id, -CR.EReal, -CR.EId, -Proto, -G, -RunP, -RC.R.RO}.

lemma evalC_imp :
  hoare [ Proto(A, CR.Log(CR.RO)).evalC : true ==> Proto.winR => Proto.winC \/ Proto.collS \/ Proto.collG ].
proof.
proc.
wp; skip => /> *.
smt().
qed.

lemma p4_imp :
  hoare [ Proto(A, CR.Log(CR.RO)).p4 : true ==> Proto.winR => Proto.winC \/ Proto.collS \/ Proto.collG ].
proof.
proc.
call evalC_imp.
inline Proto(A, CR.Log(CR.RO)).go0.
wp.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip.
qed.

declare axiom A_setup_ll (O <: CR.Oracle {-A}) : islossless O.o => islossless A(O).setup.
declare axiom A_sc_ll (O <: CR.Oracle {-A}) : islossless O.o => islossless A(O).sc.
declare axiom A_so_ll (O <: CR.Oracle {-A}) : islossless O.o => islossless A(O).so.
declare axiom A_gc_ll (O <: CR.Oracle {-A}) : islossless O.o => islossless A(O).gc.
declare axiom A_go_ll (O <: CR.Oracle {-A}) : islossless O.o => islossless A(O).go.

lemma dsH_ll : is_lossless dsH.
proof. by rewrite /dsH dprod_ll; split; exact (dlist_ll dstar nm dstar_ll). qed.

lemma dkey2_ll : is_lossless dkey2.
proof. exact (is_losslessP _ w_dkey2). qed.

lemma proto_setup0_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).setup0.
proof. move=> hO; proc; call (A_setup_ll O hO); by skip. qed.

lemma proto_smpH_ll (O <: CR.Oracle {-A, -Proto}) : islossless Proto(A, O).smpH.
proof. proc; rnd; skip => />; exact dsH_ll. qed.

lemma proto_p0_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).p0.
proof.
move=> hO; proc.
wp.
call (proto_smpH_ll O).
call (proto_setup0_ll O hO).
by skip.
qed.

lemma proto_p1_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).p1.
proof.
move=> hO; proc.
wp.
call (A_sc_ll O hO).
by wp; skip.
qed.

lemma proto_so0_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).so0.
proof.
move=> hO; proc.
wp.
call (A_so_ll O hO).
by wp; skip.
qed.

lemma proto_smpA_ll (O <: CR.Oracle {-A, -Proto}) : islossless Proto(A, O).smpA.
proof. proc; wp; rnd; skip => />; exact dkey2_ll. qed.

lemma proto_p2_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).p2.
proof.
move=> hO; proc.
wp.
call (proto_smpA_ll O).
call (proto_so0_ll O hO).
by skip.
qed.

lemma proto_p3_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).p3.
proof.
move=> hO; proc.
wp.
call (A_gc_ll O hO).
by wp; skip.
qed.

lemma proto_go0_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).go0.
proof.
move=> hO; proc.
call hO.
call hO.
call hO.
call hO.
wp.
call (A_go_ll O hO).
by wp; skip.
qed.

lemma proto_evalC_ll (O <: CR.Oracle {-A, -Proto}) : islossless Proto(A, O).evalC.
proof. proc; by wp; skip. qed.

lemma proto_p4_ll (O <: CR.Oracle {-A, -Proto}) : islossless O.o => islossless Proto(A, O).p4.
proof.
move=> hO; proc.
call (proto_evalC_ll O).
call (proto_go0_ll O hO).
by skip.
qed.


local lemma so0_refl :
  equiv [ Proto(A, CR.Log(CR.RO)).so0 ~ Proto(A, CR.Log(CR.RO)).so0 :
          ={n, glob A, glob Proto, glob CR.RO, glob CR.Log} ==> ={glob A, glob Proto, glob CR.RO, glob CR.Log} ].
proof. by proc; sim. qed.

local lemma smpA_refl :
  equiv [ Proto(A, CR.Log(CR.RO)).smpA ~ Proto(A, CR.Log(CR.RO)).smpA :
          ={glob A, glob Proto, glob CR.RO, glob CR.Log} ==> ={glob A, glob Proto, glob CR.RO, glob CR.Log} ].
proof. by proc; sim. qed.

local lemma p3_refl :
  equiv [ Proto(A, CR.Log(CR.RO)).p3 ~ Proto(A, CR.Log(CR.RO)).p3 :
          ={c, glob A, glob Proto, glob CR.RO, glob CR.Log} ==> ={glob A, glob Proto, glob CR.RO, glob CR.Log} ].
proof. by proc; sim. qed.

local lemma p4_refl :
  equiv [ Proto(A, CR.Log(CR.RO)).p4 ~ Proto(A, CR.Log(CR.RO)).p4 :
          ={n, glob A, glob Proto, glob CR.RO, glob CR.Log} ==> ={res, glob A, glob Proto, glob CR.RO, glob CR.Log} ].
proof. by proc; sim. qed.

lemma id_G :
  equiv [ CR.Id(Proto(A)).main ~ G(A).main : ={glob A, glob Proto, glob CR.Id, glob CR.RO, glob CR.Log} ==> res{1} = res{2} ].
proof.
proc.
inline CR.Id(Proto(A)).pre0 Proto(A, CR.Log(CR.RO)).p0 CR.Id(Proto(A)).w1 CR.Id(Proto(A)).w1a CR.Id(Proto(A)).w1b
       CR.Id(Proto(A)).suf Proto(A, CR.Log(CR.RO)).p2 CR.Id(Proto(A)).w2 CR.Id(Proto(A)).w2a CR.Id(Proto(A)).w2b
       CR.Id(Proto(A)).fin G(A).stA G(A).stB1 G(A).stB2 G(A).stC G(A).stD1 G(A).stD2 G(A).stE G(A).t1 G(A).t2 G(A).t3 G(A).bc.
swap{1} [10..11] -4.
seq 8 8 : (={glob A, glob Proto, glob CR.Id, glob CR.RO, glob CR.Log}).
+ by sim.
sp 3 0.
seq 5 5 : (={glob A, glob Proto, glob CR.RO, glob CR.Log, CR.Id.r1, CR.Id.c1, CR.Id.t1, CR.Id.n1, CR.Id.bad1, CR.Id.bad2}).
+ by wp; rnd; skip => />; smt().
sp 1 0.
swap{1} [6..7] -4.
seq 4 4 : (={glob A, glob Proto, glob CR.RO, glob CR.Log, CR.Id.r1, CR.Id.c1, CR.Id.t1, CR.Id.n1, CR.Id.bad1, CR.Id.bad2, CR.Id.c2}).
+ by call smpA_refl; call p3_refl; rnd; call so0_refl; skip => />.
sp 3 0.
seq 5 5 : (={glob A, glob Proto, glob CR.RO, glob CR.Log, CR.Id.r2, CR.Id.c2, CR.Id.t2, CR.Id.n2, CR.Id.bad2}).
+ by wp; rnd; skip => />; smt().
wp.
call p4_refl.
by skip => />.
qed.


lemma log_ll : islossless CR.Log(CR.RO).o.
proof. proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll'). qed.

local lemma ro_init_ll : islossless CR.RO.init.
proof. by proc; auto. qed.

local lemma stA_ll : islossless G(A).stA.
proof.
proc.
call (proto_p1_ll (CR.Log(CR.RO)) log_ll).
rnd.
call (proto_setup0_ll (CR.Log(CR.RO)) log_ll).
wp.
call ro_init_ll.
wp; skip => />; smt(dcm_ll').
qed.

local lemma stB1_ll : islossless G(A).stB1.
proof. by proc; call (proto_smpH_ll (CR.Log(CR.RO))). qed.

local lemma stB2_ll : islossless G(A).stB2.
proof. proc; wp; rnd; skip => />; smt(dn_ll'). qed.

local lemma stC_ll : islossless G(A).stC.
proof.
proc.
call (proto_p3_ll (CR.Log(CR.RO)) log_ll).
rnd.
call (proto_so0_ll (CR.Log(CR.RO)) log_ll).
by skip => />; smt(dcm_ll').
qed.

local lemma stD1_ll : islossless G(A).stD1.
proof. by proc; call (proto_smpA_ll (CR.Log(CR.RO))). qed.

local lemma stD2_ll : islossless G(A).stD2.
proof. proc; wp; rnd; skip => />; smt(dn_ll'). qed.

local lemma stE_ll : islossless G(A).stE.
proof. by proc; call (proto_p4_ll (CR.Log(CR.RO)) log_ll). qed.

local lemma t3_ll : islossless G(A).t3.
proof. by proc; call stE_ll; call stD2_ll. qed.

local lemma t2_ll : islossless G(A).t2.
proof. by proc; call t3_ll; call stD1_ll. qed.

local lemma bc_ll : islossless G(A).bc.
proof. by proc; call stC_ll; call stB2_ll. qed.

local lemma t1_ll : islossless G(A).t1.
proof. by proc; call t2_ll; call bc_ll. qed.

local lemma main_ll : islossless G(A).main.
proof. by proc; call t1_ll; call stB1_ll; call stA_ll. qed.


(* ------------------------------------------------------------------ *)
(* what each stage of the ideal game leaves untouched                     *)

local lemma stB2_keep (f : sdata -> seed -> seed -> (fe * fe) -> gmsg -> bool) :
  hoare [ G(A).stB2 : f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; wp; rnd; skip => />. qed.

local lemma stD2_keep (f : sdata -> seed -> seed -> (fe * fe) -> gmsg -> bool) :
  hoare [ G(A).stD2 : f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; wp; rnd; skip => />. qed.

local lemma stD1_keep (f : sdata -> seed -> seed -> gmsg -> bool) :
  hoare [ G(A).stD1 : f Proto.d Proto.sH Proto.mA Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.gA ].
proof. by proc; inline Proto(A, CR.Log(CR.RO)).smpA; wp; rnd; skip => />. qed.

local lemma stC_keep (f : sdata -> seed -> seed -> bool) :
  hoare [ G(A).stC : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ].
proof.
proc; inline Proto(A, CR.Log(CR.RO)).so0 Proto(A, CR.Log(CR.RO)).p3.
wp.
call (_ : true); first by proc; inline *; auto.
wp.
rnd.
wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip => />.
qed.

local lemma stE_keep (f : sdata -> seed -> seed -> (fe * fe) -> gmsg -> bool) :
  hoare [ G(A).stE : f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof.
proc; inline Proto(A, CR.Log(CR.RO)).p4 Proto(A, CR.Log(CR.RO)).go0 Proto(A, CR.Log(CR.RO)).evalC.
wp.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip => />.
qed.


local lemma t3_keep (f : sdata -> seed -> seed -> (fe * fe) -> gmsg -> bool) :
  hoare [ G(A).t3 : f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; call (stE_keep f); call (stD2_keep f); skip. qed.

local lemma t2_keep (f : sdata -> seed -> seed -> gmsg -> bool) :
  hoare [ G(A).t2 : f Proto.d Proto.sH Proto.mA Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.gA ].
proof.
proc.
call (t3_keep (fun d sH mA (aH : fe * fe) gA => f d sH mA gA)).
call (stD1_keep f).
by skip.
qed.

local lemma bc_keep (f : sdata -> seed -> seed -> bool) :
  hoare [ G(A).bc : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ].
proof.
proc.
call (stC_keep f).
call (stB2_keep (fun d sH mA (aH : fe * fe) (gA : gmsg) => f d sH mA)).
by skip.
qed.

local lemma t1_keep (f : sdata -> seed -> seed -> bool) :
  hoare [ G(A).t1 : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ].
proof.
proc.
call (t2_keep (fun d sH mA (gA : gmsg) => f d sH mA)).
call (bc_keep f).
by skip.
qed.


local lemma stA_le1 : phoare [ G(A).stA : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t1_le1 (f : sdata -> seed -> seed -> bool) :
  phoare [ G(A).t1 : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t1_ph (f : sdata -> seed -> seed -> bool) :
  phoare [ G(A).t1 : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ] = 1%r.
proof. by conseq t1_ll (t1_keep f). qed.

(* Pr[V and both inner products vanish] *)
local lemma stB1_Z12 :
  phoare [ G(A).stB1 : true ==>
           Vo Proto.d /\ S1o Proto.d Proto.sH Proto.mA = zero /\ S2o Proto.d Proto.sH Proto.mA = zero ] <= (inv (pp - 1)%r * inv (pp - 1)%r).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpH.
rnd (fun (s : seed) => Vo Proto.d /\ dot (comb s.`1 Proto.mA.`1) Proto.d.`dl = zero /\ dot (comb s.`2 Proto.mA.`2) Proto.d.`dl = zero).
skip => &hr _ /=.
split; last by smt().
have hinv : inv ((pp - 1)%r * (pp - 1)%r) = inv (pp - 1)%r * inv (pp - 1)%r.
+ by rewrite RField.invrM; smt(pp_gt1).
rewrite hinv.
case (Vo Proto.d{hr}) => hv.
+ move: hv; rewrite /Vo /valid => -[[hx [h1 [h2 hl]]] hn].
  have := z_both Proto.mA{hr}.`1 Proto.mA{hr}.`2 Proto.d{hr}.`dl hl hn.
  by apply (ler_trans _ _ _ _) => //; apply mu_sub => s /=; smt().
+ apply (ler_trans (mu dsH pred0)).
  - by apply mu_sub => s /=; rewrite /pred0; smt().
  rewrite mu0; apply mulr_ge0; exact inv_pp1_ge0.
move=> _; apply divr_ge0; [exact inv_pp1_ge0 | smt(pp_gt1)].
qed.


local lemma pZ12 &m :
  Pr[G(A).main() @ &m : Vo Proto.d /\ S1o Proto.d Proto.sH Proto.mA = zero /\ S2o Proto.d Proto.sH Proto.mA = zero]
  <= inv (pp - 1)%r * inv (pp - 1)%r.
proof.
byphoare (_ : true ==> Vo Proto.d /\ S1o Proto.d Proto.sH Proto.mA = zero /\ S2o Proto.d Proto.sH Proto.mA = zero) => //.
proc.
seq 2 : (Vo Proto.d /\ S1o Proto.d Proto.sH Proto.mA = zero /\ S2o Proto.d Proto.sH Proto.mA = zero)
        (inv (pp - 1)%r * inv (pp - 1)%r) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ seq 1 : true 1%r (inv (pp - 1)%r * inv (pp - 1)%r) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call stA_le1.
  - by call stB1_Z12.
  - by hoare; auto => />.
  - by auto.
+ by call (t1_le1 (fun d sH mA => Vo d /\ S1o d sH mA = zero /\ S2o d sH mA = zero)).
+ by hoare; call (t1_keep (fun d sH mA => !(Vo d /\ S1o d sH mA = zero /\ S2o d sH mA = zero))); skip => />.
smt().
qed.


local lemma stB1_Q1 : phoare [ G(A).stB1 : true ==> Q1o Proto.d Proto.sH Proto.mA ] <= (inv (pp - 1)%r).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpH.
rnd (fun (s : seed) => Vo Proto.d /\ dot (comb s.`1 Proto.mA.`1) Proto.d.`dl = zero /\ dot (comb s.`2 Proto.mA.`2) Proto.d.`dl <> zero).
skip => &hr _ /=.
split; last by smt().
case (Vo Proto.d{hr}) => hv.
+ move: hv; rewrite /Vo /valid => -[[hx [h1 [h2 hl]]] hn].
  have := z_first Proto.mA{hr}.`1 Proto.d{hr}.`dl hl hn.
  have h : mu dsH (fun (s : seed) => dot (comb s.`1 Proto.mA{hr}.`1) Proto.d{hr}.`dl = zero /\
                                      dot (comb s.`2 Proto.mA{hr}.`2) Proto.d{hr}.`dl <> zero)
           <= mu dsH (fun (s : seed) => dot (comb s.`1 Proto.mA{hr}.`1) Proto.d{hr}.`dl = zero).
  - by apply mu_sub => s /=; smt().
  by smt().
+ apply (ler_trans (mu dsH pred0)).
  - by apply mu_sub => s /=; rewrite /pred0; smt().
  by rewrite mu0; exact inv_pp1_ge0.
move=> _; exact inv_pp1_ge0.
qed.


local lemma stB1_Q2 : phoare [ G(A).stB1 : true ==> Q2o Proto.d Proto.sH Proto.mA ] <= (inv (pp - 1)%r).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpH.
rnd (fun (s : seed) => Vo Proto.d /\ dot (comb s.`1 Proto.mA.`1) Proto.d.`dl <> zero /\ dot (comb s.`2 Proto.mA.`2) Proto.d.`dl = zero).
skip => &hr _ /=.
split; last by smt().
case (Vo Proto.d{hr}) => hv.
+ move: hv; rewrite /Vo /valid => -[[hx [h1 [h2 hl]]] hn].
  have := z_second Proto.mA{hr}.`2 Proto.d{hr}.`dl hl hn.
  have h : mu dsH (fun (s : seed) => dot (comb s.`1 Proto.mA{hr}.`1) Proto.d{hr}.`dl <> zero /\
                                      dot (comb s.`2 Proto.mA{hr}.`2) Proto.d{hr}.`dl = zero)
           <= mu dsH (fun (s : seed) => dot (comb s.`2 Proto.mA{hr}.`2) Proto.d{hr}.`dl = zero).
  - by apply mu_sub => s /=; smt().
  by smt().
+ apply (ler_trans (mu dsH pred0)).
  - by apply mu_sub => s /=; rewrite /pred0; smt().
  by rewrite mu0; exact inv_pp1_ge0.
move=> _; exact inv_pp1_ge0.
qed.

local lemma stD1_pin2 :
  phoare [ G(A).stD1 : Q1o Proto.d Proto.sH Proto.mA ==> Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpA.
wp.
rnd (fun (a : fe * fe) => a.`2 * S2o Proto.d Proto.sH Proto.mA = T2o Proto.d Proto.sH Proto.mA Proto.gA).
skip => &hr hq /=.
split; last by smt().
move: hq; rewrite /Q1o => -[[hv [h1 hs]] _].
have e : mu dkey2 (fun (x : fe * fe) => x.`2 * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr})
         = mu dt (fun y => y * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) * weight dt.
+ by rewrite /dkey2; exact (dprodEr dt dt (fun y => y * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr})).
rewrite e w_dt.
have := single_pin (S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr}) (T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) hs.
smt().
move=> _; exact pi_ge0.
qed.


local lemma stD1_pin1 :
  phoare [ G(A).stD1 : Q2o Proto.d Proto.sH Proto.mA ==> Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpA.
wp.
rnd (fun (a : fe * fe) => a.`1 * S1o Proto.d Proto.sH Proto.mA = T1o Proto.d Proto.sH Proto.mA Proto.gA).
skip => &hr hq /=.
split; last by smt().
move: hq; rewrite /Q2o => -[[hv [hs h2]] _].
have e : mu dkey2 (fun (x : fe * fe) => x.`1 * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr})
         = mu dt (fun y => y * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) * weight dt.
+ by rewrite /dkey2; exact (dprodEl dt dt (fun y => y * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr})).
rewrite e w_dt.
have := single_pin (S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr}) (T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) hs.
smt().
move=> _; exact pi_ge0.
qed.

local lemma stD1_pin12 :
  phoare [ G(A).stD1 : true ==> Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= ((1%r / pp%r) * (1%r / pp%r)).
proof.
proc; inline Proto(A, CR.Log(CR.RO)).smpA.
wp.
rnd (fun (a : fe * fe) => Q0o Proto.d Proto.sH Proto.mA /\ a.`1 * S1o Proto.d Proto.sH Proto.mA = T1o Proto.d Proto.sH Proto.mA Proto.gA
                          /\ a.`2 * S2o Proto.d Proto.sH Proto.mA = T2o Proto.d Proto.sH Proto.mA Proto.gA).
skip => &hr _ /=.
split; last by smt().
have hinv : inv (pp%r * pp%r) = (1%r / pp%r) * (1%r / pp%r) by smt(pp_gt1).
rewrite hinv.
case (Q0o Proto.d{hr} Proto.sH{hr} Proto.mA{hr}) => hq.
+ move: hq; rewrite /Q0o => -[hv [hs1 hs2]].
  apply (ler_trans (mu dkey2 (fun (x : fe * fe) => x.`1 * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}
                                          /\ x.`2 * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}))).
  - by apply mu_sub => x /=; smt().
  rewrite /dkey2 (dprodE (fun y => y * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr})
                           (fun y => y * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) dt dt).
  have q1 := single_pin (S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr}) (T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) hs1.
  have q2 := single_pin (S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr}) (T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}) hs2.
  have g1 := ge0_mu dt (fun y => y * S1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T1o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}).
  have g2 := ge0_mu dt (fun y => y * S2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} = T2o Proto.d{hr} Proto.sH{hr} Proto.mA{hr} Proto.gA{hr}).
  exact (ler_pmul _ _ _ _ g1 g2 q1 q2).
+ apply (ler_trans (mu dkey2 pred0)).
  - by apply mu_sub => x /=; rewrite /pred0; smt().
  rewrite mu0; apply mulr_ge0; exact pi_ge0.
move=> _; apply mulr_ge0; exact pi_ge0.
qed.


local lemma bc_le1 (f : sdata -> seed -> seed -> bool) :
  phoare [ G(A).bc : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma stC_le1 (f : sdata -> seed -> seed -> bool) :
  phoare [ G(A).stC : f Proto.d Proto.sH Proto.mA ==> f Proto.d Proto.sH Proto.mA ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t3_le1 (f : sdata -> seed -> seed -> (fe * fe) -> gmsg -> bool) :
  phoare [ G(A).t3 : f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ==> f Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t2_stage_Ev2 :
  phoare [ G(A).t2 : Q1o Proto.d Proto.sH Proto.mA ==> Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc.
seq 1 : (Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) (1%r / pp%r) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call stD1_pin2.
+ by call (t3_le1 Ev2o).
+ by hoare; call (t3_keep (fun d sH mA aH gA => !Ev2o d sH mA aH gA)); skip => />.
smt().
qed.

local lemma t1_stage_Ev2 :
  phoare [ G(A).t1 : Q1o Proto.d Proto.sH Proto.mA ==> Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc.
seq 1 : (Q1o Proto.d Proto.sH Proto.mA) 1%r (1%r / pp%r) 0%r 1%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call (bc_le1 Q1o).
+ by call t2_stage_Ev2.
+ by hoare; call (bc_keep Q1o); skip => />.
smt().
qed.


local lemma t2_stage_Ev3 :
  phoare [ G(A).t2 : Q2o Proto.d Proto.sH Proto.mA ==> Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc.
seq 1 : (Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) (1%r / pp%r) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call stD1_pin1.
+ by call (t3_le1 Ev3o).
+ by hoare; call (t3_keep (fun d sH mA aH gA => !Ev3o d sH mA aH gA)); skip => />.
smt().
qed.

local lemma t1_stage_Ev3 :
  phoare [ G(A).t1 : Q2o Proto.d Proto.sH Proto.mA ==> Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= (1%r / pp%r).
proof.
proc.
seq 1 : (Q2o Proto.d Proto.sH Proto.mA) 1%r (1%r / pp%r) 0%r 1%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call (bc_le1 Q2o).
+ by call t2_stage_Ev3.
+ by hoare; call (bc_keep Q2o); skip => />.
smt().
qed.

local lemma t2_stage_Ev4 :
  phoare [ G(A).t2 : Q0o Proto.d Proto.sH Proto.mA ==> Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= ((1%r / pp%r) * (1%r / pp%r)).
proof.
proc.
seq 1 : (Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) ((1%r / pp%r) * (1%r / pp%r)) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call stD1_pin12.
+ by call (t3_le1 Ev4o).
+ by hoare; call (t3_keep (fun d sH mA aH gA => !Ev4o d sH mA aH gA)); skip => />.
smt().
qed.

local lemma pEv2 &m :
  Pr[G(A).main() @ &m : Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA] <= inv (pp - 1)%r * (1%r / pp%r).
proof.
byphoare (_ : true ==> Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) => //.
proc.
seq 2 : (Q1o Proto.d Proto.sH Proto.mA) (inv (pp - 1)%r) (1%r / pp%r) 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ seq 1 : true 1%r (inv (pp - 1)%r) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call stA_le1.
  - by call stB1_Q1.
  - by hoare; auto => />.
  - by auto.
+ by call t1_stage_Ev2.
+ hoare; call (t1_keep (fun d sH mA => !Q1o d sH mA)); skip => /> *.
  by smt().
smt().
qed.

local lemma pEv3 &m :
  Pr[G(A).main() @ &m : Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA] <= inv (pp - 1)%r * (1%r / pp%r).
proof.
byphoare (_ : true ==> Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) => //.
proc.
seq 2 : (Q2o Proto.d Proto.sH Proto.mA) (inv (pp - 1)%r) (1%r / pp%r) 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ seq 1 : true 1%r (inv (pp - 1)%r) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call stA_le1.
  - by call stB1_Q2.
  - by hoare; auto => />.
  - by auto.
+ by call t1_stage_Ev3.
+ hoare; call (t1_keep (fun d sH mA => !Q2o d sH mA)); skip => /> *.
  by smt().
smt().
qed.


local lemma bc_le1T : phoare [ G(A).bc : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t2_stage_Ev4T :
  phoare [ G(A).t2 : true ==> Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= ((1%r / pp%r) * (1%r / pp%r)).
proof.
proc.
seq 1 : (Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) ((1%r / pp%r) * (1%r / pp%r)) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call stD1_pin12.
+ by call (t3_le1 Ev4o).
+ by hoare; call (t3_keep (fun d sH mA aH gA => !Ev4o d sH mA aH gA)); skip => />.
smt().
qed.

local lemma stB1_le1 : phoare [ G(A).stB1 : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma t1_stage_Ev4 :
  phoare [ G(A).t1 : true ==> Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= ((1%r / pp%r) * (1%r / pp%r)).
proof.
proc.
seq 1 : true 1%r ((1%r / pp%r) * (1%r / pp%r)) 0%r 1%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call bc_le1T.
+ by call t2_stage_Ev4T.
+ by hoare; auto => />.
by smt().
qed.

local lemma pEv4 &m :
  Pr[G(A).main() @ &m : Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA] <= (1%r / pp%r) * (1%r / pp%r).
proof.
byphoare (_ : true ==> Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) => //.
proc.
seq 1 : true 1%r ((1%r / pp%r) * (1%r / pp%r)) 0%r 1%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ by call stA_le1.
+ seq 1 : true 1%r ((1%r / pp%r) * (1%r / pp%r)) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call stB1_le1.
  - by call t1_stage_Ev4.
  - by hoare; auto => />.
  - by auto.
+ by hoare; auto => />.
by smt().
qed.


(* ------------------------------------------------------------------ *)
(* real game = RunP against CR.RO = RunP against the library RO          *)

local lemma log_equiv :
  equiv [ CR.Log(CR.RO).o ~ CR.Log(Adp(RC.R.RO)).o :
          ={x, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==>
          ={res, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc; inline *.
sp.
case (x0{1} \in CR.RO.m{1}).
+ rcondf{1} 1; first by auto => />; smt().
  rcondf{2} 2; first by auto => />; smt().
  by wp; rnd{2}; skip => />; smt(dcm_ll').
+ rcondt{1} 1; first by auto => />; smt().
  rcondt{2} 2; first by auto => />; smt().
  by wp; rnd; skip => />; smt().
qed.

local lemma ro_equiv :
  equiv [ CR.RO.o ~ Adp(RC.R.RO).o :
          ={x} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={res} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc; inline *.
sp.
case (x{1} \in CR.RO.m{1}).
+ rcondf{1} 1; first by auto => />; smt().
  rcondf{2} 2; first by auto => />; smt().
  by wp; rnd{2}; skip => />; smt(dcm_ll').
+ rcondt{1} 1; first by auto => />; smt().
  rcondt{2} 2; first by auto => />; smt().
  by wp; rnd; skip => />; smt().
qed.


local lemma setup0_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).setup0 ~ Proto(A, CR.Log(Adp(RC.R.RO))).setup0 :
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==>
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
call (_ : ={CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2}); first by conseq log_equiv => //.
by skip.
qed.

local lemma p1_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).p1 ~ Proto(A, CR.Log(Adp(RC.R.RO))).p1 :
          ={c, glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==>
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
wp.
call (_ : ={CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2}); first by conseq log_equiv => //.
by wp; skip => />.
qed.


local lemma smpH_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).smpH ~ Proto(A, CR.Log(Adp(RC.R.RO))).smpH :
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof. by proc; rnd; skip => />. qed.

local lemma so0_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).so0 ~ Proto(A, CR.Log(Adp(RC.R.RO))).so0 :
          ={n} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
wp.
call (_ : ={CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2}); first by conseq log_equiv => //.
by wp; skip => />.
qed.

local lemma smpA_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).smpA ~ Proto(A, CR.Log(Adp(RC.R.RO))).smpA :
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof. by proc; wp; rnd; skip => />. qed.

local lemma p3_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).p3 ~ Proto(A, CR.Log(Adp(RC.R.RO))).p3 :
          ={c} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
wp.
call (_ : ={CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2}); first by conseq log_equiv => //.
by wp; skip => />.
qed.

local lemma go0_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).go0 ~ Proto(A, CR.Log(Adp(RC.R.RO))).go0 :
          ={n} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
call log_equiv.
call log_equiv.
call log_equiv.
call log_equiv.
wp.
call (_ : ={CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2}); first by conseq log_equiv => //.
by wp; skip => />.
qed.

local lemma p0_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).p0 ~ Proto(A, CR.Log(Adp(RC.R.RO))).p0 :
          ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={res} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof. by proc; wp; call smpH_eq; call setup0_eq; skip. qed.

local lemma p2_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).p2 ~ Proto(A, CR.Log(Adp(RC.R.RO))).p2 :
          ={n} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={res} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof. by proc; wp; call smpA_eq; call so0_eq; skip. qed.

local lemma p4_eq :
  equiv [ Proto(A, CR.Log(CR.RO)).p4 ~ Proto(A, CR.Log(Adp(RC.R.RO))).p4 :
          ={n} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ==> ={res} /\ ={glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
inline Proto(A, CR.Log(CR.RO)).evalC Proto(A, CR.Log(Adp(RC.R.RO))).evalC.
wp.
call go0_eq.
by skip.
qed.

local lemma run_eq :
  equiv [ RunP(A, CR.RO).run ~ RunP(A, Adp(RC.R.RO)).run :
          ={glob A, glob Proto} /\ CR.RO.m{1} = RC.R.RO.m{2} /\ ={CR.Log.qs} ==>
          ={res, glob A, glob Proto, CR.Log.qs} /\ CR.RO.m{1} = RC.R.RO.m{2} ].
proof.
proc.
call p4_eq.
call p3_eq.
call ro_equiv.
wp; rnd.
call p2_eq.
call p1_eq.
call ro_equiv.
wp; rnd.
call p0_eq.
wp; skip => />.
qed.


(* ------------------------------------------------------------------ *)
(* the four hash answers recorded by the protocol are entries of the oracle map *)

local lemma ora_get (kk : CR.key) :
  hoare [ CR.Log(Adp(RC.R.RO)).o : arg = kk ==> RC.R.RO.m.[kk] = Some res ].
proof.
proc; inline *.
sp; wp.
seq 1 : (x1 = kk).
+ by auto.
by auto => />; smt(get_setE).
qed.

local lemma ora_stab (kk : CR.key) (vv : cm) :
  hoare [ CR.Log(Adp(RC.R.RO)).o : RC.R.RO.m.[kk] = Some vv ==> RC.R.RO.m.[kk] = Some vv ].
proof.
proc; inline *.
sp; wp.
by auto => />; smt(get_setE mem_set).
qed.


local lemma ora_c (kn : CR.key) (ks : (CR.key * cm) list) :
  hoare [ CR.Log(Adp(RC.R.RO)).o :
          arg = kn /\ (forall p, p \in ks => RC.R.RO.m.[p.`1] = Some p.`2) ==>
          (forall p, p \in ks => RC.R.RO.m.[p.`1] = Some p.`2) /\ RC.R.RO.m.[kn] = Some res ].
proof.
proc; inline *.
sp; wp.
seq 1 : (x1 = kn /\ (forall p, p \in ks => RC.R.RO.m.[p.`1] = Some p.`2)).
+ by auto.
by auto => />; smt(get_setE mem_set).
qed.

local lemma p4_post :
  hoare [ Proto(A, CR.Log(Adp(RC.R.RO))).p4 : true ==>
          RC.R.RO.m.[CR.K1 (Proto.mo.`1, Proto.mo.`2)] = Some Proto.y1 /\
          RC.R.RO.m.[CR.K1 (Proto.mA, Proto.nA)] = Some Proto.y2 /\
          RC.R.RO.m.[CR.K2 (Proto.g2, Proto.ng2)] = Some Proto.y3 /\
          RC.R.RO.m.[CR.K2 (Proto.gA, Proto.nGA)] = Some Proto.y4 /\
          Proto.collS = (Proto.mo.`1 <> Proto.mA /\ Proto.y1 = Proto.y2) /\
          Proto.collG = (Proto.g2 <> Proto.gA /\ Proto.y3 = Proto.y4) /\
          res = Proto.winC /\ (Proto.winR => Proto.winC \/ Proto.collS \/ Proto.collG) ].
proof.
proc.
inline Proto(A, CR.Log(Adp(RC.R.RO))).evalC Proto(A, CR.Log(Adp(RC.R.RO))).go0.
wp.
seq 5 : true.
+ wp; call (_ : true); first by proc; inline *; auto.
  by wp; skip.
exists* Proto.mo, Proto.mA, Proto.nA, Proto.gA, Proto.nGA, Proto.g2, Proto.ng2.
elim* => mo mA nA gA nGA g2 ng2.
seq 1 : (Proto.mo = mo /\ Proto.mA = mA /\ Proto.nA = nA /\ Proto.gA = gA /\ Proto.nGA = nGA
         /\ Proto.g2 = g2 /\ Proto.ng2 = ng2
         /\ RC.R.RO.m.[CR.K1 (mo.`1, mo.`2)] = Some Proto.y1).
+ by call (ora_get (CR.K1 (mo.`1, mo.`2))); skip => />.
exists* Proto.y1; elim* => y1.
seq 1 : (Proto.mo = mo /\ Proto.mA = mA /\ Proto.nA = nA /\ Proto.gA = gA /\ Proto.nGA = nGA
         /\ Proto.g2 = g2 /\ Proto.ng2 = ng2 /\ Proto.y1 = y1
         /\ RC.R.RO.m.[CR.K1 (mo.`1, mo.`2)] = Some y1
         /\ RC.R.RO.m.[CR.K1 (mA, nA)] = Some Proto.y2).
+ call (ora_c (CR.K1 (mA, nA)) [(CR.K1 (mo.`1, mo.`2), y1)]).
  skip => /> &hr h; smt().
exists* Proto.y2; elim* => y2.
seq 1 : (Proto.mo = mo /\ Proto.mA = mA /\ Proto.nA = nA /\ Proto.gA = gA /\ Proto.nGA = nGA
         /\ Proto.g2 = g2 /\ Proto.ng2 = ng2 /\ Proto.y1 = y1 /\ Proto.y2 = y2
         /\ RC.R.RO.m.[CR.K1 (mo.`1, mo.`2)] = Some y1
         /\ RC.R.RO.m.[CR.K1 (mA, nA)] = Some y2
         /\ RC.R.RO.m.[CR.K2 (g2, ng2)] = Some Proto.y3).
+ call (ora_c (CR.K2 (g2, ng2)) [(CR.K1 (mo.`1, mo.`2), y1); (CR.K1 (mA, nA), y2)]).
  skip => /> &hr h; smt().
exists* Proto.y3; elim* => y3.
call (ora_c (CR.K2 (gA, nGA)) [(CR.K1 (mo.`1, mo.`2), y1); (CR.K1 (mA, nA), y2); (CR.K2 (g2, ng2), y3)]).
skip => /> &hr h; smt().

qed.


local lemma rl_runR :
  equiv [ CR.Rl(Proto(A)).main ~ RunR(A).main :
          ={glob A, glob Proto, glob CR.RO, glob CR.Log} ==>
          ={res, glob A, glob Proto, glob CR.RO, glob CR.Log} ].
proof.
proc.
inline CR.Rl(Proto(A)).w1 CR.Rl(Proto(A)).suf CR.Rl(Proto(A)).w2 CR.Rl(Proto(A)).fin RunP(A, CR.RO).run.
sim.
qed.


local lemma runR_DS :
  equiv [ RunR(A).main ~ RC.R.MainRM(DS(A), RC.R.RO).distinguish :
          ={glob A, glob Proto, CR.Log.qs} ==>
          res{2} = Proto.collS{1} /\ ={glob Proto} /\ CR.RO.m{1} = RC.R.RO.m{2} /\ ={CR.Log.qs} ].
proof.
proc.
inline DS(A, RC.R.RO).distinguish RC.R.RO.init CR.RO.init.
wp.
call run_eq.
by wp; skip => />.
qed.

local lemma runR_DG :
  equiv [ RunR(A).main ~ RC.R.MainRM(DG(A), RC.R.RO).distinguish :
          ={glob A, glob Proto, CR.Log.qs} ==>
          res{2} = Proto.collG{1} /\ ={glob Proto} /\ CR.RO.m{1} = RC.R.RO.m{2} /\ ={CR.Log.qs} ].
proof.
proc.
inline DG(A, RC.R.RO).distinguish RC.R.RO.init CR.RO.init.
wp.
call run_eq.
by wp; skip => />.
qed.


local lemma adp_t : hoare [ Adp(RC.R.RO).o : true ==> true ].
proof. by proc; inline *; auto. qed.

local lemma p0_t : hoare [ Proto(A, CR.Log(Adp(RC.R.RO))).p0 : true ==> true ].
proof.
proc; inline Proto(A, CR.Log(Adp(RC.R.RO))).setup0 Proto(A, CR.Log(Adp(RC.R.RO))).smpH.
wp; rnd; wp.
call (_ : true); first by proc; inline *; auto.
by skip.
qed.

local lemma p1_t : hoare [ Proto(A, CR.Log(Adp(RC.R.RO))).p1 : true ==> true ].
proof.
proc; wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip.
qed.

local lemma p2_t : hoare [ Proto(A, CR.Log(Adp(RC.R.RO))).p2 : true ==> true ].
proof.
proc; inline Proto(A, CR.Log(Adp(RC.R.RO))).so0 Proto(A, CR.Log(Adp(RC.R.RO))).smpA.
wp; rnd; wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip.
qed.

local lemma p3_t : hoare [ Proto(A, CR.Log(Adp(RC.R.RO))).p3 : true ==> true ].
proof.
proc; wp.
call (_ : true); first by proc; inline *; auto.
by wp; skip.
qed.

local lemma run_fact :
  hoare [ RunP(A, Adp(RC.R.RO)).run : true ==>
          (Proto.collS => (RC.R.RO.m.[CR.K1 (Proto.mo.`1, Proto.mo.`2)] = Some Proto.y1 /\
                           RC.R.RO.m.[CR.K1 (Proto.mA, Proto.nA)] = Some Proto.y2 /\ Proto.mo.`1 <> Proto.mA /\ Proto.y1 = Proto.y2))
          /\ (Proto.collG => (RC.R.RO.m.[CR.K2 (Proto.g2, Proto.ng2)] = Some Proto.y3 /\
                             RC.R.RO.m.[CR.K2 (Proto.gA, Proto.nGA)] = Some Proto.y4 /\ Proto.g2 <> Proto.gA /\ Proto.y3 = Proto.y4))
          /\ res = Proto.winC /\ (Proto.winR => Proto.winC \/ Proto.collS \/ Proto.collG) ].
proof.
proc.
seq 11 : true.
+ call p3_t.
  call adp_t.
  wp; rnd.
  call p2_t.
  call p1_t.
  call adp_t.
  wp; rnd.
  call p0_t.
  by wp; skip.
wp; call p4_post; skip => /> *; smt().
qed.


declare op qi : int.
declare axiom qi_ge0 : 0 <= qi.
(* P makes at most qi oracle queries, whatever the environment does between its calls (the only hypothesis
   on the adversary besides termination). *)
declare axiom Hq_env (E <: CR.Env {-A, -Proto, -CR.Log}) :
  hoare [ CR.RunEnv(Proto(A), E).main : true ==> size CR.Log.qs <= qi ].

local lemma pr_fsize_Rl &m : Pr [ CR.Rl(Proto(A)).main() @ &m : !(fsize CR.RO.m <= qi + 2) ] <= 0%r.
proof.
have h1 := CR.real_size_ok (Proto(A)) qi Hq_env &m.
have h2 : Pr [ CR.Rl(Proto(A)).main() @ &m : !(forall x, x \in CR.RO.m => x \in CR.Log.qs \/ x = CR.Rl.t1 \/ x = CR.Rl.t2) ] <= 0%r.
+ byphoare (_ : true ==> !(forall x, x \in CR.RO.m => x \in CR.Log.qs \/ x = CR.Rl.t1 \/ x = CR.Rl.t2)) => //.
  hoare.
  by conseq (CR.real_dom (Proto(A)) qi Hq_env) => /> *; smt().
have h3 : Pr [ CR.Rl(Proto(A)).main() @ &m : !(fsize CR.RO.m <= qi + 2) ]
          <= Pr [ CR.Rl(Proto(A)).main() @ &m : !(size CR.Log.qs <= qi)
                    \/ !(forall x, x \in CR.RO.m => x \in CR.Log.qs \/ x = CR.Rl.t1 \/ x = CR.Rl.t2) ].
+ rewrite Pr[mu_sub] => // &hr.
  move=> hn; case (size CR.Log.qs{hr} <= qi) => hs; last by smt().
  case (forall x, x \in CR.RO.m{hr} => x \in CR.Log.qs{hr} \/ x = CR.Rl.t1{hr} \/ x = CR.Rl.t2{hr}) => hall; last by smt().
  have := CR.fsize_bound (Proto(A)) qi Hq_env CR.RO.m{hr} CR.Log.qs{hr} CR.Rl.t1{hr} CR.Rl.t2{hr} hall.
  smt().
have h4 : Pr [ CR.Rl(Proto(A)).main() @ &m : !(size CR.Log.qs <= qi)
                    \/ !(forall x, x \in CR.RO.m => x \in CR.Log.qs \/ x = CR.Rl.t1 \/ x = CR.Rl.t2) ]
          <= Pr [ CR.Rl(Proto(A)).main() @ &m : !(size CR.Log.qs <= qi) ]
             + Pr [ CR.Rl(Proto(A)).main() @ &m : !(forall x, x \in CR.RO.m => x \in CR.Log.qs \/ x = CR.Rl.t1 \/ x = CR.Rl.t2) ].
+ by rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

local lemma pr_size_S &m : Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= qi + 2) ] <= 0%r.
proof.
have e1 : Pr [ CR.Rl(Proto(A)).main() @ &m : !(fsize CR.RO.m <= qi + 2) ] = Pr [ RunR(A).main() @ &m : !(fsize CR.RO.m <= qi + 2) ].
+ by byequiv rl_runR => //; smt().
have e2 : Pr [ RunR(A).main() @ &m : !(fsize CR.RO.m <= qi + 2) ] = Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= qi + 2) ].
+ by byequiv runR_DS => //; smt().
have := pr_fsize_Rl &m.
smt().
qed.

local lemma pr_size_G &m : Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= qi + 2) ] <= 0%r.
proof.
have e1 : Pr [ CR.Rl(Proto(A)).main() @ &m : !(fsize CR.RO.m <= qi + 2) ] = Pr [ RunR(A).main() @ &m : !(fsize CR.RO.m <= qi + 2) ].
+ by byequiv rl_runR => //; smt().
have e2 : Pr [ RunR(A).main() @ &m : !(fsize CR.RO.m <= qi + 2) ] = Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= qi + 2) ].
+ by byequiv runR_DG => //; smt().
have := pr_fsize_Rl &m.
smt().
qed.

local lemma hS_coll :
  hoare [ RC.R.MainRM(DS(A), RC.R.RO).distinguish : true ==>
          res => fcoll (fun (z : cm) => z) RC.R.RO.m ].
proof.
proc; inline DS(A, RC.R.RO).distinguish RC.R.RO.init.
wp.
call run_fact.
by wp; skip => /> *; smt(fcoll_of k1_ne).
qed.

local lemma hG_coll :
  hoare [ RC.R.MainRM(DG(A), RC.R.RO).distinguish : true ==>
          res => fcoll (fun (z : cm) => z) RC.R.RO.m ].
proof.
proc; inline DG(A, RC.R.RO).distinguish RC.R.RO.init.
wp.
call run_fact.
by wp; skip => /> *; smt(fcoll_of k2_ne).
qed.

local lemma pr_hbad_S &m :
  Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m :
       res /\ !(fcoll (fun (z : cm) => z) RC.R.RO.m /\ fsize RC.R.RO.m <= (qi + 2)) ] <= 0%r.
proof.
have h1 : Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m ] <= 0%r.
+ byphoare (_ : true ==> res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) => //.
  hoare.
  by conseq hS_coll => /> *; smt().
have h2 := pr_size_S &m.
have h3 : Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : res /\ !(fcoll (fun (z : cm) => z) RC.R.RO.m /\ fsize RC.R.RO.m <= (qi + 2)) ]
          <= Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : (res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) \/ !(fsize RC.R.RO.m <= (qi + 2)) ].
+ by rewrite Pr[mu_sub]; smt().
have h4 : Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : (res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) \/ !(fsize RC.R.RO.m <= (qi + 2)) ]
          <= Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m ]
             + Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= (qi + 2)) ].
+ by rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

lemma pr_collS &m :
  Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS ] <= ((qi + 2) * ((qi + 2) - 1))%r / 2%r * pc.
proof.
have e1 : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS ] = Pr [ RunR(A).main() @ &m : Proto.collS ].
+ by byequiv rl_runR => //; smt().
have e2 : Pr [ RunR(A).main() @ &m : Proto.collS ] = Pr [ RC.R.MainRM(DS(A), RC.R.RO).distinguish() @ &m : res ].
+ by byequiv runR_DS => //; smt().
rewrite e1 e2.
have hq2 : 0 <= qi + 2 by smt(qi_ge0).
exact (RC.rom_collision_gen (DS(A)) (qi + 2) &m hq2 (pr_hbad_S &m)).
qed.

local lemma pr_hbad_G &m :
  Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m :
       res /\ !(fcoll (fun (z : cm) => z) RC.R.RO.m /\ fsize RC.R.RO.m <= (qi + 2)) ] <= 0%r.
proof.
have h1 : Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m ] <= 0%r.
+ byphoare (_ : true ==> res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) => //.
  hoare.
  by conseq hG_coll => /> *; smt().
have h2 := pr_size_G &m.
have h3 : Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : res /\ !(fcoll (fun (z : cm) => z) RC.R.RO.m /\ fsize RC.R.RO.m <= (qi + 2)) ]
          <= Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : (res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) \/ !(fsize RC.R.RO.m <= (qi + 2)) ].
+ by rewrite Pr[mu_sub]; smt().
have h4 : Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : (res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m) \/ !(fsize RC.R.RO.m <= (qi + 2)) ]
          <= Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : res /\ !fcoll (fun (z : cm) => z) RC.R.RO.m ]
             + Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : !(fsize RC.R.RO.m <= (qi + 2)) ].
+ by rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

lemma pr_collG &m :
  Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collG ] <= ((qi + 2) * ((qi + 2) - 1))%r / 2%r * pc.
proof.
have e1 : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collG ] = Pr [ RunR(A).main() @ &m : Proto.collG ].
+ by byequiv rl_runR => //; smt().
have e2 : Pr [ RunR(A).main() @ &m : Proto.collG ] = Pr [ RC.R.MainRM(DG(A), RC.R.RO).distinguish() @ &m : res ].
+ by byequiv runR_DG => //; smt().
rewrite e1 e2.
have hq2 : 0 <= qi + 2 by smt(qi_ge0).
exact (RC.rom_collision_gen (DG(A)) (qi + 2) &m hq2 (pr_hbad_G &m)).
qed.


local lemma runR_DW :
  equiv [ RunR(A).main ~ RC.R.MainRM(DW(A), RC.R.RO).distinguish :
          ={glob A, glob Proto, CR.Log.qs} ==> ={res, glob Proto} ].
proof.
proc.
inline DW(A, RC.R.RO).distinguish RC.R.RO.init CR.RO.init.
wp.
call run_eq.
by wp; skip => />.
qed.

local lemma hW :
  hoare [ RC.R.MainRM(DW(A), RC.R.RO).distinguish : true ==>
          (Proto.winR => res \/ Proto.collS \/ Proto.collG) /\ res = Proto.winC ].
proof.
proc; inline DW(A, RC.R.RO).distinguish RC.R.RO.init.
wp.
call (_ : true ==> res = Proto.winC /\ (Proto.winR => Proto.winC \/ Proto.collS \/ Proto.collG)).
+ by conseq run_fact => /> *; smt().
by wp; skip => /> *; smt().
qed.


lemma real_le &m :
  Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR ]
  <= Pr [ CR.Rl(Proto(A)).main() @ &m : res ]
     + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS ]
     + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collG ].
proof.
have e1 : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ]
          = Pr [ RunR(A).main() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ].
+ by byequiv rl_runR => //; smt().
have e2 : Pr [ RunR(A).main() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ]
          = Pr [ RC.R.MainRM(DW(A), RC.R.RO).distinguish() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ].
+ by byequiv runR_DW => //; smt().
have e3 : Pr [ RC.R.MainRM(DW(A), RC.R.RO).distinguish() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ] <= 0%r.
+ byphoare (_ : true ==> Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG)) => //.
  hoare.
  by conseq hW => /> *; smt().
have e4 : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR ]
          <= Pr [ CR.Rl(Proto(A)).main() @ &m : res \/ Proto.collS \/ Proto.collG ]
             + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR /\ !(res \/ Proto.collS \/ Proto.collG) ].
+ rewrite Pr[mu_split (res \/ Proto.collS \/ Proto.collG)].
  have : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR /\ (res \/ Proto.collS \/ Proto.collG) ]
         <= Pr [ CR.Rl(Proto(A)).main() @ &m : res \/ Proto.collS \/ Proto.collG ].
  - by rewrite Pr[mu_sub]; smt().
  smt().
have e5 : Pr [ CR.Rl(Proto(A)).main() @ &m : res \/ Proto.collS \/ Proto.collG ]
          <= Pr [ CR.Rl(Proto(A)).main() @ &m : res ]
             + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS ]
             + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collG ].
+ have a : Pr [ CR.Rl(Proto(A)).main() @ &m : res \/ (Proto.collS \/ Proto.collG) ]
           <= Pr [ CR.Rl(Proto(A)).main() @ &m : res ] + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS \/ Proto.collG ].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  have b : Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS \/ Proto.collG ]
           <= Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collS ] + Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.collG ].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  smt().
smt().
qed.


local lemma stE_ev :
  hoare [ G(A).stE : true ==> res => EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof.
proc; inline Proto(A, CR.Log(CR.RO)).p4 Proto(A, CR.Log(CR.RO)).go0 Proto(A, CR.Log(CR.RO)).evalC.
wp.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
call (_ : true ==> true); first by proc; inline *; auto.
wp.
call (_ : true); first by proc; inline *; auto.
wp; skip => /> *.
by rewrite /EVo /Vo; smt().
qed.

local lemma stB1_t : hoare [ G(A).stB1 : true ==> true ].
proof. by proc; inline Proto(A, CR.Log(CR.RO)).smpH; rnd; skip. qed.

local lemma stA_t : hoare [ G(A).stA : true ==> true ].
proof.
proc; inline Proto(A, CR.Log(CR.RO)).setup0 Proto(A, CR.Log(CR.RO)).p1.
wp.
call (_ : true); first by proc; inline *; auto.
wp; rnd; wp.
call (_ : true); first by proc; inline *; auto.
by inline CR.RO.init; wp; skip.
qed.

local lemma t3_ev :
  hoare [ G(A).t3 : true ==> res => EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; call stE_ev; call (stD2_keep (fun d sH mA (aH : fe * fe) (gA : gmsg) => true)); skip. qed.

local lemma t2_ev :
  hoare [ G(A).t2 : true ==> res => EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; call t3_ev; call (stD1_keep (fun d sH mA (gA : gmsg) => true)); skip. qed.

local lemma t1_ev :
  hoare [ G(A).t1 : true ==> res => EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; call t2_ev; call (bc_keep (fun d sH mA => true)); skip. qed.

local lemma main_ev :
  hoare [ G(A).main : true ==> res => EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
proof. by proc; call t1_ev; call stB1_t; call stA_t; skip. qed.


lemma ideal_bound &m :
  Pr [ G(A).main() @ &m : res ]
  <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r).
proof.
have h0 : Pr [ G(A).main() @ &m : res /\ !EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ] <= 0%r.
+ byphoare (_ : true ==> res /\ !EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) => //.
  hoare.
  by conseq main_ev => /> *; smt().
have h1 : Pr [ G(A).main() @ &m : res ]
          <= Pr [ G(A).main() @ &m : Eo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
+ rewrite Pr[mu_split (EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA)].
  have : Pr [ G(A).main() @ &m : res /\ EVo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
         <= Pr [ G(A).main() @ &m : Eo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
  - rewrite Pr[mu_sub] => // &hr.
    move=> [_ hev].
    have := ev_split _ _ _ _ _ hev.
    by rewrite /Eo /Zo /Ev2o /Ev3o /Ev4o /Q1o /Q2o /Q0o; smt().
  smt().
have h2 : Pr [ G(A).main() @ &m : Eo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
          <= Pr [ G(A).main() @ &m : Zo Proto.d Proto.sH Proto.mA ]
             + Pr [ G(A).main() @ &m : Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
             + Pr [ G(A).main() @ &m : Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
             + Pr [ G(A).main() @ &m : Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
+ have a1 : Pr [ G(A).main() @ &m : Eo Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
            <= Pr [ G(A).main() @ &m : Zo Proto.d Proto.sH Proto.mA ]
               + Pr [ G(A).main() @ &m : Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ (Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) ].
  - by rewrite /Eo Pr[mu_or]; smt(mu_bounded).
  have a2 : Pr [ G(A).main() @ &m : Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ (Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA) ]
            <= Pr [ G(A).main() @ &m : Ev2o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
               + Pr [ G(A).main() @ &m : Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  have a3 : Pr [ G(A).main() @ &m : Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA \/ Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
            <= Pr [ G(A).main() @ &m : Ev3o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ]
               + Pr [ G(A).main() @ &m : Ev4o Proto.d Proto.sH Proto.mA Proto.aH Proto.gA ].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  smt().
have p1 := pZ12 &m.
have p2 := pEv2 &m.
have p3 := pEv3 &m.
have p4 := pEv4 &m.
have hp := pi_ge0.
have hb := inv_pp1_ge0.
have e : (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r)
         = inv (pp - 1)%r * inv (pp - 1)%r + inv (pp - 1)%r * (1%r / pp%r) + inv (pp - 1)%r * (1%r / pp%r)
           + (1%r / pp%r) * (1%r / pp%r) by ring.
rewrite e.
have p1' : Pr [ G(A).main() @ &m : Zo Proto.d Proto.sH Proto.mA ] <= inv (pp - 1)%r / (pp - 1)%r.
+ by move: p1; rewrite /Zo.
apply (ler_trans _ _ _ h1).
apply (ler_trans _ _ _ h2).
apply ler_add; [apply ler_add; [apply ler_add; [exact p1' | exact p2] | exact p3] | exact p4].
qed.


lemma proto_p0_ll_gen : forall (O <: CR.Oracle{-Proto(A)}), islossless O.o => islossless Proto(A, O).p0.
proof. by move=> O hO; apply (proto_p0_ll O hO). qed.
lemma proto_p1_ll_gen : forall (O <: CR.Oracle{-Proto(A)}), islossless O.o => islossless Proto(A, O).p1.
proof. by move=> O hO; apply (proto_p1_ll O hO). qed.
lemma proto_p2_ll_gen : forall (O <: CR.Oracle{-Proto(A)}), islossless O.o => islossless Proto(A, O).p2.
proof. by move=> O hO; apply (proto_p2_ll O hO). qed.
lemma proto_p3_ll_gen : forall (O <: CR.Oracle{-Proto(A)}), islossless O.o => islossless Proto(A, O).p3.
proof. by move=> O hO; apply (proto_p3_ll O hO). qed.
lemma proto_p4_ll_gen : forall (O <: CR.Oracle{-Proto(A)}), islossless O.o => islossless Proto(A, O).p4.
proof. by move=> O hO; apply (proto_p4_ll O hO). qed.

lemma spdz_rom_soundness &m :
  Pr [ CR.Rl(Proto(A)).main() @ &m : Proto.winR ]
  <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r)
     + 2%r * (qi%r * pmax)
     + ((qi + 2) * ((qi + 2) - 1))%r / 2%r * pc + ((qi + 2) * ((qi + 2) - 1))%r / 2%r * pc.
proof.
have h1 := real_le &m.
have h2 := pr_collS &m.
have h3 := pr_collG &m.
have h4 := CR.twin_hide_le (Proto(A)) (proto_p0_ll_gen) (proto_p1_ll_gen) (proto_p2_ll_gen) (proto_p3_ll_gen) (proto_p4_ll_gen) qi qi_ge0 (CR.queries_ok (Proto(A)) qi Hq_env) &m.
have h5 : Pr [ CR.Id(Proto(A)).main() @ &m : res ] = Pr [ G(A).main() @ &m : res ].
+ by byequiv id_G => //; smt().
have h6 := ideal_bound &m.
smt().
qed.

end section.
