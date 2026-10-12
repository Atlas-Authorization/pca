(* PcaCommitReveal.ec -- HIDING OF TWO SEQUENTIAL HASH COMMITMENTS INSIDE AN ARBITRARY PROTOCOL, in the ROM.

   Generalises PcaCommitROM.ec (one commitment, adversary learns a bit) to what a protocol needs: two commit/reveal
   WINDOWS in sequence,
        p0 ... commit(m1) ... p1 ... reveal(r1) ... p2 ... commit(m2) ... p3 ... reveal(r2) ... p4 -> result
   where the phases p0..p4 are an arbitrary oracle-aided program D (honest parties and adversary together) and the
   commitment of window j is  H(Kj (m_j, r_j))  for a fresh nonce r_j.  The REAL game commits honestly.
   The IDEAL game hands D an independent random string as the commitment, samples the nonce LATE (at the reveal) and
   PROGRAMS the oracle at the committed point so that everything D sees after the reveal is consistent.

   THEOREM `twin_hide` : for every D that makes at most `q` distinct oracle queries before each reveal,
        Pr[Rl(D) : res]  <=  Pr[Id(D) : res]  +  2 * q * pmax            (one-sided, for every event on res)
   and the same with Rl and Id swapped.  The only losses are the events "D queried the committed point before
   the reveal", each of probability at most q * pmax because the nonce is not yet sampled.

   This is what makes the hiding link to the protocol game a checked statement: the protocol (honest parties + adversary)
   is D, and the ideal game is the one in which the honest commitment strings are independent of the honest values. *)
require import AllCore Int Real List Distr FMap FSet StdOrder.
import RealOrder.

abstract theory TW.

type msg1.
type msg2.
type nonce.
type cm.
type key = [ K1 of msg1 * nonce | K2 of msg2 * nonce ].

op dn : nonce distr.
op dcm : cm distr.
op pmax : real.

axiom dn_ll : is_lossless dn.
axiom dcm_ll : is_lossless dcm.
axiom pmax_ge0 : 0%r <= pmax.
axiom dn_pmax (r : nonce) : mu1 dn r <= pmax.

op nonceOf (x : key) : nonce =
  with x = K1 mn => mn.`2
  with x = K2 mn => mn.`2.

op isK1 (x : key) : bool =
  with x = K1 _ => true
  with x = K2 _ => false.

lemma isK1_K1 (m : msg1) (r : nonce) : isK1 (K1 (m, r)). proof. by []. qed.
lemma isK1_K2 (m : msg2) (r : nonce) : !isK1 (K2 (m, r)). proof. by []. qed.

(* ------------------------------------------------------------------ *)
(* probability of hitting a logged point                                *)

lemma mu_hit1 (m : msg1) (l : key list) :
  mu dn (fun r => K1 (m, r) \in l) <= (size l)%r * pmax.
proof.
elim: l => [|x l ih].
+ by rewrite /= mu0_false //; smt(pmax_ge0).
have h1 : mu dn (fun r => x = K1 (m, r)) <= pmax.
+ apply (ler_trans (mu dn (pred1 (nonceOf x)))); last exact (dn_pmax _).
  by apply mu_sub => r /= h; rewrite /pred1 h /nonceOf /=.
have h2 : mu dn (fun r => K1 (m, r) \in x :: l)
          <= mu dn (fun r => x = K1 (m, r)) + mu dn (fun r => K1 (m, r) \in l).
+ apply (ler_trans (mu dn (predU (fun r => x = K1 (m, r)) (fun r => K1 (m, r) \in l)))).
  - by apply mu_sub => r /=; rewrite /predU; smt().
  by rewrite mu_or; smt(ge0_mu).
have hs : (size (x :: l))%r = 1%r + (size l)%r by smt(size_ge0).
rewrite hs; smt(pmax_ge0).
qed.

lemma mu_hit2 (m : msg2) (l : key list) :
  mu dn (fun r => K2 (m, r) \in l) <= (size l)%r * pmax.
proof.
elim: l => [|x l ih].
+ by rewrite /= mu0_false //; smt(pmax_ge0).
have h1 : mu dn (fun r => x = K2 (m, r)) <= pmax.
+ apply (ler_trans (mu dn (pred1 (nonceOf x)))); last exact (dn_pmax _).
  by apply mu_sub => r /= h; rewrite /pred1 h /nonceOf /=.
have h2 : mu dn (fun r => K2 (m, r) \in x :: l)
          <= mu dn (fun r => x = K2 (m, r)) + mu dn (fun r => K2 (m, r) \in l).
+ apply (ler_trans (mu dn (predU (fun r => x = K2 (m, r)) (fun r => K2 (m, r) \in l)))).
  - by apply mu_sub => r /=; rewrite /predU; smt().
  by rewrite mu_or; smt(ge0_mu).
have hs : (size (x :: l))%r = 1%r + (size l)%r by smt(size_ge0).
rewrite hs; smt(pmax_ge0).
qed.

(* ------------------------------------------------------------------ *)
(* the random oracle and the logging wrapper                            *)

module type Oracle = { proc o(x : key) : cm }.

module RO : Oracle = {
  var m : (key, cm) fmap
  proc init() : unit = { m <- empty; }
  proc o(x : key) : cm = {
    var y : cm;
    if (x \notin m) {
      y <$ dcm;
      m.[x] <- y;
    }
    return oget m.[x];
  }
}.

module Log (O : Oracle) : Oracle = {
  var qs : key list
  proc o(x : key) : cm = {
    var y : cm;
    qs <- x :: qs;
    y <@ O.o(x);
    return y;
  }
}.

(* the protocol: five oracle-aided phases *)
module type D (O : Oracle) = {
  proc p0() : msg1                { O.o }
  proc p1(c : cm) : unit          { O.o }
  proc p2(r : nonce) : msg2       { O.o }
  proc p3(c : cm) : unit          { O.o }
  proc p4(r : nonce) : bool       { O.o }
}.

module Rl (P : D) = {
  var r1 : nonce
  var c1 : cm
  var c2 : cm
  var r2 : nonce
  var t1 : key
  var t2 : key

  proc w1(m1 : msg1) : unit = {
    r1 <$ dn;
    t1 <- K1 (m1, r1);
    c1 <@ RO.o(t1);
    P(Log(RO)).p1(c1);
  }

  proc w2(m2 : msg2) : unit = {
    r2 <$ dn;
    t2 <- K2 (m2, r2);
    c2 <@ RO.o(t2);
    P(Log(RO)).p3(c2);
  }

  proc fin() : bool = {
    var rs : bool;
    rs <@ P(Log(RO)).p4(r2);
    return rs;
  }

  proc suf() : bool = {
    var m2 : msg2; var rs : bool;
    m2 <@ P(Log(RO)).p2(r1);
    w2(m2);
    rs <@ fin();
    return rs;
  }

  proc main() : bool = {
    var m1 : msg1; var rs : bool;
    RO.init();
    Log.qs <- [];
    m1 <@ P(Log(RO)).p0();
    w1(m1);
    rs <@ suf();
    return rs;
  }
}.

(* the ideal game with the nonces sampled EARLY (same place as the real game) *)
module IdE (P : D) = {
  var r1 : nonce
  var c1 : cm
  var c2 : cm
  var r2 : nonce
  var t1 : key
  var t2 : key
  var bad1 : bool
  var n1 : int
  var n2 : int
  var bad2 : bool

  proc w1(m1 : msg1) : unit = {
    r1 <$ dn;
    t1 <- K1 (m1, r1);
    c1 <$ dcm;
    P(Log(RO)).p1(c1);
    n1 <- size Log.qs;
    bad1 <- t1 \in Log.qs;
    if (!bad1) { RO.m.[t1] <- c1; }
  }

  proc w2(m2 : msg2) : unit = {
    r2 <$ dn;
    t2 <- K2 (m2, r2);
    c2 <$ dcm;
    P(Log(RO)).p3(c2);
    n2 <- size Log.qs;
    bad2 <- t2 \in Log.qs;
    if (!bad2) { RO.m.[t2] <- c2; }
  }

  proc fin() : bool = {
    var rs : bool;
    rs <@ P(Log(RO)).p4(r2);
    return rs;
  }

  proc suf() : bool = {
    var m2 : msg2; var rs : bool;
    m2 <@ P(Log(RO)).p2(r1);
    w2(m2);
    rs <@ fin();
    return rs;
  }

  proc main() : bool = {
    var m1 : msg1; var rs : bool;
    bad1 <- false;
    bad2 <- false;
    RO.init();
    Log.qs <- [];
    m1 <@ P(Log(RO)).p0();
    w1(m1);
    rs <@ suf();
    return rs;
  }
}.

(* the ideal game with the nonces sampled LATE (at the reveal) *)
module Id (P : D) = {
  var r1 : nonce
  var m1g : msg1
  var m2g : msg2
  var c1 : cm
  var c2 : cm
  var r2 : nonce
  var t1 : key
  var t2 : key
  var bad1 : bool
  var n1 : int
  var n2 : int
  var bad2 : bool

  proc w1a() : unit = {
    c1 <$ dcm;
    P(Log(RO)).p1(c1);
  }

  proc w1b() : unit = {
    r1 <$ dn;
    t1 <- K1 (m1g, r1);
    n1 <- size Log.qs;
    bad1 <- t1 \in Log.qs;
    if (!bad1) { RO.m.[t1] <- c1; }
  }

  proc w1(m1 : msg1) : unit = {
    m1g <- m1;
    w1a();
    w1b();
  }

  proc w2a() : unit = {
    c2 <$ dcm;
    P(Log(RO)).p3(c2);
  }

  proc w2b() : unit = {
    r2 <$ dn;
    t2 <- K2 (m2g, r2);
    n2 <- size Log.qs;
    bad2 <- t2 \in Log.qs;
    if (!bad2) { RO.m.[t2] <- c2; }
  }

  proc w2(m2 : msg2) : unit = {
    m2g <- m2;
    w2a();
    w2b();
  }

  proc fin() : bool = {
    var rs : bool;
    rs <@ P(Log(RO)).p4(r2);
    return rs;
  }

  proc suf() : bool = {
    var m2 : msg2; var rs : bool;
    m2 <@ P(Log(RO)).p2(r1);
    w2(m2);
    rs <@ fin();
    return rs;
  }

  proc pre0() : unit = {
    bad1 <- false;
    bad2 <- false;
    RO.init();
    Log.qs <- [];
    m1g <@ P(Log(RO)).p0();
  }

  proc pref() : unit = {
    pre0();
    w1a();
  }

  proc main() : bool = {
    var rs : bool;
    pre0();
    w1(m1g);
    rs <@ suf();
    return rs;
  }

  proc pm() : unit = {
    m2g <@ P(Log(RO)).p2(r1);
    w2a();
  }

  proc prefB() : unit = {
    pref();
    w1b();
    pm();
  }

  proc mainC() : bool = {
    var rs : bool;
    prefB();
    w2b();
    rs <@ fin();
    return rs;
  }

  proc mainB() : bool = {
    var rs : bool;
    pref();
    w1b();
    rs <@ suf();
    return rs;
  }
}.


(* ------------------------------------------------------------------ *)
(* the environment view: honest commit/reveal steps as an abstract module *)

module type Env = {
  proc c1(m : msg1) : cm
  proc r1(qs : key list) : nonce
  proc c2(m : msg2) : cm
  proc r2(qs : key list) : nonce
}.

module RunEnv (P : D) (E : Env) = {
  proc main() : bool = {
    var m1 : msg1; var m2 : msg2; var c1 : cm; var c2 : cm; var r1 : nonce; var r2 : nonce; var rs : bool;
    RO.init();
    Log.qs <- [];
    m1 <@ P(Log(RO)).p0();
    c1 <@ E.c1(m1);
    P(Log(RO)).p1(c1);
    r1 <@ E.r1(Log.qs);
    m2 <@ P(Log(RO)).p2(r1);
    c2 <@ E.c2(m2);
    P(Log(RO)).p3(c2);
    r2 <@ E.r2(Log.qs);
    rs <@ P(Log(RO)).p4(r2);
    return rs;
  }
}.

(* real commitments: nonce first, commitment = oracle answer *)
module EReal : Env = {
  var nn1 : nonce
  var nn2 : nonce
  proc c1(m : msg1) : cm = {
    var c : cm;
    nn1 <$ dn;
    c <@ RO.o(K1 (m, nn1));
    return c;
  }
  proc r1(qs : key list) : nonce = { return nn1; }
  proc c2(m : msg2) : cm = {
    var c : cm;
    nn2 <$ dn;
    c <@ RO.o(K2 (m, nn2));
    return c;
  }
  proc r2(qs : key list) : nonce = { return nn2; }
}.

(* ideal commitments: random string first, nonce sampled at the reveal, oracle programmed there *)
module EId : Env = {
  var mm1 : msg1
  var mm2 : msg2
  var cc1 : cm
  var cc2 : cm
  var tt1 : key
  var tt2 : key
  var bb1 : bool
  var bb2 : bool
  var k1 : int
  var k2 : int
  proc c1(m : msg1) : cm = {
    mm1 <- m;
    cc1 <$ dcm;
    return cc1;
  }
  proc r1(qs : key list) : nonce = {
    var n : nonce;
    n <$ dn;
    tt1 <- K1 (mm1, n);
    k1 <- size qs;
    bb1 <- tt1 \in qs;
    if (!bb1) { RO.m.[tt1] <- cc1; }
    return n;
  }
  proc c2(m : msg2) : cm = {
    mm2 <- m;
    cc2 <$ dcm;
    return cc2;
  }
  proc r2(qs : key list) : nonce = {
    var n : nonce;
    n <$ dn;
    tt2 <- K2 (mm2, n);
    k2 <- size qs;
    bb2 <- tt2 \in qs;
    if (!bb2) { RO.m.[tt2] <- cc2; }
    return n;
  }
}.

section.
declare module P <: D {-RO, -Log, -Rl, -IdE, -Id, -EReal, -EId}.

declare axiom p0_ll (O <: Oracle {-P}) : islossless O.o => islossless P(O).p0.
declare axiom p1_ll (O <: Oracle {-P}) : islossless O.o => islossless P(O).p1.
declare axiom p2_ll (O <: Oracle {-P}) : islossless O.o => islossless P(O).p2.
declare axiom p3_ll (O <: Oracle {-P}) : islossless O.o => islossless P(O).p3.
declare axiom p4_ll (O <: Oracle {-P}) : islossless O.o => islossless P(O).p4.

local lemma Log_ll : islossless Log(RO).o.
proof. proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll). qed.

(* inclusion invariant: every entry of the map was queried (or is the programmed point t1) *)

local lemma w1_equiv :
  equiv [ Rl(P).w1 ~ IdE(P).w1 :
          ={m1, glob P, RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1}) ==>
          IdE.bad1{2} \/
          (={glob P, RO.m, Log.qs} /\ Rl.r1{1} = IdE.r1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1}
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1})) ].
proof.
proc; inline RO.o.
seq 2 2 : (={m1, glob P, RO.m, Log.qs} /\ Rl.r1{1} = IdE.r1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1}
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1})).
+ by wp; rnd; skip => />; smt(isK1_K1).
seq 3 1 : (IdE.t1{2} \in Log.qs{2} \/
           (={glob P, Log.qs} /\ Rl.c1{1} = IdE.c1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ Rl.r1{1} = IdE.r1{2}
            /\ (forall x, x <> IdE.t1{2} => RO.m{1}.[x] = RO.m{2}.[x])
            /\ RO.m{1}.[IdE.t1{2}] = Some Rl.c1{1}
            /\ (!(IdE.t1{2} \in Log.qs{2}) => !(IdE.t1{2} \in RO.m{2}))
            /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2}))).
+ sp; if{1}.
  - wp; rnd; skip => />; smt(mem_set get_setE).
  - wp; rnd{2}; skip => />; smt(dcm_ll).
seq 1 1 : (IdE.t1{2} \in Log.qs{2} \/
           (={glob P, Log.qs} /\ Rl.c1{1} = IdE.c1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ Rl.r1{1} = IdE.r1{2}
            /\ (forall x, x <> IdE.t1{2} => RO.m{1}.[x] = RO.m{2}.[x])
            /\ RO.m{1}.[IdE.t1{2}] = Some Rl.c1{1}
            /\ (!(IdE.t1{2} \in Log.qs{2}) => !(IdE.t1{2} \in RO.m{2}))
            /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2}))).
+ call (_ : (IdE.t1 \in Log.qs),
          (={Log.qs} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ Rl.r1{1} = IdE.r1{2} /\ Rl.c1{1} = IdE.c1{2}
           /\ (forall x, x <> IdE.t1{2} => RO.m{1}.[x] = RO.m{2}.[x])
           /\ RO.m{1}.[IdE.t1{2}] = Some Rl.c1{1}
           /\ (!(IdE.t1{2} \in Log.qs{2}) => !(IdE.t1{2} \in RO.m{2}))
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2}))).
  - by move=> O hO; exact (p1_ll O hO).
  - proc; inline *; sp.
    case (x{2} = IdE.t1{2}).
    * rcondf{1} 1; first by auto => />; smt().
      rcondt{2} 1; first by auto => />; smt().
      by wp; rnd{2}; skip => />; smt(dcm_ll).
    * if; first by smt().
      + by wp; rnd; skip => />; smt(mem_set get_setE).
      + by wp; skip => />; smt().
  - by move=> &2 _; exact Log_ll.
  - move=> _; proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll).
  - skip => &1 &2 hpre; split.
    * move=> hnb; case hpre => [hb | h]; first by smt().
      by smt().
    * by move=> *; smt().
wp; skip => /> &1 &2 hpre.
case hpre => [hb | h].
+ by smt().
case (IdE.t1{2} \in Log.qs{2}) => hb; first by smt().
have hm : RO.m{1} = RO.m{2}.[IdE.t1{2} <- IdE.c1{2}].
+ by apply fmap_eqP => x; rewrite get_setE; smt().
smt(isK1_K1).
qed.


local lemma w2_equiv :
  equiv [ Rl(P).w2 ~ IdE(P).w2 :
          ={m2, glob P, RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1})
          /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} ==>
          IdE.bad2{2} \/
          (={glob P, RO.m, Log.qs} /\ Rl.r2{1} = IdE.r2{2} /\ Rl.t2{1} = IdE.t2{2}) ].
proof.
proc; inline RO.o.
seq 2 2 : (={m2, glob P, RO.m, Log.qs} /\ Rl.r2{1} = IdE.r2{2} /\ Rl.t2{1} = IdE.t2{2}
           /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ !isK1 Rl.t2{1}
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1})).
+ by wp; rnd; skip => />; smt(isK1_K2).
seq 3 1 : (IdE.t2{2} \in Log.qs{2} \/
           (={glob P, Log.qs} /\ Rl.c2{1} = IdE.c2{2} /\ Rl.t2{1} = IdE.t2{2} /\ Rl.r2{1} = IdE.r2{2}
            /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ !isK1 Rl.t2{1}
            /\ (forall x, x <> IdE.t2{2} => RO.m{1}.[x] = RO.m{2}.[x])
            /\ RO.m{1}.[IdE.t2{2}] = Some Rl.c2{1}
            /\ (!(IdE.t2{2} \in Log.qs{2}) => !(IdE.t2{2} \in RO.m{2}))
            /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2} \/ x = IdE.t2{2}))).
+ sp; if{1}.
  - wp; rnd; skip => />; smt(mem_set get_setE).
  - wp; rnd{2}; skip => />; smt(dcm_ll).
seq 1 1 : (IdE.t2{2} \in Log.qs{2} \/
           (={glob P, Log.qs} /\ Rl.c2{1} = IdE.c2{2} /\ Rl.t2{1} = IdE.t2{2} /\ Rl.r2{1} = IdE.r2{2}
            /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ !isK1 Rl.t2{1}
            /\ (forall x, x <> IdE.t2{2} => RO.m{1}.[x] = RO.m{2}.[x])
            /\ RO.m{1}.[IdE.t2{2}] = Some Rl.c2{1}
            /\ (!(IdE.t2{2} \in Log.qs{2}) => !(IdE.t2{2} \in RO.m{2}))
            /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2} \/ x = IdE.t2{2}))).
+ call (_ : (IdE.t2 \in Log.qs),
          (={Log.qs} /\ Rl.t2{1} = IdE.t2{2} /\ Rl.r2{1} = IdE.r2{2} /\ Rl.c2{1} = IdE.c2{2}
           /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1} /\ !isK1 Rl.t2{1}
           /\ (forall x, x <> IdE.t2{2} => RO.m{1}.[x] = RO.m{2}.[x])
           /\ RO.m{1}.[IdE.t2{2}] = Some Rl.c2{1}
           /\ (!(IdE.t2{2} \in Log.qs{2}) => !(IdE.t2{2} \in RO.m{2}))
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = IdE.t1{2} \/ x = IdE.t2{2}))).
  - by move=> O hO; exact (p3_ll O hO).
  - proc; inline *; sp.
    case (x{2} = IdE.t2{2}).
    * rcondf{1} 1; first by auto => />; smt().
      rcondt{2} 1; first by auto => />; smt().
      by wp; rnd{2}; skip => />; smt(dcm_ll).
    * if; first by smt().
      + by wp; rnd; skip => />; smt(mem_set get_setE).
      + by wp; skip => />; smt().
  - by move=> &2 _; exact Log_ll.
  - move=> _; proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll).
  - skip => &1 &2 hpre; split.
    * move=> hnb; case hpre => [hb | h]; first by smt().
      by smt().
    * by move=> *; smt().
wp; skip => /> &1 &2 hpre.
case hpre => [hb | h].
+ by smt().
case (IdE.t2{2} \in Log.qs{2}) => hb; first by smt().
have hm : RO.m{1} = RO.m{2}.[IdE.t2{2} <- IdE.c2{2}].
+ by apply fmap_eqP => x; rewrite get_setE; smt().
smt().
qed.


local lemma RO_ll : islossless RO.o.
proof. proc; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll). qed.

local lemma Rl_w2_ll : islossless Rl(P).w2.
proof.
proc.
call (p3_ll (Log(RO)) Log_ll).
call RO_ll.
wp; rnd; skip => />; smt(dn_ll).
qed.

local lemma IdE_w2_ll : islossless IdE(P).w2.
proof.
proc.
wp.
call (p3_ll (Log(RO)) Log_ll).
wp; rnd; wp; rnd; skip => />; smt(dn_ll dcm_ll).
qed.

local lemma Rl_fin_ll : islossless Rl(P).fin.
proof. by proc; call (p4_ll (Log(RO)) Log_ll). qed.

local lemma IdE_fin_ll : islossless IdE(P).fin.
proof. by proc; call (p4_ll (Log(RO)) Log_ll). qed.

local lemma Rl_suf_ll : islossless Rl(P).suf.
proof. proc; call Rl_fin_ll; call Rl_w2_ll; call (p2_ll (Log(RO)) Log_ll); auto. qed.

local lemma IdE_suf_ll : islossless IdE(P).suf.
proof. proc; call IdE_fin_ll; call IdE_w2_ll; call (p2_ll (Log(RO)) Log_ll); auto. qed.

local lemma IdE_w2_bad1 : hoare [ IdE(P).w2 : IdE.bad1 ==> IdE.bad1 ].
proof. proc; wp; call (_ : true); auto. qed.


local lemma IdE_fin_bad : hoare [ IdE(P).fin : IdE.bad1 ==> IdE.bad1 ].
proof. proc; call (_ : true); auto. qed.

local lemma IdE_suf_bad1 : hoare [ IdE(P).suf : IdE.bad1 ==> IdE.bad1 ].
proof. proc; call IdE_fin_bad; call IdE_w2_bad1; call (_ : true); auto. qed.

local lemma IdE_suf_ph : phoare [ IdE(P).suf : IdE.bad1 ==> IdE.bad1 ] = 1%r.
proof. by conseq IdE_suf_ll IdE_suf_bad1. qed.

local lemma fin_equiv :
  equiv [ Rl(P).fin ~ IdE(P).fin :
          IdE.bad2{2} \/ (={glob P, RO.m, Log.qs} /\ Rl.r2{1} = IdE.r2{2}) ==>
          IdE.bad2{2} \/ res{1} = res{2} ].
proof.
proc.
case (IdE.bad2{2}).
+ call{1} (p4_ll (Log(RO)) Log_ll).
  call{2} (p4_ll (Log(RO)) Log_ll).
  by skip; smt().
call (_ : ={RO.m, Log.qs}).
+ by sim.
by skip; smt().
qed.

local lemma suf_equiv_nb :
  equiv [ Rl(P).suf ~ IdE(P).suf :
          ={glob P, RO.m, Log.qs} /\ Rl.r1{1} = IdE.r1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1}
          /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1}) ==>
          IdE.bad2{2} \/ res{1} = res{2} ].
proof.
proc.
call fin_equiv.
call w2_equiv.
call (_ : ={RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1})).
+ proc; inline *; sp; if; first by smt().
  - auto => />; smt(mem_set).
  - auto => />; smt().
skip => /> &1 &2; smt().
qed.

local lemma main_equiv :
  equiv [ Rl(P).main ~ IdE(P).main :
          ={glob P} ==> res{1} = res{2} \/ IdE.bad1{2} \/ IdE.bad2{2} ].
proof.
proc.
inline RO.init.
seq 4 6 : (IdE.bad1{2} \/
           (={glob P, RO.m, Log.qs} /\ Rl.r1{1} = IdE.r1{2} /\ Rl.t1{1} = IdE.t1{2} /\ isK1 Rl.t1{1}
            /\ (forall x, x \in RO.m{1} => x \in Log.qs{1} \/ x = Rl.t1{1}))).
+ call w1_equiv.
  call (_ : ={RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1})).
  - proc; inline *; sp; if; first by smt().
    * auto => />; smt(mem_set).
    * auto => />; smt().
  wp; skip => />; smt(mem_empty).
case (IdE.bad1{2}).
+ call{1} Rl_suf_ll.
  call{2} IdE_suf_ph.
  by skip => />.
call suf_equiv_nb.
by skip => />; smt().
qed.


(* IdE ~ Id : the nonce is only used by the reveal, so it can be sampled late *)
local lemma w1_swap :
  equiv [ IdE(P).w1 ~ Id(P).w1 :
          ={m1, glob P, RO.m, Log.qs} ==>
          ={glob P, RO.m, Log.qs} /\ IdE.r1{1} = Id.r1{2} /\ IdE.t1{1} = Id.t1{2}
          /\ IdE.bad1{1} = Id.bad1{2} /\ IdE.n1{1} = Id.n1{2} ].
proof.
proc; inline Id(P).w1 Id(P).w1a Id(P).w1b.
sp.
swap{1} [1..2] 2.
wp.
rnd.
wp.
call (_ : ={RO.m, Log.qs}).
+ by sim.
by rnd; skip => />.
qed.

local lemma w2_swap :
  equiv [ IdE(P).w2 ~ Id(P).w2 :
          ={m2, glob P, RO.m, Log.qs} ==>
          ={glob P, RO.m, Log.qs} /\ IdE.r2{1} = Id.r2{2} /\ IdE.t2{1} = Id.t2{2}
          /\ IdE.bad2{1} = Id.bad2{2} /\ IdE.n2{1} = Id.n2{2} ].
proof.
proc; inline Id(P).w2 Id(P).w2a Id(P).w2b.
sp.
swap{1} [1..2] 2.
wp.
rnd.
wp.
call (_ : ={RO.m, Log.qs}).
+ by sim.
by rnd; skip => />.
qed.

local lemma main_swap :
  equiv [ IdE(P).main ~ Id(P).main : ={glob P} ==>
          res{1} = res{2} /\ IdE.bad1{1} = Id.bad1{2} /\ IdE.bad2{1} = Id.bad2{2}
          /\ IdE.n1{1} = Id.n1{2} /\ IdE.n2{1} = Id.n2{2} ].
proof.
proc.
inline RO.init Id(P).pre0.
call (_ : ={glob P, RO.m, Log.qs} /\ IdE.r1{1} = Id.r1{2} /\ IdE.bad1{1} = Id.bad1{2} /\ IdE.n1{1} = Id.n1{2}
          ==> ={res, glob P, RO.m, Log.qs} /\ IdE.bad1{1} = Id.bad1{2} /\ IdE.bad2{1} = Id.bad2{2}
              /\ IdE.n1{1} = Id.n1{2} /\ IdE.n2{1} = Id.n2{2}).
+ proc.
  call (_ : ={glob P, RO.m, Log.qs} /\ IdE.r2{1} = Id.r2{2} ==> ={res, glob P, RO.m, Log.qs}).
  - proc; call (_ : ={RO.m, Log.qs}); first by sim.
    by skip => />.
  call (w2_swap).
  call (_ : ={RO.m, Log.qs}).
  - by sim.
  skip => /> &1 &2; smt().
call w1_swap.
wp.
call (_ : ={RO.m, Log.qs}).
+ by sim.
wp; skip => />.
qed.


(* ------------------------------------------------------------------ *)
(* the bad events of the ideal game have probability at most q * pmax   *)

declare op q : int.
declare axiom q_ge0 : 0 <= q.
declare axiom P_queries : forall &m, Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)] <= 0%r.

local lemma Id_w1a_ll : islossless Id(P).w1a.
proof. proc; call (p1_ll (Log(RO)) Log_ll); rnd; skip => />; smt(dcm_ll). qed.

local lemma Id_w2a_ll : islossless Id(P).w2a.
proof. proc; call (p3_ll (Log(RO)) Log_ll); rnd; skip => />; smt(dcm_ll). qed.

local lemma Id_w1b_ll : islossless Id(P).w1b.
proof. proc; wp; rnd; skip => />; smt(dn_ll). qed.

local lemma Id_w2b_ll : islossless Id(P).w2b.
proof. proc; wp; rnd; skip => />; smt(dn_ll). qed.

local lemma Id_w1_ll : islossless Id(P).w1.
proof. proc; call Id_w1b_ll; call Id_w1a_ll; by wp; skip. qed.

local lemma Id_fin_ll : islossless Id(P).fin.
proof. by proc; call (p4_ll (Log(RO)) Log_ll). qed.

local lemma Id_suf_ll : islossless Id(P).suf.
proof.
proc.
call Id_fin_ll.
inline Id(P).w2.
call Id_w2b_ll.
call Id_w2a_ll.
wp.
call (p2_ll (Log(RO)) Log_ll).
by skip.
qed.

local lemma Id_suf_keep1 : hoare [ Id(P).suf : Id.bad1 /\ Id.n1 <= q ==> Id.bad1 /\ Id.n1 <= q ].
proof.
proc; inline Id(P).fin Id(P).w2 Id(P).w2a Id(P).w2b.
wp.
call (_ : true); first by proc; inline *; auto.
wp.
rnd.
wp.
call (_ : true); first by proc; inline *; auto.
rnd.
wp.
call (_ : true); first by proc; inline *; auto.
by skip.
qed.


local lemma Id_suf_keep1n : hoare [ Id(P).suf : !(Id.bad1 /\ Id.n1 <= q) ==> !(Id.bad1 /\ Id.n1 <= q) ].
proof.
proc; inline Id(P).fin Id(P).w2 Id(P).w2a Id(P).w2b.
wp.
call (_ : true); first by proc; inline *; auto.
wp.
rnd.
wp.
call (_ : true); first by proc; inline *; auto.
rnd.
wp.
call (_ : true); first by proc; inline *; auto.
by skip.
qed.

local lemma Id_suf_ph1 : phoare [ Id(P).suf : Id.bad1 /\ Id.n1 <= q ==> Id.bad1 /\ Id.n1 <= q ] = 1%r.
proof. by conseq Id_suf_ll Id_suf_keep1. qed.

local lemma Id_suf_le1 : phoare [ Id(P).suf : Id.bad1 /\ Id.n1 <= q ==> Id.bad1 /\ Id.n1 <= q ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma P_p0_le1 : phoare [ P(Log(RO)).p0 : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma Id_w1a_le1 : phoare [ Id(P).w1a : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma Id_pref_le1 : phoare [ Id(P).pref : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma Id_main_B :
  equiv [ Id(P).main ~ Id(P).mainB : ={glob P} ==> ={res, Id.bad1, Id.n1, Id.bad2, Id.n2} ].
proof. by proc; inline Id(P).w1 Id(P).pref; sim. qed.

local lemma id_bad1_aux &m :
  Pr[Id(P).mainB() @ &m : Id.bad1 /\ Id.n1 <= q] <= q%r * pmax.
proof.
byphoare (_ : true ==> Id.bad1 /\ Id.n1 <= q) => //.
proc.
seq 2 : (Id.bad1 /\ Id.n1 <= q) (q%r * pmax) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ inline Id(P).w1b.
  seq 1 : true 1%r (q%r * pmax) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call Id_pref_le1.
  - wp; rnd (fun r => K1 (Id.m1g, r) \in Log.qs /\ size Log.qs <= q).
    wp; skip => &hr _ /=.
    case (size Log.qs{hr} <= q) => hs.
    * apply (ler_trans ((size Log.qs{hr})%r * pmax)).
      + apply (ler_trans (mu dn (fun r => K1 (Id.m1g{hr}, r) \in Log.qs{hr}))); last exact (mu_hit1 Id.m1g{hr} Log.qs{hr}).
        by apply mu_sub => r /=; smt().
      by apply ler_wpmul2r; [exact pmax_ge0 | smt()].
    * apply (ler_trans (mu dn pred0)).
      + by apply mu_sub => r /=; rewrite /pred0; smt().
      by rewrite mu0; smt(pmax_ge0 q_ge0).
    by move=> _; apply mulr_ge0; [smt(q_ge0) | exact pmax_ge0].
  - by hoare; auto => />.
  - by auto.
+ by call Id_suf_le1.
+ by hoare; call Id_suf_keep1n; skip => />.
smt().
qed.


local lemma Id_prefB_le1 : phoare [ Id(P).prefB : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma Id_w1b_le1 : phoare [ Id(P).w1b : true ==> true ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma Id_main_C :
  equiv [ Id(P).main ~ Id(P).mainC : ={glob P} ==> ={res, Id.bad1, Id.n1, Id.bad2, Id.n2} ].
proof. by proc; inline Id(P).w1 Id(P).pref Id(P).suf Id(P).w2 Id(P).pm Id(P).prefB; sim. qed.

local lemma Id_fin_keep2 : hoare [ Id(P).fin : Id.bad2 /\ Id.n2 <= q ==> Id.bad2 /\ Id.n2 <= q ].
proof. proc; call (_ : true); first by proc; inline *; auto. by skip. qed.

local lemma Id_fin_keep2n : hoare [ Id(P).fin : !(Id.bad2 /\ Id.n2 <= q) ==> !(Id.bad2 /\ Id.n2 <= q) ].
proof. proc; call (_ : true); first by proc; inline *; auto. by skip. qed.

local lemma Id_fin_ph2 : phoare [ Id(P).fin : Id.bad2 /\ Id.n2 <= q ==> Id.bad2 /\ Id.n2 <= q ] = 1%r.
proof. by conseq Id_fin_ll Id_fin_keep2. qed.

local lemma Id_fin_le2 : phoare [ Id(P).fin : Id.bad2 /\ Id.n2 <= q ==> Id.bad2 /\ Id.n2 <= q ] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma id_bad2_aux &m :
  Pr[Id(P).mainC() @ &m : Id.bad2 /\ Id.n2 <= q] <= q%r * pmax.
proof.
byphoare (_ : true ==> Id.bad2 /\ Id.n2 <= q) => //.
proc.
seq 2 : (Id.bad2 /\ Id.n2 <= q) (q%r * pmax) 1%r 1%r 0%r.
+ by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
+ inline Id(P).w2b.
  seq 1 : true 1%r (q%r * pmax) 0%r 1%r.
  - by (conseq (_ : _ ==> true) || (hoare; auto) || auto || smt()).
  - by call Id_prefB_le1.
  - wp; rnd (fun r => K2 (Id.m2g, r) \in Log.qs /\ size Log.qs <= q).
    wp; skip => &hr _ /=.
    case (size Log.qs{hr} <= q) => hs.
    * apply (ler_trans ((size Log.qs{hr})%r * pmax)).
      + apply (ler_trans (mu dn (fun r => K2 (Id.m2g{hr}, r) \in Log.qs{hr}))); last exact (mu_hit2 Id.m2g{hr} Log.qs{hr}).
        by apply mu_sub => r /=; smt().
      by apply ler_wpmul2r; [exact pmax_ge0 | smt()].
    * apply (ler_trans (mu dn pred0)).
      + by apply mu_sub => r /=; rewrite /pred0; smt().
      by rewrite mu0; smt(pmax_ge0 q_ge0).
    by move=> _; apply mulr_ge0; [smt(q_ge0) | exact pmax_ge0].
  - by hoare; auto => />.
  - by auto.
+ by call Id_fin_le2.
+ by hoare; call Id_fin_keep2n; skip => />.
smt().
qed.


local lemma q_fail &m :
  Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)] <= 0%r.
proof. exact (P_queries &m). qed.

local lemma id_bad1 &m : Pr[Id(P).main() @ &m : Id.bad1] <= q%r * pmax.
proof.
have h0 := q_fail &m.
have e : Pr[Id(P).main() @ &m : Id.bad1 /\ Id.n1 <= q] = Pr[Id(P).mainB() @ &m : Id.bad1 /\ Id.n1 <= q].
+ by byequiv Id_main_B => //; smt().
have h1 := id_bad1_aux &m.
have h2 : Pr[Id(P).main() @ &m : Id.bad1]
          <= Pr[Id(P).main() @ &m : Id.bad1 /\ Id.n1 <= q] + Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)].
+ rewrite Pr[mu_split Id.n1 <= q].
  have : Pr[Id(P).main() @ &m : Id.bad1 /\ !(Id.n1 <= q)] <= Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)].
  - by rewrite Pr[mu_sub]; smt().
  smt().
smt(ge0_mu).
qed.

local lemma id_bad2 &m : Pr[Id(P).main() @ &m : Id.bad2] <= q%r * pmax.
proof.
have h0 := q_fail &m.
have e : Pr[Id(P).main() @ &m : Id.bad2 /\ Id.n2 <= q] = Pr[Id(P).mainC() @ &m : Id.bad2 /\ Id.n2 <= q].
+ by byequiv Id_main_C => //; smt().
have h1 := id_bad2_aux &m.
have h2 : Pr[Id(P).main() @ &m : Id.bad2]
          <= Pr[Id(P).main() @ &m : Id.bad2 /\ Id.n2 <= q] + Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)].
+ rewrite Pr[mu_split Id.n2 <= q].
  have : Pr[Id(P).main() @ &m : Id.bad2 /\ !(Id.n2 <= q)] <= Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)].
  - by rewrite Pr[mu_sub]; smt().
  smt().
smt(ge0_mu).
qed.

(* THE THEOREM: a real protocol run is no likelier to output `true` than the ideal run, up to 2 q pmax *)
lemma twin_hide_le &m :
  Pr[Rl(P).main() @ &m : res] <= Pr[Id(P).main() @ &m : res] + 2%r * (q%r * pmax).
proof.
have h1 : Pr[Rl(P).main() @ &m : res] <= Pr[IdE(P).main() @ &m : res \/ IdE.bad1 \/ IdE.bad2].
+ by byequiv main_equiv => //; smt().
have h2 : Pr[IdE(P).main() @ &m : res \/ IdE.bad1 \/ IdE.bad2] = Pr[Id(P).main() @ &m : res \/ Id.bad1 \/ Id.bad2].
+ by byequiv main_swap => //; smt().
have h3 : Pr[Id(P).main() @ &m : res \/ Id.bad1 \/ Id.bad2]
          <= Pr[Id(P).main() @ &m : res] + Pr[Id(P).main() @ &m : Id.bad1] + Pr[Id(P).main() @ &m : Id.bad2].
+ have a : Pr[Id(P).main() @ &m : res \/ (Id.bad1 \/ Id.bad2)]
            <= Pr[Id(P).main() @ &m : res] + Pr[Id(P).main() @ &m : Id.bad1 \/ Id.bad2].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  have b : Pr[Id(P).main() @ &m : Id.bad1 \/ Id.bad2]
            <= Pr[Id(P).main() @ &m : Id.bad1] + Pr[Id(P).main() @ &m : Id.bad2].
  - by rewrite Pr[mu_or]; smt(mu_bounded).
  smt().
have := id_bad1 &m; have := id_bad2 &m; smt().
qed.

end section.


section QueryBounds.
declare module P <: D {-RO, -Log, -Rl, -IdE, -Id, -EReal, -EId}.
declare op q : int.
(* P makes at most q queries, whatever the environment does between its calls *)
declare axiom Q_env (E <: Env {-P, -Log}) : hoare [ RunEnv(P, E).main : true ==> size Log.qs <= q ].

local lemma ro_refl : equiv [ RO.o ~ RO.o : ={x, RO.m} ==> ={res, RO.m} ].
proof. by sim. qed.

local lemma rl_env :
  equiv [ Rl(P).main ~ RunEnv(P, EReal).main : ={glob P, RO.m, Log.qs} ==> ={res, Log.qs} ].
proof.
proc.
inline Rl(P).w1 Rl(P).suf Rl(P).w2 Rl(P).fin EReal.c1 EReal.r1 EReal.c2 EReal.r2.
wp.
call (_ : ={RO.m, Log.qs}); first by sim.
wp.
call (_ : ={RO.m, Log.qs}); first by sim.
wp.
call ro_refl.
wp; rnd; wp.
call (_ : ={RO.m, Log.qs}); first by sim.
wp.
call (_ : ={RO.m, Log.qs}); first by sim.
wp.
call ro_refl.
wp; rnd; wp.
call (_ : ={RO.m, Log.qs}); first by sim.
inline RO.init; wp; skip => />.
qed.

local lemma id_env :
  equiv [ Id(P).main ~ RunEnv(P, EId).main : ={glob P, RO.m, Log.qs} ==>
          ={res, Log.qs} /\ Id.n1{1} = EId.k1{2} /\ Id.n2{1} = EId.k2{2} ].
proof.
proc.
inline Id(P).pre0 Id(P).w1 Id(P).w1a Id(P).w1b Id(P).suf Id(P).w2 Id(P).w2a Id(P).w2b Id(P).fin
       EId.c1 EId.r1 EId.c2 EId.r2.
sim.
qed.

local lemma er1_k (ql : key list) : hoare [ EId.r1 : qs = ql ==> EId.k1 = size ql ].
proof. by proc; wp; rnd; wp; skip => />. qed.

local lemma er2_k (ql : key list) : hoare [ EId.r2 : qs = ql ==> EId.k2 = size ql ].
proof. by proc; wp; rnd; wp; skip => />. qed.

local lemma ec1_t : hoare [ EId.c1 : true ==> true ].
proof. by proc; auto. qed.

local lemma ec2_k : hoare [ EId.c2 : EId.k1 <= size Log.qs ==> EId.k1 <= size Log.qs ].
proof. by proc; auto. qed.

local lemma er2_k1 : hoare [ EId.r2 : EId.k1 <= size Log.qs ==> EId.k1 <= size Log.qs ].
proof. by proc; wp; rnd; wp; skip => />; smt(). qed.

local lemma log_mono1 : hoare [ Log(RO).o : EId.k1 <= size Log.qs ==> EId.k1 <= size Log.qs ].
proof. proc; inline RO.o; sp; wp; if; auto => />; smt(). qed.

local lemma log_mono2 : hoare [ Log(RO).o : EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs ==> EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs ].
proof. proc; inline RO.o; sp; wp; if; auto => />; smt(). qed.

local lemma er2_k2 (ql : key list) :
  hoare [ EId.r2 : qs = ql /\ EId.k1 <= size ql ==> EId.k2 = size ql /\ EId.k1 <= size ql ].
proof. by proc; wp; rnd; wp; skip => />. qed.

local lemma id_mono :
  hoare [ RunEnv(P, EId).main : true ==> EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs ].
proof.
proc.
seq 5 : true.
+ call (_ : true); first by proc; inline *; auto.
  call ec1_t.
  call (_ : true); first by proc; inline *; auto.
  inline RO.init; wp; skip => />.
seq 1 : (EId.k1 <= size Log.qs).
+ exists* Log.qs; elim* => ql.
  call (er1_k ql).
  skip => />.
seq 3 : (EId.k1 <= size Log.qs).
+ call (_ : EId.k1 <= size Log.qs); first by exact log_mono1.
  call ec2_k.
  call (_ : EId.k1 <= size Log.qs); first by exact log_mono1.
  skip => />.
seq 1 : (EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs).
+ exists* Log.qs; elim* => ql.
  call (er2_k2 ql).
  skip => />.
call (_ : EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs); first by exact log_mono2.
skip => />.
qed.

lemma queries_ok &m :
  Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)] <= 0%r.
proof.
have e : Pr[Id(P).main() @ &m : !(Id.n1 <= q /\ Id.n2 <= q)]
         = Pr[RunEnv(P, EId).main() @ &m : !(EId.k1 <= q /\ EId.k2 <= q)].
+ by byequiv id_env => //; smt().
have h1 : Pr[RunEnv(P, EId).main() @ &m : !(size Log.qs <= q)] <= 0%r.
+ byphoare (_ : true ==> !(size Log.qs <= q)) => //.
  hoare.
  by conseq (Q_env EId) => /> *; smt().
have h2 : Pr[RunEnv(P, EId).main() @ &m : !(EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs)] <= 0%r.
+ byphoare (_ : true ==> !(EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs)) => //.
  hoare.
  by conseq id_mono => /> *; smt().
have h3 : Pr[RunEnv(P, EId).main() @ &m : !(EId.k1 <= q /\ EId.k2 <= q)]
          <= Pr[RunEnv(P, EId).main() @ &m : !(size Log.qs <= q) \/ !(EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs)].
+ by rewrite Pr[mu_sub]; smt().
have h4 : Pr[RunEnv(P, EId).main() @ &m : !(size Log.qs <= q) \/ !(EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs)]
          <= Pr[RunEnv(P, EId).main() @ &m : !(size Log.qs <= q)]
             + Pr[RunEnv(P, EId).main() @ &m : !(EId.k1 <= size Log.qs /\ EId.k2 <= size Log.qs)].
+ by rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

lemma real_size_ok &m : Pr[Rl(P).main() @ &m : !(size Log.qs <= q)] <= 0%r.
proof.
have e : Pr[Rl(P).main() @ &m : !(size Log.qs <= q)] = Pr[RunEnv(P, EReal).main() @ &m : !(size Log.qs <= q)].
+ by byequiv rl_env => //; smt().
rewrite e.
byphoare (_ : true ==> !(size Log.qs <= q)) => //.
hoare.
by conseq (Q_env EReal) => /> *; smt().
qed.

lemma fsize_bound (m : (key, cm) fmap) (l : key list) (a b : key) :
  (forall x, x \in m => x \in l \/ x = a \/ x = b) => fsize m <= size l + 2.
proof.
move=> h.
have hs : fdom m \subset oflist (a :: b :: l).
+ apply/subsetP => x; rewrite mem_fdom mem_oflist /=; smt().
have := subset_leq_fcard _ _ hs.
have := fcard_oflist (a :: b :: l).
rewrite /fsize; smt().
qed.

lemma log_dom1 : hoare [ Log(RO).o : (forall x, x \in RO.m => x \in Log.qs) ==> (forall x, x \in RO.m => x \in Log.qs) ].
proof. proc; inline RO.o; sp; wp; if; auto => />; smt(mem_set). qed.

lemma log_dom2 : hoare [ Log(RO).o : (forall x, x \in RO.m => x \in Log.qs \/ x = Rl.t1) ==> (forall x, x \in RO.m => x \in Log.qs \/ x = Rl.t1) ].
proof. proc; inline RO.o; sp; wp; if; auto => />; smt(mem_set). qed.

lemma log_dom3 : hoare [ Log(RO).o : (forall x, x \in RO.m => x \in Log.qs \/ x = Rl.t1 \/ x = Rl.t2) ==> (forall x, x \in RO.m => x \in Log.qs \/ x = Rl.t1 \/ x = Rl.t2) ].
proof. proc; inline RO.o; sp; wp; if; auto => />; smt(mem_set). qed.

lemma ro_dom1 (k : key) :
  hoare [ RO.o : (forall z, z \in RO.m => z \in Log.qs) /\ x = k ==>
          forall z, z \in RO.m => z \in Log.qs \/ z = k ].
proof. by proc; sp; if; auto => />; smt(mem_set). qed.

lemma ro_dom2 (k a : key) :
  hoare [ RO.o : (forall z, z \in RO.m => z \in Log.qs \/ z = a) /\ x = k ==>
          forall z, z \in RO.m => z \in Log.qs \/ z = a \/ z = k ].
proof. by proc; sp; if; auto => />; smt(mem_set). qed.

lemma real_dom :
  hoare [ Rl(P).main : true ==> forall x, x \in RO.m => x \in Log.qs \/ x = Rl.t1 \/ x = Rl.t2 ].
proof.
proc.
inline Rl(P).suf Rl(P).fin Rl(P).w2 Rl(P).w1.
seq 3 : (forall z, z \in RO.m => z \in Log.qs).
+ call (_ : forall z, z \in RO.m => z \in Log.qs); first by exact log_dom1.
  inline RO.init; wp; skip => />; smt(mem_empty).
seq 3 : ((forall z, z \in RO.m => z \in Log.qs)).
+ wp; rnd; wp; skip => />.
exists* Rl.t1; elim* => k.
seq 2 : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1).
+ call (_ : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1)); first by exact log_dom2.
  call (ro_dom1 k).
  skip => />.
seq 4 : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1).
+ wp; rnd; wp.
  call (_ : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1)); first by exact log_dom2.
  skip => />.
exists* Rl.t1, Rl.t2; elim* => a k2.
seq 2 : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1 \/ z = Rl.t2).
+ call (_ : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1 \/ z = Rl.t2)); first by exact log_dom3.
  call (ro_dom2 k2 a).
  skip => />.
wp.
call (_ : (forall z, z \in RO.m => z \in Log.qs \/ z = Rl.t1 \/ z = Rl.t2)); first by exact log_dom3.
skip => />.
qed.

end section QueryBounds.

end TW.

