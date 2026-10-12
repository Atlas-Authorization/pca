(* PcaCommitROM.ec -- HIDING OF THE HASH COMMITMENT IN THE RANDOM-ORACLE MODEL, with an explicit bound.

   The commitments of the MPC commit-reveal (packages/pca-mpc/src/net/protocol.ts) are
        coin :  C = SHA-256('seed'  || sid || label || id || seed)         (the 32-byte seed is the secret)
        sigma:  C = SHA-256('sigma' || sid || id || sigmas || nonce)        (32-byte random nonce)
   i.e. C = H(m || r) with a fresh high-entropy `r` (for the coin the seed itself plays the role of r).

   MODEL.  H is a random oracle (lazily sampled, answers from `dcm`); the commitment of m under
   randomness r is  com(m;r) = H(m, r).  The randomness is drawn from `dn`; the only property used is
   its MIN-ENTROPY:  mu1 dn r <= pmax  for every r  (pmax = 2^-256 for a uniform 32-byte value).

   WHAT IS PROVED (no unproved step, no cryptographic axiom; the only assumptions are the structural ones listed
   below and the query bound on the adversary).

     hide_real_le_ideal / hide_ideal_le_real
                      Pr[Real_b : res]  <=  Pr[Ideal : res] + q*pmax  and the symmetric inequality,
                      for EVERY adversary: Real_b hands the adversary c = H(m_b, r); Ideal hands it an
                      independent c <- dcm.  `bad` is "the adversary queried H at (m_b, r)".
     (inside)         if the adversary makes at most q oracle queries, Pr[Ideal : bad] <= q * pmax.
     hide_rom         |Pr[Real_0 : res] - Pr[Real_1 : res]|  <=  2 * q * pmax            (= q / 2^255 for 32 bytes)

   In words: to learn ANYTHING about which message was committed, the adversary has to query H at the
   committed value together with the randomness; with a 256-bit r that costs 2^-256 per query.
   The advantage is statistical in the oracle (it does not depend on the adversary's time, only on the
   number of its queries).

   HOW THIS REPLACES THE IDEAL-HIDING ASSUMPTION OF PcaSpdzProto.ec.  PcaSpdzProto.ec computes the honest
   commitment strings from a dummy message (`comS seed0 nonce`, `comG g00 nonce`), i.e. it assumes the
   adversary's view is independent of the committed honest value.  The real game differs only in these two
   strings.  For each of the two strings there is a hiding adversary B (explicit in the doc,
   computational-proofs.md section 5, "hiding reduction"): B samples all the honest randomness except the
   commitment randomness itself, chooses m0 = the dummy value and m1 = the real honest value, forwards the
   challenge string to the protocol adversary's COMMIT step (which is all that is run), and outputs the
   verdict of the committed-value event `winC` (a deterministic function of what the adversary committed
   to and of the honest randomness B knows).  By `hide_rom` the probability of that event changes by at
   most q * pmax per string between the real and the dummy-commitment game, where q counts the oracle
   queries of the protocol adversary's commit step (plus the O(1) queries of B).  Binding is unchanged.

   ASSUMPTIONS (structural): `dcm_ll` (the oracle answers are a proper distribution), `pmax_ge0`,
   `dn_ll`, `dn_pmax` (min-entropy of the commitment randomness).
   *)
require import AllCore Int Real List Distr FMap StdOrder.
import RealOrder.

type msg.
type nonce.
type cm.
type pt = msg * nonce.

op dn  : nonce distr.        (* distribution of the commitment randomness (32 uniform bytes in the code) *)
op dcm : cm distr.           (* distribution of the oracle's answers (uniform 256-bit strings)          *)
op pmax : real.              (* min-entropy bound:  every randomness value has probability <= pmax        *)

axiom dn_ll : is_lossless dn.
axiom dcm_ll : is_lossless dcm.
axiom pmax_ge0 : 0%r <= pmax.
axiom dn_pmax (r : nonce) : mu1 dn r <= pmax.

(* ------------------------------------------------------------------ *)
(* probability of hitting a logged point                                *)

lemma mu_hit (m : msg) (l : pt list) :
  mu dn (fun r => (m, r) \in l) <= (size l)%r * pmax.
proof.
elim: l => [|x l ih].
+ by rewrite /= mu0_false //; smt(pmax_ge0).
have h1 : mu dn (fun r => x = (m, r)) <= pmax.
+ apply (ler_trans (mu dn (pred1 x.`2))).
  - by apply mu_sub => r /= h; rewrite /pred1; rewrite h /=.
  exact (dn_pmax x.`2).
have h2 : mu dn (fun r => (m, r) \in x :: l)
          <= mu dn (fun r => x = (m, r)) + mu dn (fun r => (m, r) \in l).
+ apply (ler_trans (mu dn (predU (fun r => x = (m, r)) (fun r => (m, r) \in l)))).
  - by apply mu_sub => r /=; rewrite /predU; smt().
  by rewrite mu_or; smt(ge0_mu).
have hs : (size (x :: l))%r = 1%r + (size l)%r by smt(size_ge0).
rewrite hs; smt(pmax_ge0).
qed.

(* ------------------------------------------------------------------ *)
(* the random oracle, a logging wrapper, and the games                  *)

module type Oracle = { proc o(x : pt) : cm }.

module RO : Oracle = {
  var m : (pt, cm) fmap
  proc init() : unit = { m <- empty; }
  proc o(x : pt) : cm = {
    var y : cm;
    if (x \notin m) {
      y <$ dcm;
      m.[x] <- y;
    }
    return oget m.[x];
  }
}.

module Log (O : Oracle) : Oracle = {
  var qs : pt list
  proc o(x : pt) : cm = {
    var y : cm;
    qs <- x :: qs;
    y <@ O.o(x);
    return y;
  }
}.

(* a two-stage adversary: choose two messages, then, given the commitment string, guess a bit *)
module type Adv (O : Oracle) = {
  proc choose() : msg * msg { O.o }
  proc guess(c : cm) : bool { O.o }
}.

module HReal (A : Adv) = {
  var tgt : pt
  proc main(b : bool) : bool = {
    var m0 : msg; var m1 : msg; var r : nonce; var c : cm; var b' : bool;
    RO.init();
    Log.qs <- [];
    (m0, m1) <@ A(Log(RO)).choose();
    r <$ dn;
    tgt <- ((if b then m1 else m0), r);
    c <@ RO.o(tgt);
    b' <@ A(Log(RO)).guess(c);
    return b';
  }
}.

module HIdeal (A : Adv) = {
  var tgt : pt
  var bad : bool
  proc main(b : bool) : bool = {
    var m0 : msg; var m1 : msg; var r : nonce; var c : cm; var b' : bool;
    RO.init();
    Log.qs <- [];
    (m0, m1) <@ A(Log(RO)).choose();
    r <$ dn;
    tgt <- ((if b then m1 else m0), r);
    c <$ dcm;
    b' <@ A(Log(RO)).guess(c);
    bad <- tgt \in Log.qs;
    return b';
  }
}.

(* the same game with the commitment randomness sampled after the adversary has finished: it is only
   used by `bad`, so this is the same experiment; here the bound on Pr[bad] is a one-liner *)
module HLate (A : Adv) = {
  var mb : msg
  var bad : bool
  proc pre(b : bool) : bool = {
    var m0 : msg; var m1 : msg; var c : cm; var b' : bool;
    RO.init();
    Log.qs <- [];
    (m0, m1) <@ A(Log(RO)).choose();
    mb <- (if b then m1 else m0);
    c <$ dcm;
    b' <@ A(Log(RO)).guess(c);
    return b';
  }
  proc main(b : bool) : bool = {
    var r : nonce; var b' : bool;
    b' <@ pre(b);
    r <$ dn;
    bad <- (mb, r) \in Log.qs;
    return b';
  }
}.

section.
declare module A <: Adv {-RO, -Log, -HReal, -HIdeal, -HLate}.

(* the adversary makes at most q queries (stated for the ideal game, where it is a plain hoare statement) *)
declare op q : int.
declare axiom q_ge0 : 0 <= q.
(* the adversary terminates, whatever (terminating) oracle it is given *)
declare axiom A_guess_ll (O <: Oracle {-A}) : islossless O.o => islossless A(O).guess.
declare axiom A_choose_ll (O <: Oracle {-A}) : islossless O.o => islossless A(O).choose.
declare axiom A_queries :
  hoare [ HLate(A).pre : true ==> size Log.qs <= q ].

(* ------------------------------------------------------------------ *)
(* Real ~ Ideal, up to the adversary querying the committed point        *)

local lemma Log_ll : islossless Log(RO).o.
proof. proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll). qed.

local lemma real_ideal :
  equiv [ HReal(A).main ~ HIdeal(A).main :
          ={glob A, b} ==> (res{1} <=> res{2}) \/ HIdeal.bad{2} ].
proof.
proc.
inline RO.init.
seq 3 3 : (={glob A, b, m0, m1, RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1})).
+ call (_ : ={RO.m, Log.qs} /\ (forall x, x \in RO.m{1} => x \in Log.qs{1})).
  - proc; inline *; sp; if; first by smt().
    * auto => />; smt(mem_set).
    * auto => />; smt().
  - by wp; skip => />; smt(mem_empty).
seq 2 2 : (={glob A, b, m0, m1, RO.m, Log.qs, r} /\ HReal.tgt{1} = HIdeal.tgt{2}
           /\ (forall x, x \in RO.m{1} => x \in Log.qs{1})).
+ by wp; rnd; skip => />.
inline RO.o.
seq 3 1 : ((HIdeal.tgt{2} \in Log.qs{2}) \/
           (={glob A, Log.qs} /\ c{1} = c{2} /\ HReal.tgt{1} = HIdeal.tgt{2}
            /\ (forall x, x <> HIdeal.tgt{2} => RO.m{1}.[x] = RO.m{2}.[x])
            /\ HIdeal.tgt{2} \in RO.m{1}
            /\ (!(HIdeal.tgt{2} \in Log.qs{2}) => !(HIdeal.tgt{2} \in RO.m{2})))).
+ sp; if{1}.
  - wp; rnd; skip => />; smt(mem_set get_setE).
  - wp; rnd{2}; skip => />; smt(dcm_ll).
wp.
call (_ : (HIdeal.tgt \in Log.qs),
          (={Log.qs} /\ HReal.tgt{1} = HIdeal.tgt{2}
           /\ (forall x, x <> HIdeal.tgt{2} => RO.m{1}.[x] = RO.m{2}.[x])
           /\ HIdeal.tgt{2} \in RO.m{1}
           /\ (!(HIdeal.tgt{2} \in Log.qs{2}) => !(HIdeal.tgt{2} \in RO.m{2})))).
+ by move=> O hO; exact (A_guess_ll O hO).
+ proc; inline *; sp.
  case (x{2} = HIdeal.tgt{2}).
  - rcondf{1} 1; first by auto => />; smt().
    rcondt{2} 1; first by auto => />; smt().
    by wp; rnd{2}; skip => />; smt(dcm_ll).
  - if; first by smt().
    * by wp; rnd; skip => />; smt(mem_set get_setE).
    * by wp; skip => />; smt().
+ by move=> &2 _; exact Log_ll.
+ move=> _; proc; inline *; sp; if; wp; [ rnd; skip => /> | skip => /> ]; smt(dcm_ll).
by skip; smt().
qed.

local lemma ideal_late :
  equiv [ HIdeal(A).main ~ HLate(A).main :
          ={glob A, b} ==> res{1} = res{2} /\ HIdeal.bad{1} = HLate.bad{2} ].
proof.
proc; inline HLate(A).pre RO.init.
swap{1} [4..5] 2.
seq 3 4 : (={glob A, RO.m, Log.qs} /\ b{1} = b{2} /\ b0{2} = b{2} /\ m0{1} = m0{2} /\ m1{1} = m1{2}).
+ call (_ : ={RO.m, Log.qs}); first by sim.
  by wp; skip => />.
sp.
seq 1 1 : (={glob A, RO.m, Log.qs, c} /\ b{1} = b{2} /\ m0{1} = m0{2} /\ m1{1} = m1{2}
           /\ HLate.mb{2} = (if b{1} then m1{1} else m0{1})).
+ by rnd; skip => />; smt().
seq 1 1 : (={glob A, RO.m, Log.qs} /\ b'{1} = b'0{2} /\ b{1} = b{2} /\ m0{1} = m0{2} /\ m1{1} = m1{2}
           /\ HLate.mb{2} = (if b{1} then m1{1} else m0{1})).
+ by call (_ : ={RO.m, Log.qs}); first by sim.
wp; rnd; wp; skip => />; smt().
qed.

local lemma pre_ll : islossless HLate(A).pre.
proof.
proc.
call (A_guess_ll (Log(RO)) Log_ll).
rnd; wp.
call (A_choose_ll (Log(RO)) Log_ll).
inline RO.init; wp; skip; smt(dcm_ll).
qed.

local lemma pre_ph : phoare[HLate(A).pre : true ==> size Log.qs <= q] = 1%r.
proof. by conseq pre_ll A_queries. qed.

local lemma pre_le1 : phoare[HLate(A).pre : true ==> size Log.qs <= q] <= 1%r.
proof. by bypr => &m _; rewrite Pr[mu_le1]. qed.

local lemma late_bad &m (b : bool) :
  Pr[HLate(A).main(b) @ &m : HLate.bad] <= q%r * pmax.
proof.
byphoare (_ : true ==> HLate.bad) => //.
proc.
seq 1 : (size Log.qs <= q) 1%r (q%r * pmax) 0%r 1%r.
+ by (call (_ : true) || (hoare; auto) || auto || (wp; call (_ : true); skip) || conseq (_ : _ ==> true)).
+ by call pre_le1.
+ wp; rnd (fun r => (HLate.mb, r) \in Log.qs).
  - skip => &hr [hq _]; split.
    + apply (ler_trans ((size Log.qs{hr})%r * pmax)); first exact (mu_hit HLate.mb{hr} Log.qs{hr}).
      by apply ler_wpmul2r; [exact pmax_ge0 | smt()].
    + by move=> _ v _ h.
  - by move=> _; apply mulr_ge0; [smt(q_ge0) | exact pmax_ge0].
+ by hoare; call A_queries; skip => />.
+ smt().
qed.

local lemma ideal_indep :
  equiv [ HIdeal(A).main ~ HIdeal(A).main : ={glob A} ==> ={res} ].
proof.
proc; inline RO.init.
seq 3 3 : (={glob A, RO.m, Log.qs}).
+ call (_ : ={RO.m, Log.qs}); first by sim.
  by wp; skip.
swap{1} [1..2] 2.
swap{2} [1..2] 2.
seq 1 1 : (={glob A, RO.m, Log.qs, c}).
+ by rnd.
seq 1 1 : (={b'}).
+ by call (_ : ={RO.m, Log.qs}); first by sim.
wp; rnd{1}; rnd{2}; skip => />; smt(dn_ll).
qed.

local lemma ideal_bad_bound &m (b : bool) :
  Pr[HIdeal(A).main(b) @ &m : HIdeal.bad] <= q%r * pmax.
proof.
have -> : Pr[HIdeal(A).main(b) @ &m : HIdeal.bad] = Pr[HLate(A).main(b) @ &m : HLate.bad].
+ by byequiv ideal_late => //.
exact (late_bad &m b).
qed.

(* Pr[Real_b : res] <= Pr[Ideal_b : res] + Pr[Ideal : bad]  and the symmetric inequality *)
local lemma real_le_ideal &m (b : bool) :
  Pr[HReal(A).main(b) @ &m : res] <= Pr[HIdeal(A).main(b) @ &m : res] + Pr[HIdeal(A).main(b) @ &m : HIdeal.bad].
proof.
have h : Pr[HReal(A).main(b) @ &m : res] <= Pr[HIdeal(A).main(b) @ &m : res \/ HIdeal.bad].
+ by byequiv real_ideal => //; smt().
have h2 : Pr[HIdeal(A).main(b) @ &m : res \/ HIdeal.bad]
          <= Pr[HIdeal(A).main(b) @ &m : res] + Pr[HIdeal(A).main(b) @ &m : HIdeal.bad].
+ rewrite Pr[mu_or]; smt(mu_bounded).
smt().
qed.

local lemma ideal_real :
  equiv [ HIdeal(A).main ~ HReal(A).main :
          ={glob A, b} ==> (res{1} <=> res{2}) \/ HIdeal.bad{1} ].
proof. by symmetry; conseq real_ideal; smt(). qed.

local lemma ideal_le_real &m (b : bool) :
  Pr[HIdeal(A).main(b) @ &m : res] <= Pr[HReal(A).main(b) @ &m : res] + Pr[HIdeal(A).main(b) @ &m : HIdeal.bad].
proof.
have h : Pr[HIdeal(A).main(b) @ &m : res /\ !HIdeal.bad] <= Pr[HReal(A).main(b) @ &m : res].
+ by byequiv ideal_real => //; smt().
rewrite Pr[mu_split HIdeal.bad].
have h2 : Pr[HIdeal(A).main(b) @ &m : res /\ HIdeal.bad] <= Pr[HIdeal(A).main(b) @ &m : HIdeal.bad].
+ by rewrite Pr[mu_sub]; smt().
smt().
qed.

(* the two worlds' results do not depend on b in the ideal game *)
local lemma ideal_same &m :
  Pr[HIdeal(A).main(false) @ &m : res] = Pr[HIdeal(A).main(true) @ &m : res].
proof. by byequiv ideal_indep. qed.

(* ---- the three theorems -------------------------------------------------------------- *)

(* a real commitment is no more informative than an independent random string, except through the
   queries that hit the committed point *)
lemma hide_real_le_ideal &m (b : bool) :
  Pr[HReal(A).main(b) @ &m : res] <= Pr[HIdeal(A).main(b) @ &m : res] + q%r * pmax.
proof.
have := real_le_ideal &m b.
have := ideal_bad_bound &m b.
smt().
qed.

lemma hide_ideal_le_real &m (b : bool) :
  Pr[HIdeal(A).main(b) @ &m : res] <= Pr[HReal(A).main(b) @ &m : res] + q%r * pmax.
proof.
have := ideal_le_real &m b.
have := ideal_bad_bound &m b.
smt().
qed.

(* HIDING IN THE ROM:  |Pr[Real_0 : res] - Pr[Real_1 : res]| <= 2 q pmax *)
lemma hide_rom &m :
  `| Pr[HReal(A).main(false) @ &m : res] - Pr[HReal(A).main(true) @ &m : res] | <= 2%r * (q%r * pmax).
proof.
have h1 := hide_real_le_ideal &m false.
have h2 := hide_ideal_le_real &m false.
have h3 := hide_real_le_ideal &m true.
have h4 := hide_ideal_le_real &m true.
have h5 := ideal_same &m.
smt().
qed.

end section.

