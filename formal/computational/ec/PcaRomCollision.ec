(* PcaRomCollision.ec -- COLLISION RESISTANCE OF A RANDOM ORACLE with a 256-bit output (the binding of the
   SHA-256 commitments of the MPC commit-reveal, and of every hash-based commitment in the repository).

   THEOREM `rom_collision`.  Let H be a lazily sampled random oracle with answers from `dcm`, where every
   answer value has probability at most `pc` (2^-256 for a uniform 256-bit output).  Let A be ANY adversary
   (a module with oracle access to H) that outputs two points (x, x') and makes at most `q` distinct oracle
   queries before doing so.  Then the probability that  x <> x'  and  H(x) = H(x')  is at most
        (q+2)(q+1)/2 * pc            ( = (q+2)(q+1) / 2^257 for pc = 2^-256 ),
   where the +2 is the evaluation of H on the two output points (made by the experiment itself, so that
   the output points count as queries even when A never queried them).
   `rom_collision_sha` states the number for pc = 2^-256, and `rom_collision_sha_q` the simplified bound
   (q+2)^2 / 2^257.

   The proof reuses the EasyCrypt library lemma `PROM.fcoll_bound` (failure-event lemma `fel` on the size of
   the lazily sampled map: the i-th fresh answer collides with one of the i-1 earlier answers with probability
   at most (i-1)*pc, summed over the queries) and adds the reduction from "A finds a collision" to
   "the map of the random oracle contains a collision".  Nothing is assumed except `pc >= 0`, that no
   answer value is likelier than `pc`, and the adversary's query bound.
   *)
require import AllCore Int Real Distr FMap StdOrder.
require PROM.
import RealOrder.

abstract theory RC.

type pt.
type cm.
op dcm : cm distr.
op pc : real.
axiom pc_ge0 : 0%r <= pc.
axiom dcm_pc (y : cm) : mu1 dcm y <= pc.

clone PROM.FullRO as R with
  type in_t <- pt,
  type out_t <- cm,
  op dout <- (fun (_ : pt) => dcm),
  type d_in_t <- unit,
  type d_out_t <- bool.

import R.

(* the collision finder, as a distinguisher on the map-oracle *)
module type Finder (O : RO) = {
  proc find() : pt * pt { O.get }
}.

module Wrap (A : Finder) (O : ROmap) = {
  proc distinguish(u : unit) : bool = {
    var x : pt; var x' : pt; var y : cm; var y' : cm;
    (x, x') <@ A(O).find();
    y  <@ O.get(x);
    y' <@ O.get(x');
    return x <> x' /\ y = y';
  }
}.

section.
declare module A <: Finder {-RO}.
declare op q : int.
declare axiom q_ge0 : 0 <= q.
(* A makes at most q distinct queries: the map has at most q entries when it returns *)
declare axiom A_bounded : hoare [ A(RO).find : fsize RO.m = 0 ==> fsize RO.m <= q ].

local lemma fcollP_id :
  forall (x1 x2 : pt) (y : cm), y \in dmap (dcm) (fun (z : cm) => z) => mu1 (dmap dcm (fun (z : cm) => z)) y <= pc.
proof. by move=> x1 x2 y _; rewrite dmap_id; exact (dcm_pc y). qed.

local lemma bounded2 :
  hoare [ MainRM(Wrap(A), RO).distinguish :
          true ==> (res => (fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= q + 2)) ].
proof.
proc; inline Wrap(A, RO).distinguish RO.init.
seq 3 : (fsize RO.m <= q).
+ by call A_bounded; wp; skip => />; smt(fsize_empty).
inline RO.get; auto => />.
move=> &hr hq r0 hr0; rewrite /fcoll; split.
+ move=> hn r1 hr1; split.
  - move=> hn' hne heq; split; first by exists x0{hr} x'{hr}; smt(mem_set get_setE).
    smt(fsize_set mem_set).
  - move=> hin hne heq; split; first by exists x0{hr} x'{hr}; smt(mem_set get_setE).
    smt(fsize_set mem_set).
+ move=> hin r1 hr1; split.
  - move=> hn' hne heq; split; first by exists x0{hr} x'{hr}; smt(mem_set get_setE).
    smt(fsize_set mem_set).
  - move=> hin' hne heq; split; first by exists x0{hr} x'{hr}; smt(mem_set get_setE).
    smt(fsize_set mem_set).
qed.

lemma rom_collision &m :
  Pr [ MainRM(Wrap(A), RO).distinguish() @ &m : res ]
  <= ((q + 2) * (q + 1))%r / 2%r * pc.
proof.
have h1 : Pr [ MainRM(Wrap(A), RO).distinguish() @ &m : res ]
          <= Pr [ MainRM(Wrap(A), RO).distinguish() @ &m :
                  fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= q + 2 ].
+ byequiv (_ : ={glob A, arg} ==> res{1} => (fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= q + 2){2}) => //.
  conseq (_ : _ ==> ={res}) _ (_ : _ ==> res => (fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= q + 2)) => //=.
  - by exact bounded2.
  - by sim.
have h2 := fcoll_bound (fun (z : cm) => z) pc pc_ge0 fcollP_id (q + 2) _ (Wrap(A)) &m tt.
+ smt(q_ge0).
apply (ler_trans _ _ _ h1).
apply (ler_trans _ _ _ h2).
have -> : ((q + 2) * (q + 2 - 1))%r = ((q + 2) * (q + 1))%r by smt().
done.
qed.

lemma rom_collision_sha &m :
  pc = 1%r / (2%r ^ 256) =>
  Pr [ MainRM(Wrap(A), RO).distinguish() @ &m : res ]
  <= ((q + 2) * (q + 1))%r / (2%r ^ 257).
proof.
move=> hpc.
apply (ler_trans _ _ _ (rom_collision &m)).
rewrite hpc.
have h2 : 2%r ^ 257 = 2%r * 2%r ^ 256.
+ by rewrite (: 257 = 256 + 1) 1:// RField.exprS //.
have hp : 0%r < 2%r ^ 256 by smt(expr_gt0).
rewrite h2.
have e : ((q + 2) * (q + 1))%r / 2%r * (1%r / 2%r ^ 256) = ((q + 2) * (q + 1))%r / (2%r * 2%r ^ 256).
+ by field; smt().
by rewrite e; smt().
qed.

end section.


section GEN.
declare module D <: RM_Distinguisher {-RO}.

lemma rom_collision_gen (qq : int) &m :
  0 <= qq =>
  Pr [ MainRM(D, RO).distinguish() @ &m :
       res /\ !(fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= qq) ] <= 0%r =>
  Pr [ MainRM(D, RO).distinguish() @ &m : res ] <= (qq * (qq - 1))%r / 2%r * pc.
proof.
move=> hq hh.
have fp : forall (x1 x2 : pt) (y : cm), y \in dmap dcm (fun (z : cm) => z) => mu1 (dmap dcm (fun (z : cm) => z)) y <= pc.
+ by move=> x1 x2 y _; rewrite dmap_id; exact (dcm_pc y).
have h1 : Pr [ MainRM(D, RO).distinguish() @ &m : res ]
          <= Pr [ MainRM(D, RO).distinguish() @ &m : fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= qq ].
+ rewrite Pr[mu_split (fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= qq)].
  have : Pr [ MainRM(D, RO).distinguish() @ &m : res /\ (fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= qq) ]
         <= Pr [ MainRM(D, RO).distinguish() @ &m : fcoll (fun (z : cm) => z) RO.m /\ fsize RO.m <= qq ].
  - by rewrite Pr[mu_sub]; smt().
  smt(mu_bounded).
have h2 := fcoll_bound (fun (z : cm) => z) pc pc_ge0 fp qq hq D &m tt.
exact (ler_trans _ _ _ h1 h2).
qed.
end section GEN.

end RC.
