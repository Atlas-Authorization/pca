(* PcaPedersen.ec -- Pedersen commitment binding (reduction to discrete log) and
   perfect hiding, and the algebraic core of the OR / range proof of
   docs/pca/security/proofs/04-ratchet.md (PD-1, PD-2, RP-2, RP-4 integer step).

   The group is an abstract cyclic group of PRIME order q (EasyCrypt's CyclicGroup with the
   PowZMod field of exponents), written multiplicatively: Com(v;b) = g^v * h^b where
   the second generator h is the discrete-log challenge. *)
require import AllCore StdRing StdOrder Distr List Real Int IntDiv.
require (*--*) Group.
(*---*) import RField RealOrder.

clone Group.CyclicGroup as G.
axiom prime_p : IntDiv.prime G.order.

clone G.PowZMod as GP with
  lemma prime_order <- prime_p.

clone GP.FDistr as FD.

import G GP FD GP.ZModE.
import ZModpField.

(* ------------------------------------------------------------------ *)
(* PD-1 binding                                                         *)

module type DLAdv = { proc guess(h : group) : exp }.

(* the standard discrete-log experiment (identical to EasyCrypt's DLog.DLogStdExperiment) *)
module DL(A : DLAdv) = {
  proc main() : bool = {
    var x, x' : exp;
    x <$ dt;
    x' <@ A.guess(g ^ x);
    return x' = x;
  }
}.

module type BindAdv = { proc run(h : group) : exp * exp * exp * exp }.

(* binding experiment: the second generator is g^x for random x *)
module Bind(A : BindAdv) = {
  proc main() : bool = {
    var x, v, b, v', b' : exp;
    x <$ dt;
    (v, b, v', b') <@ A.run(g ^ x);
    return (v, b) <> (v', b') /\ g ^ v * (g ^ x) ^ b = g ^ v' * (g ^ x) ^ b';
  }
}.

module RB(A : BindAdv) = {
  proc guess(h : group) : exp = {
    var v, b, v', b' : exp;
    (v, b, v', b') <@ A.run(h);
    return (v - v') / (b' - b);
  }
}.

(* the algebra: two openings of one commitment reveal log_g h *)
lemma bind_alg (x v b v' b' : exp) :
  (v, b) <> (v', b') =>
  g ^ v * (g ^ x) ^ b = g ^ v' * (g ^ x) ^ b' =>
  (v - v') / (b' - b) = x.
proof.
move=> hne heq.
have e1 : g ^ (v + x * b) = g ^ (v' + x * b').
+ by rewrite !expD !expM.
have e2 : v + x * b = v' + x * b' by rewrite pow_bij.
case (b = b') => hb.
+ have hv : v = v'.
  - by move: e2; rewrite hb; exact addIr.
  by move: hne; rewrite hb hv.
have hnz : b' - b <> zero by smt(ZModpRing.subr_eq0).
have h3 : v - v' = x * (b' - b).
+ have hv : v = (v' + x * b') - x * b by rewrite -e2; ring.
  by rewrite hv; ring.
rewrite h3.
field.
by move: hnz; rewrite -(ZModpField.addrC b') ; smt(ZModpField.subr_eq0 ZModpField.addrC).
qed.

section.
declare module A <: BindAdv.

(* Adv^bind(A) <= Adv^dlog(RB(A)) : tight *)
lemma binding &m :
  Pr[Bind(A).main() @ &m : res] <= Pr[DL(RB(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline *.
wp; call (_ : true).
wp; rnd; skip => /> x _ r h1 h2.
have hne : (r.`1, r.`2) <> (r.`3, r.`4) by smt().
exact (bind_alg x r.`1 r.`2 r.`3 r.`4 hne h2).
qed.
end section.

(* ------------------------------------------------------------------ *)
(* PD-2 perfect hiding (uniform blinding on Z_q)                         *)

(* every group element is hit with probability exactly 1/q, whatever v is *)
lemma commit_uniform (v k : exp) (c : group) :
  k <> zero =>
  mu1 (dmap dt (fun b => g ^ v * (g ^ k) ^ b)) c = 1%r / order%r.
proof.
move=> hk.
rewrite (dmap1E_can dt (fun (b : exp) => g ^ v * (g ^ k) ^ b) (fun (c : group) => (loge c - v) / k) c).
+ move=> y /=; rewrite -expM -expD.
  have -> : v + k * ((loge y - v) / k) = loge y by field; exact hk.
  by rewrite expgK.
+ move=> b _ /=; rewrite -expM -expD loggK.
  by field; exact hk.
exact dt1E.
qed.

(* PD-2 : the commitment distribution does not depend on the committed value *)
lemma hiding (v v' k : exp) :
  k <> zero =>
  dmap dt (fun b => g ^ v * (g ^ k) ^ b) = dmap dt (fun b => g ^ v' * (g ^ k) ^ b).
proof.
move=> hk; rewrite eq_distr => c.
by rewrite !commit_uniform.
qed.

(* ------------------------------------------------------------------ *)
(* RP-2 : special soundness of the sigma protocols                       *)

(* (a) Schnorr: base h, statement D, transcripts (a; e, z) and (a; e', z'):
   verification is  h^z = a * D^e.  Two accepting transcripts with e <> e' extract the
   witness w = (z - z')/(e - e'), D = h^w. *)
lemma schnorr_ss (h D a : group) (e e' z z' : exp) :
  e <> e' =>
  h ^ z = a * D ^ e =>
  h ^ z' = a * D ^ e' =>
  D = h ^ ((z - z') / (e - e')).
proof.
move=> hne h1 h2.
have l1 : loge (h ^ z) = loge (a * D ^ e) by rewrite h1.
have l2 : loge (h ^ z') = loge (a * D ^ e') by rewrite h2.
move: l1; rewrite logrzM' logDr logrzM' => l1.
move: l2; rewrite logrzM' logDr logrzM' => l2.
have hz : loge h * (z - z') = loge D * (e - e').
+ by rewrite mulrBr mulrBr l1 l2; ring.
have hne' : e - e' <> zero by smt(ZModpField.subr_eq0).
rewrite log_bij logrzM'.
have -> : loge h * ((z - z') / (e - e')) = (loge h * (z - z')) / (e - e') by ring.
rewrite hz.
field.
by move: hne'; smt(ZModpField.addrC).
qed.

(* (b) CDS OR-proof of  B = b*G + s*H  with b in {0,1}.
   Branch j checks  h^{z_j} = a_j * P_j^{e_j}  with P_0 = B, P_1 = B/g, and e_0 + e_1 = e.
   Two accepting transcripts with the same first message and different total challenges
   extract a bit and a blinding. *)
lemma or_ss (h B a0 a1 : group) (e0 e1 e0' e1' z0 z1 z0' z1' : exp) :
  e0 + e1 <> e0' + e1' =>
  h ^ z0 = a0 * B ^ e0 =>
  h ^ z1 = a1 * (B / g) ^ e1 =>
  h ^ z0' = a0 * B ^ e0' =>
  h ^ z1' = a1 * (B / g) ^ e1' =>
  exists (b s : exp), (b = zero \/ b = one) /\ B = g ^ b * h ^ s.
proof.
move=> hne k0 k1 k0' k1'.
case (e0 = e0') => he0.
+ have he1 : e1 <> e1' by smt().
  have hD := schnorr_ss h (B / g) a1 e1 e1' z1 z1' he1 k1 k1'.
  exists one; exists ((z1 - z1') / (e1 - e1')); split; first by right.
  rewrite log_bij logDr !logrzM'.
  have hl : loge (B / g) = loge (h ^ ((z1 - z1') / (e1 - e1'))) by rewrite hD.
  move: hl; rewrite logDrN logg1 logrzM' => hl.
  have e : loge B = (loge B - one) + one by ring.
  by rewrite {1}e hl; ring.
have hD := schnorr_ss h B a0 e0 e0' z0 z0' he0 k0 k0'.
exists zero; exists ((z0 - z0') / (e0 - e0')); split; first by left.
by rewrite exp0 mul1c.
qed.

(* (c) The range statement: V = g^v h^gamma with v in [0, 2^n), extracted from n extracted bit
   openings (b_j, s_j) and a Schnorr witness w for  D = (prod_j B_j^{2^j}) / V = h^w. *)

lemma ofint_add (a b : int) : 0 <= a => 0 <= b => ZModpField.ofint (a + b) = ZModpField.ofint a + ZModpField.ofint b.
proof.
move=> ha hb; elim/natind: a ha.
+ move=> a hle ha0.
  have -> : a = 0 by smt().
  by rewrite ZModpField.ofint0 add0r.
move=> a ha ih _.
have -> : a + 1 + b = (a + b) + 1 by ring.
rewrite ZModpField.ofintS 1:/# ZModpField.ofintS // (ih ha).
by ring.
qed.

op bin (xs : exp list) : exp = foldr (fun x acc => x + (one + one) * acc) zero xs.
op ival (bs : int list) : int = foldr (fun b acc => b + 2 * acc) 0 bs.
op agg (bcs : group list) : group = foldr (fun B acc => B * acc ^ (one + one)) e bcs.
op com (h : group) (p : int * exp) : group = g ^ (ZModpField.ofint p.`1) * h ^ p.`2.

pred isbit (b : int) = b = 0 \/ b = 1.

lemma ival_cons (b : int) (bs : int list) : ival (b :: bs) = b + 2 * ival bs.
proof. by rewrite /ival. qed.

lemma ival_range (bs : int list) :
  all isbit bs => 0 <= ival bs /\ ival bs < 2 ^ size bs.
proof.
elim: bs => [|b bs ih] /=; first by rewrite /ival /= expr0.
move=> [hb hall]; have [h0 h1] := ih hall.
rewrite ival_cons (addzC 1) exprS 1:size_ge0.
by move: hb; rewrite /isbit; smt(size_ge0).
qed.

lemma ival_nonneg (bs : int list) : all isbit bs => 0 <= ival bs.
proof. by move=> h; have [] := ival_range bs h. qed.

lemma agg_open (h : group) (ops : (int * exp) list) :
  all isbit (map fst ops) =>
  agg (map (com h) ops) = g ^ (ZModpField.ofint (ival (map fst ops))) * h ^ bin (map snd ops).
proof.
elim: ops => [|p ops ih] /=.
+ by rewrite /agg /ival /bin /= ZModpField.ofint0 exp0 exp0 mulc1 //; smt(mulc1 mul1c).
move=> [hb hall].
have ihh := ih hall.
rewrite /agg /= -/(agg (map (com h) ops)) ihh.
rewrite /ival /bin /= -/(ival (map fst ops)) -/(bin (map snd ops)).
rewrite /com /=.
rewrite log_bij.
have hi := ival_nonneg _ hall.
move: hb; rewrite /isbit => hb.
have hp : 0 <= p.`1 by smt().
rewrite ofint_add //; first smt().
have h2 : ZModpField.ofint (2 * ival (map fst ops)) = ZModpField.ofint (ival (map fst ops)) + ZModpField.ofint (ival (map fst ops)).
+ by rewrite (_ : 2 * ival (map fst ops) = ival (map fst ops) + ival (map fst ops)) 1:/# ofint_add.
rewrite h2.
rewrite !logDr !logrzM' !logDr !logrzM' !logg1.
ring.
qed.

lemma range_extract (h V : group) (ops : (int * exp) list) (w : exp) :
  all isbit (map fst ops) =>
  agg (map (com h) ops) / V = h ^ w =>
  V = g ^ (ZModpField.ofint (ival (map fst ops))) * h ^ (bin (map snd ops) - w)
  /\ 0 <= ival (map fst ops) /\ ival (map fst ops) < 2 ^ size ops.
proof.
move=> hall hD.
have hA := agg_open h ops hall.
have [h0 h1] := ival_range _ hall.
rewrite size_map in h1.
split; last by smt().
have hl : loge (agg (map (com h) ops) / V) = loge (h ^ w) by rewrite hD.
have e1 : loge (agg (map (com h) ops)) =
  loge g * ZModpField.ofint (ival (map fst ops)) + loge h * bin (map snd ops).
+ by rewrite hA logDr !logrzM'.
have e2 : loge (h ^ w) = loge h * w by rewrite logrzM'.
have e3 : loge (agg (map (com h) ops) / V) = loge (agg (map (com h) ops)) - loge V by rewrite logDrN.
rewrite log_bij logDr !logrzM'.
have e : loge V = (loge g * ZModpField.ofint (ival (map fst ops)) + loge h * bin (map snd ops)) - (loge h * w).
+ move: hl; rewrite e3 e2 => hl'.
  have -> : loge V = loge (agg (map (com h) ops)) - (loge (agg (map (com h) ops)) - loge V) by ring.
  by rewrite hl' e1.
by rewrite e; ring.
qed.

(* RP-4, the integer step: if the extracted openings satisfy  c - sum v_i - sigma = 0 (mod q)
   with every v_i in [0,2^32), sigma and c in [0,2^32), and (n+1) * 2^32 <= q, then the
   congruence holds over the integers, so  sum v_i = c - sigma <= c. *)
op isum (vs : int list) : int = foldr (fun v acc => v + acc) 0 vs.

lemma isum_bounds (vs : int list) :
  all (fun v => 0 <= v /\ v < 2 ^ 32) vs =>
  0 <= isum vs /\ isum vs <= size vs * 2 ^ 32.
proof.
elim: vs => [|v vs ih] /=; first by rewrite /isum.
move=> [hv hall]; have [h0 h1] := ih hall.
have -> : isum (v :: vs) = v + isum vs by rewrite /isum.
smt(size_ge0).
qed.

lemma budget_integer (q c sigma n : int) (vs : int list) :
  0 < q => size vs = n => (n + 1) * 2 ^ 32 <= q =>
  all (fun v => 0 <= v /\ v < 2 ^ 32) vs =>
  0 <= c => c < 2 ^ 32 => 0 <= sigma => sigma < 2 ^ 32 =>
  (c - isum vs - sigma) %% q = 0 =>
  isum vs = c - sigma /\ isum vs <= c.
proof.
move=> hq hn hnq hall hc0 hc1 hs0 hs1 hmod.
have [b0 b1] := isum_bounds vs hall.
rewrite hn in b1.
have hlo : - q < c - isum vs - sigma by smt().
have hhi : c - isum vs - sigma < q by smt(expr_ge0).
have hz : c - isum vs - sigma = 0.
+ case (0 <= c - isum vs - sigma) => hnn.
  - by have := modz_small (c - isum vs - sigma) q _; smt().
  - have h2 : (c - isum vs - sigma + q) %% q = 0 by rewrite modzDr.
    have := modz_small (c - isum vs - sigma + q) q _; smt().
smt().
qed.

(* ------------------------------------------------------------------ *)
(* PD-2 for the implemented sampler: blinding uniform on the NONZERO scalars [1, q-1].  *)
(* Statistical distance at most 2/q.                                                    *)

require import Dexcepted.

op dnz : exp distr = dt \ pred1 ZModE.zero.

lemma dt_mu1 (x : exp) : mu1 dt x = 1%r / order%r by exact dt1E.

lemma excl_zero_close (P : exp -> bool) :
  `| mu dnz P - mu dt P | <= 1%r / order%r.
proof.
have hq : 2 <= order by smt(gt1_prime prime_p).
have hqr : 2%r <= order%r by smt().
have hw : weight dt = 1%r by exact (is_losslessP _ dt_ll).
have hz : mu dt (pred1 ZModE.zero) = 1%r / order%r by exact (dt_mu1 ZModE.zero).
rewrite /dnz dexceptedE hw hz.
have hsplit := mu_split dt P (pred1 ZModE.zero).
have hA : mu dt (predI P (predC (pred1 ZModE.zero))) <= 1%r - 1%r / order%r.
+ have := mu_sub dt (predI P (predC (pred1 ZModE.zero))) (predC (pred1 ZModE.zero)) _.
  - by move=> x; rewrite /predI /predC /pred1; smt().
  have h2 : mu dt (predC (pred1 ZModE.zero)) = 1%r - mu dt (pred1 ZModE.zero) by rewrite mu_not hw.
  by smt().
have hB : mu dt (predI P (pred1 ZModE.zero)) <= 1%r / order%r.
+ have := mu_sub dt (predI P (pred1 ZModE.zero)) (pred1 ZModE.zero) _.
  - by move=> x; rewrite /predI /pred1; smt().
  by smt().
have hA0 := ge0_mu dt (predI P (predC (pred1 ZModE.zero))).
have hB0 := ge0_mu dt (predI P (pred1 ZModE.zero)).
pose A := mu dt (predI P (predC (pred1 ZModE.zero))).
pose B := mu dt (predI P (pred1 ZModE.zero)).
have hmuP : mu dt P = A + B by smt().
have hwpos : 0%r < 1%r - 1%r / order%r.
+ have : 1%r / order%r <= 1%r / 2%r by apply ler_pdivr_mulr; smt().
  smt().
have hr : A / (1%r - 1%r / order%r) <= 1%r.
+ by rewrite ler_pdivr_mulr //; smt().
have hr0 : 0%r <= A / (1%r - 1%r / order%r) by apply divr_ge0; smt().
have e : A / (1%r - 1%r / order%r) - (A + B)
         = (A / (1%r - 1%r / order%r)) * (1%r / order%r) - B.
+ field; smt().
smt().
qed.

(* Statistical distance of the commitment distributions under nonzero blinding: for EVERY
   event E on the group,  | Pr_v[E] - Pr_v'[E] | <= 2/q . *)
lemma hiding_nz (v v' k : exp) (E : group -> bool) :
  k <> ZModE.zero =>
  `| mu (dmap dnz (fun (b : exp) => g ^ v * (g ^ k) ^ b)) E
   - mu (dmap dnz (fun (b : exp) => g ^ v' * (g ^ k) ^ b)) E |
  <= 2%r / order%r.
proof.
move=> hk.
rewrite !dmapE /(\o).
have h1 := excl_zero_close (fun (b : exp) => E (g ^ v * (g ^ k) ^ b)).
have h2 := excl_zero_close (fun (b : exp) => E (g ^ v' * (g ^ k) ^ b)).
have h3 : mu dt (fun (b : exp) => E (g ^ v * (g ^ k) ^ b)) = mu dt (fun (b : exp) => E (g ^ v' * (g ^ k) ^ b)).
+ have hh := hiding v v' k hk.
  have h4 : mu (dmap dt (fun (b : exp) => g ^ v * (g ^ k) ^ b)) E
          = mu (dmap dt (fun (b : exp) => g ^ v' * (g ^ k) ^ b)) E by rewrite hh.
  by move: h4; rewrite !dmapE /(\o).
smt().
qed.
