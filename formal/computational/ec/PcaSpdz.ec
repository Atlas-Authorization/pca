(* PcaSpdz.ec -- the statistical soundness bounds of the SPDZ-style MPC of
   docs/pca/security/proofs/06-mpc.md (MPC-1 MAC-check, MPC-2 sacrifice), machine-checked
   for an arbitrary prime p, then evaluated at p = 2^61 - 1.

   MPC-1 (one key):  Pr_{alpha <- F, r <- (Fstar)^m}[ <r, eps - alpha*delta> = 0 ]  <=  1/p + 1/(p-1)
                     whenever delta <> 0 (some opened value is wrong).
   MPC-2:            Pr_{e1,e2 <- F*}[ e1*d = dh1 /\ e2*d = dh2 ]  <=  (1/(p-1))^2   for d <> 0.

   What is NOT here: the protocol, the commit-then-open ordering that fixes (delta, eps)
   before the challenge is drawn (that is the hypothesis "delta, eps independent of r, alpha"
   below), the dealer / OT preprocessing that makes alpha uniform and hidden. *)
require import AllCore StdRing StdOrder Distr DProd DList Dexcepted List Real Int IntDiv.
require (*--*) ZModP Prime61.
(*---*) import RField RealOrder.

(* the modulus is the concrete Mersenne prime 2^61 - 1 of field.ts; its primality is a checked
   theorem (Prime61.prime_M61, a Pratt/Lucas certificate), not an assumption *)
op pp : int = 2 ^ 61 - 1.

lemma prime_pp : prime pp by exact Prime61.prime_M61.

clone ZModP.ZModField as F with
  op p <- pp
  proof prime_p by exact prime_pp.


(* ------------------------------------------------------------------ *)
(* a bound on a mixture                                                  *)

lemma mu_dlet_bound ['a 'b] (d : 'a distr) (G : 'a -> 'b distr) (E : 'b -> bool) (r : real) :
  0%r <= r =>
  (forall x, x \in d => mu (G x) E <= r) =>
  mu (dlet d G) E <= r.
proof.
move=> hr hb.
rewrite dletE.
have h1 : RealSeries.sum (fun x => mu1 d x * mu (G x) E) <= RealSeries.sum (fun x => r * mu1 d x).
+ apply RealSeries.ler_sum_pos.
  - move=> x /=.
    have h0 := ge0_mu (G x) E.
    have h1 := ge0_mu1 d x.
    case (mu1 d x = 0%r) => hz.
    + by rewrite hz; smt().
    have hs : x \in d by rewrite supportP.
    have h2 : mu1 d x * mu (G x) E <= mu1 d x * r by apply ler_wpmul2l => //; exact (hb x hs).
    smt().
  - exact (RealSeries.summableZ (mu1 d) r (summable_mu1 d)).
rewrite RealSeries.sumZ -weightE in h1.
have hw : weight d <= 1%r by exact (le1_mu d predT).
have hw0 := ge0_weight d.
have : r * weight d <= r by smt().
smt().
qed.

import F F.ZModpField F.DZmodP.

type fe = zmod.


(* ------------------------------------------------------------------ *)
(* Schwartz-Zippel for a nonzero linear form over independent coordinates *)

op dot (r w : fe list) : fe = foldr (fun (p : fe * fe) acc => p.`1 * p.`2 + acc) zero (zip r w).

lemma dot_cons (x y : fe) (xs ys : fe list) : dot (x :: xs) (y :: ys) = x * y + dot xs ys.
proof. by rewrite /dot /=. qed.

lemma dot_nil_l (w : fe list) : dot [] w = zero.
proof. by rewrite /dot zip0l. qed.

lemma dot_nil_r (r : fe list) : dot r [] = zero.
proof. by rewrite /dot zip0r. qed.

lemma dot_zeros (r w : fe list) : (forall z, z \in w => z = zero) => dot r w = zero.
proof.
elim: r w => [|x xs ih] w hz; first by rewrite dot_nil_l.
case: w hz => [|y ys] hz; first by rewrite dot_nil_r.
rewrite dot_cons (hz y) /=; first by rewrite /=.
rewrite mulr0 add0r; apply ih => z hzz.
by apply hz; rewrite /= hzz.
qed.

lemma lin_bound (d : fe distr) (rho : real) :
  is_lossless d => 0%r <= rho => (forall x, mu1 d x <= rho) =>
  forall n, 0 <= n =>
  forall (w : fe list) (c : fe), size w = n => (exists x, x \in w /\ x <> zero) =>
  mu (dlist d n) (fun r => dot r w = c) <= rho.
proof.
move=> hll hrho hmu n hn0; elim/natind: n hn0.
+ move=> n hn hn0 w c hs [x [hx _]].
  have hw : w = [] by smt(size_eq0 size_ge0).
  by move: hx; rewrite hw.
move=> n hn ih _ w c hs [x [hx hxz]].
case: w hs hx => [|y ws] hs hx; first by smt().
have hsz : size ws = n by smt().
rewrite dlistS //= dmapE.
rewrite /(\o).
case (exists z, z \in ws /\ z <> zero) => hws.
+ rewrite dprod_dlet.
  apply mu_dlet_bound => //.
  move=> a _.
  rewrite /=.
  have -> : dlet (dlist d n) (fun (b : fe list) => dunit (a, b)) = dmap (dlist d n) (fun (b : fe list) => (a, b)).
  + by rewrite -dlet_dunit.
  rewrite dmapE /(\o) /=.
  have e : forall b, (dot (a :: b) (y :: ws) = c) = (dot b ws = c - a * y).
  + move=> b; rewrite dot_cons; apply eq_iff; split => h.
    - by rewrite -h; ring.
    - by rewrite h; ring.
  have -> : (fun (b : fe list) => dot (a :: b) (y :: ws) = c) = (fun (b : fe list) => dot b ws = c - a * y).
  + by apply fun_ext => b /=; exact (e b).
  exact (ih hn ws (c - a * y) hsz hws).
have hwz : forall z, z \in ws => z = zero by smt().
have hy : y <> zero by smt().
have -> : (fun (x0 : fe * fe list) => dot (x0.`1 :: x0.`2) (y :: ws) = c) =
          (fun (x0 : fe * fe list) => (fun (x' : fe) => x' = c / y) x0.`1).
+ apply fun_ext => x0 /=.
  rewrite dot_cons (dot_zeros x0.`2 ws hwz) addr0; apply eq_iff; split => h.
  - by rewrite -h; field; exact hy.
  - by rewrite h; field; exact hy.
rewrite dprodEl.
have -> : weight (dlist d n) = 1%r by exact (is_losslessP _ (dlist_ll d n hll)).
by rewrite mulr1; exact (hmu (c / y)).
qed.

(* the challenge distribution: uniform on nonzero field elements (the network protocol rejects 0) *)
op dt : fe distr = dunifin.
op dstar : fe distr = dt \ pred1 zero.

lemma dt_mu1 (x : fe) : mu1 dt x = 1%r / pp%r.
proof. by rewrite /dt dunifin1E DZmodP.cardE. qed.

lemma dt_ll : is_lossless dt by rewrite /dt; exact dunifin_ll.

lemma pp_gt1 : 1 < pp.
proof. by have := gt1_prime pp prime_pp. qed.

lemma dstar_mu1 (x : fe) : mu1 dstar x <= inv (pp - 1)%r.
proof.
rewrite /dstar dexcepted1E.
case (pred1 zero x) => h; first by smt(pp_gt1).
rewrite dt_mu1 (is_losslessP _ dt_ll).
have -> : mu dt (pred1 zero) = 1%r / pp%r by exact dt_mu1.
have hp : 2 <= pp by smt(pp_gt1).
have : (1%r / pp%r) / (1%r - 1%r / pp%r) = inv (pp - 1)%r.
+ field; smt().
smt().
qed.

lemma inv_pp1_ge0 : 0%r <= inv (pp - 1)%r.
proof. by apply invr_ge0; smt(pp_gt1). qed.

lemma dstar_ll : is_lossless dstar.
proof.
rewrite /dstar; apply dexcepted_ll; first exact dt_ll.
rewrite dt_mu1.
have hp : 2 <= pp by smt(pp_gt1).
smt().
qed.

(* the error vector for key-share alpha: w_j = eps_j - alpha * delta_j *)
op wvec (es ds : fe list) (al : fe) : fe list =
  map (fun (q : fe * fe) => q.`1 - al * q.`2) (zip es ds).

lemma size_wvec (es ds : fe list) (al : fe) :
  size es = size ds => size (wvec es ds al) = size ds.
proof. by move=> h; rewrite /wvec size_map size_zip; smt(). qed.

(* a wrong opened value (delta_j <> 0) pins alpha to at most one value *)
lemma wvec_nonzero (es ds : fe list) (al : fe) (j : int) :
  size es = size ds => 0 <= j => j < size ds =>
  nth zero es j - al * nth zero ds j <> zero =>
  exists z, z \in wvec es ds al /\ z <> zero.
proof.
move=> hs hj0 hj1 hne.
exists (nth zero es j - al * nth zero ds j); split => //.
rewrite /wvec mapP; exists (nth zero es j, nth zero ds j); split => //=.
have -> : (nth zero es j, nth zero ds j) = nth (zero, zero) (zip es ds) j.
+ by rewrite nth_zip //; smt().
by apply mem_nth; rewrite size_zip; smt().
qed.

(* MPC-1, one key: a single wrong opening survives the random-linear-combination check with
   probability at most 1/p + 1/(p-1).  (es, ds) are the adversary's additive errors on the MAC
   sums and on the opened values; they are FIXED before alpha and the challenges are drawn. *)
lemma mac_bound (m : int) (es ds : fe list) :
  size es = m => size ds = m => (exists x, x \in ds /\ x <> zero) =>
  mu (dt `*` dlist dstar m) (fun (ar : fe * fe list) => dot ar.`2 (wvec es ds ar.`1) = zero)
  <= 1%r / pp%r + inv (pp - 1)%r.
proof.
move=> hes hds [x [hxin hxnz]].
have hm0 : 0 <= m by smt(size_ge0).
have [j [hj hxj]] : exists j, 0 <= j < size ds /\ x = nth zero ds j by have := (nthP zero ds x); smt().
have hdj : nth zero ds j <> zero by smt().
pose a0 := nth zero es j / nth zero ds j.
have hsub : mu (dt `*` dlist dstar m) (fun (ar : fe * fe list) => dot ar.`2 (wvec es ds ar.`1) = zero)
         <= mu (dt `*` dlist dstar m)
              (predU (fun (ar : fe * fe list) => ar.`1 = a0)
                     (fun (ar : fe * fe list) => ar.`1 <> a0 /\ dot ar.`2 (wvec es ds ar.`1) = zero)).
+ by apply mu_sub => ar /=; rewrite /predU /=; smt().
have hor := mu_or (dt `*` dlist dstar m)
              (fun (ar : fe * fe list) => ar.`1 = a0)
              (fun (ar : fe * fe list) => ar.`1 <> a0 /\ dot ar.`2 (wvec es ds ar.`1) = zero).
have hg := ge0_mu (dt `*` dlist dstar m)
              (predI (fun (ar : fe * fe list) => ar.`1 = a0)
                     (fun (ar : fe * fe list) => ar.`1 <> a0 /\ dot ar.`2 (wvec es ds ar.`1) = zero)).
have h1 : mu (dt `*` dlist dstar m) (fun (ar : fe * fe list) => ar.`1 = a0) = 1%r / pp%r.
+ have := dprodEl dt (dlist dstar m) (fun (a : fe) => a = a0).
  rewrite /= => ->.
  by rewrite (is_losslessP _ (dlist_ll dstar m dstar_ll)) mulr1; exact (dt_mu1 a0).
have h2 : mu (dt `*` dlist dstar m)
            (fun (ar : fe * fe list) => ar.`1 <> a0 /\ dot ar.`2 (wvec es ds ar.`1) = zero)
          <= inv (pp - 1)%r.
+ rewrite dprod_dlet.
  apply mu_dlet_bound.
  - exact inv_pp1_ge0.
  move=> a _ /=.
  have -> : dlet (dlist dstar m) (fun (b : fe list) => dunit (a, b)) = dmap (dlist dstar m) (fun (b : fe list) => (a, b)).
  + by rewrite -dlet_dunit.
  rewrite dmapE /(\o) /=.
  case (a = a0) => ha.
  - rewrite ha /=.
    have -> : (fun (b : fe list) => false) = pred0 by done.
    by rewrite mu0; exact inv_pp1_ge0.
  apply (ler_trans (mu (dlist dstar m) (fun (b : fe list) => dot b (wvec es ds a) = zero))).
  + by apply mu_sub => b /=; smt().
  apply (lin_bound dstar (inv (pp - 1)%r) dstar_ll _ dstar_mu1 m hm0 (wvec es ds a) zero).
  - exact inv_pp1_ge0.
  - by rewrite size_wvec; smt().
  apply (wvec_nonzero es ds a j); [smt() | smt() | smt() |].
  apply/negP => hz; apply ha.
  have e : nth zero es j = a * nth zero ds j by smt(ZModpField.subr_eq0).
  rewrite /a0 e; field.
  exact hdj.
smt().
qed.

(* MPC-1, two independent keys: independent alpha^(l), independent challenges, errors fixed. *)
lemma mac_bound2 (m : int) (es1 es2 ds : fe list) :
  size es1 = m => size es2 = m => size ds = m => (exists x, x \in ds /\ x <> zero) =>
  mu ((dt `*` dlist dstar m) `*` (dt `*` dlist dstar m))
     (fun (uv : (fe * fe list) * (fe * fe list)) =>
        dot uv.`1.`2 (wvec es1 ds uv.`1.`1) = zero /\ dot uv.`2.`2 (wvec es2 ds uv.`2.`1) = zero)
  <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r).
proof.
move=> h1 h2 h3 hx.
rewrite (dprodE (fun (u : fe * fe list) => dot u.`2 (wvec es1 ds u.`1) = zero)
                (fun (v : fe * fe list) => dot v.`2 (wvec es2 ds v.`1) = zero)).
apply ler_pmul; 1,2: exact ge0_mu.
+ exact (mac_bound m es1 ds h1 h3 hx).
exact (mac_bound m es2 ds h2 h3 hx).
qed.

(* MPC-2: triple sacrifice with two partners and independent challenges e_r in F-star:
   tau_r = e_r * d - dh_r = 0 holds for exactly one e_r when d <> 0. *)
lemma sacrifice_bound (d dh1 dh2 : fe) :
  d <> zero =>
  mu (dstar `*` dstar) (fun (e : fe * fe) => e.`1 * d = dh1 /\ e.`2 * d = dh2)
  <= inv (pp - 1)%r * inv (pp - 1)%r.
proof.
move=> hd.
have -> : (fun (e : fe * fe) => e.`1 * d = dh1 /\ e.`2 * d = dh2) =
          (fun (e : fe * fe) => (fun (x : fe) => x = dh1 / d) e.`1 /\ (fun (x : fe) => x = dh2 / d) e.`2).
+ apply fun_ext => e /=; congr.
  - apply eq_iff; split => h; first by rewrite -h; field; exact hd.
    by rewrite h; field; exact hd.
  apply eq_iff; split => h; first by rewrite -h; field; exact hd.
  by rewrite h; field; exact hd.
rewrite (dprodE (fun (x : fe) => x = dh1 / d) (fun (x : fe) => x = dh2 / d)).
apply ler_pmul; 1,2: exact ge0_mu.
+ exact (dstar_mu1 (dh1 / d)).
exact (dstar_mu1 (dh2 / d)).
qed.

(* in-process variant: the challenge 0 is mapped to 1 (spdz.ts sacrificeVerify), so mass 2/p sits on 1 *)
op dstar' : fe distr = dmap dt (fun (e : fe) => if e = zero then one else e).

lemma dstar'_mu1 (x : fe) : mu1 dstar' x <= 2%r / pp%r.
proof.
rewrite /dstar' dmap1E /(\o) /pred1.
apply (ler_trans (mu dt (predU (pred1 x) (pred1 zero)))).
+ by apply mu_sub => e /=; rewrite /predU /pred1; smt().
rewrite mu_or.
have h1 : mu dt (pred1 x) = 1%r / pp%r by exact (dt_mu1 x).
have h2 : mu dt (pred1 zero) = 1%r / pp%r by exact (dt_mu1 zero).
have h3 := ge0_mu dt (predI (pred1 x) (pred1 zero)).
smt().
qed.

lemma sacrifice_bound' (d dh1 dh2 : fe) :
  d <> zero =>
  mu (dstar' `*` dstar') (fun (e : fe * fe) => e.`1 * d = dh1 /\ e.`2 * d = dh2)
  <= (2%r / pp%r) * (2%r / pp%r).
proof.
move=> hd.
have -> : (fun (e : fe * fe) => e.`1 * d = dh1 /\ e.`2 * d = dh2) =
          (fun (e : fe * fe) => (fun (x : fe) => x = dh1 / d) e.`1 /\ (fun (x : fe) => x = dh2 / d) e.`2).
+ apply fun_ext => e /=; congr.
  - apply eq_iff; split => h; first by rewrite -h; field; exact hd.
    by rewrite h; field; exact hd.
  apply eq_iff; split => h; first by rewrite -h; field; exact hd.
  by rewrite h; field; exact hd.
rewrite (dprodE (fun (x : fe) => x = dh1 / d) (fun (x : fe) => x = dh2 / d)).
apply ler_pmul; 1,2: exact ge0_mu.
+ exact (dstar'_mu1 (dh1 / d)).
exact (dstar'_mu1 (dh2 / d)).
qed.

(* ------------------------------------------------------------------ *)
(* the numbers at p = 2^61 - 1                                           *)

lemma num_ineq (a : real) : 4%r <= a => a * a * a <= (a + 4%r) * ((a - 1%r) * (a - 1%r)).
proof.
move=> h.
have e : (a + 4%r) * ((a - 1%r) * (a - 1%r)) - a * a * a = 2%r * (a * a) - 7%r * a + 4%r by ring.
have h2 : 4%r * a <= a * a by apply ler_wpmul2r; smt().
smt().
qed.

(* p = 2^61 - 1 is the Mersenne prime used by field.ts; pp is now defined as that number and its
   primality is proved in Prime61.ec, so no axiom about the modulus remains. *)
lemma pp_M61 : pp = 2 ^ 61 - 1 by rewrite /pp.

op a60 : real = (2 ^ 60)%r.

lemma pow60 : 2 ^ 61 = 2 * 2 ^ 60 /\ 4 <= 2 ^ 60.
proof.
have h59 : 2 <= 2 ^ 59 by exact (IntOrder.ler_eexpr 2 59 _ _).
split.
+ by rewrite (_ : 61 = 60 + 1) // exprS.
have e : 2 ^ 60 = 2 * 2 ^ 59 by rewrite (_ : 60 = 59 + 1) // exprS.
smt().
qed.

lemma pp_real : pp%r = 2%r * a60 - 1%r /\ (pp - 1)%r = 2%r * (a60 - 1%r).
proof.
have [h1 h2] := pow60.
rewrite /a60 pp_M61.
split; smt().
qed.

lemma mac_num :
  (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r)
  <= (a60 + 4%r) / (a60 * a60 * a60).
proof.
have [hp hb] := pp_real.
have ha4 : 4%r <= a60 by have [_ h] := pow60; rewrite /a60; smt().
have hbpos : 0%r < (pp - 1)%r by smt().
have hinv : 1%r / pp%r <= inv (pp - 1)%r.
+ rewrite div1r; apply lef_pinv; smt().
have hS : 1%r / pp%r + inv (pp - 1)%r <= 2%r * inv (pp - 1)%r by smt().
have hS0 : 0%r <= 1%r / pp%r + inv (pp - 1)%r.
+ have : 0%r <= 1%r / pp%r by apply divr_ge0; smt().
  have := inv_pp1_ge0; smt().
apply (ler_trans ((2%r * inv (pp - 1)%r) * (2%r * inv (pp - 1)%r))).
+ by apply ler_pmul => //; smt().
have -> : (2%r * inv (pp - 1)%r) * (2%r * inv (pp - 1)%r) = 1%r / ((a60 - 1%r) * (a60 - 1%r)).
+ rewrite hb.
  have hne : a60 - 1%r <> 0%r by smt().
  field.
  - smt().
  have e : 1%r + (-2%r) * a60 + a60 ^ 2 = (a60 - 1%r) * (a60 - 1%r) by ring.
  rewrite e.
  have : 0%r < (a60 - 1%r) * (a60 - 1%r) by apply mulr_gt0; smt().
  smt().
have hq : 0%r < (a60 - 1%r) * (a60 - 1%r) by apply mulr_gt0; smt().
have hc : 0%r < a60 * a60 * a60 by apply mulr_gt0; [apply mulr_gt0 | ]; smt().
rewrite ler_pdivl_mulr 1:hc.
rewrite div1r ler_pdivr_mull 1:hq.
have := num_ineq a60 ha4.
smt().
qed.

lemma sac_num :
  inv (pp - 1)%r * inv (pp - 1)%r <= (a60 + 4%r) / (4%r * (a60 * a60 * a60)).
proof.
have [hp hb] := pp_real.
have ha4 : 4%r <= a60 by have [_ h] := pow60; rewrite /a60; smt().
have hq : 0%r < (a60 - 1%r) * (a60 - 1%r) by apply mulr_gt0; smt().
have hc : 0%r < 4%r * (a60 * a60 * a60) by apply mulr_gt0; [smt() | apply mulr_gt0; [apply mulr_gt0 | ]; smt()].
have -> : inv (pp - 1)%r * inv (pp - 1)%r = 1%r / (4%r * ((a60 - 1%r) * (a60 - 1%r))).
+ rewrite hb.
  have hne : a60 - 1%r <> 0%r by smt().
  field.
  - smt().
  have e : 4%r + (-8%r) * a60 + 4%r * a60 ^ 2 = 4%r * ((a60 - 1%r) * (a60 - 1%r)) by ring.
  rewrite e.
  have : 0%r < (a60 - 1%r) * (a60 - 1%r) by apply mulr_gt0; smt().
  smt().
have hq4 : 0%r < 4%r * ((a60 - 1%r) * (a60 - 1%r)) by smt().
rewrite ler_pdivl_mulr 1:hc.
rewrite div1r ler_pdivr_mull 1:hq4.
have := num_ineq a60 ha4.
smt().
qed.

lemma sac_inproc_num :
  (2%r / pp%r) * (2%r / pp%r) <= (a60 + 4%r) / (a60 * a60 * a60).
proof.
have [hp hb] := pp_real.
have ha4 : 4%r <= a60 by have [_ h] := pow60; rewrite /a60; smt().
have hpp : 0%r < pp%r by smt().
have hc : 0%r < a60 * a60 * a60 by apply mulr_gt0; [apply mulr_gt0 | ]; smt().
have hq : 0%r < pp%r * pp%r by apply mulr_gt0; smt().
have -> : (2%r / pp%r) * (2%r / pp%r) = 4%r / (pp%r * pp%r).
+ field.
  - smt().
  have : pp%r ^ 2 = pp%r * pp%r by ring.
  smt().
have hX : 0%r < pp%r * pp%r by smt().
have h1 : 4%r * (a60 * a60 * a60) <= (a60 + 4%r) * (pp%r * pp%r).
+ rewrite hp.
  have e : (a60 + 4%r) * ((2%r * a60 - 1%r) * (2%r * a60 - 1%r)) - 4%r * (a60 * a60 * a60)
           = 12%r * (a60 * a60) - 15%r * a60 + 4%r by ring.
  have h2 : 4%r * a60 <= a60 * a60 by apply ler_wpmul2r; smt().
  smt().
rewrite ler_pdivr_mulr 1:hX.
rewrite mulrAC.
rewrite ler_pdivl_mulr 1:hc.
smt().
qed.

(* total online error for the network protocol with n = 3, Q = 100: 208 sacrificed triples,
   2 partners each (a union bound over the 208 triples is the standard counting step), one
   batched two-key MAC-check:  2^-120 (1+2^-58) + 208 * 2^-122 (1+2^-58) = 53 * 2^-120 (1+2^-58) *)
lemma online_num :
  ((1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r))
  + 208%r * (inv (pp - 1)%r * inv (pp - 1)%r)
  <= 53%r * ((a60 + 4%r) / (a60 * a60 * a60)).
proof.
have h1 := mac_num.
have h2 := sac_num.
have ha4 : 4%r <= a60 by have [_ h] := pow60; rewrite /a60; smt().
have hc : 0%r < a60 * a60 * a60 by apply mulr_gt0; [apply mulr_gt0 | ]; smt().
have e : (a60 + 4%r) / (4%r * (a60 * a60 * a60)) * 208%r = 52%r * ((a60 + 4%r) / (a60 * a60 * a60)).
+ have p3 : a60 ^ 3 = a60 * a60 * a60 by ring.
  field.
  - smt().
  smt().
smt().
qed.
