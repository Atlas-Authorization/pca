(* PcaSpdzSeq.ec -- SEQUENTIAL COMPOSITION of the SPDZ MAC-check across many sessions.

   PcaSpdzProto.ec bounds ONE MAC-check (one session: one batch of `nm` opened values, one key pair
   (alpha^(1), alpha^(2)), one coin flip, one residual round).  The code runs one batched check per
   session and discards the keys after the session (an abort ends it).  Here we compose s sessions.

   MODEL.  The adversary has one set of coins `w` and ADAPTS: the strategy for session t is
   `A w hs` where `hs` is the list of the complete outcomes (`outc`: everything, including the honest key
   shares -- a strict over-approximation of what it saw) of sessions 0..t-1.  Every session uses
   fresh honest randomness (nonces, coin-flip seed, MAC-key shares), i.e. an independent sample of
   `dHon`.  `outsP A w [] xs` is the list of outcomes of the s sessions when the honest randomness of
   session t is `xs[t]`.

   RESULTS.
     union_seq        generic: if each session's bad event has probability <= eps GIVEN ANY HISTORY, then
                      the probability that some of s sessions is bad is <= s * eps.
     winC_fixed       the committed-value bound of PcaSpdzProto (`winC_bound`) for a FIXED adversary coin and
                      a fixed adversary strategy (the honest randomness is the only source):
                      Pr <= (1/p + 1/(p-1))^2 = b.
     seq_soundness    Pr[some session has a wrong opened value and passes the check]
                        <=  s * b  +  Pr[BindS(BSs)]  +  Pr[BindG(BGs)]
                      where BSs / BGs are explicit collision finders against the seed / residual commitment
                      (they run the s sessions and output the first break).
     seq_soundness_num  at p = 2^61 - 1:   s * (2^60 + 4) / 2^180  =  s * 2^-120 * (1 + 2^-58)
                        e.g. s = 2^40 sessions:  2^-80 * (1 + 2^-58).

   The batch size `nm` inside a session costs NOTHING (the bound does not depend on nm); the number of
   sessions costs the factor s, exactly.  Keys are never reused across sessions in the code (they come
   from a fresh preprocessing per run); the model gives the adversary the honest keys of FINISHED sessions
   for free, so it also covers a leak of an old key.
   *)
require import AllCore Int Real List Distr DProd DList StdOrder.
require import PcaSpdz.
import PcaSpdz.F PcaSpdz.F.ZModpField PcaSpdz.F.DZmodP.
import RealOrder.
require import PcaSpdzProto.

(* ------------------------------------------------------------------ *)
(* generic union bound over s sequentially sampled, history-dependent events *)

lemma union_seq ['x] (dx : 'x distr) (eps : real) :
  0%r <= eps =>
  forall (s : int), 0 <= s =>
  forall (Ev : 'x list -> 'x -> bool),
    (forall h, mu dx (Ev h) <= eps) =>
    mu (dlist dx s)
       (fun xs => exists t, 0 <= t /\ t < s /\ Ev (take t xs) (nth witness xs t))
    <= s%r * eps.
proof.
move=> he.
elim/natind => [s hs|s hs ih] hge Ev hb.
+ have -> : s = 0 by smt().
  rewrite dlist0 //.
  have -> : (fun (xs : 'x list) => exists t, 0 <= t /\ t < 0 /\ Ev (take t xs) (nth witness xs t)) = pred0.
  - by apply fun_ext => xs /=; rewrite /pred0 /=; smt().
  by rewrite mu0.
rewrite dlistS // dmapE /(\o) /=.
pose E1 := fun (p : 'x * 'x list) => Ev [] p.`1.
pose E2 := fun (p : 'x * 'x list) =>
  exists t, 0 <= t /\ t < s /\ Ev (p.`1 :: take t p.`2) (nth witness p.`2 t).
have hsub : mu (dx `*` dlist dx s)
      (fun (p : 'x * 'x list) => exists t, 0 <= t /\ t < s + 1 /\ Ev (take t (p.`1 :: p.`2)) (nth witness (p.`1 :: p.`2) t))
    <= mu (dx `*` dlist dx s) (predU E1 E2).
+ apply mu_sub => -[x ys] /=; rewrite /predU /E1 /E2 /=.
  move=> [t [h0 [h1 h2]]].
  case (t = 0) => ht.
  - by left; move: h2; rewrite ht /=.
  - right; exists (t - 1); split; first smt().
    split; first smt().
    move: h2; have -> : (t <= 0) = false by smt().
    by rewrite ht /=.
apply (ler_trans _ _ _ hsub).
apply (ler_trans (mu (dx `*` dlist dx s) E1 + mu (dx `*` dlist dx s) E2)).
+ exact (mu_or_le (dx `*` dlist dx s) E1 E2).
have h1 : mu (dx `*` dlist dx s) E1 <= eps.
+ rewrite /E1 (dprodEl dx (dlist dx s) (Ev [])).
  have := hb [].
  have : weight (dlist dx s) <= 1%r by exact le1_mu.
  have := ge0_mu dx (Ev []).
  have := ge0_weight (dlist dx s).
  smt().
have h2 : mu (dx `*` dlist dx s) E2 <= s%r * eps.
+ apply (mu_dprod_bound dx (dlist dx s) (fun x ys => exists t, 0 <= t /\ t < s /\ Ev (x :: take t ys) (nth witness ys t)) (s%r * eps)).
  - by apply mulr_ge0; smt().
  move=> x /=.
  by apply (ih hs (fun h y => Ev (x :: h) y)) => h; exact (hb (x :: h)).
smt().
qed.

(* ------------------------------------------------------------------ *)
(* the per-session committed-value bound, for a fixed adversary coin    *)

type hon = (env * seed) * (fe * fe).                         (* the honest randomness of one session *)
op dHon : hon distr = (dE `*` dsH) `*` dkey2.
op pmk (w : coin) (x : hon) : ((coin * env) * seed) * (fe * fe) = (((w, x.`1.`1), x.`1.`2), x.`2).

lemma winC_fixed (a : adv) (w0 : coin) :
  mu dHon (fun (x : hon) => winC a (pmk w0 x))
  <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r).
proof.
have hb := inv_pp1_ge0.
pose Vw' := fun (w : env * seed) => Vw a ((w0, w.`1), w.`2).
pose S1' := fun (w : env * seed) => S1w a ((w0, w.`1), w.`2).
pose S2' := fun (w : env * seed) => S2w a ((w0, w.`1), w.`2).
pose T1' := fun (w : env * seed) => T1w a ((w0, w.`1), w.`2).
pose T2' := fun (w : env * seed) => T2w a ((w0, w.`1), w.`2).
have hZZ : mu (dE `*` dsH) (fun w => Vw' w /\ S1' w = zero /\ S2' w = zero)
           <= inv (pp - 1)%r * inv (pp - 1)%r.
+ have h := mu_dprod_bound dE dsH
      (fun e sH => Vw a ((w0, e), sH) /\ S1w a ((w0, e), sH) = zero /\ S2w a ((w0, e), sH) = zero)
      (inv (pp - 1)%r * inv (pp - 1)%r) _ _.
  - by apply mulr_ge0.
  - by move=> e; exact (inner_ZZ a (w0, e)).
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[e sH] /=; rewrite /Vw' /S1' /S2' /=.
have hZ1 : mu (dE `*` dsH) (fun w => Vw' w /\ S1' w = zero) <= inv (pp - 1)%r.
+ have h := mu_dprod_bound dE dsH (fun e sH => Vw a ((w0, e), sH) /\ S1w a ((w0, e), sH) = zero)
      (inv (pp - 1)%r) hb _.
  - by move=> e; exact (inner_Z1 a (w0, e)).
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[e sH] /=; rewrite /Vw' /S1' /=.
have hZ2 : mu (dE `*` dsH) (fun w => Vw' w /\ S2' w = zero) <= inv (pp - 1)%r.
+ have h := mu_dprod_bound dE dsH (fun e sH => Vw a ((w0, e), sH) /\ S2w a ((w0, e), sH) = zero)
      (inv (pp - 1)%r) hb _.
  - by move=> e; exact (inner_Z2 a (w0, e)).
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[e sH] /=; rewrite /Vw' /S2' /=.
have hc := core (dE `*` dsH) Vw' S1' S2' T1' T2' (inv (pp - 1)%r) hb hZZ hZ1 hZ2.
apply (ler_trans _ _ _ _ hc).
rewrite /dHon.
apply mu_sub => -[w aH] /= h.
have := winC_pin a ((w0, w.`1), w.`2) aH h.
by rewrite /Vw' /S1' /S2' /T1' /T2' /=.
qed.

(* ------------------------------------------------------------------ *)
(* s adaptive sessions                                                   *)

type madv = coin -> outc list -> adv.      (* strategy of session t, given the outcomes of sessions 0..t-1 *)

op outsP (A : madv) (w : coin) (pre : outc list) (xs : hon list) : outc list =
  with xs = []        => []
  with xs = x :: xs'  => game (A w pre) (pmk w x) :: outsP A w (rcons pre (game (A w pre) (pmk w x))) xs'.

lemma size_outsP (A : madv) (w : coin) (xs : hon list) :
  forall (pre : outc list), size (outsP A w pre xs) = size xs.
proof.
elim: xs => [|x xs ih] pre /=; first by done.
by rewrite ih.
qed.

lemma nth_outsP (A : madv) (w : coin) (xs : hon list) :
  forall (pre : outc list) (t : int), 0 <= t => t < size xs =>
  nth witness (outsP A w pre xs) t
  = game (A w (pre ++ outsP A w pre (take t xs))) (pmk w (nth witness xs t)).
proof.
elim: xs => [|x xs ih] pre t h0 h1 /=; first by smt(size_ge0).
case (t = 0) => ht.
+ by subst t; rewrite /= cats0.
have e1 : (t <= 0) = false by smt().
rewrite !e1 /=.
rewrite (ih (rcons pre (game (A w pre) (pmk w x))) (t - 1)); 1,2: smt().
by rewrite cat_rcons.
qed.

(* a session whose check passes with a wrong opened value: committed-value event or a commitment break *)
lemma sess_imp (A : madv) (w : coin) (xs : hon list) (t : int) :
  0 <= t => t < size xs =>
  winR (nth witness (outsP A w [] xs) t) =>
  winC (A w (outsP A w [] (take t xs))) (pmk w (nth witness xs t))
  \/ collS (nth witness (outsP A w [] xs) t) \/ collG (nth witness (outsP A w [] xs) t).
proof.
move=> h0 h1 hw.
rewrite (nth_outsP A w xs [] t h0 h1) /= in hw.
rewrite (nth_outsP A w xs [] t h0 h1) /=.
exact (real_imp (A w (outsP A w [] (take t xs))) (pmk w (nth witness xs t)) hw).
qed.

(* ------------------------------------------------------------------ *)
(* the commitment-break finders over s sessions                          *)

op firstS (os : outc list) : (seed * nonce) * (seed * nonce) =
  let o = nth witness os (find collS os) in ((o.`o_mA, o.`o_nA), (o.`o_m2, o.`o_n2)).
op firstG (os : outc list) : (gmsg * nonce) * (gmsg * nonce) =
  let o = nth witness os (find collG os) in ((o.`o_gA, o.`o_nG), (o.`o_g2, o.`o_ng2)).

op brkS (r : (seed * nonce) * (seed * nonce)) : bool =
  r.`1.`1 <> r.`2.`1 /\ comS r.`1.`1 r.`1.`2 = comS r.`2.`1 r.`2.`2.
op brkG (r : (gmsg * nonce) * (gmsg * nonce)) : bool =
  r.`1.`1 <> r.`2.`1 /\ comG r.`1.`1 r.`1.`2 = comG r.`2.`1 r.`2.`2.

lemma firstS_break (os : outc list) : has collS os => brkS (firstS os).
proof.
move=> h; have := nth_find witness collS os h.
by rewrite /brkS /firstS /collS /ok1 /=; smt().
qed.

lemma firstG_break (os : outc list) : has collG os => brkG (firstG os).
proof.
move=> h; have := nth_find witness collG os h.
by rewrite /brkG /firstG /collG /ok2 /=; smt().
qed.

module BSs : BinderS = {
  var ad : madv
  var ns : int
  proc find() : (seed * nonce) * (seed * nonce) = {
    var p : coin * hon list;
    p <$ dcoin `*` dlist dHon BSs.ns;
    return firstS (outsP BSs.ad p.`1 [] p.`2);
  }
}.

module BGs : BinderG = {
  var ad : madv
  var ns : int
  proc find() : (gmsg * nonce) * (gmsg * nonce) = {
    var p : coin * hon list;
    p <$ dcoin `*` dlist dHon BGs.ns;
    return firstG (outsP BGs.ad p.`1 [] p.`2);
  }
}.

lemma bindSs_pr (A : madv) (s : int) &m :
  BSs.ad{m} = A => BSs.ns{m} = s =>
  Pr[BindS(BSs).main() @ &m : res]
  = mu (dcoin `*` dlist dHon s) (fun (p : coin * hon list) => brkS (firstS (outsP A p.`1 [] p.`2))).
proof.
move=> hA hs.
byphoare (_ : BSs.ad = A /\ BSs.ns = s ==> res) => //.
proc; inline *; wp.
rnd; skip => />.
qed.

lemma bindGs_pr (A : madv) (s : int) &m :
  BGs.ad{m} = A => BGs.ns{m} = s =>
  Pr[BindG(BGs).main() @ &m : res]
  = mu (dcoin `*` dlist dHon s) (fun (p : coin * hon list) => brkG (firstG (outsP A p.`1 [] p.`2))).
proof.
move=> hA hs.
byphoare (_ : BGs.ad = A /\ BGs.ns = s ==> res) => //.
proc; inline *; wp.
rnd; skip => />.
qed.

(* ------------------------------------------------------------------ *)
(* the composition theorem                                               *)

lemma seq_soundness (A : madv) (s : int) &m1 &m2 :
  0 <= s =>
  BSs.ad{m1} = A => BSs.ns{m1} = s => BGs.ad{m2} = A => BGs.ns{m2} = s =>
  mu (dcoin `*` dlist dHon s)
     (fun (p : coin * hon list) =>
        exists t, 0 <= t /\ t < s /\ winR (nth witness (outsP A p.`1 [] p.`2) t))
  <= s%r * ((1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r))
     + Pr[BindS(BSs).main() @ &m1 : res] + Pr[BindG(BGs).main() @ &m2 : res].
proof.
move=> hs h1 h2 h3 h4.
rewrite (bindSs_pr A s &m1 h1 h2) (bindGs_pr A s &m2 h3 h4).
pose b := (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r).
have hb0 : 0%r <= b.
+ have g1 := pi_ge0.
  have g2 := inv_pp1_ge0.
  have g3 : 0%r <= 1%r / pp%r + inv (pp - 1)%r by smt().
  by rewrite /b; apply mulr_ge0.
pose D := dcoin `*` dlist dHon s.
pose U1 := fun (p : coin * hon list) =>
  exists t, 0 <= t /\ t < s /\ winC (A p.`1 (outsP A p.`1 [] (take t p.`2))) (pmk p.`1 (nth witness p.`2 t)).
pose U2 := fun (p : coin * hon list) => brkS (firstS (outsP A p.`1 [] p.`2)).
pose U3 := fun (p : coin * hon list) => brkG (firstG (outsP A p.`1 [] p.`2)).
have hU1 : mu D U1 <= s%r * b.
+ apply (mu_dprod_bound dcoin (dlist dHon s)
     (fun w xs => exists t, 0 <= t /\ t < s /\ winC (A w (outsP A w [] (take t xs))) (pmk w (nth witness xs t)))
     (s%r * b)).
  - by apply mulr_ge0; [smt() | exact hb0].
  move=> w /=.
  apply (union_seq dHon b hb0 s hs (fun h x => winC (A w (outsP A w [] h)) (pmk w x))).
  by move=> h; exact (winC_fixed (A w (outsP A w [] h)) w).
have hsub : mu D (fun (p : coin * hon list) => exists t, 0 <= t /\ t < s /\ winR (nth witness (outsP A p.`1 [] p.`2) t))
            <= mu D (predU U1 (predU U2 U3)).
+ pose W := fun (p : coin * hon list) => exists t, 0 <= t /\ t < s /\ winR (nth witness (outsP A p.`1 [] p.`2) t).
  rewrite (mu_eq_support D W (fun p => W p /\ p \in D)).
  - by move=> x hx /=; rewrite hx.
  apply mu_sub => -[w xs] /=.
  rewrite /predU /U1 /U2 /U3 /W /=.
  move=> [[t [h0 [ht hw]]] hsup].
  have hsz : size xs = s.
  - move: hsup; rewrite /D supp_dprod /= => -[_ hx].
    by exact (supp_dlist_size dHon s xs hs hx).
  have hsz2 : size (outsP A w [] xs) = s by rewrite size_outsP.
  have himp := sess_imp A w xs t h0 _ hw; first by smt().
  case himp => [h|[h|h]].
  - by left; exists t.
  - right; left; apply firstS_break; rewrite hasP; exists (nth witness (outsP A w [] xs) t); split; last exact h.
    by apply mem_nth; smt().
  - right; right; apply firstG_break; rewrite hasP; exists (nth witness (outsP A w [] xs) t); split; last exact h.
    by apply mem_nth; smt().
have o1 := mu_or_le D U1 (predU U2 U3).
have o2 := mu_or_le D U2 U3.
smt().
qed.

lemma seq_soundness_num (A : madv) (s : int) &m1 &m2 :
  0 <= s =>
  BSs.ad{m1} = A => BSs.ns{m1} = s => BGs.ad{m2} = A => BGs.ns{m2} = s =>
  mu (dcoin `*` dlist dHon s)
     (fun (p : coin * hon list) =>
        exists t, 0 <= t /\ t < s /\ winR (nth witness (outsP A p.`1 [] p.`2) t))
  <= s%r * ((a60 + 4%r) / (a60 * a60 * a60))
     + Pr[BindS(BSs).main() @ &m1 : res] + Pr[BindG(BGs).main() @ &m2 : res].
proof.
move=> hs h1 h2 h3 h4.
have h := seq_soundness A s &m1 &m2 hs h1 h2 h3 h4.
have hn := mac_num.
have : s%r * ((1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r))
       <= s%r * ((a60 + 4%r) / (a60 * a60 * a60)).
+ apply ler_wpmul2l; [smt() | exact hn].
smt().
qed.
