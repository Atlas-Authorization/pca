(* Prime61.ec -- machine-checked primality of the Mersenne prime 2^61 - 1 (no axiom, no admit).

   Method: a Pratt / Lucas certificate.  From EasyCrypt's own Fermat_little we prove the Lucas criterion
       n > 1,  a^(n-1) = 1 (mod n),  gcd(n, a^e - 1) = 1 for every prime q and e with q*e = n-1
       ==>  prime n,
   then discharge it for n = 2^61 - 1 with generator a = 37, using
       n - 1 = 2 * 3^2 * 5^2 * 7 * 11 * 13 * 31 * 41 * 61 * 151 * 331 * 1321,
   trial division for the twelve small prime factors, a square-and-multiply evaluator (proved
   correct) for the modular powers, and an explicit Bezout identity for each coprimality.
   The certificate (bit strings, residues, Bezout coefficients) was produced by a Python script;
   it is checked, not trusted. *)
require import AllCore IntDiv List Int StdOrder.
import IntOrder.

(* ------------------------------------------------------------------ *)
(* strong induction on the naturals                                      *)

lemma sind (P : int -> bool) :
  (forall k, 0 <= k => (forall j, 0 <= j => j < k => P j) => P k) =>
  forall k, 0 <= k => P k.
proof.
move=> hs.
have h : forall b, 0 <= b => forall k, 0 <= k => k <= b => P k.
+ move=> b; elim/natind: b => b hb.
  - move=> _ k hk0 hk1; apply hs => // j hj0 hj1; smt().
  move=> ih _ k hk0 hk1; apply hs => // j hj0 hj1.
  by apply ih; smt().
by move=> k hk; apply (h k hk k hk) => //.
qed.

(* ------------------------------------------------------------------ *)
(* a prime divisor exists                                                *)

lemma ex_pd (n : int) : 1 < n => exists r, prime r /\ r %| n.
proof.
have : forall k, 0 <= k => 1 < k => exists r, prime r /\ r %| k.
+ apply (sind (fun k => 1 < k => exists r, prime r /\ r %| k)) => k hk ih /= hk1.
  case (prime k) => hp.
  - by exists k; rewrite hp dvdzz.
  have [d [hd [hd1 hd2]]] : exists d, d %| k /\ `|d| <> 1 /\ `|d| <> k.
  + move: hp; rewrite /prime hk1 /= negb_forall /=.
    move=> [d]; rewrite negb_imply /= negb_or /=.
    by move=> [h1 [h2 h3]]; exists d.
  have hd' : `|d| %| k by rewrite dvdz_norml.
  have hle : `|d| <= k by apply dvdn_le => //; smt().
  have hne0 : `|d| <> 0.
  + apply/negP => h0.
    have hd0 : d = 0 by smt().
    have h := hd; rewrite hd0 dvd0z in h; smt().
  have h0d : 0 <= `|d| by smt().
  have hlt : `|d| < k by rewrite ltr_neqAle hd2 hle.
  have h1d : 1 < `|d| by smt().
  have [r [hr hrd]] := ih `|d| h0d hlt h1d.
  by exists r; rewrite hr /=; exact (dvdz_trans `|d| r k hrd hd').
by move=> h hn; apply h; smt().
qed.

(* ------------------------------------------------------------------ *)
(* the order argument, in int arithmetic                                 *)

lemma pw_mod (r a k : int) : 0 <= k => eqm r (a ^ k) 1 =>
  forall t, 0 <= t => eqm r (a ^ (k * t)) 1.
proof.
move=> hk0 hk t; elim/natind: t => t ht.
+ move=> h0.
  have -> : t = 0 by smt().
  by rewrite mulr0 expr0.
move=> ih _.
have ih2 := ih _; first smt().
have e : k * (t + 1) = k * t + k by ring.
rewrite e exprD_nneg 1:/# //.
have := eqmM r _ _ _ _ ih2 hk.
by rewrite mulr1.
qed.

lemma red_mod (r a k m : int) : 0 < k => 0 <= m => eqm r (a ^ m) 1 => eqm r (a ^ k) 1 =>
  eqm r (a ^ (m %% k)) 1.
proof.
move=> hk hm h1 h2.
have hq : 0 <= m %/ k by smt(divz_ge0).
have hr : 0 <= m %% k by smt(modz_ge0).
have e : m = k * (m %/ k) + m %% k by smt(divz_eq).
have h3 := pw_mod r a k _ h2 (m %/ k) hq; first smt().
have h4 : eqm r (a ^ m) (1 * a ^ (m %% k)).
+ have -> : a ^ m = a ^ (k * (m %/ k)) * a ^ (m %% k).
  - rewrite -exprD_nneg; first smt(). exact hr.
    by congr; smt().
  exact (eqmM r _ _ _ _ h3 (eqm_refl r (a ^ (m %% k)))).
rewrite mul1r in h4.
exact (eqm_trans r _ _ _ (eqmC r _ _ h4) h1).
qed.

lemma gcd_ord (r a : int) : forall k, 0 <= k => forall m, 0 <= m =>
  eqm r (a ^ m) 1 => eqm r (a ^ k) 1 => eqm r (a ^ (gcd m k)) 1.
proof.
apply (sind (fun k => forall m, 0 <= m => eqm r (a ^ m) 1 => eqm r (a ^ k) 1 => eqm r (a ^ (gcd m k)) 1)).
move=> k hk ih /= m hm h1 h2.
case (k = 0) => hk0.
+ by rewrite hk0 gcdz0; smt().
have hkp : 0 < k by smt().
have e : gcd m k = gcd k (m %% k) by rewrite gcd_modr gcdC.
rewrite e.
have hj0 : 0 <= m %% k by smt(modz_ge0).
have hj1 : m %% k < k by smt(ltz_pmod).
exact (ih (m %% k) hj0 hj1 k _ h2 (red_mod r a k m hkp hm h1 h2)); smt().
qed.

(* ------------------------------------------------------------------ *)
(* Lucas' criterion                                                      *)

lemma lucas (n a : int) : 1 < n => eqm n (a ^ (n - 1)) 1 =>
  (forall q e, prime q => q * e = n - 1 => coprime n (a ^ e - 1)) => prime n.
proof.
move=> hn1 hf hc.
have [r [hr hrn]] := ex_pd n hn1.
have hr1 : 1 < r by exact gt1_prime.
have hfr : eqm r (a ^ (n - 1)) 1.
+ have e1 := modz_dvd (a ^ (n - 1)) n r hrn.
  have e2 := modz_dvd 1 n r hrn.
  by rewrite -e1 -e2 hf.
have hna : !(r %| a).
+ apply/negP => hra.
  have : r %| a ^ (n - 1).
  - rewrite (_ : n - 1 = (n - 2) + 1) 1:/# exprD_nneg 1:/# // expr1.
    by apply dvdz_mull.
  rewrite dvdzE => h0.
  have : (a ^ (n - 1)) %% r = 1 %% r by exact hfr.
  rewrite h0 modz_small; smt().
have hfe := Fermat_little r a hr hna.
have hfr' : eqm r (a ^ (r - 1)) 1 by move: hfe; rewrite eqz_mod_dvd.
have key : forall g, 0 <= g => g <> 0 => eqm r (a ^ g) 1 => g %| (n - 1) => g = n - 1.
+ move=> g hg0 hgne hg hgd.
  case (g = n - 1) => // hne.
  have gpos : 0 < g by smt().
  have [t ht] : exists t, n - 1 = t * g by apply dvdzP.
  have tpos : 0 < t.
  + have h : 0 < t * g by smt().
    smt(pmulr_rgt0).
  have t1 : t <> 1 by smt().
  have t2 : 1 < t by smt().
  have [q [hq hqt]] := ex_pd t t2.
  have [u hu] : exists u, t = u * q by apply dvdzP.
  have hq1 : 1 < q by exact gt1_prime.
  have upos : 0 < u.
  + have h : 0 < u * q by smt().
    smt(pmulr_lgt0).
  have heq : q * (g * u) = n - 1 by rewrite ht hu; ring.
  have hcq := hc q (g * u) hq heq.
  have hpw := pw_mod r a g hg0 hg u _; first smt().
  have hrd : r %| (a ^ (g * u) - 1).
  + by rewrite eqz_mod_dvd; exact hpw.
  have hcr := coprime_dvdl r n (a ^ (g * u) - 1) hrn hcq.
  have h1 : r %| ((a ^ (g * u) - 1) * 1) by rewrite mulr1.
  have := Gauss r (a ^ (g * u) - 1) 1 h1 hcr.
  rewrite dvdz1; smt().
have hg : eqm r (a ^ gcd (n - 1) (r - 1)) 1.
+ by apply (gcd_ord r a (r - 1) _ (n - 1) _ hfr hfr'); smt().
have hg0 : 0 <= gcd (n - 1) (r - 1) by exact ge0_gcd.
have hgne : gcd (n - 1) (r - 1) <> 0.
+ by rewrite gcd_eq0; smt().
have hgd : gcd (n - 1) (r - 1) %| (n - 1) by exact dvdz_gcdl.
have hgd' : gcd (n - 1) (r - 1) %| (r - 1) by exact dvdz_gcdr.
have hgeq := key _ hg0 hgne hg hgd.
have hrle : n - 1 <= r - 1.
+ by rewrite -hgeq; apply dvdn_le => //; smt().
have hrn' : r <= n by apply dvdn_le => //; smt().
by have -> : n = r by smt(); exact hr.
qed.

(* ------------------------------------------------------------------ *)
(* a checked square-and-multiply evaluator                               *)

op bit (b : bool) : int = if b then 1 else 0.
op vstep (e : int) (b : bool) : int = 2 * e + bit b.
op pstep (n a x : int) (b : bool) : int = (if b then (x * x %% n) * a else x * x) %% n.
op bval (bs : bool list) : int = foldl vstep 0 bs.
op bpow (n a : int) (bs : bool list) : int = foldl (pstep n a) 1 bs.

lemma ev_inv (n a : int) (bs : bool list) : forall e x, 0 <= e => eqm n (a ^ e) x =>
  0 <= foldl vstep e bs /\ eqm n (a ^ (foldl vstep e bs)) (foldl (pstep n a) x bs).
proof.
elim: bs => [|b bs ih] e x he hx /=; first by done.
have he' : 0 <= vstep e b by rewrite /vstep /bit; case b => /#.
apply (ih (vstep e b) (pstep n a x b) he').
rewrite /vstep /pstep /bit.
have hx2 : eqm n (a ^ (2 * e)) (x * x).
+ have -> : a ^ (2 * e) = a ^ e * a ^ e by rewrite (_ : 2 * e = e + e) 1:/# exprD_nneg //.
  exact (eqmM n _ _ _ _ hx hx).
have hxx : eqm n (x * x %% n) (x * x) by rewrite modz_mod.
case b => hb /=.
+ have -> : a ^ (2 * e + 1) = a ^ (2 * e) * a.
  - by rewrite exprSr 1:/#.
  have h3 := eqmM n _ _ _ _ hx2 (eqm_refl n a).
  have h4 := eqmM n _ _ _ _ hxx (eqm_refl n a).
  by rewrite modz_mod; apply (eqm_trans n (x * x * a)); [exact h3 | exact (eqmC n _ _ h4)].
by rewrite modz_mod; exact hx2.
qed.

lemma pow_cert (n a e s : int) (bs : bool list) :
  bval bs = e => bpow n a bs = s => eqm n (a ^ e) s.
proof.
move=> he hs.
have h0 : eqm n (a ^ 0) 1 by rewrite expr0.
have [_ h] := ev_inv n a bs 0 1 (lezz 0) h0.
move: he hs; rewrite /bval /bpow => he hs.
by rewrite -he -hs; exact h.
qed.

lemma cop_cert (n a e s u v : int) (bs : bool list) :
  bval bs = e => bpow n a bs = s => u * n + v * (s - 1) = 1 => coprime n (a ^ e - 1).
proof.
move=> he hs hb.
have h := pow_cert n a e s bs he hs.
have hd : n %| (a ^ e - s) by rewrite eqz_mod_dvd.
have [k hk] : exists k, a ^ e - s = k * n by apply dvdzP.
apply coprimeP.
exists (u - v * k) v.
have : a ^ e - 1 = (s - 1) + k * n by smt().
move=> h2; rewrite h2.
have -> : (u - v * k) * n + v * (s - 1 + k * n) = u * n + v * (s - 1) by ring.
exact hb.
qed.

(* ------------------------------------------------------------------ *)
(* trial division and the factorisation                                  *)

lemma prime_chk (q : int) : 1 < q => all (fun d => q %% d <> 0) (range 2 q) => prime q.
proof.
move=> hq hall; rewrite /prime hq /= => x hx.
have hx' : `|x| %| q by rewrite dvdz_norml.
have hle : `|x| <= q by apply dvdn_le => //; smt().
have hne : `|x| <> 0.
+ apply/negP => h0; have hx0 : x = 0 by smt().
  have h := hx; rewrite hx0 dvd0z in h; smt().
case (`|x| = 1) => // h1; right.
case (`|x| = q) => // h2.
have hin : `|x| \in range 2 q by rewrite mem_range; smt().
have h3 : q %% `|x| <> 0 by move: hall; rewrite allP => h; exact (h _ hin).
have h4 : q %% `|x| = 0 by rewrite -dvdzE; exact hx'.
by move: h3; rewrite h4.
qed.

lemma prime_div_prod (q : int) (l : int list) :
  prime q => q %| foldr Int.( * ) 1 l => exists x, x \in l /\ q %| x.
proof.
move=> hq; elim: l => [|x l ih] /=.

+ have h1 := gt1_prime _ hq.
  apply/negP => h.
  have : `|q| = 1 by rewrite -dvdz1.
  smt().
move=> h.
case (Euclide q x (foldr Int.( * ) 1 l) h hq) => h1.
+ by exists x; rewrite h1.
have [y [hy hqy]] := ih h1.
by exists y; rewrite hy hqy.
qed.

lemma lucas_list (n a : int) (L : int list) : 1 < n => eqm n (a ^ (n - 1)) 1 =>
  foldr Int.( * ) 1 L = n - 1 => (forall x, x \in L => prime x) =>
  (forall x, x \in L => forall e, x * e = n - 1 => coprime n (a ^ e - 1)) => prime n.
proof.
move=> h1 h2 h3 h4 h5.
apply (lucas n a h1 h2).
move=> q e hq hqe.
have hd : q %| foldr Int.( * ) 1 L by rewrite h3; apply dvdzP; exists e; smt().
have [x [hx hqx]] := prime_div_prod q L hq hd.
have hpx := h4 x hx.
have hqx' : q = x.
+ have g1 := gt1_prime _ hq.
  have g2 := gt1_prime _ hpx.
  have h6 : forall d, d %| x => `|d| = 1 \/ `|d| = x by move: hpx; rewrite /prime => -[_ h]; exact h.
  have h7 := h6 q hqx.
  smt().
have hqe2 : x * e = n - 1 by rewrite -hqx'; exact hqe.
exact (h5 x hx e hqe2).
qed.

lemma pr_2 : prime 2 by exact prime2.

lemma cop_3_2 : coprime 3 (2 ^ 1 - 1).
proof.
apply (cop_cert 3 2 1 2 0 1 [true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_3 : prime 3.
proof.
apply (lucas_list 3 2 [2]); first by done.
+ apply (pow_cert 3 2 2 1 [true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 by smt().
  move: hc.
move=> ->; exact pr_2.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 by smt().
  move: hc.
move=> ->. move=> e he; have -> : e = 1 by smt(). exact cop_3_2.
qed.

lemma cop_5_2 : coprime 5 (2 ^ 2 - 1).
proof.
apply (cop_cert 5 2 2 4 (-1) 2 [true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_5 : prime 5.
proof.
apply (lucas_list 5 2 [2; 2]); first by done.
+ apply (pow_cert 5 2 4 1 [true; false; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 by smt().
  move: hc.
move=> ->; exact pr_2.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 by smt().
  move: hc.
move=> ->. move=> e he; have -> : e = 2 by smt(). exact cop_5_2.
qed.

lemma cop_7_2 : coprime 7 (3 ^ 3 - 1).
proof.
apply (cop_cert 7 3 3 6 (-2) 3 [true; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_7_3 : coprime 7 (3 ^ 2 - 1).
proof.
apply (cop_cert 7 3 2 2 0 1 [true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_7 : prime 7.
proof.
apply (lucas_list 7 3 [2; 3]); first by done.
+ apply (pow_cert 7 3 6 1 [true; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 by smt().
  move: hc.
case => [->|]; first exact pr_2.
move=> ->; exact pr_3.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 3 by smt(). exact cop_7_2.
move=> ->. move=> e he; have -> : e = 2 by smt(). exact cop_7_3.
qed.

lemma cop_11_2 : coprime 11 (2 ^ 5 - 1).
proof.
apply (cop_cert 11 2 5 10 (-4) 5 [true; false; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_11_5 : coprime 11 (2 ^ 2 - 1).
proof.
apply (cop_cert 11 2 2 4 (-1) 4 [true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_11 : prime 11.
proof.
apply (lucas_list 11 2 [2; 5]); first by done.
+ apply (pow_cert 11 2 10 1 [true; false; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 5 by smt().
  move: hc.
case => [->|]; first exact pr_2.
move=> ->; exact pr_5.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 5 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 5 by smt(). exact cop_11_2.
move=> ->. move=> e he; have -> : e = 2 by smt(). exact cop_11_5.
qed.

lemma cop_13_2 : coprime 13 (2 ^ 6 - 1).
proof.
apply (cop_cert 13 2 6 12 (-5) 6 [true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_13_3 : coprime 13 (2 ^ 4 - 1).
proof.
apply (cop_cert 13 2 4 3 1 (-6) [true; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_13 : prime 13.
proof.
apply (lucas_list 13 2 [2; 2; 3]); first by done.
+ apply (pow_cert 13 2 12 1 [true; true; false; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 by smt().
  move: hc.
case => [->|]; first exact pr_2.
move=> ->; exact pr_3.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 6 by smt(). exact cop_13_2.
move=> ->. move=> e he; have -> : e = 4 by smt(). exact cop_13_3.
qed.

lemma cop_31_2 : coprime 31 (3 ^ 15 - 1).
proof.
apply (cop_cert 31 3 15 30 (-14) 15 [true; true; true; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_31_3 : coprime 31 (3 ^ 10 - 1).
proof.
apply (cop_cert 31 3 10 25 7 (-9) [true; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_31_5 : coprime 31 (3 ^ 6 - 1).
proof.
apply (cop_cert 31 3 6 16 1 (-2) [true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_31 : prime 31.
proof.
apply (lucas_list 31 3 [2; 3; 5]); first by done.
+ apply (pow_cert 31 3 30 1 [true; true; true; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
move=> ->; exact pr_5.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 15 by smt(). exact cop_31_2.
case => [->|].
+ move=> e he; have -> : e = 10 by smt(). exact cop_31_3.
move=> ->. move=> e he; have -> : e = 6 by smt(). exact cop_31_5.
qed.

lemma cop_41_2 : coprime 41 (6 ^ 20 - 1).
proof.
apply (cop_cert 41 6 20 40 (-19) 20 [true; false; true; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_41_5 : coprime 41 (6 ^ 8 - 1).
proof.
apply (cop_cert 41 6 8 10 2 (-9) [true; false; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_41 : prime 41.
proof.
apply (lucas_list 41 6 [2; 2; 2; 5]); first by done.
+ apply (pow_cert 41 6 40 1 [true; false; true; false; false; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 5 by smt().
  move: hc.
case => [->|]; first exact pr_2.
move=> ->; exact pr_5.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 5 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 20 by smt(). exact cop_41_2.
move=> ->. move=> e he; have -> : e = 8 by smt(). exact cop_41_5.
qed.

lemma cop_61_2 : coprime 61 (2 ^ 30 - 1).
proof.
apply (cop_cert 61 2 30 60 (-29) 30 [true; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_61_3 : coprime 61 (2 ^ 20 - 1).
proof.
apply (cop_cert 61 2 20 47 (-3) 4 [true; false; true; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_61_5 : coprime 61 (2 ^ 12 - 1).
proof.
apply (cop_cert 61 2 12 9 (-3) 23 [true; true; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_61 : prime 61.
proof.
apply (lucas_list 61 2 [2; 2; 3; 5]); first by done.
+ apply (pow_cert 61 2 60 1 [true; true; true; true; false; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
move=> ->; exact pr_5.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 30 by smt(). exact cop_61_2.
case => [->|].
+ move=> e he; have -> : e = 20 by smt(). exact cop_61_3.
move=> ->. move=> e he; have -> : e = 12 by smt(). exact cop_61_5.
qed.

lemma cop_151_2 : coprime 151 (6 ^ 75 - 1).
proof.
apply (cop_cert 151 6 75 150 (-74) 75 [true; false; false; true; false; true; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_151_3 : coprime 151 (6 ^ 50 - 1).
proof.
apply (cop_cert 151 6 50 32 (-8) 39 [true; true; false; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_151_5 : coprime 151 (6 ^ 30 - 1).
proof.
apply (cop_cert 151 6 30 59 5 (-13) [true; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_151 : prime 151.
proof.
apply (lucas_list 151 6 [2; 3; 5; 5]); first by done.
+ apply (pow_cert 151 6 150 1 [true; false; false; true; false; true; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
move=> ->; exact pr_5.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 75 by smt(). exact cop_151_2.
case => [->|].
+ move=> e he; have -> : e = 50 by smt(). exact cop_151_3.
move=> ->. move=> e he; have -> : e = 30 by smt(). exact cop_151_5.
qed.

lemma cop_331_2 : coprime 331 (3 ^ 165 - 1).
proof.
apply (cop_cert 331 3 165 330 (-164) 165 [true; false; true; false; false; true; false; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_331_3 : coprime 331 (3 ^ 110 - 1).
proof.
apply (cop_cert 331 3 110 299 (-9) 10 [true; true; false; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_331_5 : coprime 331 (3 ^ 66 - 1).
proof.
apply (cop_cert 331 3 66 64 4 (-21) [true; false; false; false; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_331_11 : coprime 331 (3 ^ 30 - 1).
proof.
apply (cop_cert 331 3 30 270 (-13) 16 [true; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_331 : prime 331.
proof.
apply (lucas_list 331 3 [2; 3; 5; 11]); first by done.
+ apply (pow_cert 331 3 330 1 [true; false; true; false; false; true; false; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 11 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
case => [->|]; first exact pr_5.
move=> ->; exact pr_11.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 11 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 165 by smt(). exact cop_331_2.
case => [->|].
+ move=> e he; have -> : e = 110 by smt(). exact cop_331_3.
case => [->|].
+ move=> e he; have -> : e = 66 by smt(). exact cop_331_5.
move=> ->. move=> e he; have -> : e = 30 by smt(). exact cop_331_11.
qed.

lemma cop_1321_2 : coprime 1321 (13 ^ 660 - 1).
proof.
apply (cop_cert 1321 13 660 1320 (-659) 660 [true; false; true; false; false; true; false; true; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_1321_3 : coprime 1321 (13 ^ 440 - 1).
proof.
apply (cop_cert 1321 13 440 297 121 (-540) [true; true; false; true; true; true; false; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_1321_5 : coprime 1321 (13 ^ 264 - 1).
proof.
apply (cop_cert 1321 13 264 133 1 (-10) [true; false; false; false; false; true; false; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_1321_11 : coprime 1321 (13 ^ 120 - 1).
proof.
apply (cop_cert 1321 13 120 925 (-263) 376 [true; true; true; true; false; false; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_1321 : prime 1321.
proof.
apply (lucas_list 1321 13 [2; 2; 2; 3; 5; 11]); first by done.
+ apply (pow_cert 1321 13 1320 1 [true; false; true; false; false; true; false; true; false; false; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 11 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
case => [->|]; first exact pr_5.
move=> ->; exact pr_11.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 11 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 660 by smt(). exact cop_1321_2.
case => [->|].
+ move=> e he; have -> : e = 440 by smt(). exact cop_1321_3.
case => [->|].
+ move=> e he; have -> : e = 264 by smt(). exact cop_1321_5.
move=> ->. move=> e he; have -> : e = 120 by smt(). exact cop_1321_11.
qed.

lemma cop_M61_2 : coprime 2305843009213693951 (37 ^ 1152921504606846975 - 1).
proof.
apply (cop_cert 2305843009213693951 37 1152921504606846975 2305843009213693950 (-1152921504606846974) 1152921504606846975 [true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_3 : coprime 2305843009213693951 (37 ^ 768614336404564650 - 1).
proof.
apply (cop_cert 2305843009213693951 37 768614336404564650 1669582390241348315 (-153564881447636741) 212086872990781878 [true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_5 : coprime 2305843009213693951 (37 ^ 461168601842738790 - 1).
proof.
apply (cop_cert 2305843009213693951 37 461168601842738790 725554454131936870 273580622699306902 (-869450890577557429) [true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false; false; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_7 : coprime 2305843009213693951 (37 ^ 329406144173384850 - 1).
proof.
apply (cop_cert 2305843009213693951 37 329406144173384850 1165310750493918737 (-31401830868929937) 62135951423208583 [true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_11 : coprime 2305843009213693951 (37 ^ 209622091746699450 - 1).
proof.
apply (cop_cert 2305843009213693951 37 209622091746699450 2266698407988980144 185261446917471656 (-188460807465984985) [true; false; true; true; true; false; true; false; false; false; true; false; true; true; true; false; true; false; false; false; true; false; true; true; true; false; true; false; false; false; true; false; true; true; true; false; true; false; false; false; true; false; true; true; true; false; true; false; false; false; true; false; true; true; true; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_13 : coprime 2305843009213693951 (37 ^ 177372539170284150 - 1).
proof.
apply (cop_cert 2305843009213693951 37 177372539170284150 1032504562576723207 475784216073654979 (-1062546111941401738) [true; false; false; true; true; true; false; true; true; false; false; false; true; false; false; true; true; true; false; true; true; false; false; false; true; false; false; true; true; true; false; true; true; false; false; false; true; false; false; true; true; true; false; true; true; false; false; false; true; false; false; true; true; true; false; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_31 : coprime 2305843009213693951 (37 ^ 74382032555280450 - 1).
proof.
apply (cop_cert 2305843009213693951 37 74382032555280450 484083891529811867 (-8866865563862607) 42235654463646013 [true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false; false; false; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_41 : coprime 2305843009213693951 (37 ^ 56240073395455950 - 1).
proof.
apply (cop_cert 2305843009213693951 37 56240073395455950 1562651311446036838 (-495307865082657554) 730874616585150915 [true; true; false; false; false; true; true; true; true; true; false; false; true; true; true; false; false; false; false; false; true; true; false; false; false; true; true; true; true; true; false; false; true; true; true; false; false; false; false; false; true; true; false; false; false; true; true; true; true; true; false; false; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_61 : coprime 2305843009213693951 (37 ^ 37800705069076950 - 1).
proof.
apply (cop_cert 2305843009213693951 37 37800705069076950 35184372088832 (-5025725293714) 329365932848850065 [true; false; false; false; false; true; true; false; false; true; false; false; true; false; true; true; true; false; false; false; true; false; true; false; false; true; true; true; true; true; false; true; true; true; true; false; false; true; true; false; true; true; false; true; false; false; false; true; true; true; false; true; false; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_151 : coprime 2305843009213693951 (37 ^ 15270483504726450 - 1).
proof.
apply (cop_cert 2305843009213693951 37 15270483504726450 1433721343585656393 (-42426085906839089) 68233547637592170 [true; true; false; true; true; false; false; true; false; false; false; false; false; false; false; true; true; false; true; true; false; false; true; false; false; false; false; false; false; false; true; true; false; true; true; false; false; true; false; false; false; false; false; false; false; true; true; false; true; true; false; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_331 : coprime 2305843009213693951 (37 ^ 6966293079195450 - 1).
proof.
apply (cop_cert 2305843009213693951 37 6966293079195450 185945230422323302 27860676671362963 (-345490693085897212) [true; true; false; false; false; true; false; true; true; true; true; true; true; true; true; false; false; true; true; true; false; true; false; false; false; false; false; false; false; false; true; true; false; false; false; true; false; true; true; true; true; true; true; true; true; false; false; true; true; true; false; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma cop_M61_1321 : coprime 2305843009213693951 (37 ^ 1745528394559950 - 1).
proof.
apply (cop_cert 2305843009213693951 37 1745528394559950 30210013857155493 1832177841764983 (-139844837147248146) [true; true; false; false; false; true; true; false; false; true; true; true; false; false; false; true; true; false; false; false; true; true; true; true; true; true; true; true; true; true; false; false; true; true; true; false; false; true; true; false; false; false; true; true; true; false; false; true; true; true; false]).
+ by rewrite /bval /vstep /bit /=.
+ by rewrite /bpow /pstep /=.
by rewrite /=.
qed.

lemma pr_M61 : prime 2305843009213693951.
proof.
apply (lucas_list 2305843009213693951 37 [2; 3; 3; 5; 5; 7; 11; 13; 31; 41; 61; 151; 331; 1321]); first by done.
+ apply (pow_cert 2305843009213693951 37 2305843009213693950 1 [true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; true; false]).
  - by rewrite /bval /vstep /bit /=.
  - by rewrite /bpow /pstep /=.
+ by rewrite /=.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 7 \/ x = 11 \/ x = 13 \/ x = 31 \/ x = 41 \/ x = 61 \/ x = 151 \/ x = 331 \/ x = 1321 by smt().
  move: hc.
case => [->|]; first exact pr_2.
case => [->|]; first exact pr_3.
case => [->|]; first exact pr_5.
case => [->|]; first exact pr_7.
case => [->|]; first exact pr_11.
case => [->|]; first exact pr_13.
case => [->|]; first exact pr_31.
case => [->|]; first exact pr_41.
case => [->|]; first exact pr_61.
case => [->|]; first exact pr_151.
case => [->|]; first exact pr_331.
move=> ->; exact pr_1321.
+ move=> x; rewrite /= => hx.
  have hc : x = 2 \/ x = 3 \/ x = 5 \/ x = 7 \/ x = 11 \/ x = 13 \/ x = 31 \/ x = 41 \/ x = 61 \/ x = 151 \/ x = 331 \/ x = 1321 by smt().
  move: hc.
case => [->|].
+ move=> e he; have -> : e = 1152921504606846975 by smt(). exact cop_M61_2.
case => [->|].
+ move=> e he; have -> : e = 768614336404564650 by smt(). exact cop_M61_3.
case => [->|].
+ move=> e he; have -> : e = 461168601842738790 by smt(). exact cop_M61_5.
case => [->|].
+ move=> e he; have -> : e = 329406144173384850 by smt(). exact cop_M61_7.
case => [->|].
+ move=> e he; have -> : e = 209622091746699450 by smt(). exact cop_M61_11.
case => [->|].
+ move=> e he; have -> : e = 177372539170284150 by smt(). exact cop_M61_13.
case => [->|].
+ move=> e he; have -> : e = 74382032555280450 by smt(). exact cop_M61_31.
case => [->|].
+ move=> e he; have -> : e = 56240073395455950 by smt(). exact cop_M61_41.
case => [->|].
+ move=> e he; have -> : e = 37800705069076950 by smt(). exact cop_M61_61.
case => [->|].
+ move=> e he; have -> : e = 15270483504726450 by smt(). exact cop_M61_151.
case => [->|].
+ move=> e he; have -> : e = 6966293079195450 by smt(). exact cop_M61_331.
move=> ->. move=> e he; have -> : e = 1745528394559950 by smt(). exact cop_M61_1321.
qed.

lemma pow2_61 : 2 ^ 61 = 2305843009213693952 by ring.

lemma prime_M61 : prime (2 ^ 61 - 1).
proof. have -> : 2 ^ 61 - 1 = 2305843009213693951 by rewrite pow2_61. exact pr_M61. qed.
