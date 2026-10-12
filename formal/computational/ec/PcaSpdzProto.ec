(* PcaSpdzProto.ec -- the multi-phase SPDZ MAC-check game: protocol ORDERING and MAC-KEY SECRECY,
   and the end-to-end soundness theorem with two independent keys.

   Protocol modelled (packages/pca-mpc/src/net/protocol.ts openMany / coin / sig-c / sig-o, and
   src/spdz.ts macResiduals / macCheck):
     phase 1  the values are opened and broadcast; the corrupt coalition adds an error vector `dl`
              to the broadcast values (and chooses its MAC shares and key shares).
     phase 2  coin flip: every party commits to a seed, all commitments are exchanged, seeds are
              opened; the joint seed gives the public challenge vector r^(l) per key l = 1,2.
     phase 3  each party commits to its residual shares sigma^(l) = <r^(l), gamma^(l)> - alpha^(l) a^(l),
              the commitments are exchanged, then opened; the check is  sum of all parties' sigma^(l) = 0
              for BOTH keys.

   What is proved (all with Alt-Ergo/Z3/CVC5 behind EasyCrypt, no admit):
     (a) ORDERING  `real_imp`, `bindS_pr`, `bindG_pr`, `soundness`.
         `dl` is a function of the adversary's coins alone (it is fixed before any honest seed exists,
         let alone the challenge).  The two ways to change a committed value after seeing more -- open
         the coin-flip seed differently from what was committed (to steer r after seeing the honest
         seed), or open the residual shares differently (to match the honest residual after seeing it)
         -- each yield, as soon as the verifier accepts an opening that differs from the committed
         one, a pair of different openings of one commitment string: a break of binding. The explicit
         collision finders are the modules BS and BG; their success probabilities are the advantage
         terms.  Without such a break the run is the one in which committed values were used.
     (b) KEY SECRECY  `key_secret`, `alpha_uniform`, `open_form`, `no_leak`, `leak`.
         The honest coalition's key shares are independent of EVERYTHING the adversary sees before the
         honest residual is opened (statistical distance 0 between the real pair (view, key) and the
         product of the marginals); the global key alpha = alpha_H + alpha_A is exactly uniform given
         the view, for every view event, and the two keys are independent.  After the opening, the
         honest residual is c - alpha_H * s with c a function of the view and s = <r, dl>: it leaks
         nothing when s = 0, and determines alpha_H when s <> 0 -- which is exactly the event that
         the soundness bound charges at 1/p.
     (c) SOUNDNESS  `soundness`, `soundness_num`.  For every adversary strategy `a` (any function of
         its coins and of everything it has received, i.e. any possibly randomised interactive
         adversary; no computational bound is needed for the information-theoretic part),
           Pr[some opened value is wrong (dl <> 0) and every check passes]
              <=  (1/p + 1/(p-1))^2  +  Pr[BindS(BS)]  +  Pr[BindG(BG)]
         and at p = 2^61 - 1 the first term is at most (2^60 + 4)/2^180 = 2^-120 (1 + 2^-58).
         The proof: the pass condition is  alpha_H^(l) * s_l = t_l  for l = 1,2 where s_l = <r_l, dl>
         and t_l depends on the view, not on alpha_H; for s_l <> 0 that pins alpha_H^(l) to one value
         (probability 1/p over the hidden key); for s_l = 0 the error vector was orthogonal to the
         challenge, which has probability at most 1/(p-1) because dl was fixed before the challenge and
         the challenge is uniform on nonzero vectors for any corrupt seed (`comb_unif`, `lin_bound`).
         The four cases are combined with the independence of the two keys and of the two challenge
         vectors (`core`).

   ASSUMPTIONS, listed:
     * structural:  `nm_ge0` (the batch size is nonnegative).  Nothing is assumed about dcoin, dn
       (arbitrary sub-distributions are covered), the commitment functions comS/comG, or the adversary.
     * binding of the two commitment functions is NOT an axiom: it is the premise (the two Pr terms).
       Instantiating it by SHA-256 collision resistance is a paper step.
     * the primality and the value of the modulus come from PcaSpdz (prime_pp, and for the number
       `pp_M61`), unchanged.

   MODEL-VERSUS-CODE GAPS (what this file abstracts):
     1. Network: reliable delivery and broadcast with echo are assumed (the code has the echo rounds
        and a transcript digest); a corrupt party that equivocates is not modelled, an opening that
        does not verify is simply a failed check.
     2. Commitments are modelled by two abstract functions comS/comG (sha256 with session id, party id,
        label and, for sigma, a 32-byte nonce, in the code).  BINDING is handled with an explicit
        reduction.  HIDING is IDEAL: the commitment string the adversary sees for the honest value is
        computed from a fresh nonce and a fixed dummy message, so it is independent of the honest seed
        and of the honest residual; the honest values are sampled independently and revealed only at
        the opening.  The real SHA-256 commitment hides only computationally (and in the code the seed
        commitment has no separate nonce: the 32-byte seed is the secret).  This idealisation is now
        bridged by PcaCommitROM.ec (hiding of H(m||r) in the ROM, |Pr[Real_0]-Pr[Real_1]| <= 2 q pmax,
        pmax = 2^-256) through a hiding reduction described in computational-proofs.md 5f.
     3. EXTRACTABILITY / non-malleability: the corrupt party's committed value is fixed at commit time
        (the game forms the commitment from the adversary's chosen value and nonce).  An adversary that
        outputs a commitment string without knowing an opening (for instance a copy of the honest one)
        is not modelled; in the code the party id and session id inside the hash block copying.
     4. Challenge derivation: the code hashes all seeds to a joint seed and expands it with SHA-256 to
        challenge field elements (challenge(joint, label, j)).  The model combines the honest seed with
        the corrupt seed coordinatewise by multiplying by the (nonzero-ized) corrupt coordinate, so the
        challenge is exactly uniform on nonzero vectors whatever the corrupt seed is; the hash expansion
        is the random-oracle idealisation of this.  The two keys use independent coordinates of the
        seed (the code uses distinct labels).
     5. One honest coalition: all honest parties are merged into one party with the sum of their
        shares and seeds (valid because only their sums enter the check; at least one honest party
        is needed so that the key share is uniform). Static corruption.
     6. The OT / dealer preprocessing that produces the shares is abstracted: the corrupt coalition
        chooses the true values x, its MAC shares and its key shares freely (a superset of the real
        distributions); the honest MAC shares are then the consistent complement alpha*x - gamma_A,
        the honest key share is uniform and independent of everything chosen (dealer honesty, or the
        OT protocol's own key-secrecy and selective-failure bounds, which are NOT proved here).
     7. Corrupt residual shares are an arbitrary function of the view (this covers every error in the
        corrupt MAC shares or in its own residual computation).
     8. One MAC-check per run; the abort ends the session (no key reuse after an abort), so the leak
        in (b3) is harmless only because of that; composition across sessions is PcaSpdzSeq.ec (s * bound + binding); the sacrifice
        step and the aborts' identification are not modelled here (the sacrifice is in PcaSpdz).
     9. Field arithmetic is exact, no side channels, no timing.
   *)
require import AllCore StdRing StdOrder Distr DProd DList Dexcepted List Real Int IntDiv.
require import PcaSpdz.
import PcaSpdz.F PcaSpdz.F.ZModpField PcaSpdz.F.DZmodP.
import RField RealOrder.

(* ------------------------------------------------------------------ *)
(* generic probability lemmas                                            *)

lemma mu_or_le ['a] (d : 'a distr) (p q : 'a -> bool) :
  mu d (predU p q) <= mu d p + mu d q.
proof. by rewrite mu_or; smt(ge0_mu). qed.

(* gating: if C w  =>  mu dX (B w) <= rho, then the mass of {C w /\ B w x} is <= rho * mu dW C *)
lemma mu_gate ['w 'x] (dW : 'w distr) (dX : 'x distr) (C : 'w -> bool) (B : 'w -> 'x -> bool) (rho : real) :
  0%r <= rho => (forall w, C w => mu dX (B w) <= rho) =>
  mu (dW `*` dX) (fun (p : 'w * 'x) => C p.`1 /\ B p.`1 p.`2) <= rho * mu dW C.
proof.
move=> hr hb.
rewrite dprod_partition muE -RealSeries.sumZ.
apply RealSeries.ler_sum_pos.
+ move=> w /=; split.
  - by apply mulr_ge0; [apply ge0_mu | apply ge0_mu1].
  case (C w) => hC /=.
  - have h1 : mu dX (fun x => B w x) <= rho by exact (hb w hC).
    have h2 := ge0_mu1 dW w.
    have : mu dX (fun x => B w x) * mu1 dW w <= rho * mu1 dW w by apply ler_wpmul2r.
    smt().
  - have h0 := mu0 dX.
    rewrite /pred0 /= in h0.
    by rewrite h0 /=; smt(ge0_mu1).
+ apply RealSeries.summableZ.
  by apply RealSeries.summable_cond; exact summable_mu1.
qed.

(* nested bound: a bound that holds for every first coordinate bounds the product *)
lemma mu_dprod_bound ['w 'x] (dW : 'w distr) (dX : 'x distr) (E : 'w -> 'x -> bool) (r : real) :
  0%r <= r => (forall w, mu dX (E w) <= r) =>
  mu (dW `*` dX) (fun (p : 'w * 'x) => E p.`1 p.`2) <= r.
proof.
move=> hr hb.
have := mu_gate dW dX predT E r hr _.
+ by move=> w _; exact (hb w).
move=> h.
have h2 : mu dW predT <= 1%r by exact le1_mu.
have h3 : r * mu dW predT <= r by smt(ge0_mu).
apply (ler_trans (r * mu dW predT)); last exact h3.
apply (ler_trans _ _ _ _ h); apply mu_sub => p /=; smt().
qed.

lemma pi_ge0 : 0%r <= 1%r / pp%r.
proof. by apply divr_ge0; smt(pp_gt1). qed.

(* a nonzero coefficient pins a uniform scalar to one value: mass 1/p *)
lemma single_pin (S T : fe) :
  S <> zero => mu dt (fun a => a * S = T) <= 1%r / pp%r.
proof.
move=> hS.
apply (ler_trans (mu dt (pred1 (T / S)))).
+ apply mu_sub => a h.
  rewrite /pred1; move: h => /= h; rewrite -h; field; exact hS.
by rewrite dt_mu1.
qed.

(* ------------------------------------------------------------------ *)
(* linearity of the inner product (used to derive the honest residual)  *)

op vadd (u w : fe list) : fe list = map (fun (p : fe * fe) => p.`1 + p.`2) (zip u w).
op vgam (al : fe) (xs ga : fe list) : fe list = map (fun (p : fe * fe) => al * p.`1 - p.`2) (zip xs ga).

lemma dot_vadd (r u w : fe list) :
  size u = size w => dot r (vadd u w) = dot r u + dot r w.
proof.
elim: r u w => [|x xs ih] u w hs.
+ by rewrite !dot_nil_l; ring.
case: u hs => [|y us] hs.
+ have -> : w = [] by smt(size_eq0).
  by rewrite /vadd zip0l /= !dot_nil_r; ring.
case: w hs => [|z ws] hs; first by smt(size_ge0).
have hs' : size us = size ws by smt().
rewrite /vadd /= -/(vadd us ws) !dot_cons (ih us ws hs').
ring.
qed.

lemma dot_vgam (r : fe list) (al : fe) (xs ga : fe list) :
  size xs = size ga => dot r (vgam al xs ga) = al * dot r xs - dot r ga.
proof.
elim: r xs ga => [|x r' ih] xs ga hs.
+ by rewrite !dot_nil_l; ring.
case: xs hs => [|y ys] hs.
+ have -> : ga = [] by smt(size_eq0).
  by rewrite /vgam zip0l /= !dot_nil_r; ring.
case: ga hs => [|z zs] hs; first by smt(size_ge0).
have hs' : size ys = size zs by smt().
rewrite /vgam /= -/(vgam al ys zs) !dot_cons (ih ys zs hs').
ring.
qed.

(* ------------------------------------------------------------------ *)
(* the honest residual share, and its algebraic form                    *)

(* honest party's sigma for one key: its MAC shares are alpha*x - gammaA (consistent sharing of
   alpha*x with the coalition's gammaA), it sees the opened values x + delta, and its key share is aH;
   alpha = aH + aA.   sigma_H = <r, gammaH> - aH * <r, x + delta>                              *)
op sigH (xs dl ga : fe list) (aA aH : fe) (r : fe list) : fe =
  dot r (vgam (aH + aA) xs ga) - aH * dot r (vadd xs dl).

lemma sigH_form (xs dl ga : fe list) (aA aH : fe) (r : fe list) :
  size xs = size ga => size xs = size dl =>
  sigH xs dl ga aA aH r = (aA * dot r xs - dot r ga) - aH * dot r dl.
proof.
move=> h1 h2.
rewrite /sigH (dot_vgam r (aH + aA) xs ga h1) (dot_vadd r xs dl h2).
ring.
qed.

(* ------------------------------------------------------------------ *)
(* the joint challenge: honest seed combined with the (arbitrary) corrupt seed, coordinatewise *)

op nz (c : fe) : fe = if c = zero then one else c.

lemma nz_ne0 (c : fe) : nz c <> zero.
proof. by rewrite /nz; case (c = zero) => h; smt(ZModpField.oner_neq0). qed.

op comb (xs cs : fe list) : fe list =
  with xs = []        => []
  with xs = x :: xs'  => (x * nz (head one cs)) :: comb xs' (behead cs).

lemma dstar1E (x : fe) :
  mu1 dstar x = if x = zero then 0%r else (1%r / pp%r) / (1%r - 1%r / pp%r).
proof.
rewrite /dstar dexcepted1E.
case (pred1 zero x) => h.
+ have hx : x = zero by smt().
  by rewrite hx /pred1 /=.
have hx : x <> zero by smt().
rewrite dt_mu1 (is_losslessP _ dt_ll).
have -> : mu dt (pred1 zero) = 1%r / pp%r by exact dt_mu1.
by rewrite hx.
qed.

lemma scale_dstar (k : fe) : k <> zero => dmap dstar (fun x => x * k) = dstar.
proof.
move=> hk.
apply eq_distr => y.
rewrite (dmap1E_can dstar (fun x => x * k) (fun y => y / k) y).
+ by move=> x /=; field; exact hk.
+ by move=> x _ /=; field; exact hk.
rewrite !dstar1E.
have -> : (y / k = zero) <=> (y = zero).
+ split => h; first by smt(ZModpField.mulf_eq0 ZModpField.invr_eq0).
  by rewrite h; ring; smt(ZModpField.mul0r).
done.
qed.

lemma comb_unif (m : int) : 0 <= m =>
  forall (cs : fe list), dmap (dlist dstar m) (fun xs => comb xs cs) = dlist dstar m.
proof.
elim/natind: m => [m hm|m hm ih] hge cs.
+ have -> : m = 0 by smt().
  have e : dlist dstar 0 = dunit [] by rewrite dlist0.
  by rewrite e dmap_dunit /=.
rewrite dlistS // dmap_comp.
have -> : ((fun xs => comb xs cs) \o (fun (xy : fe * fe list) => xy.`1 :: xy.`2))
        = ((fun (xy : fe * fe list) => xy.`1 :: xy.`2)
           \o (fun (xy : fe * fe list) => (xy.`1 * nz (head one cs), comb xy.`2 (behead cs)))).
+ by apply fun_ext => -[x xs] /=; rewrite /(\o) /=.
rewrite -dmap_comp.
have -> : dmap (dstar `*` dlist dstar m)
               (fun (xy : fe * fe list) => (xy.`1 * nz (head one cs), comb xy.`2 (behead cs)))
          = dstar `*` dlist dstar m.
+ rewrite -(dmap_dprod dstar (dlist dstar m) (fun x => x * nz (head one cs)) (fun xs => comb xs (behead cs))).
  by rewrite (scale_dstar (nz (head one cs)) (nz_ne0 (head one cs))) (ih hm (behead cs)).
done.
qed.

(* ================================================================== *)
(* THE MODEL                                                             *)
(* ================================================================== *)

type coin.                      (* the adversary's coins; any strategy is a function of them *)
op dcoin : coin distr.
type nonce.
op dn : nonce distr.
type cm.                        (* commitment strings *)
op nm : int.                    (* number of opened values in the batch *)
axiom nm_ge0 : 0 <= nm.

type seed = fe list * fe list.  (* a coin-flip contribution: one challenge seed vector per key *)
type gmsg = fe * fe.            (* a residual-share contribution, one per key *)

op comS : seed -> nonce -> cm.  (* commitment to a coin-flip seed   (sha('seed', session, label, id, seed)) *)
op comG : gmsg -> nonce -> cm.  (* commitment to residual shares     (sha('sigma', session, id, sigmas, nonce)) *)
op seed0 : seed = ([], []).
op g00 : gmsg = (zero, zero).

op dsH : seed distr = dlist dstar nm `*` dlist dstar nm.     (* the honest coalition's contribution *)
op dkey2 : (fe * fe) distr = dt `*` dt.                        (* its two MAC-key shares alpha_H^(1), alpha_H^(2) *)

(* what the adversary chooses in phase 1: the true values of the batch (x), the corrupt coalition's
   MAC shares on them per key (ga1, ga2), its key shares (aA), and the ERRORS it adds to the broadcast
   opened values (dl). *)
type sdata = { xs : fe list; ga1 : fe list; ga2 : fe list; aA : fe * fe; dl : fe list }.

(* an adversary strategy: every message is a deterministic function of its coins and of everything
   it has received so far (any randomised interactive adversary is such a function of its coins). *)
type adv = {
  a_setup : coin -> sdata;                                                    (* phase 1 *)
  a_sc    : coin -> cm -> seed * nonce;                                       (* phase 2: commit own seed, having seen the honest commitment string *)
  a_so    : coin -> cm -> seed -> nonce -> seed * nonce;                      (* phase 2: opening presented after seeing the honest opening *)
  a_gc    : coin -> cm -> seed -> nonce -> seed -> cm -> gmsg * nonce;        (* phase 3: commit residuals, having seen the challenge r *)
  a_go    : coin -> cm -> seed -> nonce -> seed -> cm -> gmsg -> nonce -> gmsg * nonce;  (* phase 3: opening, after seeing the honest residual *)
}.

type env = ((nonce * nonce) * nonce) * nonce.
op dE : env distr = dn `*` dn `*` dn `*` dn.
op e_nd  (e : env) : nonce = e.`1.`1.`1.   (* nonce of the honest seed-commitment string shown before the opening *)
op e_nH  (e : env) : nonce = e.`1.`1.`2.   (* nonce opened with the honest seed *)
op e_ng  (e : env) : nonce = e.`1.`2.      (* nonce of the honest residual-commitment string shown before the opening *)
op e_nGo (e : env) : nonce = e.`2.         (* nonce opened with the honest residual *)

type outc = {
  o_d : sdata; o_cH : cm; o_mA : seed; o_nA : nonce; o_sH : seed; o_nH : nonce;
  o_m2 : seed; o_n2 : nonce; o_r : seed; o_cGH : cm; o_gA : gmsg; o_nG : nonce;
  o_aH : fe * fe; o_sg : fe * fe; o_g2 : gmsg; o_ng2 : nonce
}.

op valid (d : sdata) : bool =
  size d.`xs = nm /\ size d.`ga1 = nm /\ size d.`ga2 = nm /\ size d.`dl = nm.
op nzv (l : fe list) : bool = exists x, x \in l /\ x <> zero.

op chal (sH : seed) (c : seed) : seed = (comb sH.`1 c.`1, comb sH.`2 c.`2).

(* the whole execution as a function of the adversary, its coins and ALL the honest randomness.
   Information flow is the order of evaluation: delta (inside d) depends on w only; the
   honest commitment strings depend on fresh nonces only (ideal hiding); the corrupt commitments
   come before the honest openings are used; r depends on the OPENED corrupt seed. *)
op run (a : adv) (w : coin) (e : env) (sH : seed) (aH : fe * fe) : outc =
  let d   = a_setup a w in
  let cH  = comS seed0 (e_nd e) in
  let mA  = a_sc a w cH in
  let mo  = a_so a w cH sH (e_nH e) in
  let r   = chal sH mo.`1 in
  let cGH = comG g00 (e_ng e) in
  let gA  = a_gc a w cH sH (e_nH e) r cGH in
  let sg  = (sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 r.`1, sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 r.`2) in
  let go  = a_go a w cH sH (e_nH e) r cGH sg (e_nGo e) in
  {| o_d = d; o_cH = cH; o_mA = mA.`1; o_nA = mA.`2; o_sH = sH; o_nH = e_nH e;
     o_m2 = mo.`1; o_n2 = mo.`2; o_r = r; o_cGH = cGH; o_gA = gA.`1; o_nG = gA.`2;
     o_aH = aH; o_sg = sg; o_g2 = go.`1; o_ng2 = go.`2 |}.

op dTop : (coin * env) distr = dcoin `*` dE.
op dAll : (((coin * env) * seed) * (fe * fe)) distr = (dTop `*` dsH) `*` dkey2.

op game (a : adv) (p : ((coin * env) * seed) * (fe * fe)) : outc =
  run a p.`1.`1.`1 p.`1.`1.`2 p.`1.`2 p.`2.
op dgame (a : adv) : outc distr = dmap dAll (game a).

(* the verdicts *)
op ok1 (o : outc) : bool = comS o.`o_m2 o.`o_n2 = comS o.`o_mA o.`o_nA.
op ok2 (o : outc) : bool = comG o.`o_g2 o.`o_ng2 = comG o.`o_gA o.`o_nG.
(* all verifier checks that matter pass, while an opened value was wrong *)
op winR (o : outc) : bool =
  valid o.`o_d /\ nzv o.`o_d.`dl /\ ok1 o /\ ok2 o /\
  o.`o_sg.`1 + o.`o_g2.`1 = zero /\ o.`o_sg.`2 + o.`o_g2.`2 = zero.
(* a corrupt party opened to something other than what it committed to, and the opening verifies *)
op collS (o : outc) : bool = o.`o_m2 <> o.`o_mA /\ ok1 o.
op collG (o : outc) : bool = o.`o_g2 <> o.`o_gA /\ ok2 o.

(* the same event computed with the COMMITTED corrupt values (the seed and residuals fixed at commit time) *)
op rC (a : adv) (top : coin * env) (sH : seed) : seed =
  chal sH (a_sc a top.`1 (comS seed0 (e_nd top.`2))).`1.

op winC (a : adv) (p : ((coin * env) * seed) * (fe * fe)) : bool =
  let top = p.`1.`1 in
  let sH  = p.`1.`2 in
  let aH  = p.`2 in
  let o   = game a p in
  let d   = o.`o_d in
  let r   = rC a top sH in
  valid d /\ nzv d.`dl /\
  sigH d.`xs d.`dl d.`ga1 d.`aA.`1 aH.`1 r.`1 + o.`o_gA.`1 = zero /\
  sigH d.`xs d.`dl d.`ga2 d.`aA.`2 aH.`2 r.`2 + o.`o_gA.`2 = zero.

(* ORDERING (a), pointwise: if the real verifier accepts, then either the corrupt party opened its
   seed or residuals differently from what it committed to (a binding break), or the run is
   exactly the one in which the committed values were used. *)
lemma real_imp (a : adv) (p : ((coin * env) * seed) * (fe * fe)) :
  winR (game a p) => winC a p \/ collS (game a p) \/ collG (game a p).
proof.
rewrite /winR /collS /collG /ok1 /ok2 /winC /game /run /rC /=.
move=> [hv [hn [h1 [h2 [e1 e2]]]]].
case ((a_so a p.`1.`1.`1 (comS seed0 (e_nd p.`1.`1.`2)) p.`1.`2 (e_nH p.`1.`1.`2)).`1
      = (a_sc a p.`1.`1.`1 (comS seed0 (e_nd p.`1.`1.`2))).`1) => hS; last by smt().
smt().
qed.

(* ------------------------------------------------------------------ *)
(* the two-key accounting, for any distribution of the adversary-side data w           *)

lemma w_dt : weight dt = 1%r by exact (is_losslessP _ dt_ll).

lemma core ['w] (dW : 'w distr) (V : 'w -> bool) (S1 S2 T1 T2 : 'w -> fe) (b : real) :
  0%r <= b =>
  mu dW (fun w => V w /\ S1 w = zero /\ S2 w = zero) <= b * b =>
  mu dW (fun w => V w /\ S1 w = zero) <= b =>
  mu dW (fun w => V w /\ S2 w = zero) <= b =>
  mu (dW `*` dkey2)
     (fun (p : 'w * (fe * fe)) => V p.`1 /\ p.`2.`1 * S1 p.`1 = T1 p.`1 /\ p.`2.`2 * S2 p.`1 = T2 p.`1)
  <= (1%r / pp%r + b) * (1%r / pp%r + b).
proof.
move=> hb hzz hz1 hz2.
have ha := pi_ge0.
pose G1 := fun (p : 'w * (fe * fe)) => (V p.`1 /\ S1 p.`1 = zero /\ S2 p.`1 = zero) /\ true.
pose G2 := fun (p : 'w * (fe * fe)) => (V p.`1 /\ S1 p.`1 = zero /\ S2 p.`1 <> zero) /\ p.`2.`2 * S2 p.`1 = T2 p.`1.
pose G3 := fun (p : 'w * (fe * fe)) => (V p.`1 /\ S1 p.`1 <> zero /\ S2 p.`1 = zero) /\ p.`2.`1 * S1 p.`1 = T1 p.`1.
pose G4 := fun (p : 'w * (fe * fe)) => (V p.`1 /\ S1 p.`1 <> zero /\ S2 p.`1 <> zero) /\
             (p.`2.`1 * S1 p.`1 = T1 p.`1 /\ p.`2.`2 * S2 p.`1 = T2 p.`1).
have hsub : mu (dW `*` dkey2)
     (fun (p : 'w * (fe * fe)) => V p.`1 /\ p.`2.`1 * S1 p.`1 = T1 p.`1 /\ p.`2.`2 * S2 p.`1 = T2 p.`1)
   <= mu (dW `*` dkey2) (predU (predU G1 G2) (predU G3 G4)).
+ by apply mu_sub => p /=; rewrite /predU /G1 /G2 /G3 /G4 /=; smt().
have hor1 := mu_or_le (dW `*` dkey2) (predU G1 G2) (predU G3 G4).
have hor2 := mu_or_le (dW `*` dkey2) G1 G2.
have hor3 := mu_or_le (dW `*` dkey2) G3 G4.
(* G1 *)
have h1 : mu (dW `*` dkey2) G1 <= b * b.
+ have := mu_gate dW dkey2 (fun w => V w /\ S1 w = zero /\ S2 w = zero) (fun (w : 'w) (x : fe * fe) => true) 1%r _ _.
  - by done.
  - by move=> w _; exact le1_mu.
  move=> h; apply (ler_trans _ _ _ h).
  by smt().
(* G2 *)
have h2 : mu (dW `*` dkey2) G2 <= (1%r / pp%r) * b.
+ have := mu_gate dW dkey2 (fun w => V w /\ S1 w = zero /\ S2 w <> zero) (fun (w : 'w) (x : fe * fe) => x.`2 * S2 w = T2 w) (1%r / pp%r) ha _.
  - move=> w [_ [_ hs]] /=.
    have e : mu dkey2 (fun (x : fe * fe) => x.`2 * S2 w = T2 w) = mu dt (fun y => y * S2 w = T2 w) * weight dt.
    + by rewrite /dkey2; exact (dprodEr dt dt (fun y => y * S2 w = T2 w)).
    by rewrite e w_dt mulr1; exact (single_pin (S2 w) (T2 w) hs).
  move=> h; apply (ler_trans _ _ _ h).
  have : mu dW (fun w => V w /\ S1 w = zero /\ S2 w <> zero) <= b.
  - by apply (ler_trans _ _ _ _ hz1); apply mu_sub => w /=; smt().
  by smt().
(* G3 *)
have h3 : mu (dW `*` dkey2) G3 <= (1%r / pp%r) * b.
+ have := mu_gate dW dkey2 (fun w => V w /\ S1 w <> zero /\ S2 w = zero) (fun (w : 'w) (x : fe * fe) => x.`1 * S1 w = T1 w) (1%r / pp%r) ha _.
  - move=> w [_ [hs _]] /=.
    have e : mu dkey2 (fun (x : fe * fe) => x.`1 * S1 w = T1 w) = mu dt (fun y => y * S1 w = T1 w) * weight dt.
    + by rewrite /dkey2; exact (dprodEl dt dt (fun y => y * S1 w = T1 w)).
    by rewrite e w_dt mulr1; exact (single_pin (S1 w) (T1 w) hs).
  move=> h; apply (ler_trans _ _ _ h).
  have : mu dW (fun w => V w /\ S1 w <> zero /\ S2 w = zero) <= b.
  - by apply (ler_trans _ _ _ _ hz2); apply mu_sub => w /=; smt().
  by smt().
(* G4 *)
have h4 : mu (dW `*` dkey2) G4 <= (1%r / pp%r) * (1%r / pp%r).
+ have := mu_gate dW dkey2 (fun w => V w /\ S1 w <> zero /\ S2 w <> zero)
            (fun (w : 'w) (x : fe * fe) => x.`1 * S1 w = T1 w /\ x.`2 * S2 w = T2 w) ((1%r / pp%r) * (1%r / pp%r)) _ _.
  - by apply mulr_ge0.
  - move=> w [_ [hs1 hs2]] /=.
    have e : mu dkey2 (fun (x : fe * fe) => x.`1 * S1 w = T1 w /\ x.`2 * S2 w = T2 w)
           = mu dt (fun y => y * S1 w = T1 w) * mu dt (fun y => y * S2 w = T2 w).
    + by rewrite /dkey2; exact (dprodE (fun y => y * S1 w = T1 w) (fun y => y * S2 w = T2 w) dt dt).
    rewrite e.
    have q1 := single_pin (S1 w) (T1 w) hs1.
    have q2 := single_pin (S2 w) (T2 w) hs2.
    exact (ler_pmul _ _ _ _ (ge0_mu dt (fun y => y * S1 w = T1 w)) (ge0_mu dt (fun y => y * S2 w = T2 w)) q1 q2).
  move=> h; apply (ler_trans _ _ _ h).
  have : mu dW (fun w => V w /\ S1 w <> zero /\ S2 w <> zero) <= 1%r by exact le1_mu.
  by smt(mulr_ge0).
by smt().
qed.

(* ------------------------------------------------------------------ *)
(* the challenge is uniform on nonzero vectors whatever seed the corrupt party committed to; so  *)
(* an error vector fixed BEFORE the seeds are opened gives a vanishing inner product w.p. <= 1/(p-1) *)

lemma z_one (cs ds : fe list) :
  size ds = nm => nzv ds =>
  mu (dlist dstar nm) (fun s => dot (comb s cs) ds = zero) <= inv (pp - 1)%r.
proof.
move=> hs hnz.
have -> : mu (dlist dstar nm) (fun s => dot (comb s cs) ds = zero)
        = mu (dmap (dlist dstar nm) (fun s => comb s cs)) (fun r => dot r ds = zero).
+ by rewrite dmapE /(\o).
rewrite (comb_unif nm nm_ge0 cs).
exact (lin_bound dstar (inv (pp - 1)%r) dstar_ll inv_pp1_ge0 dstar_mu1 nm nm_ge0 ds zero hs hnz).
qed.

lemma w_dl : weight (dlist dstar nm) = 1%r.
proof. by exact (is_losslessP _ (dlist_ll dstar nm dstar_ll)). qed.

lemma z_both (c1 c2 ds : fe list) :
  size ds = nm => nzv ds =>
  mu dsH (fun (s : seed) => dot (comb s.`1 c1) ds = zero /\ dot (comb s.`2 c2) ds = zero)
  <= inv (pp - 1)%r * inv (pp - 1)%r.
proof.
move=> hs hnz.
rewrite /dsH (dprodE (fun s => dot (comb s c1) ds = zero) (fun s => dot (comb s c2) ds = zero)).
exact (ler_pmul _ _ _ _ (ge0_mu _ _) (ge0_mu _ _) (z_one c1 ds hs hnz) (z_one c2 ds hs hnz)).
qed.

lemma z_first (c1 ds : fe list) :
  size ds = nm => nzv ds =>
  mu dsH (fun (s : seed) => dot (comb s.`1 c1) ds = zero) <= inv (pp - 1)%r.
proof.
move=> hs hnz.
have e : mu dsH (fun (s : seed) => dot (comb s.`1 c1) ds = zero)
       = mu (dlist dstar nm) (fun s => dot (comb s c1) ds = zero) * weight (dlist dstar nm).
+ by rewrite /dsH; exact (dprodEl (dlist dstar nm) (dlist dstar nm) (fun s => dot (comb s c1) ds = zero)).
rewrite e w_dl mulr1.
exact (z_one c1 ds hs hnz).
qed.

lemma z_second (c2 ds : fe list) :
  size ds = nm => nzv ds =>
  mu dsH (fun (s : seed) => dot (comb s.`2 c2) ds = zero) <= inv (pp - 1)%r.
proof.
move=> hs hnz.
have e : mu dsH (fun (s : seed) => dot (comb s.`2 c2) ds = zero)
       = mu (dlist dstar nm) (fun s => dot (comb s c2) ds = zero) * weight (dlist dstar nm).
+ by rewrite /dsH; exact (dprodEr (dlist dstar nm) (dlist dstar nm) (fun s => dot (comb s c2) ds = zero)).
rewrite e w_dl mulr1.
exact (z_one c2 ds hs hnz).
qed.

(* ------------------------------------------------------------------ *)
(* the committed-value event, in the shape the accounting lemma needs                  *)

op mAc (a : adv) (top : coin * env) : seed = (a_sc a top.`1 (comS seed0 (e_nd top.`2))).`1.
op dset (a : adv) (top : coin * env) : sdata = a_setup a top.`1.
(* the residual shares committed by the corrupt party (a function of what it has seen before aH is used) *)
op gAw (a : adv) (w : (coin * env) * seed) : gmsg = (game a (w, (zero, zero))).`o_gA.

op Vw (a : adv) (w : (coin * env) * seed) : bool = valid (dset a w.`1) /\ nzv (dset a w.`1).`dl.
op S1w (a : adv) (w : (coin * env) * seed) : fe = dot (rC a w.`1 w.`2).`1 (dset a w.`1).`dl.
op S2w (a : adv) (w : (coin * env) * seed) : fe = dot (rC a w.`1 w.`2).`2 (dset a w.`1).`dl.
op T1w (a : adv) (w : (coin * env) * seed) : fe =
  ((dset a w.`1).`aA.`1 * dot (rC a w.`1 w.`2).`1 (dset a w.`1).`xs - dot (rC a w.`1 w.`2).`1 (dset a w.`1).`ga1)
  + (gAw a w).`1.
op T2w (a : adv) (w : (coin * env) * seed) : fe =
  ((dset a w.`1).`aA.`2 * dot (rC a w.`1 w.`2).`2 (dset a w.`1).`xs - dot (rC a w.`1 w.`2).`2 (dset a w.`1).`ga2)
  + (gAw a w).`2.

lemma gAw_game (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  (game a (w, aH)).`o_gA = gAw a w.
proof. by rewrite /gAw /game /run /=. qed.

lemma game_d (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  (game a (w, aH)).`o_d = dset a w.`1.
proof. by rewrite /game /run /dset /=. qed.

lemma pin_alg (c s aa g : fe) : (c - aa * s) + g = zero => aa * s = c + g.
proof.
move=> h.
rewrite -(ZModpField.subr_eq0 (aa * s) (c + g)).
have -> : aa * s - (c + g) = -((c - aa * s) + g) by ring.
by rewrite h; ring.
qed.

(* the verifier's two checks pass  ==>  each key's honest residual pins the honest key share:
   aH^(l) * s_l = T_l   with  s_l = <r, delta>  (this is the observation that makes the check a
   linear equation in the hidden key, with right-hand side T_l independent of aH)               *)
lemma winC_pin (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  winC a (w, aH) =>
  Vw a w /\ aH.`1 * S1w a w = T1w a w /\ aH.`2 * S2w a w = T2w a w.
proof.
rewrite /winC /Vw /S1w /S2w /T1w /T2w /= => -[hv [hn [e1 e2]]].
rewrite !game_d in hv.
rewrite !game_d in hn.
rewrite !game_d in e1.
rewrite !game_d in e2.
rewrite gAw_game in e1.
rewrite gAw_game in e2.
move: hv; rewrite /valid /= => -[hx [h1 [h2 hl]]].
have s1 : size (dset a w.`1).`xs = size (dset a w.`1).`ga1 by smt().
have s2 : size (dset a w.`1).`xs = size (dset a w.`1).`ga2 by smt().
have s3 : size (dset a w.`1).`xs = size (dset a w.`1).`dl by smt().
have f1 := sigH_form (dset a w.`1).`xs (dset a w.`1).`dl (dset a w.`1).`ga1 (dset a w.`1).`aA.`1 aH.`1 (rC a w.`1 w.`2).`1 s1 s3.
have f2 := sigH_form (dset a w.`1).`xs (dset a w.`1).`dl (dset a w.`1).`ga2 (dset a w.`1).`aA.`2 aH.`2 (rC a w.`1 w.`2).`2 s2 s3.
move: e1; rewrite f1 => e1.
move: e2; rewrite f2 => e2.
split; first by rewrite /valid /=; smt().
split.
+ exact (pin_alg _ _ _ _ e1).
exact (pin_alg _ _ _ _ e2).
qed.

(* for each fixed (coin, nonces) -- hence fixed delta and fixed committed corrupt seed -- the honest
   seed makes the error inner products vanish with probability at most 1/(p-1) each, and both with
   probability at most the square *)
lemma inner_ZZ (a : adv) (top : coin * env) :
  mu dsH (fun sH => Vw a (top, sH) /\ S1w a (top, sH) = zero /\ S2w a (top, sH) = zero)
  <= inv (pp - 1)%r * inv (pp - 1)%r.
proof.
case (valid (dset a top) /\ nzv (dset a top).`dl) => hV.
+ apply (ler_trans (mu dsH (fun (s : seed) => dot (comb s.`1 (mAc a top).`1) (dset a top).`dl = zero /\
                                              dot (comb s.`2 (mAc a top).`2) (dset a top).`dl = zero))).
  - by apply mu_sub => s /=; rewrite /Vw /S1w /S2w /rC /mAc /chal /=; smt().
  by apply z_both; smt().
apply (ler_trans 0%r); last by smt(inv_pp1_ge0 mulr_ge0).
have -> : (fun sH => Vw a (top, sH) /\ S1w a (top, sH) = zero /\ S2w a (top, sH) = zero) = pred0.
+ by apply fun_ext => sH /=; rewrite /Vw /pred0 /=; smt().
by rewrite mu0.
qed.

lemma inner_Z1 (a : adv) (top : coin * env) :
  mu dsH (fun sH => Vw a (top, sH) /\ S1w a (top, sH) = zero) <= inv (pp - 1)%r.
proof.
case (valid (dset a top) /\ nzv (dset a top).`dl) => hV.
+ apply (ler_trans (mu dsH (fun (s : seed) => dot (comb s.`1 (mAc a top).`1) (dset a top).`dl = zero))).
  - by apply mu_sub => s /=; rewrite /Vw /S1w /rC /mAc /chal /=; smt().
  by apply z_first; smt().
apply (ler_trans 0%r); last by smt(inv_pp1_ge0).
have -> : (fun sH => Vw a (top, sH) /\ S1w a (top, sH) = zero) = pred0.
+ by apply fun_ext => sH /=; rewrite /Vw /pred0 /=; smt().
by rewrite mu0.
qed.

lemma inner_Z2 (a : adv) (top : coin * env) :
  mu dsH (fun sH => Vw a (top, sH) /\ S2w a (top, sH) = zero) <= inv (pp - 1)%r.
proof.
case (valid (dset a top) /\ nzv (dset a top).`dl) => hV.
+ apply (ler_trans (mu dsH (fun (s : seed) => dot (comb s.`2 (mAc a top).`2) (dset a top).`dl = zero))).
  - by apply mu_sub => s /=; rewrite /Vw /S2w /rC /mAc /chal /=; smt().
  by apply z_second; smt().
apply (ler_trans 0%r); last by smt(inv_pp1_ge0).
have -> : (fun sH => Vw a (top, sH) /\ S2w a (top, sH) = zero) = pred0.
+ by apply fun_ext => sH /=; rewrite /Vw /pred0 /=; smt().
by rewrite mu0.
qed.

(* ------------------------------------------------------------------ *)
(* the committed-value bound                                              *)

lemma winC_bound (a : adv) :
  mu dAll (winC a) <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r).
proof.
have hb := inv_pp1_ge0.
have hZZ : mu (dTop `*` dsH) (fun w => Vw a w /\ S1w a w = zero /\ S2w a w = zero)
           <= inv (pp - 1)%r * inv (pp - 1)%r.
+ have h := mu_dprod_bound dTop dsH
      (fun top sH => Vw a (top, sH) /\ S1w a (top, sH) = zero /\ S2w a (top, sH) = zero)
      (inv (pp - 1)%r * inv (pp - 1)%r) _ (inner_ZZ a).
  - by apply mulr_ge0.
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[top sH] /=.
have hZ1 : mu (dTop `*` dsH) (fun w => Vw a w /\ S1w a w = zero) <= inv (pp - 1)%r.
+ have h := mu_dprod_bound dTop dsH (fun top sH => Vw a (top, sH) /\ S1w a (top, sH) = zero)
      (inv (pp - 1)%r) hb (inner_Z1 a).
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[top sH] /=.
have hZ2 : mu (dTop `*` dsH) (fun w => Vw a w /\ S2w a w = zero) <= inv (pp - 1)%r.
+ have h := mu_dprod_bound dTop dsH (fun top sH => Vw a (top, sH) /\ S2w a (top, sH) = zero)
      (inv (pp - 1)%r) hb (inner_Z2 a).
  apply (ler_trans _ _ _ _ h).
  by apply mu_sub => -[top sH] /=.
have hc := core (dTop `*` dsH) (Vw a) (S1w a) (S2w a) (T1w a) (T2w a) (inv (pp - 1)%r) hb hZZ hZ1 hZ2.
apply (ler_trans _ _ _ _ hc).
rewrite /dAll.
by apply mu_sub => -[w aH] /= h; exact (winC_pin a w aH h).
qed.

(* ================================================================== *)
(* THE BINDING REDUCTIONS (explicit modules)                              *)
(* ================================================================== *)

(* binding game of the seed commitment / of the residual commitment: output two openings of one
   commitment string to different values *)
module type BinderS = { proc find() : (seed * nonce) * (seed * nonce) }.
module BindS (B : BinderS) = {
  proc main() : bool = {
    var r : (seed * nonce) * (seed * nonce);
    r <@ B.find();
    return r.`1.`1 <> r.`2.`1 /\ comS r.`1.`1 r.`1.`2 = comS r.`2.`1 r.`2.`2;
  }
}.

module type BinderG = { proc find() : (gmsg * nonce) * (gmsg * nonce) }.
module BindG (B : BinderG) = {
  proc main() : bool = {
    var r : (gmsg * nonce) * (gmsg * nonce);
    r <@ B.find();
    return r.`1.`1 <> r.`2.`1 /\ comG r.`1.`1 r.`1.`2 = comG r.`2.`1 r.`2.`2;
  }
}.

(* The collision finders: run the whole execution of the adversary `a` against the honest parties
   (sampling all honest randomness) and return the committed opening together with the opening the
   adversary presented at the opening round.  They have exactly the success probability of the
   events collS / collG. *)
module BS : BinderS = {
  var a : adv
  proc find() : (seed * nonce) * (seed * nonce) = {
    var o : outc;
    o <$ dgame BS.a;
    return ((o.`o_mA, o.`o_nA), (o.`o_m2, o.`o_n2));
  }
}.

module BG : BinderG = {
  var a : adv
  proc find() : (gmsg * nonce) * (gmsg * nonce) = {
    var o : outc;
    o <$ dgame BG.a;
    return ((o.`o_gA, o.`o_nG), (o.`o_g2, o.`o_ng2));
  }
}.

lemma bindS_pr (a : adv) &m :
  BS.a{m} = a =>
  Pr[BindS(BS).main() @ &m : res] = mu (dgame a) collS.
proof.
move=> ha.
byphoare (_: BS.a = a ==> res) => //.
proc; inline *; wp.
rnd; skip => /> .
by apply mu_eq => o /=; rewrite /collS /ok1; smt().
qed.

lemma bindG_pr (a : adv) &m :
  BG.a{m} = a =>
  Pr[BindG(BG).main() @ &m : res] = mu (dgame a) collG.
proof.
move=> ha.
byphoare (_: BG.a = a ==> res) => //.
proc; inline *; wp.
rnd; skip => /> .
by apply mu_eq => o /=; rewrite /collG /ok2; smt().
qed.

(* ================================================================== *)
(* (a) + (c): ORDERING and END-TO-END SOUNDNESS                          *)
(* ================================================================== *)

lemma soundness (a : adv) &m1 &m2 :
  BS.a{m1} = a => BG.a{m2} = a =>
  mu (dgame a) winR
  <= (1%r / pp%r + inv (pp - 1)%r) * (1%r / pp%r + inv (pp - 1)%r)
     + Pr[BindS(BS).main() @ &m1 : res] + Pr[BindG(BG).main() @ &m2 : res].
proof.
move=> h1 h2.
rewrite (bindS_pr a &m1 h1) (bindG_pr a &m2 h2).
rewrite /dgame !dmapE /(\o).
have hsub : mu dAll (fun p => winR (game a p))
    <= mu dAll (predU (winC a) (predU (fun p => collS (game a p)) (fun p => collG (game a p)))).
+ by apply mu_sub => p /=; rewrite /predU /=; exact (real_imp a p).
have hor1 := mu_or_le dAll (winC a) (predU (fun p => collS (game a p)) (fun p => collG (game a p))).
have hor2 := mu_or_le dAll (fun p => collS (game a p)) (fun p => collG (game a p)).
have hw := winC_bound a.
smt().
qed.

(* ================================================================== *)
(* (b) MAC-KEY SECRECY                                                    *)
(* ================================================================== *)

(* exact independence (the equality version of mu_gate) *)
lemma mu_indep ['w 'x] (dW : 'w distr) (dX : 'x distr) (P : 'w -> bool) (R : 'w -> 'x -> bool) (rho : real) :
  (forall w, P w => mu dX (R w) = rho) =>
  mu (dW `*` dX) (fun (p : 'w * 'x) => P p.`1 /\ R p.`1 p.`2) = rho * mu dW P.
proof.
move=> hR.
rewrite dprod_partition muE -RealSeries.sumZ.
apply RealSeries.eq_sum => w /=.
case (P w) => hP /=.
+ by rewrite (hR w hP) mulrC.
have h0 := mu0 dX.
rewrite /pred0 /= in h0.
by rewrite h0 /=.
qed.

(* everything the adversary has seen strictly before the honest residual is opened: its phase-1 data,
   the honest commitment strings, both corrupt commitments, the honest seed opening, the opened
   corrupt seed, the challenge, and its residual commitment *)
type prety = sdata * cm * seed * nonce * seed * nonce * seed * nonce * seed * cm * gmsg * nonce.
op pre (o : outc) : prety =
  (o.`o_d, o.`o_cH, o.`o_mA, o.`o_nA, o.`o_sH, o.`o_nH, o.`o_m2, o.`o_n2, o.`o_r, o.`o_cGH, o.`o_gA, o.`o_nG).

(* the view does not depend on the honest key shares at all: they are first used to build the honest
   residual, which is shown to the adversary only AFTER its own residuals are committed *)
lemma pre_indep (a : adv) (w : (coin * env) * seed) (aH aH' : fe * fe) :
  pre (game a (w, aH)) = pre (game a (w, aH')).
proof. by rewrite /pre /game /run /=. qed.

lemma w_dkey2 : weight dkey2 = 1%r.
proof.
have h : is_lossless (dt `*` dt) by rewrite dprod_ll; split; exact dt_ll.
by rewrite /dkey2; exact (is_losslessP _ h).
qed.

(* (b1) Whatever event Q the adversary's pre-opening view satisfies, the honest key shares are
   independent of it: the pair (view, key) has the product distribution -- statistical distance 0. *)
lemma key_secret (a : adv) (Q : prety -> bool) (K : fe * fe -> bool) :
  mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p)) /\ K p.`2)
  = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p))) * mu dkey2 K.
proof.
pose P := fun (w : (coin * env) * seed) => Q (pre (game a (w, (zero, zero)))).
have e1 : mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p)) /\ K p.`2) = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => P p.`1 /\ K p.`2).
+ by apply mu_eq => -[w aH] /=; rewrite /P (pre_indep a w aH (zero, zero)).
have e2 : mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p))) = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => P p.`1 /\ true).
+ by apply mu_eq => -[w aH] /=; rewrite /P (pre_indep a w aH (zero, zero)).
rewrite e1 e2 /dAll.
rewrite (mu_indep (dTop `*` dsH) dkey2 P (fun (w : (coin * env) * seed) (x : fe * fe) => K x) (mu dkey2 K) _).
+ by move=> w _.
rewrite (mu_indep (dTop `*` dsH) dkey2 P (fun (w : (coin * env) * seed) (x : fe * fe) => true) 1%r _).
+ by move=> w _; rewrite -w_dkey2; congr; apply fun_ext.
by ring.
qed.

lemma dt_shift (c v : fe) : mu dt (fun y => y + c = v) = 1%r / pp%r.
proof.
have -> : (fun y => y + c = v) = pred1 (v - c).
+ by apply fun_ext => y; rewrite /pred1 /=; smt(ZModpField.subr_eq0 ZModpField.addrC ZModpField.addrK).
by exact dt_mu1.
qed.

(* (b2) The global MAC key alpha^(l) = alpha_H^(l) + alpha_A^(l) is exactly uniform given the view
   (alpha_A is part of the view): for every view event Q and every pair of values v,
   Pr[Q(view) /\ alpha = v] = Pr[Q(view)] / p^2. *)
lemma alpha_uniform (a : adv) (Q : prety -> bool) (v : fe * fe) :
  mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p)) /\
                    p.`2.`1 + (game a p).`o_d.`aA.`1 = v.`1 /\ p.`2.`2 + (game a p).`o_d.`aA.`2 = v.`2)
  = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p))) * ((1%r / pp%r) * (1%r / pp%r)).
proof.
pose P := fun (w : (coin * env) * seed) => Q (pre (game a (w, (zero, zero)))).
have e1 : mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p)) /\
                    p.`2.`1 + (game a p).`o_d.`aA.`1 = v.`1 /\ p.`2.`2 + (game a p).`o_d.`aA.`2 = v.`2)
        = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => P p.`1 /\
                    (p.`2.`1 + (dset a p.`1.`1).`aA.`1 = v.`1 /\ p.`2.`2 + (dset a p.`1.`1).`aA.`2 = v.`2)).
+ by apply mu_eq => -[w aH] /=; rewrite /P (pre_indep a w aH (zero, zero)) game_d.
have e2 : mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => Q (pre (game a p))) = mu dAll (fun (p : ((coin * env) * seed) * (fe * fe)) => P p.`1 /\ true).
+ by apply mu_eq => -[w aH] /=; rewrite /P (pre_indep a w aH (zero, zero)).
rewrite e1 e2 /dAll.
rewrite (mu_indep (dTop `*` dsH) dkey2 P
           (fun (w : (coin * env) * seed) (x : fe * fe) => x.`1 + (dset a w.`1).`aA.`1 = v.`1 /\ x.`2 + (dset a w.`1).`aA.`2 = v.`2)
           ((1%r / pp%r) * (1%r / pp%r)) _).
+ move=> w _ /=.
  rewrite /dkey2 (dprodE (fun y => y + (dset a w.`1).`aA.`1 = v.`1) (fun y => y + (dset a w.`1).`aA.`2 = v.`2) dt dt).
  by rewrite !dt_shift.
rewrite (mu_indep (dTop `*` dsH) dkey2 P (fun (w : (coin * env) * seed) (x : fe * fe) => true) 1%r _).
+ by move=> w _; rewrite -w_dkey2; congr; apply fun_ext.
by ring.
qed.

(* (b3) What the honest residual share, once opened, says about the key.  For key l, with s_l the
   inner product of the challenge with the error vector and c_l a function of the view only:
       opened sigma_H^(l) = c_l - alpha_H^(l) * s_l .
   If s_l = 0 (no live error for that key) the opening is a function of the view: nothing about
   alpha_H leaks.  If s_l <> 0 the opening determines alpha_H^(l); but then the check equation
   alpha_H * s_l = t_l that the adversary needs is exactly the event bounded by 1/p in `soundness`. *)
op sO1 (o : outc) : fe = dot o.`o_r.`1 o.`o_d.`dl.
op sO2 (o : outc) : fe = dot o.`o_r.`2 o.`o_d.`dl.
op cO1 (o : outc) : fe = o.`o_d.`aA.`1 * dot o.`o_r.`1 o.`o_d.`xs - dot o.`o_r.`1 o.`o_d.`ga1.
op cO2 (o : outc) : fe = o.`o_d.`aA.`2 * dot o.`o_r.`2 o.`o_d.`xs - dot o.`o_r.`2 o.`o_d.`ga2.

lemma open_form (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  valid (dset a w.`1) =>
  (game a (w, aH)).`o_sg.`1 = cO1 (game a (w, aH)) - aH.`1 * sO1 (game a (w, aH)) /\
  (game a (w, aH)).`o_sg.`2 = cO2 (game a (w, aH)) - aH.`2 * sO2 (game a (w, aH)).
proof.
rewrite /valid /dset => hv.
rewrite /cO1 /cO2 /sO1 /sO2 /game /run /=.
split; apply sigH_form; smt().
qed.

lemma view_cs_indep (a : adv) (w : (coin * env) * seed) (aH aH' : fe * fe) :
  cO1 (game a (w, aH)) = cO1 (game a (w, aH')) /\ cO2 (game a (w, aH)) = cO2 (game a (w, aH')) /\
  sO1 (game a (w, aH)) = sO1 (game a (w, aH')) /\ sO2 (game a (w, aH)) = sO2 (game a (w, aH')).
proof. by rewrite /cO1 /cO2 /sO1 /sO2 /game /run /=. qed.

lemma no_leak (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  valid (dset a w.`1) => sO1 (game a (w, aH)) = zero =>
  (game a (w, aH)).`o_sg.`1 = cO1 (game a (w, (zero, zero))).
proof.
move=> hv hs.
have [h1 _] := open_form a w aH hv.
have [e1 _] := view_cs_indep a w aH (zero, zero).
by rewrite h1 hs -e1; ring.
qed.

lemma leak (a : adv) (w : (coin * env) * seed) (aH : fe * fe) :
  valid (dset a w.`1) => sO1 (game a (w, aH)) <> zero =>
  aH.`1 = (cO1 (game a (w, aH)) - (game a (w, aH)).`o_sg.`1) / sO1 (game a (w, aH)).
proof.
move=> hv hs.
have [h1 _] := open_form a w aH hv.
rewrite h1; field; exact hs.
qed.

(* ================================================================== *)
(* the concrete number at p = 2^61 - 1                                    *)
(* ================================================================== *)

(* The two-key soundness term of `soundness` is exactly the left side of PcaSpdz.mac_num; at
   p = 2^61 - 1 it is at most (2^60 + 4) / 2^180 = 2^-120 * (1 + 2^-58).  (`mac_num` takes the
   primality / value of the modulus from PcaSpdz.) *)
lemma soundness_num (a : adv) &m1 &m2 :
  BS.a{m1} = a => BG.a{m2} = a =>
  mu (dgame a) winR
  <= (a60 + 4%r) / (a60 * a60 * a60)
     + Pr[BindS(BS).main() @ &m1 : res] + Pr[BindG(BG).main() @ &m2 : res].
proof.
move=> h1 h2.
have hs := soundness a &m1 &m2 h1 h2.
have hn := mac_num.
smt().
qed.
