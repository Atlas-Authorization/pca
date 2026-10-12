(* PcaMultisig.ec -- role-bound t-of-n multisignature (Theorem TH-1, TH-2 of
   docs/pca/security/proofs/02-threshold-hybrid.md), machine-checked via the generic
   multi-user theory MU with n = 3 honest role keys (agent, guardian, principal).

   Proved here:
   * TH-2 (no role / signer-set / threshold / suite confusion): the share-message
     constructor is injective in (role, H(m), H(Sigma), t, suite) and disjoint from the
     PCActn (leaf) message; both from NUL-terminated prefixes and fixed-length fields.
   * TH-1 : Pr[ accepted, and a counted HONEST role's contribution was never signed
                for that exact (role, m, Sigma, t, suite) ] <= Adv_cr + 3 * Adv_suf,
     i.e. the loss factor 3.
   * the combinatorial corollary: accepted + t* > c (c = number of corrupted roles) +
     "no forgery" implies at least one honest role really signed this exact share. *)
require import AllCore List Int Real Distr FMap StdOrder.
import RealOrder.
require MU.

type byte.
op nul : byte.
pred nt (p : byte list) = exists q, p = rcons q nul /\ !(nul \in q).

lemma index_nt (p d : byte list) : nt p => index nul (p ++ d) = size p - 1.
proof.
move=> [q [-> hq]].
rewrite index_cat mem_rcons /= size_rcons.
rewrite -cats1 index_cat hq /= index_head /#.
qed.

(* two NUL-terminated prefixes that are followed by anything cannot be equal unless
   the prefixes are *)
lemma ntcat_eq (p p' d d' : byte list) :
  nt p => nt p' => p ++ d = p' ++ d' => p = p' /\ d = d'.
proof.
move=> h h' heq.
have hs : size p = size p'.
+ by have := index_nt p d h; have := index_nt p' d' h'; smt().
by move: heq; rewrite (eqseq_cat p p' d d' hs).
qed.

(* ------------------------------------------------------------------ *)
(* the share message                                                    *)

op H : byte list -> byte list.
axiom H_size : forall x, size (H x) = 32.

op pshare : int -> byte list.            (* "atlas-pca/share/<role>\0" *)
op pact   : byte list.                   (* "atlas-pca/actn/v2\0"      *)
axiom pshare_nt : forall r, nt (pshare r).
axiom pshare_inj : injective pshare.     (* the three role prefixes are pairwise distinct *)
axiom pact_nt : nt pact.
axiom pshare_ne_pact : forall r, pshare r <> pact.

op tb  : int -> byte list.               (* the threshold byte *)
op tag : int -> byte list.               (* suite tag: empty for ed25519, else NUL-prefixed alg id *)
axiom tb_size : forall t, size (tb t) = 1.
axiom tb_inj : injective tb.
axiom tag_inj : injective tag.

op msh (r : int) (m : byte list) (ss : byte list) (t : int) (a : int) : byte list =
  pshare r ++ H m ++ H ss ++ tb t ++ tag a.

op mleaf (m : byte list) : byte list = pact ++ H m.

(* TH-2 *)
lemma msh_inj r m ss t a r' m' ss' t' a' :
  msh r m ss t a = msh r' m' ss' t' a' =>
  r = r' /\ H m = H m' /\ H ss = H ss' /\ t = t' /\ a = a'.
proof.
rewrite /msh -!catA => heq.
have [h1 h2] := ntcat_eq _ _ _ _ (pshare_nt r) (pshare_nt r') heq.
have e1 : size (H m) = size (H m') by rewrite !H_size.
move: h2; rewrite (eqseq_cat _ _ _ _ e1) => -[h3 h4].
have e2 : size (H ss) = size (H ss') by rewrite !H_size.
move: h4; rewrite (eqseq_cat _ _ _ _ e2) => -[h5 h6].
have e3 : size (tb t) = size (tb t') by rewrite !tb_size.
move: h6; rewrite (eqseq_cat _ _ _ _ e3) => -[h7 h8].
do! split.
+ exact (pshare_inj _ _ h1).
+ exact h3.
+ exact h5.
+ exact (tb_inj _ _ h7).
exact (tag_inj _ _ h8).
qed.

lemma msh_ne_leaf r m ss t a m' : msh r m ss t a <> mleaf m'.
proof.
rewrite /msh /mleaf -!catA; apply/negP => heq.
have [h1 _] := ntcat_eq _ _ _ _ (pshare_nt r) pact_nt heq.
by apply (pshare_ne_pact r).
qed.

(* ------------------------------------------------------------------ *)
(* contexts, the three-key multi-user game                              *)

type pk.
type sk.
type sg.

op dkey : (pk * sk) distr.
op dsig : sk -> byte list -> sg distr.
op ver : pk -> byte list -> sg -> bool.
axiom dkey_ll : is_lossless dkey.
axiom dsig_ll : forall sk m, is_lossless (dsig sk m).

(* Share (role, m, Sigma-bytes, t, suite)  |  Leaf m  (the agent baseline over the bare message) *)
type ctx = [ Share of int & byte list & byte list & int & int | Leaf of byte list ].

op msgof (c : ctx) : byte list =
  with c = Share r m ss t a => msh r m ss t a
  with c = Leaf m => mleaf m.

(* collision pair: they differ in m or in Sigma, with equal hashes *)
op cx (c c' : ctx) : byte list * byte list =
  with c = Share r m ss t a, c' = Share r' m' ss' t' a' =>
         (if m <> m' then (m, m') else (ss, ss'))
  with c = Leaf m, c' = Leaf m' => (m, m')
  with c = Share r m ss t a, c' = Leaf m' => (m, m')
  with c = Leaf m, c' = Share r' m' ss' t' a' => (m, m').

(* the verifier's input: claimed message, signer-set bytes, threshold, suite,
   the presented role-tagged shares (role, verification key, signature), baseline *)
type out = byte list * byte list * int * int * (int * pk * sg) list * (pk * sg).

op claims (o : out) : (pk * ctx * sg) list =
  let (m, ss, t, a, shs, bl) = o in
  map (fun (x : int * pk * sg) => (x.`2, Share x.`1 m ss t a, x.`3)) shs
  ++ [(bl.`1, Leaf m, bl.`2)].

clone MU.MultiUser as CMU with
  type pk <- pk,
  type sk <- sk,
  type sg <- sg,
  type msg <- byte list,
  type bytes <- byte list,
  type dig <- byte list,
  op H <- H,
  type ctx <- ctx,
  type out <- out,
  op msgof <- msgof,
  op cx <- cx,
  op claims <- claims,
  op n <- 3,
  op dkey <- dkey,
  op dsig <- dsig,
  op ver <- ver
proof *.
realize n_pos by done.
realize dkey_ll by exact dkey_ll.
realize dsig_ll by exact dsig_ll.
realize msgof_coll.
proof.
move=> [r m ss t a | m] [r' m' ss' t' a' | m'] /=.
+ move=> hne /msh_inj [h1 [h2 [h3 [h4 h5]]]] /=.
  case (m <> m') => hm /=.
  - by rewrite /cx /=; smt().
  have hss : ss <> ss' by smt().
  by rewrite /cx /=; smt().
+ by move=> h; have := msh_ne_leaf r m ss t a m'; smt().
+ by move=> h; have := msh_ne_leaf r' m' ss' t' a' m; smt().
move=> hne.
rewrite /msgof /mleaf => h.
have := catsI _ _ _ h.
rewrite /cx /= => hh; smt().
qed.

(* ------------------------------------------------------------------ *)
(* acceptance and the forgery event (registered keys = the honest keys) *)

op roles : int list = [0; 1; 2].

(* role r presents a share that verifies under the REGISTERED key of role r *)
pred sh_ok (t : CMU.tr) (r : int) =
  let (m, ss, ts, a, shs, bl) = t.`CMU.trout in
  exists vk s, (r, vk, s) \in shs /\ vk = nth witness t.`CMU.trpk r /\ ver vk (msh r m ss ts a) s.

(* the agent baseline: the leaf signature under the registered agent key *)
pred bl_ok (t : CMU.tr) (r : int) =
  let (m, ss, ts, a, shs, bl) = t.`CMU.trout in
  r = 0 /\ bl.`1 = nth witness t.`CMU.trpk 0 /\ ver bl.`1 (mleaf m) bl.`2.

pred counted (t : CMU.tr) (r : int) = sh_ok t r \/ bl_ok t r.

(* accept iff at least t* distinct registered roles are counted *)
pred acc (t : CMU.tr) =
  let (m, ss, ts, a, shs, bl) = t.`CMU.trout in
  ts <= size (filter (counted t) roles).

(* the honest oracle signed exactly this contribution *)
pred forged (t : CMU.tr) (r : int) =
  let (m, ss, ts, a, shs, bl) = t.`CMU.trout in
  (sh_ok t r /\ !((r, Share r m ss ts a) \in t.`CMU.trlog))
  \/ (bl_ok t r /\ !((0, Leaf m) \in t.`CMU.trlog)).

pred win (t : CMU.tr) =
  acc t /\ exists r, 0 <= r /\ r < 3 /\ !(r \in t.`CMU.trcs) /\ forged t r.

lemma win_evt (t : CMU.tr) : win t => CMU.evt t.
proof.
move=> [hacc [r [hr0 [hr1 [hnc hf]]]]].
exists r; do! split => //.
have [m ss ts a shs bl hto] : exists m ss ts a shs bl, t.`CMU.trout = (m, ss, ts, a, shs, bl).
+ by case (CMU.trout t) => m ss ts a shs bl /=; smt().
move: hf; rewrite /forged /sh_ok /bl_ok hto /= => hf.
case: hf => -[hok hnl].
+ move: hok => [vk s [hin [hvk hv]]].
  exists (vk, Share r m ss ts a, s).
  rewrite /CMU.good_claim hto /=.
  have -> /= : (vk, Share r m ss ts a, s) \in claims (m, ss, ts, a, shs, bl).
  + rewrite /claims /= mem_cat; left; rewrite mapP.
    by exists (r, vk, s).
  by rewrite /msgof /=; smt().
move: hok => [h0 [hvk hv]].
exists (bl.`1, Leaf m, bl.`2).
rewrite /CMU.good_claim hto /=.
have -> /= : (bl.`1, Leaf m, bl.`2) \in claims (m, ss, ts, a, shs, bl).
+ by rewrite /claims /= mem_cat; right.
by rewrite /msgof /=; smt().
qed.

(* Counting: accepted with more required roles than corrupted roles, and no forgery,
   implies some honest role really signed (the oracle logged the exact contribution). *)
lemma honest_signed (t : CMU.tr) :
  acc t => size (undup t.`CMU.trcs) < (t.`CMU.trout).`3 =>
  (forall r, 0 <= r => r < 3 => !(r \in t.`CMU.trcs) => !forged t r) =>
  exists r, 0 <= r /\ r < 3 /\ !(r \in t.`CMU.trcs) /\ counted t r.
proof.
have [m ss ts a shs bl hto] : exists m ss ts a shs bl, t.`CMU.trout = (m, ss, ts, a, shs, bl).
+ by case (CMU.trout t) => m ss ts a shs bl /=; smt().
rewrite /acc hto /= => hacc hlt hnf.
case (exists r, 0 <= r /\ r < 3 /\ !(r \in t.`CMU.trcs) /\ counted t r) => // hno.
have hsub : forall r, r \in filter (counted t) roles => r \in undup t.`CMU.trcs.
+ move=> r; rewrite mem_filter /roles /= => -[hc hr].
  rewrite mem_undup.
  case (r \in t.`CMU.trcs) => // hnin.
  by apply hno; exists r; smt().
have huniq : uniq (filter (counted t) roles).
+ by apply filter_uniq; rewrite /roles /=.
have := uniq_leq_size _ _ huniq hsub.
smt().
qed.

section.

declare module A <: CMU.MAdv {-CMU.MG, -CMU.BR, -CMU.EUFA, -CMU.SUFA}.

declare axiom A_attack_ll (O <: CMU.MOrcl {-A}) :
  islossless O.sign => islossless A(O).attack.

(* Theorem TH-1, concrete-security form with the loss factor 3 (three role keys). *)
lemma TH1 &m (eps_cr eps_sig : real) :
  (Pr[CMU.CR(CMU.CA(A)).main() @ &m : res] <= eps_cr) =>
  (forall (a : int) &m', 0 <= a => a < 3 =>
     Pr[CMU.SUFA(CMU.BR(A)).main(a) @ &m' : res] <= eps_sig) =>
  Pr[CMU.MG(A).main() @ &m : win res] <= eps_cr + 3%r * eps_sig.
proof.
move=> hcr hsig.
have h1 : Pr[CMU.MG(A).main() @ &m : win res] <= Pr[CMU.MG(A).main() @ &m : CMU.evt res].
+ by rewrite Pr[mu_sub] // => &hr; exact win_evt.
have h2 := CMU.mu_bound A A_attack_ll &m eps_sig _.
+ move=> a &m' h0 h1'.
  by apply (ler_trans _ _ _ (CMU.euf_a_le_suf_a (CMU.BR(A)) a &m')); exact (hsig a &m' h0 h1').
smt().
qed.

end section.
