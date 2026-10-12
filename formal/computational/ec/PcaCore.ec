(* Core.ec -- PCA action-authorization unforgeability (Theorem C-1 of
   docs/pca/security/proofs/01-core.md), machine-checked.

   What is proved here (all inside EasyCrypt; every assumption is an explicit
   `axiom` or a `declare axiom` hypothesis of the final section):

   * Lemma 3.1 (domain separation) for the cap / actn message prefixes, from the
     concrete fact that both prefixes are NUL-terminated with no interior NUL.
   * the collision-extraction obligation of the generic theory MU, discharged from
     the (assumed) injectivity of the canonical encoders and Lemma 3.1.
   * Theorem C-1 :  Pr[ accepted /\ some uncorrupted honest signer never authorised
                        the hop/action ]  <=  Adv_cr + mu * Adv_suf. *)
require import AllCore List Int Real Distr FMap StdOrder.
import RealOrder.
require MU.

(* ------------------------------------------------------------------ *)
(* bytes, NUL-terminated domain prefixes                               *)

type byte.
op nul : byte.

pred nt (p : byte list) = exists q, p = rcons q nul /\ !(nul \in q).

op pcap : byte list.     (* "atlas-pca/cap/v1\0"  *)
op pact : byte list.     (* "atlas-pca/actn/v2\0" *)
axiom pcap_nt : nt pcap.
axiom pact_nt : nt pact.
axiom pcap_ne_pact : pcap <> pact.

op mcap (d : byte list) : byte list = pcap ++ d.
op mact (d : byte list) : byte list = pact ++ d.

lemma index_nt (p d : byte list) :
  nt p => index nul (p ++ d) = size p - 1.
proof.
move=> [q [-> hq]].
rewrite index_cat mem_rcons /= size_rcons.
rewrite -cats1 index_cat hq /= index_head /#.
qed.

(* Lemma 3.1: the two message sets are disjoint. *)
lemma mdisj (d d' : byte list) : mcap d <> mact d'.
proof.
rewrite /mcap /mact; apply/negP => heq.
have hi := index_nt pcap d pcap_nt.
have hi' := index_nt pact d' pact_nt.
have hs : size pcap = size pact by smt().
by move: heq; rewrite (eqseq_cat pcap pact d d' hs) => -[h1 _]; exact pcap_ne_pact.
qed.

lemma mcap_inj (d d' : byte list) : mcap d = mcap d' => d = d'.
proof. by rewrite /mcap => /catsI. qed.

lemma mact_inj (d d' : byte list) : mact d = mact d' => d = d'.
proof. by rewrite /mact => /catsI. qed.

(* ------------------------------------------------------------------ *)
(* the hash and the canonical encoders                                  *)

type hbody.   (* capability-hop bodies *)
type abody.   (* PCActn bodies         *)

op H : byte list -> byte list.     (* SHA-256 (abstract; collision resistance is a hypothesis below) *)

op ench : hbody -> byte list.
op enca : abody -> byte list.
(* Lemma 2.1 (canonical encoding injective) is a PAPER lemma; here it is an axiom. *)
axiom ench_inj : injective ench.
axiom enca_inj : injective enca.

type pk.
type sk.
type sg.

op hholder : hbody -> pk.          (* the holder key named in a hop body *)

type ctx = [ Hop of hbody | Act of abody ].

op msgof (c : ctx) : byte list =
  with c = Hop b => mcap (H (ench b))
  with c = Act a => mact (H (enca a)).

op enc (c : ctx) : byte list =
  with c = Hop b => ench b
  with c = Act a => enca a.

op cx (c c' : ctx) : byte list * byte list = (enc c, enc c').

(* PCA output: the trust-anchor key, the delegation chain, the signed action *)
type out = pk * (hbody * sg) list * (abody * sg).

op signer (p : pk) (ch : (hbody * sg) list) (j : int) : pk =
  if j = 0 then p else hholder (nth witness ch (j - 1)).`1.

(* the signature checks that the verifier performs *)
op claims (o : out) : (pk * ctx * sg) list =
  let (p, ch, lf) = o in
  mkseq (fun j => (signer p ch j, Hop (nth witness ch j).`1, (nth witness ch j).`2)) (size ch)
  ++ [(signer p ch (size ch), Act lf.`1, lf.`2)].

const mu : int.
axiom mu_pos : 0 < mu.

(* the abstract signature scheme: key generation / signing are proper (lossless) distributions *)
op dkey : (pk * sk) distr.
op dsig : sk -> byte list -> sg distr.
op ver : pk -> byte list -> sg -> bool.
axiom dkey_ll : is_lossless dkey.
axiom dsig_ll : forall sk m, is_lossless (dsig sk m).

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
  op n <- mu,
  op dkey <- dkey,
  op dsig <- dsig,
  op ver <- ver
proof *.
realize n_pos by exact mu_pos.
realize dkey_ll by exact dkey_ll.
realize dsig_ll by exact dsig_ll.
realize msgof_coll.
proof.
move=> [b | a] [b' | a'] /=.
+ move=> hne; rewrite /msgof /= => /mcap_inj hh.
  rewrite /cx /enc /=; split; last exact hh.
  by apply/negP => h; apply hne; exact (ench_inj _ _ h).
+ move=> h.
  by have := mdisj (H (ench b)) (H (enca a')); smt().
+ move=> h.
  by have := mdisj (H (ench b')) (H (enca a)); smt().
move=> hne; rewrite /msgof /= => /mact_inj hh.
rewrite /cx /enc /=; split; last exact hh.
by apply/negP => h; apply hne; exact (enca_inj _ _ h).
qed.

(* ------------------------------------------------------------------ *)
(* Theorem C-1                                                          *)

(* the verifier's signature checks all pass *)
pred acc (o : out) =
  forall cl, cl \in claims o => ver cl.`1 (msgof cl.`2) cl.`3.

(* "Bad": some UNCORRUPTED honest key i signed (as far as the verifier can tell) a hop
   of the chain, or the leaf action, that the oracle never signed for i. *)
pred bad (t : CMU.tr) =
  exists i, 0 <= i /\ i < mu /\ !(i \in t.`CMU.trcs) /\
    (let (p, ch, lf) = t.`CMU.trout in
       (exists j, 0 <= j /\ j < size ch /\ signer p ch j = nth witness t.`CMU.trpk i /\
          !((i, Hop (nth witness ch j).`1) \in t.`CMU.trlog))
       \/
       (signer p ch (size ch) = nth witness t.`CMU.trpk i /\ !((i, Act lf.`1) \in t.`CMU.trlog))).

pred win (t : CMU.tr) = acc t.`CMU.trout /\ bad t.

lemma claim_hop (p : pk) (ch : (hbody * sg) list) (lf : abody * sg) (j : int) :
  0 <= j => j < size ch =>
  (signer p ch j, Hop (nth witness ch j).`1, (nth witness ch j).`2) \in claims (p, ch, lf).
proof.
move=> h0 h1; rewrite /claims /= mem_cat mkseqP; left.
by exists j; smt().
qed.

lemma claim_leaf (p : pk) (ch : (hbody * sg) list) (lf : abody * sg) :
  (signer p ch (size ch), Act lf.`1, lf.`2) \in claims (p, ch, lf).
proof. by rewrite /claims /= mem_cat; right. qed.

lemma win_evt (t : CMU.tr) : win t => CMU.evt t.
proof.
move=> [hacc [i [hi0 [hi1 [hnc hb]]]]].
exists i; do! split => //.
have [p ch lf hto] : exists p ch lf, t.`CMU.trout = (p, ch, lf).
+ by case (CMU.trout t) => p ch lf /=; smt().
move: hacc hb; rewrite hto /= => hacc.
move=> [[j [hj0 [hj1 [hs hnl]]]] | [hs hnl]].
+ exists (signer p ch j, Hop (nth witness ch j).`1, (nth witness ch j).`2).
  rewrite /CMU.good_claim hto /=.
  do! split.
  - exact (claim_hop p ch lf j hj0 hj1).
  - exact hs.
  - by have := hacc _ (claim_hop p ch lf j hj0 hj1).
  exact hnl.
exists (signer p ch (size ch), Act lf.`1, lf.`2).
rewrite /CMU.good_claim hto /=.
do! split.
- exact (claim_leaf p ch lf).
- exact hs.
- by have := hacc _ (claim_leaf p ch lf).
exact hnl.
qed.

section.

declare module A <: CMU.MAdv {-CMU.MG, -CMU.BR, -CMU.EUFA, -CMU.SUFA}.

(* the adversary terminates whenever its oracle does (standard well-formedness) *)
declare axiom A_attack_ll (O <: CMU.MOrcl {-A}) :
  islossless O.sign => islossless A(O).attack.

(* Theorem C-1, concrete-security form.

   The adversary wins iff the verifier accepts (all signature checks pass) and some
   uncorrupted honest key did not authorise a hop / the leaf.  Then

     Pr[win] <= Pr[CR(CA(A))]                                  (hash-collision finder run by CA(A))
              + sum_{i<mu} Pr[SUFA(BR(A)).main(i)]            (one SUF-CMA forger per honest key)

   and, if every reduction forger has advantage <= eps_sig and the collision
   finder advantage is <= eps_cr:   Pr[win] <= eps_cr + mu * eps_sig. *)
lemma C1 &m (eps_cr eps_sig : real) :
  (Pr[CMU.CR(CMU.CA(A)).main() @ &m : res] <= eps_cr) =>
  (forall (a : int) &m', 0 <= a => a < mu =>
     Pr[CMU.SUFA(CMU.BR(A)).main(a) @ &m' : res] <= eps_sig) =>
  Pr[CMU.MG(A).main() @ &m : win res] <= eps_cr + mu%r * eps_sig.
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
