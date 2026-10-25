import PcaIntent.Audit
import PcaIntent.Halving
import PcaIntent.Credence

/-!
# P1 (region questions), P2 (richer finite classes, Occam prior), P10 (committee prior)

**P1.** A region question asks about a set `R` of outcomes (cells) and is answered "yes" iff every outcome of
`R` is acceptable, so a hypothesis predicts `accR acc θ R = 1[R ⊆ θ]`. The version-space development is
generic in the observation type (nothing in `VS`, `Consistent`, `DIS`, `InformRun` uses that observations are
points), so it applies verbatim with observations `(R, y) : Finset Ω × Bool`. The grant `G1` is still over
points, computed from the region version space. This file states the region instances by name.

**P2.** All version-space and credence results hold for every finite hypothesis set. Instances for unions of at
most `k` boxes (cell sets) and for decision lists; decision lists whose rules may test boxes contain the box class
(`dlAcc_boxDL`, `T1_dlist_box`); the Occam prior `decay^(c−1)` has full support.

**P10.** A committee mixture prior times a full-support base prior has full support, so `T1_bayes` applies
whatever the compilers propose.
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω]

/-! ## P1: region questions -/

/-- A hypothesis accepts a region iff it accepts every outcome in it. -/
def accR (acc : Θ → Ω → Bool) (θ : Θ) (R : Finset Ω) : Bool := decide (∀ ω ∈ R, acc θ ω = true)

lemma accR_true {acc : Θ → Ω → Bool} {θ : Θ} {R : Finset Ω} :
    accR acc θ R = true ↔ ∀ ω ∈ R, acc θ ω = true := by
  unfold accR; simp

/-- **P1/T1.** Realizability + truthful region answers ⇒ the point grant computed from the region version space
has zero risk. -/
theorem region_T1 (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Finset Ω × Bool)}
    {θs : Θ} (hreal : Realizes (acc θs) M) (hH : θs ∈ H) (hc : Consistent (accR acc) θs obs) :
    M.R (G1 acc (VS (accR acc) H obs)) = 0 := by
  apply M.R_eq_zero_of_accept
  intro ω hω
  rw [hreal ω, G1_subset_truth (truth_mem_VS hH hc) hω]
  simp

/-- **P1/T2.** More region answers never enlarge the version space; the grant only grows. -/
theorem region_T2 {acc : Θ → Ω → Bool} {H : Finset Θ} {obs obs' : List (Finset Ω × Bool)}
    (hsub : ∀ o ∈ obs, o ∈ obs') :
    VS (accR acc) H obs' ⊆ VS (accR acc) H obs ∧
      G1 acc (VS (accR acc) H obs) ⊆ G1 acc (VS (accR acc) H obs') :=
  ⟨VS_anti hsub, G1_anti (VS_anti hsub)⟩

/-- **P1/T2 (burden).** `B(G1) ≤ μ(DIS)` for the region version space (DIS over points). -/
theorem region_T2_burden (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ}
    {obs : List (Finset Ω × Bool)} {θs : Θ} (hreal : Realizes (acc θs) M) (hH : θs ∈ H)
    (hc : Consistent (accR acc) θs obs) :
    M.B (G1 acc (VS (accR acc) H obs)) ≤ ∑ ω ∈ DIS acc (VS (accR acc) H obs), M.μ ω :=
  B_G1_le_DIS M hreal (truth_mem_VS hH hc)

/-- **P1/T3.** Informative region questions: at most `|H| − 1` of them. -/
theorem region_T3 {acc : Θ → Ω → Bool} (H : Finset Θ) {θs : Θ} (hH : θs ∈ H)
    (obs : List (Finset Ω × Bool)) (hrun : InformRun (accR acc) H obs)
    (hc : Consistent (accR acc) θs obs) : obs.length + 1 ≤ H.card :=
  inform_queries H hH obs hrun hc

/-- Truthful "yes" region answers: every outcome of a "yes" region is acceptable. -/
def RegionYesTruthful (M : Model Ω) (obs : List (Finset Ω × Bool)) : Prop :=
  ∀ R, (R, true) ∈ obs → ∀ ω ∈ R, M.a ω = 1

/-- **P1/T7 (core).** Every outcome of the grant covered by a truthful "yes" region ⇒ zero risk
(no realizability). -/
theorem region_T7_audit (M : Model Ω) {obs : List (Finset Ω × Bool)} (hyes : RegionYesTruthful M obs)
    {G : Finset Ω} (hcov : ∀ ω ∈ G, ∃ R, (R, true) ∈ obs ∧ ω ∈ R) : M.R G = 0 :=
  M.R_eq_zero_of_accept fun ω hω => by
    obtain ⟨R, hR, hωR⟩ := hcov ω hω
    exact hyes R hR ω hωR

/-- **P1/T7.** If the audit asked every outcome of `G1` as a singleton region and the version space is
non-empty, all those answers were "yes", so `R(G1) = 0` without realizability. -/
theorem region_T7_G1 (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ}
    {obs : List (Finset Ω × Bool)} (hyes : RegionYesTruthful M obs)
    (hne : (VS (accR acc) H obs).Nonempty)
    (haudit : ∀ ω ∈ G1 acc (VS (accR acc) H obs), ∃ y, ({ω}, y) ∈ obs) :
    M.R (G1 acc (VS (accR acc) H obs)) = 0 := by
  apply region_T7_audit M hyes
  intro ω hω
  obtain ⟨y, hy⟩ := haudit ω hω
  obtain ⟨θ, hθ⟩ := hne
  have h1 : acc θ ω = true := (mem_G1.1 hω) θ hθ
  have h2 : accR acc θ {ω} = y := (mem_VS.1 hθ).2 ({ω}, y) hy
  have h3 : accR acc θ {ω} = true := accR_true.2 fun ω' hω' => by
    rw [Finset.mem_singleton] at hω'; rw [hω']; exact h1
  rw [h3] at h2
  exact ⟨{ω}, h2 ▸ hy, Finset.mem_singleton_self ω⟩

/-! ## P2: richer finite classes -/

open Classical in
/-- Cell-set hypotheses: `θ` accepts exactly its own outcomes. -/
noncomputable def memAcc (θ : Finset Ω) (ω : Ω) : Bool := decide (ω ∈ θ)

open Classical in
/-- Unions of at most `k` boxes from a finite family `Boxes` of cell sets. -/
noncomputable def unionClass (Boxes : Finset (Finset Ω)) (k : ℕ) : Finset (Finset Ω) :=
  (Boxes.powerset.filter (fun S => S.card ≤ k)).image (fun S => S.biUnion id)

/-- **P2 (unions of ≤ k boxes).** T1 for the union class. -/
theorem T1_union (M : Model Ω) (Boxes : Finset (Finset Ω)) (k : ℕ) {obs : List (Ω × Bool)}
    {θs : Finset Ω} (hreal : Realizes (memAcc θs) M) (hH : θs ∈ unionClass Boxes k)
    (hc : Consistent memAcc θs obs) : M.R (G1 memAcc (VS memAcc (unionClass Boxes k) obs)) = 0 :=
  T1_soundness M hreal hH hc

/-- A decision list: ordered `(rule, label)` pairs and a default label. -/
abbrev DList (Ω : Type*) := List (Finset Ω × Bool) × Bool

open Classical in
/-- First matching rule wins; otherwise the default. -/
noncomputable def dlEval : List (Finset Ω × Bool) → Bool → Ω → Bool
  | [], d, _ => d
  | (r, b) :: rest, d, ω => if ω ∈ r then b else dlEval rest d ω

/-- Acceptance of a decision-list hypothesis. -/
noncomputable def dlAcc (θ : DList Ω) (ω : Ω) : Bool := dlEval θ.1 θ.2 ω

/-- **P2 (decision lists of ≤ L rules).** T1 for any finite set of decision lists. The length bound does not
enter soundness; it only bounds `|H|`, hence the question bound of T3. -/
theorem T1_dlist (M : Model Ω) (L : ℕ) (H : Finset (DList Ω)) (_hL : ∀ θ ∈ H, θ.1.length ≤ L)
    {obs : List (Ω × Bool)} {θs : DList Ω} (hreal : Realizes (dlAcc θs) M) (hH : θs ∈ H)
    (hc : Consistent dlAcc θs obs) : M.R (G1 dlAcc (VS dlAcc H obs)) = 0 :=
  T1_soundness M hreal hH hc

/-! ### Decision lists over box conditions contain the box class

A rule's condition is an arbitrary cell set (`Finset Ω`), so `DList` covers both the legacy one-dimensional tests
(`per-verb-decision-list/v1`) and box conditions, i.e. conjunctions over dimensions (`per-verb-decision-list/v2`).
The single-rule list "if `b` then yes, else no" accepts exactly `b`. So a decision-list class that contains these
lists for a family of boxes contains that box class, at complexity 1, for every `L ≥ 1`, and the box learner's
realizable truths stay realizable (`T1_dlist_box`). With one-dimensional conditions and a fixed `L` the inclusion
fails in general (a box excluding three one-dimension pieces needs three such rules): that is why the code's
rules test boxes. -/

/-- The one-rule decision list "if `b` then accept, else reject". -/
def boxDL (b : Finset Ω) : DList Ω := ([(b, true)], false)

open Classical in
/-- `boxDL b` accepts exactly the cells of `b`. -/
theorem dlAcc_boxDL (b : Finset Ω) : dlAcc (boxDL b) = memAcc b := by
  funext ω
  by_cases h : ω ∈ b <;> simp [dlAcc, boxDL, dlEval, memAcc, h]

theorem dlAcc_boxDL_apply (b : Finset Ω) (ω : Ω) : dlAcc (boxDL b) ω = memAcc b ω := by
  rw [dlAcc_boxDL]

theorem boxDL_length (b : Finset Ω) : (boxDL b).1.length = 1 := rfl

/-- `boxDL` is injective: distinct boxes give distinct one-rule lists. -/
theorem boxDL_injective : Function.Injective (boxDL (Ω := Ω)) := by
  intro a b h
  simpa [boxDL] using h

/-- Consistency transfers along the embedding. -/
theorem consistent_boxDL {b : Finset Ω} {obs : List (Ω × Bool)} :
    Consistent dlAcc (boxDL b) obs ↔ Consistent memAcc b obs := by
  unfold Consistent
  simp only [dlAcc_boxDL_apply]

/-- **P2 (superset).** If the decision-list class `H` contains the one-rule list of every box in `Boxes`, every
box truth realizable in the box class is realizable in `H` with the same consistency, and the `τ = 1` grant from
`H` has zero risk (T1). Holds for every `L ≥ 1`: the embedded lists have one rule. -/
theorem T1_dlist_box (M : Model Ω) (L : ℕ) (_hL1 : 1 ≤ L) (Boxes : Finset (Finset Ω)) (H : Finset (DList Ω))
    (_hLen : ∀ θ ∈ H, θ.1.length ≤ L) (hsup : ∀ b ∈ Boxes, boxDL b ∈ H)
    {obs : List (Ω × Bool)} {θs : Finset Ω} (hreal : Realizes (memAcc θs) M) (hB : θs ∈ Boxes)
    (hc : Consistent memAcc θs obs) : M.R (G1 dlAcc (VS dlAcc H obs)) = 0 := by
  refine T1_soundness M (θs := boxDL θs) ?_ (hsup θs hB) (consistent_boxDL.mpr hc)
  rw [dlAcc_boxDL]; exact hreal

/-- The box family's embedded lists form a sub-class of `H`, of the same size (so `|H| ≥ |Boxes|`). -/
theorem box_card_le_dlist (Boxes : Finset (Finset Ω)) (H : Finset (DList Ω)) (hsup : ∀ b ∈ Boxes, boxDL b ∈ H) :
    Boxes.card ≤ H.card := by
  classical
  rw [← Finset.card_image_of_injective Boxes boxDL_injective]
  exact Finset.card_le_card (fun x hx => by
    obtain ⟨b, hb, rfl⟩ := Finset.mem_image.mp hx
    exact hsup b hb)

/-- **P2 (Occam prior).** `decay^(c − 1) > 0` for every complexity `c`, so the prior has full support. -/
theorem occam_pos {decay : ℝ} (hd : 0 < decay) (c : ℕ) : 0 < decay ^ (c - 1) := pow_pos hd _

/-! ## P10: committee prior -/

/-- **P10.** The committee mixture `∑_j c_j exp(−λ_j d_j)` times a positive base weight is positive, as soon as
the mixture weights are non-negative and one is positive. -/
theorem committee_pos {J : Type*} (s : Finset J) (c lam d : J → ℝ) (hc : ∀ j ∈ s, 0 ≤ c j)
    (hj : ∃ j ∈ s, 0 < c j) {base : ℝ} (hb : 0 < base) :
    0 < (∑ j ∈ s, c j * Real.exp (-(lam j * d j))) * base := by
  refine mul_pos ?_ hb
  refine Finset.sum_pos' (fun j hj' => mul_nonneg (hc j hj') (Real.exp_pos _).le) ?_
  obtain ⟨j, hjs, hcj⟩ := hj
  exact ⟨j, hjs, mul_pos hcj (Real.exp_pos _)⟩

/-- **P10 ⇒ T1.** With the committee prior (full support by `committee_pos`), the noise-free Bayes `τ = 1`
grant has zero risk, whatever the anchors `g_j` and distances are. -/
theorem T1_committee {J : Type*} (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ} (s : Finset J)
    (c lam : J → ℝ) (dist : Θ → J → ℝ) (base : Θ → ℝ) (hc : ∀ j ∈ s, 0 ≤ c j) (hj : ∃ j ∈ s, 0 < c j)
    (hb : ∀ θ, 0 < base θ) {θs : Θ} (hreal : Realizes (acc θs) M) (hH : θs ∈ H)
    {obs : List (Ω × Bool)} (hcons : Consistent acc θs obs) :
    let π0 := fun θ => (∑ j ∈ s, c j * Real.exp (-(lam j * dist θ j))) * base θ
    ∀ (hπ0 : ∀ θ, 0 ≤ π0 θ) (hpos : 0 < π0 θs),
      M.R (Gτ acc (bayes H π0 hπ0 le_rfl zero_le_one obs (Z_pos_of_truth hπ0 hH hpos hcons)) 1) = 0 := by
  intro π0 hπ0 hpos
  exact T1_bayes M hπ0 hreal hH hpos hcons

/-- The premises of `T1_committee` are discharged by `committee_pos`. -/
theorem committee_prior_ok {J : Type*} (s : Finset J) (c lam : J → ℝ) (dist : Θ → J → ℝ) (base : Θ → ℝ)
    (hc : ∀ j ∈ s, 0 ≤ c j) (hj : ∃ j ∈ s, 0 < c j) (hb : ∀ θ, 0 < base θ) (θ : Θ) :
    0 < (∑ j ∈ s, c j * Real.exp (-(lam j * dist θ j))) * base θ :=
  committee_pos s c lam (dist θ) hc hj (hb θ)

end PcaIntent
