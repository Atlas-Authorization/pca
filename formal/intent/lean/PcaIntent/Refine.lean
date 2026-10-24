import PcaIntent.Regions
import PcaIntent.Cells

/-!
# P3 (unions realizability), P4/T8 (refinement), P5 (cross-org lifting), P6 (agnostic slack),
# P7 (partial answers: exactness)
-/

namespace PcaIntent

open Finset

/-! ## P3 (L1u): realizability of unions of boxes -/

namespace Cells

variable {ι : Type*} {X C : ι → Type*} (κ : ∀ d, X d → C d)

/-- The union of a family of boxes. -/
def unionBox {k : Type*} (T : k → ∀ d, Set (X d)) : Set (∀ d, X d) := {x | ∃ i, x ∈ box (T i)}

/-- **P3 (L1u).** If every cell contained in the union lies in a single box, the inner intent of the union is
the union of the inner boxes, hence in the union-of-`k` class. -/
theorem L1_union [DecidableEq ι] {k : Type*} (T : k → ∀ d, Set (X d))
    (hsingle : ∀ x, cellOf κ x ⊆ unionBox T → ∃ i, cellOf κ x ⊆ box (T i)) (x : ∀ d, X d) :
    cellOf κ x ⊆ unionBox T ↔ ∃ i, x ∈ box (innerSide κ (T i)) := by
  constructor
  · intro h
    obtain ⟨i, hi⟩ := hsingle x h
    exact ⟨i, (L1_box κ (T i) x).1 hi⟩
  · rintro ⟨i, hi⟩ y hy
    exact ⟨i, (L1_box κ (T i) x).2 hi hy⟩

/-- **P3 counterexample.** With the cell `[1,199]` and the intervals `[0,150]`, `[100,300]`, the cell lies in
the union but in neither interval, so the union of the two inner boxes misses it: the premise of `L1_union`
cannot be dropped. -/
theorem L1_union_counterexample :
    Set.Icc (1 : ℕ) 199 ⊆ Set.Icc 0 150 ∪ Set.Icc 100 300 ∧
      ¬ Set.Icc (1 : ℕ) 199 ⊆ Set.Icc 0 150 ∧ ¬ Set.Icc (1 : ℕ) 199 ⊆ Set.Icc 100 300 := by
  refine ⟨?_, ?_, ?_⟩
  · intro n hn
    rw [Set.mem_Icc] at hn
    rw [Set.mem_union, Set.mem_Icc, Set.mem_Icc]
    omega
  · intro h
    have := h (show (199 : ℕ) ∈ Set.Icc 1 199 from ⟨by norm_num, le_rfl⟩)
    rw [Set.mem_Icc] at this
    omega
  · intro h
    have := h (show (1 : ℕ) ∈ Set.Icc 1 199 from ⟨le_rfl, by norm_num⟩)
    rw [Set.mem_Icc] at this
    omega

/-- **P7 (exactness).** If every cell is either inside the box or disjoint from it (every threshold is a cut),
the inner intent equals the intent. -/
theorem exact_of_cuts (T : ∀ d, Set (X d))
    (hcut : ∀ x, cellOf κ x ⊆ box T ∨ ∀ y ∈ cellOf κ x, y ∉ box T) (x : ∀ d, X d) :
    x ∈ box T ↔ cellOf κ x ⊆ box T := by
  constructor
  · intro hx
    rcases hcut x with h | h
    · exact h
    · exact absurd hx (h x (mem_cellOf_self κ x))
  · exact inner_le κ T

end Cells

variable {Ω Θ : Type*} [Fintype Ω]

/-- **P7 (burden).** When the true intent equals the realizable inner intent (no gap mass `N`), the burden
bound of T2 holds for the true intent itself: `B(G1) ≤ μ(DIS)`. -/
theorem P7_exact_burden {acc : Θ → Ω → Bool} (M Mf : Model Ω) (heq : ∀ ω, M.a ω = Mf.a ω)
    (hμ : ∀ ω, Mf.μ ω = M.μ ω) {V : Finset Θ} {θf : Θ} (hreal : Realizes (acc θf) Mf) (hθ : θf ∈ V) :
    M.B (G1 acc V) ≤ ∑ ω ∈ DIS acc V, M.μ ω :=
  B_G1_le_DIS M (fun ω => (heq ω).trans (hreal ω)) hθ

/-! ## P4 (T8): refinement never widens the conservative grant -/

section Refinement

variable {Ωf Ωc Θc Θf Qc Qf : Type*} [Fintype Ωf] [Fintype Ωc] [Fintype Qc] [Fintype Qf]

/-- Embedded coarse hypotheses that are consistent stay consistent after exact lifting. -/
theorem T8_vs (qc : Θc → Qc → Bool) (qf : Θf → Qf → Bool) (e : Θc → Θf) {Hc : Finset Θc}
    {Hf : Finset Θf} {obsc : List (Qc × Bool)} {obsf : List (Qf × Bool)}
    (hH : ∀ θ ∈ Hc, e θ ∈ Hf) (hlift : ∀ θ, Consistent qc θ obsc → Consistent qf (e θ) obsf) :
    ∀ θ ∈ VS qc Hc obsc, e θ ∈ VS qf Hf obsf := by
  intro θ hθ
  rw [mem_VS] at hθ ⊢
  exact ⟨hH θ hθ.1, hlift θ hθ.2⟩

/-- **T8.** With the preimage embedding (`acc_f (e θ) = acc_c θ ∘ κ`) and exactly lifted answers, the fine
conservative grant lies in the preimage of the coarse one. -/
theorem T8 (κ : Ωf → Ωc) (accc : Θc → Ωc → Bool) (accf : Θf → Ωf → Bool) (e : Θc → Θf)
    (he : ∀ θ ω, accf (e θ) ω = accc θ (κ ω)) (qc : Θc → Qc → Bool) (qf : Θf → Qf → Bool)
    {Hc : Finset Θc} {Hf : Finset Θf} {obsc : List (Qc × Bool)} {obsf : List (Qf × Bool)}
    (hH : ∀ θ ∈ Hc, e θ ∈ Hf) (hlift : ∀ θ, Consistent qc θ obsc → Consistent qf (e θ) obsf) :
    ∀ ω ∈ G1 accf (VS qf Hf obsf), κ ω ∈ G1 accc (VS qc Hc obsc) := by
  intro ω hω
  rw [mem_G1] at hω ⊢
  intro θ hθ
  rw [← he θ ω]
  exact hω (e θ) (T8_vs qc qf e hH hlift θ hθ)

open Classical in
/-- Exact lifting of a coarse region to the fine space: its preimage under `κ`. -/
noncomputable def liftRegion (κ : Ωf → Ωc) (R : Finset Ωc) : Finset Ωf := univ.filter fun ω => κ ω ∈ R

/-- For an onto refinement, the embedded hypothesis answers a lifted region exactly as the coarse one. -/
theorem accR_lift (κ : Ωf → Ωc) (hκ : Function.Surjective κ) (accc : Θc → Ωc → Bool)
    (accf : Θf → Ωf → Bool) (e : Θc → Θf) (he : ∀ θ ω, accf (e θ) ω = accc θ (κ ω)) (θ : Θc)
    (R : Finset Ωc) : accR accf (e θ) (liftRegion κ R) = accR accc θ R := by
  classical
  have hiff : (∀ ω ∈ liftRegion κ R, accf (e θ) ω = true) ↔ ∀ c ∈ R, accc θ c = true := by
    constructor
    · intro h c hc
      obtain ⟨ω, rfl⟩ := hκ c
      rw [← he θ ω]
      exact h ω (by unfold liftRegion; simp [hc])
    · intro h ω hω
      have hm : κ ω ∈ R := by unfold liftRegion at hω; simpa using hω
      rw [he θ ω]; exact h _ hm
  unfold accR
  exact decide_eq_decide.2 hiff

/-- Lifting a whole list of coarse region answers keeps every embedded consistent hypothesis consistent:
the `hlift` premise of `T8` for region answers. -/
theorem lift_consistent (κ : Ωf → Ωc) (hκ : Function.Surjective κ) (accc : Θc → Ωc → Bool)
    (accf : Θf → Ωf → Bool) (e : Θc → Θf) (he : ∀ θ ω, accf (e θ) ω = accc θ (κ ω))
    (obsc : List (Finset Ωc × Bool)) (θ : Θc) (hc : Consistent (accR accc) θ obsc) :
    Consistent (accR accf) (e θ) (obsc.map fun o => (liftRegion κ o.1, o.2)) := by
  intro o ho
  obtain ⟨o', ho', rfl⟩ := List.mem_map.1 ho
  show accR accf (e θ) (liftRegion κ o'.1) = o'.2
  rw [accR_lift κ hκ accc accf e he]
  exact hc o' ho'

/-- **T8 for region answers, end to end.** -/
theorem T8_regions (κ : Ωf → Ωc) (hκ : Function.Surjective κ) (accc : Θc → Ωc → Bool)
    (accf : Θf → Ωf → Bool) (e : Θc → Θf) (he : ∀ θ ω, accf (e θ) ω = accc θ (κ ω))
    {Hc : Finset Θc} {Hf : Finset Θf} (hH : ∀ θ ∈ Hc, e θ ∈ Hf) (obsc : List (Finset Ωc × Bool)) :
    ∀ ω ∈ G1 accf (VS (accR accf) Hf (obsc.map fun o => (liftRegion κ o.1, o.2))),
      κ ω ∈ G1 accc (VS (accR accc) Hc obsc) :=
  T8 κ accc accf e he (accR accc) (accR accf) hH (lift_consistent κ hκ accc accf e he obsc)

/-! ## P5 (L-lift): cross-org lifting -/

/-- On an outcome every remaining hypothesis rejects (an uncovered verb: the deny hypothesis carries all the
mass), a non-empty version space grants nothing. -/
theorem G1_excludes_rejected {acc : Θf → Ωf → Bool} {V : Finset Θf} (hne : V.Nonempty) {ω : Ωf}
    (hrej : ∀ θ ∈ V, acc θ ω = false) : ω ∉ G1 acc V := by
  intro hω
  obtain ⟨θ, hθ⟩ := hne
  have h1 := (mem_G1.1 hω) θ hθ
  rw [hrej θ hθ] at h1
  exact Bool.false_ne_true h1

/-- **P5.** The lifted conservative grant is inside the preimage of the original (T8) and empty on outcomes
every lifted hypothesis rejects. -/
theorem P5_lift (κ : Ωf → Ωc) (hκ : Function.Surjective κ) (accc : Θc → Ωc → Bool)
    (accf : Θf → Ωf → Bool) (e : Θc → Θf) (he : ∀ θ ω, accf (e θ) ω = accc θ (κ ω))
    {Hc : Finset Θc} {Hf : Finset Θf} (hH : ∀ θ ∈ Hc, e θ ∈ Hf) (obsc : List (Finset Ωc × Bool))
    (hne : (VS (accR accf) Hf (obsc.map fun o => (liftRegion κ o.1, o.2))).Nonempty)
    (U : Finset Ωf)
    (hU : ∀ ω ∈ U, ∀ θ ∈ VS (accR accf) Hf (obsc.map fun o => (liftRegion κ o.1, o.2)), accf θ ω = false) :
    (∀ ω ∈ G1 accf (VS (accR accf) Hf (obsc.map fun o => (liftRegion κ o.1, o.2))),
        κ ω ∈ G1 accc (VS (accR accc) Hc obsc)) ∧
    (∀ ω ∈ U, ω ∉ G1 accf (VS (accR accf) Hf (obsc.map fun o => (liftRegion κ o.1, o.2)))) :=
  ⟨T8_regions κ hκ accc accf e he hH obsc, fun ω hω => G1_excludes_rejected hne (hU ω hω)⟩

end Refinement

/-! ## P6 (A1): agnostic selection with slack -/

/-- Number of answers `θ` disagrees with. -/
def err (acc : Θ → Ω → Bool) (θ : Θ) (obs : List (Ω × Bool)) : ℕ :=
  (obs.filter fun o => acc θ o.1 != o.2).length

lemma err_eq_zero_iff {acc : Θ → Ω → Bool} {θ : Θ} {obs : List (Ω × Bool)} :
    err acc θ obs = 0 ↔ Consistent acc θ obs := by
  unfold err Consistent
  simp [List.filter_eq_nil_iff]

open Classical in
/-- Candidates within slack `s` of the best error: `{θ ∈ H : err θ ≤ min err + s}`. -/
noncomputable def Cand (acc : Θ → Ω → Bool) (H : Finset Θ) (obs : List (Ω × Bool)) (s : ℕ) : Finset Θ :=
  H.filter fun θ => ∀ θ' ∈ H, err acc θ obs ≤ err acc θ' obs + s

lemma mem_Cand {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)} {s : ℕ} {θ : Θ} :
    θ ∈ Cand acc H obs s ↔ θ ∈ H ∧ ∀ θ' ∈ H, err acc θ obs ≤ err acc θ' obs + s := by
  classical
  unfold Cand; rw [Finset.mem_filter]

/-- A hypothesis with at most `s` disagreements is always a candidate. -/
theorem P6_truth_mem {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)} {s : ℕ} {θs : Θ}
    (hH : θs ∈ H) (he : err acc θs obs ≤ s) : θs ∈ Cand acc H obs s :=
  mem_Cand.2 ⟨hH, fun θ' _ => le_trans he (Nat.le_add_left s _)⟩

/-- **P6 (A1).** If the truth disagrees with at most `e ≤ s` answers, the conservative grant over the candidate
set has zero risk. -/
theorem P6_T1 (M : Model Ω) {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)} {s : ℕ}
    {θs : Θ} (hreal : Realizes (acc θs) M) (hH : θs ∈ H) (he : err acc θs obs ≤ s) :
    M.R (G1 acc (Cand acc H obs s)) = 0 := by
  apply M.R_eq_zero_of_accept
  intro ω hω
  rw [hreal ω, G1_subset_truth (P6_truth_mem hH he) hω]
  simp

/-- **P6 (slack 0).** With no slack and a consistent hypothesis present, the candidate set is the version
space (so the posterior equals the version-space posterior). -/
theorem P6_slack0 {acc : Θ → Ω → Bool} {H : Finset Θ} {obs : List (Ω × Bool)} {θs : Θ} (hH : θs ∈ H)
    (hc : Consistent acc θs obs) : Cand acc H obs 0 = VS acc H obs := by
  ext θ
  rw [mem_Cand, mem_VS, ← err_eq_zero_iff]
  have h0 : err acc θs obs = 0 := err_eq_zero_iff.2 hc
  constructor
  · rintro ⟨hθ, h⟩
    have := h θs hH
    rw [h0] at this
    exact ⟨hθ, by omega⟩
  · rintro ⟨hθ, h⟩
    exact ⟨hθ, fun θ' _ => by omega⟩

end PcaIntent
