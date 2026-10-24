import PcaIntent.Halving

/-!
# Cell-level questions, box realizability (L1) and transfer (spec §2.7)

**L1.** One verb with dimensions `d : ι`, value sets `X d`, and a cell map `κ d : X d → C d` (each value lies in
exactly one cell of its dimension; numeric cells are intervals of a linear order, i.e. `κ d` is monotone into
a linear order of cells). A product cell is `cellOf x = {y : ∀ d, κ_d(y_d) = κ_d(x_d)}`. If the acceptable set is
a box `Π_d T_d`, the *inner intent* `a♭(x) = 1[cellOf x ⊆ Π_d T_d]` is again a box `Π_d S_d` whose sides
are unions of whole cells (`L1_box`, `S_cell_saturated`). When `T_d` is an interval and `κ_d` monotone (numeric
dimensions), the set of cells inside `T_d` is a contiguous range of cells (`L1_contiguous`) — whatever the
thresholds of `T_d`, cuts or not. So `a♭ = a_{θ♭}` for a hypothesis of the spec's class Θ_v (a box of cell
ranges/sets; the deny-verb hypothesis when some side is empty).

**Transfer.** `a♭ ≤ a` pointwise (`inner_le`), so the true risk is at most the inner-intent risk
(`transfer_R`; T1's `R = 0` transfers: `T1_cells`), and the burden pays at most the mass of cells on which `a`
is not constant (`transfer_B`, with `gap_nonconst` for the cell model).

**Questions ≤ cells.** A question in the disagreement region is answered once and for all: no informative run
asks the same outcome (cell representative) twice (`inform_questions_nodup`), so the number of questions is at
most the number of cells (`questions_le_cells`).
-/

namespace PcaIntent

open Finset

/-! ## L1: box realizability of the inner intent -/

namespace Cells

variable {ι : Type*} {X C : ι → Type*} (κ : ∀ d, X d → C d)

/-- The product cell containing `x`. -/
def cellOf (x : ∀ d, X d) : Set (∀ d, X d) := {y | ∀ d, κ d (y d) = κ d (x d)}

/-- A box `Π_d T_d`. -/
def box (T : ∀ d, Set (X d)) : Set (∀ d, X d) := {x | ∀ d, x d ∈ T d}

/-- The values of dimension `d` that lie in cell `c`. -/
def dimCell (d : ι) (c : C d) : Set (X d) := {z | κ d z = c}

/-- The inner box: on each dimension, the union of the cells that lie inside `T_d`. -/
def innerSide (T : ∀ d, Set (X d)) (d : ι) : Set (X d) := {z | dimCell κ d (κ d z) ⊆ T d}

lemma mem_cellOf_self (x : ∀ d, X d) : x ∈ cellOf κ x := fun _ => rfl

/-- A product cell lies in a box iff each of its sides lies in the corresponding side. -/
theorem cell_subset_box_iff [DecidableEq ι] (T : ∀ d, Set (X d)) (x : ∀ d, X d) :
    cellOf κ x ⊆ box T ↔ ∀ d, dimCell κ d (κ d (x d)) ⊆ T d := by
  constructor
  · intro h d z hz
    have hu : Function.update x d z ∈ cellOf κ x := by
      intro d'
      by_cases hd : d' = d
      · rw [hd, Function.update_self]; exact hz
      · rw [Function.update_of_ne hd]
    have h2 := h hu d
    rwa [Function.update_self] at h2
  · intro h y hy d
    exact h d (hy d)

/-- **L1 (box form).** The inner intent `a♭(x) = 1[cellOf x ⊆ Π T]` is the indicator of the box `Π_d S_d`. -/
theorem L1_box [DecidableEq ι] (T : ∀ d, Set (X d)) (x : ∀ d, X d) :
    cellOf κ x ⊆ box T ↔ x ∈ box (innerSide κ T) :=
  cell_subset_box_iff κ T x

/-- The sides of the inner box are unions of whole cells. -/
theorem S_cell_saturated (T : ∀ d, Set (X d)) (d : ι) {z z' : X d} (hz : z ∈ innerSide κ T d)
    (hc : κ d z' = κ d z) : z' ∈ innerSide κ T d := by
  show dimCell κ d (κ d z') ⊆ T d
  rw [hc]; exact hz

/-- **L1 (contiguity).** On a numeric dimension (values and cells linearly ordered, `κ_d` monotone and onto,
`T_d` an interval), the cells inside `T_d` form a contiguous range of cells. -/
theorem L1_contiguous (d : ι) [LinearOrder (X d)] [LinearOrder (C d)] (hmono : Monotone (κ d))
    (hsurj : Function.Surjective (κ d)) (T : Set (X d)) (hT : T.OrdConnected) :
    {c : C d | dimCell κ d c ⊆ T}.OrdConnected := by
  refine ⟨fun c1 h1 c2 h2 c hc => ?_⟩
  intro z hz
  simp only [Set.mem_setOf_eq] at h1 h2
  have hzc : κ d z = c := hz
  obtain ⟨z1, hz1⟩ := hsurj c1
  obtain ⟨z2, hz2⟩ := hsurj c2
  rcases eq_or_lt_of_le hc.1 with heq1 | hlt1
  · exact @h1 z (show κ d z = c1 by rw [hzc, heq1])
  rcases eq_or_lt_of_le hc.2 with heq2 | hlt2
  · exact @h2 z (show κ d z = c2 by rw [hzc, heq2])
  have hle1 : z1 ≤ z := by
    by_contra hlt
    have := hmono (le_of_lt (lt_of_not_ge hlt))
    rw [hzc, hz1] at this
    exact absurd hlt1 (not_lt_of_ge this)
  have hle2 : z ≤ z2 := by
    by_contra hlt
    have := hmono (le_of_lt (lt_of_not_ge hlt))
    rw [hzc, hz2] at this
    exact absurd hlt2 (not_lt_of_ge this)
  exact hT.out (@h1 z1 hz1) (@h2 z2 hz2) ⟨hle1, hle2⟩

/-- `a♭ ≤ a`: an outcome whose whole cell is acceptable is acceptable. -/
theorem inner_le (T : ∀ d, Set (X d)) {x : ∀ d, X d} (h : cellOf κ x ⊆ box T) : x ∈ box T :=
  h (mem_cellOf_self κ x)

/-- Where `a = 1` but `a♭ = 0`, the acceptability is not constant on the cell. -/
theorem gap_nonconst (T : ∀ d, Set (X d)) {x : ∀ d, X d} (h : ¬ cellOf κ x ⊆ box T) :
    ∃ y ∈ cellOf κ x, y ∉ box T := by
  by_contra hne
  push_neg at hne
  exact h hne

end Cells

/-! ## Transfer from the inner intent to the true intent -/

variable {Ω Θ : Type*} [Fintype Ω]

/-- True risk is at most the inner-intent risk (same harm and workload, `a♭ ≤ a`). -/
theorem transfer_R (M Mf : Model Ω) (hh : ∀ ω, Mf.h ω = M.h ω) (hμ : ∀ ω, Mf.μ ω = M.μ ω)
    (hle : ∀ ω, Mf.a ω ≤ M.a ω) (G : Finset Ω) : M.R G ≤ Mf.R G := by
  unfold Model.R
  refine Finset.sum_le_sum fun ω _ => ?_
  rw [hh ω, hμ ω]
  have : 0 ≤ M.h ω * M.μ ω := mul_nonneg (M.h_nonneg ω) (M.μ_nonneg ω)
  have h2 : (1 - M.a ω) ≤ (1 - Mf.a ω) := by linarith [hle ω]
  nlinarith

open Classical in
/-- True burden pays at most the workload mass `N` of cells on which `a` is not constant. -/
theorem transfer_B (M Mf : Model Ω) (hμ : ∀ ω, Mf.μ ω = M.μ ω) (N : Finset Ω)
    (hgap : ∀ ω, M.a ω ≤ Mf.a ω + if ω ∈ N then 1 else 0) (G : Finset Ω) :
    M.B G ≤ Mf.B G + ∑ ω ∈ N, M.μ ω := by
  classical
  unfold Model.B
  calc ∑ ω ∈ Gᶜ, M.a ω * M.μ ω
      ≤ ∑ ω ∈ Gᶜ, (Mf.a ω * Mf.μ ω + (if ω ∈ N then M.μ ω else 0)) := by
        refine Finset.sum_le_sum fun ω _ => ?_
        rw [hμ ω]
        have := mul_le_mul_of_nonneg_right (hgap ω) (M.μ_nonneg ω)
        split_ifs at this ⊢ with hN
        · rw [add_mul, one_mul] at this; linarith
        · rw [add_zero] at this; linarith
    _ = ∑ ω ∈ Gᶜ, Mf.a ω * Mf.μ ω + ∑ ω ∈ Gᶜ ∩ N, M.μ ω := by
        rw [Finset.sum_add_distrib, Finset.sum_ite_mem]
    _ ≤ ∑ ω ∈ Gᶜ, Mf.a ω * Mf.μ ω + ∑ ω ∈ N, M.μ ω := by
        have : ∑ ω ∈ Gᶜ ∩ N, M.μ ω ≤ ∑ ω ∈ N, M.μ ω :=
          Finset.sum_le_sum_of_subset_of_nonneg Finset.inter_subset_right fun ω _ _ => M.μ_nonneg ω
        linarith

/-- **T1 for the true intent via L1.** If the inner intent is realised by `θ♭ ∈ H` and the (cell-question)
answers are consistent with `θ♭`, then the conservative grant has zero *true* risk. -/
theorem T1_cells {acc : Θ → Ω → Bool} (M Mf : Model Ω) (hh : ∀ ω, Mf.h ω = M.h ω)
    (hμ : ∀ ω, Mf.μ ω = M.μ ω) (hle : ∀ ω, Mf.a ω ≤ M.a ω) {H : Finset Θ}
    {obs : List (Ω × Bool)} {θf : Θ} (hreal : Realizes (acc θf) Mf) (hH : θf ∈ H)
    (hc : Consistent acc θf obs) : M.R (G1 acc (VS acc H obs)) = 0 := by
  have h0 := T1_soundness Mf hreal hH hc
  have h1 := transfer_R M Mf hh hμ hle (G1 acc (VS acc H obs))
  rw [h0] at h1
  exact le_antisymm h1 (M.R_nonneg _)

/-! ## Questions ≤ number of cells -/

/-- An informative run never repeats a question. -/
theorem inform_questions_nodup {acc : Θ → Ω → Bool} (H : Finset Θ) :
    ∀ obs : List (Ω × Bool), InformRun acc H obs → (obs.map Prod.fst).Nodup
  | [], _ => List.nodup_nil
  | o :: obs, ⟨hrun, hd⟩ => by
      rw [List.map_cons, List.nodup_cons]
      refine ⟨fun hmem => ?_, inform_questions_nodup H obs hrun⟩
      obtain ⟨p, hp, hpo⟩ := List.mem_map.1 hmem
      obtain ⟨θ, hθ, θ', hθ', hne⟩ := mem_DIS.1 hd
      have e1 := (mem_VS.1 hθ).2 p hp
      have e2 := (mem_VS.1 hθ').2 p hp
      rw [hpo] at e1 e2
      exact hne (e1.trans e2.symm)

/-- **Questions ≤ number of cells.** Over a finite outcome space of cell representatives, an informative run
has at most `|Ω|` questions. -/
theorem questions_le_cells {acc : Θ → Ω → Bool} (H : Finset Θ) (obs : List (Ω × Bool))
    (hrun : InformRun acc H obs) : obs.length ≤ Fintype.card Ω := by
  have h := (inform_questions_nodup H obs hrun).length_le_card
  rwa [List.length_map] at h

/-! ## Multi-principal with the product rule (spec §4.3: joint acceptance = product of the p's) -/

/-- With `p_i ∈ [0,1]`, the product-rule joint grant `{∏ p_i ≥ τ}` is inside every principal's own `τ`-grant. -/
theorem prod_le_each {ι : Type*} [Fintype ι] (p : ι → ℝ) (h0 : ∀ i, 0 ≤ p i) (h1 : ∀ i, p i ≤ 1) (i : ι) :
    ∏ j, p j ≤ p i := by
  classical
  rw [← Finset.mul_prod_erase Finset.univ p (Finset.mem_univ i)]
  have hle : ∏ j ∈ Finset.univ.erase i, p j ≤ 1 :=
    Finset.prod_le_one₀ (fun j _ => h0 j) (fun j _ => h1 j)
  nlinarith [h0 i, Finset.prod_nonneg (s := Finset.univ.erase i) (fun j _ => h0 j)]

/-- The product rule satisfies the conjunctive-aggregation hypothesis of `T5_joint`:
`1 − ∏ aᵢ ≤ ∑ (1 − aᵢ)` for `aᵢ ∈ [0,1]` (Weierstrass product inequality). -/
theorem agg_prod {ι : Type*} (s : Finset ι) (a : ι → ℝ) (h0 : ∀ i, 0 ≤ a i) (h1 : ∀ i, a i ≤ 1) :
    1 - ∏ i ∈ s, a i ≤ ∑ i ∈ s, (1 - a i) := by
  classical
  induction s using Finset.induction_on with
  | empty => simp
  | insert j s hj ih =>
      rw [Finset.prod_insert hj, Finset.sum_insert hj]
      have hp0 : 0 ≤ ∏ i ∈ s, a i := Finset.prod_nonneg fun i _ => h0 i
      have hp1 : ∏ i ∈ s, a i ≤ 1 := Finset.prod_le_one₀ (fun i _ => h0 i) (fun i _ => h1 i)
      nlinarith [h0 j, h1 j, mul_nonneg (sub_nonneg.2 (h1 j)) (sub_nonneg.2 hp1)]

end PcaIntent
