import PcaMath.Fork

/-!
# The forking lemma for random-oracle algorithms, and extraction from special soundness

A random-oracle algorithm is modelled by what it does on coins `ρ : R` and a *query-indexed*
oracle table `h : Fin q → H` (the answer to the `i`-th query).  This is the standard model of
Bellare-Neven: an algorithm making at most `q` queries to a random oracle with answers uniform in
`H` is a deterministic function of its coins and the table of its `q` answers (repeated queries
are cached, so WLOG the queried points are distinct).

`fork_rom`: the forking algorithm
  1. samples `(ρ, h)` uniformly and runs the algorithm; if it accepts with fork index `i`,
  2. re-samples the answers `h_i, ..., h_{q-1}` (keeps `ρ` and `h_0..h_{i-1}`) giving `h'`, runs again,
  3. succeeds iff the second run accepts with the same index and `h'_i ≠ h_i`,
succeeds with probability at least `acc * (acc / q - 1 / |H|)`.
-/

open Finset

namespace PcaMath.Rom

open PcaMath.Fork

variable {R H : Type*} [Fintype R] [Fintype H] [DecidableEq R] [DecidableEq H] {q : ℕ}

/-- Run `ω = (ρ, h)` is in the same class as `ω'` at fork point `i`: same coins, same answers before `i`. -/
def cls (i : Fin q) (ω : R × (Fin q → H)) : R × (Fin q → Option H) :=
  (ω.1, fun j => if j < i then some (ω.2 j) else none)

def ans (i : Fin q) (ω : R × (Fin q → H)) : H := ω.2 i

/-- size of a class at fork point `i`: `|H|` to the number of answers not fixed. -/
def csize (q : ℕ) (H : Type*) [Fintype H] (i : Fin q) : ℕ :=
  ∏ j : Fin q, (if j < i then 1 else Fintype.card H)

lemma cls_eq_iff (i : Fin q) (ω ω' : R × (Fin q → H)) :
    cls i ω' = cls i ω ↔ ω'.1 = ω.1 ∧ ∀ j : Fin q, j < i → ω'.2 j = ω.2 j := by
  unfold cls
  simp only [Prod.mk.injEq, funext_iff]
  constructor
  · rintro ⟨h1, h2⟩
    refine ⟨h1, fun j hj => ?_⟩
    have := h2 j
    simpa [hj] using this
  · rintro ⟨h1, h2⟩
    refine ⟨h1, fun j => ?_⟩
    by_cases hj : j < i
    · simp [hj, h2 j hj]
    · simp [hj]

/-- cardinality of the set of tables that agree with `h` on all `j` with `P j`. -/
lemma card_agree (P : Fin q → Prop) [DecidablePred P] (h : Fin q → H) :
    (univ.filter (fun h' : Fin q → H => ∀ j, P j → h' j = h j)).card
      = ∏ j : Fin q, (if P j then 1 else Fintype.card H) := by
  have : (univ.filter (fun h' : Fin q → H => ∀ j, P j → h' j = h j))
      = Fintype.piFinset (fun j => if P j then ({h j} : Finset H) else univ) := by
    ext h'
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Fintype.mem_piFinset]
    constructor
    · intro hh j
      by_cases hj : P j
      · simp [hj, hh j hj]
      · simp [hj]
    · intro hh j hj
      have := hh j
      simpa [hj] using this
  rw [this, Fintype.card_piFinset]
  apply Finset.prod_congr rfl
  intro j _
  by_cases hj : P j <;> simp [hj]

lemma card_cls (i : Fin q) (ω : R × (Fin q → H)) :
    (univ.filter (fun ω' : R × (Fin q → H) => cls i ω' = cls i ω)).card = csize q H i := by
  have : (univ.filter (fun ω' : R × (Fin q → H) => cls i ω' = cls i ω))
      = ({ω.1} : Finset R) ×ˢ (univ.filter (fun h' : Fin q → H => ∀ j, j < i → h' j = ω.2 j)) := by
    ext ⟨ρ', h'⟩
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_product,
      Finset.mem_singleton, cls_eq_iff]
  rw [this, Finset.card_product, card_agree (fun j => j < i)]
  simp [csize]

lemma card_cls_ans (i : Fin q) (ω : R × (Fin q → H)) (c : H) :
    (univ.filter (fun ω' : R × (Fin q → H) => cls i ω' = cls i ω ∧ ans i ω' = c)).card
      * Fintype.card H = csize q H i := by
  have : (univ.filter (fun ω' : R × (Fin q → H) => cls i ω' = cls i ω ∧ ans i ω' = c))
      = ({ω.1} : Finset R) ×ˢ
        (univ.filter (fun h' : Fin q → H => ∀ j, j ≤ i → h' j = (Function.update ω.2 i c) j)) := by
    ext ⟨ρ', h'⟩
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_product,
      Finset.mem_singleton, cls_eq_iff, ans]
    constructor
    · rintro ⟨⟨h1, h2⟩, h3⟩
      refine ⟨h1, fun j hj => ?_⟩
      rcases lt_or_eq_of_le hj with hlt | heq
      · rw [h2 j hlt, Function.update_of_ne (ne_of_lt hlt)]
      · subst heq; simp [h3]
    · rintro ⟨h1, h2⟩
      refine ⟨⟨h1, fun j hj => ?_⟩, ?_⟩
      · rw [h2 j hj.le, Function.update_of_ne (ne_of_lt hj)]
      · have := h2 i le_rfl; simpa using this
  rw [this, Finset.card_product, card_agree (fun j => j ≤ i)]
  simp only [Finset.card_singleton, one_mul, csize]
  -- ∏_j (if j ≤ i then 1 else |H|) * |H| = ∏_j (if j < i then 1 else |H|)
  rw [← Finset.mul_prod_erase (Finset.univ) (fun j : Fin q => if j < i then 1 else Fintype.card H) (Finset.mem_univ i),
      ← Finset.mul_prod_erase (Finset.univ) (fun j : Fin q => if j ≤ i then 1 else Fintype.card H) (Finset.mem_univ i)]
  have hr : ∏ j ∈ univ.erase i, (if j ≤ i then 1 else Fintype.card H)
      = ∏ j ∈ univ.erase i, (if j < i then 1 else Fintype.card H) := by
    apply Finset.prod_congr rfl
    intro j hj
    have hne : j ≠ i := Finset.ne_of_mem_erase hj
    have : (j ≤ i) ↔ (j < i) := ⟨fun h => lt_of_le_of_ne h hne, le_of_lt⟩
    simp [this]
  rw [hr]
  simp [mul_comm]

/-- accepting runs with fork index `i`. -/
def accSet (idx : R × (Fin q → H) → Option (Fin q)) (i : Fin q) : Finset (R × (Fin q → H)) :=
  univ.filter (fun ω => idx ω = some i)

/-- Success mass (`|Ω|` times the probability) of the forking experiment. -/
noncomputable def frkMass (idx : R × (Fin q → H) → Option (Fin q)) : ℝ :=
  forkMass (cls (R := R) (H := H) (q := q)) ans (csize q H) (accSet idx)

/-- The forking lemma, counting form:  `frk >= acc (acc / q - 1/|H|)`, where the probabilities
are `frkMass / |Ω|` and `accMass / |Ω|` and `|Ω| = |R| * |H|^q`. -/
theorem fork_rom (idx : R × (Fin q → H) → Option (Fin q)) [Nonempty R] [Nonempty H] :
    frkMass idx / (Fintype.card (R × (Fin q → H)) : ℝ) ≥
      (accMass (accSet idx) / (Fintype.card (R × (Fin q → H)) : ℝ)) *
        ((accMass (accSet idx) / (Fintype.card (R × (Fin q → H)) : ℝ)) / (q : ℝ)
          - 1 / (Fintype.card H : ℝ)) := by
  classical
  have hH : 0 < Fintype.card H := Fintype.card_pos
  have hΩ : 0 < Fintype.card (R × (Fin q → H)) := Fintype.card_pos
  have key := fork_mass_ge (cls (R := R) (H := H) (q := q)) ans (csize q H) (accSet idx)
    (fun i ω => card_cls i ω) (fun i ω c => card_cls_ans i ω c) hH hΩ
  have hΩr : (0 : ℝ) < Fintype.card (R × (Fin q → H)) := by exact_mod_cast hΩ
  have hHr : (0 : ℝ) < Fintype.card H := by exact_mod_cast hH
  simp only [Fintype.card_fin] at key
  set Ω := (Fintype.card (R × (Fin q → H)) : ℝ)
  set a := accMass (accSet idx)
  have e : a / Ω * (a / Ω / (q : ℝ) - 1 / (Fintype.card H : ℝ))
      = (a ^ 2 / ((q : ℝ) * Ω) - a / (Fintype.card H : ℝ)) / Ω := by
    by_cases hq : (q : ℝ) = 0
    · simp [hq]; field_simp
    · field_simp
  rw [e]
  exact div_le_div_of_nonneg_right key hΩr.le

end PcaMath.Rom
