import Mathlib

/-!
# T8b: conflict vetoes for the box class are refinement-invariant (P4, second half)

Box hypotheses over dimensions `d : ι` with linearly ordered values `X d`: a box is `Π_d T_d` with every side
order-convex (an interval; the empty box included). Each "yes" region must lie inside the hypothesis, so the
yes-consistent boxes are exactly the boxes containing `Y = ∪ yes-regions`. A "no" about `R` *conflicts* with all
of them iff `R` lies in every box containing `Y`.

* `boxHull Y = {x : ∀ d, ∃ a b ∈ Y, a_d ≤ x_d ≤ b_d}`, the smallest box containing `Y`
  (`subset_boxHull`, `isBox_boxHull`, `boxHull_minimal`);
* `conflict_iff_hull` : conflict ⇔ `R ⊆ boxHull Y`;
* refinement (`κ_d : Xf d → Xc d` monotone and onto, regions lifted by preimage):
  `boxHull_lift` : `boxHull (κ⁻¹ Y) = κ⁻¹ (boxHull Y)`;
* **T8b** (`T8b_conflict_invariant`) : the fine conflict test on lifted regions coincides with the coarse one,
  so coarse and fine conflict-vetoes coincide and T8 holds with vetoes for the box class.

The statement concerns the version space determined by the "yes" answers (earlier non-conflicting "no"
answers that do not cut off `boxHull Y` leave it in the version space, so the same characterisation applies).
For unions and decision lists the conflict sets can differ, as the spec says; nothing is claimed there.
-/

namespace PcaIntent.Hull

variable {ι : Type*} {X : ι → Type*} [∀ d, LinearOrder (X d)]

/-- A box with interval sides. -/
def IsBox (θ : Set (∀ d, X d)) : Prop :=
  ∃ T : ∀ d, Set (X d), (∀ d, (T d).OrdConnected) ∧ θ = {x | ∀ d, x d ∈ T d}

/-- The smallest box containing `Y`. -/
def boxHull (Y : Set (∀ d, X d)) : Set (∀ d, X d) :=
  {x | ∀ d, ∃ a ∈ Y, ∃ b ∈ Y, a d ≤ x d ∧ x d ≤ b d}

theorem subset_boxHull (Y : Set (∀ d, X d)) : Y ⊆ boxHull Y :=
  fun x hx d => ⟨x, hx, x, hx, le_rfl, le_rfl⟩

theorem isBox_boxHull (Y : Set (∀ d, X d)) : IsBox (boxHull Y) := by
  refine ⟨fun d => {z | ∃ a ∈ Y, ∃ b ∈ Y, a d ≤ z ∧ z ≤ b d}, fun d => ⟨?_⟩, rfl⟩
  intro z1 h1 z2 h2 z hz
  obtain ⟨a, ha, -, -, ha1, -⟩ := h1
  obtain ⟨-, -, b, hb, -, hb2⟩ := h2
  exact ⟨a, ha, b, hb, le_trans ha1 hz.1, le_trans hz.2 hb2⟩

theorem boxHull_minimal {Y θ : Set (∀ d, X d)} (hθ : IsBox θ) (hY : Y ⊆ θ) : boxHull Y ⊆ θ := by
  obtain ⟨T, hT, rfl⟩ := hθ
  intro x hx d
  obtain ⟨a, ha, b, hb, hax, hxb⟩ := hx d
  exact (hT d).out (hY ha d) (hY hb d) ⟨hax, hxb⟩

/-- **Conflict characterisation.** A "no" about `R` contradicts every yes-consistent box iff
`R ⊆ boxHull Y`. -/
theorem conflict_iff_hull (Y R : Set (∀ d, X d)) :
    (∀ θ, IsBox θ → Y ⊆ θ → R ⊆ θ) ↔ R ⊆ boxHull Y := by
  constructor
  · intro h
    exact h _ (isBox_boxHull Y) (subset_boxHull Y)
  · intro hR θ hθ hY
    exact Set.Subset.trans hR (boxHull_minimal hθ hY)

/-! ## Refinement -/

variable {Xf : ι → Type*} [∀ d, LinearOrder (Xf d)]

/-- The product of the per-dimension refinement maps. -/
def kap (κ : ∀ d, Xf d → X d) (x : ∀ d, Xf d) : ∀ d, X d := fun d => κ d (x d)

/-- Lifting a coarse region to the fine space: its preimage. -/
def lift (κ : ∀ d, Xf d → X d) (S : Set (∀ d, X d)) : Set (∀ d, Xf d) := {x | kap κ x ∈ S}

/-- Hull commutes with lifting, for monotone onto refinements. -/
theorem boxHull_lift [DecidableEq ι] (κ : ∀ d, Xf d → X d) (hmono : ∀ d, Monotone (κ d))
    (hsurj : ∀ d, Function.Surjective (κ d)) (Y : Set (∀ d, X d)) :
    boxHull (lift κ Y) = lift κ (boxHull Y) := by
  -- a fine preimage of any coarse point
  have pre : ∀ A : ∀ d, X d, ∃ a : ∀ d, Xf d, kap κ a = A := fun A =>
    ⟨fun d => (hsurj d (A d)).choose, funext fun d => (hsurj d (A d)).choose_spec⟩
  ext x
  simp only [boxHull, lift, Set.mem_setOf_eq]
  constructor
  · intro hx d
    obtain ⟨a, ha, b, hb, hax, hxb⟩ := hx d
    exact ⟨kap κ a, ha, kap κ b, hb, hmono d hax, hmono d hxb⟩
  · intro hx d
    obtain ⟨A, hA, B, hB, hAx, hxB⟩ := hx d
    obtain ⟨a', ha'⟩ := pre A
    obtain ⟨b', hb'⟩ := pre B
    -- adjust the d-th coordinate so that the fine witnesses bracket `x d`
    let a := Function.update a' d (min (a' d) (x d))
    let b := Function.update b' d (max (b' d) (x d))
    have hka : kap κ a = A := by
      funext d'
      by_cases hd : d' = d
      · subst hd
        show κ d' (Function.update a' d' (min (a' d') (x d')) d') = A d'
        rw [Function.update_self, (hmono d').map_min]
        have : κ d' (a' d') = A d' := congrFun ha' d'
        rw [this]; exact min_eq_left hAx
      · show κ d' (Function.update a' d (min (a' d) (x d)) d') = A d'
        rw [Function.update_of_ne hd]; exact congrFun ha' d'
    have hkb : kap κ b = B := by
      funext d'
      by_cases hd : d' = d
      · subst hd
        show κ d' (Function.update b' d' (max (b' d') (x d')) d') = B d'
        rw [Function.update_self, (hmono d').map_max]
        have : κ d' (b' d') = B d' := congrFun hb' d'
        rw [this]; exact max_eq_left hxB
      · show κ d' (Function.update b' d (max (b' d) (x d)) d') = B d'
        rw [Function.update_of_ne hd]; exact congrFun hb' d'
    refine ⟨a, ?_, b, ?_, ?_, ?_⟩
    · show kap κ a ∈ Y; rw [hka]; exact hA
    · show kap κ b ∈ Y; rw [hkb]; exact hB
    · show Function.update a' d (min (a' d) (x d)) d ≤ x d
      rw [Function.update_self]; exact min_le_right _ _
    · show x d ≤ Function.update b' d (max (b' d) (x d)) d
      rw [Function.update_self]; exact le_max_right _ _

/-- Lifting reflects inclusion when the refinement is onto. -/
theorem lift_subset_iff (κ : ∀ d, Xf d → X d) (hsurj : ∀ d, Function.Surjective (κ d))
    (R S : Set (∀ d, X d)) : lift κ R ⊆ lift κ S ↔ R ⊆ S := by
  constructor
  · intro h A hA
    let a : ∀ d, Xf d := fun d => (hsurj d (A d)).choose
    have hka : kap κ a = A := funext fun d => (hsurj d (A d)).choose_spec
    have : a ∈ lift κ R := by show kap κ a ∈ R; rw [hka]; exact hA
    have h2 := h this
    change kap κ a ∈ S at h2
    rwa [hka] at h2
  · intro h x hx
    exact h hx

/-- **T8b.** For the box class, the fine conflict test on lifted regions is the coarse conflict test: a coarse
"no" is vetoed iff its lifted fine version is. -/
theorem T8b_conflict_invariant [DecidableEq ι] (κ : ∀ d, Xf d → X d) (hmono : ∀ d, Monotone (κ d))
    (hsurj : ∀ d, Function.Surjective (κ d)) (Y R : Set (∀ d, X d)) :
    (∀ θ : Set (∀ d, Xf d), IsBox θ → lift κ Y ⊆ θ → lift κ R ⊆ θ) ↔
      (∀ θ : Set (∀ d, X d), IsBox θ → Y ⊆ θ → R ⊆ θ) := by
  rw [conflict_iff_hull (lift κ Y) (lift κ R), conflict_iff_hull Y R, boxHull_lift κ hmono hsurj,
    lift_subset_iff κ hsurj]

end PcaIntent.Hull
