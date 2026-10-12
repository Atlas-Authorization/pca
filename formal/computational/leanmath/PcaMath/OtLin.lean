import Mathlib
open Finset

namespace PcaMath.OtLin

variable {D : Type*} [AddCommGroup D] [Fintype D] [DecidableEq D]
variable {Var : Type*} [Fintype Var] [DecidableEq Var]

/-- `(some i, c)` is the term `σ i + c`; `(none, c)` is the constant `c`. -/
abbrev Term (Var D : Type*) := Option Var × D

def Term.eval (σ : Var → D) : Term Var D → D
  | (some i, c) => σ i + c
  | (none, c) => c

omit [DecidableEq D] in
lemma card_le_of_det (i : Var) (P : (Var → D) → Prop) [DecidablePred P]
    (h : ∀ σ σ', P σ → P σ' → (∀ v, v ≠ i → σ v = σ' v) → σ = σ') :
    (Finset.univ.filter P).card ≤ Fintype.card D ^ (Fintype.card Var - 1) := by
  classical
  have key := Finset.card_le_card_of_injOn
    (s := Finset.univ.filter P) (t := (Finset.univ : Finset ({v // v ≠ i} → D)))
    (fun σ (v : {v // v ≠ i}) => σ v.1) (by intro σ _; simp) (by
      intro σ hσ σ' hσ' he
      simp only [Finset.coe_filter, Finset.mem_univ, true_and, Set.mem_setOf_eq] at hσ hσ'
      exact h σ σ' hσ hσ' (fun v hv => congrFun he ⟨v, hv⟩))
  have hc : Fintype.card {v // v ≠ i} = Fintype.card Var - 1 := by
    simp [Fintype.card_subtype_compl]
  simpa [Fintype.card_fun, hc] using key

/-- two terms over different variables (or one constant, the other not: `.1` differ) agree on at most
`|D|^(|Var|-1)` assignments. -/
theorem card_event_le (t1 t2 : Term Var D) (h : t1.1 ≠ t2.1) :
    (Finset.univ.filter (fun σ : Var → D => t1.eval σ = t2.eval σ)).card
      ≤ Fintype.card D ^ (Fintype.card Var - 1) := by
  rcases t1 with ⟨_ | i, c1⟩ <;> rcases t2 with ⟨_ | j, c2⟩
  · exact absurd rfl h
  · -- c1 = σ j + c2
    refine card_le_of_det j _ ?_
    intro σ σ' hσ hσ' he
    simp only [Term.eval] at hσ hσ'
    funext v
    by_cases hv : v = j
    · subst hv
      have := hσ.symm.trans hσ'
      simpa using this
    · exact he v hv
  · refine card_le_of_det i _ ?_
    intro σ σ' hσ hσ' he
    simp only [Term.eval] at hσ hσ'
    funext v
    by_cases hv : v = i
    · subst hv
      have := hσ.trans hσ'.symm
      simpa using this
    · exact he v hv
  · have hij : i ≠ j := by
      intro e; apply h; simp [e]
    refine card_le_of_det i _ ?_
    intro σ σ' hσ hσ' he
    simp only [Term.eval] at hσ hσ'
    funext v
    by_cases hv : v = i
    · subst hv
      have h1 : σ v = σ j + c2 - c1 := by rw [← hσ]; abel
      have h2 : σ' v = σ' j + c2 - c1 := by rw [← hσ']; abel
      rw [h1, h2, he j (Ne.symm hij)]
    · exact he v hv

/-- same variable (or both constant) but different offsets: never equal. -/
theorem event_empty (t1 t2 : Term Var D) (h : t1.1 = t2.1) (hc : t1.2 ≠ t2.2) (σ : Var → D) :
    t1.eval σ ≠ t2.eval σ := by
  rcases t1 with ⟨_ | i, c1⟩ <;> rcases t2 with ⟨_ | j, c2⟩
  · simpa [Term.eval] using hc
  · simp at h
  · simp at h
  · simp at h
    subst h
    intro e
    apply hc
    simpa [Term.eval] using e

/-- union bound over unordered pairs of a family of terms in which any two distinct members that share their
variable have different offsets. -/
theorem card_bad_le {ι : Type*} [Fintype ι] [DecidableEq ι] (T : ι → Term Var D)
    (hsame : ∀ p p', p ≠ p' → (T p).1 = (T p').1 → (T p).2 ≠ (T p').2) :
    (Finset.univ.filter (fun σ : Var → D => ∃ p p', p ≠ p' ∧ (T p).eval σ = (T p').eval σ)).card
      ≤ (Fintype.card ι).choose 2 * Fintype.card D ^ (Fintype.card Var - 1) := by
  classical
  have hsub : (Finset.univ.filter (fun σ : Var → D => ∃ p p', p ≠ p' ∧ (T p).eval σ = (T p').eval σ))
      ⊆ (Finset.powersetCard 2 (Finset.univ : Finset ι)).biUnion
        (fun s => Finset.univ.filter (fun σ : Var → D =>
          ∃ p ∈ s, ∃ p' ∈ s, p ≠ p' ∧ (T p).eval σ = (T p').eval σ)) := by
    intro σ hσ
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hσ
    obtain ⟨p, p', hne, he⟩ := hσ
    simp only [Finset.mem_biUnion, Finset.mem_powersetCard, Finset.subset_univ, true_and,
      Finset.mem_filter, Finset.mem_univ]
    refine ⟨{p, p'}, Finset.card_pair hne, p, by simp, p', by simp, hne, he⟩
  refine (Finset.card_le_card hsub).trans (Finset.card_biUnion_le.trans ?_)
  have : ∀ s ∈ Finset.powersetCard 2 (Finset.univ : Finset ι),
      (Finset.univ.filter (fun σ : Var → D =>
          ∃ p ∈ s, ∃ p' ∈ s, p ≠ p' ∧ (T p).eval σ = (T p').eval σ)).card
        ≤ Fintype.card D ^ (Fintype.card Var - 1) := by
    intro s hs
    rw [Finset.mem_powersetCard] at hs
    obtain ⟨a, b, hab, rfl⟩ := Finset.card_eq_two.mp hs.2
    by_cases h1 : (T a).1 = (T b).1
    · have : (Finset.univ.filter (fun σ : Var → D =>
          ∃ p ∈ ({a, b} : Finset ι), ∃ p' ∈ ({a, b} : Finset ι), p ≠ p' ∧
            (T p).eval σ = (T p').eval σ)) = ∅ := by
        apply Finset.filter_eq_empty_iff.mpr
        intro σ _ ⟨p, hp, p', hp', hpp, he⟩
        simp only [Finset.mem_insert, Finset.mem_singleton] at hp hp'
        rcases hp with rfl | rfl <;> rcases hp' with rfl | rfl
        · exact hpp rfl
        · exact event_empty _ _ h1 (hsame _ _ hab h1) σ he
        · exact event_empty _ _ h1.symm (hsame _ _ hab.symm h1.symm) σ he
        · exact hpp rfl
      rw [this]; simp
    · refine le_trans (Finset.card_le_card ?_) (card_event_le (T a) (T b) h1)
      intro σ hσ
      simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_insert,
        Finset.mem_singleton] at hσ ⊢
      obtain ⟨p, hp, p', hp', hpp, he⟩ := hσ
      rcases hp with rfl | rfl <;> rcases hp' with rfl | rfl
      · exact absurd rfl hpp
      · exact he
      · exact he.symm
      · exact absurd rfl hpp
  refine (Finset.sum_le_sum this).trans ?_
  rw [Finset.sum_const, Finset.card_powersetCard, Finset.card_univ]
  simp

/-- real-valued form, safe when `Var` is empty. -/
theorem card_bad_le_real {ι : Type*} [Fintype ι] [DecidableEq ι] (T : ι → Term Var D)
    (hsame : ∀ p p', p ≠ p' → (T p).1 = (T p').1 → (T p).2 ≠ (T p').2) :
    ((Finset.univ.filter (fun σ : Var → D =>
        ∃ p p', p ≠ p' ∧ (T p).eval σ = (T p').eval σ)).card : ℝ) * (Fintype.card D : ℝ)
      ≤ ((Fintype.card ι).choose 2 : ℝ) * (Fintype.card D : ℝ) ^ (Fintype.card Var) := by
  classical
  rcases Nat.eq_zero_or_pos (Fintype.card Var) with h0 | hpos
  · have hv : IsEmpty Var := Fintype.card_eq_zero_iff.mp h0
    have hempty : (Finset.univ.filter (fun σ : Var → D =>
        ∃ p p', p ≠ p' ∧ (T p).eval σ = (T p').eval σ)) = ∅ := by
      apply Finset.filter_eq_empty_iff.mpr
      rintro σ _ ⟨p, p', hne, he⟩
      have h1 : ∀ q, (T q).1 = none := fun q => by
        rcases h : (T q).1 with _ | i
        · rfl
        · exact (hv.false i).elim
      exact event_empty _ _ ((h1 p).trans (h1 p').symm) (hsame _ _ hne ((h1 p).trans (h1 p').symm))
        σ he
    rw [hempty]
    simp only [Finset.card_empty, Nat.cast_zero, zero_mul]
    positivity
  · have h := card_bad_le T hsame
    have h' : ((Finset.univ.filter (fun σ : Var → D =>
        ∃ p p', p ≠ p' ∧ (T p).eval σ = (T p').eval σ)).card : ℝ)
        ≤ ((Fintype.card ι).choose 2 * Fintype.card D ^ (Fintype.card Var - 1) : ℕ) := by
      exact_mod_cast h
    have hD : (0 : ℝ) ≤ (Fintype.card D : ℝ) := Nat.cast_nonneg _
    calc _ ≤ ((Fintype.card ι).choose 2 * Fintype.card D ^ (Fintype.card Var - 1) : ℕ) *
          (Fintype.card D : ℝ) := mul_le_mul_of_nonneg_right h' hD
      _ = _ := by
        push_cast
        have : Fintype.card Var = (Fintype.card Var - 1) + 1 := by omega
        conv_rhs => rw [this, pow_succ]
        ring

end PcaMath.OtLin
