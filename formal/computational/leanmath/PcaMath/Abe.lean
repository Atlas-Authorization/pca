import Mathlib

/-!
# ABE-A / ABE-4: Shamir access trees (the access structure of `packages/pca-abe`; FAME's span program is this sharing)

A tree has threshold gates and leaves (attribute positions).  `Ach T σ f` says that the leaf-share assignment
`f` is a possible output of the Shamir sharing of the secret `σ` along `T` (every gate with threshold `t`
picks a polynomial of degree `< t` with constant term = its secret and hands `q(j+1)` to child `j`).

* `reconstruction` : if the attribute set `Xs` satisfies `T`, there are coefficients `c` supported on `Xs` with
  `Σ c x * f x = σ` for EVERY sharing  (Lagrange interpolation at 0 on `t` qualified children, recursively).
* `privacy`        : if `Xs` does not satisfy `T`, for every secret there is a sharing in which all shares of `Xs`
  are `0` (so the shares of `Xs` carry no information; in particular the secret `1` has a sharing vanishing on `Xs`).
Together: `s ∈ span{λ_x : x ∈ Xs}` iff `Xs` satisfies `T` (Lemma ABE-A).  `decrypt` succeeds iff the tree is
satisfied (ABE-4) because `plan()` computes exactly `Qual`.
-/

open Finset Polynomial

namespace PcaMath.Abe

variable {F : Type*} [Field F]

inductive T : Type
  | leaf (i : ℕ) : T
  | gate (t k : ℕ) (cs : Fin k → T) : T

namespace T

noncomputable def leaves : T → Finset ℕ
  | leaf i => {i}
  | gate _ k cs => Finset.univ.biUnion (fun j : Fin k => leaves (cs j))

/-- well-formed: fan-in at most `K`, the leaves of distinct children are disjoint, recursively -/
def Wf (K : ℕ) : T → Prop
  | leaf _ => True
  | gate _ k cs => k ≤ K ∧ (∀ j, Wf K (cs j)) ∧ ∀ j j', j ≠ j' → Disjoint (leaves (cs j)) (leaves (cs j'))

open Classical in
/-- the tree is satisfied by the attribute positions `Xs` (what `plan()`/boolean evaluation computes) -/
noncomputable def Qual (Xs : Finset ℕ) : T → Prop
  | leaf i => i ∈ Xs
  | gate t k cs => t ≤ (Finset.univ.filter (fun j : Fin k => Qual Xs (cs j))).card

def Ach : T → F → (ℕ → F) → Prop
  | leaf i, σ, f => f i = σ
  | gate t k cs, σ, f =>
      ∃ q : F[X], q.degree < t ∧ q.eval 0 = σ ∧ ∀ j : Fin k, Ach (cs j) (q.eval ((j : F) + 1)) f

theorem Ach_congr : ∀ (T : T) (σ : F) (f g : ℕ → F), (∀ x ∈ T.leaves, f x = g x) → Ach T σ f → Ach T σ g
  | leaf i, σ, f, g, h, hA => by
      simp only [Ach] at hA ⊢
      rw [← h i (by simp [leaves])]; exact hA
  | gate t k cs, σ, f, g, h, ⟨q, hq1, hq2, hq3⟩ => by
      refine ⟨q, hq1, hq2, fun j => ?_⟩
      refine Ach_congr (cs j) _ f g (fun x hx => h x ?_) (hq3 j)
      simp only [leaves, Finset.mem_biUnion, Finset.mem_univ, true_and]
      exact ⟨j, hx⟩

theorem Ach_zero : ∀ (T : T), Ach T (0 : F) (fun _ => 0)
  | leaf i => rfl
  | gate t k cs => ⟨0, by simp, by simp, fun j => by simpa using Ach_zero (cs j)⟩

/-- the evaluation points `1, 2, ..., K` are distinct and nonzero in `F` -/
def GoodIdx (F : Type*) [Field F] (K : ℕ) : Prop :=
  ∀ i j : ℕ, i < K → j < K → (((i : F) + 1 = (j : F) + 1) → i = j) ∧ ((i : F) + 1 ≠ 0)

open Classical in
/-- gluing assignments of disjoint children -/
theorem glue (k : ℕ) (cs : Fin k → T) (hdis : ∀ j j', j ≠ j' → Disjoint (leaves (cs j)) (leaves (cs j')))
    (g : Fin k → ℕ → F) :
    ∃ f : ℕ → F, ∀ j, ∀ x ∈ leaves (cs j), f x = g j x := by
  refine ⟨fun x => if h : ∃ j, x ∈ leaves (cs j) then g (Classical.choose h) x else 0, fun j x hx => ?_⟩
  have h : ∃ j, x ∈ leaves (cs j) := ⟨j, hx⟩
  simp only [h, dite_true]
  have hj := Classical.choose_spec h
  by_cases e : Classical.choose h = j
  · rw [e]
  · exact absurd hx (Finset.disjoint_left.mp (hdis _ _ e) hj)

open Classical in
theorem privacy (K : ℕ) (hK : GoodIdx F K) :
    ∀ (T : T), Wf K T → ∀ (Xs : Finset ℕ), ¬ Qual Xs T → ∀ σ : F,
      ∃ f : ℕ → F, Ach T σ f ∧ ∀ x ∈ Xs, x ∈ T.leaves → f x = 0
  | leaf i, _, Xs, hq, σ => by
      refine ⟨fun x => if x = i then σ else 0, by simp [Ach], ?_⟩
      intro x hx hxl
      simp only [leaves, Finset.mem_singleton] at hxl
      subst hxl
      exact absurd hx hq
  | gate t k cs, ⟨hk, hw, hdis⟩, Xs, hq, σ => by
      set Qs := Finset.univ.filter (fun j : Fin k => Qual Xs (cs j)) with hQs
      have hlt : Qs.card < t := not_le.mp (by simpa [Qual, hQs] using hq)
      let q : F[X] := C σ * ∏ j ∈ Qs, (1 - C (((j : F) + 1)⁻¹) * X)
      have hq0 : q.eval 0 = σ := by simp [q, eval_prod]
      have hqdeg : q.degree < t := by
        by_cases hz : q = 0
        · rw [hz, degree_zero]; exact WithBot.bot_lt_coe t
        · have h1 : q.natDegree ≤ Qs.card := by
            calc q.natDegree ≤ (C σ : F[X]).natDegree + (∏ j ∈ Qs, (1 - C (((j : F) + 1)⁻¹) * X)).natDegree :=
                  natDegree_mul_le
              _ ≤ 0 + Qs.card := by
                  refine add_le_add (by simp) ?_
                  calc (∏ j ∈ Qs, (1 - C (((j : F) + 1)⁻¹) * X)).natDegree
                      ≤ ∑ j ∈ Qs, (1 - C (((j : F) + 1)⁻¹) * X).natDegree := natDegree_prod_le _ _
                    _ ≤ ∑ _j ∈ Qs, 1 := by
                        refine Finset.sum_le_sum fun j _ => ?_
                        calc (1 - C (((j : F) + 1)⁻¹) * X).natDegree
                            ≤ max (1 : F[X]).natDegree (C (((j : F) + 1)⁻¹) * X).natDegree := natDegree_sub_le _ _
                          _ ≤ 1 := by
                              refine max_le (by simp) ?_
                              exact (natDegree_C_mul_le _ _).trans (by simp)
                    _ = Qs.card := by simp
              _ = Qs.card := by simp
          exact (natDegree_lt_iff_degree_lt hz).mp (lt_of_le_of_lt h1 hlt)
      -- shares: children in Qs get the zero sharing, the others a sharing vanishing on Xs
      have hex : ∀ j : Fin k, ∃ g : ℕ → F, Ach (cs j) (q.eval ((j : F) + 1)) g ∧ ∀ x ∈ Xs, x ∈ (cs j).leaves → g x = 0 := by
        intro j
        by_cases hj : j ∈ Qs
        · have hv : q.eval ((j : F) + 1) = 0 := by
            simp only [q, eval_mul, eval_C, eval_prod]
            rw [Finset.prod_eq_zero hj]
            · simp
            · have hne := (hK j j (lt_of_lt_of_le j.2 hk) (lt_of_lt_of_le j.2 hk)).2
              simp only [eval_sub, eval_one, eval_mul, eval_C, eval_X]
              rw [inv_mul_cancel₀ hne]; ring
          exact ⟨fun _ => 0, by rw [hv]; exact Ach_zero _, fun _ _ _ => rfl⟩
        · have hnq : ¬ Qual Xs (cs j) := by simpa [hQs] using hj
          exact privacy K hK (cs j) (hw j) Xs hnq _ |>.imp fun g hg => hg
      choose g hg using hex
      obtain ⟨f, hf⟩ := glue k cs hdis g
      refine ⟨f, ⟨q, hqdeg, hq0, fun j => ?_⟩, ?_⟩
      · exact Ach_congr (cs j) _ (g j) f (fun x hx => (hf j x hx).symm) (hg j).1
      · intro x hx hxl
        simp only [leaves, Finset.mem_biUnion, Finset.mem_univ, true_and] at hxl
        obtain ⟨j, hj⟩ := hxl
        rw [hf j x hj]
        exact (hg j).2 x hx hj


open Classical in
theorem reconstruction (K : ℕ) (hK : GoodIdx F K) :
    ∀ (T : T), Wf K T → ∀ (Xs : Finset ℕ), Qual Xs T →
      ∃ c : ℕ → F, (∀ x, x ∉ Xs → c x = 0) ∧ (∀ x, x ∉ T.leaves → c x = 0) ∧
        ∀ (σ : F) (f : ℕ → F), Ach T σ f → ∑ x ∈ T.leaves, c x * f x = σ
  | leaf i, _, Xs, hq => by
      refine ⟨fun x => if x = i then 1 else 0, ?_, ?_, ?_⟩
      · intro x hx
        have : x ≠ i := fun e => hx (e ▸ hq)
        simp [this]
      · intro x hx
        have : x ≠ i := by intro e; apply hx; simp [leaves, e]
        simp [this]
      · intro σ f hA
        simp only [Ach] at hA
        simp [leaves, hA]
  | gate t k cs, ⟨hk, hw, hdis⟩, Xs, hq => by
      set Qs := Finset.univ.filter (fun j : Fin k => Qual Xs (cs j)) with hQs
      have hge : t ≤ Qs.card := by simpa [Qual, hQs] using hq
      obtain ⟨S, hSQ, hSc⟩ := Finset.exists_subset_card_eq hge
      have hIH : ∀ j : Fin k, ∃ c : ℕ → F, j ∈ S →
          (∀ x, x ∉ Xs → c x = 0) ∧ (∀ x, x ∉ (cs j).leaves → c x = 0) ∧
          ∀ (σ : F) (f : ℕ → F), Ach (cs j) σ f → ∑ x ∈ (cs j).leaves, c x * f x = σ := by
        intro j
        by_cases hj : j ∈ S
        · have hjq : Qual Xs (cs j) := by simpa [hQs] using hSQ hj
          obtain ⟨c, hc⟩ := reconstruction K hK (cs j) (hw j) Xs hjq
          exact ⟨c, fun _ => hc⟩
        · exact ⟨fun _ => 0, fun h => absurd h hj⟩
      choose cj hcj using hIH
      let v : Fin k → F := fun j => (j : F) + 1
      have hv : Set.InjOn v S := by
        intro a ha b hb hab
        have := (hK a b (lt_of_lt_of_le a.2 hk) (lt_of_lt_of_le b.2 hk)).1 hab
        exact Fin.ext this
      let lag : Fin k → F := fun j => (Lagrange.basis S v j).eval 0
      refine ⟨fun x => ∑ j ∈ S, lag j * cj j x, ?_, ?_, ?_⟩
      · intro x hx
        exact Finset.sum_eq_zero fun j hj => by simp [(hcj j hj).1 x hx]
      · intro x hx
        refine Finset.sum_eq_zero fun j hj => ?_
        have : x ∉ (cs j).leaves := fun h => hx (by
          simp only [leaves, Finset.mem_biUnion, Finset.mem_univ, true_and]; exact ⟨j, h⟩)
        simp [(hcj j hj).2.1 x this]
      · intro σ f ⟨q, hqd, hq0, hqs⟩
        have hqS : q.degree < (S.card : WithBot ℕ) := by rw [hSc]; exact hqd
        have hint := Lagrange.eq_interpolate (v := v) hv hqS
        have h0 : q.eval 0 = ∑ j ∈ S, q.eval (v j) * lag j := by
          conv_lhs => rw [hint]
          rw [Lagrange.interpolate_apply, eval_finset_sum]
          simp [lag, eval_mul, eval_C]
        calc ∑ x ∈ (gate t k cs).leaves, (∑ j ∈ S, lag j * cj j x) * f x
            = ∑ x ∈ (gate t k cs).leaves, ∑ j ∈ S, lag j * (cj j x * f x) := by
              refine Finset.sum_congr rfl fun x _ => ?_
              rw [Finset.sum_mul]; refine Finset.sum_congr rfl fun j _ => by ring
          _ = ∑ j ∈ S, lag j * ∑ x ∈ (gate t k cs).leaves, cj j x * f x := by
              rw [Finset.sum_comm]
              refine Finset.sum_congr rfl fun j _ => ?_
              rw [Finset.mul_sum]
          _ = ∑ j ∈ S, lag j * q.eval (v j) := by
              refine Finset.sum_congr rfl fun j hj => ?_
              congr 1
              have hsub : (cs j).leaves ⊆ (gate t k cs).leaves := by
                intro x hx
                simp only [leaves, Finset.mem_biUnion, Finset.mem_univ, true_and]; exact ⟨j, hx⟩
              rw [← Finset.sum_subset hsub (fun x _ hx => by simp [(hcj j hj).2.1 x hx])]
              exact (hcj j hj).2.2 _ f (hqs j)
          _ = q.eval 0 := by rw [h0]; exact Finset.sum_congr rfl fun j _ => by ring
          _ = σ := hq0


/-- ABE-4, the "no" direction: if the key's attributes do not satisfy the tree there are two sharings of
different secrets (`0` and `1`) that agree on every share the key can use: nothing determines the secret. -/
theorem no_recovery (K : ℕ) (hK : GoodIdx F K) (T : T) (hw : Wf K T) (Xs : Finset ℕ) (hq : ¬ Qual Xs T) :
    ∃ f₀ f₁ : ℕ → F, Ach T (0 : F) f₀ ∧ Ach T (1 : F) f₁ ∧ ∀ x ∈ Xs, x ∈ T.leaves → f₀ x = f₁ x := by
  obtain ⟨f₁, h1, hz⟩ := privacy K hK T hw Xs hq (1 : F)
  exact ⟨fun _ => 0, f₁, Ach_zero T, h1, fun x hx hl => (hz x hx hl).symm⟩

end T

end PcaMath.Abe
