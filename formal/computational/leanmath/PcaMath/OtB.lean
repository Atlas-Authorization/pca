import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtHC

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

/-- a table of hash entries is a partial function -/
def Func {α β : Type} (ctx : Finset (α × β)) : Prop := ∀ p ∈ ctx, ∀ q ∈ ctx, p.1 = q.1 → p.2 = q.2

/-- structural impossibility in the real world: a zero output, or two outputs of one correlation/input group
that coincide (for different tweaks). -/
def BadH (S : Finset ((V × D × D) × D)) : Prop :=
  (∃ h ∈ S, h.2 = 0) ∨
  (∃ h ∈ S, ∃ h' ∈ S, h.1.1 = h'.1.1 ∧ h.1.2.1 = h'.1.2.1 ∧ h ≠ h' ∧ h.2 = h'.2)

/-- `fb r s = (s+1) + (s+2) + ... + (s+r)` -/
def fb (r s : ℕ) : ℝ := ∑ j ∈ range r, ((s + j + 1 : ℕ) : ℝ)

theorem fb_succ (r s : ℕ) : fb (r + 1) s = ((s + 1 : ℕ) : ℝ) + fb r (s + 1) := by
  unfold fb
  rw [Finset.sum_range_succ' _ r]
  have : ∀ j ∈ range r, ((s + (j + 1) + 1 : ℕ) : ℝ) = ((s + 1 + j + 1 : ℕ) : ℝ) := by
    intros; push_cast; ring
  rw [Finset.sum_congr rfl this]; push_cast; ring

theorem fb_mono {r r' : ℕ} (s : ℕ) (h : r ≤ r') : fb r s ≤ fb r' s := by
  unfold fb
  apply Finset.sum_le_sum_of_subset_of_nonneg
  · exact Finset.range_mono h
  · intro i _ _; positivity

theorem fb_nonneg (r s : ℕ) : 0 ≤ fb r s := by unfold fb; positivity

theorem Func_card_lt {α β : Type} [Fintype α] [DecidableEq α] {ctx : Finset (α × β)} (hf : Func ctx)
    (pt : α) (hpt : ∀ o, (pt, o) ∉ ctx) : ctx.card < Fintype.card α := by
  have hinj : Set.InjOn Prod.fst (ctx : Set (α × β)) := by
    intro p hp q hq h
    exact Prod.ext h (hf p hp q hq h)
  have h1 : (ctx.image Prod.fst).card = ctx.card := Finset.card_image_of_injOn hinj
  have h2 : (ctx.image Prod.fst) ⊂ (Finset.univ : Finset α) := by
    refine ⟨Finset.subset_univ _, fun hs => ?_⟩
    have := hs (Finset.mem_univ pt)
    obtain ⟨⟨a, b⟩, hm, rfl⟩ := Finset.mem_image.mp this
    exact hpt b hm
  rw [← h1]
  exact lt_of_lt_of_le (Finset.card_lt_card h2) (by simp)

theorem Func_insert {α β : Type} [DecidableEq α] [DecidableEq β] {ctx : Finset (α × β)} (hf : Func ctx)
    (pt : α) (o : β) (hpt : ∀ o', (pt, o') ∉ ctx) : Func (insert (pt, o) ctx) := by
  have key : ∀ q ∈ ctx, q.1 ≠ pt := by
    intro q hq h
    apply hpt q.2
    have : q = (pt, q.2) := Prod.ext h rfl
    rw [this] at hq; exact hq
  intro p hp q hq h
  rcases Finset.mem_insert.mp hp with rfl | hp
  · rcases Finset.mem_insert.mp hq with rfl | hq
    · rfl
    · exact absurd h.symm (key q hq)
  · rcases Finset.mem_insert.mp hq with rfl | hq
    · exact absurd h (key p hp)
    · exact hf p hp q hq h

theorem BadH_insert_iff {ctx : Finset ((V × D × D) × D)} (hf : Func ctx) (hnb : ¬ BadH ctx)
    (pt : V × D × D) (hpt : ∀ o', (pt, o') ∉ ctx) (o : D) :
    BadH (insert (pt, o) ctx) ↔
      o = 0 ∨ ∃ h' ∈ ctx, h'.1.1 = pt.1 ∧ h'.1.2.1 = pt.2.1 ∧ h'.2 = o := by
  constructor
  · rintro (⟨h, hh, h0⟩ | ⟨h, hh, h', hh', hv, hx, hne, hoo⟩)
    · rcases Finset.mem_insert.mp hh with rfl | hh
      · exact Or.inl h0
      · exact absurd (Or.inl ⟨h, hh, h0⟩) hnb
    · rcases Finset.mem_insert.mp hh with rfl | hh <;> rcases Finset.mem_insert.mp hh' with rfl | hh'
      · exact absurd rfl hne
      · exact Or.inr ⟨h', hh', hv.symm, hx.symm, hoo.symm⟩
      · exact Or.inr ⟨h, hh, hv, hx, hoo⟩
      · exact absurd (Or.inr ⟨h, hh, h', hh', hv, hx, hne, hoo⟩) hnb
  · rintro (h0 | ⟨h', hh', hv, hx, hoo⟩)
    · exact Or.inl ⟨(pt, o), Finset.mem_insert_self _ _, h0⟩
    · refine Or.inr ⟨(pt, o), Finset.mem_insert_self _ _, h', Finset.mem_insert_of_mem hh', hv.symm, hx.symm, ?_, hoo.symm⟩
      intro heq
      exact hpt o (by rw [heq]; exact hh')

end PcaMath.OtDefs
