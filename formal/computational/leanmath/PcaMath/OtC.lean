import Mathlib
import PcaMath.OtDefs
import PcaMath.OtA
import PcaMath.OtHC
import PcaMath.OtB

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

open Classical in
theorem delta_count (π : Equiv.Perm D) :
    ∀ (A : Adv V D) (kp kh : ℕ), A.Bdd kp kh → ∀ (ctx : Finset ((V × D × D) × D)), Func ctx → ¬ BadH ctx →
    ((Finset.univ.filter (fun R : V × D × D → D =>
        (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet (A.play (oY π R)).1))).card : ℝ) * Fintype.card D
      ≤ fb kh ctx.card * (Fintype.card D : ℝ) ^ (Fintype.card (V × D × D) - ctx.card) := by
  intro A
  induction A with
  | done b =>
    intro kp kh _ ctx hf hnb
    have : (Finset.univ.filter (fun R : V × D × D → D =>
        (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((Adv.done b : Adv V D).play (oY π R)).1))) = ∅ := by
      apply Finset.filter_eq_empty_iff.mpr
      intro R _ ⟨_, hb⟩
      apply hnb
      simpa [Adv.play, hSet] using hb
    rw [this]
    simp only [Finset.card_empty, Nat.cast_zero, zero_mul]
    have := fb_nonneg kh ctx.card
    positivity
  | ask q k ih =>
    intro kp kh hb ctx hf hnb
    cases q with
    | P z =>
      obtain ⟨_, hall⟩ := hb
      have : (Finset.univ.filter (fun R : V × D × D → D =>
          (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((Adv.ask (Qry.P z) k).play (oY π R)).1))) =
          (Finset.univ.filter (fun R : V × D × D → D =>
          (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((k (π z)).play (oY π R)).1))) := by
        apply Finset.filter_congr; intro R _
        simp [Adv.play, oY, hSet_cons_P]
      rw [this]
      exact ih (π z) (kp - 1) kh (hall (π z)) ctx hf hnb
    | Pi w =>
      obtain ⟨_, hall⟩ := hb
      have : (Finset.univ.filter (fun R : V × D × D → D =>
          (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((Adv.ask (Qry.Pi w) k).play (oY π R)).1))) =
          (Finset.univ.filter (fun R : V × D × D → D =>
          (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((k (π.symm w)).play (oY π R)).1))) := by
        apply Finset.filter_congr; intro R _
        simp [Adv.play, oY, hSet_cons_Pi]
      rw [this]
      exact ih (π.symm w) (kp - 1) kh (hall (π.symm w)) ctx hf hnb
    | H v x t =>
      obtain ⟨hpos, hall⟩ := hb
      set N : ℕ := Fintype.card D with hN
      set M : ℕ := Fintype.card (V × D × D) with hM
      by_cases hin : ∃ o, ((v, x, t), o) ∈ ctx
      · obtain ⟨o, ho⟩ := hin
        have : (Finset.univ.filter (fun R : V × D × D → D =>
            (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((Adv.ask (Qry.H v x t) k).play (oY π R)).1))) =
            (Finset.univ.filter (fun R : V × D × D → D =>
            (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((k o).play (oY π R)).1))) := by
          apply Finset.filter_congr; intro R _
          constructor
          · rintro ⟨hc, hbad⟩
            have hR : R (v, x, t) = o := hc _ ho
            refine ⟨hc, ?_⟩
            simp only [Adv.play, oY, hSet_cons_H, hR] at hbad
            rwa [Finset.union_insert, Finset.insert_eq_of_mem (Finset.mem_union_left _ ho)] at hbad
          · rintro ⟨hc, hbad⟩
            have hR : R (v, x, t) = o := hc _ ho
            refine ⟨hc, ?_⟩
            simp only [Adv.play, oY, hSet_cons_H, hR]
            rwa [Finset.union_insert, Finset.insert_eq_of_mem (Finset.mem_union_left _ ho)]
        rw [this]
        refine le_trans (ih o kp (kh - 1) (hall o) ctx hf hnb) ?_
        have h1 := fb_mono (r := kh - 1) (r' := kh) ctx.card (Nat.sub_le _ _)
        have h2 : (0:ℝ) ≤ (N:ℝ) ^ (M - ctx.card) := by positivity
        exact mul_le_mul_of_nonneg_right h1 h2
      · push_neg at hin
        set s := ctx.card with hs
        have hlt : s < M := Func_card_lt hf (v, x, t) hin
        have hexp : M - s = (M - (s + 1)) + 1 := by omega
        let bad : D → Prop := fun o => o = 0 ∨ ∃ h' ∈ ctx, h'.1.1 = v ∧ h'.1.2.1 = x ∧ h'.2 = o
        classical
        have hbadcard : (Finset.univ.filter bad).card ≤ s + 1 := by
          have hsub : Finset.univ.filter bad ⊆
              insert 0 ((ctx.filter (fun h' => h'.1.1 = v ∧ h'.1.2.1 = x)).image (fun h' => h'.2)) := by
            intro o ho
            simp only [Finset.mem_filter, Finset.mem_univ, true_and, bad] at ho
            simp only [Finset.mem_insert, Finset.mem_image, Finset.mem_filter]
            rcases ho with h0 | ⟨h', hh', h1, h2, h3⟩
            · exact Or.inl h0
            · exact Or.inr ⟨h', ⟨hh', h1, h2⟩, h3⟩
          refine le_trans (Finset.card_le_card hsub) ?_
          refine le_trans (Finset.card_insert_le _ _) ?_
          have := Finset.card_image_le (s := ctx.filter (fun h' => h'.1.1 = v ∧ h'.1.2.1 = x)) (f := fun h' => h'.2)
          have h2 := Finset.card_filter_le ctx (fun h' => h'.1.1 = v ∧ h'.1.2.1 = x)
          omega
        -- the per-value counts
        let Fo : D → ℕ := fun o => (Finset.univ.filter (fun R : V × D × D → D =>
            (∀ h ∈ insert ((v, x, t), o) ctx, R h.1 = h.2) ∧
            BadH (insert ((v, x, t), o) ctx ∪ hSet ((k o).play (oY π R)).1))).card
        have hsplit : (Finset.univ.filter (fun R : V × D × D → D =>
            (∀ h ∈ ctx, R h.1 = h.2) ∧ BadH (ctx ∪ hSet ((Adv.ask (Qry.H v x t) k).play (oY π R)).1))).card
            = ∑ o : D, Fo o := by
          rw [Finset.card_eq_sum_card_fiberwise (f := fun R : V × D × D → D => R (v, x, t)) (t := Finset.univ)
            (fun _ _ => Finset.mem_univ _)]
          apply Finset.sum_congr rfl; intro o _
          congr 1
          ext R
          simp only [Finset.mem_filter, Finset.mem_univ, true_and]
          constructor
          · rintro ⟨⟨hc, hbad⟩, hR⟩
            refine ⟨?_, ?_⟩
            · intro h hh
              rcases Finset.mem_insert.mp hh with rfl | hh
              · exact hR
              · exact hc h hh
            · simp only [Adv.play, oY, hSet_cons_H, hR] at hbad
              rwa [Finset.union_insert, ← Finset.insert_union] at hbad
          · rintro ⟨hc, hbad⟩
            have hR : R (v, x, t) = o := hc _ (Finset.mem_insert_self _ _)
            refine ⟨⟨fun h hh => hc h (Finset.mem_insert_of_mem hh), ?_⟩, hR⟩
            simp only [Adv.play, oY, hSet_cons_H, hR]
            rwa [Finset.union_insert, ← Finset.insert_union]
        have hf' : ∀ o, Func (insert (((v, x, t), o) : (V × D × D) × D) ctx) := fun o => Func_insert hf _ o hin
        have hcard' : ∀ o, (insert (((v, x, t), o) : (V × D × D) × D) ctx).card = s + 1 := fun o =>
          Finset.card_insert_of_notMem (hin o)
        have hnb' : ∀ o, ¬ bad o → ¬ BadH (insert (((v, x, t), o) : (V × D × D) × D) ctx) := by
          intro o hnbo hbo
          exact hnbo ((BadH_insert_iff hf hnb (v, x, t) hin o).mp hbo)
        have hbad' : ∀ o, bad o → BadH (insert (((v, x, t), o) : (V × D × D) × D) ctx) := by
          intro o hbo
          exact (BadH_insert_iff hf hnb (v, x, t) hin o).mpr hbo
        set a : ℝ := (N : ℝ) ^ (M - s) with ha
        set b : ℝ := fb (kh - 1) (s + 1) * (N : ℝ) ^ (M - (s + 1)) with hb'
        have hFo : ∀ o, (Fo o : ℝ) * N ≤ (if bad o then a else 0) + b := by
          intro o
          by_cases hbo : bad o
          · have hle : Fo o ≤ N ^ (M - (s + 1)) := by
              have := OtHC.card_fun_extend (insert (((v, x, t), o) : (V × D × D) × D) ctx) (hf' o)
              rw [hcard' o] at this
              rw [← this]
              apply Finset.card_le_card
              intro R hR
              simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hR ⊢
              exact hR.1
            have h1 : (Fo o : ℝ) * N ≤ (N : ℝ) ^ (M - (s + 1)) * N := by
              apply mul_le_mul_of_nonneg_right _ (by positivity)
              exact_mod_cast hle
            have h2 : (N : ℝ) ^ (M - (s + 1)) * N = a := by
              rw [ha, hexp, pow_succ]
            have h3 : 0 ≤ b := by
              rw [hb']; have := fb_nonneg (kh - 1) (s + 1); positivity
            rw [if_pos hbo]; linarith
          · have := ih o kp (kh - 1) (hall o) _ (hf' o) (hnb' o hbo)
            rw [hcard' o] at this
            rw [if_neg hbo]
            simpa [hb', Fo] using this
        have hsum : ((∑ o : D, Fo o : ℕ) : ℝ) * N ≤ ((s + 1 : ℕ) : ℝ) * a + N * b := by
          push_cast
          rw [Finset.sum_mul]
          calc ∑ o : D, (Fo o : ℝ) * N ≤ ∑ o : D, ((if bad o then a else 0) + b) :=
                Finset.sum_le_sum (fun o _ => hFo o)
            _ = (Finset.univ.filter bad).card * a + N * b := by
                rw [Finset.sum_add_distrib, Finset.sum_const, Finset.card_univ]
                have e : ∑ o : D, (if bad o then a else 0) = ((Finset.univ.filter bad).card : ℝ) * a := by
                  rw [Finset.sum_ite, Finset.sum_const_zero, add_zero, Finset.sum_const, nsmul_eq_mul]
                rw [e]; simp; left; rfl
            _ ≤ ((s : ℝ) + 1) * a + N * b := by
                have : ((Finset.univ.filter bad).card : ℝ) ≤ (s : ℝ) + 1 := by exact_mod_cast hbadcard
                have ha0 : 0 ≤ a := by positivity
                nlinarith
        rw [hsplit]
        have hkh : kh = (kh - 1) + 1 := by omega
        calc ((∑ o : D, Fo o : ℕ) : ℝ) * N ≤ ((s + 1 : ℕ) : ℝ) * a + N * b := hsum
          _ = fb kh s * (N : ℝ) ^ (M - s) := by
            have e1 : (N : ℝ) * b = fb (kh - 1) (s + 1) * a := by
              rw [hb', ha, hexp, pow_succ]; ring
            rw [e1]
            conv_rhs => rw [hkh, fb_succ]
            push_cast; ring

end PcaMath.OtDefs
