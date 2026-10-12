import Mathlib
import PcaMath.OtDefs
import PcaMath.OtF
import PcaMath.OtI
import PcaMath.OtRows
import PcaMath.OtCounter

open Finset

namespace PcaMath.OtDefs

variable {V D : Type} [Fintype V] [DecidableEq V] [AddCommGroup D] [Fintype D] [DecidableEq D]

/-- post-process the answers of hash queries by `f` (e.g. keep the low 64 bits) -/
def Adv.mapH (f : D → D) : Adv V D → Adv V D
  | .done b => .done b
  | .ask q k => .ask q (fun d => (k (match q with | .H _ _ _ => f d | _ => d)).mapH f)

def hmap (f : D → D) (O : Qry V D → D) : Qry V D → D := fun q =>
  match q with | .H v x t => f (O (.H v x t)) | q => O q

theorem mapH_play (f : D → D) (A : Adv V D) (O : Qry V D → D) :
    ((A.mapH f).play O).2 = (A.play (hmap f O)).2 := by
  induction A with
  | done b => rfl
  | ask q k ih =>
    cases q <;> simp_all [Adv.mapH, Adv.play, hmap]

theorem mapH_Bdd (f : D → D) : ∀ (A : Adv V D) (kp kh : ℕ), A.Bdd kp kh → (A.mapH f).Bdd kp kh := by
  intro A
  induction A with
  | done b => intro _ _ _; simp [Adv.mapH, Adv.Bdd]
  | ask q k ih =>
    intro kp kh h
    cases q with
    | P z => exact ⟨h.1, fun d => ih d _ _ (h.2 d)⟩
    | Pi w => exact ⟨h.1, fun d => ih d _ _ (h.2 d)⟩
    | H v x t => exact ⟨h.1, fun d => ih (f d) _ _ (h.2 (f d))⟩

open Classical in
/-- TRUNCATION: the same bound for the game in which hash answers are post-processed by ANY map `f`
(in particular `low64`): post-processing cannot help, because the post-processing adversary is an
adversary of the full game with the same query counts. -/
theorem tcr_icm_post (h2 : ∀ x : D, x + x = 0) (f : D → D) (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh) :
    |(((Finset.univ.filter (fun ω : Equiv.Perm D × (V → D) =>
          (A.play (hmap f (oX ω.1 ω.2))).2 = true)).card : ℝ) / Fintype.card (Equiv.Perm D × (V → D)))
     - (((Finset.univ.filter (fun ω : Equiv.Perm D × (V × D × D → D) =>
          (A.play (hmap f (oY ω.1 ω.2))).2 = true)).card : ℝ) / Fintype.card (Equiv.Perm D × (V × D × D → D)))|
    ≤ ((((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) + (kh : ℝ) * (kh + 1) / 2) / Fintype.card D := by
  have := tcr_icm h2 (A.mapH f) kp kh (mapH_Bdd f A kp kh hA)
  unfold prX prY at this
  simpa [mapH_play] using this

/-- cleaner constant: with `L = kp + 2 kh` and `N = |D|`, the advantage is at most `2 L^2 / N`. -/
theorem tcr_icm_simple (h2 : ∀ x : D, x + x = 0) (A : Adv V D) (kp kh : ℕ) (hA : A.Bdd kp kh) :
    |prX A - prY A| ≤ 2 * ((kp + 2 * kh : ℕ) : ℝ) ^ 2 / Fintype.card D := by
  refine le_trans (tcr_icm h2 A kp kh hA) ?_
  have hN : (0 : ℝ) < Fintype.card D := by exact_mod_cast Fintype.card_pos
  apply div_le_div_of_nonneg_right _ hN.le
  have h1 : (((kp + 2 * kh) * (kp + 2 * kh - 1) : ℕ) : ℝ) ≤ ((kp + 2 * kh : ℕ) : ℝ) ^ 2 := by
    have : (kp + 2 * kh) * (kp + 2 * kh - 1) ≤ (kp + 2 * kh) ^ 2 := by
      rw [sq]; exact Nat.mul_le_mul_left _ (Nat.sub_le _ _)
    exact_mod_cast this
  have h2' : (kh : ℝ) * (kh + 1) / 2 ≤ ((kp + 2 * kh : ℕ) : ℝ) ^ 2 := by
    push_cast
    have : (0:ℝ) ≤ kp := by positivity
    have : (0:ℝ) ≤ kh := by positivity
    have hk : (kh : ℝ) ≤ (kh : ℝ) ^ 2 := by exact_mod_cast Nat.le_self_pow (by norm_num) kh
    nlinarith
  linarith

end PcaMath.OtDefs
