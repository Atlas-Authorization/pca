/-!
# Conformal risk control, finite-sample core (goal-to-decision spec F5)

Setting. Goals `0 .. n` (`n` calibration goals and one held-out goal, `n+1` in all) share a loss `L i ℓ ∈ {0,1}`
(1 = a widening event: the auto-accepted policy permits a probe the principal rejects) and a threshold index `ℓ`
(larger = more conservative) with `L i` nonincreasing in `ℓ`. The rule picks a threshold whose corrected empirical
risk is at most `α = a / b`:  `(Σ_{i≠j} L i ℓ + B) · b ≤ a · (n+1)` with `B = 1`, where `j` is the held-out goal.

`crc_finite` is the exchangeability step in its exact finite form: conditioning on the unordered sample, the held-out
index is uniform on `0..n`. For every choice `lhat j` computed from the other `n` goals and satisfying the corrected
condition, the held-out loss summed over the uniform held-out index satisfies `(Σ_j L j (lhat j)) · b ≤ a · (n+1)`, i.e.
the expected held-out loss is at most `α`. Taking expectation over an exchangeable draw of the `n+1` goals is the same
permutation-invariance argument as `PcaIntent.Stats.split_conformal`; the hypotheses (exchangeability, label quality,
probe coverage) are empirical and are stated in every published report. Plain Lean core only (no Mathlib): sums are the
structural recursion `S`.

* `S_split`, `corr_imp_full`: the corrected condition for held-out `j` implies the full-sample condition.
* `crc_finite`: the guarantee, for any threshold at least the least conservative feasible one.
* `corr_mono`: feasibility is monotone in the threshold, so a more conservative choice (for example one that also
  requires a Clopper-Pearson gate) keeps the guarantee.
* `corr_top`: the most conservative threshold (loss 0: escalate everything) is feasible iff `b ≤ a (n+1)`.
-/
namespace PcaIntent.Crc

/-- `S f n = f 0 + … + f (n-1)`. -/
def S (f : Nat → Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => S f n + f n

theorem S_mono (f g : Nat → Nat) : ∀ n, (∀ i, i < n → f i ≤ g i) → S f n ≤ S g n
  | 0, _ => Nat.le_refl 0
  | n + 1, h => by
      have ih := S_mono f g n (fun i hi => h i (Nat.lt_succ_of_lt hi))
      have hn := h n (Nat.lt_succ_self n)
      show S f n + f n ≤ S g n + g n
      omega

theorem term_le_S (f : Nat → Nat) : ∀ n j, j < n → f j ≤ S f n
  | 0, j, h => absurd h (Nat.not_lt_zero j)
  | n + 1, j, h => by
      show f j ≤ S f n + f n
      rcases Nat.lt_succ_iff_lt_or_eq.mp h with h' | h'
      · have := term_le_S f n j h'; omega
      · subst h'; omega

/-- `f` with the held-out goal `j` zeroed out: the loss over the other goals only. -/
def excl (f : Nat → Nat) (j : Nat) : Nat → Nat := fun i => if i = j then 0 else f i

theorem S_split (f : Nat → Nat) (j : Nat) : ∀ n, j < n → S f n = S (excl f j) n + f j
  | 0, h => absurd h (Nat.not_lt_zero j)
  | n + 1, h => by
      show S f n + f n = S (excl f j) n + excl f j n + f j
      rcases Nat.lt_succ_iff_lt_or_eq.mp h with h' | h'
      · have ih := S_split f j n h'
        have hne : n ≠ j := Nat.ne_of_gt h'
        have e : excl f j n = f n := by simp [excl, hne]
        omega
      · have hn : n = j := h'.symm
        have e : excl f j n = 0 := by simp [excl, hn]
        have hz : ∀ m, m ≤ n → S f m = S (excl f j) m := by
          intro m; induction m with
          | zero => intro _; rfl
          | succ m ih =>
              intro hm
              have hne : m ≠ j := fun hmj => by omega
              have e2 : excl f j m = f m := by simp [excl, hne]
              show S f m + f m = S (excl f j) m + excl f j m
              rw [ih (Nat.le_of_succ_le hm), e2]
        have h4 := hz n (Nat.le_refl n)
        rw [← hn] at *
        omega

/-- Corrected condition for held-out goal `j`: loss over the other `n` goals, plus `B = 1`. -/
def Corr (L : Nat → Nat → Nat) (n a b j ℓ : Nat) : Prop :=
  (S (excl (fun i => L i ℓ) j) (n + 1) + 1) * b ≤ a * (n + 1)

/-- Full-sample condition on all `n+1` goals. -/
def Full (L : Nat → Nat → Nat) (n a b ℓ : Nat) : Prop :=
  S (fun i => L i ℓ) (n + 1) * b ≤ a * (n + 1)

theorem corr_imp_full (L : Nat → Nat → Nat) (hB : ∀ i ℓ, L i ℓ ≤ 1) (n a b j ℓ : Nat) (hj : j < n + 1)
    (h : Corr L n a b j ℓ) : Full L n a b ℓ := by
  unfold Corr at h
  unfold Full
  have h1 := S_split (fun i => L i ℓ) j (n + 1) hj
  have h2 := hB j ℓ
  have h3 : S (fun i => L i ℓ) (n + 1) ≤ S (excl (fun i => L i ℓ) j) (n + 1) + 1 := by
    omega
  exact Nat.le_trans (Nat.mul_le_mul_right b h3) h

theorem crc_finite (L : Nat → Nat → Nat) (hB : ∀ i ℓ, L i ℓ ≤ 1)
    (hmono : ∀ i ℓ₁ ℓ₂, ℓ₁ ≤ ℓ₂ → L i ℓ₂ ≤ L i ℓ₁)
    (n a b : Nat) (lhat : Nat → Nat)
    (hfeas : ∀ j, j < n + 1 → Corr L n a b j (lhat j))
    (ℓs : Nat) (hs : Full L n a b ℓs) (hmin : ∀ ℓ, Full L n a b ℓ → ℓs ≤ ℓ) :
    S (fun j => L j (lhat j)) (n + 1) * b ≤ a * (n + 1) := by
  have hle : S (fun j => L j (lhat j)) (n + 1) ≤ S (fun j => L j ℓs) (n + 1) :=
    S_mono _ _ (n + 1) fun j hj =>
      hmono j ℓs (lhat j) (hmin _ (corr_imp_full L hB n a b j _ hj (hfeas j hj)))
  unfold Full at hs
  exact Nat.le_trans (Nat.mul_le_mul_right b hle) hs

theorem corr_mono (L : Nat → Nat → Nat) (hmono : ∀ i ℓ₁ ℓ₂, ℓ₁ ≤ ℓ₂ → L i ℓ₂ ≤ L i ℓ₁) (n a b j : Nat)
    {ℓ₁ ℓ₂ : Nat} (hl : ℓ₁ ≤ ℓ₂) (h : Corr L n a b j ℓ₁) : Corr L n a b j ℓ₂ := by
  unfold Corr at h ⊢
  have hs : S (excl (fun i => L i ℓ₂) j) (n + 1) ≤ S (excl (fun i => L i ℓ₁) j) (n + 1) :=
    S_mono _ _ (n + 1) fun i _ => by
      show (if i = j then 0 else L i ℓ₂) ≤ (if i = j then 0 else L i ℓ₁)
      split
      · exact Nat.le_refl 0
      · exact hmono i ℓ₁ ℓ₂ hl
  exact Nat.le_trans (Nat.mul_le_mul_right b (Nat.add_le_add_right hs 1)) h

theorem corr_top (L : Nat → Nat → Nat) (n a b j ℓt : Nat) (hz : ∀ i, L i ℓt = 0) (hb : b ≤ a * (n + 1)) :
    Corr L n a b j ℓt := by
  unfold Corr
  have h0 : S (excl (fun i => L i ℓt) j) (n + 1) = 0 := by
    have : ∀ m, S (excl (fun i => L i ℓt) j) m = 0 := by
      intro m; induction m with
      | zero => rfl
      | succ m ih =>
          show S (excl (fun i => L i ℓt) j) m + excl (fun i => L i ℓt) j m = 0
          have : excl (fun i => L i ℓt) j m = 0 := by simp [excl, hz m]
          omega
    exact this (n + 1)
  rw [h0]
  simpa using hb

end PcaIntent.Crc
