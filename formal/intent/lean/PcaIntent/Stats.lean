import PcaIntent.V2Misc

/-!
# The statistical parts, mechanised: Clopper–Pearson, split-conformal, union bound

Previously "cited, not proved" (spec v1 L3, v2 T17 and T20). Here they are theorems whose only hypotheses are
the sampling assumptions, stated explicitly.

**Finite probability spaces** (`FinProb`): non-negative weights summing to one on a `Fintype`.

* `cdf_stat_le` (the core of every exact test): for any `ℕ`-valued statistic `X` with CDF `F(k) = P(X ≤ k)`,
  `P(F(X) ≤ α) ≤ α`.
* **Clopper–Pearson (one-sided upper bound).** `bern n q` is the law of `n` i.i.d. Bernoulli(`q`) trials on
  `Fin n → Bool`. For an observed count `k`, `cpUpper n α k = sup {q ∈ [0,1] : α < P_q(count ≤ k)}` is the exact
  (Clopper–Pearson) upper confidence bound. `CP_coverage`: `P_p(p ≤ cpUpper(count)) ≥ 1 − α` for every
  `p ∈ [0,1]`. No normal approximation, no continuity assumption.
* `T17_canary_bound`: the canary false-yes estimate (v2 T17): `k` canaries answered i.i.d. with false-yes rate
  `η⁺` give `P(η⁺ ≤ η̄⁺) ≥ 1 − δ_c`.
* `prob_union_le`: the finite union bound; `T20_stat`: if each confusion entry has an upper bound valid with
  probability `≥ 1 − δ_Γ/|L|²` (CP per entry), the classifier risk bound of T20 holds with the estimated
  `Γ̄` with probability `≥ 1 − δ_Γ`.

**Split-conformal coverage** (`split_conformal`, measure-theoretic, any score distribution, ties allowed):
for exchangeable scores `Z_1, …, Z_{n+1}` (the joint law is invariant under every permutation), with
`m ≥ (n+1)(1−α)`, `m ≤ n+1`, the event "fewer than `m` calibration scores are below the test score" has
probability `≥ 1 − α`; by `orderStat_iff` that event is "test score `≤ q̂`" for `q̂` the `m`-th smallest
calibration score (`split_conformal_qhat`). This is the judge panel's guarantee (v1 L3, M5): the false-allow
rate is at most `α` (`conformal_false_allow`).
-/

namespace PcaIntent.Stats

open Finset

/-! ## Finite probability spaces -/

/-- A probability distribution on a finite type. -/
structure FinProb (S : Type*) [Fintype S] where
  w : S → ℝ
  nonneg : ∀ s, 0 ≤ w s
  sum_one : ∑ s, w s = 1

variable {S : Type*} [Fintype S]

open Classical in
/-- Probability of an event. -/
noncomputable def FinProb.prob (P : FinProb S) (E : S → Prop) : ℝ := ∑ s ∈ univ.filter E, P.w s

namespace FinProb

variable (P : FinProb S)

lemma prob_nonneg (E : S → Prop) : 0 ≤ P.prob E := by
  classical
  unfold prob; exact Finset.sum_nonneg fun s _ => P.nonneg s

lemma prob_mono {E E' : S → Prop} (h : ∀ s, E s → E' s) : P.prob E ≤ P.prob E' := by
  classical
  unfold prob
  refine Finset.sum_le_sum_of_subset_of_nonneg ?_ fun s _ _ => P.nonneg s
  intro s hs
  rw [Finset.mem_filter] at hs ⊢
  exact ⟨hs.1, h s hs.2⟩

lemma prob_add_compl (E : S → Prop) : P.prob E + P.prob (fun s => ¬ E s) = 1 := by
  classical
  unfold prob
  rw [Finset.sum_filter_add_sum_filter_not, P.sum_one]

lemma prob_le_one (E : S → Prop) : P.prob E ≤ 1 := by
  have := P.prob_add_compl E
  have := P.prob_nonneg (fun s => ¬ E s)
  linarith

open Classical in
lemma prob_eq_sum (E : S → Prop) : P.prob E = ∑ s, if E s then P.w s else 0 := by
  unfold prob; rw [Finset.sum_filter]

lemma prob_or_le (E F : S → Prop) : P.prob (fun s => E s ∨ F s) ≤ P.prob E + P.prob F := by
  classical
  rw [prob_eq_sum, prob_eq_sum, prob_eq_sum, ← Finset.sum_add_distrib]
  refine Finset.sum_le_sum fun s _ => ?_
  have := P.nonneg s
  split_ifs <;> simp_all

/-- The finite union bound. -/
theorem prob_union_le {I : Type*} (T : Finset I) (E : I → S → Prop) :
    P.prob (fun s => ∃ i ∈ T, E i s) ≤ ∑ i ∈ T, P.prob (E i) := by
  classical
  induction T using Finset.induction_on with
  | empty =>
      rw [Finset.sum_empty]
      have h : P.prob (fun s => ∃ i ∈ (∅ : Finset I), E i s) ≤ P.prob (fun _ => False) :=
        P.prob_mono fun s hs => by simp at hs
      have h0 : P.prob (fun _ : S => False) = 0 := by rw [prob_eq_sum]; simp
      linarith
  | insert a T ha ih =>
      rw [Finset.sum_insert ha]
      have h1 : P.prob (fun s => ∃ i ∈ insert a T, E i s) ≤
          P.prob (fun s => E a s ∨ ∃ i ∈ T, E i s) := by
        apply P.prob_mono
        intro s hs
        obtain ⟨i, hi, hE⟩ := hs
        rcases Finset.mem_insert.1 hi with rfl | hT
        · exact Or.inl hE
        · exact Or.inr ⟨i, hT, hE⟩
      have h2 := P.prob_or_le (E a) (fun s => ∃ i ∈ T, E i s)
      linarith

/-- **The core of exact tests.** For a `ℕ`-valued statistic with CDF `F(k) = P(X ≤ k)`, `P(F(X) ≤ α) ≤ α`. -/
theorem cdf_stat_le (X : S → ℕ) {α : ℝ} (hα : 0 ≤ α) :
    P.prob (fun s => P.prob (fun t => X t ≤ X s) ≤ α) ≤ α := by
  classical
  by_cases hex : ∃ s, P.prob (fun t => X t ≤ X s) ≤ α
  · set T := univ.filter (fun s => P.prob (fun t => X t ≤ X s) ≤ α) with hT
    have hne : T.Nonempty := by
      obtain ⟨s, hs⟩ := hex
      exact ⟨s, Finset.mem_filter.2 ⟨Finset.mem_univ s, hs⟩⟩
    obtain ⟨s0, hs0, hmax⟩ := Finset.exists_max_image T X hne
    have hF : P.prob (fun t => X t ≤ X s0) ≤ α := (Finset.mem_filter.1 hs0).2
    refine le_trans (P.prob_mono fun s hs => ?_) hF
    exact hmax s (Finset.mem_filter.2 ⟨Finset.mem_univ s, hs⟩)
  · push_neg at hex
    have h0 : P.prob (fun s => P.prob (fun t => X t ≤ X s) ≤ α) ≤ P.prob (fun _ => False) :=
      P.prob_mono fun s hs => absurd hs (not_le.2 (hex s))
    have h1 : P.prob (fun _ : S => False) = 0 := by rw [prob_eq_sum]; simp
    linarith

end FinProb

/-! ## Clopper–Pearson -/

/-- `n` i.i.d. Bernoulli(`q`) trials. -/
noncomputable def bern (n : ℕ) (q : ℝ) (h0 : 0 ≤ q) (h1 : q ≤ 1) : FinProb (Fin n → Bool) where
  w v := ∏ i, (if v i then q else 1 - q)
  nonneg v := Finset.prod_nonneg fun i _ => by split_ifs <;> linarith
  sum_one := by
    have h := (Fintype.prod_sum (fun (_ : Fin n) (b : Bool) => if b then q else 1 - q)).symm
    rw [h]
    simp

/-- Number of successes. -/
def count {n : ℕ} (v : Fin n → Bool) : ℕ := ∑ i, (if v i = true then 1 else 0)

open Classical in
/-- The binomial CDF `P_q(count ≤ k)`, as a function of `q` (`0` outside `[0,1]`, never used there). -/
noncomputable def binCdf (n : ℕ) (q : ℝ) (k : ℕ) : ℝ :=
  if h : 0 ≤ q ∧ q ≤ 1 then (bern n q h.1 h.2).prob (fun v => count v ≤ k) else 0

/-- The exact one-sided confidence set for the success probability after observing `k` successes. -/
def cpSet (n : ℕ) (α : ℝ) (k : ℕ) : Set ℝ := {q | 0 ≤ q ∧ q ≤ 1 ∧ α < binCdf n q k}

/-- The Clopper–Pearson upper confidence bound. -/
noncomputable def cpUpper (n : ℕ) (α : ℝ) (k : ℕ) : ℝ := sSup (cpSet n α k)

/-- **Clopper–Pearson coverage (confidence-set form).** -/
theorem CP_set_coverage (n : ℕ) {p : ℝ} (h0 : 0 ≤ p) (h1 : p ≤ 1) {α : ℝ} (hα : 0 ≤ α) :
    1 - α ≤ (bern n p h0 h1).prob (fun v => p ∈ cpSet n α (count v)) := by
  set P := bern n p h0 h1
  have hcdf : ∀ k, binCdf n p k = P.prob (fun v => count v ≤ k) := by
    intro k; unfold binCdf; rw [dif_pos ⟨h0, h1⟩]
  have hbad := P.cdf_stat_le count hα
  have hcomp := P.prob_add_compl (fun v => P.prob (fun t => count t ≤ count v) ≤ α)
  have hmono : P.prob (fun v => ¬ P.prob (fun t => count t ≤ count v) ≤ α) ≤
      P.prob (fun v => p ∈ cpSet n α (count v)) := by
    apply P.prob_mono
    intro v hv
    refine ⟨h0, h1, ?_⟩
    rw [hcdf]
    exact lt_of_not_ge hv
  linarith

/-- **Clopper–Pearson coverage.** For every true `p ∈ [0,1]`: `P_p(p ≤ cpUpper(count)) ≥ 1 − α`. -/
theorem CP_coverage (n : ℕ) {p : ℝ} (h0 : 0 ≤ p) (h1 : p ≤ 1) {α : ℝ} (hα : 0 ≤ α) :
    1 - α ≤ (bern n p h0 h1).prob (fun v => p ≤ cpUpper n α (count v)) := by
  refine le_trans (CP_set_coverage n h0 h1 hα) ((bern n p h0 h1).prob_mono fun v hv => ?_)
  have hbdd : BddAbove (cpSet n α (count v)) := ⟨1, fun q hq => hq.2.1⟩
  exact le_csSup hbdd hv

/-- **T17 (canaries).** `k` canaries answered i.i.d. with false-yes rate `η⁺`: with probability `≥ 1 − δ_c`,
`η⁺ ≤ cpUpper k δ_c (number of false yeses)`. -/
theorem T17_canary_bound (k : ℕ) {ηp : ℝ} (h0 : 0 ≤ ηp) (h1 : ηp ≤ 1) {δc : ℝ} (hδ : 0 ≤ δc) :
    1 - δc ≤ (bern k ηp h0 h1).prob (fun v => ηp ≤ cpUpper k δc (count v)) :=
  CP_coverage k h0 h1 hδ

/-! ## Code = definition: the recursion the TypeScript evaluates, antitonicity, certified brackets

`packages/pca-intent/src/clopper.ts` evaluates `cdfRec` exactly (integer arithmetic at dyadic points) and returns
a dyadic `hi` with `cdfRec hi ≤ α` certified, plus a certified `lo` with `α < cdfRec lo`, `hi − lo ≤ 2^−44`. The
lemmas below make that sound: `bern_prob_eq_cdfRec` (the recursion is the binomial CDF of the i.i.d. model),
`cdfRec_antitone`, `cpUpper_le_of_cdf_le`, `le_cpUpper_of_lt_cdf`, and `CP_coverage_of_ge` (any bound at least
`cpUpper` keeps the coverage). No Beta-function identity is needed. -/

/-- The recursion `P_q(count ≤ k)` satisfies; the TypeScript evaluates exactly this. -/
def cdfRec (q : ℝ) : ℕ → ℕ → ℝ
  | 0, _ => 1
  | n + 1, k => q * (if k = 0 then 0 else cdfRec q n (k - 1)) + (1 - q) * cdfRec q n k

lemma sum_cons {n : ℕ} (g : (Fin (n + 1) → Bool) → ℝ) :
    ∑ v, g v = ∑ u : Fin n → Bool, g (Fin.cons true u) + ∑ u : Fin n → Bool, g (Fin.cons false u) := by
  rw [← Fintype.sum_equiv (Fin.consEquiv fun _ => Bool) _ g (fun _ => rfl), Fintype.sum_prod_type,
    Fintype.sum_bool]
  rfl

lemma count_cons_true {n : ℕ} (u : Fin n → Bool) :
    count (Fin.cons true u : Fin (n + 1) → Bool) = count u + 1 := by
  unfold count; rw [Fin.sum_univ_succ]; simp [add_comm]

lemma count_cons_false {n : ℕ} (u : Fin n → Bool) :
    count (Fin.cons false u : Fin (n + 1) → Bool) = count u := by
  unfold count; rw [Fin.sum_univ_succ]; simp

lemma bern_w_true {n : ℕ} {q : ℝ} (h0 : 0 ≤ q) (h1 : q ≤ 1) (u : Fin n → Bool) :
    (bern (n + 1) q h0 h1).w (Fin.cons true u) = q * (bern n q h0 h1).w u := by
  simp only [bern]; rw [Fin.prod_univ_succ]; simp

lemma bern_w_false {n : ℕ} {q : ℝ} (h0 : 0 ≤ q) (h1 : q ≤ 1) (u : Fin n → Bool) :
    (bern (n + 1) q h0 h1).w (Fin.cons false u) = (1 - q) * (bern n q h0 h1).w u := by
  simp only [bern]; rw [Fin.prod_univ_succ]; simp

/-- First-trial decomposition of the i.i.d. Bernoulli law. -/
theorem bern_prob_succ {n : ℕ} {q : ℝ} (h0 : 0 ≤ q) (h1 : q ≤ 1) (P : ℕ → Prop) :
    (bern (n + 1) q h0 h1).prob (fun v => P (count v)) =
      q * (bern n q h0 h1).prob (fun u => P (count u + 1)) +
        (1 - q) * (bern n q h0 h1).prob (fun u => P (count u)) := by
  rw [FinProb.prob_eq_sum, FinProb.prob_eq_sum, FinProb.prob_eq_sum, sum_cons, Finset.mul_sum,
    Finset.mul_sum]
  congr 1
  · refine Finset.sum_congr rfl fun u _ => ?_
    rw [count_cons_true]
    by_cases h : P (count u + 1)
    · rw [if_pos h, if_pos h, bern_w_true]
    · rw [if_neg h, if_neg h, mul_zero]
  · refine Finset.sum_congr rfl fun u _ => ?_
    rw [count_cons_false]
    by_cases h : P (count u)
    · rw [if_pos h, if_pos h, bern_w_false]
    · rw [if_neg h, if_neg h, mul_zero]

lemma FinProb.prob_false (P : FinProb S) : P.prob (fun _ => False) = 0 := by
  rw [FinProb.prob_eq_sum]; simp

/-- **The recursion is the binomial CDF of the i.i.d. model.** -/
theorem bern_prob_eq_cdfRec {q : ℝ} (h0 : 0 ≤ q) (h1 : q ≤ 1) :
    ∀ n k, (bern n q h0 h1).prob (fun v => count v ≤ k) = cdfRec q n k
  | 0, k => by
      rw [FinProb.prob_eq_sum, Fintype.sum_unique]
      simp [bern, count, cdfRec]
  | n + 1, k => by
      have hs := bern_prob_succ h0 h1 (n := n) (fun c => c ≤ k)
      beta_reduce at hs
      rw [hs, bern_prob_eq_cdfRec h0 h1 n k]
      simp only [cdfRec]
      congr 1
      by_cases hk : k = 0
      · subst hk
        rw [if_pos rfl]
        have : (fun u : Fin n → Bool => count u + 1 ≤ 0) = fun _ => False :=
          funext fun u => propext (by simp)
        rw [this, FinProb.prob_false]
      · rw [if_neg hk]
        have : (fun u : Fin n → Bool => count u + 1 ≤ k) = fun u => count u ≤ k - 1 :=
          funext fun u => propext ⟨fun h => by omega, fun h => by omega⟩
        rw [this, bern_prob_eq_cdfRec h0 h1 n (k - 1)]

section Rec

variable {q : ℝ}

lemma cdfRec_bounds (h0 : 0 ≤ q) (h1 : q ≤ 1) : ∀ n k, 0 ≤ cdfRec q n k ∧ cdfRec q n k ≤ 1
  | 0, k => by simp [cdfRec]
  | n + 1, k => by
      obtain ⟨b0, b1⟩ := cdfRec_bounds h0 h1 n k
      have hc : 0 ≤ (if k = 0 then 0 else cdfRec q n (k - 1)) ∧ (if k = 0 then 0 else cdfRec q n (k - 1)) ≤ 1 := by
        split_ifs
        · exact ⟨le_rfl, zero_le_one⟩
        · exact cdfRec_bounds h0 h1 n (k - 1)
      simp only [cdfRec]
      constructor <;> nlinarith [hc.1, hc.2]

lemma cdfRec_mono_k (h0 : 0 ≤ q) (h1 : q ≤ 1) : ∀ n k, cdfRec q n k ≤ cdfRec q n (k + 1)
  | 0, k => by simp [cdfRec]
  | n + 1, k => by
      simp only [cdfRec]
      have hB := cdfRec_mono_k h0 h1 n k
      have hC : (if k = 0 then 0 else cdfRec q n (k - 1)) ≤ (if k + 1 = 0 then 0 else cdfRec q n (k + 1 - 1)) := by
        rw [if_neg (Nat.succ_ne_zero k), Nat.add_sub_cancel]
        split_ifs with hk
        · exact (cdfRec_bounds h0 h1 n k).1
        · have := cdfRec_mono_k h0 h1 n (k - 1)
          rwa [Nat.sub_add_cancel (Nat.pos_of_ne_zero hk)] at this
      have h1q : 0 ≤ 1 - q := by linarith
      nlinarith [mul_le_mul_of_nonneg_left hC h0, mul_le_mul_of_nonneg_left hB h1q]

lemma cdfRec_prev_le (h0 : 0 ≤ q) (h1 : q ≤ 1) (n k : ℕ) :
    (if k = 0 then 0 else cdfRec q n (k - 1)) ≤ cdfRec q n k := by
  split_ifs with hk
  · exact (cdfRec_bounds h0 h1 n k).1
  · have := cdfRec_mono_k h0 h1 n (k - 1)
    rwa [Nat.sub_add_cancel (Nat.pos_of_ne_zero hk)] at this

end Rec

/-- **The binomial CDF is antitone in the success probability.** -/
theorem cdfRec_antitone {q q' : ℝ} (h0 : 0 ≤ q) (hqq : q ≤ q') (h1 : q' ≤ 1) :
    ∀ n k, cdfRec q' n k ≤ cdfRec q n k
  | 0, k => le_rfl
  | n + 1, k => by
      have hq1 : q ≤ 1 := le_trans hqq h1
      have hq'0 : 0 ≤ q' := le_trans h0 hqq
      have hB := cdfRec_antitone h0 hqq h1 n k
      have hC : (if k = 0 then 0 else cdfRec q' n (k - 1)) ≤ (if k = 0 then 0 else cdfRec q n (k - 1)) := by
        split_ifs
        · exact le_rfl
        · exact cdfRec_antitone h0 hqq h1 n (k - 1)
      have hCB := cdfRec_prev_le h0 hq1 n k
      simp only [cdfRec]
      have h1q' : 0 ≤ 1 - q' := by linarith
      nlinarith [mul_le_mul_of_nonneg_left hC hq'0, mul_le_mul_of_nonneg_left hB h1q',
        mul_nonneg (sub_nonneg.2 hqq) (sub_nonneg.2 hCB)]

theorem binCdf_eq_cdfRec (n : ℕ) {q : ℝ} (h0 : 0 ≤ q) (h1 : q ≤ 1) (k : ℕ) :
    binCdf n q k = cdfRec q n k := by
  unfold binCdf; rw [dif_pos ⟨h0, h1⟩]; exact bern_prob_eq_cdfRec h0 h1 n k

/-- A certified upper end: `cdfRec b ≤ α` ⇒ `cpUpper ≤ b`. -/
theorem cpUpper_le_of_cdf_le {n k : ℕ} {α b : ℝ} (hb0 : 0 ≤ b) (hb1 : b ≤ 1) (hF : cdfRec b n k ≤ α) :
    cpUpper n α k ≤ b := by
  unfold cpUpper
  by_cases hne : (cpSet n α k).Nonempty
  · apply csSup_le hne
    intro q hq
    by_contra hlt
    push_neg at hlt
    obtain ⟨hq0, hq1, hqα⟩ := hq
    rw [binCdf_eq_cdfRec n hq0 hq1] at hqα
    have := cdfRec_antitone hb0 hlt.le hq1 n k
    linarith
  · rw [Set.not_nonempty_iff_eq_empty.1 hne, Real.sSup_empty]
    exact hb0

/-- A certified lower end: `α < cdfRec a` ⇒ `a ≤ cpUpper`. -/
theorem le_cpUpper_of_lt_cdf {n k : ℕ} {α a : ℝ} (ha0 : 0 ≤ a) (ha1 : a ≤ 1) (hF : α < cdfRec a n k) :
    a ≤ cpUpper n α k :=
  le_csSup ⟨1, fun q hq => hq.2.1⟩ ⟨ha0, ha1, by rw [binCdf_eq_cdfRec n ha0 ha1]; exact hF⟩

theorem cpUpper_le_one (n : ℕ) (α : ℝ) (k : ℕ) : cpUpper n α k ≤ 1 := by
  unfold cpUpper
  by_cases hne : (cpSet n α k).Nonempty
  · exact csSup_le hne fun q hq => hq.2.1
  · rw [Set.not_nonempty_iff_eq_empty.1 hne, Real.sSup_empty]; exact zero_le_one

/-- **Coverage of the implemented bound.** Any bound `U ≥ cpUpper` (the TypeScript returns a certified `hi` with
`cdfRec hi ≤ α`, or `1`) keeps `P_p(p ≤ U(count)) ≥ 1 − α`. -/
theorem CP_coverage_of_ge (n : ℕ) {p : ℝ} (h0 : 0 ≤ p) (h1 : p ≤ 1) {α : ℝ} (hα : 0 ≤ α) (U : ℕ → ℝ)
    (hU : ∀ k, cpUpper n α k ≤ U k) :
    1 - α ≤ (bern n p h0 h1).prob (fun v => p ≤ U (count v)) :=
  le_trans (CP_coverage n h0 h1 hα) ((bern n p h0 h1).prob_mono fun v hv => le_trans hv (hU _))

/-- The implemented bound's two cases discharge `hU`: a certified `hi ∈ [0,1]` with `cdfRec hi ≤ α`, or `1`. -/
theorem implemented_bound_ok {n : ℕ} {α : ℝ} (U : ℕ → ℝ)
    (hU : ∀ k, U k = 1 ∨ (0 ≤ U k ∧ U k ≤ 1 ∧ cdfRec (U k) n k ≤ α)) (k : ℕ) : cpUpper n α k ≤ U k := by
  rcases hU k with h | ⟨h0, h1, hF⟩
  · rw [h]; exact cpUpper_le_one n α k
  · exact cpUpper_le_of_cdf_le h0 h1 hF

/-! ## T20 with estimated confusion bounds -/

section Classifier

variable {Xc L : Type*} [Fintype Xc] [Fintype L]

/-- `R_κ` is monotone in the confusion matrix (for non-negative weights). -/
lemma GammaSet_mono [DecidableEq Xc] [DecidableEq L] {Γ Γ' : L → L → ℝ} (h : ∀ ℓh ℓ, Γ ℓh ℓ ≤ Γ' ℓh ℓ)
    (G : Finset (Xc × L)) (x : Xc) (ℓ : L) : GammaSet Γ G x ℓ ≤ GammaSet Γ' G x ℓ :=
  Finset.sum_le_sum fun ℓh _ => h ℓh ℓ

/-- **T20 (statistical part).** Calibration data drawn from any finite probability space `P`; every entry's
estimated upper bound `Γ̄ s ℓh ℓ` fails to cover the true `Γ ℓh ℓ` with probability at most `ε` (`CP_coverage`
gives this with `ε = δ_Γ/|L|²` when the entry's count is binomial). Then, with probability `≥ 1 − |L|² ε`, the
T20 risk bound holds with `Γ̄` in place of `Γ`. -/
theorem T20_stat [DecidableEq Xc] [DecidableEq L] (P : FinProb S) (μ a h : Xc → L → ℝ) (Γ : L → L → ℝ)
    (Γbar : S → L → L → ℝ) (G : Finset (Xc × L)) (Hmax ε : ℝ) (hμ : ∀ x ℓ, 0 ≤ μ x ℓ)
    (ha : ∀ x ℓ, a x ℓ ≤ 1) (hh : ∀ x ℓ, h x ℓ ≤ Hmax) (hΓ : ∀ ℓh ℓ, 0 ≤ Γ ℓh ℓ) (hH : 0 ≤ Hmax)
    (hcov : ∀ ℓh ℓ, P.prob (fun s => ¬ Γ ℓh ℓ ≤ Γbar s ℓh ℓ) ≤ ε) :
    1 - (Fintype.card L : ℝ) ^ 2 * ε ≤ P.prob (fun s =>
      Rkappa μ a h Γ G ≤ Hmax * ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * GammaSet (Γbar s) G x ℓ) := by
  classical
  have hunion := P.prob_union_le (univ : Finset (L × L)) (fun e s => ¬ Γ e.1 e.2 ≤ Γbar s e.1 e.2)
  have hsum : ∑ e ∈ (univ : Finset (L × L)), P.prob (fun s => ¬ Γ e.1 e.2 ≤ Γbar s e.1 e.2) ≤
      (Fintype.card L : ℝ) ^ 2 * ε := by
    calc ∑ e ∈ (univ : Finset (L × L)), P.prob (fun s => ¬ Γ e.1 e.2 ≤ Γbar s e.1 e.2)
        ≤ ∑ _e ∈ (univ : Finset (L × L)), ε := Finset.sum_le_sum fun e _ => hcov e.1 e.2
      _ = (Fintype.card L : ℝ) ^ 2 * ε := by
          rw [Finset.sum_const, Finset.card_univ, Fintype.card_prod, nsmul_eq_mul]
          push_cast
          ring
  have hgood : ∀ s, (∀ ℓh ℓ, Γ ℓh ℓ ≤ Γbar s ℓh ℓ) →
      Rkappa μ a h Γ G ≤ Hmax * ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * GammaSet (Γbar s) G x ℓ := by
    intro s hs
    refine le_trans (T20_label_sound_bound μ a h Γ G Hmax hμ ha hh hΓ) ?_
    refine mul_le_mul_of_nonneg_left ?_ hH
    refine Finset.sum_le_sum fun x _ => Finset.sum_le_sum fun ℓ _ => ?_
    exact mul_le_mul_of_nonneg_left (GammaSet_mono hs G x ℓ)
      (mul_nonneg (hμ x ℓ) (sub_nonneg.2 (ha x ℓ)))
  have hcompl := P.prob_add_compl (fun s => ∃ e ∈ (univ : Finset (L × L)), ¬ Γ e.1 e.2 ≤ Γbar s e.1 e.2)
  have hmono : P.prob (fun s => ¬ ∃ e ∈ (univ : Finset (L × L)), ¬ Γ e.1 e.2 ≤ Γbar s e.1 e.2) ≤
      P.prob (fun s =>
        Rkappa μ a h Γ G ≤ Hmax * ∑ x, ∑ ℓ, μ x ℓ * (1 - a x ℓ) * GammaSet (Γbar s) G x ℓ) := by
    apply P.prob_mono
    intro s hs
    apply hgood s
    intro ℓh ℓ
    by_contra hc
    exact hs ⟨(ℓh, ℓ), Finset.mem_univ _, hc⟩
  linarith

end Classifier

/-! ## Split-conformal coverage -/

section Conformal

open MeasureTheory
open scoped ENNReal

variable {Ω : Type*} [MeasurableSpace Ω] (P : Measure Ω) [IsProbabilityMeasure P] {N : ℕ}

/-- Number of scores strictly below `z i`. -/
noncomputable def rankLT (z : Fin N → ℝ) (i : Fin N) : ℕ := (univ.filter fun j => z j < z i).card

/-- **Rank counting.** At least `m` indices have fewer than `m` scores strictly below them (ties allowed). -/
theorem count_low_rank (z : Fin N → ℝ) {m : ℕ} (hm : m ≤ N) :
    m ≤ (univ.filter fun i => rankLT z i < m).card := by
  by_contra hlt
  push_neg at hlt
  set T := univ.filter fun i => rankLT z i < m with hT
  have hC : (univ \ T).Nonempty := by
    rw [Finset.nonempty_iff_ne_empty]
    intro he
    have : T = univ := by
      rw [Finset.sdiff_eq_empty_iff_subset] at he
      exact Finset.eq_univ_of_forall fun i => he (Finset.mem_univ i)
    rw [this, Finset.card_univ, Fintype.card_fin] at hlt
    omega
  obtain ⟨i0, hi0, hmin⟩ := Finset.exists_min_image (univ \ T) z hC
  have hsub : (univ.filter fun j => z j < z i0) ⊆ T := by
    intro j hj
    rw [Finset.mem_filter] at hj
    by_contra hjT
    have := hmin j (Finset.mem_sdiff.2 ⟨Finset.mem_univ j, hjT⟩)
    linarith [hj.2]
  have hrank : rankLT z i0 < m := lt_of_le_of_lt (Finset.card_le_card hsub) hlt
  exact (Finset.mem_sdiff.1 hi0).2 (Finset.mem_filter.2 ⟨Finset.mem_univ i0, hrank⟩)

/-- Ranks are permutation-equivariant. -/
lemma rankLT_perm (z : Fin N → ℝ) (σ : Equiv.Perm (Fin N)) (i : Fin N) :
    rankLT (z ∘ σ) i = rankLT z (σ i) := by
  unfold rankLT
  apply Finset.card_equiv σ
  intro j
  simp

lemma measurable_rankLT (i : Fin N) : Measurable fun z : Fin N → ℝ => rankLT z i := by
  have : (fun z : Fin N → ℝ => rankLT z i) =
      fun z => ∑ j, (if z j < z i then (1 : ℕ) else 0) := by
    funext z; unfold rankLT; rw [Finset.card_filter]
  rw [this]
  refine Finset.measurable_sum _ fun j _ => Measurable.ite ?_ measurable_const measurable_const
  exact measurableSet_lt (measurable_pi_apply j) (measurable_pi_apply i)

/-- Exchangeability: the joint law of the scores is invariant under every permutation. -/
def Exchangeable (Z : Ω → Fin N → ℝ) : Prop :=
  ∀ σ : Equiv.Perm (Fin N), P.map (fun ω => Z ω ∘ σ) = P.map Z

/-- Under exchangeability every index has the same probability of a low rank. -/
lemma rank_event_eq {Z : Ω → Fin N → ℝ} (hZ : Measurable Z) (hex : Exchangeable P Z) (m : ℕ)
    (i j : Fin N) : P {ω | rankLT (Z ω) i < m} = P {ω | rankLT (Z ω) j < m} := by
  have hA : MeasurableSet {z : Fin N → ℝ | rankLT z j < m} :=
    measurable_rankLT j (MeasurableSet.of_discrete : MeasurableSet {k : ℕ | k < m})
  have hσ : Measurable fun ω => Z ω ∘ Equiv.swap i j :=
    Measurable.comp (g := fun z : Fin N → ℝ => z ∘ Equiv.swap i j)
      (measurable_pi_iff.2 fun k => measurable_pi_apply _) hZ
  have h1 : (P.map (fun ω => Z ω ∘ Equiv.swap i j)) {z | rankLT z j < m} = (P.map Z) {z | rankLT z j < m} := by
    rw [hex (Equiv.swap i j)]
  rw [Measure.map_apply hσ hA, Measure.map_apply hZ hA] at h1
  have h2 : (fun ω => Z ω ∘ Equiv.swap i j) ⁻¹' {z | rankLT z j < m} = {ω | rankLT (Z ω) i < m} := by
    ext ω
    simp only [Set.mem_preimage, Set.mem_setOf_eq]
    rw [rankLT_perm, Equiv.swap_apply_right]
  rw [h2] at h1
  exact h1

/-- **Split-conformal coverage (rank form).** For exchangeable scores (`N = n + 1`, the last one the test
score) and `m ≤ N` with `N (1 − α) ≤ m`: `P(rank of the test score < m) ≥ 1 − α`. -/
theorem split_conformal {n : ℕ} {Z : Ω → Fin (n + 1) → ℝ} (hZ : Measurable Z) (hex : Exchangeable P Z)
    {m : ℕ} (hm : m ≤ n + 1) {α : ℝ} (hmα : ((n : ℝ) + 1) * (1 - α) ≤ m) :
    1 - α ≤ P.real {ω | rankLT (Z ω) (Fin.last n) < m} := by
  set E : Fin (n + 1) → Set Ω := fun i => {ω | rankLT (Z ω) i < m} with hE
  have hmeas : ∀ i, MeasurableSet (E i) := fun i =>
    (measurable_rankLT i).comp hZ (MeasurableSet.of_discrete : MeasurableSet {k : ℕ | k < m})
  -- Σ_i P(E_i) = ∫ Σ_i 1_{E_i} ≥ m
  have hsum : (m : ℝ≥0∞) ≤ ∑ i, P (E i) := by
    have hint : ∑ i, P (E i) = ∫⁻ ω, ∑ i, (E i).indicator 1 ω ∂P := by
      rw [lintegral_finsetSum _ fun i _ => (measurable_one.indicator (hmeas i))]
      exact Finset.sum_congr rfl fun i _ => (lintegral_indicator_one (hmeas i)).symm
    rw [hint]
    calc (m : ℝ≥0∞) = ∫⁻ _ω, (m : ℝ≥0∞) ∂P := by simp
      _ ≤ ∫⁻ ω, ∑ i, (E i).indicator 1 ω ∂P := by
          apply lintegral_mono
          intro ω
          show (m : ℝ≥0∞) ≤ ∑ i, (E i).indicator 1 ω
          have hc := count_low_rank (Z ω) hm
          have : ∑ i, (E i).indicator (1 : Ω → ℝ≥0∞) ω =
              ∑ i, (if rankLT (Z ω) i < m then (1 : ℝ≥0∞) else 0) :=
            Finset.sum_congr rfl fun i _ => by simp [Set.indicator_apply, hE]
          rw [this, Finset.sum_boole]
          exact_mod_cast hc
  have heq : ∀ i, P (E i) = P (E (Fin.last n)) := fun i => rank_event_eq P hZ hex m i (Fin.last n)
  have hN : (m : ℝ≥0∞) ≤ ((n + 1 : ℕ) : ℝ≥0∞) * P (E (Fin.last n)) := by
    rw [Finset.sum_congr rfl fun i _ => heq i, Finset.sum_const, Finset.card_univ, Fintype.card_fin,
      nsmul_eq_mul] at hsum
    exact hsum
  have hfin : ((n + 1 : ℕ) : ℝ≥0∞) * P (E (Fin.last n)) ≠ ∞ :=
    ENNReal.mul_ne_top (ENNReal.natCast_ne_top _) (measure_ne_top P _)
  have hreal := ENNReal.toReal_mono hfin hN
  rw [ENNReal.toReal_mul, ENNReal.toReal_natCast, ENNReal.toReal_natCast] at hreal
  have hpos : (0 : ℝ) < ((n + 1 : ℕ) : ℝ) := by positivity
  show 1 - α ≤ (P (E (Fin.last n))).toReal
  have h3 : ((n : ℝ) + 1) * (1 - α) ≤ ((n + 1 : ℕ) : ℝ) * (P (E (Fin.last n))).toReal := by
    push_cast at hreal ⊢; linarith
  push_cast at h3
  have hn : (0 : ℝ) < (n : ℝ) + 1 := by positivity
  exact le_of_mul_le_mul_left h3 hn

/-- `q` is the `m`-th smallest calibration score (indices other than the last). -/
def IsOrderStat {n : ℕ} (z : Fin (n + 1) → ℝ) (m : ℕ) (q : ℝ) : Prop :=
  (univ.filter fun j => j ≠ Fin.last n ∧ z j < q).card < m ∧
    m ≤ (univ.filter fun j => j ≠ Fin.last n ∧ z j ≤ q).card

/-- The rank event is exactly "test score `≤ q̂`". -/
theorem orderStat_iff {n : ℕ} (z : Fin (n + 1) → ℝ) {m : ℕ} {q : ℝ} (hq : IsOrderStat z m q) :
    rankLT z (Fin.last n) < m ↔ z (Fin.last n) ≤ q := by
  have hr : rankLT z (Fin.last n) =
      (univ.filter fun j => j ≠ Fin.last n ∧ z j < z (Fin.last n)).card := by
    unfold rankLT
    congr 1
    ext j
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    constructor
    · intro h
      refine ⟨fun he => ?_, h⟩
      rw [he] at h; exact lt_irrefl _ h
    · exact fun h => h.2
  rw [hr]
  constructor
  · intro h
    by_contra hgt
    push_neg at hgt
    have hsub : (univ.filter fun j => j ≠ Fin.last n ∧ z j ≤ q) ⊆
        (univ.filter fun j => j ≠ Fin.last n ∧ z j < z (Fin.last n)) := by
      intro j hj
      rw [Finset.mem_filter] at hj ⊢
      exact ⟨hj.1, hj.2.1, lt_of_le_of_lt hj.2.2 hgt⟩
    have := Finset.card_le_card hsub
    have := hq.2
    omega
  · intro h
    have hsub : (univ.filter fun j => j ≠ Fin.last n ∧ z j < z (Fin.last n)) ⊆
        (univ.filter fun j => j ≠ Fin.last n ∧ z j < q) := by
      intro j hj
      rw [Finset.mem_filter] at hj ⊢
      exact ⟨hj.1, hj.2.1, lt_of_lt_of_le hj.2.2 h⟩
    exact lt_of_le_of_lt (Finset.card_le_card hsub) hq.1

/-- **Split-conformal coverage (spec form).** `P(score_{n+1} ≤ q̂) ≥ 1 − α`, where `q̂(ω)` is the `m`-th smallest
calibration score and `m = ⌈(n+1)(1−α)⌉ ≤ n + 1`. -/
theorem split_conformal_qhat {n : ℕ} {Z : Ω → Fin (n + 1) → ℝ} (hZ : Measurable Z) (hex : Exchangeable P Z)
    {m : ℕ} (hm : m ≤ n + 1) {α : ℝ} (hmα : ((n : ℝ) + 1) * (1 - α) ≤ m) (qhat : Ω → ℝ)
    (hq : ∀ ω, IsOrderStat (Z ω) m (qhat ω)) :
    1 - α ≤ P.real {ω | Z ω (Fin.last n) ≤ qhat ω} := by
  refine le_trans (split_conformal P hZ hex hm hmα) (measureReal_mono ?_)
  intro ω hω
  exact (orderStat_iff (Z ω) (hq ω)).1 hω

/-- **Judge-panel false-allow rate (v1 L3, M5).** Calibrating on off-intent examples, an off-intent test
example exchangeable with them is allowed (its score exceeds `q̂`) with probability at most `α`. -/
theorem conformal_false_allow {n : ℕ} {Z : Ω → Fin (n + 1) → ℝ} (hZ : Measurable Z) (hex : Exchangeable P Z)
    {m : ℕ} (hm : m ≤ n + 1) {α : ℝ} (hmα : ((n : ℝ) + 1) * (1 - α) ≤ m) (qhat : Ω → ℝ)
    (hqm : Measurable qhat) (hq : ∀ ω, IsOrderStat (Z ω) m (qhat ω)) :
    P.real {ω | qhat ω < Z ω (Fin.last n)} ≤ α := by
  have hcov := split_conformal_qhat P hZ hex hm hmα qhat hq
  have hA : MeasurableSet {ω | Z ω (Fin.last n) ≤ qhat ω} :=
    measurableSet_le ((measurable_pi_apply _).comp hZ) hqm
  have hset : {ω | qhat ω < Z ω (Fin.last n)} = {ω | Z ω (Fin.last n) ≤ qhat ω}ᶜ := by
    ext ω; simp [not_le]
  rw [hset]
  show (P {ω | Z ω (Fin.last n) ≤ qhat ω}ᶜ).toReal ≤ α
  rw [prob_compl_eq_one_sub hA, ENNReal.toReal_sub_of_le prob_le_one ENNReal.one_ne_top,
    ENNReal.toReal_one]
  have : 1 - α ≤ (P {ω | Z ω (Fin.last n) ≤ qhat ω}).toReal := hcov
  linarith

/-! ## T19: existence of a median with the bracket property (no order-statistic assumption) -/

/-- For `n ≥ 2f + 1` values there is an index whose value has at least `f + 1` values `≤` it and at least
`f + 1` values `≥` it (a median). -/
theorem median_exists {n f : ℕ} (vals : Fin n → ℝ) (hn : 2 * f + 1 ≤ n) :
    ∃ i, f + 1 ≤ (univ.filter fun j => vals j ≤ vals i).card ∧
      f + 1 ≤ (univ.filter fun j => vals i ≤ vals j).card := by
  classical
  have hT := count_low_rank vals (m := f + 1) (by omega)
  set T := univ.filter fun i => rankLT vals i < f + 1 with hTdef
  have hne : T.Nonempty := Finset.card_pos.1 (by omega)
  obtain ⟨i, hi, hmax⟩ := Finset.exists_max_image T vals hne
  refine ⟨i, ?_, ?_⟩
  · have hsub : T ⊆ univ.filter fun j => vals j ≤ vals i := by
      intro j hj
      exact Finset.mem_filter.2 ⟨Finset.mem_univ j, hmax j hj⟩
    exact le_trans hT (Finset.card_le_card hsub)
  · have hr : rankLT vals i < f + 1 := (Finset.mem_filter.1 hi).2
    have hsplit := Finset.card_filter_add_card_filter_not (s := (univ : Finset (Fin n)))
      (fun j => vals j < vals i)
    have heq : (univ.filter fun j => ¬ vals j < vals i) = univ.filter fun j => vals i ≤ vals j :=
      Finset.filter_congr fun j _ => not_lt
    rw [heq, Finset.card_univ, Fintype.card_fin] at hsplit
    have : rankLT vals i = (univ.filter fun j => vals j < vals i).card := rfl
    omega

/-- **T19 (robust facts, assumption-free median).** With `n ≥ 2f + 1` reported values and at most `f` faulty
reporters, a median value lies between two honest values. -/
theorem T19_robust {n f : ℕ} (vals : Fin n → ℝ) (hn : 2 * f + 1 ≤ n) (faulty : Finset (Fin n))
    (hf : faulty.card ≤ f) :
    ∃ i, (∃ a, a ∉ faulty ∧ vals a ≤ vals i) ∧ (∃ b, b ∉ faulty ∧ vals i ≤ vals b) := by
  obtain ⟨i, hlo, hhi⟩ := median_exists vals hn
  exact ⟨i, T19_median_bracket vals faulty hf (vals i) hlo hhi⟩

end Conformal

end PcaIntent.Stats
