import PcaIntent.VersionSpace

/-!
# Query optimality: the halving argument (spec claim T3; brief item 4)

Elicitation asks a question `ω` and the answer `y` replaces the version space `V` by `answer V ω y =
{θ ∈ V : a_θ(ω) = y}` (`VS_cons`). Runs are lists of answered questions, newest first.

* `Halves V ω` : both answers keep at most half: `|V| ≤ 2·|{θ∈V : ω∈θ}|` and `|V| ≤ 2·|{θ∈V : ω∉θ}|`
  (equivalently, `min(|acc|, |rej|) ≥ |V|/2`, the maximal-disagreement query of spec T3).
* `Splits c V ω` : the "roughly half" generalisation, `min(|acc|, |rej|) ≥ c·|V|` for a constant `0 < c ≤ 1/2`.
* `InformRun` : every question lies in the disagreement region (no other assumption).

Results (finite `H`):
* `halving_card`    : after `n` halving questions, `2^n · |VS_n| ≤ |H|`;
* `halving_queries` : under realizability + noise-free answers, a halving run has length `≤ ⌊log₂ |H|⌋`;
* `split_card`      : after `n` `c`-splitting questions, `|VS_n| ≤ (1−c)^n · |H|`;
* `split_queries`   : … and the run length `n` satisfies `c·(n−1) ≤ ln(|H|/2)`, i.e. `n = O(log |H| / c)`;
* `inform_card`/`inform_queries` : any run of informative questions has length `≤ |H| − 1`.
This is the classical halving argument (Littlestone 1988; Angluin 1988) in Mitchell's version-space setting.
-/

namespace PcaIntent

open Finset

variable {Ω Θ : Type*} [Fintype Ω] {acc : Θ → Ω → Bool}

variable (acc) in
open Classical in
/-- The version space that remains after answering `y` to the question `ω`. -/
noncomputable def answer (V : Finset Θ) (ω : Ω) (y : Bool) : Finset Θ := V.filter fun θ => acc θ ω = y

lemma answer_subset (V : Finset Θ) (ω : Ω) (y : Bool) : answer acc V ω y ⊆ V := by
  classical
  unfold answer; exact Finset.filter_subset _ _

lemma VS_cons_answer (H : Finset Θ) (o : Ω × Bool) (obs : List (Ω × Bool)) :
    VS acc H (o :: obs) = answer acc (VS acc H obs) o.1 o.2 := by
  unfold answer; exact VS_cons H o obs

lemma VS_nil (H : Finset Θ) : VS acc H ([] : List (Ω × Bool)) = H := by
  ext θ
  rw [mem_VS]
  simp [Consistent]

/-- The two answers partition the version space. -/
lemma card_answer_add (V : Finset Θ) (ω : Ω) :
    (answer acc V ω true).card + (answer acc V ω false).card = V.card := by
  classical
  unfold answer
  have h := Finset.card_filter_add_card_filter_not (s := V) (fun θ => acc θ ω = true)
  simpa only [Bool.not_eq_true] using h

/-! ## Exact halving -/

/-- The halving condition of spec T3. -/
def Halves (V : Finset Θ) (ω : Ω) : Prop :=
  V.card ≤ 2 * (answer acc V ω true).card ∧ V.card ≤ 2 * (answer acc V ω false).card

variable (acc) in
/-- A run in which every question halves the then-current version space. -/
def HalvingRun (H : Finset Θ) : List (Ω × Bool) → Prop
  | [] => True
  | o :: obs => HalvingRun H obs ∧ Halves (acc := acc) (VS acc H obs) o.1

lemma two_mul_answer_le {V : Finset Θ} {ω : Ω} (hh : Halves (acc := acc) V ω) (y : Bool) :
    2 * (answer acc V ω y).card ≤ V.card := by
  have hs := card_answer_add (acc := acc) V ω
  obtain ⟨h1, h2⟩ := hh
  cases y <;> omega

/-- **Geometric shrinkage.** After `n` halving questions, `2^n · |VS_n| ≤ |H|`. -/
theorem halving_card (H : Finset Θ) :
    ∀ obs : List (Ω × Bool), HalvingRun acc H obs → 2 ^ obs.length * (VS acc H obs).card ≤ H.card
  | [], _ => by simp [VS_nil]
  | o :: obs, ⟨hrun, hh⟩ => by
      have ih := halving_card H obs hrun
      have hstep := two_mul_answer_le hh o.2
      rw [VS_cons_answer, List.length_cons, pow_succ]
      calc 2 ^ obs.length * 2 * (answer acc (VS acc H obs) o.1 o.2).card
          = 2 ^ obs.length * (2 * (answer acc (VS acc H obs) o.1 o.2).card) := by ring
        _ ≤ 2 ^ obs.length * (VS acc H obs).card := Nat.mul_le_mul_left _ hstep
        _ ≤ H.card := ih

/-- A halving question asked of a non-empty version space is informative, so that space has `≥ 2` members. -/
lemma two_le_card_of_halves {V : Finset Θ} {ω : Ω} (hh : Halves (acc := acc) V ω) (hne : V.Nonempty) :
    2 ≤ V.card := by
  have hs := card_answer_add (acc := acc) V ω
  have hpos := Finset.card_pos.2 hne
  obtain ⟨h1, h2⟩ := hh
  omega

/-- **T3 (halving termination).** Under realizability and noise-free answers, a run of halving questions has
at most `⌊log₂ |H|⌋` questions. -/
theorem halving_queries (H : Finset Θ) {θs : Θ} (hH : θs ∈ H) :
    ∀ obs : List (Ω × Bool), HalvingRun acc H obs → Consistent acc θs obs →
      obs.length ≤ Nat.log 2 H.card
  | [], _, _ => Nat.zero_le _
  | o :: obs, ⟨hrun, hh⟩, hc => by
      have hc' : Consistent acc θs obs := fun o' ho' => hc o' (List.mem_cons_of_mem _ ho')
      have hne : (VS acc H obs).Nonempty := ⟨θs, truth_mem_VS hH hc'⟩
      have h2 := two_le_card_of_halves hh hne
      have hk := halving_card H obs hrun
      apply Nat.le_log_of_pow_le (by norm_num)
      rw [List.length_cons, pow_succ]
      calc 2 ^ obs.length * 2 ≤ 2 ^ obs.length * (VS acc H obs).card := Nat.mul_le_mul_left _ h2
        _ ≤ H.card := hk

/-! ## "Roughly half": constant-fraction splits -/

/-- Each answer removes at least a `c` fraction of the version space. -/
def Splits (c : ℝ) (V : Finset Θ) (ω : Ω) : Prop :=
  c * V.card ≤ (answer acc V ω true).card ∧ c * V.card ≤ (answer acc V ω false).card

variable (acc) in
/-- A run of `c`-splitting questions. -/
def SplitRun (c : ℝ) (H : Finset Θ) : List (Ω × Bool) → Prop
  | [] => True
  | o :: obs => SplitRun c H obs ∧ Splits (acc := acc) c (VS acc H obs) o.1

lemma answer_le_of_splits {c : ℝ} {V : Finset Θ} {ω : Ω} (hs : Splits (acc := acc) c V ω) (y : Bool) :
    ((answer acc V ω y).card : ℝ) ≤ (1 - c) * V.card := by
  have hsum : ((answer acc V ω true).card : ℝ) + (answer acc V ω false).card = V.card := by
    exact_mod_cast card_answer_add (acc := acc) V ω
  obtain ⟨h1, h2⟩ := hs
  cases y <;> linarith

/-- **Geometric shrinkage for `c`-splits.** `|VS_n| ≤ (1−c)^n · |H|`. -/
theorem split_card {c : ℝ} (hc1 : c ≤ 1) (H : Finset Θ) :
    ∀ obs : List (Ω × Bool), SplitRun acc c H obs →
      ((VS acc H obs).card : ℝ) ≤ (1 - c) ^ obs.length * H.card
  | [], _ => by simp [VS_nil]
  | o :: obs, ⟨hrun, hs⟩ => by
      have ih := split_card hc1 H obs hrun
      have hstep := answer_le_of_splits hs o.2
      rw [VS_cons_answer, List.length_cons, pow_succ]
      have h0 : 0 ≤ 1 - c := by linarith
      calc ((answer acc (VS acc H obs) o.1 o.2).card : ℝ) ≤ (1 - c) * (VS acc H obs).card := hstep
        _ ≤ (1 - c) * ((1 - c) ^ obs.length * H.card) := mul_le_mul_of_nonneg_left ih h0
        _ = (1 - c) ^ obs.length * (1 - c) * H.card := by ring

/-- **Termination for `c`-splits.** Under realizability + noise-free answers and `0 < c ≤ 1`, a run of `n + 1`
splitting questions satisfies `2 ≤ (1−c)^n · |H|` and hence `c · n ≤ ln(|H| / 2)`: `O(log |H| / c)` questions. -/
theorem split_queries {c : ℝ} (hc0 : 0 < c) (hc1 : c ≤ 1) (H : Finset Θ) {θs : Θ} (hH : θs ∈ H)
    (o : Ω × Bool) (obs : List (Ω × Bool)) (hrun : SplitRun acc c H (o :: obs))
    (hc : Consistent acc θs (o :: obs)) :
    (2 : ℝ) ≤ (1 - c) ^ obs.length * H.card ∧ c * obs.length ≤ Real.log (H.card / 2) := by
  obtain ⟨hrun', hs⟩ := hrun
  have hc' : Consistent acc θs obs := fun o' ho' => hc o' (List.mem_cons_of_mem _ ho')
  have hmem := truth_mem_VS hH hc'
  have hpos : (1 : ℝ) ≤ (VS acc H obs).card := by
    exact_mod_cast Finset.card_pos.2 ⟨θs, hmem⟩
  have hsum : ((answer acc (VS acc H obs) o.1 true).card : ℝ) +
      (answer acc (VS acc H obs) o.1 false).card = (VS acc H obs).card := by
    exact_mod_cast card_answer_add (acc := acc) (VS acc H obs) o.1
  obtain ⟨h1, h2⟩ := hs
  -- both sides are non-empty, so the version space has at least two members
  have hA : (1 : ℝ) ≤ (answer acc (VS acc H obs) o.1 true).card := by
    have hc0' : (0 : ℝ) < c * (VS acc H obs).card := mul_pos hc0 (by linarith)
    have : (0 : ℝ) < (answer acc (VS acc H obs) o.1 true).card := lt_of_lt_of_le hc0' h1
    have hnat : 0 < (answer acc (VS acc H obs) o.1 true).card := by exact_mod_cast this
    exact_mod_cast Nat.succ_le_of_lt hnat
  have hB : (1 : ℝ) ≤ (answer acc (VS acc H obs) o.1 false).card := by
    have hc0' : (0 : ℝ) < c * (VS acc H obs).card := mul_pos hc0 (by linarith)
    have : (0 : ℝ) < (answer acc (VS acc H obs) o.1 false).card := lt_of_lt_of_le hc0' h2
    have hnat : 0 < (answer acc (VS acc H obs) o.1 false).card := by exact_mod_cast this
    exact_mod_cast Nat.succ_le_of_lt hnat
  have h2le : (2 : ℝ) ≤ (VS acc H obs).card := by linarith
  have hk := split_card hc1 H obs hrun'
  have hfirst : (2 : ℝ) ≤ (1 - c) ^ obs.length * H.card := le_trans h2le hk
  refine ⟨hfirst, ?_⟩
  -- (1 - c)^n ≤ exp(-c)^n = exp(-c n)
  have hexp : (1 - c) ^ obs.length ≤ Real.exp (-(c * obs.length)) := by
    have hb : 0 ≤ 1 - c := by linarith
    calc (1 - c) ^ obs.length ≤ (Real.exp (-c)) ^ obs.length :=
          pow_le_pow_left₀ hb (by have := Real.add_one_le_exp (-c); linarith) _
      _ = Real.exp (-(c * obs.length)) := by
          rw [← Real.exp_nat_mul]; congr 1; ring
  have hHpos : (0 : ℝ) ≤ H.card := by positivity
  have h3 : (2 : ℝ) ≤ Real.exp (-(c * obs.length)) * H.card :=
    le_trans hfirst (mul_le_mul_of_nonneg_right hexp hHpos)
  have h4 : Real.exp (c * obs.length) * 2 ≤ H.card := by
    have he : Real.exp (c * obs.length) * Real.exp (-(c * obs.length)) = 1 := by
      rw [← Real.exp_add]; simp
    have hpos' : 0 < Real.exp (c * obs.length) := Real.exp_pos _
    calc Real.exp (c * obs.length) * 2
        ≤ Real.exp (c * obs.length) * (Real.exp (-(c * obs.length)) * H.card) :=
          mul_le_mul_of_nonneg_left h3 hpos'.le
      _ = (Real.exp (c * obs.length) * Real.exp (-(c * obs.length))) * H.card := by ring
      _ = H.card := by rw [he, one_mul]
  have hH2 : (0 : ℝ) < H.card / 2 := by
    have : (0 : ℝ) < Real.exp (c * obs.length) * 2 := by positivity
    linarith
  rw [Real.le_log_iff_exp_le hH2]
  linarith

/-! ## No assumption on the question beyond informativeness -/

variable (acc) in
/-- A run in which every question lies in the disagreement region of the then-current version space. -/
def InformRun (H : Finset Θ) : List (Ω × Bool) → Prop
  | [] => True
  | o :: obs => InformRun H obs ∧ o.1 ∈ DIS acc (VS acc H obs)

lemma answer_ssubset {V : Finset Θ} {ω : Ω} (hd : ω ∈ DIS acc V) (y : Bool) :
    answer acc V ω y ⊂ V := by
  classical
  unfold answer
  rw [Finset.filter_ssubset]
  obtain ⟨θ, hθ, θ', hθ', hne⟩ := mem_DIS.1 hd
  by_cases h : acc θ ω = y
  · exact ⟨θ', hθ', fun h' => hne (h.trans h'.symm)⟩
  · exact ⟨θ, hθ, h⟩

/-- Every informative question removes at least one hypothesis: `n + |VS_n| ≤ |H|`. -/
theorem inform_card (H : Finset Θ) :
    ∀ obs : List (Ω × Bool), InformRun acc H obs → obs.length + (VS acc H obs).card ≤ H.card
  | [], _ => by simp [VS_nil]
  | o :: obs, ⟨hrun, hd⟩ => by
      have ih := inform_card H obs hrun
      have hlt := Finset.card_lt_card (answer_ssubset hd o.2)
      rw [VS_cons_answer, List.length_cons]
      omega

/-- **T3, assumption-free part.** Under realizability + noise-free answers, any run of informative questions
has at most `|H| − 1` questions. -/
theorem inform_queries (H : Finset Θ) {θs : Θ} (hH : θs ∈ H) (obs : List (Ω × Bool))
    (hrun : InformRun acc H obs) (hc : Consistent acc θs obs) : obs.length + 1 ≤ H.card := by
  have h := inform_card H obs hrun
  have hpos := Finset.card_pos.2 ⟨θs, truth_mem_VS hH hc⟩
  omega

end PcaIntent
