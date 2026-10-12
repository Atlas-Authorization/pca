import PcaMath.Star
import PcaMath.Rom

/-!
# Joint knowledge soundness of a composite Fiat-Shamir proof (OR proofs + aggregation Schnorr)

Instantiates the k-fork lemma `Star.star_mass_ge` for a random-oracle prover that outputs a composite
proof with several components (index type `κ`), each component's challenge being the answer to its own
random-oracle query.  Then specialises to the range proof of `packages/pca-ratchet` (`accumulator.ts`:
`n = 32` bit commitments `B_j`, one OR proof per bit, one aggregation Schnorr proof; `n + 1 = 33` challenges,
each `hashToScalar(domain || ctx || ...)` with `ctx` binding all `B_j`).

Result (`range_knowledge_soundness`): if the verifier accepts the proof with probability `p` over the
random oracle and the prover's coins, then with probability at least
`p * ((p/q)^(n+1) - (n+1)/|H|)` the run is accepting AND the committed point `V` opens as
`V = v*G + γ*H` with an integer `0 <= v < 2^n`.
-/

open Finset

namespace PcaMath.Multi

open PcaMath.Fork PcaMath.Rom PcaMath.Star

/-! ## Generic multi-component prover -/

structure MProver (R H : Type*) (q : ℕ) (κ Out : Type*) where
  out : R × (Fin q → H) → Option Out
  idx : Out → κ → Fin q
  Acc : κ → Out → H → Prop
  Agree : κ → Out → Out → Prop
  Good : κ → Out → Out → Prop
  /-- an accepting run is accepted by every component's verifier, on the oracle answer of its query. -/
  accepts : ∀ ω o, out ω = some o → ∀ r, Acc r o (ω.2 (idx o r))
  /-- causality: the statement and announcement of component `r` are fixed by the coins and the answers
      before its challenge query. -/
  causal : ∀ r (i : Fin q) ω ω' o o', cls i ω' = cls i ω → out ω = some o → out ω' = some o' →
    idx o r = i → idx o' r = i → Agree r o o'
  /-- special soundness of component `r`. -/
  sound : ∀ r o o' e e', e ≠ e' → Agree r o o' → Acc r o e → Acc r o' e' → Good r o o'

section Gen
variable {R H : Type*} [Fintype R] [Fintype H] [DecidableEq R] [DecidableEq H] {q : ℕ} [NeZero q]
  {κ Out : Type*} [Fintype κ]

open Classical in
noncomputable def MProver.accS (P : MProver R H q κ Out) : Finset (R × (Fin q → H)) :=
  univ.filter (fun ω => (P.out ω).isSome)

open Classical in
noncomputable def MProver.ix (P : MProver R H q κ Out) (r : κ) (ω : R × (Fin q → H)) : Fin q :=
  match P.out ω with
  | some o => P.idx o r
  | none => 0

lemma MProver.ix_eq (P : MProver R H q κ Out) {r : κ} {ω : R × (Fin q → H)} {o : Out}
    (h : P.out ω = some o) : P.ix r ω = P.idx o r := by
  unfold MProver.ix; rw [h]

open Classical in
lemma MProver.mem_accS (P : MProver R H q κ Out) (ω : R × (Fin q → H)) :
    ω ∈ P.accS ↔ ∃ o, P.out ω = some o := by
  simp [MProver.accS, Option.isSome_iff_exists]

open Classical in
/-- number of runs in the class of `ω` at component `r`'s fork point that are accepting, with the same index,
a different answer, and form a good pair with `ω`. -/
noncomputable def MProver.goodCnt (P : MProver R H q κ Out) (r : κ) (ω : R × (Fin q → H)) : ℝ :=
  ((P.accS.filter (fun ω' => P.ix r ω' = P.ix r ω ∧ cls (P.ix r ω) ω' = cls (P.ix r ω) ω ∧
        ans (P.ix r ω) ω' ≠ ans (P.ix r ω) ω ∧
        ∃ o o', P.out ω = some o ∧ P.out ω' = some o' ∧ P.Good r o o')).card : ℝ)

open Classical in
lemma goodCnt_eq (P : MProver R H q κ Out) {ω : R × (Fin q → H)} (hω : ω ∈ P.accS) (r : κ) :
    P.goodCnt r ω = dcnt (cls (R := R) (H := H) (q := q)) ans P.accS P.ix r ω := by
  unfold MProver.goodCnt dcnt
  congr 2
  apply Finset.filter_congr
  intro ω' hω'
  constructor
  · rintro ⟨h1, h2, h3, _⟩; exact ⟨h1, h2, h3⟩
  · rintro ⟨h1, h2, h3⟩
    refine ⟨h1, h2, h3, ?_⟩
    obtain ⟨o', ho'⟩ := (P.mem_accS ω').mp hω'
    obtain ⟨o, ho⟩ := (P.mem_accS ω).mp hω
    refine ⟨o, o', ho, ho', ?_⟩
    rw [P.ix_eq ho] at h1 h2 h3
    rw [P.ix_eq ho'] at h1
    have hag := P.causal r (P.idx o r) ω ω' o o' h2 ho ho' rfl h1
    refine P.sound r o o' (ω.2 (P.idx o r)) (ω'.2 (P.idx o r)) (fun h => h3 h.symm) hag ?_ ?_
    · exact P.accepts ω o ho r
    · have := P.accepts ω' o' ho' r
      rw [h1] at this; exact this

open Classical in
/-- `|Ω|` times the probability that the extractor obtains a good pair for every component, when the
per-component success probability `x` (one re-sample is good) is post-processed by `Ψ`
(`Ψ = id`: one re-sample per component; `Ψ = retryΨ T`: `T` re-samples). -/
noncomputable def genMassP (P : MProver R H q κ Out) (Ψ : ℝ → ℝ) : ℝ :=
  ∑ ω ∈ P.accS, ∏ r, Ψ (P.goodCnt r ω / (csize q H (P.ix r ω) : ℝ))

open Classical in
lemma genMassP_eq (P : MProver R H q κ Out) (Ψ : ℝ → ℝ) :
    genMassP P Ψ = genMass (cls (R := R) (H := H) (q := q)) ans (csize q H) P.accS P.ix Ψ := by
  unfold genMassP genMass
  apply Finset.sum_congr rfl; intro ω hω
  apply Finset.prod_congr rfl; intro r _
  rw [goodCnt_eq P hω r]

open Classical in
/-- **Joint knowledge soundness in the ROM, single re-sample per component** (k-fork). -/
theorem multi_knowledge_soundness (P : MProver R H q κ Out) [Nonempty R] [Nonempty H] :
    genMassP P id / (Fintype.card (R × (Fin q → H)) : ℝ) ≥
      ((P.accS.card : ℝ) / (Fintype.card (R × (Fin q → H)) : ℝ)) *
        ((((P.accS.card : ℝ) / (Fintype.card (R × (Fin q → H)) : ℝ)) / (q : ℝ)) ^ (Fintype.card κ)
          - (Fintype.card κ : ℝ) / (Fintype.card H : ℝ)) := by
  have hH : 0 < Fintype.card H := Fintype.card_pos
  have hΩ : 0 < Fintype.card (R × (Fin q → H)) := Fintype.card_pos
  have key := star_mass_ge (cls (R := R) (H := H) (q := q)) ans (csize q H) P.accS P.ix
    (fun i ω => card_cls i ω) (fun i ω c => card_cls_ans i ω c) hH
  have hg : genMassP P id = starMass (cls (R := R) (H := H) (q := q)) ans (csize q H) P.accS P.ix := by
    rw [genMassP_eq]; rfl
  rw [hg]
  simp only [Fintype.card_fin] at key
  have hΩr : (0 : ℝ) < Fintype.card (R × (Fin q → H)) := by exact_mod_cast hΩ
  set Ω := (Fintype.card (R × (Fin q → H)) : ℝ)
  set a := (P.accS.card : ℝ)
  have e : a / Ω * (((a / Ω) / (q : ℝ)) ^ (Fintype.card κ) - (Fintype.card κ : ℝ) / (Fintype.card H : ℝ))
      = (a * ((a / ((q : ℝ) * Ω)) ^ (Fintype.card κ) - (Fintype.card κ : ℝ) / (Fintype.card H : ℝ))) / Ω := by
    rw [div_div, mul_comm Ω]
    ring
  rw [e]
  exact div_le_div_of_nonneg_right key hΩr.le

open Classical in
/-- **Joint knowledge soundness with `T` re-samples per component** (linear in the accepting probability).
`p = |accS|/|Ω|`, `ε = 1/|H|`, threshold `δ > ε` (with `δ - ε <= 1`):
Pr[extractor gets all `k` good pairs] `>= (p - k δ q) * (1 - (1 - (δ - ε))^T)^k`. -/
theorem multi_retry_soundness (P : MProver R H q κ Out) [Nonempty R] [Nonempty H] (T : ℕ) (δ : ℝ)
    (hδ : 1 / (Fintype.card H : ℝ) < δ) (hδ1 : δ - 1 / (Fintype.card H : ℝ) ≤ 1) :
    genMassP P (retryΨ T) / (Fintype.card (R × (Fin q → H)) : ℝ) ≥
      (((P.accS.card : ℝ) / (Fintype.card (R × (Fin q → H)) : ℝ)) - (Fintype.card κ : ℝ) * (δ * (q : ℝ))) *
        (1 - (1 - (δ - 1 / (Fintype.card H : ℝ))) ^ T) ^ (Fintype.card κ) := by
  have hH : 0 < Fintype.card H := Fintype.card_pos
  have hΩ : 0 < Fintype.card (R × (Fin q → H)) := Fintype.card_pos
  have key := retry_mass_ge (cls (R := R) (H := H) (q := q)) ans (csize q H) P.accS P.ix
    (fun i ω => card_cls i ω) (fun i ω c => card_cls_ans i ω c) hH T δ hδ hδ1
  rw [← genMassP_eq] at key
  simp only [Fintype.card_fin] at key
  have hΩr : (0 : ℝ) < Fintype.card (R × (Fin q → H)) := by exact_mod_cast hΩ
  set Ω := (Fintype.card (R × (Fin q → H)) : ℝ)
  set c := (1 - (1 - (δ - 1 / (Fintype.card H : ℝ))) ^ T) ^ (Fintype.card κ)
  have e : ((P.accS.card : ℝ) / Ω - (Fintype.card κ : ℝ) * (δ * (q : ℝ))) * c
      = (((P.accS.card : ℝ) - (Fintype.card κ : ℝ) * (δ * ((q : ℝ) * Ω))) * c) / Ω := by
    field_simp
  rw [e]
  exact div_le_div_of_nonneg_right key hΩr.le

open Classical in
/-- the mass is carried by runs on which the glued conclusion `Fin'` holds (`Ψ` with `Ψ 0 = 0`, `Ψ ∈ [0,1]`
on `[0,1]`). -/
lemma genMassP_le_card (P : MProver R H q κ Out) (Ψ : ℝ → ℝ) (hΨ0 : Ψ 0 = 0)
    (hΨnn : ∀ x, 0 ≤ x → x ≤ 1 → 0 ≤ Ψ x) (hΨ1 : ∀ x, 0 ≤ x → x ≤ 1 → Ψ x ≤ 1)
    (Fin' : Out → Prop) (glue : ∀ o, (∀ r, ∃ o', P.Good r o o') → Fin' o) :
    genMassP P Ψ ≤ ((P.accS.filter (fun ω => ∃ o, P.out ω = some o ∧ Fin' o)).card : ℝ) := by
  unfold genMassP
  rw [Finset.card_filter, Nat.cast_sum]
  apply Finset.sum_le_sum
  intro ω hω
  obtain ⟨o, ho⟩ := (P.mem_accS ω).mp hω
  have hrange : ∀ r, 0 ≤ P.goodCnt r ω / (csize q H (P.ix r ω) : ℝ) ∧
      P.goodCnt r ω / (csize q H (P.ix r ω) : ℝ) ≤ 1 := by
    intro r
    have hN : 0 < csize q H (P.ix r ω) := by
      rw [← card_cls (P.ix r ω) ω]
      exact Finset.card_pos.mpr ⟨ω, by simp⟩
    have hNr : (0 : ℝ) < csize q H (P.ix r ω) := by exact_mod_cast hN
    refine ⟨by unfold MProver.goodCnt; positivity, ?_⟩
    rw [div_le_one hNr, ← card_cls (P.ix r ω) ω]
    unfold MProver.goodCnt
    exact_mod_cast Finset.card_le_card (fun x hx => by simp at hx ⊢; exact hx.2.2.1)
  by_cases hF : ∃ o, P.out ω = some o ∧ Fin' o
  · rw [if_pos hF, Nat.cast_one]
    exact Finset.prod_le_one₀ (fun r _ => hΨnn _ (hrange r).1 (hrange r).2)
      (fun r _ => hΨ1 _ (hrange r).1 (hrange r).2)
  · rw [if_neg hF]
    by_contra hpos
    push_neg at hpos
    have hall : ∀ r, ∃ o', P.Good r o o' := by
      intro r
      have hne : P.goodCnt r ω ≠ 0 := by
        intro h0
        have : ∏ r, Ψ (P.goodCnt r ω / (csize q H (P.ix r ω) : ℝ)) = 0 :=
          Finset.prod_eq_zero (Finset.mem_univ r) (by rw [h0]; simp [hΨ0])
        linarith
      have hc : 0 < (P.accS.filter (fun ω' => P.ix r ω' = P.ix r ω ∧ cls (P.ix r ω) ω' = cls (P.ix r ω) ω ∧
          ans (P.ix r ω) ω' ≠ ans (P.ix r ω) ω ∧
          ∃ o o', P.out ω = some o ∧ P.out ω' = some o' ∧ P.Good r o o')).card := by
        by_contra h
        apply hne
        have : (P.accS.filter (fun ω' => P.ix r ω' = P.ix r ω ∧ cls (P.ix r ω) ω' = cls (P.ix r ω) ω ∧
          ans (P.ix r ω) ω' ≠ ans (P.ix r ω) ω ∧
          ∃ o o', P.out ω = some o ∧ P.out ω' = some o' ∧ P.Good r o o')).card = 0 := Nat.eq_zero_of_not_pos h
        unfold MProver.goodCnt; rw [this]; simp
      obtain ⟨ω', hω'⟩ := Finset.card_pos.mp hc
      simp only [Finset.mem_filter] at hω'
      obtain ⟨o1, o2, h1, h2, h3⟩ := hω'.2.2.2.2
      rw [ho] at h1; cases h1
      exact ⟨o2, h3⟩
    exact hF ⟨o, ho, glue o hall⟩

end Gen

/-! ## Algebra of the OR proof, the aggregation proof and the range glue -/

section Alg
variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

/-- OR proof (`proveBit`/`verifyBit` in `accumulator.ts`), special soundness. -/
lemma or_special_sound (Gg Hh B a0 a1 : G) (e e' e0 e1 z0 z1 e0' e1' z0' z1' : F) (hne : e ≠ e')
    (h : e0 + e1 = e) (h' : e0' + e1' = e')
    (v0 : z0 • Hh = a0 + e0 • B) (v1 : z1 • Hh = a1 + e1 • (B - Gg))
    (v0' : z0' • Hh = a0 + e0' • B) (v1' : z1' • Hh = a1 + e1' • (B - Gg)) :
    ∃ (b : Bool) (s : F), B = (if b then (1 : F) else 0) • Gg + s • Hh := by
  by_cases h0 : e0 = e0'
  · have h1 : e1 ≠ e1' := by
      intro h1; apply hne; rw [← h, ← h', h0, h1]
    have hd : e1 - e1' ≠ 0 := sub_ne_zero.mpr h1
    have h3 : (z1 - z1') • Hh = (e1 - e1') • (B - Gg) := by
      rw [sub_smul, sub_smul, v1, v1']; abel
    refine ⟨true, (e1 - e1')⁻¹ * (z1 - z1'), ?_⟩
    have : B - Gg = ((e1 - e1')⁻¹ * (z1 - z1')) • Hh := by
      rw [mul_smul, h3, smul_smul, inv_mul_cancel₀ hd, one_smul]
    simp only [if_true, one_smul]
    rw [← this]; abel
  · have hd : e0 - e0' ≠ 0 := sub_ne_zero.mpr h0
    have h3 : (z0 - z0') • Hh = (e0 - e0') • B := by
      rw [sub_smul, sub_smul, v0, v0']; abel
    refine ⟨false, (e0 - e0')⁻¹ * (z0 - z0'), ?_⟩
    have : B = ((e0 - e0')⁻¹ * (z0 - z0')) • Hh := by
      rw [mul_smul, h3, smul_smul, inv_mul_cancel₀ hd, one_smul]
    simp only [Bool.false_eq_true, if_false, zero_smul, zero_add]
    exact this

/-- Aggregation Schnorr proof, special soundness. -/
lemma agg_special_sound (Hh D a : G) (e e' z z' : F) (hne : e ≠ e')
    (v : z • Hh = a + e • D) (v' : z' • Hh = a + e' • D) : ∃ w : F, D = w • Hh := by
  have hd : e - e' ≠ 0 := sub_ne_zero.mpr hne
  have h3 : (z - z') • Hh = (e - e') • D := by
    rw [sub_smul, sub_smul, v, v']; abel
  refine ⟨(e - e')⁻¹ * (z - z'), ?_⟩
  rw [mul_smul, h3, smul_smul, inv_mul_cancel₀ hd, one_smul]

/-- Range glue: bit commitments open to bits, and `Σ 2^j B_j - V` is a pure `H`-multiple, then `V` opens to an
integer in `[0, 2^n)`. -/
lemma range_glue (Gg Hh V : G) (n : ℕ) (B : Fin n → G)
    (hb : ∀ j, ∃ (b : Bool) (s : F), B j = (if b then (1 : F) else 0) • Gg + s • Hh)
    (hw : ∃ w : F, (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j) - V = w • Hh) :
    ∃ vn : ℕ, vn < 2 ^ n ∧ ∃ γ : F, V = (vn : F) • Gg + γ • Hh := by
  choose b s hbs using hb
  obtain ⟨w, hw⟩ := hw
  set vn : ℕ := ∑ j : Fin n, if b j then 2 ^ (j : ℕ) else 0 with hvn
  refine ⟨vn, ?_, (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) * s j) - w, ?_⟩
  · have h1 : vn ≤ ∑ j : Fin n, 2 ^ (j : ℕ) := by
      apply Finset.sum_le_sum; intro j _; split_ifs <;> simp
    have h2 : ∑ j : Fin n, 2 ^ (j : ℕ) = 2 ^ n - 1 := by
      rw [Fin.sum_univ_eq_sum_range (fun j => 2 ^ j) n]
      have := Nat.geomSum_eq (m := 2) (le_refl 2) n
      simpa using this
    have h3 : 0 < 2 ^ n := by positivity
    omega
  · have hsum : (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j)
        = (vn : F) • Gg + (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) * s j) • Hh := by
      have : ∀ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j
          = (((2 : F) ^ (j : ℕ)) * (if b j then (1 : F) else 0)) • Gg + (((2 : F) ^ (j : ℕ)) * s j) • Hh := by
        intro j
        rw [hbs j, smul_add, smul_smul, smul_smul]
      rw [Finset.sum_congr rfl (fun j _ => this j), Finset.sum_add_distrib, ← Finset.sum_smul, ← Finset.sum_smul]
      congr 2
      rw [hvn]; push_cast
      apply Finset.sum_congr rfl; intro j _; split_ifs <;> simp
    have : V = (∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • B j) - w • Hh := by rw [← hw]; abel
    rw [this, hsum, sub_smul]; abel

end Alg

/-! ## The range proof -/

section Range
variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

structure RangeOut (F G : Type*) (n q : ℕ) where
  B : Fin n → G
  a0 : Fin n → G
  a1 : Fin n → G
  aa : G
  e0 : Fin n → F
  e1 : Fin n → F
  z0 : Fin n → F
  z1 : Fin n → F
  za : F
  qi : Fin n → Fin q
  qa : Fin q

def RangeOut.idx {n q : ℕ} (o : RangeOut F G n q) : Option (Fin n) → Fin q
  | some j => o.qi j
  | none => o.qa

variable (Gg Hh V : G) (n q : ℕ)

def rAcc : Option (Fin n) → RangeOut F G n q → F → Prop
  | some j, o, e => o.e0 j + o.e1 j = e ∧ o.z0 j • Hh = o.a0 j + o.e0 j • o.B j ∧
      o.z1 j • Hh = o.a1 j + o.e1 j • (o.B j - Gg)
  | none, o, e => o.za • Hh = o.aa + e • ((∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • o.B j) - V)

def rAgree : Option (Fin n) → RangeOut F G n q → RangeOut F G n q → Prop
  | some j, o, o' => o.B = o'.B ∧ o.a0 j = o'.a0 j ∧ o.a1 j = o'.a1 j
  | none, o, o' => o.B = o'.B ∧ o.aa = o'.aa

def rGood : Option (Fin n) → RangeOut F G n q → RangeOut F G n q → Prop
  | some j, o, _ => ∃ (b : Bool) (s : F), o.B j = (if b then (1 : F) else 0) • Gg + s • Hh
  | none, o, _ => ∃ w : F, ((∑ j : Fin n, ((2 : F) ^ (j : ℕ)) • o.B j) - V) = w • Hh

lemma rSound (r : Option (Fin n)) (o o' : RangeOut F G n q) (e e' : F) (hne : e ≠ e')
    (hag : rAgree n q r o o') (h : rAcc Gg Hh V n q r o e) (h' : rAcc Gg Hh V n q r o' e') :
    rGood Gg Hh V n q r o o' := by
  cases r with
  | some j =>
    obtain ⟨hB, ha0, ha1⟩ := hag
    obtain ⟨c, v0, v1⟩ := h
    obtain ⟨c', v0', v1'⟩ := h'
    rw [← hB, ← ha0] at v0'
    rw [← hB, ← ha1] at v1'
    exact or_special_sound Gg Hh (o.B j) (o.a0 j) (o.a1 j) e e' (o.e0 j) (o.e1 j) (o.z0 j) (o.z1 j)
      (o'.e0 j) (o'.e1 j) (o'.z0 j) (o'.z1 j) hne c c' v0 v1 v0' v1'
  | none =>
    obtain ⟨hB, haa⟩ := hag
    simp only [rAcc] at h h'
    rw [← hB, ← haa] at h'
    exact agg_special_sound Hh _ o.aa e e' o.za o'.za hne h h'

/-- The range-proof prover in the ROM over the scalar field `F` (the challenge space): `out` returns the
proof (bit commitments, announcements, responses, and the query index of each of the `n + 1` challenges)
of an accepting run. -/
def mkRange {R : Type*} (out : R × (Fin q → F) → Option (RangeOut F G n q))
    (accepts : ∀ ω o, out ω = some o → ∀ r, rAcc Gg Hh V n q r o (ω.2 (o.idx r)))
    (causal : ∀ r (i : Fin q) ω ω' o o', cls i ω' = cls i ω → out ω = some o → out ω' = some o' →
      o.idx r = i → o'.idx r = i → rAgree n q r o o') :
    MProver R F q (Option (Fin n)) (RangeOut F G n q) where
  out := out
  idx := fun o r => o.idx r
  Acc := rAcc Gg Hh V n q
  Agree := rAgree n q
  Good := rGood Gg Hh V n q
  accepts := accepts
  causal := causal
  sound := fun r o o' e e' hne hag h h' => rSound Gg Hh V n q r o o' e e' hne hag h h'

/-- the glued conclusion: `V` opens, with an integer value in `[0, 2^n)`. -/
def Openable : Prop := ∃ vn : ℕ, vn < 2 ^ n ∧ ∃ γ : F, V = (vn : F) • Gg + γ • Hh

lemma glue_range (o : RangeOut F G n q) (h : ∀ r, ∃ o', rGood Gg Hh V n q r o o') :
    Openable (F := F) Gg Hh V n := by
  apply range_glue Gg Hh V n o.B
  · intro j
    obtain ⟨_, hj⟩ := h (some j)
    exact hj
  · obtain ⟨_, hw⟩ := h none
    exact hw

section RangeThm
variable [Fintype F] [DecidableEq F] {R : Type*} [Fintype R] [DecidableEq R] [Nonempty R] [NeZero q] [Nonempty F]

open Classical in
/-- **Range proof: knowledge soundness in the ROM** (all 33 challenges at once).  Let `p` be the probability
that the verifier accepts the prover's range proof for `V`.  For every threshold `ε < δ` and number `T` of
re-samples per challenge, with probability at least `(p - (n+1) δ q) (1 - (1 - (δ - ε))^T)^(n+1)` (`ε = 1/|F|`)
the run is accepting AND `V` has an opening `vn * G + γ * H` with an integer `0 <= vn < 2^n`. -/
theorem range_knowledge_soundness
    (out : R × (Fin q → F) → Option (RangeOut F G n q))
    (accepts : ∀ ω o, out ω = some o → ∀ r, rAcc Gg Hh V n q r o (ω.2 (o.idx r)))
    (causal : ∀ r (i : Fin q) ω ω' o o', cls i ω' = cls i ω → out ω = some o → out ω' = some o' →
      o.idx r = i → o'.idx r = i → rAgree n q r o o')
    (T : ℕ) (δ : ℝ) (hδ : 1 / (Fintype.card F : ℝ) < δ) (hδ1 : δ - 1 / (Fintype.card F : ℝ) ≤ 1) :
    ((((mkRange Gg Hh V n q out accepts causal).accS.filter
        (fun ω => ∃ o, out ω = some o ∧ Openable (F := F) Gg Hh V n)).card : ℝ)
      / (Fintype.card (R × (Fin q → F)) : ℝ)) ≥
      ((((mkRange Gg Hh V n q out accepts causal).accS.card : ℝ) / (Fintype.card (R × (Fin q → F)) : ℝ))
          - ((n : ℝ) + 1) * (δ * (q : ℝ))) *
        (1 - (1 - (δ - 1 / (Fintype.card F : ℝ))) ^ T) ^ (n + 1) := by
  set P := mkRange Gg Hh V n q out accepts causal with hP
  have hmain := multi_retry_soundness P T δ hδ hδ1
  have hle := genMassP_le_card P (retryΨ T)
    (by unfold retryΨ; simp)
    (fun x h0 h1 => by
      unfold retryΨ
      have : (1 - x) ^ T ≤ 1 := pow_le_one₀ (by linarith) (by linarith)
      linarith)
    (fun x h0 h1 => by
      unfold retryΨ
      have : 0 ≤ (1 - x) ^ T := pow_nonneg (by linarith) T
      linarith)
    (fun _ => Openable (F := F) Gg Hh V n)
    (fun o h => glue_range Gg Hh V n q o h)
  have hΩ : (0 : ℝ) < Fintype.card (R × (Fin q → F)) := by exact_mod_cast Fintype.card_pos
  have hk : Fintype.card (Option (Fin n)) = n + 1 := by simp
  rw [hk] at hmain
  push_cast at hmain
  calc _ ≥ genMassP P (retryΨ T) / (Fintype.card (R × (Fin q → F)) : ℝ) :=
        div_le_div_of_nonneg_right hle hΩ.le
    _ ≥ _ := hmain

open Classical in
/-- **Soundness error of the range proof.**  If `V` has no opening with an integer value in `[0, 2^n)`,
every prover (making at most `q` oracle queries) is accepted with probability at most `(n + 1) q / |F|`. -/
theorem range_soundness_error
    (out : R × (Fin q → F) → Option (RangeOut F G n q))
    (accepts : ∀ ω o, out ω = some o → ∀ r, rAcc Gg Hh V n q r o (ω.2 (o.idx r)))
    (causal : ∀ r (i : Fin q) ω ω' o o', cls i ω' = cls i ω → out ω = some o → out ω' = some o' →
      o.idx r = i → o'.idx r = i → rAgree n q r o o')
    (hno : ¬ Openable (F := F) Gg Hh V n) :
    ((mkRange Gg Hh V n q out accepts causal).accS.card : ℝ) / (Fintype.card (R × (Fin q → F)) : ℝ)
      ≤ ((n : ℝ) + 1) * (q : ℝ) / (Fintype.card F : ℝ) := by
  set P := mkRange Gg Hh V n q out accepts causal with hP
  set p : ℝ := (P.accS.card : ℝ) / (Fintype.card (R × (Fin q → F)) : ℝ) with hp
  set ε : ℝ := 1 / (Fintype.card F : ℝ) with hε
  have hFpos : (0 : ℝ) < Fintype.card F := by exact_mod_cast Fintype.card_pos
  have hε0 : 0 < ε := by positivity
  have hΩ : (0 : ℝ) < Fintype.card (R × (Fin q → F)) := by exact_mod_cast Fintype.card_pos
  have hp1 : p ≤ 1 := by
    rw [hp, div_le_one hΩ]
    exact_mod_cast Finset.card_le_univ _
  have hq : (1 : ℝ) ≤ q := by exact_mod_cast Nat.one_le_iff_ne_zero.mpr (NeZero.ne q)
  set M : ℝ := ((n : ℝ) + 1) * q with hM
  have hM1 : 1 ≤ M := by
    have : (1 : ℝ) ≤ (n : ℝ) + 1 := by linarith [(Nat.cast_nonneg n : (0 : ℝ) ≤ n)]
    nlinarith
  have hε1 : ε ≤ 1 := by
    rw [hε, div_le_one hFpos]
    exact_mod_cast Fintype.card_pos
  have target : ((n : ℝ) + 1) * (q : ℝ) / (Fintype.card F : ℝ) = M * ε := by
    rw [hM, hε]; ring
  rw [target]
  by_contra hcon
  push_neg at hcon
  -- δ halfway between ε and p / M
  have hpM : ε < p / M := by
    rw [lt_div_iff₀ (by linarith)]; linarith
  set δ : ℝ := (ε + p / M) / 2 with hδ
  have hδε : ε < δ := by rw [hδ]; linarith
  have hpM1 : p / M ≤ 1 := by
    rw [div_le_one (by linarith)]; linarith
  have hδ1 : δ - ε ≤ 1 := by rw [hδ]; linarith
  have key := range_knowledge_soundness Gg Hh V n q out accepts causal 1 δ hδε hδ1
  have hempty : (P.accS.filter (fun ω => ∃ o, out ω = some o ∧ Openable (F := F) Gg Hh V n)) = ∅ := by
    apply Finset.filter_false_of_mem
    intro ω _ ⟨o, _, h⟩
    exact hno h
  simp only [hP] at hempty
  rw [hempty] at key
  simp only [Finset.card_empty, Nat.cast_zero, zero_div, pow_one, sub_sub_cancel] at key
  have hc : 0 < δ - ε := by linarith
  have hk : (δ - ε) ^ (n + 1) > 0 := pow_pos hc _
  have : (p - ((n : ℝ) + 1) * (δ * (q : ℝ))) ≤ 0 := by
    by_contra h
    push_neg at h
    have := mul_pos h hk
    linarith
  have e : ((n : ℝ) + 1) * (δ * (q : ℝ)) = M * δ := by rw [hM]; ring
  rw [e] at this
  have : M * δ = (M * ε + p) / 2 := by
    rw [hδ]; field_simp
  nlinarith

end RangeThm

end Range

end PcaMath.Multi
