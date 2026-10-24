import PcaIntent.Halving
import PcaIntent.Hoeffding

/-!
# v2 trajectory intent (spec v2 §2.1–2.2, claims T10, T11, T11b, T29, T30)

**T10.** Histories are lists of events; `lift ξ ω t` is the augmented outcome (outcome, post-action accumulator
values, monitor states). An *attempt sequence* is any list of `(ω, t)`; because every run of any agent strategy
(adaptive or adversarial, with its randomness fixed) produces some attempt sequence, quantifying over all
sequences covers all strategies. A denied attempt leaves the history unchanged. If the trajectory intent is
Ψ-expressible (`a* ξ ω t = ã (lift ξ ω t)`) and the grant only contains `ã = 1` points, every admitted step has
`a* = 1`, so the trajectory risk is 0 (`T10_lift_sound`, `T10_risk_zero`). With `G = G_1(VS_n)` over Ω̃, T1
supplies the premise (`T10_instances`): v1's theorems apply verbatim because Ω̃ is just a `Fintype`.

**T11.** Post-action cap: an admission check "`s + v ≤ c`" keeps the counted sum `≤ c` for every attempt
sequence (`T11_cap_invariant`); splitting one action into pieces with the same total changes nothing
(`T11_split_invariant`); a split never lowers a count (`T11_count_split_mono`). **T11b**: per-site caps whose
allocations sum to `≤ c` keep the global sum `≤ c` (`T11b_partition`).

**T29.** Per-session harm in `[0, L_max · H_max]` gives T4 with that range (`T29_trajectory_mc`).

**T30.** A downward-closed intent on a sum/count side `{0, …, k}` is a prefix (`T30_mono_realizes`), and a
halving search over the `k + 1` prefix thresholds takes at most `⌊log₂ (k+1)⌋` questions (`T30_mono_halving`).
-/

namespace PcaIntent.Traj

open Finset

variable {Om Ev Ωt : Type*}

open Classical in
/-- The admitted steps `(history before, outcome, time)` of an attempt sequence, from history `ξ`. -/
noncomputable def admitted (lift : List Ev → Om → ℕ → Ωt) (mk : Om → ℕ → Ev) (G : Set Ωt) :
    List Ev → List (Om × ℕ) → List (List Ev × Om × ℕ)
  | _, [] => []
  | ξ, (ω, t) :: rest =>
      if lift ξ ω t ∈ G then (ξ, ω, t) :: admitted lift mk G (ξ ++ [mk ω t]) rest
        else admitted lift mk G ξ rest

/-- **T10 (lifting soundness).** Every admitted step of every attempt sequence has `a* = 1`. -/
theorem T10_lift_sound (lift : List Ev → Om → ℕ → Ωt) (mk : Om → ℕ → Ev) (G : Set Ωt)
    (astar : List Ev → Om → ℕ → Bool) (atil : Ωt → Bool)
    (hexp : ∀ ξ ω t, astar ξ ω t = atil (lift ξ ω t)) (hG : ∀ x ∈ G, atil x = true) :
    ∀ (ξ : List Ev) (atts : List (Om × ℕ)), ∀ p ∈ admitted lift mk G ξ atts,
      astar p.1 p.2.1 p.2.2 = true := by
  intro ξ atts
  induction atts generalizing ξ with
  | nil => intro p hp; simp [admitted] at hp
  | cons att rest ih =>
      obtain ⟨ω, t⟩ := att
      intro p hp
      classical
      simp only [admitted] at hp
      split_ifs at hp with hin
      · rcases List.mem_cons.1 hp with rfl | hp'
        · rw [hexp]; exact hG _ hin
        · exact ih _ p hp'
      · exact ih _ p hp

/-- **T10 (trajectory risk zero).** The harm-weighted count of admitted unwanted steps is zero. -/
theorem T10_risk_zero (lift : List Ev → Om → ℕ → Ωt) (mk : Om → ℕ → Ev) (G : Set Ωt)
    (astar : List Ev → Om → ℕ → Bool) (atil : Ωt → Bool)
    (hexp : ∀ ξ ω t, astar ξ ω t = atil (lift ξ ω t)) (hG : ∀ x ∈ G, atil x = true)
    (h : Om → ℝ) (ξ : List Ev) (atts : List (Om × ℕ)) :
    ((admitted lift mk G ξ atts).map
      fun p => (if astar p.1 p.2.1 p.2.2 = true then 0 else 1) * h p.2.1).sum = 0 := by
  apply List.sum_eq_zero
  intro x hx
  obtain ⟨p, hp, rfl⟩ := List.mem_map.1 hx
  show (if astar p.1 p.2.1 p.2.2 = true then (0 : ℝ) else 1) * h p.2.1 = 0
  rw [T10_lift_sound lift mk G astar atil hexp hG ξ atts p hp]
  simp

/-- **T10 instances.** v1's T1 over the augmented space supplies the premise of `T10_lift_sound`:
`G_1(VS_n) ⊆ θ̃*` when θ̃* realizes `ã` and the answers are noise-free. -/
theorem T10_instances [Fintype Ωt] {Θ : Type*} {acc : Θ → Ωt → Bool} {H : Finset Θ}
    {obs : List (Ωt × Bool)} {θs : Θ} (hH : θs ∈ H) (hc : Consistent acc θs obs) :
    ∀ x ∈ ((G1 acc (VS acc H obs) : Finset Ωt) : Set Ωt), acc θs x = true :=
  fun _ hx => G1_subset_truth (truth_mem_VS hH hc) hx

/-! ## T11: caps on post-action accumulator values -/

/-- Sum after processing contributions `vs` with the admission check `s + v ≤ c`. -/
def capRun (c : ℕ) : ℕ → List ℕ → ℕ
  | s, [] => s
  | s, v :: rest => if s + v ≤ c then capRun c (s + v) rest else capRun c s rest

/-- **T11 (cap invariant).** For every attempt sequence, the counted sum never exceeds the cap. -/
theorem T11_cap_invariant (c : ℕ) : ∀ (s : ℕ) (vs : List ℕ), s ≤ c → capRun c s vs ≤ c
  | s, [], hs => hs
  | s, v :: rest, hs => by
      simp only [capRun]
      split_ifs with h
      · exact T11_cap_invariant c (s + v) rest h
      · exact T11_cap_invariant c s rest hs

/-- The counted sum never decreases. -/
theorem capRun_ge (c : ℕ) : ∀ (s : ℕ) (vs : List ℕ), s ≤ capRun c s vs
  | s, [] => le_rfl
  | s, v :: rest => by
      simp only [capRun]
      split_ifs
      · exact le_trans (Nat.le_add_right s v) (capRun_ge c (s + v) rest)
      · exact capRun_ge c s rest

/-- **T11 (splitting is useless).** If the whole action fits, its pieces are all admitted and reach exactly the
same sum; whatever happens, the cap holds. -/
theorem T11_split_invariant (c s : ℕ) (ps : List ℕ) (hfit : s + ps.sum ≤ c) :
    capRun c s ps = s + ps.sum := by
  induction ps generalizing s with
  | nil => simp [capRun]
  | cons v rest ih =>
      have h1 : s + v ≤ c := by simp [List.sum_cons] at hfit; omega
      have h2 : s + v + rest.sum ≤ c := by simp [List.sum_cons] at hfit; omega
      simp only [capRun]
      rw [if_pos h1, ih (s + v) h2, List.sum_cons]
      ring

/-- **T11 (count).** Splitting an action counted by `sel` into non-empty pieces that are all in `sel` (SEL)
never lowers the count. -/
theorem T11_count_split_mono {α : Type*} (inSel : α → Bool) (ps : List α) (hne : ps ≠ [])
    (hsel : ∀ p ∈ ps, inSel p = true) : 1 ≤ (ps.filter inSel).length := by
  obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil ps hne
  exact List.length_pos_of_mem (List.mem_filter.2 ⟨hp, hsel p hp⟩)

/-- **T11b (static partition).** Per-site totals under per-site caps whose allocations sum to at most `c`. -/
theorem T11b_partition {S : Type*} (sites : Finset S) (tot alloc : S → ℕ) (c : ℕ)
    (hsite : ∀ s ∈ sites, tot s ≤ alloc s) (hall : ∑ s ∈ sites, alloc s ≤ c) :
    ∑ s ∈ sites, tot s ≤ c :=
  le_trans (Finset.sum_le_sum hsite) hall

/-! ## T29: trajectory Monte Carlo -/

/-- **T29.** T4 with range `L_max · H_max` for the per-session harm. -/
theorem T29_trajectory_mc {S : Type*} [MeasurableSpace S] {P : MeasureTheory.Measure S}
    [MeasureTheory.IsProbabilityMeasure P] {m : ℕ} (hm : 0 < m) {Lmax : ℕ} {Hmax r : ℝ}
    (hpos : 0 < (Lmax : ℝ) * Hmax) (X : ℕ → S → ℝ) (hind : ProbabilityTheory.iIndepFun X P)
    (hmeas : ∀ j, Measurable (X j)) (hb : ∀ j s, X j s ∈ Set.Icc 0 ((Lmax : ℝ) * Hmax))
    (hmean : ∀ j, ∫ s, X j s ∂P = r) {δ' : ℝ} (hδ0 : 0 < δ') (hδ2 : δ' ≤ 2) :
    P.real {s | MC.radius ((Lmax : ℝ) * Hmax) m δ' ≤ |MC.mean X m s - r|} ≤ δ' :=
  MC.hoeffding_conf X hm hpos hind hmeas hb hmean hδ0 hδ2

/-! ## T30: downward-closed intent on an accumulator side -/

/-- **T30 (realizable in the monotone class).** A downward-closed set of accumulator values is a prefix
`{0, …, c−1}`. -/
theorem T30_mono_realizes (D : Finset ℕ) (hdown : ∀ n ∈ D, ∀ m ≤ n, m ∈ D) :
    ∃ c, D = Finset.range c := by
  by_cases hne : D.Nonempty
  · refine ⟨D.max' hne + 1, ?_⟩
    ext x
    rw [Finset.mem_range]
    constructor
    · intro hx; exact Nat.lt_succ_of_le (D.le_max' x hx)
    · intro hx; exact hdown _ (D.max'_mem hne) x (Nat.le_of_lt_succ hx)
  · refine ⟨0, ?_⟩
    rw [Finset.not_nonempty_iff_eq_empty] at hne
    rw [hne, Finset.range_zero]

/-- Threshold hypotheses on a chain side with `k + 1` values: `c` accepts the values `< c`. -/
def thrAcc (k c : ℕ) (n : Fin (k + 1)) : Bool := decide (n.val < c)

/-- **T30 (halving bound).** On a side with `k` cells there are `k + 1` thresholds; a halving run over them
asks at most `⌊log₂ (k+1)⌋ ≤ ⌈log₂ (k+1)⌉` questions. -/
theorem T30_mono_halving (k : ℕ) {cs : ℕ} (hcs : cs ∈ Finset.range (k + 1))
    (obs : List (Fin (k + 1) × Bool)) (hrun : HalvingRun (thrAcc k) (Finset.range (k + 1)) obs)
    (hc : Consistent (thrAcc k) cs obs) : obs.length ≤ Nat.log 2 (k + 1) := by
  have h := halving_queries (Finset.range (k + 1)) hcs obs hrun hc
  rwa [Finset.card_range] at h

end PcaIntent.Traj
