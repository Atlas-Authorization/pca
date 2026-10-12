import Mathlib

/-!
# OT-extension tweak counter (R4-12, part 3)

Rounds hash `ms[0], ms[1], ...` rows.  The channel-global row index of position `j` in round `i` is
`off ms i + j` with `off ms i = ms[0] + ... + ms[i-1]` (the field `rowsDone`, advanced by `m` per round).
-/

namespace PcaMath.OtCounter

def off (ms : List ℕ) (i : ℕ) : ℕ := (ms.take i).sum

/-- lockstep advance by exactly `m` per round -/
theorem off_succ (ms : List ℕ) (i : ℕ) (hi : i < ms.length) : off ms (i + 1) = off ms i + ms[i] := by
  unfold off
  exact List.sum_take_succ ms i hi

theorem off_succ_ge (ms : List ℕ) (i : ℕ) : off ms i ≤ off ms (i + 1) := by
  unfold off
  rw [List.take_succ]
  cases ms[i]? <;> simp

/-- monotone -/
theorem off_mono (ms : List ℕ) {i i' : ℕ} (h : i ≤ i') : off ms i ≤ off ms i' := by
  induction h with
  | refl => exact le_rfl
  | step _ ih => exact le_trans ih (off_succ_ge ms _)

/-- the global index of slot `(i, j)` -/
def idx (ms : List ℕ) (i j : ℕ) : ℕ := off ms i + j

/-- DISTINCT TWEAKS: distinct slots of one channel have distinct global indices. -/
theorem idx_injective (ms : List ℕ) {i j i' j' : ℕ} (hi : i < ms.length) (hj : j < ms[i])
    (hi' : i' < ms.length) (hj' : j' < ms[i']) (h : idx ms i j = idx ms i' j') : i = i' ∧ j = j' := by
  unfold idx at h
  rcases lt_trichotomy i i' with hlt | heq | hgt
  · exfalso
    have h1 := off_succ ms i hi
    have h2 : off ms (i + 1) ≤ off ms i' := off_mono ms hlt
    omega
  · subst heq; omega
  · exfalso
    have h1 := off_succ ms i' hi'
    have h2 : off ms (i' + 1) ≤ off ms i := off_mono ms hgt
    omega

/-- NO WRAP: if the session hashes fewer than `2^64` rows in total, every global index is `< 2^64`
(so the 64-bit counter field holds it exactly). -/
theorem idx_lt (ms : List ℕ) (hsum : ms.sum < 2 ^ 64) {i j : ℕ} (hi : i < ms.length) (hj : j < ms[i]) :
    idx ms i j < 2 ^ 64 := by
  unfold idx
  have h1 := off_succ ms i hi
  have h2 : off ms (i + 1) ≤ ms.sum := by
    unfold off
    obtain ⟨t, ht⟩ := List.take_prefix (i + 1) ms
    calc (ms.take (i + 1)).sum ≤ (ms.take (i + 1)).sum + t.sum := Nat.le_add_right _ _
      _ = ms.sum := by rw [← List.sum_append, ht]
  omega

/-- The code's 64-bit add (low word `offLo + j`, high word `offHi + carry`) equals the true sum:
with `M = 2^32`, `offLo = o % M`, `offHi = o / M`, `v = offLo + j`, the pair `(v % M, offHi + v / M)` is the
base-`M` expansion of `o + j`. -/
theorem word_add (o j : ℕ) :
    (o % 4294967296 + j) % 4294967296 = (o + j) % 4294967296 ∧
    o / 4294967296 + (o % 4294967296 + j) / 4294967296 = (o + j) / 4294967296 := by
  constructor <;> omega

/-- the 128-bit tweak is injective in (domain, index): domain words fill bits 64..127, index bits 0..63. -/
theorem tweak_injective {d d' x x' : ℕ} (hx : x < 2 ^ 64) (hx' : x' < 2 ^ 64)
    (h : d * 2 ^ 64 + x = d' * 2 ^ 64 + x') : d = d' ∧ x = x' := by
  constructor <;> omega

end PcaMath.OtCounter
