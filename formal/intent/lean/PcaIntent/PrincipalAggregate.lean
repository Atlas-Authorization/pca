import PcaIntent.Halving

/-!
# G-T8 (goal-to-decision spec): aggregate soundness of the durable budget ledger

Model of `packages/pca/src/budget-ledger.ts`: one key (a principal, an org or a fleet) holds a list of reservations.
Each has an amount, a status (`reserved`, `committed`, `released`), a `started` flag (recorded BEFORE its effect runs) and a
ghost flag `ran` (the effect happened). The ledger's total counts every entry that is not released.

Operations (`Step`): `reserve` (admitted only when `total + a ≤ cap`: the atomic compare-and-cap step), `start`, `run`
(the effect, only after `start` and only while open), `commit` (after the effect), `release` (the effect did not run) and
`expire` (frees an open reservation that was never started; enabled at any time, so it models an arbitrary clock).
A crash is the absence of steps; a retry of a reservation is a replay and changes nothing.

* `no_overspend`: every reachable ledger has `total ≤ cap`, for every interleaving (the list is the linearized order).
* `spent_bounded`: the sum of the effects that RAN is `≤ cap` (the ledger covers what actually happened).
* `ran_counted`: an effect that ran is never released (so expiry and release cannot free spent budget).
* `sessions_share_one_cap` (W9): two different sessions of one key together stay `≤ cap`; keying by session instead lets
  each have the whole cap (`per_session_keying_overspends`).
* `rollback_restores`: a reservation released again leaves the total as before (the multi-key admission rolls back this way).
-/

namespace PcaIntent.PrincipalAggregate

inductive St where
  | reserved
  | committed
  | released
  deriving DecidableEq

structure Ent where
  sess : ℕ
  amt : ℕ
  st : St
  started : Bool
  ran : Bool

abbrev Ledger := List Ent

/-- What an entry counts: nothing once released. -/
def w (e : Ent) : ℕ := if e.st = St.released then 0 else e.amt
/-- The ledger's counted total. -/
def total (L : Ledger) : ℕ := (L.map w).sum

@[simp] theorem total_nil : total [] = 0 := by simp [total]
@[simp] theorem total_cons (e : Ent) (L : Ledger) : total (e :: L) = w e + total L := by simp [total]
theorem total_append (A B : Ledger) : total (A ++ B) = total A + total B := by
  simp [total, List.map_append, List.sum_append]

/-- One ledger operation; an entry is replaced in place (the order of the list is the linearization order). -/
inductive Step (cap : ℕ) : Ledger → Ledger → Prop
  | reserve {L : Ledger} (s a : ℕ) (h : total L + a ≤ cap) :
      Step cap L (L ++ [⟨s, a, St.reserved, false, false⟩])
  | start {A B : Ledger} (e : Ent) (h : e.st = St.reserved) :
      Step cap (A ++ e :: B) (A ++ { e with started := true } :: B)
  | run {A B : Ledger} (e : Ent) (h : e.st = St.reserved) (hs : e.started = true) :
      Step cap (A ++ e :: B) (A ++ { e with ran := true } :: B)
  | commit {A B : Ledger} (e : Ent) (h : e.st = St.reserved) (hr : e.ran = true) :
      Step cap (A ++ e :: B) (A ++ { e with st := St.committed } :: B)
  | release {A B : Ledger} (e : Ent) (h : e.st = St.reserved) (hr : e.ran = false) :
      Step cap (A ++ e :: B) (A ++ { e with st := St.released } :: B)
  | expire {A B : Ledger} (e : Ent) (h : e.st = St.reserved) (hs : e.started = false) :
      Step cap (A ++ e :: B) (A ++ { e with st := St.released } :: B)

/-- The invariant: the total is within the cap, and an effect that ran was started and is still counted. -/
abbrev Inv (cap : ℕ) (L : Ledger) : Prop :=
  total L ≤ cap ∧ ∀ e ∈ L, e.ran = true → (e.started = true ∧ e.st ≠ St.released)

theorem inv_replace (cap : ℕ) (A B : Ledger) (e e' : Ent) (hw : w e' ≤ w e)
    (hmem : e'.ran = true → (e'.started = true ∧ e'.st ≠ St.released))
    (h : Inv cap (A ++ e :: B)) : Inv cap (A ++ e' :: B) := by
  obtain ⟨h1, h2⟩ := h
  refine ⟨?_, ?_⟩
  · rw [total_append, total_cons] at h1 ⊢
    omega
  · intro x hx hr
    rw [List.mem_append, List.mem_cons] at hx
    rcases hx with hx | hx | hx
    · exact h2 x (by simp [hx]) hr
    · rw [hx] at hr ⊢
      exact hmem hr
    · exact h2 x (by simp [hx]) hr

theorem step_inv {cap : ℕ} {L L' : Ledger} (hs : Step cap L L') (h : Inv cap L) : Inv cap L' := by
  cases hs with
  | reserve s a hcap =>
    refine ⟨?_, ?_⟩
    · have : total [⟨s, a, St.reserved, false, false⟩] = a := by simp [total, w]
      rw [total_append, this]
      exact hcap
    · intro x hx hr
      rw [List.mem_append] at hx
      rcases hx with hx | hx
      · exact h.2 x hx hr
      · rw [List.mem_singleton] at hx
        rw [hx] at hr
        simp at hr
  | start e he =>
    exact inv_replace cap _ _ e _ (le_of_eq (by simp [w])) (fun _ => ⟨rfl, by simp [he]⟩) h
  | run e he hst =>
    exact inv_replace cap _ _ e _ (le_of_eq (by simp [w])) (fun _ => ⟨hst, by simp [he]⟩) h
  | commit e he hr =>
    exact inv_replace cap _ _ e _ (le_of_eq (by simp [w, he]))
      (fun _ => ⟨(h.2 e (by simp) hr).1, by simp⟩) h
  | release e he hr =>
    exact inv_replace cap _ _ e _ (by simp [w]) (fun h' => by simp [hr] at h') h
  | expire e he hst =>
    exact inv_replace cap _ _ e _ (by simp [w])
      (fun h' => by
        have := h.2 e (by simp) h'
        simp [hst] at this) h

/-- Reachable ledgers: the empty one, and any step from a reachable one. -/
inductive Reach (cap : ℕ) : Ledger → Prop
  | init : Reach cap []
  | step {L L' : Ledger} : Reach cap L → Step cap L L' → Reach cap L'

theorem reach_inv {cap : ℕ} {L : Ledger} (h : Reach cap L) : Inv cap L := by
  induction h with
  | init => exact ⟨by simp, by simp⟩
  | step _ hs ih => exact step_inv hs ih

/-- **G-T8 (no overspend).** For every interleaving of reservations, starts, effects, commits, releases and expiries, the
ledger's counted total never passes the cap. -/
theorem no_overspend {cap : ℕ} {L : Ledger} (h : Reach cap L) : total L ≤ cap := (reach_inv h).1

/-- An effect that ran is never released: neither a release nor an expiry can free spent budget. -/
theorem ran_counted {cap : ℕ} {L : Ledger} (h : Reach cap L) : ∀ e ∈ L, e.ran = true → e.st ≠ St.released :=
  fun e he hr => ((reach_inv h).2 e he hr).2

/-- What actually happened: the amounts of the effects that ran. -/
def sp (e : Ent) : ℕ := if e.ran then e.amt else 0
def spent (L : Ledger) : ℕ := (L.map sp).sum

theorem sp_le_w (e : Ent) (h : e.ran = true → e.st ≠ St.released) : sp e ≤ w e := by
  unfold sp w
  by_cases hr : e.ran = true
  · have := h hr
    simp [hr, this]
  · simp [hr]

theorem spent_le_total : ∀ (L : Ledger), (∀ e ∈ L, e.ran = true → e.st ≠ St.released) → spent L ≤ total L
  | [], _ => by simp [spent, total]
  | e :: L, h => by
    have h1 := sp_le_w e (h e (by simp))
    have h2 := spent_le_total L (fun x hx => h x (by simp [hx]))
    simp only [spent, total, List.map_cons, List.sum_cons] at h2 ⊢
    omega

/-- **Spent is bounded.** The effects that ran sum to at most the cap: the ledger covers what happened, not only what it counted. -/
theorem spent_bounded {cap : ℕ} {L : Ledger} (h : Reach cap L) : spent L ≤ cap :=
  le_trans (spent_le_total L (ran_counted h)) (no_overspend h)

/-- The part of the total belonging to one session. -/
def wBy (s : ℕ) (e : Ent) : ℕ := if e.sess = s then w e else 0
def totalBy (s : ℕ) (L : Ledger) : ℕ := (L.map (wBy s)).sum

theorem two_sessions (s t : ℕ) (hst : s ≠ t) : ∀ L : Ledger, totalBy s L + totalBy t L ≤ total L
  | [] => by simp [totalBy, total]
  | e :: L => by
    have ih := two_sessions s t hst L
    have key : wBy s e + wBy t e ≤ w e := by
      unfold wBy
      by_cases h1 : e.sess = s
      · have h2 : ¬ e.sess = t := fun h2 => hst (h1.symm.trans h2)
        rw [if_pos h1, if_neg h2]
        omega
      · by_cases h2 : e.sess = t
        · rw [if_neg h1, if_pos h2]
          omega
        · rw [if_neg h1, if_neg h2]
          omega
    simp only [totalBy, total, List.map_cons, List.sum_cons] at ih ⊢
    omega

/-- **W9 (one cap for all sessions).** Any two different sessions of one key together stay within the one cap. -/
theorem sessions_share_one_cap {cap : ℕ} {L : Ledger} (h : Reach cap L) (s t : ℕ) (hst : s ≠ t) :
    totalBy s L + totalBy t L ≤ cap :=
  le_trans (two_sessions s t hst L) (no_overspend h)

/-- Negative control: a cap kept PER SESSION (keyed by grant or session, not by principal) lets two sessions each hold
the whole cap, so the principal's total is twice it. -/
theorem per_session_keying_overspends (c : ℕ) (hc : 1 ≤ c) :
    ∃ L : Ledger, totalBy 0 L ≤ c ∧ totalBy 1 L ≤ c ∧ c < total L := by
  refine ⟨[⟨0, c, St.reserved, false, false⟩, ⟨1, c, St.reserved, false, false⟩], ?_, ?_, ?_⟩
  all_goals simp [totalBy, total, w, wBy]
  all_goals omega

/-- A reservation released again leaves the total as it was: the rollback of a multi-key admission that failed at a later key. -/
theorem rollback_restores (L : Ledger) (s a : ℕ) :
    total (L ++ [⟨s, a, St.released, false, false⟩]) = total L := by
  have h0 : total [⟨s, a, St.released, false, false⟩] = 0 := by simp [total, w]
  rw [total_append, h0]
  exact Nat.add_zero _

end PcaIntent.PrincipalAggregate
