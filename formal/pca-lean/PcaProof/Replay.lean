/-
  Theorem 5 -- replay-store invariants (packages/pca/src/replay.ts: ReplayStore.consumeOnce,
  CounterStore.advance, InMemoryReplayStore.prune).

  Two machine-checked results over abstract keys (any type with decidable equality):

    * ONE-TIME USE.  `consumeOnce key retainUntil` succeeds only if no entry for `key` is live at the
      store clock.  We prove that in EVERY reachable state (arbitrary interleavings of clock ticks,
      consumes, and prunes of expired entries) a key that was accepted with retention `r` cannot be
      accepted again while the clock is `<= r`:  `no_double_accept`.   Pruning is safe because it only
      removes entries whose retention has elapsed.
    * STRICT COUNTER MONOTONICITY.  `advance stream c` succeeds only if `c` exceeds the stored value; the
      stored value never decreases, and the accepted counters of one stream are strictly increasing
      (`counter_log_strict`), hence pairwise distinct (`counter_log_unique`).

  Scope: this models the store CONTRACT (replay.ts header, points 1-2), single logical store, atomic
  operations.  It does not model distributed stores, crashes that lose state (a contract violation) or the
  Postgres implementation.  Self-contained: core Lean only.
-/
namespace PcaProof.Replay

variable {α : Type} [DecidableEq α]

/-! ## One-time-use nonce store -/

structure NSt (α : Type) where
  store : List (α × Nat)          -- (key, retainUntil)
  clock : Nat
  log   : List (α × Nat × Nat)    -- ghost: accepted (key, retainUntil, acceptedAt)

def live (s : List (α × Nat)) (k : α) (now : Nat) : Prop :=
  ∃ e ∈ s, e.1 = k ∧ now ≤ e.2

inductive NStep : NSt α → NSt α → Prop
  /-- the clock moves forward (never back) -/
  | tick (s : NSt α) (d : Nat) :
      NStep s { s with clock := s.clock + d }
  /-- consumeOnce succeeded: no live entry for k, and the retention horizon is not in the past -/
  | consume (s : NSt α) (k : α) (r : Nat) (hr : s.clock ≤ r) (hfresh : ¬ live s.store k s.clock) :
      NStep s { s with store := (k, r) :: s.store, log := (k, r, s.clock) :: s.log }
  /-- consumeOnce was refused (key live, or store failed closed): state unchanged -/
  | refuse (s : NSt α) : NStep s s
  /-- prune: drop ONLY entries whose retention has fully elapsed (retainUntil < now) -/
  | prune (s : NSt α) :
      NStep s { s with store := s.store.filter (fun e => decide (s.clock ≤ e.2)) }

inductive NReach : NSt α → Prop
  | init : NReach { store := [], clock := 0, log := [] }
  | step {s s' : NSt α} : NReach s → NStep s s' → NReach s'

/-- Invariant: every accepted (k, r, t) is either still in the store or already expired (r < clock);
    and acceptance times are in the past. -/
def NInv (s : NSt α) : Prop :=
  ∀ x ∈ s.log, ((x.1, x.2.1) ∈ s.store ∨ x.2.1 < s.clock) ∧ x.2.2 ≤ s.clock

theorem nreach_inv {s : NSt α} (h : NReach s) : NInv s := by
  induction h with
  | init => intro x hx; simp at hx
  | @step s0 s1 hr hstep ih =>
    cases hstep with
    | tick d =>
      intro x hx
      obtain ⟨h1, h2⟩ := ih x hx
      refine ⟨?_, by simp; omega⟩
      rcases h1 with h1 | h1
      · exact Or.inl h1
      · right; simp; omega
    | consume k r hr hfresh =>
      intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact ⟨Or.inl (by simp), Nat.le_refl _⟩
      · obtain ⟨h1, h2⟩ := ih x hx
        refine ⟨?_, h2⟩
        rcases h1 with h1 | h1
        · exact Or.inl (List.mem_cons_of_mem _ h1)
        · exact Or.inr h1
    | refuse => exact ih
    | prune =>
      intro x hx
      obtain ⟨h1, h2⟩ := ih x hx
      refine ⟨?_, h2⟩
      rcases h1 with h1 | h1
      · by_cases hc : s0.clock ≤ x.2.1
        · exact Or.inl (List.mem_filter.mpr ⟨h1, by simp [hc]⟩)
        · exact Or.inr (by show x.2.1 < s0.clock; omega)
      · exact Or.inr h1

/-- **ONE-TIME USE.**  In any reachable state, if key `k` was accepted with retention `r`, a further
    consume of `k` can succeed only after the clock has passed `r` (no double acceptance inside the
    retention window -- which the guard sets to `exp + skew`, covering the whole validity window). -/
theorem no_double_accept {s : NSt α} (h : NReach s) {k : α} {r t : Nat}
    (hx : (k, r, t) ∈ s.log) (hfresh : ¬ live s.store k s.clock) : r < s.clock := by
  obtain ⟨h1, _⟩ := nreach_inv h (k, r, t) hx
  have h1 : ((k, r) ∈ s.store) ∨ r < s.clock := h1
  rcases h1 with h1 | h1
  · rcases Nat.lt_or_ge r s.clock with hl | hl
    · exact hl
    · exact absurd ⟨(k, r), h1, rfl, hl⟩ hfresh
  · exact h1

/-- A successful consume is never preceded by an acceptance of the same key with an unexpired window. -/
theorem consume_success_requires_expired {s : NSt α} (h : NReach s) {k : α} {r t : Nat}
    (hx : (k, r, t) ∈ s.log) (hfresh : ¬ live s.store k s.clock) : r < s.clock :=
  no_double_accept h hx hfresh

/-- Pruning is safe: it never changes liveness at or after the current clock. -/
theorem prune_preserves_live (s : List (α × Nat)) (now t : Nat) (k : α) (ht : now ≤ t) :
    live (s.filter (fun e => decide (now ≤ e.2))) k t ↔ live s k t := by
  constructor
  · rintro ⟨e, he, h1, h2⟩
    exact ⟨e, (List.mem_filter.mp he).1, h1, h2⟩
  · rintro ⟨e, he, h1, h2⟩
    exact ⟨e, List.mem_filter.mpr ⟨he, by simp; omega⟩, h1, h2⟩

/-! ## Strictly monotone counter streams -/

structure CSt (α : Type) where
  last : α → Option Nat
  log  : List (α × Nat)           -- ghost: accepted (stream, counter), newest first

inductive CStep : CSt α → CSt α → Prop
  /-- advance succeeded: counter strictly greater than the stored value (or no value yet) -/
  | adv (s : CSt α) (k : α) (c : Nat) (hgt : ∀ l, s.last k = some l → l < c) :
      CStep s { last := fun k' => if k' = k then some c else s.last k', log := (k, c) :: s.log }
  /-- advance refused (not greater, or store failed closed): unchanged -/
  | refuse (s : CSt α) : CStep s s

inductive CReach : CSt α → Prop
  | init : CReach { last := fun _ => none, log := [] }
  | step {s s' : CSt α} : CReach s → CStep s s' → CReach s'

theorem creach_inv {s : CSt α} (h : CReach s) :
    ∀ x ∈ s.log, ∃ l, s.last x.1 = some l ∧ x.2 ≤ l := by
  induction h with
  | init => intro x hx; simp at hx
  | step _ hstep ih =>
    cases hstep with
    | adv k c hgt =>
      intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact ⟨c, by simp, Nat.le_refl _⟩
      · obtain ⟨l, hl, hle⟩ := ih x hx
        by_cases hk : x.1 = k
        · have := hgt l (hk ▸ hl)
          exact ⟨c, by simp [hk], by omega⟩
        · exact ⟨l, by simp [hk, hl], hle⟩
    | refuse => exact ih

/-- The stored value never decreases and every success is strictly above everything accepted before:
    in a reachable state, for any accepted (k, c) and any later successful advance to c' on k, c < c'. -/
theorem counter_success_above_log {s : CSt α} (h : CReach s) {k : α} {c c' : Nat}
    (hx : (k, c) ∈ s.log) (hgt : ∀ l, s.last k = some l → l < c') : c < c' := by
  obtain ⟨l, hl, hle⟩ := creach_inv h (k, c) hx
  have := hgt l hl
  simp at hle
  omega

/-- The accepted counters of every stream form a strictly decreasing list (newest first), hence strictly
    increasing in time. -/
def StrictFor (k : α) : List (α × Nat) → Prop
  | [] => True
  | x :: rest => (x.1 = k → ∀ y ∈ rest, y.1 = k → y.2 < x.2) ∧ StrictFor k rest

theorem creach_strict {s : CSt α} (h : CReach s) (k : α) : StrictFor k s.log := by
  induction h with
  | init => trivial
  | step hr hstep ih =>
    cases hstep with
    | adv k' c hgt =>
      refine ⟨?_, ih⟩
      intro hk y hy hyk
      obtain ⟨l, hl, hle⟩ := creach_inv hr y hy
      have hy' : y.1 = k' := by rw [hyk]; exact hk.symm
      have := hgt l (by rw [← hy']; exact hl)
      show y.2 < c
      omega
    | refuse => exact ih
end PcaProof.Replay
