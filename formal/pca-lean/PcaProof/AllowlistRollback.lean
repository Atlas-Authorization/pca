/-
  Allowlist manifest rollback, UNBOUNDED in the number of steps (complements formal/tamarin/pca_allowlist_v3b.spthy, which
  is bounded).  Versions are naturals.  A run is a list of events.
    pub v    the operator publishes version v (nondecreasing order; the anchor head is the max published)
    acc v    the verifier is offered the published manifest v (v <= head) and accepts it iff the guard holds
    wipe     the adversary deletes the verifier's local lastSeen register
  Guards: shipped (last <= v); anchored (last <= v and head <= v, head = CURRENT log head, challenge-bound);
  replay (head taken from ANY head ever issued).
  Theorems: shipped without wipe: accepted versions nondecreasing; shipped with wipe: rollback run exists;
  anchored with wipe allowed: accepted versions nondecreasing; anchored head replay with wipe: rollback run exists.
-/
namespace AllowlistRollback

inductive Ev | pub (v : Nat) | acc (v : Nat) | wipe
  deriving DecidableEq

structure St where
  head : Nat        -- anchor register: highest published version
  last : Nat        -- verifier's local lastSeen
  old  : List Nat   -- every head ever issued (replay variant)
  deriving DecidableEq

inductive Guard | shipped | anchored | replay
  deriving DecidableEq

def okAcc : Guard → St → Nat → Bool
  | .shipped,  s, v => decide (s.last ≤ v)
  | .anchored, s, v => decide (s.last ≤ v) && decide (s.head ≤ v)
  | .replay,   s, v => decide (s.last ≤ v) && s.old.any (fun h => decide (h ≤ v))

/-- one event; none = event refused. Output: new state and the version accepted (if any). -/
def stepF (g : Guard) (w : Bool) (s : St) : Ev → Option (St × Option Nat)
  | .pub v  => if s.head ≤ v then some (⟨v, s.last, v :: s.old⟩, none) else none
  | .acc v  => if v ≤ s.head && okAcc g s v then some (⟨s.head, v, s.old⟩, some v) else none
  | .wipe   => if w then some (⟨s.head, 0, s.old⟩, none) else none

/-- run a whole event list; the output is the list of accepted versions in order; none = some event refused (not a run). -/
def runF (g : Guard) (w : Bool) : St → List Ev → Option (List Nat)
  | _, [] => some []
  | s, e :: es =>
    match stepF g w s e with
    | none => none
    | some (s', o) =>
      match runF g w s' es with
      | none => none
      | some acc => some (match o with | some v => v :: acc | none => acc)

def init : St := ⟨0, 0, [0]⟩

def Mono : List Nat → Prop
  | [] => True
  | [_] => True
  | a :: b :: r => a ≤ b ∧ Mono (b :: r)

-- ---- concrete attacks / witnesses (kernel-checked by evaluation) -----------------------------------------
theorem shipped_wipe_rollback :
    runF .shipped true init [.pub 1, .pub 2, .acc 2, .wipe, .acc 1] = some [2, 1] := by decide

theorem shipped_nowipe_blocks_that_run :
    runF .shipped false init [.pub 1, .pub 2, .acc 2, .wipe, .acc 1] = none := by decide

theorem anchored_blocks_wipe_rollback :
    runF .anchored true init [.pub 1, .pub 2, .acc 2, .wipe, .acc 1] = none := by decide

theorem replay_wipe_rollback :
    runF .replay true init [.pub 1, .pub 2, .acc 2, .wipe, .acc 1] = some [2, 1] := by decide

-- ---- general theorems ------------------------------------------------------------------------------------
theorem runF_cons {g w s e es acc} (h : runF g w s (e :: es) = some acc) :
    ∃ s' o acc', stepF g w s e = some (s', o) ∧ runF g w s' es = some acc' ∧
      acc = (match o with | some v => v :: acc' | none => acc') := by
  unfold runF at h
  cases h1 : stepF g w s e with
  | none => rw [h1] at h; simp at h
  | some r =>
    obtain ⟨s', o⟩ := r
    rw [h1] at h
    simp only at h
    cases h2 : runF g w s' es with
    | none => rw [h2] at h; simp at h
    | some acc' => rw [h2] at h; exact ⟨s', o, acc', rfl, h2, (Option.some.inj h).symm⟩

-- what each event does
theorem step_pub {g w s v s' o} (h : stepF g w s (.pub v) = some (s', o)) :
    s.head ≤ v ∧ s' = ⟨v, s.last, v :: s.old⟩ ∧ o = none := by
  simp only [stepF] at h
  by_cases hh : s.head ≤ v
  · rw [if_pos hh] at h
    injection h with h; injection h with h1 h2; exact ⟨hh, h1.symm, h2.symm⟩
  · rw [if_neg hh] at h; simp at h

theorem step_wipe {g w s s' o} (h : stepF g w s .wipe = some (s', o)) :
    w = true ∧ s' = ⟨s.head, 0, s.old⟩ ∧ o = none := by
  simp only [stepF] at h
  by_cases hh : w = true
  · rw [if_pos hh] at h
    injection h with h; injection h with h1 h2; exact ⟨hh, h1.symm, h2.symm⟩
  · rw [if_neg hh] at h; simp at h

theorem step_acc {g w s v s' o} (h : stepF g w s (.acc v) = some (s', o)) :
    v ≤ s.head ∧ okAcc g s v = true ∧ s' = ⟨s.head, v, s.old⟩ ∧ o = some v := by
  simp only [stepF] at h
  by_cases hh : (decide (v ≤ s.head) && okAcc g s v) = true
  · rw [if_pos hh] at h
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hh
    injection h with h; injection h with h1 h2
    exact ⟨hh.1, hh.2, h1.symm, h2.symm⟩
  · rw [if_neg hh] at h; simp at h

-- ---- shipped, no wipe: lastSeen is a lower bound on every later acceptance ------------------------------
theorem shipped_inv : ∀ {es : List Ev} {s : St} {acc : List Nat},
    runF .shipped false s es = some acc → ∀ x ∈ acc, s.last ≤ x := by
  intro es
  induction es with
  | nil => intro s acc h; simp [runF] at h; subst h; simp
  | cons e es ih =>
    intro s acc h x hx
    obtain ⟨s', o, acc', h1, h2, rfl⟩ := runF_cons h
    cases e with
    | pub v =>
      obtain ⟨_, rfl, rfl⟩ := step_pub h1
      simpa using ih h2 x hx
    | wipe => have := (step_wipe h1).1; simp at this
    | acc v =>
      obtain ⟨_, hok, rfl, rfl⟩ := step_acc h1
      simp only [okAcc, decide_eq_true_eq] at hok
      simp at hx
      rcases hx with rfl | hx
      · exact hok
      · exact Nat.le_trans hok (by simpa using ih h2 x hx)

theorem shipped_nowipe_mono : ∀ {es : List Ev} {s : St} {acc : List Nat},
    runF .shipped false s es = some acc → Mono acc := by
  intro es
  induction es with
  | nil => intro s acc h; simp [runF] at h; subst h; trivial
  | cons e es ih =>
    intro s acc h
    obtain ⟨s', o, acc', h1, h2, rfl⟩ := runF_cons h
    cases e with
    | pub v => obtain ⟨_, rfl, rfl⟩ := step_pub h1; exact ih h2
    | wipe => have := (step_wipe h1).1; simp at this
    | acc v =>
      obtain ⟨_, hok, rfl, rfl⟩ := step_acc h1
      cases acc' with
      | nil => trivial
      | cons b r =>
        have := shipped_inv h2 b (by simp)
        simp only [okAcc, decide_eq_true_eq] at hok
        exact ⟨by simpa using this, ih h2⟩

-- ---- anchored (current head) with wipe ALLOWED: still monotone ----------------------------------------------
theorem anchored_inv : ∀ {es : List Ev} {s : St} {acc : List Nat},
    runF .anchored true s es = some acc → ∀ x ∈ acc, s.head ≤ x := by
  intro es
  induction es with
  | nil => intro s acc h; simp [runF] at h; subst h; simp
  | cons e es ih =>
    intro s acc h x hx
    obtain ⟨s', o, acc', h1, h2, rfl⟩ := runF_cons h
    cases e with
    | pub v =>
      obtain ⟨hh, rfl, rfl⟩ := step_pub h1
      exact Nat.le_trans hh (by simpa using ih h2 x hx)
    | wipe => obtain ⟨_, rfl, rfl⟩ := step_wipe h1; simpa using ih h2 x hx
    | acc v =>
      obtain ⟨_, hok, rfl, rfl⟩ := step_acc h1
      simp only [okAcc, Bool.and_eq_true, decide_eq_true_eq] at hok
      simp at hx
      rcases hx with rfl | hx
      · exact hok.2
      · simpa using ih h2 x hx

theorem anchored_wipe_mono : ∀ {es : List Ev} {s : St} {acc : List Nat},
    runF .anchored true s es = some acc → Mono acc := by
  intro es
  induction es with
  | nil => intro s acc h; simp [runF] at h; subst h; trivial
  | cons e es ih =>
    intro s acc h
    obtain ⟨s', o, acc', h1, h2, rfl⟩ := runF_cons h
    cases e with
    | pub v => obtain ⟨_, rfl, rfl⟩ := step_pub h1; exact ih h2
    | wipe => obtain ⟨_, rfl, rfl⟩ := step_wipe h1; exact ih h2
    | acc v =>
      obtain ⟨hv, hok, rfl, rfl⟩ := step_acc h1
      cases acc' with
      | nil => trivial
      | cons b r =>
        have := anchored_inv h2 b (by simp)
        exact ⟨Nat.le_trans hv (by simpa using this), ih h2⟩

end AllowlistRollback

#print axioms AllowlistRollback.shipped_nowipe_mono
#print axioms AllowlistRollback.anchored_wipe_mono
#print axioms AllowlistRollback.shipped_wipe_rollback
#print axioms AllowlistRollback.replay_wipe_rollback
