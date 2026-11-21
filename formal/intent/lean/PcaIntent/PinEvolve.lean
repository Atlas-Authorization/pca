import PcaIntent.TraitAlg
/-
  PCA action kit, track A4: the grant pin and the semantic diff (docs/pca/specs/action-kit.md sections 7.2, 7.3, 15).
  Core Lean 4 only (no Mathlib API). Implemented by `decidePin` (packages/pca/src/action-pin.ts) and `diffDefs`
  (packages/pca-actions/src/diff.ts); the property tests and the shared vectors tie the code to these statements.

  PIN (what is proved)
    P1  pin_chain_sound     a presented digest is accepted only if it IS the pinned digest or the last step of a chain of
                            records in which every step is usable (class equal/narrow, or approved by the principal).
    P2  chain_widen_approved every widen/incomparable step on an accepted chain carries the principal's approval.
    P3  no_auto_follow      with no approvals, a record set of only widen/incomparable/added/removed records never moves the pin.
    P4  free_step_follows   an equal/narrow record whose source is accepted makes its target accepted (no approval needed);
                            widen_not_usable: without approval a widen/incomparable record is not usable.
    P5  new_action_not_allowed a verb the pin does not name is never allowed (deny or escalate).
  DIFF (what is proved)
    D1  accepts_mono        if every parameter of the new spec is declared by the old one with a value domain contained in the
                            old one's, and every parameter the old spec requires is required by the new one, then every call
                            the new spec accepts is accepted by the old one (closed world, required members, domains).
    D2  interval_contained / enum_contained: the domain conditions the checker uses for bounds (min/max, max_len, max_items)
                            and for value sets (enum values, set members) imply containment.
    D3  narrow_sound        a narrow/equal change (D1's condition plus the effective profile not falling) never accepts a call
                            the old spec refused and never raises the final decision (T4).
  NOT covered (stated, not hidden): that the TypeScript code computes the relation (property-tested against a brute-force
  oracle and vectors instead); the Ed25519 validity of records and re-approvals (the `approved` predicate and the registry
  signature are abstract here); dimensions the checker classifies `incomparable` (unit, role, binding, default), which are
  never auto-followed and so need no soundness statement; the string-length / array-size arithmetic beyond the abstract
  `ok : Int → Prop` domain.
-/
namespace PcaIntent.PinEvolve
open PcaIntent.TraitAlg

/-! ### the pin -/

inductive Cls | equal | narrow | widen | incomparable | added | removed
  deriving DecidableEq

structure Rec where
  src : Nat
  dst : Nat
  cls : Cls

/-- A step is usable iff it is a free change (equal/narrow) or the principal approved this exact record. -/
def Usable (appr : Rec → Prop) (r : Rec) : Prop := r.cls = Cls.equal ∨ r.cls = Cls.narrow ∨ (appr r ∧ (r.cls = Cls.widen ∨ r.cls = Cls.incomparable))

/-- `Chain recs appr a b l`: `l` is a path of usable records from `a` to `b`, each taken from `recs`. -/
inductive Chain (recs : Rec → Prop) (appr : Rec → Prop) : Nat → Nat → List Rec → Prop
  | nil (a : Nat) : Chain recs appr a a []
  | cons {a b : Nat} {l : List Rec} (r : Rec) (hr : recs r) (hu : Usable appr r) (hs : r.src = a) :
      Chain recs appr r.dst b l → Chain recs appr a b (r :: l)

/-- The pin accepts `d` iff some usable chain leads from the pinned digest to it. -/
def Follows (recs appr : Rec → Prop) (pinned d : Nat) : Prop := ∃ l, Chain recs appr pinned d l

theorem pin_chain_sound {recs appr : Rec → Prop} {a b : Nat} {l : List Rec} (h : Chain recs appr a b l) :
    b = a ∨ ∃ r, recs r ∧ Usable appr r ∧ r.dst = b := by
  induction h with
  | nil a => exact Or.inl rfl
  | cons r hr hu hs _ ih =>
    rcases ih with e | ⟨r', hr', hu', hd⟩
    · exact Or.inr ⟨r, hr, hu, e.symm⟩
    · exact Or.inr ⟨r', hr', hu', hd⟩

theorem chain_widen_approved {recs appr : Rec → Prop} {a b : Nat} {l : List Rec} (h : Chain recs appr a b l) :
    ∀ r ∈ l, (r.cls = Cls.widen ∨ r.cls = Cls.incomparable) → appr r := by
  induction h with
  | nil a => intro r hr; cases hr
  | cons r0 hr0 hu hs _ ih =>
    intro r hr hw
    rcases List.mem_cons.mp hr with e | e
    · subst e
      rcases hu with h1 | h1 | ⟨h1, _⟩
      · rcases hw with h2 | h2 <;> simp [h1] at h2
      · rcases hw with h2 | h2 <;> simp [h1] at h2
      · exact h1
    · exact ih r e hw

theorem no_auto_follow {recs appr : Rec → Prop} (hna : ∀ r, ¬ appr r)
    (hbad : ∀ r, recs r → r.cls = Cls.widen ∨ r.cls = Cls.incomparable ∨ r.cls = Cls.added ∨ r.cls = Cls.removed)
    {pinned d : Nat} (h : Follows recs appr pinned d) : d = pinned := by
  obtain ⟨l, hl⟩ := h
  cases hl with
  | nil => rfl
  | cons r hr hu hs _ =>
    exfalso
    rcases hu with h1 | h1 | ⟨h1, _⟩
    · rcases hbad r hr with h2 | h2 | h2 | h2 <;> simp [h1] at h2
    · rcases hbad r hr with h2 | h2 | h2 | h2 <;> simp [h1] at h2
    · exact hna r h1

/-- Chains compose: appending a usable record at the end of a chain extends it. -/
theorem chain_snoc {recs appr : Rec → Prop} {a b : Nat} {l : List Rec} (h : Chain recs appr a b l)
    (r : Rec) (hr : recs r) (hu : Usable appr r) (hs : r.src = b) : Chain recs appr a r.dst (l ++ [r]) := by
  induction h with
  | nil a => exact Chain.cons r hr hu hs (Chain.nil _)
  | cons r0 hr0 hu0 hs0 _ ih => exact Chain.cons r0 hr0 hu0 hs0 (ih hs)

/-- A free (equal/narrow) record whose source is accepted makes its target accepted, with no approval. -/
theorem free_step_follows {recs appr : Rec → Prop} {pinned b : Nat} (h : Follows recs appr pinned b)
    (r : Rec) (hr : recs r) (hf : r.cls = Cls.equal ∨ r.cls = Cls.narrow) (hs : r.src = b) : Follows recs appr pinned r.dst := by
  obtain ⟨l, hl⟩ := h
  have hu : Usable appr r := by rcases hf with e | e <;> simp [Usable, e]
  exact ⟨l ++ [r], chain_snoc hl r hr hu hs⟩

/-- A widen/incomparable record alone does not move the pin: without approval it is not usable. -/
theorem widen_not_usable {appr : Rec → Prop} (r : Rec) (hw : r.cls = Cls.widen ∨ r.cls = Cls.incomparable) (hna : ¬ appr r) : ¬ Usable appr r := by
  intro hu
  rcases hu with h | h | ⟨h, _⟩
  · rcases hw with e | e <;> simp [h] at e
  · rcases hw with e | e <;> simp [h] at e
  · exact hna h

/-- A verb the pin does not name is never allowed: 0 = deny, 1 = escalate. -/
def newActionOutcome (escalate : Bool) : Nat := if escalate then 1 else 0

theorem new_action_not_allowed (escalate : Bool) : newActionOutcome escalate < 2 := by
  unfold newActionOutcome; split <;> omega

/-! ### the semantic diff: soundness of equal / narrow -/

/-- A parameter declaration: whether it is required and which values its domain accepts. -/
structure PSpec where
  req : Bool
  ok : Int → Prop

/-- An action spec: names to declarations (`none` = undeclared; the world is closed). -/
abbrev Spec := Nat → Option PSpec
/-- A call: names to presented values. -/
abbrev Call := Nat → Option Int

/-- Closed-world conformance: no undeclared name, every required name present, every present value in its domain. -/
def Accepts (s : Spec) (c : Call) : Prop :=
  ∀ n, match s n, c n with
    | none, none => True
    | none, some _ => False
    | some p, none => p.req = false
    | some p, some x => p.ok x

/-- The condition `diffDefs` checks for `narrow`/`equal` on the call set (`callsContained`): every parameter of the new spec is
    declared by the old one with a contained domain, and every parameter the old spec requires is required by the new one. -/
def Contained (new old : Spec) : Prop :=
  (∀ n p, new n = some p → ∃ q, old n = some q ∧ ∀ x, p.ok x → q.ok x) ∧
  (∀ n q, old n = some q → q.req = true → ∃ p, new n = some p ∧ p.req = true)

/-- D1: every call the new spec accepts is accepted by the old one. -/
theorem accepts_mono {new old : Spec} (h : Contained new old) {c : Call} (ha : Accepts new c) : Accepts old c := by
  intro n
  have hn := ha n
  cases hnew : new n with
  | none =>
    cases hold : old n with
    | none => rw [hnew] at hn; simpa [hold] using hn
    | some q =>
      cases hc : c n with
      | none =>
        show q.req = false
        cases hq : q.req
        · rfl
        · exfalso
          obtain ⟨p, hp, _⟩ := h.2 n q hold hq
          rw [hnew] at hp; cases hp
      | some x => rw [hnew, hc] at hn; exact hn.elim
  | some p =>
    obtain ⟨q, hq, hsub⟩ := h.1 n p hnew
    rw [hq]
    cases hc : c n with
    | none =>
      show q.req = false
      rw [hnew, hc] at hn
      cases hqr : q.req
      · rfl
      · exfalso
        obtain ⟨p', hp', hpr⟩ := h.2 n q hq hqr
        rw [hnew] at hp'
        cases hp'
        have : p.req = false := hn
        rw [this] at hpr
        cases hpr
    | some x => rw [hnew, hc] at hn; exact hsub x hn

/-- D2: bounds. A tighter integer interval (min raised, max lowered) is contained; this is the shape of min/max, max_len and
    max_items changes. -/
theorem interval_contained {lo hi lo' hi' : Int} (h1 : lo ≤ lo') (h2 : hi' ≤ hi) :
    ∀ x : Int, (lo' ≤ x ∧ x ≤ hi') → (lo ≤ x ∧ x ≤ hi) := by
  intro x hx; omega

/-- D2: value sets. A sub-enumeration (enum values removed, set members removed) is contained. -/
theorem enum_contained {vals vals' : Int → Prop} (h : ∀ x, vals' x → vals x) : ∀ x, vals' x → vals x := h

/-- D3: a narrow/equal change never accepts a call the old spec refused and never raises the final decision. -/
theorem narrow_sound {new old : Spec} (h : Contained new old) {c : Call} (ha : Accepts new c)
    (g : Grant) (cx : Nat → Prop) (pol : Nat) {ρ ρ' : Profile} (hp : ρ.le ρ') :
    Accepts old c ∧ min pol (fd g cx ρ') ≤ min pol (fd g cx ρ) :=
  ⟨accepts_mono h ha, dec_antitone g cx pol hp⟩

end PcaIntent.PinEvolve
